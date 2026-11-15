// SPDX-License-Identifier: EUPL-1.2

//! Verification of Android Key Attestation certificates.
//!
//! This is the "trust but verify" step: after Kotlin asks Keystore for a
//! StrongBox key, we parse the attestation leaf ourselves and refuse to
//! create a passkey unless the hardware itself claims that the key
//!  * lives in StrongBox (both attestation and KeyMint security level),
//!  * was GENERATED inside it (not imported => no copy exists elsewhere),
//!  * is a P-256 EC key that requires user authentication,
//!  * is bound to *this* ceremony via the attestation challenge.
//!
//! With the `chain-verification` feature (default), [`verify_strongbox`] also
//! verifies the chain against pinned Google roots and the revocation snapshot
//! (see `chain.rs`). Without it, only the leaf's claims are checked, which
//! guards against a silent TEE/software fallback but not against a forged
//! chain. Either way, relying parties that request `attestation: "direct"`
//! receive the full chain in an `android-key` statement and can verify it.

use crate::der::{self, CLASS_CONTEXT, CLASS_UNIVERSAL, Tlv};
use crate::error::{Error, Result};

/// 1.3.6.1.4.1.11129.2.1.17
const OID_KEY_ATTESTATION: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
/// 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// 1.2.840.10045.3.1.7
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

pub const SECURITY_LEVEL_SOFTWARE: u64 = 0;
pub const SECURITY_LEVEL_TEE: u64 = 1;
pub const SECURITY_LEVEL_STRONGBOX: u64 = 2;

// KeyMint tag numbers (without type bits), as used in AuthorizationList.
const KM_TAG_PURPOSE: u32 = 1;
const KM_TAG_ALGORITHM: u32 = 2;
const KM_TAG_EC_CURVE: u32 = 10;
const KM_TAG_NO_AUTH_REQUIRED: u32 = 503;
const KM_TAG_USER_AUTH_TYPE: u32 = 504;
const KM_TAG_AUTH_TIMEOUT: u32 = 505;
const KM_TAG_ORIGIN: u32 = 702;
const KM_TAG_ROOT_OF_TRUST: u32 = 704;

const KM_PURPOSE_SIGN: u64 = 2;
const KM_ALGORITHM_EC: u64 = 3;
const KM_EC_CURVE_P256: u64 = 1;
const KM_ORIGIN_GENERATED: u64 = 0;

/// The bits of an X.509 certificate we care about.
pub struct Cert<'a> {
    /// Raw TBSCertificate (what the issuer signed).
    pub tbs: &'a [u8],
    /// Serial number INTEGER contents.
    pub serial: &'a [u8],
    /// Raw issuer / subject Names, compared byte-for-byte when chaining.
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// Full SubjectPublicKeyInfo DER.
    pub spki: &'a [u8],
    /// Uncompressed SEC1 point (0x04 || X || Y) if the key is P-256.
    pub p256_point: Option<&'a [u8]>,
    /// OID (contents) of the outer signatureAlgorithm.
    pub signature_algorithm: &'a [u8],
    /// Signature BIT STRING contents, without the unused-bits byte.
    pub signature: &'a [u8],
    pub key_description: Option<&'a [u8]>,
    /// basicConstraints cA, if the extension is present.
    pub is_ca: Option<bool>,
}

/// 2.5.29.19
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

pub fn parse_cert(der_bytes: &[u8]) -> Result<Cert<'_>> {
    let cert = der::read_one(der_bytes)?.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "Certificate")?;
    let [tbs, sig_alg, sig] = cert.children()?[..] else {
        return Err(Error::data("Certificate must have 3 fields"));
    };
    let tbs = tbs.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "TBSCertificate")?;
    let signature_algorithm = sig_alg
        .expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "signatureAlgorithm")?
        .children()?
        .first()
        .ok_or_else(|| Error::data("empty signatureAlgorithm"))?
        .expect(CLASS_UNIVERSAL, der::TAG_OID, "signature OID")?
        .value;
    let signature = match sig.expect(CLASS_UNIVERSAL, der::TAG_BIT_STRING, "signatureValue")?.value {
        [0x00, rest @ ..] => rest,
        _ => return Err(Error::data("signature BIT STRING has unused bits")),
    };

    let mut fields = tbs.children()?.into_iter().peekable();
    // [0] version (optional), serial, signature, issuer, validity, subject, spki
    if fields.peek().is_some_and(|t| t.is(CLASS_CONTEXT, 0)) {
        fields.next();
    }
    let mut next = |what: &str| fields.next().ok_or_else(|| Error::data(format!("certificate missing {what}")));
    let serial = next("serialNumber")?.expect(CLASS_UNIVERSAL, der::TAG_INTEGER, "serialNumber")?.value;
    next("signature")?;
    let issuer = next("issuer")?.raw;
    next("validity")?;
    let subject = next("subject")?.raw;
    let spki_tlv = next("subjectPublicKeyInfo")?;
    let p256_point = parse_spki_p256(&spki_tlv)?;

    let mut key_description = None;
    let mut is_ca = None;
    for f in fields {
        if f.is(CLASS_CONTEXT, 3) {
            for ext in f.explicit_inner()?.children()? {
                let parts = ext.children()?;
                let oid = parts
                    .first()
                    .ok_or_else(|| Error::data("empty extension"))?
                    .expect(CLASS_UNIVERSAL, der::TAG_OID, "extnID")?;
                let value = parts
                    .last()
                    .ok_or_else(|| Error::data("extension without value"))?
                    .expect(CLASS_UNIVERSAL, der::TAG_OCTET_STRING, "extnValue")?;
                if oid.value == OID_KEY_ATTESTATION {
                    if key_description.replace(value.value).is_some() {
                        return Err(Error::security("duplicate key attestation extension"));
                    }
                } else if oid.value == OID_BASIC_CONSTRAINTS {
                    let bc = der::read_one(value.value)?.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "BasicConstraints")?;
                    let ca = match bc.children()?.first() {
                        Some(b) if b.is(CLASS_UNIVERSAL, der::TAG_BOOLEAN) => b.as_bool()?,
                        _ => false, // cA DEFAULT FALSE
                    };
                    is_ca = Some(ca);
                }
            }
        }
    }

    Ok(Cert {
        tbs: tbs.raw,
        serial,
        issuer,
        subject,
        spki: spki_tlv.raw,
        p256_point,
        signature_algorithm,
        signature,
        key_description,
        is_ca,
    })
}

fn parse_spki_p256<'a>(spki: &Tlv<'a>) -> Result<Option<&'a [u8]>> {
    let parts = spki.children()?;
    let [alg, key] = parts.as_slice() else {
        return Err(Error::data("malformed SPKI"));
    };
    let alg = alg.children()?;
    let is_p256 = alg.len() == 2 && alg[0].value == OID_EC_PUBLIC_KEY && alg[1].value == OID_PRIME256V1;
    if !is_p256 {
        return Ok(None);
    }
    let bits = key.expect(CLASS_UNIVERSAL, der::TAG_BIT_STRING, "subjectPublicKey")?.value;
    match bits {
        [0x00, point @ ..] if point.len() == 65 && point[0] == 0x04 => Ok(Some(point)),
        _ => Err(Error::data("unexpected EC point encoding")),
    }
}

pub use crate::pb::{AttestationReport, ChainSummary};

/// Leaf policy plus, if compiled in, full chain verification.
pub fn verify_strongbox<'a>(x5c: &'a [Vec<u8>], expected_challenge: &[u8]) -> Result<(Cert<'a>, AttestationReport)> {
    let leaf = x5c.first().ok_or_else(|| Error::security("empty attestation chain"))?;
    #[allow(unused_mut)]
    let (cert, mut report) = verify_strongbox_leaf(leaf, expected_challenge)?;
    #[cfg(feature = "chain-verification")]
    {
        let c = crate::chain::verify(x5c, &crate::chain::embedded())?;
        report.chain = Some(ChainSummary {
            root: c.root,
            length: c.length as u32,
        });
    }
    Ok((cert, report))
}

/// Parse the leaf of an attestation chain and enforce the StrongBox policy.
/// Returns the leaf's P-256 point and a report describing the device state.
pub fn verify_strongbox_leaf<'a>(
    leaf_der: &'a [u8],
    expected_challenge: &[u8],
) -> Result<(Cert<'a>, AttestationReport)> {
    let cert = parse_cert(leaf_der)?;
    if cert.p256_point.is_none() {
        return Err(Error::security("attested key is not P-256"));
    }
    let kd = cert
        .key_description
        .ok_or_else(|| Error::security("leaf certificate has no key attestation extension"))?;
    let report = check_key_description(kd, expected_challenge)?;
    Ok((cert, report))
}

fn check_key_description(kd: &[u8], expected_challenge: &[u8]) -> Result<AttestationReport> {
    let seq = der::read_one(kd)?.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "KeyDescription")?;
    let f = seq.children()?;
    if f.len() < 8 {
        return Err(Error::data("KeyDescription too short"));
    }
    let attestation_version = f[0].as_u64()?;
    let attestation_security_level = f[1].as_u64()?;
    let key_mint_version = f[2].as_u64()?;
    let key_mint_security_level = f[3].as_u64()?;
    let challenge = f[4].expect(CLASS_UNIVERSAL, der::TAG_OCTET_STRING, "attestationChallenge")?;
    let sw = auth_list(&f[6])?;
    let hw = auth_list(&f[7])?;

    if attestation_security_level != SECURITY_LEVEL_STRONGBOX {
        return Err(Error::security(format!(
            "attestation security level is {} ({}), StrongBox required",
            attestation_security_level,
            level_name(attestation_security_level)
        )));
    }
    if key_mint_security_level != SECURITY_LEVEL_STRONGBOX {
        return Err(Error::security(format!(
            "KeyMint security level is {} ({}), StrongBox required",
            key_mint_security_level,
            level_name(key_mint_security_level)
        )));
    }
    if !constant_time_eq(challenge.value, expected_challenge) {
        return Err(Error::security("attestation challenge does not match this ceremony"));
    }

    let origin = find(&hw, KM_TAG_ORIGIN).ok_or_else(|| Error::security("hardware did not enforce key origin"))?;
    if origin.as_u64()? != KM_ORIGIN_GENERATED {
        return Err(Error::security("key was imported, not generated inside StrongBox"));
    }
    let alg = find(&hw, KM_TAG_ALGORITHM).ok_or_else(|| Error::security("algorithm not hardware-enforced"))?;
    if alg.as_u64()? != KM_ALGORITHM_EC {
        return Err(Error::security("attested key is not EC"));
    }
    let curve = find(&hw, KM_TAG_EC_CURVE).ok_or_else(|| Error::security("curve not hardware-enforced"))?;
    if curve.as_u64()? != KM_EC_CURVE_P256 {
        return Err(Error::security("attested key is not P-256"));
    }
    let purposes = find(&hw, KM_TAG_PURPOSE).ok_or_else(|| Error::security("purpose not hardware-enforced"))?;
    let purposes = purposes
        .expect(CLASS_UNIVERSAL, der::TAG_SET, "purpose SET")?
        .children()?
        .iter()
        .map(Tlv::as_u64)
        .collect::<Result<Vec<_>>>()?;
    if purposes != [KM_PURPOSE_SIGN] {
        return Err(Error::security(format!("unexpected key purposes {purposes:?}")));
    }
    if find(&hw, KM_TAG_NO_AUTH_REQUIRED).is_some() || find(&sw, KM_TAG_NO_AUTH_REQUIRED).is_some() {
        return Err(Error::security("key does not require user authentication"));
    }
    if find(&hw, KM_TAG_USER_AUTH_TYPE).is_none() {
        return Err(Error::security("user authentication is not hardware-enforced"));
    }
    if find(&hw, KM_TAG_AUTH_TIMEOUT).is_some() || find(&sw, KM_TAG_AUTH_TIMEOUT).is_some() {
        return Err(Error::security("key allows time-based auth; per-use auth required"));
    }

    let (mut verified_boot_state, mut device_locked) = (None, None);
    if let Some(rot) = find(&hw, KM_TAG_ROOT_OF_TRUST) {
        let r = rot.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "RootOfTrust")?.children()?;
        if r.len() >= 3 {
            device_locked = Some(r[1].as_bool()?);
            verified_boot_state = Some(small(r[2].as_u64()?)?);
        }
    }

    Ok(AttestationReport {
        attestation_version: small(attestation_version)?,
        attestation_security_level: small(attestation_security_level)?,
        key_mint_version: small(key_mint_version)?,
        key_mint_security_level: small(key_mint_security_level)?,
        verified_boot_state,
        device_locked,
        chain: None,
    })
}

fn small(v: u64) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::data("attestation value out of range"))
}

/// AuthorizationList ::= SEQUENCE of optional `[tag] EXPLICIT <value>`.
/// Returns (tag, inner value) pairs.
fn auth_list<'a>(t: &Tlv<'a>) -> Result<Vec<(u32, Tlv<'a>)>> {
    t.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "AuthorizationList")?
        .children()?
        .into_iter()
        .map(|e| {
            if e.class != CLASS_CONTEXT {
                return Err(Error::data("AuthorizationList entry is not context-tagged"));
            }
            Ok((e.tag, e.explicit_inner()?))
        })
        .collect()
}

fn find<'a>(list: &[(u32, Tlv<'a>)], tag: u32) -> Option<Tlv<'a>> {
    list.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
}

fn level_name(l: u64) -> &'static str {
    match l {
        SECURITY_LEVEL_SOFTWARE => "Software",
        SECURITY_LEVEL_TEE => "TrustedEnvironment",
        SECURITY_LEVEL_STRONGBOX => "StrongBox",
        _ => "unknown",
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- tiny DER *writer* for building synthetic attestation extensions ---
    fn tlv(first: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = first.to_vec();
        let n = value.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend([0x81, n as u8]);
        } else {
            out.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(value);
        out
    }
    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }
    fn int(v: u8) -> Vec<u8> {
        tlv(&[0x02], &[v])
    }
    fn enumerated(v: u8) -> Vec<u8> {
        tlv(&[0x0a], &[v])
    }
    fn octets(v: &[u8]) -> Vec<u8> {
        tlv(&[0x04], v)
    }
    /// Context-specific constructed tag with high-tag-number form.
    fn ctx(tag: u32, inner: Vec<u8>) -> Vec<u8> {
        if tag < 31 {
            return tlv(&[0xa0 | tag as u8], &inner);
        }
        let mut b = vec![(tag & 0x7f) as u8];
        let mut t = tag >> 7;
        while t > 0 {
            b.push(0x80 | (t & 0x7f) as u8);
            t >>= 7;
        }
        b.push(0xbf);
        b.reverse();
        tlv(&b, &inner)
    }

    fn key_description(level: u8, challenge: &[u8], origin: u8, no_auth: bool) -> Vec<u8> {
        let mut hw = vec![
            ctx(KM_TAG_PURPOSE, tlv(&[0x31], &int(2))),
            ctx(KM_TAG_ALGORITHM, int(3)),
            ctx(KM_TAG_EC_CURVE, int(1)),
            ctx(KM_TAG_USER_AUTH_TYPE, int(3)),
            ctx(KM_TAG_ORIGIN, int(origin)),
            ctx(
                KM_TAG_ROOT_OF_TRUST,
                seq(&[octets(&[0; 32]), tlv(&[0x01], &[0xff]), enumerated(0), octets(&[0; 32])]),
            ),
        ];
        if no_auth {
            hw.push(ctx(KM_TAG_NO_AUTH_REQUIRED, tlv(&[0x05], &[])));
        }
        seq(&[
            int(100),
            enumerated(level),
            int(100),
            enumerated(level),
            octets(challenge),
            octets(&[]),
            seq(&[]),
            seq(&hw),
        ])
    }

    #[test]
    fn accepts_strongbox_generated_key() {
        let kd = key_description(2, b"challenge", 0, false);
        let r = check_key_description(&kd, b"challenge").unwrap();
        assert_eq!(r.attestation_security_level, 2);
        assert_eq!(r.device_locked, Some(true));
        assert_eq!(r.verified_boot_state, Some(0));
    }

    #[test]
    fn rejects_tee() {
        let kd = key_description(1, b"c", 0, false);
        let e = check_key_description(&kd, b"c").unwrap_err();
        assert!(e.message.contains("StrongBox required"), "{e}");
    }

    #[test]
    fn rejects_imported() {
        let kd = key_description(2, b"c", 2, false);
        let e = check_key_description(&kd, b"c").unwrap_err();
        assert!(e.message.contains("imported"), "{e}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let kd = key_description(2, b"c", 0, false);
        let e = check_key_description(&kd, b"d").unwrap_err();
        assert!(e.message.contains("challenge"), "{e}");
    }

    #[test]
    fn rejects_no_auth_required() {
        let kd = key_description(2, b"c", 0, true);
        let e = check_key_description(&kd, b"c").unwrap_err();
        assert!(e.message.contains("user authentication"), "{e}");
    }

    #[test]
    fn parses_real_shaped_certificate() {
        // Self-signed P-256 cert produced by openssl with a synthetic
        // attestation extension; see tests/fixtures/README.md.
        let der = include_bytes!("../tests/fixtures/strongbox_leaf.der");
        let cert = parse_cert(der).unwrap();
        assert!(cert.p256_point.is_some());
        assert!(cert.spki.len() == 91, "P-256 SPKI is 91 bytes");
        let (_, r) = verify_strongbox_leaf(der, b"hwbp-test-challenge").unwrap();
        assert_eq!(r.key_mint_security_level, 2);
    }
}
