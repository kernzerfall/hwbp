// SPDX-License-Identifier: EUPL-1.2

//! Attestation chain verification: signatures, pinned Google roots, and the
//! revocation snapshot embedded at build time.
//!
//! Compiled only with the `chain-verification` feature.
//!
//! Certificate validity periods are deliberately not checked. Android leaf
//! certificates carry placeholder dates, and Google's documented mechanism
//! for retiring attestation keys is the revocation list.

use crate::attestation::{self, Cert};
use crate::error::{Error, Result};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384};

mod trust {
    include!(concat!(env!("OUT_DIR"), "/trust.rs"));
}

// Signature algorithms (OID contents).
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

// Key algorithms / curves.
const KEY_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const CURVE_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const CURVE_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const KEY_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

#[derive(Debug, Clone)]
pub struct ChainReport {
    /// File stem of the pinned root the chain ends at.
    pub root: String,
    pub length: usize,
}

/// Trust inputs, parameterised so tests can use their own roots and lists.
pub struct Trust<'a> {
    pub roots: &'a [(&'a str, &'a [u8])],
    /// Sorted by serial.
    pub revoked: &'a [(&'a str, &'a str)],
}

pub fn embedded() -> Trust<'static> {
    Trust {
        roots: trust::ROOTS,
        revoked: trust::REVOKED,
    }
}

pub fn revocation_snapshot() -> (usize, Option<u64>) {
    (trust::REVOKED.len(), trust::REVOCATION_SNAPSHOT_UNIX)
}

/// Verify `chain` (leaf first, root last) against `trust`.
pub fn verify(chain: &[Vec<u8>], trust: &Trust<'_>) -> Result<ChainReport> {
    if chain.len() < 2 {
        return Err(Error::security("attestation chain too short"));
    }
    let certs = chain
        .iter()
        .map(|c| attestation::parse_cert(c))
        .collect::<Result<Vec<_>>>()?;

    // Only the leaf may carry a KeyDescription. Otherwise anyone holding a
    // genuinely attested signing key could use it to sign a forged "leaf" with
    // arbitrary claims and prepend it to a real chain.
    if certs[1..].iter().any(|c| c.key_description.is_some()) {
        return Err(Error::security("attestation extension found outside the leaf"));
    }

    for (i, pair) in certs.windows(2).enumerate() {
        let (child, issuer) = (&pair[0], &pair[1]);
        if child.issuer != issuer.subject {
            return Err(Error::security(format!("certificate {i}: issuer does not match the next certificate's subject")));
        }
        // Every issuer, including the attestation key that signs the leaf, must
        // be a CA (true for both RKP and factory-provisioned chains).
        if issuer.is_ca != Some(true) {
            return Err(Error::security(format!("certificate {} is not a CA", i + 1)));
        }
        verify_signature(child, issuer).map_err(|e| Error::security(format!("certificate {i}: {}", e.message)))?;
    }

    let last = certs.last().unwrap();
    let root = trust
        .roots
        .iter()
        .find_map(|(name, der)| {
            let pinned = attestation::parse_cert(der).ok()?;
            (pinned.spki == last.spki).then_some(*name)
        })
        .ok_or_else(|| Error::security("attestation chain does not end at a pinned Google root"))?;
    // Self-signature of the root is implied by pinning its key, but check it
    // anyway so a malformed root cert can't slip through.
    verify_signature(last, last).map_err(|e| Error::security(format!("root: {}", e.message)))?;

    for (i, c) in certs.iter().enumerate() {
        let serial = serial_hex(c.serial);
        if let Ok(idx) = trust.revoked.binary_search_by(|(s, _)| (*s).cmp(serial.as_str())) {
            return Err(Error::security(format!(
                "certificate {i} (serial {serial}) is revoked: {}",
                trust.revoked[idx].1
            )));
        }
    }

    Ok(ChainReport {
        root: root.to_owned(),
        length: certs.len(),
    })
}

/// Lowercase hex without leading zeros. Must match `normalise_serial` in build.rs.
pub fn serial_hex(serial: &[u8]) -> String {
    let hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
    let t = hex.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

fn verify_signature(child: &Cert<'_>, issuer: &Cert<'_>) -> Result<()> {
    let digest: Vec<u8> = match child.signature_algorithm {
        ECDSA_SHA256 | RSA_SHA256 => Sha256::digest(child.tbs).to_vec(),
        ECDSA_SHA384 => Sha384::digest(child.tbs).to_vec(),
        _ => return Err(Error::security("unsupported signature algorithm")),
    };
    let SpkiParts(key_alg, curve, key_bits) = spki_parts(issuer.spki)?;
    let bad = || Error::security("signature does not verify");

    match (child.signature_algorithm, key_alg) {
        (ECDSA_SHA256 | ECDSA_SHA384, KEY_EC) if curve == Some(CURVE_P256) => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits).map_err(|_| bad())?;
            let sig = p256::ecdsa::Signature::from_der(child.signature).map_err(|_| bad())?;
            vk.verify_prehash(&digest, &sig).map_err(|_| bad())
        }
        (ECDSA_SHA256 | ECDSA_SHA384, KEY_EC) if curve == Some(CURVE_P384) => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits).map_err(|_| bad())?;
            let sig = p384::ecdsa::Signature::from_der(child.signature).map_err(|_| bad())?;
            vk.verify_prehash(&digest, &sig).map_err(|_| bad())
        }
        (RSA_SHA256, KEY_RSA) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::SignatureScheme;
            let pk = rsa::PublicKey::from_pkcs1_der(key_bits).map_err(|_| bad())?;
            rsa::Pkcs1v15Sign::new::<Sha256>()
                .verify(&pk, &digest, child.signature)
                .map_err(|_| bad())
        }
        _ => Err(Error::security("issuer key type does not match signature algorithm")),
    }
}

/// Algorithm OID, curve OID (EC only), and subjectPublicKey bits of an SPKI.
struct SpkiParts<'a>(&'a [u8], Option<&'a [u8]>, &'a [u8]);

fn spki_parts(spki: &[u8]) -> Result<SpkiParts<'_>> {
    use crate::der::{self, CLASS_UNIVERSAL};
    let seq = der::read_one(spki)?.expect(CLASS_UNIVERSAL, der::TAG_SEQUENCE, "SPKI")?;
    let [alg, bits] = seq.children()?[..] else {
        return Err(Error::data("malformed SPKI"));
    };
    let alg = alg.children()?;
    let oid = alg.first().ok_or_else(|| Error::data("empty AlgorithmIdentifier"))?.value;
    let curve = alg
        .get(1)
        .filter(|p| p.is(CLASS_UNIVERSAL, der::TAG_OID))
        .map(|p| p.value);
    let bits = match bits.expect(CLASS_UNIVERSAL, der::TAG_BIT_STRING, "subjectPublicKey")?.value {
        [0x00, rest @ ..] => rest,
        _ => return Err(Error::data("subjectPublicKey has unused bits")),
    };
    Ok(SpkiParts(oid, curve, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(dir: &str) -> Vec<Vec<u8>> {
        let base = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
        (0..)
            .map(|i| std::fs::read(format!("{base}{dir}/{i}.der")))
            .take_while(|r| r.is_ok())
            .map(std::result::Result::unwrap)
            .collect()
    }

    fn trust_for<'a>(chain: &'a [Vec<u8>], revoked: &'a [(&'a str, &'a str)]) -> Trust<'a> {
        Trust {
            roots: Box::leak(vec![("test-root", chain.last().unwrap().as_slice())].into_boxed_slice()),
            revoked,
        }
    }

    #[test]
    fn ec_chain_verifies() {
        let c = load("chain_ec");
        let r = verify(&c, &trust_for(&c, &[])).unwrap();
        assert_eq!((r.root.as_str(), r.length), ("test-root", 4));
    }

    #[test]
    fn rsa_rooted_chain_verifies() {
        let c = load("chain_rsa");
        verify(&c, &trust_for(&c, &[])).unwrap();
    }

    #[test]
    fn unpinned_root_rejected() {
        let c = load("chain_ec");
        let e = verify(&c, &embedded()).unwrap_err();
        assert!(e.message.contains("pinned"), "{e}");
    }

    #[test]
    fn revoked_intermediate_rejected() {
        let c = load("chain_ec");
        let e = verify(&c, &trust_for(&c, &[("1001", "KEY_COMPROMISE")])).unwrap_err();
        assert!(e.message.contains("revoked") && e.message.contains("KEY_COMPROMISE"), "{e}");
    }

    #[test]
    fn forged_leaf_signed_by_attested_key_rejected() {
        let c = load("forged");
        let e = verify(&c, &trust_for(&c, &[])).unwrap_err();
        assert!(e.message.contains("outside the leaf"), "{e}");
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut c = load("chain_ec");
        let n = c[0].len();
        c[0][n - 3] ^= 0x01; // inside the leaf's signature
        let e = verify(&c, &trust_for(&c, &[])).unwrap_err();
        assert!(e.message.contains("certificate 0"), "{e}");
    }

    #[test]
    fn misordered_chain_rejected() {
        let mut c = load("chain_ec");
        c.swap(1, 2);
        assert!(verify(&c, &trust_for(&c, &[])).is_err());
    }

    /// Real chain from a Pixel 9 Pro (Titan M2, KeyMint 300, RKP), captured from
    /// the HWBP self-test on 2026-11-14.
    #[test]
    fn real_pixel_strongbox_chain() {
        let c = load("pixel9pro_strongbox");
        assert_eq!(c.len(), 5);
        let r = verify(&c, &Trust { roots: embedded().roots, revoked: &[] }).unwrap();
        assert_eq!(r.root, "google-p384-ca1");

        // The leaf policy holds too, given the challenge the self-test used.
        let kd = attestation::parse_cert(&c[0]).unwrap().key_description.unwrap();
        let fields = crate::der::read_one(kd).unwrap().children().unwrap();
        let challenge = fields[4].value;
        let (_, report) = attestation::verify_strongbox_leaf(&c[0], challenge).unwrap();
        assert_eq!((report.attestation_security_level, report.key_mint_version), (2, 300));
    }

    #[test]
    fn serial_normalisation() {
        assert_eq!(serial_hex(&[0x00, 0x0a, 0xbc]), "abc");
        assert_eq!(serial_hex(&[0x00]), "0");
    }
}
