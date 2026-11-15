// SPDX-License-Identifier: EUPL-1.2

//! WebAuthn Level 3 payload construction for a single-device, hardware-bound
//! platform authenticator.
//!
//! Nothing in here touches private key material: Rust prepares the bytes to
//! sign, Kotlin has StrongBox sign them behind BiometricPrompt, and Rust then
//! verifies the signature against the attested public key before assembling
//! the response.
//!
//! State passed between steps (plans, caller) uses the protobuf types from
//! `crate::pb` directly. JSON only appears where WebAuthn mandates it.

use crate::attestation;
use crate::b64;
use crate::error::{Code, Error, Result};
use crate::pb::{
    AssertionPlan, AssertionSummary, AttestationFormat, AttestationReport, Caller, ClientData, RegistrationPlan,
    RegistrationSummary,
};
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// HWBP's AAGUID. Lets relying parties recognise (and, with attestation,
/// verify) that a credential came from this authenticator.
pub const AAGUID: [u8; 16] = [
    0x81, 0xba, 0x41, 0xaf, 0x6f, 0x45, 0x49, 0xe5, 0x92, 0xfd, 0x2b, 0x88, 0x32, 0x4a, 0xdb, 0xc2,
];

pub const COSE_ALG_ES256: i64 = -7;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
/// Backup Eligibility. Never set: these credentials can't leave the chip.
#[allow(dead_code)]
const FLAG_BE: u8 = 0x08;
/// Backup State. Never set.
#[allow(dead_code)]
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

const CREDENTIAL_ID_LEN: usize = 32;

/// Origin scheme of native-app callers, followed by base64url(SHA-256(signing cert)).
const APK_KEY_HASH_PREFIX: &str = "android:apk-key-hash:";

// ---------------------------------------------------------------------------
// Incoming requests (subset of PublicKeyCredential{Creation,Request}Options JSON)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationOptions {
    challenge: String,
    rp: RpEntity,
    user: UserEntity,
    pub_key_cred_params: Vec<CredParam>,
    #[serde(default)]
    exclude_credentials: Vec<CredDescriptor>,
    #[serde(default)]
    attestation: Option<String>,
}

#[derive(Deserialize)]
struct RpEntity {
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserEntity {
    id: String,
    name: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct CredParam {
    #[serde(rename = "type")]
    ty: String,
    alg: i64,
}

#[derive(Deserialize)]
struct CredDescriptor {
    #[serde(rename = "type")]
    ty: String,
    id: String,
}

impl CredDescriptor {
    fn public_key_ids(list: &[CredDescriptor]) -> Result<Vec<Vec<u8>>> {
        list.iter()
            .filter(|c| c.ty == "public-key")
            .map(|c| b64::decode(&c.id))
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestOptions {
    challenge: String,
    rp_id: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<CredDescriptor>,
}

// ---------------------------------------------------------------------------
// clientDataJSON and RP ID
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientDataJson<'a> {
    #[serde(rename = "type")]
    ty: &'static str,
    challenge: String,
    origin: &'a str,
    cross_origin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_package_name: Option<&'a str>,
}

fn client_data(ty: &'static str, challenge: &str, caller: &Caller) -> Result<ClientData> {
    if let Some(h) = &caller.client_data_hash {
        if h.len() != 32 {
            return Err(Error::data("clientDataHash must be 32 bytes"));
        }
        return Ok(ClientData {
            json: None,
            hash: h.clone(),
        });
    }
    let challenge = b64::decode(challenge)?;
    if challenge.len() < 16 {
        return Err(Error::data("challenge must be at least 16 bytes"));
    }
    let json = serde_json::to_string(&ClientDataJson {
        ty,
        challenge: b64::encode(&challenge),
        origin: &caller.origin,
        cross_origin: false,
        android_package_name: caller.package_name.as_deref(),
    })?;
    Ok(ClientData {
        hash: Sha256::digest(json.as_bytes()).to_vec(),
        json: Some(json),
    })
}

fn client_data_of(c: &Option<ClientData>) -> Result<&ClientData> {
    c.as_ref().ok_or_else(|| Error::data("plan has no clientData"))
}

/// Resolve and validate the RP ID against the caller's origin.
fn resolve_rp_id(requested: Option<&str>, caller: &Caller) -> Result<String> {
    let web_host = caller
        .origin
        .strip_prefix("https://")
        .map(|rest| rest.split(['/', ':']).next().unwrap_or("").to_ascii_lowercase());

    let rp_id = match (requested, &web_host) {
        (Some(r), _) => r.to_ascii_lowercase(),
        (None, Some(host)) => host.clone(),
        (None, None) => return Err(Error::data("rp.id is required for app callers")),
    };
    if rp_id.is_empty() || rp_id.contains(['/', ':', ' ']) {
        return Err(Error::security("invalid RP ID"));
    }

    match web_host {
        Some(host) => {
            // Registrable-suffix check. The privileged browser has already done
            // the full PSL-aware check; this is defence in depth.
            if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
                return Err(Error::security(format!("RP ID {rp_id} is not valid for origin {}", caller.origin)));
            }
        }
        None => check_app_caller(&rp_id, caller)?,
    }
    Ok(rp_id)
}

/// Native-app callers. There is no Digital Asset Links check, so nothing ties
/// the app to the RP's domain cryptographically. Instead the user binds
/// (package, signing cert) to an RP ID on first use, and Kotlin passes that
/// binding as `trusted_rp_id`. Without it any app could claim any RP ID, phish
/// assertions from RPs that accept app origins, and replace (destroy) existing
/// passkeys by registering with a guessed user.id.
fn check_app_caller(rp_id: &str, caller: &Caller) -> Result<()> {
    let key_hash = caller
        .origin
        .strip_prefix(APK_KEY_HASH_PREFIX)
        .ok_or_else(|| Error::new(Code::NotAllowed, format!("unsupported caller origin {}", caller.origin)))?;
    if b64::decode(key_hash).map(|h| h.len()).unwrap_or(0) != 32 {
        return Err(Error::security("app origin is not a SHA-256 signing certificate hash"));
    }
    if caller.package_name.as_deref().unwrap_or("").is_empty() {
        return Err(Error::security("app caller without a package name"));
    }
    // Only a privileged browser may hand us a ready-made clientDataHash; for an
    // app it would let the app pick the origin the RP sees.
    if caller.client_data_hash.is_some() {
        return Err(Error::security("app callers cannot supply a clientDataHash"));
    }
    match caller.trusted_rp_id.as_deref() {
        Some(t) if t.eq_ignore_ascii_case(rp_id) => Ok(()),
        _ => Err(Error::new(
            Code::NotAllowed,
            format!("the user has not bound this app to RP ID {rp_id}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Cheap parse used to show the user what a native app is asking for before
/// the app is bound to the RP ID. Nothing here is validated against the caller;
/// `registration_begin` does that.
pub fn inspect_registration(request_json: &str) -> Result<RegistrationSummary> {
    let opts: CreationOptions = serde_json::from_str(request_json)?;
    Ok(RegistrationSummary {
        rp_id: opts.rp.id.map(|r| r.to_ascii_lowercase()),
        user_id: b64::decode(&opts.user.id)?,
        user_name: opts.user.name,
    })
}

pub fn registration_begin(request_json: &str, caller: &Caller, existing: &[Vec<u8>]) -> Result<RegistrationPlan> {
    let opts: CreationOptions = serde_json::from_str(request_json)?;
    let rp_id = resolve_rp_id(opts.rp.id.as_deref(), caller)?;

    if !opts
        .pub_key_cred_params
        .iter()
        .any(|p| p.ty == "public-key" && p.alg == COSE_ALG_ES256)
    {
        return Err(Error::new(Code::NotSupported, "RP does not accept ES256 (-7); StrongBox only supports P-256"));
    }

    if CredDescriptor::public_key_ids(&opts.exclude_credentials)?
        .iter()
        .any(|ex| existing.contains(ex))
    {
        return Err(Error::new(Code::InvalidState, "a passkey for this account already exists on this device"));
    }

    let user_id = b64::decode(&opts.user.id)?;
    if user_id.is_empty() || user_id.len() > 64 {
        return Err(Error::data("user.id must be 1..=64 bytes"));
    }

    let mut cred_id = vec![0u8; CREDENTIAL_ID_LEN];
    getrandom::fill(&mut cred_id).map_err(|e| Error::data(format!("RNG failure: {e}")))?;

    let attestation_format = match opts.attestation.as_deref() {
        Some("direct" | "enterprise" | "indirect") => AttestationFormat::AndroidKey,
        _ => AttestationFormat::None,
    };

    Ok(RegistrationPlan {
        client_data: Some(client_data("webauthn.create", &opts.challenge, caller)?),
        rp_id,
        user_id,
        user_display_name: opts.user.display_name.clone().unwrap_or_else(|| opts.user.name.clone()),
        user_name: opts.user.name,
        credential_id: cred_id,
        attestation_format: attestation_format.into(),
    })
}

fn flags_and_counter(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    // BE and BS are intentionally never set: single-device, non-backupable.
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

fn cose_es256(point: &[u8]) -> Result<Vec<u8>> {
    let (x, y) = (&point[1..33], &point[33..65]);
    // CTAP2 canonical key order: 1, 3, -1, -2, -3
    let key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer(COSE_ALG_ES256.into())), // alg
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ]);
    cbor(&key)
}

fn cbor(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::data(format!("CBOR: {e}")))?;
    Ok(out)
}

pub struct RegistrationAuthData {
    pub authenticator_data: Vec<u8>,
    pub to_be_signed: Vec<u8>,
    pub report: AttestationReport,
}

/// Verify the StrongBox attestation of the freshly generated key and build
/// authenticatorData. The attestation challenge Kotlin used must be the
/// clientDataHash, binding the hardware attestation to this ceremony.
pub fn registration_auth_data(plan: &RegistrationPlan, x5c: &[Vec<u8>]) -> Result<RegistrationAuthData> {
    let cdh = &client_data_of(&plan.client_data)?.hash;
    let (cert, report) = attestation::verify_strongbox(x5c, cdh)?;
    let point = cert.p256_point.expect("checked by verify_strongbox_leaf");

    let cred_id = &plan.credential_id;
    let mut ad = flags_and_counter(&plan.rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0);
    ad.extend_from_slice(&AAGUID);
    ad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    ad.extend_from_slice(cred_id);
    ad.extend_from_slice(&cose_es256(point)?);

    let mut tbs = ad.clone();
    tbs.extend_from_slice(cdh);
    Ok(RegistrationAuthData {
        authenticator_data: ad,
        to_be_signed: tbs,
        report,
    })
}

fn verify_sig(point: &[u8], msg: &[u8], der_sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::security("invalid public key"))?;
    let sig = Signature::from_der(der_sig).map_err(|_| Error::data("signature is not DER ECDSA"))?;
    vk.verify(msg, &sig)
        .map_err(|_| Error::security("signature does not verify against the attested key"))
}

fn client_data_json_b64(cd: &ClientData) -> String {
    cd.json.as_deref().map(|j| b64::encode(j.as_bytes())).unwrap_or_default()
}

pub struct RegistrationResult {
    pub response_json: String,
    pub public_key_spki: Vec<u8>,
}

pub fn registration_finish(
    plan: &RegistrationPlan,
    authenticator_data: &[u8],
    signature: &[u8],
    x5c: &[Vec<u8>],
) -> Result<RegistrationResult> {
    // Re-derive everything rather than trusting the caller-supplied authData.
    let expected = registration_auth_data(plan, x5c)?;
    if expected.authenticator_data != authenticator_data {
        return Err(Error::security("authenticatorData changed between steps"));
    }
    let leaf = attestation::parse_cert(&x5c[0])?;
    let point = leaf.p256_point.ok_or_else(|| Error::security("leaf key is not P-256"))?;
    verify_sig(point, &expected.to_be_signed, signature)?;

    let (fmt, att_stmt) = match plan.attestation_format() {
        AttestationFormat::AndroidKey => (
            "android-key",
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer(COSE_ALG_ES256.into())),
                (Value::Text("sig".into()), Value::Bytes(signature.to_vec())),
                (
                    Value::Text("x5c".into()),
                    Value::Array(x5c.iter().map(|c| Value::Bytes(c.clone())).collect()),
                ),
            ]),
        ),
        AttestationFormat::None => ("none", Value::Map(vec![])),
        AttestationFormat::Unspecified => return Err(Error::data("plan has no attestation format")),
    };
    let att_obj = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text(fmt.into())),
        (Value::Text("attStmt".into()), att_stmt),
        (Value::Text("authData".into()), Value::Bytes(authenticator_data.to_vec())),
    ]))?;

    let id = b64::encode(&plan.credential_id);
    let response = serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": client_data_json_b64(client_data_of(&plan.client_data)?),
            "attestationObject": b64::encode(&att_obj),
            "authenticatorData": b64::encode(authenticator_data),
            "publicKey": b64::encode(leaf.spki),
            "publicKeyAlgorithm": COSE_ALG_ES256,
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    Ok(RegistrationResult {
        response_json: response.to_string(),
        public_key_spki: leaf.spki.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// Cheap parse used while building the credential list (before the user has
/// picked anything and before we know the verified origin).
pub fn inspect_request(request_json: &str) -> Result<AssertionSummary> {
    let opts: RequestOptions = serde_json::from_str(request_json)?;
    Ok(AssertionSummary {
        rp_id: opts.rp_id.map(|r| r.to_ascii_lowercase()),
        allow_credentials: CredDescriptor::public_key_ids(&opts.allow_credentials)?,
    })
}

pub fn assertion_begin(
    request_json: &str,
    caller: &Caller,
    credential_id: &[u8],
    credential_rp_id: &str,
) -> Result<AssertionPlan> {
    let opts: RequestOptions = serde_json::from_str(request_json)?;
    let rp_id = resolve_rp_id(opts.rp_id.as_deref(), caller)?;

    // The credential must have been created for exactly this RP.
    if !credential_rp_id.eq_ignore_ascii_case(&rp_id) {
        return Err(Error::new(Code::NotAllowed, "credential is not registered for this RP"));
    }
    if !opts.allow_credentials.is_empty()
        && !CredDescriptor::public_key_ids(&opts.allow_credentials)?
            .iter()
            .any(|id| id == credential_id)
    {
        return Err(Error::new(Code::NotAllowed, "credential not in allowCredentials"));
    }
    Ok(AssertionPlan {
        client_data: Some(client_data("webauthn.get", &opts.challenge, caller)?),
        rp_id,
        credential_id: credential_id.to_vec(),
    })
}

pub struct AssertionAuthData {
    pub authenticator_data: Vec<u8>,
    pub to_be_signed: Vec<u8>,
}

pub fn assertion_auth_data(plan: &AssertionPlan, sign_count: u32) -> Result<AssertionAuthData> {
    let ad = flags_and_counter(&plan.rp_id, FLAG_UP | FLAG_UV, sign_count);
    let mut tbs = ad.clone();
    tbs.extend_from_slice(&client_data_of(&plan.client_data)?.hash);
    Ok(AssertionAuthData {
        authenticator_data: ad,
        to_be_signed: tbs,
    })
}

pub fn assertion_finish(
    plan: &AssertionPlan,
    authenticator_data: &[u8],
    signature: &[u8],
    user_handle: &[u8],
    public_key_spki: &[u8],
) -> Result<String> {
    if authenticator_data.len() != 37 || authenticator_data[..32] != Sha256::digest(plan.rp_id.as_bytes())[..] {
        return Err(Error::security("authenticatorData does not belong to this RP"));
    }
    let cd = client_data_of(&plan.client_data)?;
    let mut tbs = authenticator_data.to_vec();
    tbs.extend_from_slice(&cd.hash);
    verify_sig(spki_point(public_key_spki)?, &tbs, signature)?;

    let id = b64::encode(&plan.credential_id);
    Ok(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": client_data_json_b64(cd),
            "authenticatorData": b64::encode(authenticator_data),
            "signature": b64::encode(signature),
            "userHandle": b64::encode(user_handle),
        },
        "clientExtensionResults": {},
    })
    .to_string())
}

/// Extract the SEC1 point from a P-256 SubjectPublicKeyInfo.
fn spki_point(spki: &[u8]) -> Result<&[u8]> {
    // P-256 SPKI is a fixed 26-byte header followed by the 65-byte point.
    const HEADER: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    match spki.split_at_checked(26) {
        Some((h, p)) if h == HEADER && p.len() == 65 && p[0] == 0x04 => Ok(p),
        _ => Err(Error::data("public key is not an uncompressed P-256 SPKI")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web(origin: &str) -> Caller {
        Caller {
            origin: origin.into(),
            package_name: None,
            client_data_hash: None,
            trusted_rp_id: None,
        }
    }

    fn app(trusted_rp_id: Option<&str>) -> Caller {
        Caller {
            origin: format!("{APK_KEY_HASH_PREFIX}{}", b64::encode(&[7; 32])),
            package_name: Some("com.x".into()),
            client_data_hash: None,
            trusted_rp_id: trusted_rp_id.map(Into::into),
        }
    }

    #[test]
    fn rp_id_rules() {
        assert_eq!(resolve_rp_id(Some("example.com"), &web("https://login.example.com")).unwrap(), "example.com");
        assert!(resolve_rp_id(Some("example.com"), &web("https://evil-example.com")).is_err());
        assert!(resolve_rp_id(Some("example.com"), &web("http://example.com")).is_err());
        assert_eq!(resolve_rp_id(None, &web("https://a.b.c:8443/x")).unwrap(), "a.b.c");
    }

    #[test]
    fn app_callers_need_a_user_confirmed_binding() {
        // No binding, or a binding for another RP ID.
        assert_eq!(resolve_rp_id(Some("example.com"), &app(None)).err().unwrap().code, Code::NotAllowed);
        assert_eq!(resolve_rp_id(Some("example.com"), &app(Some("other.com"))).err().unwrap().code, Code::NotAllowed);
        // Apps have no origin to default the RP ID from.
        assert!(resolve_rp_id(None, &app(Some("example.com"))).is_err());

        assert_eq!(resolve_rp_id(Some("Example.com"), &app(Some("example.com"))).unwrap(), "example.com");

        let mut c = app(Some("example.com"));
        c.client_data_hash = Some(vec![9; 32]);
        assert_eq!(resolve_rp_id(Some("example.com"), &c).err().unwrap().code, Code::Security);

        let mut c = app(Some("example.com"));
        c.package_name = None;
        assert!(resolve_rp_id(Some("example.com"), &c).is_err());

        for origin in ["android:apk-key-hash:abc", "http://example.com", "example.com"] {
            let mut c = app(Some("example.com"));
            c.origin = origin.into();
            assert!(resolve_rp_id(Some("example.com"), &c).is_err(), "{origin}");
        }
    }

    #[test]
    fn app_client_data_names_the_package() {
        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com"},
            "user":{"id":"dXNlcg","name":"alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#;
        let s = inspect_registration(req).unwrap();
        assert_eq!((s.rp_id.as_deref(), s.user_id.as_slice(), s.user_name.as_str()), (Some("example.com"), &b"user"[..], "alice"));

        let caller = app(Some("example.com"));
        let plan = registration_begin(req, &caller, &[]).unwrap();
        let json = plan.client_data.unwrap().json.unwrap();
        assert!(json.contains(&format!(r#""origin":"{}""#, caller.origin)), "{json}");
        assert!(json.contains(r#""androidPackageName":"com.x""#), "{json}");
    }

    #[test]
    fn registration_plan_and_client_data() {
        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com","name":"Ex"},
            "user":{"id":"dXNlcg","name":"alice","displayName":"Alice"},
            "pubKeyCredParams":[{"type":"public-key","alg":-257},{"type":"public-key","alg":-7}],
            "attestation":"direct"}"#;
        let plan = registration_begin(req, &web("https://example.com"), &[]).unwrap();
        assert_eq!(plan.attestation_format(), AttestationFormat::AndroidKey);
        assert_eq!(plan.user_id, b"user");
        let json = plan.client_data.as_ref().unwrap().json.as_deref().unwrap();
        assert!(json.starts_with(r#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#), "{json}");
        assert_eq!(plan.credential_id.len(), 32);
    }

    #[test]
    fn browser_supplied_client_data_hash() {
        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com"},
            "user":{"id":"dXNlcg","name":"a"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#;
        let mut caller = web("https://example.com");
        caller.client_data_hash = Some(vec![9; 32]);
        let plan = registration_begin(req, &caller, &[]).unwrap();
        let cd = plan.client_data.unwrap();
        assert_eq!((cd.json, cd.hash), (None, vec![9; 32]));
        caller.client_data_hash = Some(vec![9; 31]);
        assert!(registration_begin(req, &caller, &[]).is_err());
    }

    #[test]
    fn rejects_without_es256() {
        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com"},
            "user":{"id":"dXNlcg","name":"a"},"pubKeyCredParams":[{"type":"public-key","alg":-8}]}"#;
        let e = registration_begin(req, &web("https://example.com"), &[]).err().unwrap();
        assert_eq!(e.code, Code::NotSupported);
    }

    #[test]
    fn exclude_credentials() {
        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com"},
            "user":{"id":"dXNlcg","name":"a"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "excludeCredentials":[{"type":"public-key","id":"AQID"}]}"#;
        let e = registration_begin(req, &web("https://example.com"), &[vec![1, 2, 3]]).err().unwrap();
        assert_eq!(e.code, Code::InvalidState);
    }

    #[test]
    fn assertion_roundtrip_with_software_key() {
        use p256::ecdsa::{SigningKey, signature::Signer};
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(point.as_bytes());

        let req = r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rpId":"example.com","allowCredentials":[]}"#;
        let id = [1u8, 2, 3];
        assert!(assertion_begin(req, &web("https://example.com"), &id, "other.com").is_err());
        let plan = assertion_begin(req, &web("https://example.com"), &id, "example.com").unwrap();
        let ad = assertion_auth_data(&plan, 5).unwrap();
        assert_eq!(ad.authenticator_data[32], FLAG_UP | FLAG_UV, "BE/BS must never be set");
        let sig: Signature = sk.sign(&ad.to_be_signed);
        let out = assertion_finish(&plan, &ad.authenticator_data, sig.to_der().as_bytes(), b"user", &spki).unwrap();
        assert!(out.contains(r#""userHandle":"dXNlcg""#), "{out}");

        let other = SigningKey::from_slice(&[8u8; 32]).unwrap();
        let bad: Signature = other.sign(&ad.to_be_signed);
        assert!(assertion_finish(&plan, &ad.authenticator_data, bad.to_der().as_bytes(), b"user", &spki).is_err());
    }
}
