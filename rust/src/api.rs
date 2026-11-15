// SPDX-License-Identifier: EUPL-1.2

//! Protobuf dispatcher behind the single JNI function. Decodes a
//! `pb::Request`, runs the operation, and encodes a `pb::Response`. Errors
//! travel as `Response.error` rather than as Java exceptions, so the FFI layer
//! stays trivial and every operation is testable on the host.
//!
//! Schema: `proto/hwbp/v1/core.proto`.

use crate::error::{Code, Error, Result};
use crate::pb::{self, request::Op, response::Result as Out};
use crate::webauthn;
use prost::Message;

pub fn dispatch(input: &[u8]) -> Vec<u8> {
    let result = match handle(input) {
        Ok(out) => out,
        Err(e) => Out::Error(pb::Error {
            code: error_code(e.code).into(),
            message: e.message,
        }),
    };
    pb::Response { result: Some(result) }.encode_to_vec()
}

fn error_code(c: Code) -> pb::ErrorCode {
    match c {
        Code::Data => pb::ErrorCode::Data,
        Code::NotSupported => pb::ErrorCode::NotSupported,
        Code::InvalidState => pb::ErrorCode::InvalidState,
        Code::NotAllowed => pb::ErrorCode::NotAllowed,
        Code::Security => pb::ErrorCode::Security,
    }
}

fn required<T>(v: Option<T>, what: &str) -> Result<T> {
    v.ok_or_else(|| Error::data(format!("missing {what}")))
}

fn handle(input: &[u8]) -> Result<Out> {
    let req = pb::Request::decode(input).map_err(|e| Error::data(format!("protobuf: {e}")))?;
    Ok(match required(req.op, "op")? {
        Op::Version(_) => Out::Version(version()),

        Op::RegistrationInspect(r) => Out::RegistrationSummary(webauthn::inspect_registration(&r.request_json)?),

        Op::RegistrationBegin(r) => Out::RegistrationPlan(webauthn::registration_begin(
            &r.request_json,
            &required(r.caller, "caller")?,
            &r.existing_credential_ids,
        )?),

        Op::RegistrationAuthData(r) => {
            let a = webauthn::registration_auth_data(&required(r.plan, "plan")?, &r.x5c)?;
            Out::ToSign(pb::ToSign {
                authenticator_data: a.authenticator_data,
                to_be_signed: a.to_be_signed,
                attestation: Some(a.report),
            })
        }

        Op::RegistrationFinish(r) => {
            let f = webauthn::registration_finish(
                &required(r.plan, "plan")?,
                &r.authenticator_data,
                &r.signature,
                &r.x5c,
            )?;
            Out::RegistrationFinish(pb::RegistrationFinishResponse {
                response_json: f.response_json,
                public_key_spki: f.public_key_spki,
            })
        }

        Op::AssertionInspect(r) => Out::AssertionSummary(webauthn::inspect_request(&r.request_json)?),

        Op::AssertionBegin(r) => Out::AssertionPlan(webauthn::assertion_begin(
            &r.request_json,
            &required(r.caller, "caller")?,
            &r.credential_id,
            &r.credential_rp_id,
        )?),

        Op::AssertionAuthData(r) => {
            let a = webauthn::assertion_auth_data(&required(r.plan, "plan")?, r.sign_count)?;
            Out::ToSign(pb::ToSign {
                authenticator_data: a.authenticator_data,
                to_be_signed: a.to_be_signed,
                attestation: None,
            })
        }

        Op::AssertionFinish(r) => Out::AssertionFinish(pb::AssertionFinishResponse {
            response_json: webauthn::assertion_finish(
                &required(r.plan, "plan")?,
                &r.authenticator_data,
                &r.signature,
                &r.user_handle,
                &r.public_key_spki,
            )?,
        }),

        Op::AttestationVerify(r) => {
            let (_, report) = crate::attestation::verify_strongbox(&r.x5c, &r.challenge)?;
            Out::AttestationReport(report)
        }
    })
}

fn version() -> pb::VersionResponse {
    #[cfg(feature = "chain-verification")]
    let chain = {
        let (entries, snapshot) = crate::chain::revocation_snapshot();
        pb::ChainVerification {
            enabled: true,
            revoked_entries: entries as u32,
            revocation_snapshot_unix: snapshot,
        }
    };
    #[cfg(not(feature = "chain-verification"))]
    let chain = pb::ChainVerification::default();
    pb::VersionResponse {
        chain_verification: Some(chain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(op: Op) -> Out {
        let bytes = dispatch(&pb::Request { op: Some(op) }.encode_to_vec());
        pb::Response::decode(bytes.as_slice()).unwrap().result.unwrap()
    }

    #[test]
    fn version() {
        let Out::Version(v) = call(Op::Version(pb::VersionRequest {})) else { panic!() };
        assert_eq!(v.chain_verification.unwrap().enabled, cfg!(feature = "chain-verification"));
    }

    #[test]
    fn errors_are_responses() {
        let Out::Error(e) = call(Op::AssertionInspect(pb::AssertionInspectRequest {
            request_json: "not json".into(),
        })) else {
            panic!()
        };
        assert_eq!(e.code(), pb::ErrorCode::Data);

        let garbage = pb::Response::decode(dispatch(&[0xff, 0xff]).as_slice()).unwrap();
        assert!(matches!(garbage.result, Some(Out::Error(_))));
    }

    #[test]
    fn missing_fields_rejected() {
        let Out::Error(e) = call(Op::RegistrationBegin(pb::RegistrationBeginRequest::default())) else {
            panic!()
        };
        assert!(e.message.contains("caller"), "{}", e.message);
    }
}
