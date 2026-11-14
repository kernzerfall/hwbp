// SPDX-License-Identifier: EUPL-1.2

//! HWBP core: WebAuthn payloads + StrongBox attestation policy.
//!
//! Design rule: **no private key material ever enters this library.** Keys are
//! generated and used exclusively inside StrongBox via Android Keystore; this
//! crate only builds the bytes to be signed, checks what the hardware attests
//! to, verifies signatures, and assembles responses.

pub mod api;

/// Generated from `proto/hwbp/v1/core.proto`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/hwbp.v1.rs"));
}

pub mod attestation;
#[cfg(feature = "chain-verification")]
pub mod chain;
pub mod der;
pub mod error;
pub mod webauthn;

mod b64 {
    use crate::error::{Error, Result};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

    pub fn encode(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    /// Lenient decode: accept base64url or standard alphabet, padded or not,
    /// since RPs are inconsistent about what they send.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        let s = s.trim_end_matches('=');
        URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| STANDARD_NO_PAD.decode(s))
            .map_err(|_| Error::data("invalid base64"))
    }
}

use jni::EnvUnowned;
use jni::objects::{JByteArray, JClass};

/// `k3r.hwbp.core.NativeCore.invoke(byte[]): byte[]`
#[unsafe(no_mangle)]
pub extern "system" fn Java_k3r_hwbp_core_NativeCore_invoke<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, jni::errors::Error> {
            let input = env.convert_byte_array(&request)?;
            let output = api::dispatch(&input);
            env.byte_array_from_slice(&output)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
