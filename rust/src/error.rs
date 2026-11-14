// SPDX-License-Identifier: EUPL-1.2

use std::fmt;

/// Error codes mirror the WebAuthn DOMException names the Kotlin side maps
/// onto Credential Manager exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Malformed input from the caller / platform.
    Data,
    /// The request can't be satisfied (e.g. no ES256 in pubKeyCredParams).
    NotSupported,
    /// excludeCredentials matched an existing credential.
    InvalidState,
    /// No usable credential / user refused.
    NotAllowed,
    /// Origin/RP mismatch, attestation not StrongBox, signature mismatch...
    Security,
}

#[derive(Debug, Clone, thiserror::Error)]
pub struct Error {
    pub code: Code,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn data(m: impl Into<String>) -> Self {
        Self::new(Code::Data, m)
    }
    pub fn security(m: impl Into<String>) -> Self {
        Self::new(Code::Security, m)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::data(format!("JSON: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
