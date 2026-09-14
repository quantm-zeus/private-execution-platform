//! Server-side OKX API credentials.
//!
//! Credentials are held in [`zeroize::Zeroizing`] buffers, are readable only
//! inside this crate (`pub(crate)` accessors), and never implement `Serialize`,
//! `Clone`, `Display`, or a payload-bearing `Debug`. The only thing that leaves
//! the crate is the per-request [`crate::auth::OkxAuthHeaders`] (also redacted)
//! that a transport implementation needs to attach to a single call.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::OkxClientError;

/// Maximum accepted length of any single credential component.
pub const MAX_CREDENTIAL_BYTES: usize = 256;

/// Validated, redacted OKX API credentials.
pub struct OkxCredentials {
    api_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    passphrase: Zeroizing<String>,
}

impl OkxCredentials {
    /// Validates and constructs the credential set.
    ///
    /// Each component must be non-empty, at most [`MAX_CREDENTIAL_BYTES`] bytes,
    /// and printable non-space ASCII. Rejecting whitespace and control bytes
    /// prevents header/query injection through a credential field.
    pub fn new(
        api_key: impl Into<String>,
        secret_key: impl Into<String>,
        passphrase: impl Into<String>,
    ) -> Result<Self, OkxClientError> {
        let api_key = api_key.into();
        let secret_key = secret_key.into();
        let passphrase = passphrase.into();
        validate_component(&api_key)?;
        validate_component(&secret_key)?;
        validate_component(&passphrase)?;
        Ok(Self {
            api_key: Zeroizing::new(api_key),
            secret_key: Zeroizing::new(secret_key),
            passphrase: Zeroizing::new(passphrase),
        })
    }

    /// Read-only API key accessor; crate-internal only.
    pub(crate) fn api_key(&self) -> &str {
        self.api_key.as_str()
    }

    /// Read-only signing-secret accessor; crate-internal only.
    pub(crate) fn secret_key(&self) -> &str {
        self.secret_key.as_str()
    }

    /// Read-only passphrase accessor; crate-internal only.
    pub(crate) fn passphrase(&self) -> &str {
        self.passphrase.as_str()
    }
}

fn validate_component(value: &str) -> Result<(), OkxClientError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES {
        return Err(OkxClientError::InvalidCredentials);
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(OkxClientError::InvalidCredentials);
    }
    Ok(())
}

impl fmt::Debug for OkxCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OkxCredentials { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_credentials_construct_and_redact() {
        let credentials = OkxCredentials::new("key-abc", "secret-def", "pass-ghi").expect("valid");
        assert_eq!(credentials.api_key(), "key-abc");
        assert_eq!(credentials.secret_key(), "secret-def");
        assert_eq!(credentials.passphrase(), "pass-ghi");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("key-abc"));
        assert!(!debug.contains("secret-def"));
        assert!(!debug.contains("pass-ghi"));
    }

    #[test]
    fn empty_or_whitespace_credentials_fail_closed() {
        assert_eq!(
            OkxCredentials::new("", "s", "p").err(),
            Some(OkxClientError::InvalidCredentials)
        );
        assert_eq!(
            OkxCredentials::new("k", "s", "p q").err(),
            Some(OkxClientError::InvalidCredentials)
        );
        assert_eq!(
            OkxCredentials::new("k", "s\n", "p").err(),
            Some(OkxClientError::InvalidCredentials)
        );
    }

    #[test]
    fn overlong_credential_fails_closed() {
        let long = "a".repeat(MAX_CREDENTIAL_BYTES + 1);
        assert_eq!(
            OkxCredentials::new(long, "s", "p").err(),
            Some(OkxClientError::InvalidCredentials)
        );
    }
}
