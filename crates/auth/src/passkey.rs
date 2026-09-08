//! Real WebAuthn passkey authentication boundary.

use std::{fmt, sync::Arc};

#[cfg(test)]
use std::sync::Mutex;

use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use crate::AuthError;

pub trait PasskeyCredentialStore: Send + Sync {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError>;
    fn apply_authentication_result(&self, result: &AuthenticationResult) -> Result<(), AuthError>;
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryPasskeyCredentialStore {
    passkeys: Mutex<Vec<Passkey>>,
}

#[cfg(test)]
impl InMemoryPasskeyCredentialStore {
    pub fn new(passkeys: Vec<Passkey>) -> Self {
        Self {
            passkeys: Mutex::new(passkeys),
        }
    }
}

#[cfg(test)]
impl PasskeyCredentialStore for InMemoryPasskeyCredentialStore {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
        self.passkeys
            .lock()
            .map(|v| v.clone())
            .map_err(|_| AuthError::VerifierUnavailable)
    }

    fn apply_authentication_result(&self, result: &AuthenticationResult) -> Result<(), AuthError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        let passkey = passkeys
            .iter_mut()
            .find(|p| p.cred_id() == result.cred_id())
            .ok_or(AuthError::VerificationFailed)?;
        passkey
            .update_credential(result)
            .ok_or(AuthError::VerificationFailed)?;
        Ok(())
    }
}

pub struct AuthenticationAttempt {
    state: PasskeyAuthentication,
}

impl fmt::Debug for AuthenticationAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationAttempt([REDACTED])")
    }
}

pub struct VerifiedPasskeyAuthentication {
    _private: (),
}

impl fmt::Debug for VerifiedPasskeyAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPasskeyAuthentication([REDACTED])")
    }
}

impl VerifiedPasskeyAuthentication {
    pub(crate) fn consume(self) {}
}

pub struct WebAuthnPasskeyAuthenticator {
    webauthn: Webauthn,
    store: Arc<dyn PasskeyCredentialStore>,
}

impl WebAuthnPasskeyAuthenticator {
    pub fn new(
        rp_id: &str,
        origin: &str,
        store: Arc<dyn PasskeyCredentialStore>,
    ) -> Result<Self, AuthError> {
        let origin = Url::parse(origin).map_err(|_| AuthError::InvalidBinding)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.username() != ""
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(AuthError::InvalidBinding);
        }
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .and_then(WebauthnBuilder::build)
            .map_err(|_| AuthError::InvalidBinding)?;
        Ok(Self { webauthn, store })
    }

    pub fn start_authentication(
        &self,
    ) -> Result<(RequestChallengeResponse, AuthenticationAttempt), AuthError> {
        let passkeys = self.store.list_passkeys()?;
        if passkeys.is_empty() {
            return Err(AuthError::VerifierUnavailable);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AuthError::VerificationFailed)?;
        Ok((options, AuthenticationAttempt { state }))
    }

    pub fn finish_authentication(
        &self,
        attempt: AuthenticationAttempt,
        credential: &PublicKeyCredential,
    ) -> Result<VerifiedPasskeyAuthentication, AuthError> {
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &attempt.state)
            .map_err(|_| AuthError::VerificationFailed)?;
        self.store.apply_authentication_result(&result)?;
        Ok(VerifiedPasskeyAuthentication { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthState;
    use webauthn_authenticator_rs::{prelude::WebauthnAuthenticator, softpasskey::SoftPasskey};
    use webauthn_rs::prelude::Uuid;

    #[test]
    fn invalid_origin_and_empty_store_fail_closed() {
        let store: Arc<dyn PasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::default());
        assert!(matches!(
            WebAuthnPasskeyAuthenticator::new("example.com", "http://example.com", store.clone()),
            Err(AuthError::InvalidBinding)
        ));
        let auth =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();
        assert!(matches!(
            auth.start_authentication(),
            Err(AuthError::VerifierUnavailable)
        ));
    }

    #[test]
    fn rejects_non_default_origin_components_and_mismatched_rp() {
        let store: Arc<dyn PasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::default());
        for origin in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com?query",
            "https://example.com#fragment",
        ] {
            assert!(matches!(
                WebAuthnPasskeyAuthenticator::new("example.com", origin, store.clone()),
                Err(AuthError::InvalidBinding)
            ));
        }
        assert!(matches!(
            WebAuthnPasskeyAuthenticator::new("other.example", "https://example.com", store),
            Err(AuthError::InvalidBinding)
        ));
    }

    #[test]
    fn real_softpasskey_cryptographic_roundtrip_returns_sealed_capability() -> Result<(), AuthError>
    {
        let origin = Url::parse("https://example.com").unwrap();
        let registration_server = WebauthnBuilder::new("example.com", &origin)
            .and_then(WebauthnBuilder::build)
            .unwrap();
        let (creation, registration_state) = registration_server
            .start_passkey_registration(Uuid::new_v4(), "owner", "Owner", None)
            .unwrap();
        let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = client.do_registration(origin.clone(), creation).unwrap();
        let passkey = registration_server
            .finish_passkey_registration(&registration, &registration_state)
            .unwrap();

        let store: Arc<dyn PasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new(vec![passkey]));
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();
        let (request, attempt) = authenticator.start_authentication().unwrap();
        let credential = client.do_authentication(origin, request).unwrap();
        let verified = authenticator
            .finish_authentication(attempt, &credential)
            .unwrap();
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedPasskeyAuthentication([REDACTED])"
        );

        let mut auth_state = AuthState::new(60_000, 60_000, 60_000)?;
        let session = auth_state.create_session_from_verified(verified, 1_000)?;
        assert_eq!(session.expires_at_ms(), 61_000);
        auth_state.validate_session(session.id(), 60_999)?;
        assert_eq!(
            auth_state.validate_session(session.id(), 61_000),
            Err(AuthError::SessionExpired)
        );
        Ok(())
    }
}
