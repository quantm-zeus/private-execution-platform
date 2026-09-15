//! Real WebAuthn passkey authentication boundary.
//!
//! # Credential-store contract (P0-9 documentation follow-up)
//!
//! Implementors of [`PasskeyCredentialStore`] hold credential material
//! (`Passkey` records, credential ids, counters) and MUST observe two
//! rules:
//!
//! 1. **Never log.** Store implementations must not log credential ids,
//!    public-key material, counters, passkey records, or error payloads
//!    that embed them. Errors are already opaque `AuthError` values;
//!    forward them without decoration. No administrative path in Phase 0
//!    should ever need credential data in a log line.
//! 2. **Never expose via `Debug`.** `Passkey` and credential-bearing
//!    types are third-party (webauthn-rs) values; do not wrap, clone, or
//!    re-derive `Debug`/`Display` implementations for them that could
//!    interpolate credential material. Redact at the boundary: types this
//!    crate defines around credential data implement `Debug` with
//!    `[REDACTED]`-style output, and store authors must preserve that
//!    discipline.
//!
//! Availability semantics: a store that cannot persist right now returns
//! [`AuthError::VerifierUnavailable`] (HTTP 503 territory), while a store
//! that answers but rejects the credential returns
//! [`AuthError::VerificationFailed`] (HTTP 401 territory). Implementors
//! must not conflate the two — the HTTP taxonomy depends on it.

use std::{fmt, sync::Arc};

#[cfg(test)]
use std::sync::Mutex;

#[cfg(any(test, feature = "private-test-support"))]
use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
#[cfg(any(test, feature = "private-test-support"))]
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::{AuthError, AuthenticationResult, Passkey};

pub trait PasskeyCredentialStore: Send + Sync {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError>;
    fn apply_authentication_result(&self, result: &AuthenticationResult) -> Result<(), AuthError>;

    /// Persist a freshly registered passkey.
    ///
    /// Only the public credential record (credential id, COSE public key,
    /// signature counter, transports) is ever handed to a store; a store must
    /// never persist private key material because none is produced by WebAuthn
    /// registration. The default is intentionally fail-closed: a store that has
    /// not implemented enrollment refuses rather than silently dropping the
    /// credential (which would make the next authentication fail with no
    /// diagnostic).
    fn register_passkey(&self, _passkey: Passkey) -> Result<(), AuthError> {
        Err(AuthError::VerifierUnavailable)
    }
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

    fn register_passkey(&self, passkey: Passkey) -> Result<(), AuthError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        if passkeys
            .iter()
            .any(|existing| existing.cred_id() == passkey.cred_id())
        {
            return Err(AuthError::CredentialConflict);
        }
        passkeys.push(passkey);
        Ok(())
    }
}

#[cfg(test)]
struct FailingResultStore {
    passkey: Passkey,
}

#[cfg(test)]
impl PasskeyCredentialStore for FailingResultStore {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
        Ok(vec![self.passkey.clone()])
    }

    fn apply_authentication_result(&self, _: &AuthenticationResult) -> Result<(), AuthError> {
        Err(AuthError::VerificationFailed)
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

/// Pending WebAuthn registration ceremony state.
///
/// Holds the single-use server challenge between the begin and finish steps.
/// It is never serialized, persisted or logged; `Debug` is redacted so an
/// accidental formatting cannot disclose the ceremony challenge.
pub struct PasskeyRegistrationAttempt {
    state: PasskeyRegistration,
}

impl fmt::Debug for PasskeyRegistrationAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyRegistrationAttempt([REDACTED])")
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
    pub(super) fn consume(self) {}
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

    /// Begin an operator-driven passkey enrollment ceremony.
    ///
    /// The caller is responsible for authenticating the enrollment request
    /// out-of-band (private-api gates this on an operator bootstrap secret);
    /// this method only performs the WebAuthn ceremony.
    pub fn start_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistrationAttempt), AuthError> {
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_unique_id, user_name, user_display_name, None)
            .map_err(|_| AuthError::VerificationFailed)?;
        Ok((options, PasskeyRegistrationAttempt { state }))
    }

    /// Finish an enrollment ceremony and durably register the credential.
    ///
    /// The credential is only considered enrolled after the store has
    /// persisted it; a store failure returns [`AuthError::VerifierUnavailable`]
    /// and no credential is registered.
    pub fn finish_registration(
        &self,
        attempt: PasskeyRegistrationAttempt,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AuthError> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &attempt.state)
            .map_err(|_| AuthError::VerificationFailed)?;
        self.store.register_passkey(passkey.clone())?;
        Ok(passkey)
    }

    /// Whether any credential is registered. Used to fail the enrollment
    /// surface closed before the WebAuthn ceremony when there is nothing to
    /// authenticate against.
    pub fn has_credentials(&self) -> Result<bool, AuthError> {
        Ok(!self.store.list_passkeys()?.is_empty())
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

#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
pub fn __private_test_origin() -> Url {
    Url::parse("https://example.com").unwrap()
}

#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
pub fn __private_test_origin_url() -> Url {
    Url::parse("https://example.com").unwrap()
}

#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
pub fn __private_test_uuid() -> Uuid {
    Uuid::new_v4()
}

#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
pub fn __private_test_client(falsify_uv: bool) -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(falsify_uv))
}

/// Concrete client type returned by [`__private_test_client`], for test code that
/// must retain the same authenticator instance across a ceremony.
#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
#[allow(non_camel_case_types)]
pub type __private_test_client_type = WebauthnAuthenticator<SoftPasskey>;

#[doc(hidden)]
#[cfg(any(test, feature = "private-test-support"))]
pub fn __private_test_server(origin: &Url) -> Webauthn {
    WebauthnBuilder::new("example.com", origin)
        .and_then(WebauthnBuilder::build)
        .unwrap()
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

    #[test]
    fn failed_store_application_mints_no_verified_capability_or_session() {
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

        let store: Arc<dyn PasskeyCredentialStore> = Arc::new(FailingResultStore { passkey });
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();
        let (request, attempt) = authenticator.start_authentication().unwrap();
        let credential = client.do_authentication(origin, request).unwrap();
        assert!(matches!(
            authenticator.finish_authentication(attempt, &credential),
            Err(AuthError::VerificationFailed)
        ));
    }

    #[test]
    fn registration_round_trip_enrolls_then_authenticates() {
        let origin = Url::parse("https://example.com").unwrap();
        let store: Arc<dyn PasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new(Vec::new()));
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();

        // No credential yet: the store is empty and authentication fails closed.
        assert!(!authenticator.has_credentials().unwrap());
        assert!(matches!(
            authenticator.start_authentication(),
            Err(AuthError::VerifierUnavailable)
        ));

        let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let (creation, attempt) = authenticator
            .start_registration(Uuid::new_v4(), "owner", "Owner")
            .unwrap();
        assert_eq!(
            format!("{attempt:?}"),
            "PasskeyRegistrationAttempt([REDACTED])"
        );
        let registration = client.do_registration(origin.clone(), creation).unwrap();
        let passkey = authenticator
            .finish_registration(attempt, &registration)
            .unwrap();
        assert!(authenticator.has_credentials().unwrap());

        // The just-enrolled credential authenticates with no restart.
        let (request, auth_attempt) = authenticator.start_authentication().unwrap();
        let credential = client.do_authentication(origin, request).unwrap();
        let verified = authenticator
            .finish_authentication(auth_attempt, &credential)
            .unwrap();
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedPasskeyAuthentication([REDACTED])"
        );

        // Re-registering the same credential is refused, never silently replaced.
        let concrete = InMemoryPasskeyCredentialStore::new(vec![passkey.clone()]);
        assert!(matches!(
            concrete.register_passkey(passkey),
            Err(AuthError::CredentialConflict)
        ));
    }

    #[test]
    fn store_without_enrollment_support_refuses_registration() {
        // `FailingResultStore` only overrides the two auth methods; the default
        // `register_passkey` must refuse rather than silently drop the credential.
        let origin = Url::parse("https://example.com").unwrap();
        let registration_server = WebauthnBuilder::new("example.com", &origin)
            .and_then(WebauthnBuilder::build)
            .unwrap();
        let (creation, registration_state) = registration_server
            .start_passkey_registration(Uuid::new_v4(), "owner", "Owner", None)
            .unwrap();
        let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = client.do_registration(origin, creation).unwrap();
        let existing = registration_server
            .finish_passkey_registration(&registration, &registration_state)
            .unwrap();
        let store: Arc<dyn PasskeyCredentialStore> =
            Arc::new(FailingResultStore { passkey: existing });

        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();
        let (creation, attempt) = authenticator
            .start_registration(Uuid::new_v4(), "owner", "Owner")
            .unwrap();
        let mut fresh_client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = fresh_client
            .do_registration(Url::parse("https://example.com").unwrap(), creation)
            .unwrap();
        assert!(matches!(
            authenticator.finish_registration(attempt, &registration),
            Err(AuthError::VerifierUnavailable)
        ));
    }
}
