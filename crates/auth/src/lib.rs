//! Authentication and private-workspace authorization boundary.

pub mod passkey;

pub use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PublicKeyCredential, RequestChallengeResponse,
};

use std::collections::HashMap;
use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

use passkey::VerifiedPasskeyAuthentication;

const TOKEN_BYTES: usize = 32;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, Hash, zeroize::ZeroizeOnDrop)]
        pub struct $name([u8; TOKEN_BYTES]);
        impl $name {
            fn random() -> Result<Self, AuthError> {
                Ok(Self(random_bytes()?))
            }
            /// Reference to the raw id bytes. Opaque ids are bearer references
            /// the legitimate holder already knows; exposing a borrow (never a
            /// copy or serialization) lets transports echo them back.
            pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_id!(SessionId);
opaque_id!(ArtifactGrantId);

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0u8; N];
    if getrandom::getrandom(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(AuthError::EntropyUnavailable);
    }
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedSession {
    id: SessionId,
    issued_at_ms: i64,
    expires_at_ms: i64,
}
impl AuthenticatedSession {
    pub fn id(&self) -> &SessionId {
        &self.id
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}
impl fmt::Debug for AuthenticatedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedSession")
            .field("id", &self.id)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactGrant {
    id: ArtifactGrantId,
    session_id: SessionId,
    issued_at_ms: i64,
    expires_at_ms: i64,
}
impl ArtifactGrant {
    pub fn id(&self) -> &ArtifactGrantId {
        &self.id
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}
impl fmt::Debug for ArtifactGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactGrant")
            .field("id", &self.id)
            .field("session_id", &"[REDACTED]")
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

pub struct AuthState {
    session_ttl_ms: i64,
    grant_ttl_ms: i64,
    sessions: HashMap<SessionId, AuthenticatedSession>,
    grants: HashMap<ArtifactGrantId, ArtifactGrant>,
}

impl AuthState {
    pub fn new(
        challenge_ttl_ms: i64,
        session_ttl_ms: i64,
        grant_ttl_ms: i64,
    ) -> Result<Self, AuthError> {
        // `challenge_ttl_ms` is retained as a validated input for API compatibility;
        // challenge issuance now lives entirely in the WebAuthn ceremony (passkey.rs).
        if challenge_ttl_ms <= 0 || session_ttl_ms <= 0 || grant_ttl_ms <= 0 {
            return Err(AuthError::InvalidTtl);
        }
        Ok(Self {
            session_ttl_ms,
            grant_ttl_ms,
            sessions: HashMap::new(),
            grants: HashMap::new(),
        })
    }

    fn mint_session(&mut self, now_ms: i64) -> Result<AuthenticatedSession, AuthError> {
        let expires_at_ms = now_ms
            .checked_add(self.session_ttl_ms)
            .ok_or(AuthError::InvalidTtl)?;
        let session = AuthenticatedSession {
            id: SessionId::random()?,
            issued_at_ms: now_ms,
            expires_at_ms,
        };
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    pub fn create_session_from_verified(
        &mut self,
        verified: VerifiedPasskeyAuthentication,
        now_ms: i64,
    ) -> Result<AuthenticatedSession, AuthError> {
        verified.consume();
        self.mint_session(now_ms)
    }

    pub fn validate_session(
        &self,
        id: &SessionId,
        now_ms: i64,
    ) -> Result<&AuthenticatedSession, AuthError> {
        let session = self.sessions.get(id).ok_or(AuthError::SessionNotFound)?;
        if now_ms < session.issued_at_ms {
            return Err(AuthError::InvalidTimestamp);
        }
        if now_ms >= session.expires_at_ms {
            return Err(AuthError::SessionExpired);
        }
        Ok(session)
    }

    pub fn issue_artifact_grant(
        &mut self,
        session_id: &SessionId,
        now_ms: i64,
    ) -> Result<ArtifactGrant, AuthError> {
        self.validate_session(session_id, now_ms)?;
        let expires_at_ms = now_ms
            .checked_add(self.grant_ttl_ms)
            .ok_or(AuthError::InvalidTtl)?;
        let grant = ArtifactGrant {
            id: ArtifactGrantId::random()?,
            session_id: session_id.clone(),
            issued_at_ms: now_ms,
            expires_at_ms,
        };
        self.grants.insert(grant.id.clone(), grant.clone());
        Ok(grant)
    }

    pub fn validate_artifact_grant(
        &self,
        id: &ArtifactGrantId,
        session_id: &SessionId,
        now_ms: i64,
    ) -> Result<&ArtifactGrant, AuthError> {
        self.validate_session(session_id, now_ms)?;
        let grant = self.grants.get(id).ok_or(AuthError::GrantNotFound)?;
        if &grant.session_id != session_id {
            return Err(AuthError::GrantSessionMismatch);
        }
        if now_ms < grant.issued_at_ms {
            return Err(AuthError::InvalidTimestamp);
        }
        if now_ms >= grant.expires_at_ms {
            return Err(AuthError::GrantExpired);
        }
        Ok(grant)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("secure entropy unavailable")]
    EntropyUnavailable,
    #[error("invalid ttl")]
    InvalidTtl,
    #[error("invalid authentication binding")]
    InvalidBinding,
    #[error("timestamp precedes issued time")]
    InvalidTimestamp,
    #[error("passkey verifier unavailable")]
    VerifierUnavailable,
    #[error("passkey verification failed")]
    VerificationFailed,
    #[error("session not found")]
    SessionNotFound,
    #[error("session expired")]
    SessionExpired,
    #[error("artifact grant not found")]
    GrantNotFound,
    #[error("artifact grant expired")]
    GrantExpired,
    #[error("artifact grant session mismatch")]
    GrantSessionMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AuthState {
        AuthState::new(100, 200, 50).unwrap()
    }

    /// Mints a genuine `VerifiedPasskeyAuthentication` through a real SoftPasskey
    /// registration + authentication ceremony, using the crate's test-only helpers.
    /// The deleted legacy raw-challenge verifier tests are covered by passkey.rs
    /// binding/fail-closed tests and the private-api HTTP ceremony tests.
    pub(super) fn genuine_verified() -> Result<VerifiedPasskeyAuthentication, AuthError> {
        use crate::passkey::{
            __private_test_client, __private_test_origin, __private_test_server,
            __private_test_uuid, InMemoryPasskeyCredentialStore, WebAuthnPasskeyAuthenticator,
        };
        use std::sync::Arc;

        let origin = __private_test_origin();
        let server = __private_test_server(&origin);
        let (creation, reg_state) = server
            .start_passkey_registration(__private_test_uuid(), "owner", "Owner", None)
            .map_err(|_| AuthError::VerificationFailed)?;
        let mut client = __private_test_client(true);
        let registration = client
            .do_registration(origin.clone(), creation)
            .map_err(|_| AuthError::VerificationFailed)?;
        let passkey = server
            .finish_passkey_registration(&registration, &reg_state)
            .map_err(|_| AuthError::VerificationFailed)?;

        let store: Arc<dyn crate::passkey::PasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new(vec![passkey]));
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store)?;
        let (request, attempt) = authenticator.start_authentication()?;
        let credential = client
            .do_authentication(origin, request)
            .map_err(|_| AuthError::VerificationFailed)?;
        authenticator.finish_authentication(attempt, &credential)
    }

    #[test]
    fn real_ceremony_mints_session_and_enforces_expiry() {
        let mut s = state();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        assert!(s.validate_session(session.id(), 200).is_ok());
        assert_eq!(
            s.validate_session(session.id(), 201),
            Err(AuthError::SessionExpired)
        );

        let mut s = state();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        let grant = s.issue_artifact_grant(session.id(), 2).unwrap();
        assert!(s
            .validate_artifact_grant(grant.id(), session.id(), 51)
            .is_ok());
        assert_eq!(
            s.validate_artifact_grant(grant.id(), session.id(), 52),
            Err(AuthError::GrantExpired)
        );
        assert!(format!("{session:?}{grant:?}").contains("[REDACTED]"));
    }
}

#[cfg(test)]
mod security_tests {
    use super::tests::genuine_verified;
    use super::*;

    #[test]
    fn session_and_grant_reject_time_before_issue() {
        let mut s = AuthState::new(100, 200, 50).unwrap();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 10).unwrap();
        let grant = s.issue_artifact_grant(session.id(), 10).unwrap();
        assert_eq!(
            s.validate_session(session.id(), 9),
            Err(AuthError::InvalidTimestamp)
        );
        assert_eq!(
            s.validate_artifact_grant(grant.id(), session.id(), 9),
            Err(AuthError::InvalidTimestamp)
        );
    }

    #[test]
    fn secret_ids_are_not_exposed_by_serialization_or_bytes_api() {
        let mut s = AuthState::new(100, 200, 50).unwrap();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        let grant = s.issue_artifact_grant(session.id(), 2).unwrap();
        let dbg = format!("{session:?}{grant:?}");
        assert!(dbg.contains("[REDACTED]"));
    }
}
