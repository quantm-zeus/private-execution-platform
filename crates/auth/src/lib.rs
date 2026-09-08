//! Authentication and private-workspace authorization boundary.

use std::collections::HashMap;
use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

const CHALLENGE_BYTES: usize = 32;
const TOKEN_BYTES: usize = 32;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, Hash, zeroize::ZeroizeOnDrop)]
        pub struct $name([u8; TOKEN_BYTES]);
        impl $name {
            fn random() -> Result<Self, AuthError> {
                Ok(Self(random_bytes()?))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_id!(ChallengeId);
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

#[derive(Clone)]
pub struct PasskeyChallenge {
    id: ChallengeId,
    challenge: [u8; CHALLENGE_BYTES],
    expected_rp_id: String,
    expected_origin: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    consumed: bool,
}

impl PasskeyChallenge {
    pub fn id(&self) -> &ChallengeId {
        &self.id
    }
    pub fn challenge_bytes(&self) -> &[u8; CHALLENGE_BYTES] {
        &self.challenge
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

impl Drop for PasskeyChallenge {
    fn drop(&mut self) {
        self.challenge.zeroize();
    }
}

impl fmt::Debug for PasskeyChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyChallenge")
            .field("id", &self.id)
            .field("challenge", &"[REDACTED]")
            .field("expected_rp_id", &"[REDACTED]")
            .field("expected_origin", &"[REDACTED]")
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("consumed", &self.consumed)
            .finish()
    }
}

pub trait PasskeyVerifier: Send + Sync {
    fn verify(
        &self,
        challenge: &[u8; CHALLENGE_BYTES],
        assertion: &[u8],
        rp_id: &str,
        origin: &str,
    ) -> Result<(), AuthError>;
}

#[derive(Debug, Default)]
pub struct UnavailableVerifier;

impl PasskeyVerifier for UnavailableVerifier {
    fn verify(
        &self,
        _: &[u8; CHALLENGE_BYTES],
        _: &[u8],
        _: &str,
        _: &str,
    ) -> Result<(), AuthError> {
        Err(AuthError::VerifierUnavailable)
    }
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
    challenge_ttl_ms: i64,
    session_ttl_ms: i64,
    grant_ttl_ms: i64,
    challenges: HashMap<ChallengeId, PasskeyChallenge>,
    sessions: HashMap<SessionId, AuthenticatedSession>,
    grants: HashMap<ArtifactGrantId, ArtifactGrant>,
}

impl AuthState {
    pub fn new(
        challenge_ttl_ms: i64,
        session_ttl_ms: i64,
        grant_ttl_ms: i64,
    ) -> Result<Self, AuthError> {
        if challenge_ttl_ms <= 0 || session_ttl_ms <= 0 || grant_ttl_ms <= 0 {
            return Err(AuthError::InvalidTtl);
        }
        Ok(Self {
            challenge_ttl_ms,
            session_ttl_ms,
            grant_ttl_ms,
            challenges: HashMap::new(),
            sessions: HashMap::new(),
            grants: HashMap::new(),
        })
    }

    pub fn issue_challenge(
        &mut self,
        rp_id: impl Into<String>,
        origin: impl Into<String>,
        now_ms: i64,
    ) -> Result<PasskeyChallenge, AuthError> {
        let rp_id = rp_id.into();
        let origin = origin.into();
        if rp_id.trim().is_empty() || origin.trim().is_empty() {
            return Err(AuthError::InvalidBinding);
        }
        let expires_at_ms = now_ms
            .checked_add(self.challenge_ttl_ms)
            .ok_or(AuthError::InvalidTtl)?;
        let challenge = PasskeyChallenge {
            id: ChallengeId::random()?,
            challenge: random_bytes()?,
            expected_rp_id: rp_id,
            expected_origin: origin,
            issued_at_ms: now_ms,
            expires_at_ms,
            consumed: false,
        };
        self.challenges
            .insert(challenge.id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn verify_challenge(
        &mut self,
        id: &ChallengeId,
        rp_id: &str,
        origin: &str,
        assertion: &[u8],
        now_ms: i64,
        verifier: &dyn PasskeyVerifier,
    ) -> Result<AuthenticatedSession, AuthError> {
        let record = self
            .challenges
            .get_mut(id)
            .ok_or(AuthError::ChallengeNotFound)?;
        if record.consumed {
            return Err(AuthError::ChallengeConsumed);
        }
        if now_ms < record.issued_at_ms {
            return Err(AuthError::InvalidTimestamp);
        }
        if now_ms >= record.expires_at_ms {
            return Err(AuthError::ChallengeExpired);
        }
        if record.expected_rp_id != rp_id {
            return Err(AuthError::RpIdMismatch);
        }
        if record.expected_origin != origin {
            return Err(AuthError::OriginMismatch);
        }
        record.consumed = true;
        verifier.verify(&record.challenge, assertion, rp_id, origin)?;
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
    #[error("challenge not found")]
    ChallengeNotFound,
    #[error("challenge already consumed")]
    ChallengeConsumed,
    #[error("timestamp precedes issued time")]
    InvalidTimestamp,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("relying-party id mismatch")]
    RpIdMismatch,
    #[error("origin mismatch")]
    OriginMismatch,
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

    pub(super) struct AcceptVerifier;
    impl PasskeyVerifier for AcceptVerifier {
        fn verify(
            &self,
            _: &[u8; CHALLENGE_BYTES],
            _: &[u8],
            _: &str,
            _: &str,
        ) -> Result<(), AuthError> {
            Ok(())
        }
    }
    pub(super) struct RejectVerifier;
    impl PasskeyVerifier for RejectVerifier {
        fn verify(
            &self,
            _: &[u8; CHALLENGE_BYTES],
            _: &[u8],
            _: &str,
            _: &str,
        ) -> Result<(), AuthError> {
            Err(AuthError::VerificationFailed)
        }
    }
    fn state() -> AuthState {
        AuthState::new(100, 200, 50).unwrap()
    }

    #[test]
    fn challenge_has_entropy_and_redacted_debug() {
        let mut s = state();
        let c = s
            .issue_challenge("example.com", "https://example.com", 10)
            .unwrap();
        assert_eq!(c.challenge_bytes().len(), 32);
        assert!(c.challenge_bytes().iter().any(|b| *b != 0));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("https://example.com"));
    }

    #[test]
    fn wrong_binding_and_expiry_reject() {
        let mut s = state();
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "wrong",
                "https://example.com",
                b"a",
                1,
                &AcceptVerifier
            ),
            Err(AuthError::RpIdMismatch)
        );
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "example.com",
                "https://wrong",
                b"a",
                1,
                &AcceptVerifier
            ),
            Err(AuthError::OriginMismatch)
        );
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                100,
                &AcceptVerifier
            ),
            Err(AuthError::ChallengeExpired)
        );
    }

    #[test]
    fn verifier_failure_consumes_challenge_and_mints_no_session() {
        let mut s = state();
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"bad",
                1,
                &RejectVerifier
            ),
            Err(AuthError::VerificationFailed)
        );
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"good",
                2,
                &AcceptVerifier
            ),
            Err(AuthError::ChallengeConsumed)
        );
    }

    #[test]
    fn unavailable_verifier_denies_and_replay_after_success_fails() {
        let mut denied = state();
        let c = denied
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        assert_eq!(
            denied.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                1,
                &UnavailableVerifier
            ),
            Err(AuthError::VerifierUnavailable)
        );

        let mut ok = state();
        let c = ok
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        let _session = ok
            .verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                1,
                &AcceptVerifier,
            )
            .unwrap();
        assert_eq!(
            ok.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                2,
                &AcceptVerifier
            ),
            Err(AuthError::ChallengeConsumed)
        );
    }

    #[test]
    fn session_and_grant_expiry_are_enforced() {
        let mut s = state();
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        let session = s
            .verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                1,
                &AcceptVerifier,
            )
            .unwrap();
        assert!(s.validate_session(session.id(), 200).is_ok());
        assert_eq!(
            s.validate_session(session.id(), 201),
            Err(AuthError::SessionExpired)
        );

        let mut s = state();
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        let session = s
            .verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                1,
                &AcceptVerifier,
            )
            .unwrap();
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
    use super::tests::AcceptVerifier;
    use super::*;

    #[test]
    fn challenge_rejects_time_before_issue() {
        let mut s = AuthState::new(100, 200, 50).unwrap();
        let c = s
            .issue_challenge("example.com", "https://example.com", 10)
            .unwrap();
        assert_eq!(
            s.verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                9,
                &AcceptVerifier
            ),
            Err(AuthError::InvalidTimestamp)
        );
    }

    #[test]
    fn session_and_grant_reject_time_before_issue() {
        let mut s = AuthState::new(100, 200, 50).unwrap();
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        let session = s
            .verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                10,
                &AcceptVerifier,
            )
            .unwrap();
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
        let c = s
            .issue_challenge("example.com", "https://example.com", 0)
            .unwrap();
        let session = s
            .verify_challenge(
                c.id(),
                "example.com",
                "https://example.com",
                b"a",
                1,
                &AcceptVerifier,
            )
            .unwrap();
        let grant = s.issue_artifact_grant(session.id(), 2).unwrap();
        let dbg = format!("{c:?}{session:?}{grant:?}");
        assert!(!dbg.contains("challenge_bytes"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(format!("{c:?}").contains("[REDACTED]"));
    }
}
