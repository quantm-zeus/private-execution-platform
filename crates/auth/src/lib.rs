//! Authentication and private-workspace authorization boundary.

pub mod passkey;

pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
};

use std::collections::HashMap;
use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

use passkey::VerifiedPasskeyAuthentication;

const TOKEN_BYTES: usize = 32;
pub const WORKSPACE_PUBLIC_KEY_BYTES: usize = 32;
pub const WORKSPACE_KID_BYTES: usize = 16;
pub const ARTIFACT_VERSION: u8 = 1;
/// Bounded live-grant budget (MEDIUM-1 fix). Grants are TTL-pruned on every
/// mint; beyond this many simultaneously live grants, issue_artifact_grant
/// fails with VerifierUnavailable (HTTP 503) instead of growing memory.
const MAX_LIVE_ARTIFACT_GRANTS: usize = 1024;
const MAX_LIVE_WORKSPACE_ENROLLMENTS: usize = 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct WorkspacePublicKeyMetadata {
    version: u8,
    kid: [u8; WORKSPACE_KID_BYTES],
    public_key: [u8; WORKSPACE_PUBLIC_KEY_BYTES],
    enrolled_at_ms: i64,
}

impl WorkspacePublicKeyMetadata {
    pub fn new(
        version: u8,
        kid: [u8; WORKSPACE_KID_BYTES],
        public_key: [u8; WORKSPACE_PUBLIC_KEY_BYTES],
        enrolled_at_ms: i64,
    ) -> Result<Self, AuthError> {
        if version != ARTIFACT_VERSION {
            return Err(AuthError::UnsupportedVersion);
        }
        if kid.iter().all(|&b| b == 0) || public_key.iter().all(|&b| b == 0) {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self {
            version,
            kid,
            public_key,
            enrolled_at_ms,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn kid(&self) -> &[u8; WORKSPACE_KID_BYTES] {
        &self.kid
    }

    pub fn public_key(&self) -> &[u8; WORKSPACE_PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    pub fn enrolled_at_ms(&self) -> i64 {
        self.enrolled_at_ms
    }
}

impl fmt::Debug for WorkspacePublicKeyMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspacePublicKeyMetadata")
            .field("version", &self.version)
            .field("kid", &self.kid)
            .field("public_key", &self.public_key)
            .field("enrolled_at_ms", &self.enrolled_at_ms)
            .finish()
    }
}

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
    enrollments: HashMap<SessionId, WorkspacePublicKeyMetadata>,
    /// Upper bound on live grants so a minting loop cannot grow this ledger
    /// without bound (MEDIUM-1 fix: bounded per-process grant budget).
    max_live_grants: usize,
    max_live_enrollments: usize,
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
            enrollments: HashMap::new(),
            max_live_grants: MAX_LIVE_ARTIFACT_GRANTS,
            max_live_enrollments: MAX_LIVE_WORKSPACE_ENROLLMENTS,
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

    /// Session identity binding expectations (P0-9 documentation
    /// follow-up) for `create_session_from_verified`.
    ///
    /// Today a session is an opaque [`SessionId`] minted after a
    /// successful WebAuthn ceremony and stored only inside this process's
    /// [`AuthState`]; the HTTP layer binds it to a single random transport
    /// token (cookie). With exactly one credential store this is
    /// unambiguous.
    ///
    /// When Phase 0+ introduces additional credential stores (e.g. a
    /// Postgres-backed store alongside the in-process one), the session
    /// MUST be bound to the authenticated identity — the credential id /
    /// user handle proven by the ceremony — rather than to the store
    /// instance that happened to verify it. Concretely:
    ///
    /// - `VerifiedPasskeyAuthentication` must carry (or be extended with)
    ///   the credential identity so the session records *who* verified,
    ///   not just *that* verification succeeded.
    /// - Session lookup must resolve by that identity so a store swap or
    ///   a second store cannot mint a parallel, unlinked session family.
    /// - Single-use, TTL, and fail-closed defaults are unchanged by this
    ///   binding; it only constrains future store plumbing.
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
        // Drop expired grants first so steady-state minting cannot exhaust the
        // bounded ledger; then refuse beyond the live-grant budget (503-class
        // failure at the HTTP layer, matching VerifierUnavailable semantics).
        self.grants.retain(|_, grant| grant.expires_at_ms > now_ms);
        if self.grants.len() >= self.max_live_grants {
            return Err(AuthError::VerifierUnavailable);
        }
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

    pub fn enroll_workspace_public_key(
        &mut self,
        session_id: &SessionId,
        version: u8,
        kid: [u8; WORKSPACE_KID_BYTES],
        public_key: [u8; WORKSPACE_PUBLIC_KEY_BYTES],
        now_ms: i64,
    ) -> Result<WorkspacePublicKeyMetadata, AuthError> {
        self.validate_session(session_id, now_ms)?;
        if version != ARTIFACT_VERSION {
            return Err(AuthError::UnsupportedVersion);
        }
        if kid.iter().all(|&b| b == 0) || public_key.iter().all(|&b| b == 0) {
            return Err(AuthError::InvalidInput);
        }
        if self.enrollments.contains_key(session_id) {
            return Err(AuthError::EnrollmentConflict);
        }
        self.enrollments.retain(|sid, _| {
            self.sessions
                .get(sid)
                .is_some_and(|s| s.expires_at_ms() > now_ms)
        });
        if self.enrollments.len() >= self.max_live_enrollments {
            return Err(AuthError::VerifierUnavailable);
        }
        let metadata = WorkspacePublicKeyMetadata {
            version,
            kid,
            public_key,
            enrolled_at_ms: now_ms,
        };
        self.enrollments
            .insert(session_id.clone(), metadata.clone());
        Ok(metadata)
    }

    pub fn get_workspace_enrollment(
        &self,
        session_id: &SessionId,
        now_ms: i64,
    ) -> Result<&WorkspacePublicKeyMetadata, AuthError> {
        self.validate_session(session_id, now_ms)?;
        self.enrollments
            .get(session_id)
            .ok_or(AuthError::EnrollmentNotFound)
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
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("invalid input")]
    InvalidInput,
    #[error("workspace enrollment conflict")]
    EnrollmentConflict,
    #[error("workspace enrollment not found")]
    EnrollmentNotFound,
    #[error("passkey credential already registered")]
    CredentialConflict,
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

    #[test]
    fn grant_ledger_is_bounded_and_ttl_pruned() {
        let mut s = state();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        // Fill the bounded budget; further mints fail closed without growing.
        for _ in 0..MAX_LIVE_ARTIFACT_GRANTS {
            s.issue_artifact_grant(session.id(), 2).unwrap();
        }
        assert_eq!(
            s.issue_artifact_grant(session.id(), 2),
            Err(AuthError::VerifierUnavailable)
        );
        // Time passes the 50 ms grant TTL: all grants prune, budget recovers.
        s.issue_artifact_grant(session.id(), 53).unwrap();
    }

    #[test]
    fn workspace_public_key_enrollment_succeeds_and_rejects_duplicate_or_conflict() {
        let mut s = state();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        let kid = [1u8; WORKSPACE_KID_BYTES];
        let public_key = [2u8; WORKSPACE_PUBLIC_KEY_BYTES];

        // Valid enrollment succeeds
        let meta = s
            .enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, kid, public_key, 10)
            .unwrap();
        assert_eq!(meta.version(), ARTIFACT_VERSION);
        assert_eq!(meta.kid(), &kid);
        assert_eq!(meta.public_key(), &public_key);
        assert_eq!(meta.enrolled_at_ms(), 10);

        // Fetching enrollment returns same metadata
        let fetched = s.get_workspace_enrollment(session.id(), 15).unwrap();
        assert_eq!(fetched, &meta);

        // Duplicate enrollment with identical key fails closed with Conflict
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, kid, public_key, 20),
            Err(AuthError::EnrollmentConflict)
        );

        // Conflicting enrollment with different key fails closed with Conflict
        let other_pk = [3u8; WORKSPACE_PUBLIC_KEY_BYTES];
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, kid, other_pk, 20),
            Err(AuthError::EnrollmentConflict)
        );
    }

    #[test]
    fn workspace_public_key_enrollment_rejects_invalid_inputs() {
        let mut s = state();
        let verified = genuine_verified().unwrap();
        let session = s.create_session_from_verified(verified, 1).unwrap();
        let valid_kid = [1u8; WORKSPACE_KID_BYTES];
        let valid_pk = [2u8; WORKSPACE_PUBLIC_KEY_BYTES];

        // Unsupported version
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), 2, valid_kid, valid_pk, 5),
            Err(AuthError::UnsupportedVersion)
        );

        // All-zero kid
        let zero_kid = [0u8; WORKSPACE_KID_BYTES];
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, zero_kid, valid_pk, 5),
            Err(AuthError::InvalidInput)
        );

        // All-zero public key
        let zero_pk = [0u8; WORKSPACE_PUBLIC_KEY_BYTES];
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, valid_kid, zero_pk, 5),
            Err(AuthError::InvalidInput)
        );

        // Expired session rejected
        assert_eq!(
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, valid_kid, valid_pk, 201),
            Err(AuthError::SessionExpired)
        );

        // Unknown session rejected
        let unknown_session = SessionId::random().unwrap();
        assert_eq!(
            s.enroll_workspace_public_key(
                &unknown_session,
                ARTIFACT_VERSION,
                valid_kid,
                valid_pk,
                5
            ),
            Err(AuthError::SessionNotFound)
        );
    }

    #[test]
    fn workspace_enrollment_ledger_is_bounded_and_pruned() {
        let mut s = state();
        let kid = [1u8; WORKSPACE_KID_BYTES];
        let pk = [2u8; WORKSPACE_PUBLIC_KEY_BYTES];

        // Create MAX_LIVE_WORKSPACE_ENROLLMENTS sessions and enroll each
        let mut sessions = Vec::new();
        for _ in 0..MAX_LIVE_WORKSPACE_ENROLLMENTS {
            let session = s.mint_session(1).unwrap();
            s.enroll_workspace_public_key(session.id(), ARTIFACT_VERSION, kid, pk, 2)
                .unwrap();
            sessions.push(session);
        }

        // Additional enrollment on another session exceeds budget
        let extra_session = s.mint_session(1).unwrap();
        assert_eq!(
            s.enroll_workspace_public_key(extra_session.id(), ARTIFACT_VERSION, kid, pk, 2),
            Err(AuthError::VerifierUnavailable)
        );

        // Advance clock past session TTL (200 ms) so old sessions expire
        // Mint new session and enroll: expired enrollments are pruned and budget recovers
        let recovered_session = s.mint_session(205).unwrap();
        assert!(s
            .enroll_workspace_public_key(recovered_session.id(), ARTIFACT_VERSION, kid, pk, 205)
            .is_ok());
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

    #[test]
    fn workspace_public_key_metadata_holds_only_public_data() {
        let kid = [0x42u8; WORKSPACE_KID_BYTES];
        let pk = [0x55u8; WORKSPACE_PUBLIC_KEY_BYTES];
        let meta = WorkspacePublicKeyMetadata::new(ARTIFACT_VERSION, kid, pk, 100).unwrap();
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("WorkspacePublicKeyMetadata"));
        assert!(dbg.contains("version: 1"));
        assert!(!dbg.contains("secret"));
        assert!(!dbg.contains("private"));
    }
}
