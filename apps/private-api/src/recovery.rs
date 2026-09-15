//! Additive, operator-owned passkey-bound workspace recovery wrappers.
//!
//! This module is deliberately *additive*: it does not change the existing
//! artifact, KID, unlock-secret derivation, or offline recovery-code path. A
//! workspace remains fully recoverable with the offline code alone; passkey
//! recovery is an optional convenience layered on top.
//!
//! ## Model
//!
//! The workspace root key material is the existing 32-byte high-entropy unlock
//! secret. It is never sent to the server. For each trusted recovery credential
//! the browser wraps that secret locally:
//!
//! ```text
//! passkey:  PRF output --HKDF-SHA256(salt, info)--> AES-256-GCM wrapping key
//!           --AES-256-GCM(secret)--> wrapped_root_key
//! offline:  recovery secret --same HKDF--> AES-256-GCM wrapping key
//!           --AES-256-GCM(secret)--> wrapped_root_key
//! ```
//!
//! Only the opaque ciphertext plus public metadata (credential id, label,
//! scheme, salt, IV, coarse lifecycle timestamps) is stored here. The PRF
//! output, the wrapping key and the unwrapped secret never reach the server.
//!
//! ## Authorization
//!
//! Mutating a wrapper (add/rotate/revoke) requires a **proof of possession of
//! the workspace private key** — that is, an existing trusted recovery factor,
//! not perimeter identity alone. The server seals a fresh random nonce to the
//! enrolled workspace public key (HPKE base mode, the same primitive that seals
//! the artifact) and accepts the mutation only when the client returns the
//! decrypted nonce. The server never learns the secret and never validates a
//! guess at it: it only checks that the client could open a challenge the
//! server itself produced. The challenge is single-use, session-bound and
//! TTL-bounded. Because the enrolled key must also match the release manifest's
//! recipient fingerprint before a challenge is issued, an attacker cannot
//! enroll a key they control and self-approve.
//!
//! A normal WebAuthn assertion signature is never used as key material.

use std::{
    collections::HashMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use auth::{AuthError, SessionId};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::base64_encode;
use crate::release::{decode_canonical_b64, decode_canonical_b64_variable};

/// Wrapper scheme version carried by every stored record.
pub const RECOVERY_WRAPPER_VERSION: u8 = 1;
/// Exact algorithm string bound into the record and the HKDF/AEAD AAD.
pub const RECOVERY_ALGORITHM: &str = "HKDF-SHA256/AES-256-GCM";
/// Identifies what the wrapper protects. `unlock_secret_v1` means the existing
/// offline unlock secret (the current artifact derivation input). A future
/// random-root-key migration must introduce a new value rather than reinterpret
/// existing records.
pub const RECOVERY_KEY_SOURCE_UNLOCK_SECRET_V1: &str = "unlock_secret_v1";
pub const RECOVERY_SALT_BYTES: usize = 32;
pub const RECOVERY_IV_BYTES: usize = 12;
/// AES-256-GCM ciphertext of a 32-byte secret (32 bytes plaintext + 16-byte tag).
pub const WRAPPED_ROOT_KEY_BYTES: usize = 48;
/// Upper bound on a WebAuthn credential id; real values are far smaller.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
/// Upper bound on the operator-visible label.
pub const MAX_RECOVERY_LABEL_BYTES: usize = 64;
/// Upper bound on stored wrappers per workspace.
pub const MAX_RECOVERY_WRAPPERS: usize = 32;

const RECOVERY_STORE_VERSION: u32 = 1;
/// Upper bound on the on-disk wrapper store; a larger file is refused rather
/// than read into memory.
const MAX_RECOVERY_STORE_BYTES: u64 = 1024 * 1024;

/// Random nonce sealed into a proof-of-possession challenge.
pub const RECOVERY_CHALLENGE_BYTES: usize = 32;
/// Random challenge identifier length (hex-encoded on the wire).
pub const RECOVERY_CHALLENGE_ID_BYTES: usize = 16;
/// Proof-of-possession challenge lifetime.
pub const RECOVERY_CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
/// Global bound on simultaneously pending challenges (mirrors the auth budget).
pub const MAX_PENDING_RECOVERY_CHALLENGES: usize = 32;
/// Per-session bound, so one authenticated session cannot consume the whole
/// global challenge set and deny wrapper mutation to every other session.
pub const MAX_PENDING_RECOVERY_CHALLENGES_PER_SESSION: usize = 4;

/// A stored wrapper. Contains no plaintext key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWrapperRecord {
    pub credential_id_b64: String,
    pub label: String,
    pub version: u8,
    pub algorithm: String,
    pub key_source: String,
    pub salt_b64: String,
    pub iv_b64: String,
    pub wrapped_root_key_b64: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub last_used_at_ms: Option<i64>,
    #[serde(default)]
    pub revoked_at_ms: Option<i64>,
}

/// Client-supplied wrapper fields. Lifecycle timestamps are server-owned.
#[derive(Debug, Clone, Deserialize)]
pub struct RecoveryWrapperInput {
    pub credential_id_b64: String,
    pub label: String,
    pub version: u8,
    pub algorithm: String,
    pub key_source: String,
    pub salt_b64: String,
    pub iv_b64: String,
    pub wrapped_root_key_b64: String,
}

/// Why a client-supplied wrapper or challenge request was refused. Deliberately
/// coarse: the HTTP layer maps it to a bounded status, so no detail is echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryInputError {
    /// A bounded public field was missing, oversized, non-canonical or unknown.
    Invalid,
}

impl RecoveryWrapperInput {
    /// Validate every bounded public field and re-canonicalize the base64 so a
    /// non-canonical encoding cannot create two records for one credential.
    pub fn into_record(self, now_ms: i64) -> Result<RecoveryWrapperRecord, RecoveryInputError> {
        let credential_id = decode_canonical_b64_variable(&self.credential_id_b64)
            .ok_or(RecoveryInputError::Invalid)?;
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(RecoveryInputError::Invalid);
        }
        let trimmed = self.label.trim();
        if trimmed.len() > MAX_RECOVERY_LABEL_BYTES || trimmed.chars().any(char::is_control) {
            return Err(RecoveryInputError::Invalid);
        }
        let label = if trimmed.is_empty() {
            "Recovery passkey".to_string()
        } else {
            trimmed.to_string()
        };
        if self.version != RECOVERY_WRAPPER_VERSION
            || self.algorithm != RECOVERY_ALGORITHM
            || self.key_source != RECOVERY_KEY_SOURCE_UNLOCK_SECRET_V1
        {
            return Err(RecoveryInputError::Invalid);
        }
        if decode_canonical_b64(&self.salt_b64, RECOVERY_SALT_BYTES).is_none()
            || decode_canonical_b64(&self.iv_b64, RECOVERY_IV_BYTES).is_none()
            || decode_canonical_b64(&self.wrapped_root_key_b64, WRAPPED_ROOT_KEY_BYTES).is_none()
        {
            return Err(RecoveryInputError::Invalid);
        }
        Ok(RecoveryWrapperRecord {
            credential_id_b64: base64_encode(&credential_id),
            label,
            version: RECOVERY_WRAPPER_VERSION,
            algorithm: RECOVERY_ALGORITHM.to_string(),
            key_source: RECOVERY_KEY_SOURCE_UNLOCK_SECRET_V1.to_string(),
            salt_b64: self.salt_b64,
            iv_b64: self.iv_b64,
            wrapped_root_key_b64: self.wrapped_root_key_b64,
            created_at_ms: now_ms,
            last_used_at_ms: None,
            revoked_at_ms: None,
        })
    }
}

/// Constant-time equality for proof nonces. Length is not secret, but the
/// comparison is still constant-time to avoid a timing oracle on the nonce.
pub fn proof_matches(proof: &[u8], expected: &[u8]) -> bool {
    proof.len() == expected.len() && proof.ct_eq(expected).into()
}

/// Durable, operator-owned wrapper store.
pub trait RecoveryWrapperStore: Send + Sync {
    fn list(&self) -> Result<Vec<RecoveryWrapperRecord>, AuthError>;
    /// Insert or replace the record for its credential id. Re-adding a revoked
    /// credential clears the revocation and preserves the original creation
    /// time.
    fn upsert(&self, record: RecoveryWrapperRecord) -> Result<(), AuthError>;
    /// Soft-revoke a credential. Returns `true` when a live record was changed.
    fn revoke(&self, credential_id_b64: &str, now_ms: i64) -> Result<bool, AuthError>;
    /// Record a coarse last-used timestamp for a live credential.
    fn touch(&self, credential_id_b64: &str, now_ms: i64) -> Result<(), AuthError>;
}

/// Pending proof-of-possession challenge. The nonce is zeroized on drop.
pub struct PendingRecoveryChallenge {
    nonce: Zeroizing<Vec<u8>>,
    session_id: SessionId,
    expires_at_ms: i64,
}

/// Bounded in-memory challenge set. Challenges never persist: a process restart
/// simply invalidates outstanding proofs.
#[derive(Default)]
pub struct RecoveryChallengeState {
    pending: HashMap<String, PendingRecoveryChallenge>,
}

impl RecoveryChallengeState {
    fn prune(&mut self, now_ms: i64) {
        self.pending
            .retain(|_, challenge| challenge.expires_at_ms > now_ms);
    }

    /// Register a fresh challenge. Errors when the global pending budget is
    /// exhausted, so a caller cannot grow server memory without bound.
    pub fn issue(
        &mut self,
        now_ms: i64,
        session_id: SessionId,
        challenge_id: String,
        nonce: Vec<u8>,
    ) -> Result<(), RecoveryInputError> {
        self.prune(now_ms);
        if self.pending.len() >= MAX_PENDING_RECOVERY_CHALLENGES {
            return Err(RecoveryInputError::Invalid);
        }
        let session_pending = self
            .pending
            .values()
            .filter(|challenge| challenge.session_id == session_id)
            .count();
        if session_pending >= MAX_PENDING_RECOVERY_CHALLENGES_PER_SESSION {
            return Err(RecoveryInputError::Invalid);
        }
        self.pending.insert(
            challenge_id,
            PendingRecoveryChallenge {
                nonce: Zeroizing::new(nonce),
                session_id,
                expires_at_ms: now_ms.saturating_add(RECOVERY_CHALLENGE_TTL_MS),
            },
        );
        Ok(())
    }

    /// Single-use consume bound to the authenticated session. A mismatched
    /// session or an expired/unknown id leaves the challenge untouched, so one
    /// caller cannot destroy another session's outstanding challenge; a matching
    /// session always removes it, success or (proof) failure, so a failed proof
    /// cannot be replayed.
    pub fn consume(
        &mut self,
        now_ms: i64,
        challenge_id: &str,
        session_id: &SessionId,
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.prune(now_ms);
        match self.pending.get(challenge_id) {
            Some(challenge)
                if challenge.expires_at_ms > now_ms && challenge.session_id == *session_id => {}
            _ => return None,
        }
        self.pending
            .remove(challenge_id)
            .map(|challenge| challenge.nonce)
    }
}

#[derive(Serialize, Deserialize)]
struct RecoveryStoreDocument {
    version: u32,
    #[serde(default)]
    wrappers: Vec<RecoveryWrapperRecord>,
}

/// File-backed [`RecoveryWrapperStore`] with the same on-disk safety properties
/// as the passkey credential store: atomic owner-only writes, refused symlinks,
/// checked inode/permissions, and a bounded document size.
pub struct FileRecoveryWrapperStore {
    path: PathBuf,
    wrappers: Mutex<Vec<RecoveryWrapperRecord>>,
}

impl fmt::Debug for FileRecoveryWrapperStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileRecoveryWrapperStore([REDACTED])")
    }
}

impl FileRecoveryWrapperStore {
    /// Open (or create) the store at `path`. A missing file is an empty store;
    /// every other failure refuses startup.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let path = path.into();
        let wrappers = load_wrappers(&path)?;
        Ok(Self {
            path,
            wrappers: Mutex::new(wrappers),
        })
    }

    /// Configured store path (not secret; useful for diagnostics and tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self, wrappers: &[RecoveryWrapperRecord]) -> Result<(), AuthError> {
        let document = RecoveryStoreDocument {
            version: RECOVERY_STORE_VERSION,
            wrappers: wrappers.to_vec(),
        };
        let bytes = serde_json::to_vec(&document).map_err(|_| AuthError::VerifierUnavailable)?;
        let temp_path = unique_temp_path(&self.path)?;
        let write_result = write_private_file(&temp_path, &bytes).and_then(|()| {
            fs::rename(&temp_path, &self.path).map_err(|_| std::io::Error::other("rename failed"))
        });
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
            return Err(AuthError::VerifierUnavailable);
        }
        if let Some(parent) = self.path.parent() {
            if let Ok(directory) = fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }
}

impl RecoveryWrapperStore for FileRecoveryWrapperStore {
    fn list(&self) -> Result<Vec<RecoveryWrapperRecord>, AuthError> {
        self.wrappers
            .lock()
            .map(|wrappers| wrappers.clone())
            .map_err(|_| AuthError::VerifierUnavailable)
    }

    fn upsert(&self, record: RecoveryWrapperRecord) -> Result<(), AuthError> {
        let mut wrappers = self
            .wrappers
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        let mut updated = wrappers.clone();
        match updated
            .iter_mut()
            .find(|existing| existing.credential_id_b64 == record.credential_id_b64)
        {
            Some(existing) => {
                let created_at_ms = existing.created_at_ms;
                let last_used_at_ms = existing.last_used_at_ms;
                *existing = record;
                existing.created_at_ms = created_at_ms;
                existing.last_used_at_ms = last_used_at_ms;
                existing.revoked_at_ms = None;
            }
            None => {
                if updated.len() >= MAX_RECOVERY_WRAPPERS {
                    return Err(AuthError::CredentialConflict);
                }
                updated.push(record);
            }
        }
        self.persist(&updated)?;
        *wrappers = updated;
        Ok(())
    }

    fn revoke(&self, credential_id_b64: &str, now_ms: i64) -> Result<bool, AuthError> {
        let mut wrappers = self
            .wrappers
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        let mut updated = wrappers.clone();
        let Some(existing) = updated
            .iter_mut()
            .find(|existing| existing.credential_id_b64 == credential_id_b64)
        else {
            return Ok(false);
        };
        if existing.revoked_at_ms.is_some() {
            return Ok(false);
        }
        existing.revoked_at_ms = Some(now_ms);
        self.persist(&updated)?;
        *wrappers = updated;
        Ok(true)
    }

    fn touch(&self, credential_id_b64: &str, now_ms: i64) -> Result<(), AuthError> {
        let mut wrappers = self
            .wrappers
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        let mut updated = wrappers.clone();
        let Some(existing) = updated.iter_mut().find(|existing| {
            existing.credential_id_b64 == credential_id_b64 && existing.revoked_at_ms.is_none()
        }) else {
            return Ok(());
        };
        existing.last_used_at_ms = Some(now_ms);
        self.persist(&updated)?;
        *wrappers = updated;
        Ok(())
    }
}

fn load_wrappers(path: &Path) -> Result<Vec<RecoveryWrapperRecord>, AuthError> {
    let Some((metadata, file)) = open_private_file(path)? else {
        return Ok(Vec::new());
    };
    if metadata.len() > MAX_RECOVERY_STORE_BYTES {
        return Err(AuthError::VerifierUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RECOVERY_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::VerifierUnavailable)?;
    if bytes.len() as u64 > MAX_RECOVERY_STORE_BYTES {
        return Err(AuthError::VerifierUnavailable);
    }
    let document: RecoveryStoreDocument =
        serde_json::from_slice(&bytes).map_err(|_| AuthError::VerifierUnavailable)?;
    if document.version != RECOVERY_STORE_VERSION || document.wrappers.len() > MAX_RECOVERY_WRAPPERS
    {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(document.wrappers)
}

/// Open an existing private store file after validating the parent directory,
/// the opened inode and its ownership/permissions. `Ok(None)` means the store
/// does not exist yet.
fn open_private_file(path: &Path) -> Result<Option<(fs::Metadata, fs::File)>, AuthError> {
    use std::os::unix::fs::OpenOptionsExt;

    check_parent_directory(path)?;
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuthError::VerifierUnavailable),
    };
    if !link_metadata.is_file() {
        return Err(AuthError::VerifierUnavailable);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| AuthError::VerifierUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| AuthError::VerifierUnavailable)?;
    if !metadata.is_file() || !same_file(&link_metadata, &metadata) {
        return Err(AuthError::VerifierUnavailable);
    }
    check_private_permissions(&metadata)?;
    Ok(Some((metadata, file)))
}

#[cfg(unix)]
fn check_private_permissions(metadata: &fs::Metadata) -> Result<(), AuthError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.mode() & 0o077 != 0 {
        return Err(AuthError::VerifierUnavailable);
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid && metadata.uid() != 0 {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_metadata: &fs::Metadata) -> Result<(), AuthError> {
    Ok(())
}

#[cfg(unix)]
fn check_parent_directory(path: &Path) -> Result<(), AuthError> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent).map_err(|_| AuthError::VerifierUnavailable)?;
    // Group- OR world-writable: another local principal could rename/replace the
    // store between our checks, so refuse the directory entirely.
    if metadata.mode() & 0o022 != 0 {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_parent_directory(_path: &Path) -> Result<(), AuthError> {
    Ok(())
}

#[cfg(unix)]
fn same_file(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(not(unix))]
fn same_file(_first: &fs::Metadata, _second: &fs::Metadata) -> bool {
    true
}

fn unique_temp_path(path: &Path) -> Result<PathBuf, AuthError> {
    let file_name = path
        .file_name()
        .ok_or(AuthError::VerifierUnavailable)?
        .to_owned();
    let mut random = [0u8; 8];
    if getrandom::getrandom(&mut random).is_err() {
        return Err(AuthError::VerifierUnavailable);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(16);
    for byte in random {
        suffix.push(HEX[(byte >> 4) as usize] as char);
        suffix.push(HEX[(byte & 0x0f) as usize] as char);
    }
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".{suffix}.tmp"));
    Ok(path.with_file_name(temp_name))
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> SessionId {
        auth::__private_test_session_id()
    }

    fn valid_input() -> RecoveryWrapperInput {
        RecoveryWrapperInput {
            credential_id_b64: base64_encode(&[0x11; 32]),
            label: "Studio MacBook".to_string(),
            version: RECOVERY_WRAPPER_VERSION,
            algorithm: RECOVERY_ALGORITHM.to_string(),
            key_source: RECOVERY_KEY_SOURCE_UNLOCK_SECRET_V1.to_string(),
            salt_b64: base64_encode(&[0x22; RECOVERY_SALT_BYTES]),
            iv_b64: base64_encode(&[0x33; RECOVERY_IV_BYTES]),
            wrapped_root_key_b64: base64_encode(&[0x44; WRAPPED_ROOT_KEY_BYTES]),
        }
    }

    #[test]
    fn input_validation_accepts_valid_and_rejects_every_field() {
        let record = valid_input().into_record(10).unwrap();
        assert_eq!(record.label, "Studio MacBook");
        assert_eq!(record.created_at_ms, 10);
        assert_eq!(record.last_used_at_ms, None);
        assert_eq!(record.revoked_at_ms, None);

        // Empty label falls back to a neutral default.
        let mut empty_label = valid_input();
        empty_label.label = "   ".to_string();
        assert_eq!(
            empty_label.into_record(0).unwrap().label,
            "Recovery passkey"
        );

        let mut too_long = valid_input();
        too_long.wrapped_root_key_b64 = base64_encode(&[0x44; WRAPPED_ROOT_KEY_BYTES + 1]);
        assert!(too_long.into_record(0).is_err());

        let mut wrong_version = valid_input();
        wrong_version.version = 2;
        assert!(wrong_version.into_record(0).is_err());

        let mut wrong_algorithm = valid_input();
        wrong_algorithm.algorithm = "rot13".to_string();
        assert!(wrong_algorithm.into_record(0).is_err());

        let mut wrong_source = valid_input();
        wrong_source.key_source = "root_key_v2".to_string();
        assert!(wrong_source.into_record(0).is_err());

        let mut short_salt = valid_input();
        short_salt.salt_b64 = base64_encode(&[0x22; 16]);
        assert!(short_salt.into_record(0).is_err());

        let mut short_iv = valid_input();
        short_iv.iv_b64 = base64_encode(&[0x33; 8]);
        assert!(short_iv.into_record(0).is_err());

        let mut empty_credential = valid_input();
        empty_credential.credential_id_b64 = String::new();
        assert!(empty_credential.into_record(0).is_err());

        let mut noncanonical = valid_input();
        noncanonical.credential_id_b64 = format!("{}!", noncanonical.credential_id_b64);
        assert!(noncanonical.into_record(0).is_err());

        let mut control_label = valid_input();
        control_label.label = "bad\u{7}label".to_string();
        assert!(control_label.into_record(0).is_err());
    }

    #[test]
    fn proof_comparison_is_exact() {
        assert!(proof_matches(&[1, 2, 3], &[1, 2, 3]));
        assert!(!proof_matches(&[1, 2, 3], &[1, 2, 4]));
        assert!(!proof_matches(&[1, 2], &[1, 2, 3]));
        assert!(!proof_matches(&[], &[1]));
    }

    #[test]
    fn sealed_challenge_only_opens_with_the_workspace_key() {
        use crypto_envelope::{
            derive_workspace_keypair, seal_artifact, ARTIFACT_VERSION, UNLOCK_SECRET_LEN,
        };

        let secret = [0x5A; UNLOCK_SECRET_LEN];
        let kid = [0x11; auth::WORKSPACE_KID_BYTES];
        let keypair = derive_workspace_keypair(&secret, ARTIFACT_VERSION, &kid).unwrap();
        let nonce = vec![7u8; RECOVERY_CHALLENGE_BYTES];
        let sealed = seal_artifact(
            &crypto_envelope::hpke::HpkePublicKey(keypair.public_key_bytes()),
            ARTIFACT_VERSION,
            &kid,
            &nonce,
        )
        .unwrap();
        let opened = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        assert!(proof_matches(&opened, &nonce));

        let wrong =
            derive_workspace_keypair(&[0x5B; UNLOCK_SECRET_LEN], ARTIFACT_VERSION, &kid).unwrap();
        assert!(crypto_envelope::decrypt_artifact(&wrong, &sealed).is_err());
    }

    #[test]
    fn challenge_is_single_use_session_bound_and_bounded() {
        let mut state = RecoveryChallengeState::default();
        let session = session_id();
        let other = session_id();
        state
            .issue(0, session.clone(), "abc".to_string(), vec![9; 32])
            .unwrap();

        // Wrong session cannot consume nor destroy the challenge.
        assert!(state.consume(0, "abc", &other).is_none());
        let nonce = state.consume(0, "abc", &session).expect("nonce");
        assert_eq!(&nonce[..], &[9u8; 32]);
        // Single use.
        assert!(state.consume(0, "abc", &session).is_none());

        // Expiry.
        state
            .issue(0, session.clone(), "exp".to_string(), vec![7; 32])
            .unwrap();
        assert!(state
            .consume(RECOVERY_CHALLENGE_TTL_MS + 1, "exp", &session)
            .is_none());

        // Unknown id.
        assert!(state.consume(0, "missing", &session).is_none());

        // Per-session budget: one session cannot exhaust the global set, so a
        // single authenticated caller cannot deny wrapper mutation to others.
        let mut per_session = RecoveryChallengeState::default();
        for index in 0..MAX_PENDING_RECOVERY_CHALLENGES_PER_SESSION {
            per_session
                .issue(0, session.clone(), format!("s{index}"), vec![1; 32])
                .unwrap();
        }
        assert!(per_session
            .issue(0, session.clone(), "s-over".to_string(), vec![1; 32])
            .is_err());
        // A different session can still issue while the first is saturated.
        assert!(per_session
            .issue(0, other.clone(), "other".to_string(), vec![1; 32])
            .is_ok());

        // Global budget across distinct sessions.
        let mut full = RecoveryChallengeState::default();
        for index in 0..MAX_PENDING_RECOVERY_CHALLENGES {
            full.issue(0, session_id(), format!("c{index}"), vec![1; 32])
                .unwrap();
        }
        assert!(full
            .issue(0, session_id(), "overflow".to_string(), vec![1; 32])
            .is_err());
    }

    #[test]
    fn file_store_roundtrips_owner_only_and_survives_reload() {
        let directory = private_dir();
        let path = directory.path().join("recovery.json");
        let record = valid_input().into_record(5).unwrap();
        {
            let store = FileRecoveryWrapperStore::open(&path).unwrap();
            assert!(store.list().unwrap().is_empty());
            store.upsert(record.clone()).unwrap();
            assert_eq!(store.list().unwrap().len(), 1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let reloaded = FileRecoveryWrapperStore::open(&path).unwrap();
        let listed = reloaded.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].credential_id_b64, record.credential_id_b64);
        assert_eq!(listed[0].created_at_ms, 5);
    }

    #[test]
    fn file_store_upsert_revoke_touch_and_bounds() {
        let directory = private_dir();
        let path = directory.path().join("recovery.json");
        let store = FileRecoveryWrapperStore::open(&path).unwrap();
        let mut record = valid_input().into_record(5).unwrap();
        record.credential_id_b64 = base64_encode(&[0xAB; 32]);
        store.upsert(record.clone()).unwrap();

        // Re-upsert preserves creation time and clears revocation.
        store.revoke(&record.credential_id_b64, 50).unwrap();
        assert_eq!(store.list().unwrap()[0].revoked_at_ms, Some(50));
        let mut replacement = record.clone();
        replacement.label = "New label".to_string();
        store.upsert(replacement).unwrap();
        let current = &store.list().unwrap()[0];
        assert_eq!(current.created_at_ms, 5);
        assert_eq!(current.revoked_at_ms, None);
        assert_eq!(current.label, "New label");

        // Revoke is idempotent and reports unknown ids.
        assert!(store.revoke(&record.credential_id_b64, 60).unwrap());
        assert!(!store.revoke(&record.credential_id_b64, 61).unwrap());
        assert!(!store.revoke("unknown", 0).unwrap());

        // Touch a live record only.
        let live = valid_input().into_record(5).unwrap();
        store.upsert(live.clone()).unwrap();
        store.touch(&live.credential_id_b64, 99).unwrap();
        assert_eq!(
            store
                .list()
                .unwrap()
                .iter()
                .find(|r| r.credential_id_b64 == live.credential_id_b64)
                .unwrap()
                .last_used_at_ms,
            Some(99)
        );

        // Wrapper count bound.
        for index in 0..MAX_RECOVERY_WRAPPERS {
            let mut extra = valid_input().into_record(0).unwrap();
            extra.credential_id_b64 = base64_encode(&[index as u8; 32]);
            extra.label = format!("device {index}");
            let _ = store.upsert(extra);
        }
        let mut overflow = valid_input().into_record(0).unwrap();
        overflow.credential_id_b64 = base64_encode(&[0xFF; 32]);
        assert!(store.upsert(overflow).is_err());
    }

    #[test]
    fn corrupt_symlinked_and_group_readable_stores_refuse_startup() {
        let directory = private_dir();
        let corrupt = directory.path().join("corrupt.json");
        fs::write(&corrupt, b"not json").unwrap();
        #[cfg(unix)]
        set_mode(&corrupt, 0o600);
        assert!(FileRecoveryWrapperStore::open(&corrupt).is_err());

        let wrong_version = directory.path().join("version.json");
        fs::write(&wrong_version, br#"{"version":99,"wrappers":[]}"#).unwrap();
        #[cfg(unix)]
        set_mode(&wrong_version, 0o600);
        assert!(FileRecoveryWrapperStore::open(&wrong_version).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let target = directory.path().join("real.json");
            fs::write(&target, br#"{"version":1,"wrappers":[]}"#).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(FileRecoveryWrapperStore::open(&link).is_err());

            // Group/other readable is refused even with valid content.
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(FileRecoveryWrapperStore::open(&target).is_err());
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A store directory that satisfies the owner-only parent check. `tempfile`
    /// honours `$TMPDIR`, which may be group/world-writable, so tests create an
    /// explicitly private directory instead of relying on the ambient temp root.
    fn private_dir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        set_mode(directory.path(), 0o700);
        directory
    }

    #[test]
    fn debug_never_exposes_wrapper_material() {
        let directory = private_dir();
        let store = FileRecoveryWrapperStore::open(directory.path().join("recovery.json")).unwrap();
        assert_eq!(format!("{store:?}"), "FileRecoveryWrapperStore([REDACTED])");
    }
}
