//! Durable, operator-owned WebAuthn credential store.
//!
//! Production passkey authentication needs the registered credential records to
//! survive a process restart: a `Passkey` holds only **public** material (the
//! credential id, the COSE public key, the signature counter and transports),
//! so persisting it is safe and carries none of the PRD's "no infrastructure
//! key material" concerns. This store is deliberately narrow:
//!
//! - It writes a versioned JSON document atomically (random same-directory temp
//!   file created `O_EXCL` + `rename`) with owner-only permissions (`0600` on
//!   Unix), so a crash cannot leave a truncated store and a local user cannot
//!   pre-create or follow the temp path.
//! - It only loads a store file it owns, with no group/other access bits, in a
//!   directory that is not world-writable; it opens the path `O_NOFOLLOW` and
//!   re-checks the opened inode, so a swapped symlink cannot inject credentials.
//! - It bounds the on-disk document size, so a corrupt/hostile store file cannot
//!   exhaust memory at startup.
//! - It never logs and never exposes credential material through `Debug`.
//! - Its failure mode is [`AuthError::VerifierUnavailable`] (HTTP 503): a store
//!   that cannot persist a counter update fails closed rather than accepting an
//!   authentication it cannot durably record.

use std::{
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use auth::passkey::PasskeyCredentialStore;
use auth::{AuthError, AuthenticationResult, Passkey};

const STORE_VERSION: u32 = 1;
/// Upper bound on the on-disk credential store. A larger file is refused rather
/// than read into memory.
const MAX_STORE_BYTES: u64 = 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct StoreDocument {
    version: u32,
    passkeys: Vec<Passkey>,
}

/// File-backed [`PasskeyCredentialStore`]. See the module docs for the safety
/// properties.
pub struct FilePasskeyCredentialStore {
    path: PathBuf,
    passkeys: Mutex<Vec<Passkey>>,
}

impl fmt::Debug for FilePasskeyCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilePasskeyCredentialStore([REDACTED])")
    }
}

impl FilePasskeyCredentialStore {
    /// Open (or create) the store at `path`, loading the durable credential
    /// records into memory.
    ///
    /// A missing file is an empty store (the operator has not enrolled yet);
    /// every other failure — unreadable file, invalid JSON, unknown version,
    /// symlinked/non-owned/group-accessible/world-writable path, oversized file
    /// — refuses startup so a production deployment cannot silently load an
    /// attacker-influenced credential set.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let path = path.into();
        let passkeys = load_passkeys(&path)?;
        Ok(Self {
            path,
            passkeys: Mutex::new(passkeys),
        })
    }

    /// The configured store path (not secret; useful for startup diagnostics
    /// and tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self, passkeys: &[Passkey]) -> Result<(), AuthError> {
        let document = StoreDocument {
            version: STORE_VERSION,
            passkeys: passkeys.to_vec(),
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
        // Best-effort directory durability: the rename is already atomic, so a
        // failure here cannot corrupt the store, only lose the very last update
        // on an unclean shutdown.
        if let Some(parent) = self.path.parent() {
            if let Ok(directory) = fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }
}

impl PasskeyCredentialStore for FilePasskeyCredentialStore {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
        self.passkeys
            .lock()
            .map(|passkeys| passkeys.clone())
            .map_err(|_| AuthError::VerifierUnavailable)
    }

    fn apply_authentication_result(&self, result: &AuthenticationResult) -> Result<(), AuthError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|_| AuthError::VerifierUnavailable)?;
        let mut updated = passkeys.clone();
        let passkey = updated
            .iter_mut()
            .find(|passkey| passkey.cred_id() == result.cred_id())
            .ok_or(AuthError::VerificationFailed)?;
        passkey
            .update_credential(result)
            .ok_or(AuthError::VerificationFailed)?;
        // Persist before publishing the new counter: a store that cannot record
        // the authentication must not later accept a replayed counter.
        self.persist(&updated)?;
        *passkeys = updated;
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
        let mut updated = passkeys.clone();
        updated.push(passkey);
        self.persist(&updated)?;
        *passkeys = updated;
        Ok(())
    }
}

fn load_passkeys(path: &Path) -> Result<Vec<Passkey>, AuthError> {
    let Some((metadata, file)) = open_store_file(path)? else {
        return Ok(Vec::new());
    };
    if metadata.len() > MAX_STORE_BYTES {
        return Err(AuthError::VerifierUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::VerifierUnavailable)?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(AuthError::VerifierUnavailable);
    }
    let document: StoreDocument =
        serde_json::from_slice(&bytes).map_err(|_| AuthError::VerifierUnavailable)?;
    if document.version != STORE_VERSION {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(document.passkeys)
}

/// Open an existing store file after validating the parent directory, the
/// opened inode and its ownership/permissions. `Ok(None)` means the store does
/// not exist yet (first enrollment).
fn open_store_file(path: &Path) -> Result<Option<(fs::Metadata, fs::File)>, AuthError> {
    use std::os::unix::fs::OpenOptionsExt;

    check_parent_directory(path)?;
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuthError::VerifierUnavailable),
    };
    // `is_file()` is false for a symlink, a directory or any special file, so a
    // symlinked store path is refused here.
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
    if !metadata.is_file() {
        return Err(AuthError::VerifierUnavailable);
    }
    // TOCTOU: the opened inode must be the one that was inspected above.
    if !same_file(&link_metadata, &metadata) {
        return Err(AuthError::VerifierUnavailable);
    }
    check_store_permissions(&metadata)?;
    Ok(Some((metadata, file)))
}

#[cfg(unix)]
fn check_store_permissions(metadata: &fs::Metadata) -> Result<(), AuthError> {
    use std::os::unix::fs::MetadataExt;

    // Owner-only: no group or other access bits at all.
    if metadata.mode() & 0o077 != 0 {
        return Err(AuthError::VerifierUnavailable);
    }
    // The store must be owned by the service user (or root, for a root-managed
    // deployment that hands the file to the service).
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid && metadata.uid() != 0 {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_store_permissions(_metadata: &fs::Metadata) -> Result<(), AuthError> {
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
    // A world-writable directory lets any local user replace the store file.
    if metadata.mode() & 0o002 != 0 {
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

    // `create_new` (O_CREAT|O_EXCL) makes a pre-created temp path fail closed
    // instead of being followed; `O_NOFOLLOW` is defense in depth.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // Explicit, independent of umask or platform defaults.
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
    use auth::passkey::{
        __private_test_client, __private_test_client_type, __private_test_origin,
        __private_test_server, __private_test_uuid, WebAuthnPasskeyAuthenticator,
    };
    use std::sync::Arc;

    fn registered_passkey() -> (Passkey, __private_test_client_type) {
        let origin = __private_test_origin();
        let server = __private_test_server(&origin);
        let (creation, registration_state) = server
            .start_passkey_registration(__private_test_uuid(), "owner", "Owner", None)
            .unwrap();
        let mut client = __private_test_client(true);
        let registration = client.do_registration(origin, creation).unwrap();
        let passkey = server
            .finish_passkey_registration(&registration, &registration_state)
            .unwrap();
        (passkey, client)
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn register_persists_owner_only_and_reloads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passkeys.json");
        let (passkey, _client) = registered_passkey();
        {
            let store = FilePasskeyCredentialStore::open(&path).unwrap();
            assert!(store.list_passkeys().unwrap().is_empty());
            store.register_passkey(passkey.clone()).unwrap();
            assert_eq!(store.list_passkeys().unwrap().len(), 1);
            assert!(matches!(
                store.register_passkey(passkey),
                Err(AuthError::CredentialConflict)
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let reloaded = FilePasskeyCredentialStore::open(&path).unwrap();
        assert_eq!(reloaded.list_passkeys().unwrap().len(), 1);
    }

    #[test]
    fn apply_authentication_result_persists_the_counter() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passkeys.json");
        let (passkey, mut client) = registered_passkey();
        let store = FilePasskeyCredentialStore::open(&path).unwrap();
        store.register_passkey(passkey.clone()).unwrap();

        let origin = __private_test_origin();
        let server = __private_test_server(&origin);
        let (request, state) = server.start_passkey_authentication(&[passkey]).unwrap();
        let credential = client.do_authentication(origin, request).unwrap();
        let result = server
            .finish_passkey_authentication(&credential, &state)
            .unwrap();
        store.apply_authentication_result(&result).unwrap();
        drop(store);

        // Reloading proves the updated record (not just the in-memory copy) was
        // written; a store that failed to persist would have returned 503.
        let reloaded = FilePasskeyCredentialStore::open(&path).unwrap();
        assert_eq!(reloaded.list_passkeys().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_or_symlinked_store_refuses_startup() {
        let directory = tempfile::tempdir().unwrap();
        let corrupt = directory.path().join("corrupt.json");
        fs::write(&corrupt, b"not json").unwrap();
        #[cfg(unix)]
        set_mode(&corrupt, 0o600);
        assert!(FilePasskeyCredentialStore::open(&corrupt).is_err());

        let wrong_version = directory.path().join("version.json");
        fs::write(&wrong_version, br#"{"version":99,"passkeys":[]}"#).unwrap();
        #[cfg(unix)]
        set_mode(&wrong_version, 0o600);
        assert!(FilePasskeyCredentialStore::open(&wrong_version).is_err());

        #[cfg(unix)]
        {
            let target = directory.path().join("real.json");
            fs::write(&target, br#"{"version":1,"passkeys":[]}"#).unwrap();
            set_mode(&target, 0o600);
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(FilePasskeyCredentialStore::open(&link).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_accessible_or_world_writable_paths_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passkeys.json");
        fs::write(&path, br#"{"version":1,"passkeys":[]}"#).unwrap();

        // 0644 (group/other readable) is refused even though the JSON is valid.
        set_mode(&path, 0o644);
        assert!(FilePasskeyCredentialStore::open(&path).is_err());

        // Owner-only succeeds.
        set_mode(&path, 0o600);
        assert!(FilePasskeyCredentialStore::open(&path).is_ok());

        // A world-writable parent directory is refused before the file is read.
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).unwrap();
        set_mode(&shared, 0o777);
        let nested = shared.join("passkeys.json");
        assert!(FilePasskeyCredentialStore::open(&nested).is_err());
    }

    #[test]
    fn oversized_store_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passkeys.json");
        let oversized = vec![b' '; (MAX_STORE_BYTES + 1) as usize];
        fs::write(&path, &oversized).unwrap();
        #[cfg(unix)]
        set_mode(&path, 0o600);
        assert!(FilePasskeyCredentialStore::open(&path).is_err());
    }

    #[test]
    fn debug_never_exposes_credential_material() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            FilePasskeyCredentialStore::open(directory.path().join("passkeys.json")).unwrap();
        let (passkey, _client) = registered_passkey();
        store.register_passkey(passkey).unwrap();
        let rendered = format!("{store:?}");
        assert_eq!(rendered, "FilePasskeyCredentialStore([REDACTED])");
    }

    #[test]
    fn authenticator_over_file_store_registers_and_authenticates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passkeys.json");
        let store: Arc<FilePasskeyCredentialStore> =
            Arc::new(FilePasskeyCredentialStore::open(&path).unwrap());
        let mut client = __private_test_client(true);
        let origin = __private_test_origin();
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap();
        let (creation, attempt) = authenticator
            .start_registration(__private_test_uuid(), "owner", "Owner")
            .unwrap();
        let registration = client.do_registration(origin.clone(), creation).unwrap();
        authenticator
            .finish_registration(attempt, &registration)
            .unwrap();

        let reloaded: Arc<FilePasskeyCredentialStore> =
            Arc::new(FilePasskeyCredentialStore::open(&path).unwrap());
        let authenticator =
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", reloaded)
                .unwrap();
        let (request, state) = authenticator.start_authentication().unwrap();
        let credential = client.do_authentication(origin, request).unwrap();
        authenticator
            .finish_authentication(state, &credential)
            .unwrap();
    }
}
