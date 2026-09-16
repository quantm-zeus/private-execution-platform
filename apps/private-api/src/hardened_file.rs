//! Hardened, symlink-resistant reads for operator-configured trust-anchor files.
//!
//! The release manifest and the sealed workspace artifact are the trust anchors
//! of the browser unlock contract: the manifest binds the recipient public-key
//! fingerprint that authorizes recovery mutation, and the artifact is the exact
//! ciphertext the browser decrypts. They were originally read with
//! `fs::metadata` + `File::open`, both of which follow symlinks and ignore
//! ownership and permissions. A local principal able to write the configured
//! path (or its parent) could then plant a symlink or swap in a self-consistent
//! file and defeat that binding.
//!
//! This mirrors the hardening already applied to the passkey and recovery
//! stores: reject symlinks and non-regular files, re-check the opened inode so a
//! swapped path (TOCTOU) is refused, require an owner-only-writable file owned
//! by the service user (or root), and refuse a world-writable parent directory.
//! The file's *read* bits are not constrained: the manifest is public metadata
//! and is published `0644`, while the artifact is `0600`.
//!
//! Scope and deployment notes:
//! - The symlink/owner/mode checks are Unix-only; on non-Unix the module falls
//!   back to a plain `File::open`.
//! - Only the *final* path component is refused when it is a symlink. An
//!   intermediate symlink is followed, so the documented
//!   `<releases-root>/current/workspace.artifact` layout works; the operator must
//!   point the env vars at a real final file, not a symlink to one.
//! - A group-writable parent is deliberately tolerated (matching the passkey
//!   store). That tolerance depends on the owner check rejecting a foreign-owned
//!   replacement file; do not relax the owner check independently.

use std::fs;
use std::path::Path;

/// A validated, non-symlink, owner-controlled file opened for reading.
pub struct HardenedFile {
    pub metadata: fs::Metadata,
    pub file: fs::File,
}

/// Open `path` after validating the parent directory, the opened inode, and its
/// ownership/permissions.
///
/// `Ok(None)` means the path does not exist. Every other failure (symlink, wrong
/// owner, group/world-writable file or parent, unreadable) is an error, so a
/// configured-but-untrusted file is never silently accepted.
pub fn open_hardened(path: &Path) -> std::io::Result<Option<HardenedFile>> {
    check_parent_directory(path)?;
    let link_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // `is_file()` is false for a symlink, a directory or any special file, so a
    // symlinked trust-anchor path is refused before it is opened.
    if !link_metadata.is_file() {
        return Err(std::io::Error::other("trust file is not a regular file"));
    }
    let file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("trust file is not a regular file"));
    }
    // TOCTOU: the opened inode must be the one that was inspected above.
    if !same_file(&link_metadata, &metadata) {
        return Err(std::io::Error::other("trust file changed while opening"));
    }
    check_file_permissions(&metadata)?;
    Ok(Some(HardenedFile { metadata, file }))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    // `O_NONBLOCK` closes a rename-swap availability hole: the earlier
    // `symlink_metadata(...).is_file()` check and this `open` are separate
    // syscalls, so a writer to a group-writable parent could replace the
    // inspected regular file with a FIFO and make a blocking `open` hang a
    // Tokio blocking thread forever. Regular files ignore the flag; a FIFO
    // open now fails fast and the post-open `metadata.is_file()` check rejects
    // it. The final-component symlink is still refused by `O_NOFOLLOW`.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

#[cfg(unix)]
fn check_file_permissions(metadata: &fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    // No group or other *write* bit: another local user must not be able to
    // replace the bytes. Read bits are allowed (the manifest is public).
    if metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::other(
            "trust file must not be group/world writable",
        ));
    }
    // The file must belong to the service user, or to root for a root-managed
    // deployment that hands the file to the service.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid && metadata.uid() != 0 {
        return Err(std::io::Error::other("trust file has an untrusted owner"));
    }
    Ok(())
}

/// Open a *secret* file (an API key or bearer token) with the same hardening as
/// [`open_hardened`] plus an owner-only read check. A mapped trust anchor may be
/// world-readable; a secret may not, because any local user could then read it.
pub fn open_hardened_secret(path: &Path) -> std::io::Result<Option<HardenedFile>> {
    let opened = open_hardened(path)?;
    if let Some(file) = &opened {
        check_secret_permissions(&file.metadata)?;
    }
    Ok(opened)
}

#[cfg(unix)]
fn check_secret_permissions(metadata: &fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    // Owner-only: no group/other read, write or execute bits.
    if metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "secret file must be owner-only (0600)",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secret_permissions(_metadata: &fs::Metadata) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn check_file_permissions(_metadata: &fs::Metadata) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_parent_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent)?;
    // A world-writable directory lets any local user replace the file. This
    // matches the passkey store's parent rule (group-writable stays permitted,
    // so a group-managed release directory is not a startup failure).
    if metadata.mode() & 0o002 != 0 {
        return Err(std::io::Error::other(
            "trust file parent must not be world writable",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_parent_directory(_path: &Path) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hardened-file-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn opens_an_owner_only_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let path = dir.join("manifest.json");
        {
            let mut file = fs::File::create(&path).unwrap();
            file.write_all(b"{}").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let opened = open_hardened(&path).unwrap().expect("file present");
        assert_eq!(opened.metadata.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_path() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let real = dir.join("real.json");
        fs::write(&real, b"{}").unwrap();
        let link = dir.join("link.json");
        symlink(&real, &link).unwrap();
        assert!(open_hardened(&link).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_group_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let path = dir.join("manifest.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(open_hardened(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let path = dir.join("manifest.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_hardened(&path).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn open_no_follow_does_not_block_on_a_fifo() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = temp_dir();
        let path = dir.join("pipe");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // A read-only open of a FIFO with no writer blocks indefinitely unless
        // `O_NONBLOCK` is set. This is the rename-swap availability hole the
        // flag closes: a group writer can replace a checked regular file with a
        // FIFO between the `is_file()` check and the open. The open must fail
        // fast instead of hanging a Tokio blocking thread forever.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
        let started = std::time::Instant::now();
        // A read-only `O_NONBLOCK` open of a writerless FIFO returns immediately
        // (it may succeed or fail depending on the OS); either way it must not
        // block, and a successful open must not look like a regular file.
        let opened = open_no_follow(&path);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "opening a FIFO must not block"
        );
        if let Ok(file) = opened {
            assert!(
                !file.metadata().unwrap().is_file(),
                "a FIFO must not be accepted as a regular trust file"
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_path_is_none() {
        let dir = temp_dir();
        let path = dir.join("absent.json");
        assert!(open_hardened(&path).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
