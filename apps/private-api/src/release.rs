//! Immutable workspace release descriptor and artifact compatibility preflight.
//!
//! The browser must never be asked to type an artifact Key ID, and the server
//! must never wrap an artifact that cannot possibly be decrypted by the
//! authenticated workspace enrollment bound to the requesting session. This
//! module owns the public, non-secret metadata that makes both true:
//!
//! * It parses the bounded artifact header (`version || kid || encapsulated`).
//! * It validates an optional immutable release manifest (release id, source
//!   SHA, recipient public-key fingerprint, package/protocol versions, digests).
//! * It answers a single privacy-safe compatibility decision before encrypted
//!   delivery: `Ok`, `EnrollmentRequired`, or `ArtifactIncompatible`.
//!
//! Nothing in this module returns secret material. The release manifest and the
//! artifact header are public protocol metadata; the manifest is only served
//! from an operator-configured path and never echoes file contents on failure.

use crypto_envelope::ArtifactEnvelope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::base64_encode;

/// Workspace protocol the clear shell speaks to `/internal/*`.
pub const WORKSPACE_PROTOCOL_VERSION: u8 = 1;
/// Custom in-memory package format version produced by the build script.
pub const PACKAGE_FORMAT_VERSION: u8 = 1;
/// Accepted release-manifest schema version.
pub const MANIFEST_VERSION: u8 = 1;

/// Environment variable naming the immutable release manifest.
pub const RELEASE_MANIFEST_ENV: &str = "WORKSPACE_RELEASE_MANIFEST";

/// Upper bound on the operator-configured release manifest file. The manifest is
/// a small public document; a larger file is a misconfiguration and must not be
/// read unbounded from an unauthenticated readiness probe.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Upper bounds on public manifest string fields, so a hand-written manifest
/// cannot echo an unbounded value through the authenticated descriptor.
const MAX_RELEASE_ID_BYTES: usize = 256;
const MAX_SOURCE_SHA_BYTES: usize = 128;
const MAX_DIGEST_HEX_BYTES: usize = 128;

/// Failures that must map to a fail-closed HTTP status, never a detail leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    /// The artifact file is absent/unreadable/malformed.
    ArtifactUnavailable,
    /// A configured release manifest is missing, unreadable, or inconsistent.
    ManifestInvalid,
}

/// Public-key fingerprint (SHA-256, standard base64) used only for equality
/// checks between the sealed release and the enrolled workspace public key.
pub fn public_key_fingerprint_b64(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    base64_encode(&digest)
}

/// SHA-256 digest as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode canonical standard base64 with an exact expected length.
pub(crate) fn decode_canonical_b64(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    if !input.is_ascii() {
        return None;
    }
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(expected_len);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut pad = 0usize;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'=' {
            // Padding may only appear in the final one/two positions.
            if index + 2 < bytes.len() {
                return None;
            }
            pad += 1;
            if pad > 2 {
                return None;
            }
            continue;
        }
        if pad > 0 {
            return None;
        }
        let value = match byte {
            b'A'..=b'Z' => (byte - b'A') as u32,
            b'a'..=b'z' => (byte - b'a' + 26) as u32,
            b'0'..=b'9' => (byte - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if out.len() != expected_len {
        return None;
    }
    // Reject non-canonical encodings (e.g. trailing bits set).
    if base64_encode(&out) != input {
        return None;
    }
    Some(out)
}

/// Minimal snapshot of the authenticated workspace enrollment needed by the
/// preflight. Owned so the auth lock is not held across artifact I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentSnapshot {
    pub version: u8,
    pub kid: [u8; auth::WORKSPACE_KID_BYTES],
    pub public_key: [u8; auth::WORKSPACE_PUBLIC_KEY_BYTES],
}

/// The single privacy-safe compatibility decision returned before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockCompatibility {
    Ok,
    EnrollmentRequired,
    ArtifactIncompatible,
}

/// Immutable release manifest emitted by the production build script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub manifest_version: u8,
    pub release_id: String,
    pub source_sha: String,
    pub artifact: ManifestArtifact,
    pub recipient: ManifestRecipient,
    pub workspace_protocol: ManifestProtocol,
    #[serde(default)]
    pub shell: Option<ManifestShell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    pub version: u8,
    pub kid_b64: String,
    pub sha256_hex: String,
    pub size: u64,
    pub package_format_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRecipient {
    pub public_key_fingerprint_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProtocol {
    pub min: u8,
    pub max: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestShell {
    pub asset_digest_hex: String,
}

impl ReleaseManifest {
    /// Validate that this manifest describes exactly these artifact bytes.
    pub fn validate_against(&self, artifact: &[u8]) -> Result<(), DescriptorError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(DescriptorError::ManifestInvalid);
        }
        if self.release_id.trim().is_empty() || self.source_sha.trim().is_empty() {
            return Err(DescriptorError::ManifestInvalid);
        }
        if self.release_id.len() > MAX_RELEASE_ID_BYTES
            || self.source_sha.len() > MAX_SOURCE_SHA_BYTES
            || self.artifact.kid_b64.len() > MAX_DIGEST_HEX_BYTES
            || self.artifact.sha256_hex.len() > MAX_DIGEST_HEX_BYTES
        {
            return Err(DescriptorError::ManifestInvalid);
        }
        if self.artifact.package_format_version != PACKAGE_FORMAT_VERSION {
            return Err(DescriptorError::ManifestInvalid);
        }
        if self.workspace_protocol.min > self.workspace_protocol.max
            || self.workspace_protocol.min > WORKSPACE_PROTOCOL_VERSION
            || self.workspace_protocol.max < WORKSPACE_PROTOCOL_VERSION
        {
            return Err(DescriptorError::ManifestInvalid);
        }
        if decode_canonical_b64(&self.recipient.public_key_fingerprint_b64, 32).is_none() {
            return Err(DescriptorError::ManifestInvalid);
        }
        if let Some(shell) = &self.shell {
            // The release tool emits exactly 64 lowercase hex chars; require the
            // same so a lax manifest cannot bind a differently-shaped digest.
            if shell.asset_digest_hex.len() != 64
                || !shell
                    .asset_digest_hex
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(DescriptorError::ManifestInvalid);
            }
        }

        let envelope = ArtifactEnvelope::from_bytes(artifact)
            .map_err(|_| DescriptorError::ArtifactUnavailable)?;
        if envelope.version != self.artifact.version {
            return Err(DescriptorError::ManifestInvalid);
        }
        if base64_encode(&envelope.kid) != self.artifact.kid_b64 {
            return Err(DescriptorError::ManifestInvalid);
        }
        if artifact.len() as u64 != self.artifact.size {
            return Err(DescriptorError::ManifestInvalid);
        }
        if sha256_hex(artifact) != self.artifact.sha256_hex {
            return Err(DescriptorError::ManifestInvalid);
        }
        Ok(())
    }
}

/// Read and validate the operator-configured release manifest.
///
/// `Ok(None)` means the operator has not configured an immutable manifest; the
/// descriptor then falls back to artifact-derived public metadata so existing
/// deployments keep working. A configured-but-broken manifest is an error and
/// must not be silently ignored.
pub fn load_release_manifest_from_env() -> Result<Option<ReleaseManifest>, DescriptorError> {
    let path = match std::env::var(RELEASE_MANIFEST_ENV) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    load_release_manifest_from(std::path::Path::new(&path)).map(Some)
}

/// Read and parse a manifest from an explicit path, bounding the read. Exposed
/// to tests without touching process-global environment state.
fn load_release_manifest_from(path: &std::path::Path) -> Result<ReleaseManifest, DescriptorError> {
    let metadata = std::fs::metadata(path).map_err(|_| DescriptorError::ManifestInvalid)?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(DescriptorError::ManifestInvalid);
    }
    let bytes = std::fs::read(path).map_err(|_| DescriptorError::ManifestInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| DescriptorError::ManifestInvalid)
}

/// Evaluate the artifact/enrollment compatibility contract.
///
/// The decision is derived only from public metadata (artifact header, enrolled
/// public key, release fingerprint); it is not an oracle for the unlock secret.
/// With no configured release manifest the server has no trusted recipient
/// public key to compare, so it enforces the version/KID binding only; a
/// mismatched key in that mode is still rejected fail-closed by the browser's
/// `decrypt_artifact` and by the enrolled-key fingerprint when a manifest is
/// present.
pub fn preflight(
    artifact: &[u8],
    enrollment: Option<&EnrollmentSnapshot>,
    manifest: Option<&ReleaseManifest>,
) -> UnlockCompatibility {
    let envelope = match ArtifactEnvelope::from_bytes(artifact) {
        Ok(envelope) => envelope,
        Err(_) => return UnlockCompatibility::ArtifactIncompatible,
    };
    if let Some(manifest) = manifest {
        if manifest.validate_against(artifact).is_err() {
            return UnlockCompatibility::ArtifactIncompatible;
        }
    }
    let Some(enrollment) = enrollment else {
        return UnlockCompatibility::EnrollmentRequired;
    };
    if enrollment.version != envelope.version || enrollment.kid != envelope.kid {
        return UnlockCompatibility::ArtifactIncompatible;
    }
    if let Some(manifest) = manifest {
        if public_key_fingerprint_b64(&enrollment.public_key)
            != manifest.recipient.public_key_fingerprint_b64
        {
            return UnlockCompatibility::ArtifactIncompatible;
        }
    }
    UnlockCompatibility::Ok
}

/// Public, authenticated artifact descriptor returned to the shell.
///
/// Contains only release metadata and the expected recipient public-key
/// fingerprint. Never contains ciphertext, paths, secrets, or private keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactDescriptor {
    pub protocol_version: u8,
    pub artifact_version: u8,
    pub artifact_kid_b64: String,
    pub artifact_size: u64,
    pub artifact_sha256_hex: String,
    pub package_format_version: u8,
    pub release_id: Option<String>,
    pub source_sha: Option<String>,
    /// Fingerprint the enrolled workspace public key must match for this
    /// release, when an immutable manifest is configured.
    pub expected_public_key_fingerprint_b64: Option<String>,
    pub min_shell_protocol: u8,
    pub max_shell_protocol: u8,
    /// Session-scoped enrollment state (public metadata only).
    pub enrolled: bool,
    pub enrolled_kid_b64: Option<String>,
    pub enrolled_public_key_fingerprint_b64: Option<String>,
}

/// Build the descriptor from artifact bytes and an optional release manifest.
pub fn describe(
    artifact: &[u8],
    manifest: Option<&ReleaseManifest>,
) -> Result<ArtifactDescriptor, DescriptorError> {
    let envelope =
        ArtifactEnvelope::from_bytes(artifact).map_err(|_| DescriptorError::ArtifactUnavailable)?;
    if let Some(manifest) = manifest {
        manifest.validate_against(artifact)?;
    }
    Ok(ArtifactDescriptor {
        protocol_version: WORKSPACE_PROTOCOL_VERSION,
        artifact_version: envelope.version,
        artifact_kid_b64: base64_encode(&envelope.kid),
        artifact_size: artifact.len() as u64,
        artifact_sha256_hex: sha256_hex(artifact),
        package_format_version: PACKAGE_FORMAT_VERSION,
        release_id: manifest.map(|m| m.release_id.clone()),
        source_sha: manifest.map(|m| m.source_sha.clone()),
        expected_public_key_fingerprint_b64: manifest
            .map(|m| m.recipient.public_key_fingerprint_b64.clone()),
        min_shell_protocol: WORKSPACE_PROTOCOL_VERSION,
        max_shell_protocol: WORKSPACE_PROTOCOL_VERSION,
        enrolled: false,
        enrolled_kid_b64: None,
        enrolled_public_key_fingerprint_b64: None,
    })
}

impl ArtifactDescriptor {
    /// Attach the current session's public enrollment metadata.
    pub fn with_enrollment(mut self, enrollment: Option<&EnrollmentSnapshot>) -> Self {
        if let Some(enrollment) = enrollment {
            self.enrolled = true;
            self.enrolled_kid_b64 = Some(base64_encode(&enrollment.kid));
            self.enrolled_public_key_fingerprint_b64 =
                Some(public_key_fingerprint_b64(&enrollment.public_key));
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_envelope::{
        derive_workspace_keypair, seal_artifact, ARTIFACT_VERSION, UNLOCK_SECRET_LEN,
    };

    const TEST_SECRET: [u8; UNLOCK_SECRET_LEN] = [0x33; UNLOCK_SECRET_LEN];
    const TEST_KID: [u8; auth::WORKSPACE_KID_BYTES] = [0x44; auth::WORKSPACE_KID_BYTES];

    fn sealed_artifact() -> (Vec<u8>, EnrollmentSnapshot) {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let artifact = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"payload",
        )
        .unwrap();
        let snapshot = EnrollmentSnapshot {
            version: ARTIFACT_VERSION,
            kid: TEST_KID,
            public_key: keypair.public_key_bytes(),
        };
        (artifact, snapshot)
    }

    #[test]
    fn fingerprint_is_stable_and_base64() {
        let fp = public_key_fingerprint_b64(&[7u8; 32]);
        assert_eq!(fp.len(), 44);
        assert!(fp.ends_with('='));
        assert_eq!(fp, public_key_fingerprint_b64(&[7u8; 32]));
        assert_ne!(fp, public_key_fingerprint_b64(&[8u8; 32]));
    }

    #[test]
    fn describe_requires_a_well_formed_artifact() {
        assert_eq!(
            describe(b"not-an-artifact", None),
            Err(DescriptorError::ArtifactUnavailable)
        );
        let (artifact, _) = sealed_artifact();
        let descriptor = describe(&artifact, None).expect("descriptor");
        assert_eq!(descriptor.artifact_version, ARTIFACT_VERSION);
        assert_eq!(descriptor.package_format_version, PACKAGE_FORMAT_VERSION);
        assert_eq!(descriptor.protocol_version, WORKSPACE_PROTOCOL_VERSION);
        assert_eq!(descriptor.artifact_kid_b64, base64_encode(&TEST_KID));
        assert_eq!(descriptor.artifact_size, artifact.len() as u64);
        assert_eq!(descriptor.artifact_sha256_hex, sha256_hex(&artifact));
        assert!(!descriptor.enrolled);
    }

    #[test]
    fn preflight_requires_enrollment_then_exact_match() {
        let (artifact, snapshot) = sealed_artifact();
        assert_eq!(
            preflight(&artifact, None, None),
            UnlockCompatibility::EnrollmentRequired
        );
        assert_eq!(
            preflight(&artifact, Some(&snapshot), None),
            UnlockCompatibility::Ok
        );

        let mut wrong_kid = snapshot;
        wrong_kid.kid[0] ^= 1;
        assert_eq!(
            preflight(&artifact, Some(&wrong_kid), None),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut wrong_version = snapshot;
        wrong_version.version = ARTIFACT_VERSION + 1;
        assert_eq!(
            preflight(&artifact, Some(&wrong_version), None),
            UnlockCompatibility::ArtifactIncompatible
        );

        assert_eq!(
            preflight(b"garbage", Some(&snapshot), None),
            UnlockCompatibility::ArtifactIncompatible
        );
    }

    fn manifest_for(artifact: &[u8], snapshot: &EnrollmentSnapshot) -> ReleaseManifest {
        ReleaseManifest {
            manifest_version: MANIFEST_VERSION,
            release_id: "release-1".into(),
            source_sha: "9a5a712".into(),
            artifact: ManifestArtifact {
                version: ARTIFACT_VERSION,
                kid_b64: base64_encode(&snapshot.kid),
                sha256_hex: sha256_hex(artifact),
                size: artifact.len() as u64,
                package_format_version: PACKAGE_FORMAT_VERSION,
            },
            recipient: ManifestRecipient {
                public_key_fingerprint_b64: public_key_fingerprint_b64(&snapshot.public_key),
            },
            workspace_protocol: ManifestProtocol {
                min: WORKSPACE_PROTOCOL_VERSION,
                max: WORKSPACE_PROTOCOL_VERSION,
            },
            shell: Some(ManifestShell {
                asset_digest_hex: "ab".repeat(32),
            }),
        }
    }

    #[test]
    fn manifest_must_match_artifact_exactly() {
        let (artifact, snapshot) = sealed_artifact();
        let manifest = manifest_for(&artifact, &snapshot);
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&manifest)),
            UnlockCompatibility::Ok
        );

        let mut wrong_digest = manifest.clone();
        wrong_digest.artifact.sha256_hex = "00".repeat(32);
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&wrong_digest)),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut wrong_size = manifest.clone();
        wrong_size.artifact.size += 1;
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&wrong_size)),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut wrong_kid = manifest.clone();
        wrong_kid.artifact.kid_b64 = base64_encode(&[0x99; 16]);
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&wrong_kid)),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut bad_fingerprint = manifest.clone();
        bad_fingerprint.recipient.public_key_fingerprint_b64 = "!!!".into();
        // Invalid manifest is itself a compatibility failure.
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&bad_fingerprint)),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut wrong_protocol = manifest.clone();
        wrong_protocol.workspace_protocol.min = WORKSPACE_PROTOCOL_VERSION + 1;
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&wrong_protocol)),
            UnlockCompatibility::ArtifactIncompatible
        );

        let mut wrong_fingerprint = manifest.clone();
        wrong_fingerprint.recipient.public_key_fingerprint_b64 =
            public_key_fingerprint_b64(&[0u8; 32]);
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&wrong_fingerprint)),
            UnlockCompatibility::ArtifactIncompatible
        );

        // A shell digest that is not exactly 64 lowercase hex is rejected, so a
        // lax manifest cannot bind a differently-shaped digest.
        let mut bad_shell_digest = manifest.clone();
        bad_shell_digest.shell = Some(ManifestShell {
            asset_digest_hex: "abc123".into(),
        });
        assert_eq!(
            preflight(&artifact, Some(&snapshot), Some(&bad_shell_digest)),
            UnlockCompatibility::ArtifactIncompatible
        );
    }

    #[test]
    fn canonical_base64_rejects_noncanonical() {
        assert!(decode_canonical_b64("AAAA", 3).is_some());
        assert!(decode_canonical_b64("AAA", 3).is_none());
        assert!(decode_canonical_b64("A===", 1).is_none());
        assert!(decode_canonical_b64("!!!!", 3).is_none());
    }
}
