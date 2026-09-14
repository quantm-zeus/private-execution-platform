//! Audited workspace unlock key derivation and artifact sealing/decryption.
//!
//! Domain separation binds "private-execution/workspace-unlock/v1", protocol
//! version, and kid to ensure deterministic derivation of the X25519 workspace
//! keypair. The private key never leaves memory, is zeroized on drop, and is
//! never exposed.
//!
//! The artifact envelope is bounded and exposes ONLY non-secret metadata:
//! version (1 byte) || kid (16 bytes) || encapsulated_key (32 bytes) || ciphertext.

use crate::{
    hpke::{fresh_rng, HpkePublicKey},
    CryptoError, KID_LEN,
};
use ::hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

pub const WORKSPACE_UNLOCK_DOMAIN: &[u8] = b"private-execution/workspace-unlock/v1";
pub const ARTIFACT_SEAL_DOMAIN: &[u8] = b"private-execution/workspace-artifact/v1";

pub const ARTIFACT_VERSION: u8 = 1;
pub const UNLOCK_SECRET_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const ENCAPSULATED_KEY_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const ARTIFACT_HEADER_LEN: usize = 1 + KID_LEN + ENCAPSULATED_KEY_LEN; // 49 bytes
pub const MIN_ARTIFACT_LEN: usize = ARTIFACT_HEADER_LEN + AEAD_TAG_LEN; // 65 bytes
pub const MAX_ARTIFACT_LEN: usize = 256 * 1024 * 1024; // 256 MiB bound
pub const MAX_ARTIFACT_PAYLOAD_LEN: usize = MAX_ARTIFACT_LEN - MIN_ARTIFACT_LEN;

/// Canonical domain-separated info for deterministic workspace key derivation.
pub fn canonical_unlock_info(version: u8, kid: &[u8; KID_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(WORKSPACE_UNLOCK_DOMAIN.len() + 1 + KID_LEN);
    info.extend_from_slice(WORKSPACE_UNLOCK_DOMAIN);
    info.push(version);
    info.extend_from_slice(kid);
    info
}

/// Canonical domain-separated info for HPKE artifact sealing.
pub fn canonical_artifact_info(version: u8, kid: &[u8; KID_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(ARTIFACT_SEAL_DOMAIN.len() + 1 + KID_LEN);
    info.extend_from_slice(ARTIFACT_SEAL_DOMAIN);
    info.push(version);
    info.extend_from_slice(kid);
    info
}

/// RAM-only workspace keypair derived deterministically from unlock secret.
/// Private key is never exported or serialized; Debug is strictly redacted.
pub struct WorkspaceUnlockKeyPair {
    private: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    public: HpkePublicKey,
    version: u8,
    kid: [u8; KID_LEN],
}

impl WorkspaceUnlockKeyPair {
    /// Return the public key (safe to export).
    pub fn public_key(&self) -> HpkePublicKey {
        self.public.clone()
    }

    /// Return the 32-byte public key as raw bytes.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.0
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn kid(&self) -> [u8; KID_LEN] {
        self.kid
    }
}

impl std::fmt::Debug for WorkspaceUnlockKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkspaceUnlockKeyPair([REDACTED])")
    }
}

/// Deterministically derives a workspace X25519 keypair from an exact 32-byte
/// unlock secret + canonical kid/version context.
///
/// Any changed secret, kid, or version produces a distinct keypair.
pub fn derive_workspace_keypair(
    unlock_secret: &[u8; UNLOCK_SECRET_LEN],
    version: u8,
    kid: &[u8; KID_LEN],
) -> Result<WorkspaceUnlockKeyPair, CryptoError> {
    if version != ARTIFACT_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    if unlock_secret.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput);
    }
    if kid.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput);
    }

    let info = canonical_unlock_info(version, kid);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, unlock_secret);
    let mut derived_seed = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut derived_seed[..])
        .map_err(|_| CryptoError::DerivationFailed)?;

    let (sk, pk) = <X25519HkdfSha256 as KemTrait>::derive_keypair(&derived_seed[..]);
    let pk_bytes: [u8; 32] = pk.to_bytes().into();

    Ok(WorkspaceUnlockKeyPair {
        private: sk,
        public: HpkePublicKey(pk_bytes),
        version,
        kid: *kid,
    })
}

/// Bounded wire envelope carrying ONLY non-secret metadata needed for decrypt:
/// `version(1) || kid(16) || encapsulated_key(32) || ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactEnvelope {
    pub version: u8,
    pub kid: [u8; KID_LEN],
    pub encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
    pub ciphertext: Vec<u8>,
}

impl ArtifactEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ARTIFACT_HEADER_LEN + self.ciphertext.len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.kid);
        bytes.extend_from_slice(&self.encapsulated_key);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(wire: &[u8]) -> Result<Self, CryptoError> {
        if wire.len() < MIN_ARTIFACT_LEN || wire.len() > MAX_ARTIFACT_LEN {
            return Err(CryptoError::FormatError);
        }
        let version = wire[0];
        if version != ARTIFACT_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        let mut kid = [0u8; KID_LEN];
        kid.copy_from_slice(&wire[1..1 + KID_LEN]);
        if kid.iter().all(|&b| b == 0) {
            return Err(CryptoError::FormatError);
        }

        let mut encapsulated_key = [0u8; ENCAPSULATED_KEY_LEN];
        encapsulated_key.copy_from_slice(&wire[1 + KID_LEN..ARTIFACT_HEADER_LEN]);
        if encapsulated_key.iter().all(|&b| b == 0) {
            return Err(CryptoError::FormatError);
        }

        let ciphertext = wire[ARTIFACT_HEADER_LEN..].to_vec();
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(CryptoError::CiphertextTooShort);
        }

        Ok(Self {
            version,
            kid,
            encapsulated_key,
            ciphertext,
        })
    }
}

/// Seals payload to the recipient public key using audited HPKE Rust crypto.
/// Ephemeral symmetric material is zeroized and discarded.
pub fn seal_artifact(
    recipient_public_key: &HpkePublicKey,
    version: u8,
    kid: &[u8; KID_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if version != ARTIFACT_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    if recipient_public_key.0.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput);
    }
    if kid.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput);
    }
    if payload.is_empty() || payload.len() > MAX_ARTIFACT_PAYLOAD_LEN {
        return Err(CryptoError::InvalidInput);
    }

    let pk = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&recipient_public_key.0)
        .map_err(|_| CryptoError::InvalidInput)?;

    let info = canonical_artifact_info(version, kid);
    let mut rng = fresh_rng().map_err(|_| CryptoError::RngUnavailable)?;

    let (encapped, mut aead_ctx) = ::hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &pk, &info, &mut rng)
    .map_err(|_| CryptoError::EncryptFailed)?;

    let encapped_bytes: [u8; ENCAPSULATED_KEY_LEN] = encapped.to_bytes().into();

    let mut aad = [0u8; ARTIFACT_HEADER_LEN];
    aad[0] = version;
    aad[1..1 + KID_LEN].copy_from_slice(kid);
    aad[1 + KID_LEN..ARTIFACT_HEADER_LEN].copy_from_slice(&encapped_bytes);

    let ciphertext = aead_ctx
        .seal(payload, &aad)
        .map_err(|_| CryptoError::EncryptFailed)?;

    let envelope = ArtifactEnvelope {
        version,
        kid: *kid,
        encapsulated_key: encapped_bytes,
        ciphertext,
    };
    Ok(envelope.to_bytes())
}

/// Authenticated workspace artifact decryption using the in-memory derived keypair.
///
/// Fails closed on wrong secret/key, wrong kid, wrong version, or any tampering.
pub fn decrypt_artifact(
    keypair: &WorkspaceUnlockKeyPair,
    artifact_wire: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let envelope = ArtifactEnvelope::from_bytes(artifact_wire)?;
    if envelope.version != keypair.version {
        return Err(CryptoError::UnsupportedVersion);
    }
    if envelope.kid != keypair.kid {
        return Err(CryptoError::KeyIdMismatch);
    }

    let encapped =
        <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&envelope.encapsulated_key)
            .map_err(|_| CryptoError::DecryptFailed)?;

    let info = canonical_artifact_info(envelope.version, &envelope.kid);
    let mut aead_ctx = ::hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &keypair.private,
        &encapped,
        &info,
    )
    .map_err(|_| CryptoError::DecryptFailed)?;

    let aad = &artifact_wire[..ARTIFACT_HEADER_LEN];
    let plaintext = aead_ctx
        .open(&envelope.ciphertext, aad)
        .map_err(|_| CryptoError::DecryptFailed)?;

    if plaintext.is_empty() {
        return Err(CryptoError::FormatError);
    }
    Ok(plaintext)
}

/// Convenience helper to decrypt using unlock secret directly (derives key in RAM,
/// opens payload, and zeroizes key on drop).
pub fn decrypt_artifact_with_secret(
    unlock_secret: &[u8; UNLOCK_SECRET_LEN],
    version: u8,
    kid: &[u8; KID_LEN],
    artifact_wire: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let keypair = derive_workspace_keypair(unlock_secret, version, kid)?;
    decrypt_artifact(&keypair, artifact_wire)
}

/// Re-seals an existing workspace artifact from the old unlock keypair to a new
/// recipient public key + kid, executing one rotation step.
///
/// Decrypts `artifact_wire` with `old_keypair`, then re-seals the recovered
/// plaintext to `new_recipient` under `new_kid` at [`ARTIFACT_VERSION`]. The
/// intermediate plaintext is held in a zeroizing buffer and never rendered.
/// Fails closed on any wrong key/kid/version/tamper (via [`decrypt_artifact`])
/// or an invalid payload/recipient (via [`seal_artifact`]); no rotated wire is
/// produced on failure. The input wire is never mutated.
pub fn rotate_artifact(
    old_keypair: &WorkspaceUnlockKeyPair,
    new_recipient: &HpkePublicKey,
    new_kid: &[u8; KID_LEN],
    artifact_wire: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Old side: authenticated decrypt with the existing primitive. The
    // recovered plaintext is wiped when this binding drops.
    let plaintext = Zeroizing::new(decrypt_artifact(old_keypair, artifact_wire)?);
    // New side: re-seal under the new recipient/kid at the current version.
    seal_artifact(new_recipient, ARTIFACT_VERSION, new_kid, &plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 32] = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61,
    ];
    const TEST_KID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const EXPECTED_PUBLIC_KEY: [u8; 32] = [
        0xfc, 0x41, 0xce, 0x56, 0x69, 0xad, 0x52, 0xcf, 0xb3, 0xa5, 0x3a, 0x58, 0x1e, 0x35, 0xbd,
        0x5e, 0xe7, 0x09, 0x01, 0x15, 0xcd, 0xa8, 0x03, 0x26, 0x35, 0xc6, 0x46, 0xad, 0x2c, 0xc9,
        0xe0, 0x34,
    ];

    #[test]
    fn deterministic_unlock_secret_derivation_known_vector() {
        let keypair1 = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID)
            .expect("derivation 1");
        let keypair2 = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID)
            .expect("derivation 2");

        let pk1 = keypair1.public_key_bytes();
        let pk2 = keypair2.public_key_bytes();
        assert_eq!(pk1, pk2, "derivation must be deterministic");
        assert_eq!(
            pk1, EXPECTED_PUBLIC_KEY,
            "derived public key must match hard-coded expected vector"
        );

        // Verify repeatability: fixed vector check
        let keypair3 = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID)
            .expect("derivation 3");
        assert_eq!(keypair3.public_key_bytes(), EXPECTED_PUBLIC_KEY);
    }

    #[test]
    fn domain_separation_changed_secret_kid_version() {
        let base_kp = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let base_pk = base_kp.public_key_bytes();

        // Changed secret (1 bit)
        let mut changed_secret = TEST_SECRET;
        changed_secret[0] ^= 1;
        let diff_secret_kp =
            derive_workspace_keypair(&changed_secret, ARTIFACT_VERSION, &TEST_KID).unwrap();
        assert_ne!(base_pk, diff_secret_kp.public_key_bytes());

        // Changed kid (1 byte)
        let mut changed_kid = TEST_KID;
        changed_kid[15] ^= 1;
        let diff_kid_kp =
            derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &changed_kid).unwrap();
        assert_ne!(base_pk, diff_kid_kp.public_key_bytes());

        // Changed version rejects or produces different key
        let diff_ver = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION + 1, &TEST_KID);
        assert!(diff_ver.is_err(), "unsupported version must fail");
    }

    #[test]
    fn seal_and_decrypt_roundtrip() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let public_key = keypair.public_key();

        let payload = b"{\"modules\":[\"payload-bundle-content\"],\"timestamp\":123456789}";
        let sealed = seal_artifact(&public_key, ARTIFACT_VERSION, &TEST_KID, payload)
            .expect("seal succeeds");

        assert_eq!(sealed[0], ARTIFACT_VERSION);
        assert_eq!(&sealed[1..17], &TEST_KID);
        assert!(sealed.len() >= MIN_ARTIFACT_LEN + payload.len());

        let decrypted = decrypt_artifact(&keypair, &sealed).expect("decrypt succeeds");
        assert_eq!(decrypted, payload);

        // Also test convenience decrypt with secret
        let decrypted_secret =
            decrypt_artifact_with_secret(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID, &sealed)
                .expect("decrypt with secret");
        assert_eq!(decrypted_secret, payload);
    }

    #[test]
    fn wrong_secret_fails_closed() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let sealed = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"secret payload",
        )
        .unwrap();

        let mut wrong_secret = TEST_SECRET;
        wrong_secret[31] ^= 0xff;
        let wrong_keypair =
            derive_workspace_keypair(&wrong_secret, ARTIFACT_VERSION, &TEST_KID).unwrap();

        assert!(decrypt_artifact(&wrong_keypair, &sealed).is_err());
        assert!(
            decrypt_artifact_with_secret(&wrong_secret, ARTIFACT_VERSION, &TEST_KID, &sealed)
                .is_err()
        );
    }

    #[test]
    fn wrong_kid_fails_closed() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let sealed = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"secret payload",
        )
        .unwrap();

        let mut wrong_kid = TEST_KID;
        wrong_kid[0] ^= 1;
        let wrong_keypair =
            derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &wrong_kid).unwrap();

        assert!(decrypt_artifact(&wrong_keypair, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_and_tag_fail_closed() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let sealed = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"secret payload",
        )
        .unwrap();

        // Tamper ciphertext byte
        let mut tampered_ct = sealed.clone();
        let last_idx = tampered_ct.len() - 1;
        tampered_ct[last_idx] ^= 0x01;
        assert!(decrypt_artifact(&keypair, &tampered_ct).is_err());

        // Tamper header encapsulated key
        let mut tampered_enc = sealed.clone();
        tampered_enc[17] ^= 0x01;
        assert!(decrypt_artifact(&keypair, &tampered_enc).is_err());

        // Tamper kid byte
        let mut tampered_kid = sealed.clone();
        tampered_kid[1] ^= 0x01;
        assert!(decrypt_artifact(&keypair, &tampered_kid).is_err());

        // Tamper version byte
        let mut tampered_ver = sealed.clone();
        tampered_ver[0] = 0x99;
        assert!(decrypt_artifact(&keypair, &tampered_ver).is_err());
    }

    #[test]
    fn truncation_and_bounds_fail_closed() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let sealed = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"secret payload",
        )
        .unwrap();

        assert!(decrypt_artifact(&keypair, &[]).is_err());
        assert!(decrypt_artifact(&keypair, &sealed[..MIN_ARTIFACT_LEN - 1]).is_err());
        assert!(decrypt_artifact(&keypair, &sealed[..ARTIFACT_HEADER_LEN]).is_err());

        // All zero secret is rejected
        assert!(derive_workspace_keypair(&[0u8; 32], ARTIFACT_VERSION, &TEST_KID).is_err());
        // All zero public key is rejected
        assert!(seal_artifact(
            &HpkePublicKey([0u8; 32]),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"test"
        )
        .is_err());
        // All zero kid is rejected in derivation and sealing
        assert!(derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &[0u8; 16]).is_err());
        assert!(
            seal_artifact(&keypair.public_key(), ARTIFACT_VERSION, &[0u8; 16], b"test").is_err()
        );
    }

    #[test]
    fn all_zero_kid_rejected_consistently() {
        let all_zero_kid = [0u8; 16];
        // 1. Key derivation rejects all-zero kid
        assert!(derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &all_zero_kid).is_err());

        // 2. Artifact seal rejects all-zero kid
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        assert!(seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &all_zero_kid,
            b"payload"
        )
        .is_err());

        // 3. Artifact wire envelope with all-zero kid is rejected by parser and decryptors
        let valid_sealed = seal_artifact(
            &keypair.public_key(),
            ARTIFACT_VERSION,
            &TEST_KID,
            b"payload",
        )
        .unwrap();
        let mut tampered_zero_kid = valid_sealed.clone();
        tampered_zero_kid[1..17].fill(0);
        assert!(ArtifactEnvelope::from_bytes(&tampered_zero_kid).is_err());
        assert!(decrypt_artifact(&keypair, &tampered_zero_kid).is_err());
        assert!(decrypt_artifact_with_secret(
            &TEST_SECRET,
            ARTIFACT_VERSION,
            &TEST_KID,
            &tampered_zero_kid
        )
        .is_err());
    }

    #[test]
    fn debug_output_redacts_private_material() {
        let keypair = derive_workspace_keypair(&TEST_SECRET, ARTIFACT_VERSION, &TEST_KID).unwrap();
        let dbg = format!("{:?}", keypair);
        assert_eq!(dbg, "WorkspaceUnlockKeyPair([REDACTED])");
        assert!(!dbg.contains("42"));
    }
}
