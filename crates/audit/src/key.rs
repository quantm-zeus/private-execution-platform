//! Audit key material and the fail-closed provider trait.

use crypto_envelope::SealKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::AuditError;

/// 32-byte keyed-PRF key for blind indexes.
///
/// Separate from the seal key by construction. Zeroized on drop and never
/// revealed by `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlindIndexKey([u8; 32]);

impl BlindIndexKey {
    /// Wraps exactly 32 bytes of caller-supplied key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw key bytes for in-crate HMAC derivation only.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindIndexKey([REDACTED])")
    }
}

/// Complete key material for one audit key id.
///
/// The seal key and blind-index key are distinct; both are moved into this
/// value. `Debug` never reveals the key id or either key.
pub struct AuditKeyMaterial {
    /// Key identifier carried in the at-rest wire header.
    pub kid: [u8; 16],
    /// At-rest AEAD key.
    pub seal: SealKey,
    /// Blind-index HMAC key.
    pub blind_index: BlindIndexKey,
}

impl std::fmt::Debug for AuditKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKeyMaterial")
            .field("kid", &"[REDACTED]")
            .field("seal", &"[REDACTED]")
            .field("blind_index", &"[REDACTED]")
            .finish()
    }
}

/// Supplies audit key material.
///
/// Implementations must be deterministic for a given key id and must never
/// substitute a different key on failure.
pub trait AuditKeyProvider: Send + Sync {
    /// Returns the active key material used for new appends.
    fn current(&self) -> Result<AuditKeyMaterial, AuditError>;

    /// Returns the key material for a specific id, for replay of older records.
    fn by_id(&self, kid: &[u8; 16]) -> Result<AuditKeyMaterial, AuditError>;
}

/// Production provider: no key material is wired in, so every lookup fails
/// closed. A real key source must be installed under review before appends can
/// succeed.
#[derive(Debug, Default)]
pub struct UnavailableKeyProvider;

impl AuditKeyProvider for UnavailableKeyProvider {
    fn current(&self) -> Result<AuditKeyMaterial, AuditError> {
        Err(AuditError::KeyUnavailable)
    }

    fn by_id(&self, _kid: &[u8; 16]) -> Result<AuditKeyMaterial, AuditError> {
        Err(AuditError::KeyUnavailable)
    }
}
