//! Validated, redaction-safe venue and pool-reference labels.
//!
//! Labels are the only caller-supplied strings that reach a [`domain::RouteLeg`].
//! They are validated structurally at construction time so a malformed or
//! control-character-bearing string can never be embedded in a route plan or a
//! signed digest. The label value is opaque; only its validated form is exposed.

use serde::{Deserialize, Serialize};

use crate::error::RoutingError;

/// Maximum accepted label length in bytes.
pub const MAX_LABEL_BYTES: usize = 64;

fn validate_label(value: &str) -> Result<(), RoutingError> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES {
        return Err(RoutingError::InvalidVenueLabel);
    }
    // Printable, non-space ASCII only: rejects empty, whitespace-only, leading or
    // trailing whitespace, interior whitespace, control characters, and non-ASCII.
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(RoutingError::InvalidVenueLabel);
    }
    Ok(())
}

/// Validated router/venue identifier used for `RouteLeg.venue`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VenueLabel(String);

impl VenueLabel {
    /// Validates and constructs a venue label.
    pub fn new(value: impl Into<String>) -> Result<Self, RoutingError> {
        let value = value.into();
        validate_label(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for VenueLabel {
    type Error = RoutingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<VenueLabel> for String {
    fn from(value: VenueLabel) -> Self {
        value.0
    }
}

/// Validated pool account (EVM) or program id (Solana) used for `RouteLeg.pool_ref`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PoolRefLabel(String);

impl PoolRefLabel {
    /// Validates and constructs a pool-reference label.
    pub fn new(value: impl Into<String>) -> Result<Self, RoutingError> {
        let value = value.into();
        validate_label(&value).map_err(|_| RoutingError::InvalidPoolRef)?;
        Ok(Self(value))
    }

    /// Returns the validated label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PoolRefLabel {
    type Error = RoutingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PoolRefLabel> for String {
    fn from(value: PoolRefLabel) -> Self {
        value.0
    }
}
