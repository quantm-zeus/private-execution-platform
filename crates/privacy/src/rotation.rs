//! Deterministic artifact-rotation policy.
//!
//! Decides when an encrypted artifact should be rotated from its age and use
//! count. It is pure: the caller supplies the observed age and uses, so the
//! policy is trivially testable and holds no key material itself.

use crate::error::PrivacyError;

/// Rotation bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationConfig {
    /// Maximum age in milliseconds before rotation.
    pub max_age_ms: i64,
    /// Maximum uses before rotation.
    pub max_uses: u64,
    /// Nominal rotation window (a scheduling hint; the rotation scheduler uses
    /// `max_age_ms` as the exact due deadline).
    pub window_ms: i64,
}

impl RotationConfig {
    /// A conservative default: rotate after a day, or after 10_000 uses.
    pub const fn default_config() -> Self {
        Self {
            max_age_ms: 86_400_000,
            max_uses: 10_000,
            window_ms: 86_400_000,
        }
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// A validated artifact-rotation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPolicy {
    config: RotationConfig,
}

impl RotationPolicy {
    /// Builds a policy, rejecting non-positive bounds.
    pub fn new(config: RotationConfig) -> Result<Self, PrivacyError> {
        if config.max_age_ms <= 0 || config.window_ms <= 0 || config.max_uses == 0 {
            return Err(PrivacyError::InvalidRotationBounds);
        }
        Ok(Self { config })
    }

    /// The configured bounds.
    pub fn config(&self) -> RotationConfig {
        self.config
    }

    /// Whether an artifact with the given age and use count must be rotated.
    ///
    /// Both bounds are inclusive; a negative age is treated as zero.
    pub fn should_rotate(&self, age_ms: i64, uses: u64) -> bool {
        age_ms.max(0) >= self.config.max_age_ms || uses >= self.config.max_uses
    }

    /// The nominal time the next rotation is due for an artifact created at
    /// `created_at_ms` (saturating).
    pub fn next_rotation_at_ms(&self, created_at_ms: i64) -> i64 {
        created_at_ms.saturating_add(self.config.window_ms)
    }
}
