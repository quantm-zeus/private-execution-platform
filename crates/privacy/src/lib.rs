//! # Advanced privacy policies (Phase 9)
//!
//! Small, pure, deterministic policy cores for the optional advanced-privacy
//! work:
//!
//! - **[`PaddingPolicy`]** rounds a private frame's byte length up to a fixed
//!   ladder of sizes so an observer cannot infer its exact length. It never
//!   truncates: a frame above the largest bucket is reported as unpadded at its
//!   real length, letting the caller split it.
//! - **[`RotationPolicy`]** decides when an encrypted artifact should be rotated
//!   from its age and use count.
//! - **[`plan_rotations`]** turns that policy into a bounded, deterministic pass
//!   over a caller-supplied set of artifacts, deferring the remainder.
//!
//! ## Boundaries
//! - **No secrets, no crypto, no I/O.** These are pure policies; key material
//!   stays in the existing `crypto-envelope`/`privy` boundaries. This crate has
//!   no dependency on signing, storage, or the network.
//! - **Deterministic and allocation-light.** The same input always yields the same
//!   decision, so padding/rotation are reproducible and testable.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod error;
mod padding;
mod rotation;
mod scheduler;

pub use error::PrivacyError;
pub use padding::{PaddedFrame, PaddingPolicy};
pub use rotation::{RotationConfig, RotationPolicy};
pub use scheduler::{plan_rotations, ArtifactRotation, RotationPlan};
