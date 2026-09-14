//! # Provider proposal verification (P84C)
//!
//! Pure, fail-closed verification of an untrusted external swap proposal before
//! anything may be signed. A provider (for example OKX) returns router calldata
//! and quoted economics; this crate binds that proposal to the approved intent,
//! route, net delta, and tax assessment, enforces a trusted allowlist/spend
//! policy, recomputes the calldata digest, and returns the single
//! [`ApprovedProviderPayload`] shape that a signing boundary may accept.
//!
//! ## Boundaries
//! - **No signing, submission, network, clock, RNG, or floating point.** The
//!   reference time and every policy value are supplied by the caller.
//! - **Untrusted input.** [`ProviderSwapProposal`] is never trusted until
//!   [`verify_provider_proposal`] returns `Ok`; a rejected proposal yields only a
//!   redacted [`ProviderVerificationError`].
//! - **Redaction.** No address, amount, calldata byte, or digest is rendered by
//!   any `Debug`/`Display`/error surface; the approved payload is not
//!   `Serialize`.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod error;
mod verify;

pub use error::ProviderVerificationError;
pub use verify::{
    calldata_digest, is_valid_label, verify_provider_proposal, ApprovedProviderPayload,
    ProviderSwapProposal, ProviderVerificationPolicy, MAX_CALLDATA_BYTES, MAX_LABEL_BYTES,
};
