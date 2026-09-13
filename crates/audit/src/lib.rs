//! Encrypted audit trail (P42).
//!
//! This crate turns a typed, plaintext audit event into an opaque, blind-indexed
//! ciphertext record and back. It owns no network, database driver, signing
//! capability, or relay capability; persistence goes through the
//! [`storage::OpaqueStore`] contract and sealing goes through
//! [`crypto_envelope::at_rest`].
//!
//! # Security posture
//! - Encryption happens immediately: [`ExecutionAuditEvent`] is serialized and
//!   sealed before it reaches any store, and the outer
//!   [`storage::OpaqueEventRecord`] never carries trading semantics.
//! - Blind indexes are keyed HMAC-SHA256 equality tokens only. Token symbols,
//!   wallets, amounts, sides, venues, and outcomes are never indexed.
//! - The production [`UnavailableKeyProvider`] is fail-closed: without injected
//!   key material every operation returns [`AuditError::KeyUnavailable`].
//! - The crate defines its own [`SigningReference`] and [`RelayOutcomeClass`]
//!   newtypes instead of depending on `privy`/`execution-relay`, so a relay can
//!   later depend on `audit` for a durable journal without a dependency cycle.
//!
//! # Adaptations from the P42 sketch (recorded deliberately)
//! 1. The sketch's `AuditLookup { Intent(IntentId), Execution(ExecutionId),
//!    Idempotency(IdempotencyKey) }` cannot reconstruct the chain-scoped stream
//!    key `HMAC(stream_tag || chain_tag || intent_id)`, because a single
//!    component does not identify the stream. Every [`AuditLookup`] variant
//!    therefore carries the `(chain, intent_id)` stream scope; `Execution` and
//!    `Idempotency` additionally filter the decrypted events. This preserves the
//!    sketch's semantics (equal streams, filtered views) while making the enum
//!    actually resolvable.
//! 2. The event model carries `execution_id` so the `Execution` lookup has
//!    something to match.
//! 3. `chain_tag` is a fixed-width 32-byte SHA-256 of the canonical chain
//!    identity so `chain_tag || intent_id` cannot be reinterpreted across the
//!    variable-length boundary. The index is still a keyed PRF with the sketch's
//!    domain labels.
//! 4. `serde_json` is a normal dependency (not dev-only) because the writer must
//!    canonicalize the event before sealing; the deterministic struct encoding is
//!    part of the stored contract.
//! 5. `chain-types` and `market-types` are direct dependencies because the event
//!    fields are the canonical `AssetId`, `ChainId`, `AtomicAmount`, and
//!    `PriceRatio`/`AmountType` domain types.

#![forbid(unsafe_code)]

pub mod blind_index;
pub mod error;
pub mod event;
pub mod key;
pub mod writer;

pub use blind_index::{
    execution_blind_index, idempotency_blind_index, owner_blind_index, stream_blind_index,
    EXECUTION_DOMAIN, IDEMPOTENCY_DOMAIN, OWNER_DOMAIN, STREAM_DOMAIN,
};
pub use error::AuditError;
pub use event::{
    ExecutionAuditEvent, PolicyApprovalSummary, RelayOutcomeClass, RelaySummary,
    RevalidationOutcomeClass, RevalidationSummary, SigningReference, SigningSummary,
    AUDIT_SCHEMA_VERSION,
};
pub use key::{AuditKeyMaterial, AuditKeyProvider, BlindIndexKey, UnavailableKeyProvider};
pub use writer::{AuditLookup, AuditRecordRef, AuditWriter};

#[cfg(test)]
mod test_support;
