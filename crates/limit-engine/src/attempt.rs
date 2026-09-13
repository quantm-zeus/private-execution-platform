//! P48 — durable limit-order attempt records.
//!
//! This module defines the sealed, append-only *attempt* record that the Phase-5
//! orchestrator (P49) persists **before** it reaches the signing boundary. It is
//! the durable reserve-before-sign WAL: a bound attempt survives a restart and
//! is classified as possibly-sent so it can be reconciled, never re-signed.
//!
//! Nothing in this module signs, submits, reads a clock, or performs I/O. The
//! types are plain serializable records; [`crate::journal`] owns sealing,
//! contiguity, and recovery.

use domain::{ExecutionPreview, IdempotencyKey, IntentId, OrderId, RoutePlan, TradeIntent};
use serde::{Deserialize, Serialize};

use crate::error::LimitEngineError;
use crate::journal::{chain_tag, derive, to_hex, BlindIndexKey};

/// Schema version stamped on every attempt record.
pub const ATTEMPT_SCHEMA_VERSION: u16 = 1;

/// Domain label for the per-order attempt stream.
pub const ATTEMPT_STREAM_DOMAIN: &[u8] = b"limit.attempt.stream.v1";
/// Domain label for the deterministic per-attempt idempotency key.
pub const ATTEMPT_KEY_DOMAIN: &[u8] = b"limit.attempt.key.v1";
/// Domain label for the deterministic per-attempt intent id.
pub const ATTEMPT_INTENT_DOMAIN: &[u8] = b"limit.attempt.intent.v1";
/// Domain label for the deterministic opaque prepared-execution reference.
///
/// The reference is never a signing capability: it is a stable, opaque handle
/// the injected execution seam may use to build a `privy::PreparedExecutionRef`
/// for exactly one `(order, attempt_seq)`.
pub const ATTEMPT_PREPARED_DOMAIN: &[u8] = b"limit.attempt.prepared.v1";

/// Lifecycle phase of one execution attempt.
///
/// The ordering is meaningful: `Bound` precedes any signer contact, `Signed`
/// and later phases may already have reached the chain, and `Unknown` is the
/// ambiguous state that forces reconciliation instead of a retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPhase {
    /// The attempt context is durably bound but the signer has not run.
    Bound,
    /// The signing boundary produced a reference.
    Signed,
    /// The chain adapter acknowledged a submission.
    Submitted,
    /// The submission state could not be determined; reconcile, never retry.
    Unknown,
    /// The chain confirmed the attempt.
    Confirmed,
    /// The chain definitively rejected the attempt.
    Rejected,
    /// The attempt failed before any chain submission occurred.
    FailedBeforeSubmit,
}

impl AttemptPhase {
    /// Terminal phases are never revisited and never re-signed.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Rejected | Self::FailedBeforeSubmit
        )
    }

    /// Whether the attempt may still be live; reconciliation (not retry) applies.
    pub const fn is_in_flight(self) -> bool {
        matches!(
            self,
            Self::Bound | Self::Signed | Self::Submitted | Self::Unknown
        )
    }

    /// Whether the attempt may already have reached the chain.
    ///
    /// A `Bound` attempt is pre-sign and is safe to consider not-sent; the other
    /// in-flight phases are possibly-sent and must be reconciled, never
    /// re-signed or re-submitted.
    pub const fn may_have_reached_chain(self) -> bool {
        matches!(self, Self::Signed | Self::Submitted | Self::Unknown)
    }
}

/// Serializable copy of the `policy::ApprovedExecution` evidence.
///
/// `ApprovedExecution` intentionally has no serde surface (and no public
/// constructor), so the durable record carries only its read-only projection.
/// Recovery never needs to rebuild an `ApprovedExecution`: it reconciles, it
/// does not sign.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    /// Intent the approval was issued for.
    pub intent_id: IntentId,
    /// Wallet the approval was issued for.
    pub wallet_ref: domain::WalletRef,
    /// Chain the approval was issued for.
    pub chain: chain_types::ChainId,
    /// Idempotency key the approval was bound to.
    pub idempotency_key: IdempotencyKey,
    /// Approval expiry, if any.
    pub expires_at_ms: Option<i64>,
    /// Approved trade valuation in USD micros.
    pub approved_trade_usd: u64,
    /// Time the approval was issued at, in milliseconds.
    pub approved_at_ms: i64,
}

impl std::fmt::Debug for ApprovalSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The snapshot carries wallet/idempotency/amount semantics; render only
        // the chain and expiry shape.
        formatter
            .debug_struct("ApprovalSnapshot")
            .field("chain", &self.chain)
            .field("has_expiry", &self.expires_at_ms.is_some())
            .finish_non_exhaustive()
    }
}

/// The fully bound context of one attempt, persisted before signing.
///
/// `preview` is the *inner* [`ExecutionPreview`], not the validating wrapper:
/// [`domain::ValidatedExecutionPreview`] is deliberately not `Deserialize`, so
/// the binder re-runs the locked validation when the context is used again.
/// The digest fields are raw 32-byte tokens, never rendered.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundAttempt {
    /// Per-attempt intent handed to policy/signing.
    pub intent: TradeIntent,
    /// Exact simulated route bound to `intent`.
    pub route: RoutePlan,
    /// Exact preview bound to `intent` and `route`.
    pub preview: ExecutionPreview,
    /// Policy approval evidence.
    pub approval: ApprovalSnapshot,
    /// Opaque prepared-execution reference.
    pub prepared_reference: String,
    /// SHA-256 of the unsigned payload bound into the signing request.
    pub payload_digest: [u8; 32],
    /// Deterministic per-attempt idempotency key.
    pub attempt_key: IdempotencyKey,
    /// Attempt sequence this context belongs to.
    pub attempt_seq: u64,
    /// Per-attempt nonce (`order.nonce + attempt_seq`).
    pub nonce: u64,
}

impl std::fmt::Debug for BoundAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the intent, route, approval, reference, digests, or keys.
        formatter
            .debug_struct("BoundAttempt")
            .field("attempt_seq", &self.attempt_seq)
            .finish_non_exhaustive()
    }
}

impl BoundAttempt {
    /// Validates the minimal structural bindings a durable bound attempt needs.
    ///
    /// The full policy/domain validation reruns through the locked
    /// `SigningRequest::bind` path; this check only rejects an obviously
    /// malformed or unattributable record before it is sealed.
    pub fn validate(&self) -> Result<(), LimitEngineError> {
        if self.attempt_seq == 0 || self.nonce == 0 {
            return Err(LimitEngineError::RecordMalformed);
        }
        if self.prepared_reference.trim().is_empty() {
            return Err(LimitEngineError::RecordMalformed);
        }
        if self.payload_digest == [0u8; 32] {
            return Err(LimitEngineError::RecordMalformed);
        }
        if self.intent.amount.is_zero() {
            return Err(LimitEngineError::RecordMalformed);
        }
        Ok(())
    }
}

/// One append-only attempt-lifecycle event on a per-order attempt stream.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderAttemptEvent {
    /// Attempt-event schema version.
    pub schema_version: u16,
    /// Per-order attempt-event sequence, contiguous from one.
    pub sequence: u64,
    /// Order the attempt belongs to.
    pub order_id: OrderId,
    /// Monotonic per-order attempt counter.
    pub attempt_seq: u64,
    /// Deterministic per-attempt idempotency key.
    pub attempt_key: IdempotencyKey,
    /// Phase this event records.
    pub phase: AttemptPhase,
    /// Canonical signing request digest, once known.
    pub request_digest: Option<[u8; 32]>,
    /// Payload digest bound before signing, once known.
    pub payload_digest: Option<[u8; 32]>,
    /// Explicit caller-supplied time in milliseconds.
    pub occurred_at_ms: i64,
    /// Bound context; present exactly on a `Bound` event.
    pub bound: Option<BoundAttempt>,
}

impl std::fmt::Debug for OrderAttemptEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render order ids, keys, digests, or the bound context.
        formatter
            .debug_struct("OrderAttemptEvent")
            .field("sequence", &self.sequence)
            .field("attempt_seq", &self.attempt_seq)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl OrderAttemptEvent {
    /// Builds a `Bound` event carrying the context that must survive a restart.
    pub fn bound(bound: BoundAttempt, order_id: OrderId, occurred_at_ms: i64) -> Self {
        Self {
            schema_version: ATTEMPT_SCHEMA_VERSION,
            sequence: 0,
            order_id,
            attempt_seq: bound.attempt_seq,
            attempt_key: bound.attempt_key.clone(),
            phase: AttemptPhase::Bound,
            request_digest: None,
            payload_digest: Some(bound.payload_digest),
            occurred_at_ms,
            bound: Some(bound),
        }
    }

    /// Builds a later-phase event for `bound`'s attempt (no repeated context).
    ///
    /// `sequence` is assigned by the store when the event is appended.
    pub fn phase(
        order_id: OrderId,
        attempt_seq: u64,
        attempt_key: IdempotencyKey,
        phase: AttemptPhase,
        request_digest: Option<[u8; 32]>,
        occurred_at_ms: i64,
    ) -> Self {
        Self {
            schema_version: ATTEMPT_SCHEMA_VERSION,
            sequence: 0,
            order_id,
            attempt_seq,
            attempt_key,
            phase,
            request_digest,
            payload_digest: None,
            occurred_at_ms,
            bound: None,
        }
    }

    /// Rejects a self-inconsistent phase/context combination.
    pub fn validate(&self) -> Result<(), LimitEngineError> {
        if self.schema_version != ATTEMPT_SCHEMA_VERSION {
            return Err(LimitEngineError::RecordMalformed);
        }
        if self.sequence == 0 || self.attempt_seq == 0 {
            return Err(LimitEngineError::RecordMalformed);
        }
        match (&self.bound, self.phase) {
            (Some(bound), AttemptPhase::Bound) => {
                bound.validate()?;
                if bound.attempt_seq != self.attempt_seq
                    || bound.attempt_key != self.attempt_key
                    || self.payload_digest != Some(bound.payload_digest)
                {
                    return Err(LimitEngineError::RecordMalformed);
                }
            }
            (None, AttemptPhase::Bound) => return Err(LimitEngineError::RecordMalformed),
            (Some(_), _) => return Err(LimitEngineError::RecordMalformed),
            (None, _) => {}
        }
        Ok(())
    }
}

/// `HMAC(key, "limit.attempt.stream.v1" || chain_tag || order_id)`.
pub fn attempt_stream_blind_index(
    key: &BlindIndexKey,
    chain: &chain_types::ChainId,
    order_id: &OrderId,
) -> Result<[u8; 32], LimitEngineError> {
    let tag = chain_tag(chain);
    derive(
        key,
        ATTEMPT_STREAM_DOMAIN,
        &[&tag, order_id.as_str().as_bytes()],
    )
}

/// `hex(HMAC(key, "limit.attempt.key.v1" || chain_tag || order_id || u64be(attempt_seq)))`.
///
/// The result is opaque, deterministic, and restart-stable: the same order and
/// attempt sequence always derive the same idempotency key, so a restarted
/// reconciler can locate the attempt without re-signing.
pub fn attempt_key(
    key: &BlindIndexKey,
    chain: &chain_types::ChainId,
    order_id: &OrderId,
    attempt_seq: u64,
) -> Result<IdempotencyKey, LimitEngineError> {
    let tag = chain_tag(chain);
    let mac = derive(
        key,
        ATTEMPT_KEY_DOMAIN,
        &[
            &tag,
            order_id.as_str().as_bytes(),
            &attempt_seq.to_be_bytes(),
        ],
    )?;
    IdempotencyKey::new(to_hex(&mac)).map_err(|_| LimitEngineError::RecordMalformed)
}

/// `hex(HMAC(key, "limit.attempt.prepared.v1" || chain_tag || order_id || u64be(attempt_seq)))`.
///
/// The prepared-execution reference is opaque, deterministic, and
/// restart-stable: the same order and attempt sequence always derive the same
/// reference, so a restarted caller reconstructs the same binding without
/// re-signing. It carries no key material and grants no signing capability.
pub fn attempt_prepared_reference(
    key: &BlindIndexKey,
    chain: &chain_types::ChainId,
    order_id: &OrderId,
    attempt_seq: u64,
) -> Result<String, LimitEngineError> {
    let tag = chain_tag(chain);
    let mac = derive(
        key,
        ATTEMPT_PREPARED_DOMAIN,
        &[
            &tag,
            order_id.as_str().as_bytes(),
            &attempt_seq.to_be_bytes(),
        ],
    )?;
    Ok(to_hex(&mac))
}

/// `hex(HMAC(key, "limit.attempt.intent.v1" || chain_tag || order_id || u64be(attempt_seq)))`.
pub fn attempt_intent_id(
    key: &BlindIndexKey,
    chain: &chain_types::ChainId,
    order_id: &OrderId,
    attempt_seq: u64,
) -> Result<IntentId, LimitEngineError> {
    let tag = chain_tag(chain);
    let mac = derive(
        key,
        ATTEMPT_INTENT_DOMAIN,
        &[
            &tag,
            order_id.as_str().as_bytes(),
            &attempt_seq.to_be_bytes(),
        ],
    )?;
    IntentId::new(to_hex(&mac)).map_err(|_| LimitEngineError::RecordMalformed)
}
