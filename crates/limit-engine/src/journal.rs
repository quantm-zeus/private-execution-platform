//! P46 — Phase 5 L3: durable encrypted order store and recovery.
//!
//! This module makes the P44 [`crate::store::LimitOrderStore`] contract durable
//! without changing its semantics. Order state is persisted as opaque,
//! encrypted records in [`storage::OpaqueStore`]: a per-order append-only event
//! stream (authoritative) plus a materialized per-order object (fast lookup and
//! enumeration). Every plaintext field -- order ids, tokens, wallets, amounts,
//! prices -- lives only inside the ciphertext; the outer record carries keyed
//! blind indexes and a caller-supplied coarse bucket.
//!
//! # Key material
//! [`OrderKeyMaterial`] carries a 16-byte key id, a
//! [`crypto_envelope::at_rest::SealKey`], and a local [`BlindIndexKey`]. Keys
//! come from an injected [`OrderKeyProvider`]. The production default,
//! [`UnavailableOrderKeyProvider`], fails closed: no key material means nothing
//! can be sealed or opened. Tests inject deterministic keys.
//!
//! # Blind indexes
//! All indexes are `HMAC-SHA256(blind_index, domain || ...)` (full 32 bytes):
//! - `stream_blind_index = HMAC("limit.order.stream.v1" || chain_tag || order_id)`
//! - `object_id = hex(HMAC("limit.order.object.v1" || chain_tag || order_id))`
//! - `class_blind_index = HMAC("limit.order.class.v1")`
//! - `owner_blind_index = HMAC("limit.order.owner.v1" || user_id)`
//! - `order_id_for_creation = hex(HMAC("limit.order.id.v1" || creation_key))`
//!
//! No `OrderId`, token, wallet, or amount is ever placed in an outer record.
//!
//! # Sealing and nonce safety
//! Events seal under `(stream_blind_index, transition_seq)`; objects seal under
//! `(object_id bytes, object version)`. Those scopes are domain-separated (32
//! random bytes vs. ASCII hex) and each sequence monotonically increases, so
//! `at_rest`'s deterministic nonce is never reused for different plaintext at
//! the same `(scope, sequence)`. The read-check-seal-CAS sequence is serialized
//! by a process-global async mutex, and the pre-seal check reads the
//! *authoritative event stream* -- never the materialized object -- to decide
//! whether the target sequence is free. A writer therefore never seals an event
//! at an occupied `(stream, sequence)`, even when the materialized object lags
//! behind the stream. The append-event compare-and-swap is a backstop, not the
//! only guard.
//!
//! # Single-writer assumption and cross-process uniqueness
//! The store assumes a **single writer per order stream in-process**: the
//! process-global lock serializes every durable store sharing one
//! [`OpaqueStore`], so the read-stream -> check -> seal -> append path is
//! atomic within the process. Across processes, persisted-record uniqueness
//! relies on the `append_event` contiguity gate: a racing append either lands
//! exactly the next `(stream, sequence)` or conflicts, so only one ciphertext
//! is ever persisted per `(stream, sequence)`. A conflicting writer re-reads
//! the stream and takes the idempotent/conflict path without re-sealing a
//! different plaintext. A durable single-writer or database advisory lock that
//! would additionally make the *discarded* cross-process seal attempts
//! nonce-safe is deferred; until it lands, two processes racing at one sequence
//! can still each seal once, though only the winner's ciphertext is persisted.
//!
//! # Adaptations forced by the real APIs
//! 1. `OpaqueStore::list_objects_by_class` is added with a fail-closed default
//!    body (`StorageError::Unavailable`) instead of no body. A required method
//!    would break the in-memory `OpaqueStore` fakes in `crates/audit`, which
//!    this slice must not modify; the default keeps every existing
//!    implementation compiling while still failing closed on stores that cannot
//!    list. `list_objects_by_class_page` adds the same fail-closed default for
//!    cursor paging, and `PostgresStore` implements the real queries.
//! 2. The P44 [`crate::store::LimitOrderStore::load`] signature carries no
//!    chain, but the spec binds `chain_tag` into the object id. The durable
//!    store therefore holds the single chain it serves, fixed at construction.
//!    `recover_open` enumerates the chain-independent class index instead.
//! 3. The spec sketches the sealed object plaintext as the current
//!    `StoredLimitOrder`. Idempotent creation and `replay_from` both need the
//!    creation baseline, and the object is the only durable per-order record, so
//!    the sealed payload is [`DurableOrderRecord`] (baseline + current +
//!    bucket). It is still fully encrypted.
//! 4. The P44 trait carries no `CreatedBucket`. The store quantizes the
//!    caller-supplied `at_ms` (transitions) and the order deadline (creation)
//!    to a one-day bucket; the bucket is preserved across updates.
//! 5. Creation idempotency follows the spec exactly: the caller derives
//!    `OrderId` with [`order_id_for_creation`], and `create` rejects a record
//!    whose id disagrees so the same creation key can never fork a stream.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use chain_types::ChainId;
use crypto_envelope::at_rest::{open_at_rest, seal_at_rest, wire_kid, SealKey};
use domain::{IdempotencyKey, IntentId, OrderId, OrderStatus, UserId};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage::{
    ClassListCursor, CreatedBucket, EventBus, InternalEventEnvelope, OpaqueEventRecord,
    OpaqueObject, OpaqueStore, StorageError,
};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::attempt::{attempt_stream_blind_index, OrderAttemptEvent, ATTEMPT_SCHEMA_VERSION};
use crate::error::LimitEngineError;
use crate::events::{event_subject, order_event_id, PendingOrderEvent};
use crate::fill::conservation_holds;
use crate::fsm::{apply_transition, is_terminal};
use crate::order::{OrderTransition, StoredLimitOrder, DEFAULT_SCHEMA_VERSION};
use crate::store::{AppendOutcome, CreateOutcome, LimitOrderStore};

/// Domain label for the per-order event stream index.
pub const STREAM_DOMAIN: &[u8] = b"limit.order.stream.v1";
/// Domain label for the per-order object id.
pub const OBJECT_DOMAIN: &[u8] = b"limit.order.object.v1";
/// Domain label for the order class index.
pub const CLASS_DOMAIN: &[u8] = b"limit.order.class.v1";
/// Domain label for the owner index.
pub const OWNER_DOMAIN: &[u8] = b"limit.order.owner.v1";
/// Domain label for the deterministic order id.
pub const ORDER_ID_DOMAIN: &[u8] = b"limit.order.id.v1";
/// Domain label for the fixed-width chain tag.
pub const CHAIN_TAG_DOMAIN: &[u8] = b"limit.order.chain_tag.v1";

/// Objects fetched per page during a bounded listing/recovery pass.
pub const RECOVERY_LIST_LIMIT: usize = 1024;
/// Hard cap on objects examined during one listing/recovery pass.
///
/// Enumeration pages until the class is exhausted, but never examines more than
/// this many objects. A pass that stops here reports truncation rather than
/// silently omitting older orders.
pub const RECOVERY_MAX_OBJECTS: usize = 4096;
/// Maximum event records fetched per `read_events` round.
pub const REPLAY_BATCH: usize = 256;
/// Maximum object compare-and-swap attempts before admitting a conflict.
pub const MAX_OBJECT_CAS_ATTEMPTS: u32 = 4;
/// Width of the coarse creation bucket, in milliseconds (one day).
pub const BUCKET_WIDTH_MS: i64 = 86_400_000;

type HmacSha256 = Hmac<Sha256>;

/// Serializes the read-check-seal-CAS critical section for every durable store
/// in this process.
///
/// `at_rest` derives the nonce deterministically from
/// `(key, scope, sequence, schema)`, so two writers must never seal different
/// plaintext at the same pair: that would reuse a nonce. The compare-and-swap
/// alone discards the loser, but only *after* it has already sealed, so the
/// invariant would hold by accident. Holding this lock across the whole
/// read-check-seal-CAS sequence makes the invariant structural, independent of
/// how many store instances share one `OpaqueStore`.
///
/// The lock is process-global and bounded (one cell, no per-scope map to grow).
/// It deliberately also covers recovery, whose object repair seals at the same
/// `(object_id, version)` scope as a concurrent append.
fn seal_guard() -> &'static AsyncMutex<()> {
    static GUARD: OnceLock<AsyncMutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| AsyncMutex::new(()))
}

/// 32-byte keyed-PRF key for order blind indexes.
///
/// Zeroized on drop and never revealed by `Debug`. Kept local to this crate so
/// `limit-engine` does not depend on `audit`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlindIndexKey([u8; 32]);

impl BlindIndexKey {
    /// Wraps exactly 32 bytes of caller-supplied key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw key bytes for in-crate HMAC derivation only.
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindIndexKey([REDACTED])")
    }
}

/// Complete key material for one order key id.
///
/// The seal key and blind-index key are distinct. `Debug` never reveals the key
/// id or either key.
pub struct OrderKeyMaterial {
    /// Key identifier carried in the at-rest wire header.
    pub kid: [u8; 16],
    /// At-rest AEAD key.
    pub seal: SealKey,
    /// Blind-index HMAC key.
    pub blind_index: BlindIndexKey,
}

impl std::fmt::Debug for OrderKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderKeyMaterial")
            .field("kid", &"[REDACTED]")
            .field("seal", &"[REDACTED]")
            .field("blind_index", &"[REDACTED]")
            .finish()
    }
}

/// Supplies order key material.
///
/// Implementations must be deterministic for a given key id and must never
/// substitute a different key on failure.
pub trait OrderKeyProvider: Send + Sync {
    /// Returns the active key material used for new appends.
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError>;

    /// Returns the key material for a specific id, for replay of older records.
    fn by_id(&self, kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError>;
}

/// Production provider: no key material is wired in, so every lookup fails
/// closed. A real key source must be installed under review before the durable
/// store can persist anything.
#[derive(Debug, Default)]
pub struct UnavailableOrderKeyProvider;

impl OrderKeyProvider for UnavailableOrderKeyProvider {
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError> {
        Err(LimitEngineError::KeyUnavailable)
    }

    fn by_id(&self, _kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError> {
        Err(LimitEngineError::KeyUnavailable)
    }
}

/// Sealed plaintext of a per-order object: the creation baseline plus the
/// current record. The baseline is required for exact idempotent creation and
/// for `replay_from`; it never changes after creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableOrderRecord {
    /// Persisted record schema version.
    pub schema_version: u16,
    /// Coarse creation bucket, preserved across every update.
    pub created_bucket: CreatedBucket,
    /// The immutable creation payload.
    pub baseline: StoredLimitOrder,
    /// The current order state.
    pub current: StoredLimitOrder,
}

/// Sealed payload of one append-only transition event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderTransitionEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Per-order transition sequence, equal to the outer record sequence.
    pub transition_seq: u64,
    /// Post-state order record.
    pub order: StoredLimitOrder,
    /// The validated transition that produced `order`.
    pub transition: OrderTransition,
    /// Exact caller-supplied time; ciphertext-only.
    pub occurred_at_ms: i64,
}

/// Result of appending an attempt event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptAppendOutcome {
    /// The event was assigned the next sequence and appended.
    Applied(OrderAttemptEvent),
    /// An identical `(attempt_seq, phase)` event already exists; nothing was
    /// re-sealed and nothing was re-appended.
    AlreadyApplied(OrderAttemptEvent),
}

/// Deterministic identity of the next attempt for an order.
///
/// Derived from the authoritative attempt stream, never from
/// [`StoredLimitOrder::attempt_seq`] (which stays vestigial at its stored value
/// per the Phase-5 design note). A restarted caller therefore derives the same
/// identity and never re-signs an attempt it already reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptIdentity {
    /// 1-based attempt sequence (`latest_attempt_seq + 1`).
    pub attempt_seq: u64,
    /// Deterministic per-attempt intent id.
    pub intent_id: IntentId,
    /// Deterministic per-attempt idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Opaque, deterministic reference the execution seam uses to build a
    /// `privy::PreparedExecutionRef` for this attempt.
    pub prepared_reference: String,
}

/// One open order whose latest attempt may already have reached the chain.
#[derive(Clone, PartialEq, Eq)]
pub struct InFlightAttempt {
    /// Opaque keyed object id, never the order id.
    pub object_id: String,
    /// The reconstructed open order.
    pub order: StoredLimitOrder,
    /// Latest attempt event for `order`.
    pub attempt: OrderAttemptEvent,
}

impl std::fmt::Debug for InFlightAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The order carries plaintext trading semantics; never render it. The
        // attempt's own Debug is already redacted.
        formatter
            .debug_struct("InFlightAttempt")
            .field("phase", &self.attempt.phase)
            .finish_non_exhaustive()
    }
}

/// Result of an attempt-aware recovery pass.
///
/// `Debug` is redacted: the orders carry plaintext trading semantics, so only
/// counts and classification are rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct AttemptRecoveryOutcome {
    /// Non-terminal orders whose attempt stream also authenticated.
    pub open: Vec<StoredLimitOrder>,
    /// Open orders whose latest attempt is non-terminal (reserved before
    /// signing, or possibly already sent).
    pub in_flight: Vec<InFlightAttempt>,
    /// Quarantined orders, including attempt-stream faults.
    pub quarantined: Vec<QuarantinedOrder>,
    /// Whether order enumeration stopped at the hard object cap.
    pub truncated: bool,
}

impl std::fmt::Debug for AttemptRecoveryOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttemptRecoveryOutcome")
            .field("open", &self.open.len())
            .field("in_flight", &self.in_flight.len())
            .field("quarantined", &self.quarantined.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// One order skipped by recovery because its durable records could not be
/// trusted.
///
/// `object_id` is the opaque keyed blind-index hex, never an order id, and
/// `reason` is a redacted [`LimitEngineError`] class, so the quarantine list
/// carries no plaintext and no foreign record content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedOrder {
    /// Opaque object id of the quarantined order.
    pub object_id: String,
    /// Redacted failure class that caused the quarantine.
    pub reason: LimitEngineError,
}

/// Result of a recovery pass.
///
/// Healthy, non-terminal orders are returned in `open`; every order whose
/// records could not be trusted is returned in `quarantined` instead of
/// aborting the whole pass. `truncated` is set when the hard object cap
/// ([`RECOVERY_MAX_OBJECTS`]) was reached, so the caller knows older orders may
/// not have been examined.
///
/// `Debug` is redacted: only counts are rendered, never the plaintext orders.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    /// Healthy orders that are not terminal.
    pub open: Vec<StoredLimitOrder>,
    /// Orders skipped as untrustworthy, with a redacted reason.
    pub quarantined: Vec<QuarantinedOrder>,
    /// Whether enumeration stopped at the hard object cap.
    pub truncated: bool,
}

impl std::fmt::Debug for RecoveryOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryOutcome")
            .field("open", &self.open.len())
            .field("quarantined", &self.quarantined.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Fixed-width canonical chain tag (unkeyed; the outer HMAC keys the result).
pub(crate) fn chain_tag(chain: &ChainId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_TAG_DOMAIN);
    match chain {
        ChainId::Solana => hasher.update(b"solana"),
        ChainId::Base => hasher.update(b"base"),
        ChainId::BnbChain => hasher.update(b"bnb_chain"),
        ChainId::Ethereum => hasher.update(b"ethereum"),
        ChainId::RobinhoodAssociated => hasher.update(b"robinhood_associated"),
        ChainId::Other(id) => {
            hasher.update(b"other");
            hasher.update(id.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Keyed HMAC over `domain` followed by each `part`.
pub(crate) fn derive(
    key: &BlindIndexKey,
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<[u8; 32], LimitEngineError> {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| LimitEngineError::SealFailed)?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// Lowercase hex encoding; no dependency and no padding ambiguity.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `HMAC(key, "limit.order.stream.v1" || chain_tag || order_id)`.
pub fn stream_blind_index(
    key: &BlindIndexKey,
    chain: &ChainId,
    order_id: &OrderId,
) -> Result<[u8; 32], LimitEngineError> {
    let tag = chain_tag(chain);
    derive(key, STREAM_DOMAIN, &[&tag, order_id.as_str().as_bytes()])
}

/// `hex(HMAC(key, "limit.order.object.v1" || chain_tag || order_id))`.
pub fn object_id(
    key: &BlindIndexKey,
    chain: &ChainId,
    order_id: &OrderId,
) -> Result<String, LimitEngineError> {
    let tag = chain_tag(chain);
    let mac = derive(key, OBJECT_DOMAIN, &[&tag, order_id.as_str().as_bytes()])?;
    Ok(to_hex(&mac))
}

/// `HMAC(key, "limit.order.class.v1")`; one token for every order.
pub fn class_blind_index(key: &BlindIndexKey) -> Result<[u8; 32], LimitEngineError> {
    derive(key, CLASS_DOMAIN, &[])
}

/// `HMAC(key, "limit.order.owner.v1" || user_id)`.
pub fn owner_blind_index(
    key: &BlindIndexKey,
    user_id: &UserId,
) -> Result<[u8; 32], LimitEngineError> {
    derive(key, OWNER_DOMAIN, &[user_id.as_str().as_bytes()])
}

/// `hex(HMAC(key, "limit.order.id.v1" || creation_key))`.
///
/// Deriving the order id from the creation idempotency key makes the same
/// creation request map to the same order stream/object by construction.
pub fn order_id_for_creation(
    key: &BlindIndexKey,
    creation_key: &IdempotencyKey,
) -> Result<OrderId, LimitEngineError> {
    let mac = derive(key, ORDER_ID_DOMAIN, &[creation_key.as_str().as_bytes()])?;
    OrderId::new(to_hex(&mac)).map_err(|_| LimitEngineError::RecordMalformed)
}

/// Resolves the key material named by an at-rest wire header.
fn material_for(
    keys: &dyn OrderKeyProvider,
    ciphertext: &[u8],
) -> Result<OrderKeyMaterial, LimitEngineError> {
    let kid = wire_kid(ciphertext).map_err(|_| LimitEngineError::OpenFailed)?;
    let material = keys.by_id(&kid)?;
    if material.kid != kid {
        return Err(LimitEngineError::KeyIdMismatch);
    }
    Ok(material)
}

/// Maps a storage failure onto the redacted engine taxonomy.
fn map_storage(error: StorageError) -> LimitEngineError {
    match error {
        StorageError::Conflict => LimitEngineError::PersistenceConflict,
        StorageError::Invalid(_) => LimitEngineError::RecordMalformed,
        StorageError::NotFound => LimitEngineError::StoreInvalid,
        StorageError::Unavailable | StorageError::Backend => {
            LimitEngineError::PersistenceUnavailable
        }
    }
}

/// Coarse bucket derived from an explicit millisecond time.
fn bucket_for_ms(at_ms: i64) -> Result<CreatedBucket, LimitEngineError> {
    let bucket = at_ms.div_euclid(BUCKET_WIDTH_MS).max(0);
    CreatedBucket::new(bucket).ok_or(LimitEngineError::RecordMalformed)
}

/// Validates a record as a statically-valid order at its own deadline boundary.
///
/// The store owns no clock, so it asks "is this record consistent with some
/// instant in its validity window?" rather than "is it valid now?". That is the
/// weakest time assumption that still rejects a structurally impossible record.
fn validate_static_order(order: &StoredLimitOrder) -> Result<(), LimitEngineError> {
    if order.schema_version != DEFAULT_SCHEMA_VERSION {
        return Err(LimitEngineError::RecordMalformed);
    }
    if !conservation_holds(order) {
        return Err(LimitEngineError::InvalidOrder);
    }
    let at_ms = if order.order.status == OrderStatus::Expired {
        order.order.expires_at_ms
    } else {
        order.order.expires_at_ms.saturating_sub(1)
    };
    order
        .order
        .validate(at_ms)
        .map_err(|_| LimitEngineError::InvalidOrder)
}

/// Structural validation shared by every decoded object.
fn validate_record(record: &DurableOrderRecord) -> Result<(), LimitEngineError> {
    if record.schema_version != DEFAULT_SCHEMA_VERSION {
        return Err(LimitEngineError::RecordMalformed);
    }
    if record.baseline.version != 1 || record.baseline.last_transition_seq != 0 {
        return Err(LimitEngineError::RecordMalformed);
    }
    // The creation baseline has published nothing, and the watermark can never
    // name a transition that does not exist (OE-5).
    if record.baseline.published_seq != 0
        || record.current.published_seq > record.current.last_transition_seq
    {
        return Err(LimitEngineError::RecordMalformed);
    }
    if record.baseline.order.id != record.current.order.id
        || record.baseline.order.chain != record.current.order.chain
    {
        return Err(LimitEngineError::RecordMalformed);
    }
    if record.current.version < record.baseline.version {
        return Err(LimitEngineError::RecordMalformed);
    }
    validate_static_order(&record.baseline)?;
    validate_static_order(&record.current)?;
    Ok(())
}

/// Compares two records on every field except the store CAS `version` and the
/// out-of-band outbox `published_seq` watermark.
///
/// Publication advances both without applying a transition, so a sealed event
/// captures the version and watermark that existed when it was appended; a later
/// publication can move the object past that point. Replay and idempotency
/// checks must therefore compare the state machine and ledger (the fields a
/// transition actually changes) plus `last_transition_seq`, not the out-of-band
/// bookkeeping that publication owns.
fn fsm_state_eq(left: &StoredLimitOrder, right: &StoredLimitOrder) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.version = 0;
    right.version = 0;
    left.published_seq = 0;
    right.published_seq = 0;
    left == right
}

/// Seals an object payload under `(object_id, version)`.
fn seal_record(
    material: &OrderKeyMaterial,
    object_id: &str,
    version: u64,
    record: &DurableOrderRecord,
) -> Result<Vec<u8>, LimitEngineError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(record).map_err(|_| LimitEngineError::SealFailed)?);
    seal_at_rest(
        &material.seal,
        &material.kid,
        version,
        DEFAULT_SCHEMA_VERSION,
        object_id.as_bytes(),
        &plaintext,
    )
    .map_err(|_| LimitEngineError::SealFailed)
}

/// Seals an event payload under `(stream, sequence)`.
fn seal_event(
    material: &OrderKeyMaterial,
    stream: &[u8],
    sequence: u64,
    event: &OrderTransitionEvent,
) -> Result<Vec<u8>, LimitEngineError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(event).map_err(|_| LimitEngineError::SealFailed)?);
    seal_at_rest(
        &material.seal,
        &material.kid,
        sequence,
        DEFAULT_SCHEMA_VERSION,
        stream,
        &plaintext,
    )
    .map_err(|_| LimitEngineError::SealFailed)
}

/// Opens and validates an object record.
fn open_record(
    keys: &dyn OrderKeyProvider,
    object: &OpaqueObject,
) -> Result<DurableOrderRecord, LimitEngineError> {
    let material = material_for(keys, &object.ciphertext)?;
    let plaintext = Zeroizing::new(
        open_at_rest(
            &material.seal,
            &material.kid,
            object.version,
            DEFAULT_SCHEMA_VERSION,
            object.id.as_bytes(),
            &object.ciphertext,
        )
        .map_err(|_| LimitEngineError::OpenFailed)?,
    );
    let record: DurableOrderRecord =
        serde_json::from_slice(&plaintext).map_err(|_| LimitEngineError::RecordMalformed)?;
    if record.current.version != object.version {
        return Err(LimitEngineError::RecordMalformed);
    }
    let expected_id = object_id(
        &material.blind_index,
        &record.current.order.chain,
        &record.current.order.id,
    )?;
    if expected_id != object.id {
        return Err(LimitEngineError::RecordMalformed);
    }
    if object.class_blind_index.as_slice() != class_blind_index(&material.blind_index)?.as_slice() {
        return Err(LimitEngineError::RecordMalformed);
    }
    if object.owner_blind_index.as_slice()
        != owner_blind_index(&material.blind_index, &record.current.order.owner)?.as_slice()
    {
        return Err(LimitEngineError::RecordMalformed);
    }
    validate_record(&record)?;
    Ok(record)
}

/// Opens and validates one event record.
fn open_event(
    keys: &dyn OrderKeyProvider,
    stream: &[u8],
    record: &OpaqueEventRecord,
) -> Result<OrderTransitionEvent, LimitEngineError> {
    let material = material_for(keys, &record.ciphertext)?;
    let plaintext = Zeroizing::new(
        open_at_rest(
            &material.seal,
            &material.kid,
            record.sequence,
            record.schema_version,
            stream,
            &record.ciphertext,
        )
        .map_err(|_| LimitEngineError::OpenFailed)?,
    );
    let event: OrderTransitionEvent =
        serde_json::from_slice(&plaintext).map_err(|_| LimitEngineError::RecordMalformed)?;
    if event.schema_version != DEFAULT_SCHEMA_VERSION
        || event.schema_version != record.schema_version
        || event.transition_seq != record.sequence
    {
        return Err(LimitEngineError::RecordMalformed);
    }
    Ok(event)
}

/// Seals an attempt payload under `(attempt_stream, sequence)`.
///
/// The attempt stream is domain-separated from both the transition stream and
/// the object id, so the at-rest deterministic nonce is never reused across
/// scopes.
fn seal_attempt(
    material: &OrderKeyMaterial,
    stream: &[u8],
    sequence: u64,
    event: &OrderAttemptEvent,
) -> Result<Vec<u8>, LimitEngineError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(event).map_err(|_| LimitEngineError::SealFailed)?);
    seal_at_rest(
        &material.seal,
        &material.kid,
        sequence,
        ATTEMPT_SCHEMA_VERSION,
        stream,
        &plaintext,
    )
    .map_err(|_| LimitEngineError::SealFailed)
}

/// Opens and validates one attempt record.
fn open_attempt(
    keys: &dyn OrderKeyProvider,
    chain: &ChainId,
    stream: &[u8],
    record: &OpaqueEventRecord,
) -> Result<OrderAttemptEvent, LimitEngineError> {
    let material = material_for(keys, &record.ciphertext)?;
    let plaintext = Zeroizing::new(
        open_at_rest(
            &material.seal,
            &material.kid,
            record.sequence,
            record.schema_version,
            stream,
            &record.ciphertext,
        )
        .map_err(|_| LimitEngineError::OpenFailed)?,
    );
    let event: OrderAttemptEvent =
        serde_json::from_slice(&plaintext).map_err(|_| LimitEngineError::RecordMalformed)?;
    if event.schema_version != record.schema_version || event.sequence != record.sequence {
        return Err(LimitEngineError::RecordMalformed);
    }
    event.validate()?;
    attempt_identity_binds(&material.blind_index, chain, &event)?;
    Ok(event)
}

/// Re-derives the per-attempt identities and requires the record to carry them.
///
/// The attempt journal is a reserve-before-sign WAL, so its identities must be
/// reproducible, not caller-asserted: any component (or a corrupted record) must
/// not be able to persist an attempt whose idempotency key or intent id belongs
/// to a different `(order, attempt_seq)`. A mismatch is fail-closed
/// [`LimitEngineError::RecordMalformed`]. For a `Bound` event the bound intent is
/// additionally required to be the derived per-attempt intent on the same chain,
/// and its `prepared_reference` must equal the derived per-attempt reference, so
/// a restarted reconciler can always reconstruct the reservation it names.
fn attempt_identity_binds(
    blind_index: &BlindIndexKey,
    chain: &ChainId,
    event: &OrderAttemptEvent,
) -> Result<(), LimitEngineError> {
    let expected_key =
        crate::attempt::attempt_key(blind_index, chain, &event.order_id, event.attempt_seq)?;
    if event.attempt_key != expected_key {
        return Err(LimitEngineError::RecordMalformed);
    }
    if let Some(bound) = &event.bound {
        let expected_intent = crate::attempt::attempt_intent_id(
            blind_index,
            chain,
            &event.order_id,
            event.attempt_seq,
        )?;
        let expected_reference = crate::attempt::attempt_prepared_reference(
            blind_index,
            chain,
            &event.order_id,
            event.attempt_seq,
        )?;
        if bound.intent.idempotency_key != expected_key
            || bound.intent.id != expected_intent
            || bound.intent.chain != *chain
            || bound.prepared_reference != expected_reference
        {
            return Err(LimitEngineError::RecordMalformed);
        }
    }
    Ok(())
}

/// Enforces per-order attempt ordering on the authoritative attempt stream.
///
/// The attempt stream is the durable reserve-before-sign log, so its ordering is
/// an invariant, not a convention:
/// - the first event is `Bound` for attempt `1`;
/// - a later phase may only continue the *latest* attempt while it is not
///   terminal (so `Unknown` blocks any new attempt until it is reconciled);
/// - a new attempt must be `Bound` with `attempt_seq == last + 1` and may only
///   start after the previous attempt is terminal.
///
/// This is what makes "restart never creates a duplicate trade" structural: a
/// non-terminal attempt can never be followed by a fresh signable `Bound`.
fn validate_attempt_order(
    existing: &[OrderAttemptEvent],
    candidate: &OrderAttemptEvent,
) -> Result<(), LimitEngineError> {
    let Some(last) = existing.last() else {
        if candidate.attempt_seq == 1 && candidate.phase == crate::attempt::AttemptPhase::Bound {
            return Ok(());
        }
        return Err(LimitEngineError::StoreInvalid);
    };
    if candidate.attempt_seq == last.attempt_seq {
        if last.phase.is_terminal() || candidate.phase == crate::attempt::AttemptPhase::Bound {
            return Err(LimitEngineError::StoreInvalid);
        }
        return Ok(());
    }
    let expected_next = last
        .attempt_seq
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    if candidate.attempt_seq == expected_next
        && last.phase.is_terminal()
        && candidate.phase == crate::attempt::AttemptPhase::Bound
    {
        return Ok(());
    }
    Err(LimitEngineError::StoreInvalid)
}

/// Reads and authenticates a contiguous attempt stream from sequence one.
async fn read_attempt_records<S: OpaqueStore>(
    store: &S,
    keys: &dyn OrderKeyProvider,
    chain: &ChainId,
    stream: &[u8],
) -> Result<Vec<OrderAttemptEvent>, LimitEngineError> {
    let mut expected: u64 = 1;
    let mut events = Vec::new();
    loop {
        let batch = store
            .read_events(stream, expected, REPLAY_BATCH)
            .await
            .map_err(map_storage)?;
        let batch_len = batch.len();
        if batch_len == 0 {
            break;
        }
        for record in batch {
            if record.sequence != expected {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
            let event = open_attempt(keys, chain, stream, &record)?;
            validate_attempt_order(&events, &event)?;
            events.push(event);
            expected = expected
                .checked_add(1)
                .ok_or(LimitEngineError::ArithmeticOverflow)?;
        }
        if batch_len < REPLAY_BATCH {
            break;
        }
    }
    Ok(events)
}

/// Enumerates every object of `class` by paging the deterministic class
/// ordering, stopping at [`RECOVERY_MAX_OBJECTS`].
///
/// Returns the objects and whether the hard cap was reached, so callers can
/// surface truncation instead of silently omitting older orders. A page
/// shorter than the requested size means the class was exhausted.
async fn enumerate_class<S: OpaqueStore>(
    store: &S,
    class: &[u8],
) -> Result<(Vec<OpaqueObject>, bool), LimitEngineError> {
    let mut cursor: Option<ClassListCursor> = None;
    let mut objects: Vec<OpaqueObject> = Vec::new();
    let mut truncated = false;
    loop {
        let remaining = RECOVERY_MAX_OBJECTS.saturating_sub(objects.len());
        if remaining == 0 {
            // At the cap: one more probe distinguishes "exactly the cap" from
            // "more objects exist".
            let extra = store
                .list_objects_by_class_page(class, cursor.as_ref(), 1)
                .await
                .map_err(map_storage)?;
            truncated = !extra.is_empty();
            break;
        }
        let limit = remaining.min(RECOVERY_LIST_LIMIT);
        let page = store
            .list_objects_by_class_page(class, cursor.as_ref(), limit)
            .await
            .map_err(map_storage)?;
        if page.is_empty() {
            break;
        }
        cursor = page.last().map(|object| ClassListCursor {
            created_bucket: object.created_bucket,
            id: object.id.clone(),
        });
        let page_len = page.len();
        objects.extend(page);
        if page_len < limit {
            break;
        }
    }
    Ok((objects, truncated))
}

/// Whether a per-order recovery failure is a record fault that can be
/// quarantined rather than an environmental fault that must abort the pass.
///
/// A single corrupt, foreign, or inconsistent order must not block recovery of
/// every healthy order. A lost store or an unusable key provider, by contrast,
/// affects every order and cannot be fixed by skipping one, so those stay
/// fatal and fail the whole pass closed.
fn is_per_order_fault(error: LimitEngineError) -> bool {
    !matches!(
        error,
        LimitEngineError::PersistenceUnavailable | LimitEngineError::KeyUnavailable
    )
}

/// One read of the not-yet-published tail of an order's transition stream.
///
/// Carries the watermark and object version observed by the read so
/// [`DurableLimitOrderStore::publish_pending`] can advance the watermark with a
/// compare-and-swap anchored at the exact state the envelopes were built from.
struct PendingBatch {
    /// Ready-to-publish envelopes, strictly after `published_seq`, in order.
    events: Vec<PendingOrderEvent>,
    /// Watermark observed when the batch was read.
    published_seq: u64,
    /// Object version observed when the batch was read.
    version: u64,
}

/// Durable, encrypted [`LimitOrderStore`] over an [`OpaqueStore`].
///
/// The store is bound to one [`ChainId`] because the P44 `load(order_id)` API
/// carries no chain while the spec binds `chain_tag` into the object id.
pub struct DurableLimitOrderStore<S: OpaqueStore> {
    store: Arc<S>,
    keys: Arc<dyn OrderKeyProvider>,
    chain: ChainId,
}

impl<S: OpaqueStore> std::fmt::Debug for DurableLimitOrderStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableLimitOrderStore")
            .field("chain", &self.chain)
            .finish_non_exhaustive()
    }
}

impl<S: OpaqueStore> DurableLimitOrderStore<S> {
    /// Builds a durable store over `store` for `chain`.
    pub fn new(store: Arc<S>, keys: Arc<dyn OrderKeyProvider>, chain: ChainId) -> Self {
        Self { store, keys, chain }
    }

    /// The chain this store serves.
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// Enumerates open orders and classifies each one's latest attempt.
    ///
    /// Locked P52 seam: delegates to the free [`recover_in_flight`] over this
    /// store's backend and keys. It is read-authoritative (it may repair a
    /// lagging materialized object) and never signs or submits; a possibly-sent
    /// attempt is classified for reconciliation, never resubmitted.
    pub async fn recover(&self) -> Result<AttemptRecoveryOutcome, LimitEngineError> {
        recover_in_flight(self.store.as_ref(), self.keys.as_ref()).await
    }

    /// Publishes every durable order's pending outbox events, terminal orders
    /// included.
    ///
    /// Per-open-order recovery cannot reach a terminal order whose final
    /// `Filled`/`FailedFinal` event failed to publish, because
    /// [`DurableLimitOrderStore::recover`] only returns non-terminal orders.
    /// This bounded pass enumerates the whole order class and drains each
    /// order's outbox, so a terminal order's owed event is retried on restart.
    ///
    /// The pass is best-effort and read-mostly: a per-order fault (a malformed
    /// record or a gapped/tampered event stream) skips that order and continues,
    /// and a bus error stops only that order's batch (it is contained by
    /// [`DurableLimitOrderStore::publish_pending`]). An environmental fault (an
    /// unavailable store or key provider) still fails the whole pass closed,
    /// because skipping one order cannot fix it. Publication always follows the
    /// durable repair/append performed earlier in the same pass (OE-1), and no
    /// failure here can roll back order state (OE-2).
    ///
    /// Enumeration stops at [`RECOVERY_MAX_OBJECTS`]; reaching the cap drains
    /// what was enumerated and returns [`LimitEngineError::RecoveryFailed`], so
    /// the caller can tell that older orders were not examined. Returns the
    /// total number of envelopes the bus accepted otherwise.
    pub async fn drain_all_pending(
        &self,
        bus: &dyn EventBus,
        max_per_order: usize,
    ) -> Result<u32, LimitEngineError> {
        let material = self.keys.current()?;
        let class = class_blind_index(&material.blind_index)?;
        let (objects, truncated) = enumerate_class(self.store.as_ref(), &class).await?;
        let mut published: u32 = 0;
        for object in objects {
            // A foreign-class object is a per-order fault: skip it rather than
            // abort every healthy order's drain.
            if object.class_blind_index.as_slice() != class.as_slice() {
                continue;
            }
            let record = match open_record(self.keys.as_ref(), &object) {
                Ok(record) => record,
                Err(reason) if is_per_order_fault(reason) => continue,
                Err(error) => return Err(error),
            };
            match self
                .publish_pending(&record.current.order.id, bus, max_per_order)
                .await
            {
                Ok(count) => published = published.saturating_add(count),
                // A malformed/gapped stream for one order is skipped; a bus
                // error already stopped only that order's batch inside
                // `publish_pending` and is not an error here.
                Err(reason) if is_per_order_fault(reason) => continue,
                Err(error) => return Err(error),
            }
        }
        if truncated {
            return Err(LimitEngineError::RecoveryFailed);
        }
        Ok(published)
    }

    async fn read_record(
        &self,
        object_id: &str,
    ) -> Result<Option<DurableOrderRecord>, LimitEngineError> {
        let Some(object) = self
            .store
            .get_object(object_id)
            .await
            .map_err(map_storage)?
        else {
            return Ok(None);
        };
        Ok(Some(open_record(self.keys.as_ref(), &object)?))
    }

    /// Reads and authenticates every event of `stream` from sequence one,
    /// enforcing contiguity.
    async fn read_stream(
        &self,
        stream: &[u8],
    ) -> Result<Vec<OrderTransitionEvent>, LimitEngineError> {
        let mut expected: u64 = 1;
        let mut events = Vec::new();
        loop {
            let batch = self
                .store
                .read_events(stream, expected, REPLAY_BATCH)
                .await
                .map_err(map_storage)?;
            let batch_len = batch.len();
            if batch_len == 0 {
                break;
            }
            for record in batch {
                if record.sequence != expected {
                    return Err(LimitEngineError::RecoveryInconsistent);
                }
                events.push(open_event(self.keys.as_ref(), stream, &record)?);
                expected = expected
                    .checked_add(1)
                    .ok_or(LimitEngineError::ArithmeticOverflow)?;
            }
            if batch_len < REPLAY_BATCH {
                break;
            }
        }
        Ok(events)
    }

    /// Reads the sealed, not-yet-published transition events after the outbox
    /// watermark, building ready-to-publish envelopes.
    ///
    /// The `payload` of every envelope is the raw sealed
    /// [`OpaqueEventRecord::ciphertext`] (byte-equal to `read_events`); the
    /// sealed event is opened in-crate only to derive the post-state subject,
    /// and `occurred_at_ms` is the record's coarse `created_bucket`. `max_events`
    /// bounds the batch; `max_events == 0` is a no-op with no I/O.
    pub async fn pending_events(
        &self,
        order_id: &OrderId,
        max_events: usize,
    ) -> Result<Vec<PendingOrderEvent>, LimitEngineError> {
        Ok(self.pending_batch(order_id, max_events).await?.events)
    }

    /// Publishes up to `max_events` pending events on `bus`, advancing the
    /// object watermark only past events the bus accepted.
    ///
    /// Returns the number of events the bus accepted. A bus failure stops the
    /// pump without failing the caller and without rolling back any order state;
    /// the next call retries from the watermark (at-least-once, deduped by the
    /// deterministic `event_id`). A failed or conflicted watermark write is also
    /// swallowed for the same reason. `max_events == 0` is a no-op.
    pub async fn publish_pending(
        &self,
        order_id: &OrderId,
        bus: &dyn EventBus,
        max_events: usize,
    ) -> Result<u32, LimitEngineError> {
        if max_events == 0 {
            return Ok(0);
        }
        let batch = self.pending_batch(order_id, max_events).await?;
        let mut published: u32 = 0;
        let mut highest = batch.published_seq;
        for event in batch.events {
            let seq = event.transition_seq;
            match bus.publish(event.envelope).await {
                Ok(()) => {
                    published = published.saturating_add(1);
                    highest = seq;
                }
                // Stop on the first bus error: never skip an event and never
                // advance the watermark past a failure (OE-2, OE-5).
                Err(_) => break,
            }
        }
        if published > 0 {
            // Best-effort: if the watermark write conflicts or fails, the next
            // pump republishes from the old watermark. Consumers dedupe by the
            // deterministic `event_id`.
            let _ = self.mark_published(order_id, batch.version, highest).await;
        }
        Ok(published)
    }

    /// Advances the outbox watermark with an object-only compare-and-swap.
    ///
    /// Re-seals the [`DurableOrderRecord`] at the next object version with
    /// `current.published_seq` advanced to `published_seq`, preserving the
    /// baseline, the current order state, and every other field. It **never**
    /// appends a transition event. The write is serialized with every other
    /// sealing path by the process seal lock and retried a bounded number of
    /// times on CAS conflict. A watermark already at or past the request is an
    /// idempotent no-op.
    ///
    /// Crate-private on purpose: the outbox watermark must only ever advance
    /// from [`DurableLimitOrderStore::publish_pending`], which caps the target
    /// at the events the bus actually accepted. Exposing it would let a caller
    /// assert a sequence the stream never delivered.
    pub(crate) async fn mark_published(
        &self,
        order_id: &OrderId,
        expected_version: u64,
        published_seq: u64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        let material = self.keys.current()?;
        let object_id = object_id(&material.blind_index, &self.chain, order_id)?;
        let _guard = seal_guard().lock().await;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let Some(record) = self.read_record(&object_id).await? else {
                return Err(LimitEngineError::StoreInvalid);
            };
            // A concurrent publisher already advanced the watermark: idempotent.
            if record.current.published_seq >= published_seq {
                return Ok(record.current);
            }
            // The watermark may never name a transition the object has not
            // applied; writing one would make the sealed record invalid on the
            // next read. `publish_pending` already caps its batch, so this only
            // rejects a direct-method caller.
            if published_seq > record.current.last_transition_seq {
                return Err(LimitEngineError::StoreInvalid);
            }
            // The caller's optimistic version is stale; report the conflict so
            // the next pump retries from the current watermark rather than
            // advancing from a state the caller did not observe.
            if record.current.version != expected_version {
                return Err(LimitEngineError::PersistenceConflict);
            }
            let version = record
                .current
                .version
                .checked_add(1)
                .ok_or(LimitEngineError::ArithmeticOverflow)?;
            let mut current = record.current.clone();
            current.version = version;
            current.published_seq = published_seq;
            let write = DurableOrderRecord {
                schema_version: DEFAULT_SCHEMA_VERSION,
                created_bucket: record.created_bucket,
                baseline: record.baseline.clone(),
                current: current.clone(),
            };
            let ciphertext = seal_record(&material, &object_id, version, &write)?;
            let object = OpaqueObject {
                id: object_id.clone(),
                owner_blind_index: owner_blind_index(&material.blind_index, &current.order.owner)?
                    .to_vec(),
                class_blind_index: class_blind_index(&material.blind_index)?.to_vec(),
                version,
                ciphertext,
                created_bucket: record.created_bucket,
            };
            match self.store.put_object(object).await {
                Ok(()) => return Ok(current),
                Err(StorageError::Conflict) if attempt < MAX_OBJECT_CAS_ATTEMPTS => continue,
                Err(StorageError::Conflict) => return Err(LimitEngineError::PersistenceConflict),
                Err(error) => return Err(map_storage(error)),
            }
        }
    }

    /// Reads and authenticates the sealed transition records after the outbox
    /// watermark, mapping each to an envelope.
    ///
    /// The batch is capped at the object's *materialized* head
    /// (`last_transition_seq`): the watermark lives on the object, so advancing
    /// it past an event the object has not yet applied would make the record's
    /// own `published_seq <= last_transition_seq` invariant false. An event that
    /// is durable in the stream but not yet materialized is published once
    /// recovery/replay repairs the object. Enforces stream contiguity from
    /// `published_seq + 1`, so a gap is a fail-closed
    /// [`LimitEngineError::RecoveryInconsistent`] rather than a silent skip.
    async fn pending_batch(
        &self,
        order_id: &OrderId,
        max_events: usize,
    ) -> Result<PendingBatch, LimitEngineError> {
        if max_events == 0 {
            return Ok(PendingBatch {
                events: Vec::new(),
                published_seq: 0,
                version: 0,
            });
        }
        let material = self.keys.current()?;
        let object_id = object_id(&material.blind_index, &self.chain, order_id)?;
        let Some(record) = self.read_record(&object_id).await? else {
            return Err(LimitEngineError::StoreInvalid);
        };
        let published_seq = record.current.published_seq;
        let version = record.current.version;
        let available = record
            .current
            .last_transition_seq
            .saturating_sub(published_seq);
        let limit = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(max_events);
        if limit == 0 {
            return Ok(PendingBatch {
                events: Vec::new(),
                published_seq,
                version,
            });
        }
        let stream = stream_blind_index(&material.blind_index, &self.chain, order_id)?;
        let from = published_seq
            .checked_add(1)
            .ok_or(LimitEngineError::ArithmeticOverflow)?;
        let records = self
            .store
            .read_events(&stream, from, limit)
            .await
            .map_err(map_storage)?;
        let mut events = Vec::with_capacity(records.len());
        let mut expected = from;
        for record in records {
            if record.sequence != expected {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
            let opened = open_event(self.keys.as_ref(), &stream, &record)?;
            events.push(PendingOrderEvent {
                transition_seq: record.sequence,
                envelope: InternalEventEnvelope {
                    event_id: order_event_id(&material.blind_index, &stream, record.sequence)?,
                    subject: event_subject(opened.order.order.status),
                    schema_version: DEFAULT_SCHEMA_VERSION,
                    // Coarse one-day bucket *ordinal*, not epoch ms: the exact
                    // transition instant stays inside the sealed ciphertext
                    // (privacy design; see `events::PendingOrderEvent`).
                    occurred_at_ms: record.created_bucket.get(),
                    payload: record.ciphertext,
                },
            });
            expected = expected
                .checked_add(1)
                .ok_or(LimitEngineError::ArithmeticOverflow)?;
        }
        Ok(PendingBatch {
            events,
            published_seq,
            version,
        })
    }

    /// Writes the next object state, retrying a bounded number of CAS
    /// conflicts by re-reading and re-applying the transition.
    async fn write_object_cas(
        &self,
        material: &OrderKeyMaterial,
        object_id: &str,
        transition: &OrderTransition,
        next: &StoredLimitOrder,
        mut current: DurableOrderRecord,
    ) -> Result<AppendOutcome, LimitEngineError> {
        let mut candidate = next.clone();
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let write = DurableOrderRecord {
                schema_version: DEFAULT_SCHEMA_VERSION,
                created_bucket: current.created_bucket,
                baseline: current.baseline.clone(),
                current: candidate.clone(),
            };
            let ciphertext = seal_record(material, object_id, candidate.version, &write)?;
            let object = OpaqueObject {
                id: object_id.to_string(),
                owner_blind_index: owner_blind_index(
                    &material.blind_index,
                    &candidate.order.owner,
                )?
                .to_vec(),
                class_blind_index: class_blind_index(&material.blind_index)?.to_vec(),
                version: candidate.version,
                ciphertext,
                created_bucket: current.created_bucket,
            };
            match self.store.put_object(object).await {
                Ok(()) => return Ok(AppendOutcome::Applied(candidate)),
                Err(StorageError::Conflict) if attempt < MAX_OBJECT_CAS_ATTEMPTS => {
                    let Some(reloaded) = self.read_record(object_id).await? else {
                        return Err(LimitEngineError::PersistenceUnavailable);
                    };
                    if reloaded.current.last_transition_seq >= transition.transition_seq {
                        // The object advanced under us. Return the replayed
                        // authoritative head, not the materialized record we
                        // just read, which may itself lag the event stream.
                        let authoritative = self
                            .replay_from(&transition.order_id, transition.transition_seq)
                            .await?;
                        return Ok(AppendOutcome::AlreadyApplied(authoritative));
                    }
                    let expected_seq = reloaded
                        .current
                        .last_transition_seq
                        .checked_add(1)
                        .ok_or(LimitEngineError::ArithmeticOverflow)?;
                    if transition.transition_seq != expected_seq {
                        return Err(LimitEngineError::PersistenceConflict);
                    }
                    let rederived = apply_transition(
                        &reloaded.current,
                        transition.to,
                        transition.fill.as_ref(),
                        transition.at_ms,
                    )
                    .map_err(|_| LimitEngineError::StoreInvalid)?;
                    if !fsm_state_eq(&rederived, next) {
                        return Err(LimitEngineError::PersistenceConflict);
                    }
                    current = reloaded;
                    candidate = rederived;
                }
                Err(StorageError::Conflict) => return Err(LimitEngineError::PersistenceConflict),
                Err(error) => return Err(map_storage(error)),
            }
        }
    }

    /// Reads and authenticates `order_id`'s append-only attempt stream.
    pub async fn read_attempts(
        &self,
        order_id: &OrderId,
    ) -> Result<Vec<OrderAttemptEvent>, LimitEngineError> {
        let material = self.keys.current()?;
        let stream = attempt_stream_blind_index(&material.blind_index, &self.chain, order_id)?;
        read_attempt_records(
            self.store.as_ref(),
            self.keys.as_ref(),
            &self.chain,
            &stream,
        )
        .await
    }

    /// Returns the latest attempt event for `order_id`, if any.
    pub async fn latest_attempt(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<OrderAttemptEvent>, LimitEngineError> {
        Ok(self.read_attempts(order_id).await?.pop())
    }

    /// Derives the next attempt identity from the authoritative attempt stream.
    ///
    /// `attempt_seq = latest_attempt_seq + 1` (1 when no attempt exists); the
    /// intent id, idempotency key, and prepared reference are the deterministic
    /// per-attempt derivations, so a restarted caller derives the same identity
    /// and never re-signs an attempt it already reserved.
    pub async fn next_attempt_identity(
        &self,
        order_id: &OrderId,
    ) -> Result<AttemptIdentity, LimitEngineError> {
        let material = self.keys.current()?;
        let attempt_seq = self
            .read_attempts(order_id)
            .await?
            .pop()
            .map(|event| event.attempt_seq)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(LimitEngineError::ArithmeticOverflow)?;
        let blind_index = &material.blind_index;
        Ok(AttemptIdentity {
            attempt_seq,
            intent_id: crate::attempt::attempt_intent_id(
                blind_index,
                &self.chain,
                order_id,
                attempt_seq,
            )?,
            idempotency_key: crate::attempt::attempt_key(
                blind_index,
                &self.chain,
                order_id,
                attempt_seq,
            )?,
            prepared_reference: crate::attempt::attempt_prepared_reference(
                blind_index,
                &self.chain,
                order_id,
                attempt_seq,
            )?,
        })
    }

    /// Appends one attempt-lifecycle event idempotently.
    ///
    /// The identity of an append is `(attempt_seq, phase)`: re-appending the
    /// same phase returns [`AttemptAppendOutcome::AlreadyApplied`] without
    /// sealing or writing anything, while a different payload for the same
    /// `(attempt_seq, phase)` is [`LimitEngineError::PersistenceConflict`]. The
    /// caller-supplied `sequence` is ignored; the store assigns the next free
    /// contiguous sequence after reading the authoritative stream. Ordering is
    /// enforced by [`validate_attempt_order`], so a fresh `Bound` can never
    /// follow a non-terminal attempt.
    pub async fn append_attempt(
        &self,
        event: &OrderAttemptEvent,
    ) -> Result<AttemptAppendOutcome, LimitEngineError> {
        let material = self.keys.current()?;
        let stream =
            attempt_stream_blind_index(&material.blind_index, &self.chain, &event.order_id)?;

        // Serialize the authoritative-read -> check -> seal -> append-CAS path so
        // a racing writer observes the winner before sealing a different event
        // at the same deterministic nonce scope.
        let _guard = seal_guard().lock().await;

        // An attempt is only meaningful for an order this store already holds.
        let object_id = object_id(&material.blind_index, &self.chain, &event.order_id)?;
        let Some(record) = self.read_record(&object_id).await? else {
            return Err(LimitEngineError::StoreInvalid);
        };

        let events = read_attempt_records(
            self.store.as_ref(),
            self.keys.as_ref(),
            &self.chain,
            &stream,
        )
        .await?;
        // Idempotency first: an existing `(attempt_seq, phase)` event wins, even
        // if the order has since become terminal. A crash-retry of the exact same
        // event must always be a no-op, never an error.
        if let Some(present) = events.iter().find(|present| {
            present.attempt_seq == event.attempt_seq && present.phase == event.phase
        }) {
            let mut normalized = event.clone();
            normalized.sequence = present.sequence;
            normalized.validate()?;
            attempt_identity_binds(&material.blind_index, &self.chain, &normalized)?;
            if *present != normalized {
                return Err(LimitEngineError::PersistenceConflict);
            }
            return Ok(AttemptAppendOutcome::AlreadyApplied(present.clone()));
        }

        // The materialized object can lag the authoritative transition stream
        // (see the module docs); its status must therefore not gate a new
        // signable attempt until it is known to be in sync. A lagging object is
        // repaired by recovery, never by deriving a forward attempt from stale
        // state.
        let transition_stream =
            stream_blind_index(&material.blind_index, &self.chain, &event.order_id)?;
        let transition_events = self.read_stream(&transition_stream).await?;
        let transition_head = transition_events
            .last()
            .map(|present| present.transition_seq)
            .unwrap_or(0);
        if record.current.last_transition_seq != transition_head {
            return Err(LimitEngineError::RecoveryInconsistent);
        }

        // A `Bound` event starts a new signable attempt, so it must never be
        // attached to a terminal order. Later-phase events are permitted so a
        // late reconciliation can still record an already-observed outcome.
        if event.phase == crate::attempt::AttemptPhase::Bound
            && is_terminal(record.current.order.status)
        {
            return Err(LimitEngineError::InvalidTransition);
        }

        let head = events.last().map(|present| present.sequence).unwrap_or(0);
        let sequence = head
            .checked_add(1)
            .ok_or(LimitEngineError::ArithmeticOverflow)?;
        let mut record_event = event.clone();
        record_event.sequence = sequence;
        record_event.validate()?;
        attempt_identity_binds(&material.blind_index, &self.chain, &record_event)?;
        validate_attempt_order(&events, &record_event)?;

        let record = OpaqueEventRecord {
            stream_blind_index: stream.to_vec(),
            sequence,
            schema_version: ATTEMPT_SCHEMA_VERSION,
            ciphertext: seal_attempt(&material, &stream, sequence, &record_event)?,
            created_bucket: bucket_for_ms(record_event.occurred_at_ms)?,
        };
        record
            .validate()
            .map_err(|_| LimitEngineError::RecordMalformed)?;
        match self.store.append_event(record).await {
            Ok(()) => Ok(AttemptAppendOutcome::Applied(record_event)),
            Err(StorageError::Conflict) => {
                // A cross-process writer landed this sequence first. Re-read and
                // take the idempotent/conflict path; never seal a second event.
                let existing = self
                    .store
                    .read_events(&stream, sequence, 1)
                    .await
                    .map_err(map_storage)?;
                match existing.first() {
                    Some(record) if record.sequence == sequence => {
                        let present =
                            open_attempt(self.keys.as_ref(), &self.chain, &stream, record)?;
                        let mut normalized = event.clone();
                        normalized.sequence = present.sequence;
                        normalized.validate()?;
                        attempt_identity_binds(&material.blind_index, &self.chain, &normalized)?;
                        if present != normalized {
                            return Err(LimitEngineError::PersistenceConflict);
                        }
                        Ok(AttemptAppendOutcome::AlreadyApplied(present))
                    }
                    _ => Err(LimitEngineError::PersistenceConflict),
                }
            }
            Err(error) => Err(map_storage(error)),
        }
    }
}

/// Enumerates open orders and classifies each one's latest attempt.
///
/// This is the restart read path the Phase-5 orchestrator consumes: an order
/// whose latest attempt is non-terminal is reported in `in_flight` and must be
/// reconciled, never re-signed. No signing or submission capability exists on
/// this path.
///
/// An order whose attempt stream cannot be authenticated is *not* reported as
/// healthy: it is quarantined and omitted from `open`, so a caller can never
/// mistake an unreadable in-flight attempt for an idle order.
pub async fn recover_in_flight<S: OpaqueStore>(
    store: &S,
    keys: &dyn OrderKeyProvider,
) -> Result<AttemptRecoveryOutcome, LimitEngineError> {
    let recovery = recover_open(store, keys).await?;
    let material = keys.current()?;
    let mut open = Vec::new();
    let mut in_flight = Vec::new();
    let mut quarantined = recovery.quarantined;
    for order in recovery.open {
        let object_key = object_id(&material.blind_index, &order.order.chain, &order.order.id)?;
        let stream = match attempt_stream_blind_index(
            &material.blind_index,
            &order.order.chain,
            &order.order.id,
        ) {
            Ok(stream) => stream,
            Err(reason) if is_per_order_fault(reason) => {
                quarantined.push(QuarantinedOrder {
                    object_id: object_key,
                    reason,
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        match read_attempt_records(store, keys, &order.order.chain, &stream).await {
            Ok(events) => {
                if let Some(latest) = events.last() {
                    if latest.phase.is_in_flight() {
                        in_flight.push(InFlightAttempt {
                            object_id: object_key,
                            order: order.clone(),
                            attempt: latest.clone(),
                        });
                    }
                }
                open.push(order);
            }
            Err(reason) if is_per_order_fault(reason) => {
                quarantined.push(QuarantinedOrder {
                    object_id: object_key,
                    reason,
                });
            }
            Err(error) => return Err(error),
        }
    }
    in_flight.sort_by(|left, right| left.object_id.cmp(&right.object_id));
    open.sort_by(|left, right| left.order.id.as_str().cmp(right.order.id.as_str()));
    Ok(AttemptRecoveryOutcome {
        open,
        in_flight,
        quarantined,
        truncated: recovery.truncated,
    })
}

#[async_trait]
impl<S: OpaqueStore> LimitOrderStore for DurableLimitOrderStore<S> {
    async fn create(&self, order: StoredLimitOrder) -> Result<CreateOutcome, LimitEngineError> {
        if order.order.chain != self.chain {
            return Err(LimitEngineError::StoreInvalid);
        }
        validate_static_order(&order)?;
        if order.version != 1 || order.last_transition_seq != 0 || order.published_seq != 0 {
            return Err(LimitEngineError::InvalidOrder);
        }
        let material = self.keys.current()?;
        let derived_id =
            order_id_for_creation(&material.blind_index, &order.order_idempotency_key)?;
        if order.order.id != derived_id {
            return Err(LimitEngineError::IdempotencyConflict);
        }
        let object_id = object_id(&material.blind_index, &self.chain, &order.order.id)?;

        // Serialize read-check-seal-CAS: two creates with the same creation key
        // must not both seal a v1 object under the same deterministic nonce.
        let _guard = seal_guard().lock().await;

        if let Some(existing) = self.read_record(&object_id).await? {
            if existing.baseline != order {
                return Err(LimitEngineError::IdempotencyConflict);
            }
            return Ok(CreateOutcome::Existing(existing.current));
        }

        let created_bucket = bucket_for_ms(order.order.expires_at_ms)?;
        let write = DurableOrderRecord {
            schema_version: DEFAULT_SCHEMA_VERSION,
            created_bucket,
            baseline: order.clone(),
            current: order.clone(),
        };
        let ciphertext = seal_record(&material, &object_id, 1, &write)?;
        let object = OpaqueObject {
            id: object_id.clone(),
            owner_blind_index: owner_blind_index(&material.blind_index, &order.order.owner)?
                .to_vec(),
            class_blind_index: class_blind_index(&material.blind_index)?.to_vec(),
            version: 1,
            ciphertext,
            created_bucket,
        };
        match self.store.put_object(object).await {
            Ok(()) => Ok(CreateOutcome::Created(order)),
            Err(StorageError::Conflict) => match self.read_record(&object_id).await? {
                Some(existing) if existing.baseline == order => {
                    Ok(CreateOutcome::Existing(existing.current))
                }
                Some(_) => Err(LimitEngineError::IdempotencyConflict),
                None => Err(LimitEngineError::PersistenceConflict),
            },
            Err(error) => Err(map_storage(error)),
        }
    }

    async fn load(&self, order_id: &OrderId) -> Result<Option<StoredLimitOrder>, LimitEngineError> {
        let material = self.keys.current()?;
        let object_id = object_id(&material.blind_index, &self.chain, order_id)?;
        match self.read_record(&object_id).await? {
            Some(record) => Ok(Some(record.current)),
            None => Ok(None),
        }
    }

    async fn append_transition(
        &self,
        expected_version: u64,
        transition: &OrderTransition,
        next: &StoredLimitOrder,
    ) -> Result<AppendOutcome, LimitEngineError> {
        let material = self.keys.current()?;
        let object_id = object_id(&material.blind_index, &self.chain, &transition.order_id)?;
        let stream = stream_blind_index(&material.blind_index, &self.chain, &transition.order_id)?;

        // Serialize the whole authoritative-read -> check -> seal -> append-CAS
        // path. A racing writer for the same sequence must observe the winner
        // and take the idempotent/conflict path before it seals a different
        // event under the same deterministic nonce.
        let _guard = seal_guard().lock().await;

        // The event stream is authoritative for contiguity and idempotency and
        // is read before sealing anything. The materialized object may lag the
        // stream, so keying the pre-seal check off it could seal a different
        // plaintext at an already-occupied `(stream, sequence)`.
        let events = self.read_stream(&stream).await?;
        let stream_head = events.last().map(|event| event.transition_seq).unwrap_or(0);
        let expected_seq = stream_head
            .checked_add(1)
            .ok_or(LimitEngineError::ArithmeticOverflow)?;

        // The target sequence is already occupied by the authoritative stream:
        // this is an idempotent replay or a genuine conflict. Never seal.
        if transition.transition_seq <= stream_head {
            let present = events
                .iter()
                .find(|event| event.transition_seq == transition.transition_seq)
                .ok_or(LimitEngineError::StoreInvalid)?;
            if present.transition != *transition || !fsm_state_eq(&present.order, next) {
                return Err(LimitEngineError::PersistenceConflict);
            }
            // Replayed authoritative head. Repair a lagging materialized object
            // from the stream (object scope only; the event is never re-sealed)
            // so a partial materialization cannot wedge the stream.
            let Some(record) = self.read_record(&object_id).await? else {
                return Err(LimitEngineError::StoreInvalid);
            };
            let authoritative = reconcile_lagging(
                self.store.as_ref(),
                self.keys.as_ref(),
                &stream,
                &object_id,
                &record,
            )
            .await?;
            return Ok(AppendOutcome::AlreadyApplied(authoritative));
        }

        // Only the next free sequence may be sealed; anything further is a gap.
        if transition.transition_seq != expected_seq {
            return Err(LimitEngineError::StoreInvalid);
        }

        let Some(initial) = self.read_record(&object_id).await? else {
            return Err(LimitEngineError::StoreInvalid);
        };
        // The materialized object must agree with the authoritative head so the
        // caller's expected version describes the state the transition applies
        // to. A lagging object is repaired by replay or recovery, not by
        // deriving a forward transition from stale state.
        if initial.current.last_transition_seq != stream_head {
            return Err(LimitEngineError::RecoveryInconsistent);
        }
        if expected_version != initial.current.version {
            return Err(LimitEngineError::PersistenceConflict);
        }
        if next.order.id != transition.order_id || transition.from != initial.current.order.status {
            return Err(LimitEngineError::StoreInvalid);
        }
        let derived = apply_transition(
            &initial.current,
            transition.to,
            transition.fill.as_ref(),
            transition.at_ms,
        )
        .map_err(|_| LimitEngineError::StoreInvalid)?;
        if derived != *next {
            return Err(LimitEngineError::StoreInvalid);
        }

        // (1) Append the authoritative event. The stream confirmed the target
        // sequence is free, so this is the only seal at this pair in-process.
        let event = OrderTransitionEvent {
            schema_version: DEFAULT_SCHEMA_VERSION,
            transition_seq: transition.transition_seq,
            order: next.clone(),
            transition: transition.clone(),
            occurred_at_ms: transition.at_ms,
        };
        let event_record = OpaqueEventRecord {
            stream_blind_index: stream.to_vec(),
            sequence: transition.transition_seq,
            schema_version: DEFAULT_SCHEMA_VERSION,
            ciphertext: seal_event(&material, &stream, transition.transition_seq, &event)?,
            created_bucket: bucket_for_ms(transition.at_ms)?,
        };
        match self.store.append_event(event_record).await {
            Ok(()) => {}
            Err(StorageError::Conflict) => {
                // A cross-process writer landed this sequence first. Re-read the
                // stream and take the idempotent/conflict path; never seal a
                // second event at this sequence.
                let existing = self
                    .store
                    .read_events(&stream, transition.transition_seq, 1)
                    .await
                    .map_err(map_storage)?;
                match existing.first() {
                    Some(record) if record.sequence == transition.transition_seq => {
                        let present = open_event(self.keys.as_ref(), &stream, record)?;
                        if present.transition != *transition || !fsm_state_eq(&present.order, next)
                        {
                            return Err(LimitEngineError::PersistenceConflict);
                        }
                        let authoritative = self
                            .replay_from(&transition.order_id, transition.transition_seq)
                            .await?;
                        return Ok(AppendOutcome::AlreadyApplied(authoritative));
                    }
                    _ => return Err(LimitEngineError::PersistenceConflict),
                }
            }
            Err(error) => return Err(map_storage(error)),
        }

        // (2) Materialize the object. The event stream is authoritative, so if
        // this lags, replay repairs it.
        self.write_object_cas(&material, &object_id, transition, next, initial)
            .await
    }

    async fn replay_from(
        &self,
        order_id: &OrderId,
        from_seq: u64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        let material = self.keys.current()?;
        let object_id = object_id(&material.blind_index, &self.chain, order_id)?;
        let Some(record) = self.read_record(&object_id).await? else {
            return Err(LimitEngineError::StoreInvalid);
        };
        let stream = stream_blind_index(&material.blind_index, &self.chain, order_id)?;
        let events = self.read_stream(&stream).await?;

        let mut state = if from_seq == 0 {
            record.baseline.clone()
        } else {
            match events
                .iter()
                .find(|event| event.transition_seq.saturating_add(1) == from_seq)
            {
                Some(event) => event.order.clone(),
                None => {
                    let first_seq = events.first().map(|event| event.transition_seq);
                    if first_seq.is_none_or(|seq| from_seq <= seq) {
                        record.baseline.clone()
                    } else {
                        return Err(LimitEngineError::RecoveryInconsistent);
                    }
                }
            }
        };

        for event in events
            .iter()
            .filter(|event| event.transition_seq >= from_seq)
        {
            state = apply_transition(
                &state,
                event.transition.to,
                event.transition.fill.as_ref(),
                event.transition.at_ms,
            )?;
            if !fsm_state_eq(&state, &event.order) {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
        }
        // Replay reaches the head, so the reconstructed record must carry the
        // object's current CAS version and watermark: a publication that landed
        // after an event was sealed is not visible in that event's payload.
        state.version = record.current.version;
        state.published_seq = record.current.published_seq;
        Ok(state)
    }

    async fn list_open(&self) -> Result<Vec<StoredLimitOrder>, LimitEngineError> {
        let material = self.keys.current()?;
        let class = class_blind_index(&material.blind_index)?;
        // Page the whole class instead of reading a single truncated page. The
        // trait cannot return a has-more flag, so a pass that reaches the hard
        // cap fails closed rather than silently omitting older orders.
        let (objects, truncated) = enumerate_class(self.store.as_ref(), &class).await?;
        if truncated {
            return Err(LimitEngineError::RecoveryFailed);
        }
        let mut open = Vec::new();
        for object in objects {
            let record = open_record(self.keys.as_ref(), &object)?;
            if !is_terminal(record.current.order.status) {
                open.push(record.current);
            }
        }
        open.sort_by(|left, right| left.order.id.as_str().cmp(right.order.id.as_str()));
        Ok(open)
    }
}

/// Best-effort repair of a lagging object during recovery.
///
/// A conflict means another writer already advanced the object, which is safe:
/// the event stream is authoritative and the next recovery pass is a no-op.
async fn repair_object<S: OpaqueStore>(
    store: &S,
    keys: &dyn OrderKeyProvider,
    object_id: &str,
    record: &DurableOrderRecord,
    state: &StoredLimitOrder,
) -> Result<(), LimitEngineError> {
    let material = keys.current()?;
    let write = DurableOrderRecord {
        schema_version: DEFAULT_SCHEMA_VERSION,
        created_bucket: record.created_bucket,
        baseline: record.baseline.clone(),
        current: state.clone(),
    };
    let ciphertext = seal_record(&material, object_id, state.version, &write)?;
    let object = OpaqueObject {
        id: object_id.to_string(),
        owner_blind_index: owner_blind_index(&material.blind_index, &state.order.owner)?.to_vec(),
        class_blind_index: class_blind_index(&material.blind_index)?.to_vec(),
        version: state.version,
        ciphertext,
        created_bucket: record.created_bucket,
    };
    match store.put_object(object).await {
        Ok(()) | Err(StorageError::Conflict) => Ok(()),
        Err(error) => Err(map_storage(error)),
    }
}

/// Replays a lagging object one transition at a time, repairing each step.
async fn reconcile_lagging<S: OpaqueStore>(
    store: &S,
    keys: &dyn OrderKeyProvider,
    stream: &[u8],
    object_id: &str,
    record: &DurableOrderRecord,
) -> Result<StoredLimitOrder, LimitEngineError> {
    let mut state = record.current.clone();
    let mut expected = state
        .last_transition_seq
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    loop {
        let batch = store
            .read_events(stream, expected, REPLAY_BATCH)
            .await
            .map_err(map_storage)?;
        let batch_len = batch.len();
        if batch_len == 0 {
            break;
        }
        for event_record in batch {
            if event_record.sequence != expected {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
            let event = open_event(keys, stream, &event_record)?;
            let next = apply_transition(
                &state,
                event.transition.to,
                event.transition.fill.as_ref(),
                event.transition.at_ms,
            )?;
            if !fsm_state_eq(&next, &event.order) {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
            state = next;
            expected = expected
                .checked_add(1)
                .ok_or(LimitEngineError::ArithmeticOverflow)?;
            repair_object(store, keys, object_id, record, &state).await?;
        }
        if batch_len < REPLAY_BATCH {
            break;
        }
    }
    Ok(state)
}

/// Enumerates durable open orders, repairs any object that lags its event
/// stream, and returns the reconstructed non-terminal states plus a quarantine
/// list.
///
/// Recovery is read-authoritative: the event stream wins and the object is
/// rewritten. It performs no signing and no submission; an order with an
/// in-flight attempt is surfaced for reconciliation, never resubmitted.
///
/// A single corrupt, foreign, or inconsistent order is quarantined and the pass
/// continues, so it can never block recovery of every healthy order. An
/// environmental failure (a lost store or an unusable key provider) still fails
/// the whole pass closed because skipping one order cannot fix it.
pub async fn recover_open<S: OpaqueStore>(
    store: &S,
    keys: &dyn OrderKeyProvider,
) -> Result<RecoveryOutcome, LimitEngineError> {
    let material = keys.current()?;
    let class = class_blind_index(&material.blind_index)?;

    // Recovery seals object repairs, so it shares the sealing critical section
    // with create/append.
    let _guard = seal_guard().lock().await;

    let (objects, truncated) = enumerate_class(store, &class).await?;
    let mut open = Vec::new();
    let mut quarantined = Vec::new();
    for object in objects {
        let object_id = object.id.clone();
        if object.class_blind_index.as_slice() != class.as_slice() {
            quarantined.push(QuarantinedOrder {
                object_id,
                reason: LimitEngineError::RecordMalformed,
            });
            continue;
        }
        let record = match open_record(keys, &object) {
            Ok(record) => record,
            Err(reason) if is_per_order_fault(reason) => {
                quarantined.push(QuarantinedOrder { object_id, reason });
                continue;
            }
            Err(error) => return Err(error),
        };
        let stream = match stream_blind_index(
            &material.blind_index,
            &record.current.order.chain,
            &record.current.order.id,
        ) {
            Ok(stream) => stream,
            Err(reason) if is_per_order_fault(reason) => {
                quarantined.push(QuarantinedOrder { object_id, reason });
                continue;
            }
            Err(error) => return Err(error),
        };
        match reconcile_lagging(store, keys, &stream, &object_id, &record).await {
            Ok(state) => {
                if !is_terminal(state.order.status) {
                    open.push(state);
                }
            }
            Err(reason) if is_per_order_fault(reason) => {
                quarantined.push(QuarantinedOrder { object_id, reason });
            }
            Err(error) => return Err(error),
        }
    }
    open.sort_by(|left, right| left.order.id.as_str().cmp(right.order.id.as_str()));
    Ok(RecoveryOutcome {
        open,
        quarantined,
        truncated,
    })
}
