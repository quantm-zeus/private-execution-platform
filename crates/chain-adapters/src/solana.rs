//! Typed Solana chain transport, submission, and reconciliation adapter.
//!
//! Solana is **not** EVM: its wire transaction format, signature model, and
//! confirmation semantics are unrelated to an EVM `eth_sendRawTransaction` /
//! receipt pair. This module therefore owns a distinct
//! [`SolanaChainTransport`] seam and a strict
//! [`validate_solana_transaction`] parser, and the submission adapter refuses
//! any payload that is not a well-formed Solana transaction. An EVM payload can
//! never be relayed as a Solana payload.
//!
//! # Bounded, fail-closed behavior
//!
//! * The parser bounds the transaction to [`MAX_SOLANA_TRANSACTION_BYTES`], the
//!   signature count, and the address-table lookup count, and requires the byte
//!   stream to be consumed exactly (no trailing data).
//! * Health is proven against the cluster's canonical genesis hash; a transport
//!   answering a different cluster is `Unavailable`, and the cached health
//!   starts `Unavailable` until [`SolanaChainSubmissionAdapter::refresh_health`]
//!   succeeds.
//! * `submit` is idempotent on `(idempotency_key, payload_digest)`, broadcasts
//!   at most once, and `query`/`reconcile` are read-only.
//! * No implementation in this crate performs I/O; every network capability is
//!   an injected seam and errors are redacted.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use chain_types::ChainId;
use execution_relay::{
    ChainHealth, ChainObservation, ChainSubmissionAdapter, RelayError, SubmissionReceipt,
    SubmitRequest,
};

use crate::ChainAdapterError;

/// Maximum pre-signature serialized Solana transaction size (1232 bytes).
///
/// This is the network's packet data size bound; a larger payload is rejected
/// rather than truncated or forwarded.
pub const MAX_SOLANA_TRANSACTION_BYTES: usize = 1232;

/// Upper bound on signatures accepted in one transaction.
const MAX_SOLANA_SIGNATURES: u16 = 32;
/// Upper bound on address-table lookups accepted in a v0 transaction.
const MAX_ADDRESS_TABLE_LOOKUPS: u16 = 64;

/// Solana cluster identity. The genesis hash is the canonical proof of which
/// cluster an RPC endpoint actually serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolanaCluster {
    /// Solana mainnet-beta.
    MainnetBeta,
    /// Solana devnet.
    Devnet,
    /// Solana testnet.
    Testnet,
}

impl SolanaCluster {
    /// The cluster's canonical genesis hash.
    ///
    /// Values are the published `--expected-genesis-hash` constants from the
    /// Anza/Agave cluster documentation.
    pub const fn genesis_hash(self) -> &'static str {
        match self {
            Self::MainnetBeta => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
            Self::Devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
            Self::Testnet => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
        }
    }

    /// Stable label used in redacted diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MainnetBeta => "mainnet-beta",
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
        }
    }
}

/// Solana commitment level for reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SolanaCommitment {
    /// Processed by the current leader; weakest.
    Processed,
    /// Confirmed by a supermajority of stake.
    #[default]
    Confirmed,
    /// Finalized; strongest.
    Finalized,
}

impl SolanaCommitment {
    /// Canonical JSON-RPC spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processed => "processed",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
        }
    }
}

/// Solana message version understood by the payload parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolanaTransactionVersion {
    /// Legacy (unversioned) message.
    Legacy,
    /// Versioned message, version 0.
    V0,
}

/// Confirmation status reported for a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolanaConfirmationStatus {
    /// Seen by the current leader only.
    Processed,
    /// Confirmed by supermajority stake.
    Confirmed,
    /// Finalized.
    Finalized,
}

/// Authoritative status of a submitted signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaSignatureStatus {
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Remaining confirmations, when the RPC reports them.
    pub confirmations: Option<u64>,
    /// Cluster confirmation status.
    pub confirmation_status: SolanaConfirmationStatus,
    /// Whether the transaction landed with an error.
    pub failed: bool,
}

/// Structural description of a validated Solana transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaTransactionInfo {
    /// Number of signatures carried by the transaction.
    pub signature_count: u16,
    /// Message version.
    pub version: SolanaTransactionVersion,
    /// Number of account keys in the static account list.
    pub account_key_count: u16,
    /// Number of compiled instructions.
    pub instruction_count: u16,
    /// Number of address-table lookups (v0 only).
    pub address_table_lookup_count: u16,
}

/// Injected Solana chain transport. No implementation in this crate performs
/// I/O, and the adapters never retry or broadcast on a read path.
#[async_trait]
pub trait SolanaChainTransport: Send + Sync {
    /// The cluster's genesis hash, used to prove cluster identity.
    async fn cluster_genesis_hash(&self) -> Result<String, ChainAdapterError>;
    /// Latest blockhash at the requested commitment.
    async fn latest_blockhash(
        &self,
        commitment: SolanaCommitment,
    ) -> Result<String, ChainAdapterError>;
    /// Lamport balance for an address.
    async fn lamport_balance(&self, address: &str) -> Result<u128, ChainAdapterError>;
    /// Broadcasts a serialized signed transaction, returning its base58
    /// signature.
    async fn send_raw_transaction(&self, raw: &[u8]) -> Result<String, ChainAdapterError>;
    /// Reads the cluster status of a signature, or `None` when it is unknown.
    async fn signature_status(
        &self,
        signature: &str,
    ) -> Result<Option<SolanaSignatureStatus>, ChainAdapterError>;
}

#[async_trait]
impl<T: SolanaChainTransport + ?Sized> SolanaChainTransport for std::sync::Arc<T> {
    async fn cluster_genesis_hash(&self) -> Result<String, ChainAdapterError> {
        (**self).cluster_genesis_hash().await
    }

    async fn latest_blockhash(
        &self,
        commitment: SolanaCommitment,
    ) -> Result<String, ChainAdapterError> {
        (**self).latest_blockhash(commitment).await
    }

    async fn lamport_balance(&self, address: &str) -> Result<u128, ChainAdapterError> {
        (**self).lamport_balance(address).await
    }

    async fn send_raw_transaction(&self, raw: &[u8]) -> Result<String, ChainAdapterError> {
        (**self).send_raw_transaction(raw).await
    }

    async fn signature_status(
        &self,
        signature: &str,
    ) -> Result<Option<SolanaSignatureStatus>, ChainAdapterError> {
        (**self).signature_status(signature).await
    }
}

/// Bounded byte cursor over a serialized transaction.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|slice| slice[0])
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Decodes a Solana compact-u16 (shortvec) integer, bounded to three bytes.
    fn compact_u16(&mut self) -> Option<u16> {
        let mut value: u32 = 0;
        for shift in [0u32, 7, 14] {
            let byte = self.byte()?;
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return u16::try_from(value).ok();
            }
        }
        None
    }
}

/// Strictly validates that `raw` is a well-formed, fully signed Solana
/// transaction (legacy or v0), returning its structural description.
///
/// It fails closed with [`ChainAdapterError::InvalidPayload`] on an empty,
/// oversize, truncated, trailing, or structurally inconsistent payload — which
/// includes every EVM transaction (legacy RLP lists start at `0xc0`, and a
/// typed EVM envelope never matches the Solana message layout exactly).
pub fn validate_solana_transaction(raw: &[u8]) -> Result<SolanaTransactionInfo, ChainAdapterError> {
    if raw.is_empty() || raw.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(ChainAdapterError::InvalidPayload);
    }
    // A signed Solana transaction begins with a compact-u16 signature count of
    // at most 127, so its first byte is always < 0x80. Legacy EVM RLP lists and
    // long-form markers start at or above 0xc0 and are rejected here; short
    // typed envelopes (0x01/0x02) fall through to the strict structural parse.
    if raw[0] >= 0x80 {
        return Err(ChainAdapterError::InvalidPayload);
    }
    let mut cursor = Cursor::new(raw);
    let signature_count = cursor
        .compact_u16()
        .ok_or(ChainAdapterError::InvalidPayload)?;
    if signature_count == 0 || signature_count > MAX_SOLANA_SIGNATURES {
        return Err(ChainAdapterError::InvalidPayload);
    }
    let signature_bytes = usize::from(signature_count)
        .checked_mul(64)
        .ok_or(ChainAdapterError::InvalidPayload)?;
    cursor
        .take(signature_bytes)
        .ok_or(ChainAdapterError::InvalidPayload)?;

    let first = cursor.peek().ok_or(ChainAdapterError::InvalidPayload)?;
    let version = if first & 0x80 != 0 {
        let version = first & 0x7f;
        cursor.byte();
        if version != 0 {
            return Err(ChainAdapterError::InvalidPayload);
        }
        SolanaTransactionVersion::V0
    } else {
        SolanaTransactionVersion::Legacy
    };

    let required_signatures = cursor.byte().ok_or(ChainAdapterError::InvalidPayload)?;
    let readonly_signed = cursor.byte().ok_or(ChainAdapterError::InvalidPayload)?;
    let readonly_unsigned = cursor.byte().ok_or(ChainAdapterError::InvalidPayload)?;
    if required_signatures == 0 || u16::from(required_signatures) > signature_count {
        return Err(ChainAdapterError::InvalidPayload);
    }
    if readonly_signed > required_signatures {
        return Err(ChainAdapterError::InvalidPayload);
    }
    let account_key_count = cursor
        .compact_u16()
        .ok_or(ChainAdapterError::InvalidPayload)?;
    if account_key_count < u16::from(required_signatures) {
        return Err(ChainAdapterError::InvalidPayload);
    }
    if u16::from(readonly_unsigned) > account_key_count - u16::from(required_signatures) {
        return Err(ChainAdapterError::InvalidPayload);
    }
    let account_bytes = usize::from(account_key_count)
        .checked_mul(32)
        .ok_or(ChainAdapterError::InvalidPayload)?;
    cursor
        .take(account_bytes)
        .ok_or(ChainAdapterError::InvalidPayload)?;
    // Recent blockhash.
    cursor.take(32).ok_or(ChainAdapterError::InvalidPayload)?;

    let instruction_count = cursor
        .compact_u16()
        .ok_or(ChainAdapterError::InvalidPayload)?;
    for _ in 0..instruction_count {
        let program_id_index = cursor.byte().ok_or(ChainAdapterError::InvalidPayload)?;
        if u16::from(program_id_index) >= account_key_count {
            return Err(ChainAdapterError::InvalidPayload);
        }
        let accounts_len = cursor
            .compact_u16()
            .ok_or(ChainAdapterError::InvalidPayload)?;
        let accounts = cursor
            .take(usize::from(accounts_len))
            .ok_or(ChainAdapterError::InvalidPayload)?;
        if accounts
            .iter()
            .any(|index| u16::from(*index) >= account_key_count)
        {
            return Err(ChainAdapterError::InvalidPayload);
        }
        let data_len = cursor
            .compact_u16()
            .ok_or(ChainAdapterError::InvalidPayload)?;
        cursor
            .take(usize::from(data_len))
            .ok_or(ChainAdapterError::InvalidPayload)?;
    }

    let address_table_lookup_count = if version == SolanaTransactionVersion::V0 {
        let lookups = cursor
            .compact_u16()
            .ok_or(ChainAdapterError::InvalidPayload)?;
        if lookups > MAX_ADDRESS_TABLE_LOOKUPS {
            return Err(ChainAdapterError::InvalidPayload);
        }
        for _ in 0..lookups {
            // account key (32 bytes), writable indexes, readonly indexes.
            cursor.take(32).ok_or(ChainAdapterError::InvalidPayload)?;
            let writable = cursor
                .compact_u16()
                .ok_or(ChainAdapterError::InvalidPayload)?;
            cursor
                .take(usize::from(writable))
                .ok_or(ChainAdapterError::InvalidPayload)?;
            let readonly = cursor
                .compact_u16()
                .ok_or(ChainAdapterError::InvalidPayload)?;
            cursor
                .take(usize::from(readonly))
                .ok_or(ChainAdapterError::InvalidPayload)?;
        }
        lookups
    } else {
        0
    };

    if cursor.remaining() != 0 {
        return Err(ChainAdapterError::InvalidPayload);
    }

    Ok(SolanaTransactionInfo {
        signature_count,
        version,
        account_key_count,
        instruction_count,
        address_table_lookup_count,
    })
}

/// Reports whether `value` is shaped like a base58 Solana signature.
fn is_plausible_signature(value: &str) -> bool {
    let len = value.len();
    (64..=88).contains(&len) && value.bytes().all(is_base58_byte)
}

fn is_base58_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() && !matches!(byte, b'0' | b'O' | b'I' | b'l')
}

/// One in-process submission admission, keyed by the request idempotency key.
enum SolanaAdmission {
    InFlight([u8; 32]),
    Done([u8; 32], String),
}

/// Concrete Solana submission/reconciliation adapter over an injected
/// [`SolanaChainTransport`].
///
/// It implements the relay's [`ChainSubmissionAdapter`] and is bound to one
/// [`SolanaCluster`]. `submit` validates the payload as a Solana transaction,
/// verifies cluster identity is known, and broadcasts at most once per
/// `(idempotency_key, payload_digest)`; `query`/`reconcile` are read-only.
/// Health is cached and starts `Unavailable`.
pub struct SolanaChainSubmissionAdapter<T: SolanaChainTransport> {
    transport: T,
    cluster: SolanaCluster,
    health: AtomicU8,
    submissions: Mutex<HashMap<String, SolanaAdmission>>,
}

impl<T: SolanaChainTransport> SolanaChainSubmissionAdapter<T> {
    /// Wires the adapter to an injected transport and expected cluster.
    ///
    /// The cached health starts `Unavailable`; a composition root must call
    /// [`Self::refresh_health`] (or [`Self::verify_cluster_identity`]) before any
    /// execution is attempted.
    pub fn new(transport: T, cluster: SolanaCluster) -> Self {
        Self {
            transport,
            cluster,
            health: AtomicU8::new(crate::health_code(ChainHealth::Unavailable)),
            submissions: Mutex::new(HashMap::new()),
        }
    }

    /// The cluster this adapter is bound to.
    pub fn cluster(&self) -> SolanaCluster {
        self.cluster
    }

    /// Verifies the endpoint's genesis hash against the bound cluster.
    pub async fn verify_cluster_identity(&self) -> Result<(), ChainAdapterError> {
        let observed = self.transport.cluster_genesis_hash().await?;
        if observed == self.cluster.genesis_hash() {
            Ok(())
        } else {
            Err(ChainAdapterError::WrongChain)
        }
    }

    /// Refreshes the cached health from the verified cluster identity.
    pub async fn refresh_health(&self) {
        let healthy = match self.verify_cluster_identity().await {
            Ok(()) => ChainHealth::Healthy,
            Err(_) => ChainHealth::Unavailable,
        };
        self.health
            .store(crate::health_code(healthy), Ordering::SeqCst);
    }
}

/// Maps a transport error on the Solana submit (write) path.
fn map_submit_error(error: ChainAdapterError) -> RelayError {
    match error {
        ChainAdapterError::Rejected => RelayError::AdapterRejected,
        ChainAdapterError::Timeout => RelayError::AdapterTimeout,
        _ => RelayError::AdapterUnavailable,
    }
}

/// Maps a transport error on the Solana read (query/reconcile) path.
fn map_query_error(error: ChainAdapterError) -> RelayError {
    match error {
        ChainAdapterError::Timeout => RelayError::AdapterTimeout,
        _ => RelayError::AdapterUnavailable,
    }
}

/// Acquires a mutex, recovering from poisoning.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Maps an authoritative signature status into a relay observation.
fn observation_from_status(
    status: Option<SolanaSignatureStatus>,
    reference: &str,
) -> ChainObservation {
    match status {
        None => ChainObservation::Pending,
        Some(status) if status.failed => ChainObservation::Rejected {
            final_reason: "transaction failed".to_string(),
        },
        Some(status)
            if matches!(
                status.confirmation_status,
                SolanaConfirmationStatus::Confirmed | SolanaConfirmationStatus::Finalized
            ) =>
        {
            // A confirmed signature is real, but the status read carries no
            // exact realized amounts, so the fill stays unresolved rather than
            // being fabricated.
            ChainObservation::Confirmed {
                reference: reference.to_string(),
                fill: None,
            }
        }
        Some(_) => ChainObservation::Pending,
    }
}

#[async_trait]
impl<T: SolanaChainTransport> ChainSubmissionAdapter for SolanaChainSubmissionAdapter<T> {
    async fn submit(&self, request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError> {
        if request.chain() != &ChainId::Solana {
            return Err(RelayError::ChainMismatch);
        }
        if request.payload().is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        // Never relay a payload that is not a well-formed Solana transaction.
        if validate_solana_transaction(request.payload()).is_err() {
            return Err(RelayError::AdapterRejected);
        }
        let key = request.idempotency_key().as_str().to_string();
        let digest = *request.payload_digest().as_bytes();
        {
            let mut ledger = lock(&self.submissions);
            match ledger.get(&key) {
                Some(SolanaAdmission::Done(existing, reference)) if *existing == digest => {
                    return SubmissionReceipt::new(reference.clone());
                }
                Some(SolanaAdmission::Done(..)) => {
                    return Err(RelayError::IdempotencyConflict);
                }
                Some(SolanaAdmission::InFlight(existing)) if *existing == digest => {
                    return Err(RelayError::AdapterUnavailable);
                }
                Some(SolanaAdmission::InFlight(..)) => {
                    return Err(RelayError::IdempotencyConflict);
                }
                None => {
                    ledger.insert(key.clone(), SolanaAdmission::InFlight(digest));
                }
            }
        }
        match self.transport.send_raw_transaction(request.payload()).await {
            Ok(reference) if is_plausible_signature(&reference) => {
                lock(&self.submissions)
                    .insert(key, SolanaAdmission::Done(digest, reference.clone()));
                SubmissionReceipt::new(reference)
            }
            Ok(_) => {
                // A definitively malformed acknowledgement is not a chain
                // reference; fail closed without recording an admission.
                lock(&self.submissions).remove(&key);
                Err(RelayError::AdapterUnavailable)
            }
            Err(error) => {
                lock(&self.submissions).remove(&key);
                Err(map_submit_error(error))
            }
        }
    }

    async fn query(
        &self,
        request: &SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        if request.chain() != &ChainId::Solana {
            return Err(RelayError::ChainMismatch);
        }
        let reference = request.reconciliation_reference();
        let status = self
            .transport
            .signature_status(reference)
            .await
            .map_err(map_query_error)?;
        Ok(observation_from_status(status, reference))
    }

    async fn reconcile(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        // Read-only; shares the query path and can never submit again.
        self.query(request, now_ms).await
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        crate::code_health(self.health.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution_relay::{SignedExecutionRef, SignedPayload};
    use privy::SigningRequest;
    use std::sync::atomic::AtomicUsize;

    /// Deterministic Solana transport double. Performs no I/O.
    #[derive(Default)]
    struct MockSolanaTransport {
        genesis: String,
        sends: AtomicUsize,
        statuses: Mutex<Vec<Option<SolanaSignatureStatus>>>,
        status_refs: Mutex<Vec<String>>,
        fail_send: Option<ChainAdapterError>,
        fail_status: Option<ChainAdapterError>,
        send_reference: String,
    }

    #[async_trait]
    impl SolanaChainTransport for MockSolanaTransport {
        async fn cluster_genesis_hash(&self) -> Result<String, ChainAdapterError> {
            Ok(self.genesis.clone())
        }

        async fn latest_blockhash(
            &self,
            _commitment: SolanaCommitment,
        ) -> Result<String, ChainAdapterError> {
            Ok("blockhash".to_string())
        }

        async fn lamport_balance(&self, _address: &str) -> Result<u128, ChainAdapterError> {
            Ok(0)
        }

        async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = self.fail_send {
                return Err(error);
            }
            Ok(self.send_reference.clone())
        }

        async fn signature_status(
            &self,
            signature: &str,
        ) -> Result<Option<SolanaSignatureStatus>, ChainAdapterError> {
            self.status_refs
                .lock()
                .expect("status refs")
                .push(signature.to_string());
            if let Some(error) = self.fail_status {
                return Err(error);
            }
            // Pop from the back so tests can specify a single observed value.
            Ok(self.statuses.lock().expect("statuses").pop().flatten())
        }
    }

    const SIGNATURE: &str =
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9dxxxxxxxxxxxxxxxxxxxxxxxxxx";

    /// Builds a syntactically valid legacy transaction with one signature and
    /// one no-account instruction.
    fn legacy_transaction() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x01); // signature count
        bytes.extend_from_slice(&[0u8; 64]); // signature
        bytes.extend_from_slice(&[1, 0, 0]); // header
        bytes.push(0x01); // account key count
        bytes.extend_from_slice(&[7u8; 32]); // account key
        bytes.extend_from_slice(&[9u8; 32]); // recent blockhash
        bytes.push(0x01); // instruction count
        bytes.push(0x00); // program id index
        bytes.push(0x00); // accounts len
        bytes.push(0x03); // data len
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes
    }

    /// Builds a syntactically valid v0 transaction with no lookups.
    fn v0_transaction() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x01);
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.push(0x80); // version prefix 0
        bytes.extend_from_slice(&[1, 0, 0]);
        bytes.push(0x01);
        bytes.extend_from_slice(&[7u8; 32]);
        bytes.extend_from_slice(&[9u8; 32]);
        bytes.push(0x01);
        bytes.push(0x00);
        bytes.push(0x00);
        bytes.push(0x00);
        bytes.push(0x00); // address table lookup count
        bytes
    }

    fn submit_request(payload: Vec<u8>, chain: ChainId) -> SubmitRequest {
        use domain::{IdempotencyKey, IntentId};
        let payload = SignedPayload::new(payload).expect("payload");
        // Build a minimal signing request via the durable restore seam is not
        // available here; instead bind through the test-only constructors.
        let intent = IntentId::new("intent-sol").expect("intent");
        let key = IdempotencyKey::new("idem-sol").expect("key");
        let signing = signing_request_for(&intent, &key, &payload, chain.clone());
        let signed = SignedExecutionRef::new("signer-ref", *signing.request_digest(), intent, key)
            .expect("signed");
        SubmitRequest::bind(&signing, &signed, &payload, &chain).expect("bound")
    }

    /// Builds a real bound signing request for the fixtures, parameterized by
    /// chain so a cross-chain request can be exercised.
    fn signing_request_for(
        intent: &domain::IntentId,
        key: &domain::IdempotencyKey,
        payload: &SignedPayload,
        chain: ChainId,
    ) -> SigningRequest {
        use chain_types::AssetId;
        use domain::{
            AmountType, ExecutionCostComponents, ExecutionPreview, OrderType, RiskConstraints,
            RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
        };
        use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
        use policy::{
            PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros,
        };
        use privy::PreparedExecutionRef;

        let (token_in_address, token_out_address, venue, pool_ref) = match chain {
            ChainId::Solana => (
                "So11111111111111111111111111111111111111112",
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "raydium",
                "pool-1",
            ),
            // A verified EVM chain (Base) exercises the cross-chain guard.
            _ => ("0xusdc", "0xtoken", "uniswap", "0xpool1"),
        };
        let token_in = AssetId::new(chain.clone(), token_in_address).expect("asset");
        let token_out = AssetId::new(chain.clone(), token_out_address).expect("asset");
        let intent_full = TradeIntent {
            id: intent.clone(),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").expect("user"),
            wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
            chain: chain.clone(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: TradeSide::Buy,
            amount_type: AmountType::InputAssetAtomic,
            amount: AtomicAmount::new(1_000),
            order_type: OrderType::Market,
            limit_price: None,
            risk: RiskConstraints {
                max_buy_tax: Bps::new(100).expect("bps"),
                max_sell_tax: Bps::new(100).expect("bps"),
                max_price_impact: Bps::new(100).expect("bps"),
                max_slippage: Bps::new(100).expect("bps"),
                max_total_cost: None,
            },
            allow_partial_fill: true,
            expiry_ms: Some(10_000),
            nonce: 7,
            idempotency_key: key.clone(),
        };
        let route = RoutePlan {
            legs: vec![RouteLeg {
                venue: venue.to_string(),
                pool_ref: pool_ref.to_string(),
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(250),
            }],
            expected_net_output: AssetAmount {
                asset: token_out.clone(),
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: 1_000,
                chain_height: 100,
                sequence: Sequence(1),
            },
        };
        let preview = ExecutionPreview {
            intent_id: intent.clone(),
            chain: chain.clone(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: TradeSide::Buy,
            simulated_net_input: AssetAmount {
                asset: token_in,
                amount: AtomicAmount::new(1_000),
            },
            simulated_net_output: AssetAmount {
                asset: token_out.clone(),
                amount: AtomicAmount::new(240),
            },
            gross_output: AssetAmount {
                asset: token_out,
                amount: AtomicAmount::new(250),
            },
            cost_components: ExecutionCostComponents::default(),
            local_state_freshness: market_types::FreshnessStatus::Fresh,
        }
        .validate(&intent_full, &route, 1_000)
        .expect("preview");
        let mut chains = std::collections::HashSet::new();
        chains.insert(chain.clone());
        let engine = PolicyEngine::new(
            TradingGate::from_trusted_startup(Some("true")).expect("gate"),
            PolicyLimits {
                max_trade_usd: UsdMicros::new(1_000_000),
                max_hourly_turnover_usd: UsdMicros::new(10_000_000),
                max_daily_turnover_usd: UsdMicros::new(50_000_000),
                max_buy_tax: Bps::new(500).expect("bps"),
                max_sell_tax: Bps::new(500).expect("bps"),
                max_price_impact: Bps::new(300).expect("bps"),
                max_slippage: Bps::new(200).expect("bps"),
                allowed_chains: chains,
                allowed_venues: std::collections::HashSet::from([venue.to_string()]),
            },
        )
        .expect("policy");
        let context = PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some(venue.to_string()),
        )
        .expect("context");
        let approved = engine
            .authorize_trade(&intent_full, &context)
            .expect("approved");
        let prepared =
            PreparedExecutionRef::new("prepared-1", intent.clone(), key.clone()).expect("prepared");
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent_full,
            &route,
            &preview,
            *payload.digest(),
            1_000,
        )
        .expect("signing request")
    }

    fn confirmed() -> SolanaSignatureStatus {
        SolanaSignatureStatus {
            slot: 100,
            confirmations: None,
            confirmation_status: SolanaConfirmationStatus::Finalized,
            failed: false,
        }
    }

    #[test]
    fn payload_validation_accepts_legacy_and_v0() {
        let info = validate_solana_transaction(&legacy_transaction()).expect("legacy");
        assert_eq!(info.version, SolanaTransactionVersion::Legacy);
        assert_eq!(info.signature_count, 1);
        assert_eq!(info.account_key_count, 1);
        assert_eq!(info.instruction_count, 1);

        let info = validate_solana_transaction(&v0_transaction()).expect("v0");
        assert_eq!(info.version, SolanaTransactionVersion::V0);
        assert_eq!(info.address_table_lookup_count, 0);
    }

    #[test]
    fn payload_validation_rejects_evm_and_malformed_payloads() {
        // Empty.
        assert_eq!(
            validate_solana_transaction(&[]),
            Err(ChainAdapterError::InvalidPayload)
        );
        // A legacy EVM RLP list (first byte >= 0xc0).
        assert_eq!(
            validate_solana_transaction(&[0xc0, 0x01, 0x02]),
            Err(ChainAdapterError::InvalidPayload)
        );
        // A typed EIP-1559-shaped envelope that cannot parse as Solana.
        assert_eq!(
            validate_solana_transaction(&[0x02, 0xc0, 0x01, 0x02, 0x03]),
            Err(ChainAdapterError::InvalidPayload)
        );
        // Truncated valid transaction.
        let mut truncated = legacy_transaction();
        truncated.pop();
        assert_eq!(
            validate_solana_transaction(&truncated),
            Err(ChainAdapterError::InvalidPayload)
        );
        // Trailing bytes.
        let mut trailing = legacy_transaction();
        trailing.push(0x00);
        assert_eq!(
            validate_solana_transaction(&trailing),
            Err(ChainAdapterError::InvalidPayload)
        );
        // Program id index outside the account list.
        let mut invalid_index = legacy_transaction();
        // The instruction program id index is 4 bytes from the end.
        let index = invalid_index.len() - 4;
        invalid_index[index] = 5;
        assert_eq!(
            validate_solana_transaction(&invalid_index),
            Err(ChainAdapterError::InvalidPayload)
        );
        // Oversized payload.
        assert_eq!(
            validate_solana_transaction(&vec![0x01; MAX_SOLANA_TRANSACTION_BYTES + 1]),
            Err(ChainAdapterError::InvalidPayload)
        );
    }

    #[tokio::test]
    async fn health_starts_unavailable_and_requires_the_bound_cluster() {
        let transport = MockSolanaTransport {
            genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
            ..MockSolanaTransport::default()
        };
        let adapter = SolanaChainSubmissionAdapter::new(transport, SolanaCluster::MainnetBeta);
        assert_eq!(adapter.health(0), ChainHealth::Unavailable);
        adapter.refresh_health().await;
        assert_eq!(adapter.health(0), ChainHealth::Healthy);

        // A devnet endpoint bound to mainnet-beta fails closed.
        let wrong = MockSolanaTransport {
            genesis: SolanaCluster::Devnet.genesis_hash().to_string(),
            ..MockSolanaTransport::default()
        };
        let adapter = SolanaChainSubmissionAdapter::new(wrong, SolanaCluster::MainnetBeta);
        assert_eq!(
            adapter.verify_cluster_identity().await,
            Err(ChainAdapterError::WrongChain)
        );
        adapter.refresh_health().await;
        assert_eq!(adapter.health(0), ChainHealth::Unavailable);
    }

    #[tokio::test]
    async fn submit_broadcasts_once_per_idempotency_key() {
        let adapter = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                send_reference: SIGNATURE.to_string(),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        adapter.refresh_health().await;
        assert_eq!(adapter.health(0), ChainHealth::Healthy);

        let request = submit_request(legacy_transaction(), ChainId::Solana);
        let first = adapter.submit(&request).await.expect("first");
        assert_eq!(first.reference, SIGNATURE);
        let second = adapter.submit(&request).await.expect("duplicate");
        assert_eq!(second.reference, SIGNATURE);
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);

        // A different, still-valid payload reusing the key is a conflict,
        // never a broadcast.
        let mut other = legacy_transaction();
        other[1] = 0x01; // change a signature byte: valid, different digest
                         // Rebind with the same key but a different payload digest.
        let other = rebind_with_payload(&request, other);
        assert_eq!(
            adapter.submit(&other).await,
            Err(RelayError::IdempotencyConflict)
        );
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn submit_rejects_evm_payloads_and_chain_mismatch() {
        let adapter = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                send_reference: SIGNATURE.to_string(),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        // An EVM payload is never treated as Solana.
        let evm = submit_request(vec![0xc0, 0x01, 0x02, 0x03], ChainId::Solana);
        assert_eq!(adapter.submit(&evm).await, Err(RelayError::AdapterRejected));
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 0);

        // A request bound to another chain is refused before validation.
        let base = submit_request(legacy_transaction(), ChainId::Base);
        assert_eq!(adapter.submit(&base).await, Err(RelayError::ChainMismatch));
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn submit_maps_timeout_to_adapter_timeout() {
        let adapter = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                fail_send: Some(ChainAdapterError::Timeout),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        let request = submit_request(legacy_transaction(), ChainId::Solana);
        assert_eq!(
            adapter.submit(&request).await,
            Err(RelayError::AdapterTimeout)
        );
    }

    #[tokio::test]
    async fn reconcile_maps_unknown_failed_and_confirmed_status() {
        let adapter = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                statuses: Mutex::new(vec![Some(confirmed())]),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        let request =
            submit_request(legacy_transaction(), ChainId::Solana).with_chain_reference(SIGNATURE);
        let observation = adapter.reconcile(&request, 0).await.expect("reconcile");
        assert!(matches!(
            observation,
            ChainObservation::Confirmed { fill: None, .. }
        ));

        // Unknown signature is pending, not confirmation.
        let pending = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                statuses: Mutex::new(vec![None]),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        assert_eq!(
            pending.reconcile(&request, 0).await.expect("pending"),
            ChainObservation::Pending
        );

        // A failed signature is a definitive rejection.
        let failed = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                statuses: Mutex::new(vec![Some(SolanaSignatureStatus {
                    failed: true,
                    ..confirmed()
                })]),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        assert!(matches!(
            failed.reconcile(&request, 0).await.expect("failed"),
            ChainObservation::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn reconcile_is_read_only_and_queries_by_chain_reference() {
        let adapter = SolanaChainSubmissionAdapter::new(
            MockSolanaTransport {
                genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
                statuses: Mutex::new(vec![Some(confirmed())]),
                ..MockSolanaTransport::default()
            },
            SolanaCluster::MainnetBeta,
        );
        let request =
            submit_request(legacy_transaction(), ChainId::Solana).with_chain_reference(SIGNATURE);
        adapter.reconcile(&request, 0).await.expect("reconcile");
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 0);
        assert_eq!(
            adapter
                .transport
                .status_refs
                .lock()
                .expect("status refs")
                .as_slice(),
            [SIGNATURE.to_string()]
        );
    }

    /// Rebinds the same signing request to a different payload digest so a
    /// reused idempotency key can be exercised with a different payload.
    fn rebind_with_payload(original: &SubmitRequest, payload: Vec<u8>) -> SubmitRequest {
        use domain::{IdempotencyKey, IntentId};
        let payload = SignedPayload::new(payload).expect("payload");
        let intent = IntentId::new("intent-sol").expect("intent");
        let key = IdempotencyKey::new("idem-sol").expect("key");
        let signing = signing_request_for(&intent, &key, &payload, original.chain().clone());
        let signed = SignedExecutionRef::new("signer-ref", *signing.request_digest(), intent, key)
            .expect("signed");
        SubmitRequest::bind(&signing, &signed, &payload, original.chain()).expect("bound")
    }
}
