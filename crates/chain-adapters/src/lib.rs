//! Multi-chain live adapter foundation — shared EVM transport + typed Solana.
//!
//! # Scope
//!
//! Base, Ethereum and BNB Chain share one EVM-family transport seam
//! ([`EvmChainTransport`]) and one submission adapter
//! ([`EvmChainSubmissionAdapter`]) that binds and verifies the expected
//! `eth_chainId`. Solana has a distinct typed seam
//! ([`SolanaChainTransport`]) because its transaction, signature, and
//! confirmation semantics are unrelated to EVM; its payload parser rejects any
//! non-Solana (including EVM) payload.
//!
//! `RobinhoodAssociated` is deliberately **not** an execution chain here: its
//! transport, signing-payload, submit, and receipt layers are unverified, so
//! [`support::execution_support`] records an explicit hard blocker with evidence
//! and the adapter factory refuses to build an execution adapter for it.
//!
//! # Boundaries
//!
//! Every network capability is an injected seam ([`EvmChainTransport`],
//! [`SolanaChainTransport`], [`MarketCodec`], [`QuoteCodec`]); this crate owns
//! no HTTP client, no credentials, and no signing key.
//! [`EvmChainSubmissionAdapter::for_chain`] and
//! [`SolanaChainSubmissionAdapter::new`] take operator-injected transports, and
//! the deterministic tests use fixtures only — no real broadcast, no real
//! credentials, no real endpoint calls.
//!
//! This crate is a foundation: it composes concrete ports and exposes a factory
//! handoff ([`ChainAdapterRegistry`]) but is **not** wired into a running
//! service here, and it does not advertise live capability.

#![forbid(unsafe_code)]

pub mod solana;
pub mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use execution_relay::{
    ChainHealth, ChainObservation, ChainSubmissionAdapter, ObservedFill, RelayError,
    SubmissionReceipt, SubmitRequest,
};
use thiserror::Error;

pub use solana::{
    validate_solana_transaction, SolanaChainSubmissionAdapter, SolanaChainTransport, SolanaCluster,
    SolanaCommitment, SolanaConfirmationStatus, SolanaSignatureStatus, SolanaTransactionInfo,
    SolanaTransactionVersion, MAX_SOLANA_TRANSACTION_BYTES,
};
pub use support::{
    execution_support, submission_adapter_for_chain, ChainAdapterRegistry, ChainExecutionSupport,
    ExecutionBlocker, ExecutionVerdict,
};

/// Fail-closed adapter error. Redacted: no endpoints, addresses, or payloads.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ChainAdapterError {
    /// The injected transport is unavailable or failed ambiguously.
    #[error("chain transport unavailable")]
    TransportUnavailable,
    /// The injected transport timed out; the request state is unknown.
    #[error("chain transport timed out")]
    Timeout,
    /// The transport definitively rejected the request.
    #[error("chain transport rejected request")]
    Rejected,
    /// The requested chain is not the chain this adapter is bound to.
    #[error("unsupported chain")]
    UnsupportedChain,
    /// The transport reported a chain identity that does not match the binding.
    #[error("chain identity mismatch")]
    WrongChain,
    /// A payload is not a well-formed transaction for the bound chain family.
    #[error("chain payload invalid")]
    InvalidPayload,
    /// A response could not be decoded.
    #[error("chain response invalid")]
    InvalidResponse,
}

/// A supported EVM-family execution chain with its canonical chain id.
///
/// `RobinhoodAssociated` is deliberately **not** a variant: its execution
/// semantics are not verified (see [`support`]), so it must not be silently
/// treated as a generic EVM chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvmChain {
    /// Base mainnet (`8453`).
    Base,
    /// Ethereum mainnet (`1`).
    Ethereum,
    /// BNB Smart Chain (`56`).
    BnbChain,
}

impl EvmChain {
    /// The canonical `eth_chainId` value this chain must report.
    pub const fn expected_chain_id(self) -> u64 {
        match self {
            Self::Base => 8453,
            Self::Ethereum => 1,
            Self::BnbChain => 56,
        }
    }

    /// The canonical domain chain identifier.
    pub const fn chain(self) -> ChainId {
        match self {
            Self::Base => ChainId::Base,
            Self::Ethereum => ChainId::Ethereum,
            Self::BnbChain => ChainId::BnbChain,
        }
    }

    /// Maps a domain chain identifier to its EVM execution chain, if it has one.
    ///
    /// Only the three verified EVM chains map; `RobinhoodAssociated` and custom
    /// chains return `None` rather than being guessed into the EVM family.
    pub fn from_chain_id(chain: &ChainId) -> Option<Self> {
        match chain {
            ChainId::Base => Some(Self::Base),
            ChainId::Ethereum => Some(Self::Ethereum),
            ChainId::BnbChain => Some(Self::BnbChain),
            _ => None,
        }
    }

    /// Stable label used in redacted diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Ethereum => "ethereum",
            Self::BnbChain => "bnb_chain",
        }
    }
}

/// Token metadata read from authoritative chain state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenMetadata {
    pub symbol: String,
    pub decimals: u8,
}

/// A wallet balance observation for one asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceObservation {
    pub asset: AssetId,
    pub atomic: u128,
    pub block_number: u64,
}

/// Authoritative pool-state bytes plus the head they were read at.
#[derive(Clone, PartialEq, Eq)]
pub struct PoolStateObservation {
    pub pool_ref: String,
    pub block_number: u64,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for PoolStateObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Pool reference and raw state bytes are private execution semantics.
        formatter.write_str("PoolStateObservation { .. }")
    }
}

/// Exact quote/simulation result.
///
/// Only the exact simulated net output is execution truth; `gross_output` is
/// informational.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteObservation {
    pub gross_output: u128,
    pub net_output: u128,
    pub block_number: u64,
}

/// Receipt status from authoritative chain state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// The transaction succeeded.
    Success,
    /// The transaction reverted.
    Reverted,
    /// The transaction is not yet mined.
    Pending,
}

/// A mined (or pending) receipt observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptObservation {
    pub status: ReceiptStatus,
    pub net_input: Option<u128>,
    pub net_output: Option<u128>,
}

/// Injected EVM-family chain transport shared by Base, Ethereum, and BNB Chain.
///
/// The transport is deliberately chain-agnostic: it reports whatever
/// `eth_chainId` the endpoint answers with, and the chain binding (and its
/// verification) lives in [`EvmChainSubmissionAdapter`]. One concrete JSON-RPC
/// transport therefore serves every EVM chain instead of a copy per chain. No
/// implementation in this crate performs I/O.
///
/// A production implementation owns the RPC endpoint, credentials, and
/// retry-free policy; the adapters below never retry and never broadcast on a
/// read path.
///
/// [`BaseChainTransport`] remains as a compatibility alias for the original
/// Base-only name.
#[async_trait]
pub trait EvmChainTransport: Send + Sync {
    /// The endpoint's reported `eth_chainId`; the adapter binds it to the
    /// expected [`EvmChain::expected_chain_id`] and fails closed on a mismatch.
    async fn chain_id(&self) -> Result<u64, ChainAdapterError>;
    /// Latest block number.
    async fn block_number(&self) -> Result<u64, ChainAdapterError>;
    /// `eth_call` against `to` with `data`, returning the raw return bytes.
    async fn call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, ChainAdapterError>;
    /// ERC-20 `balanceOf(owner)` in atomic units.
    async fn erc20_balance(&self, token: &str, owner: &str) -> Result<u128, ChainAdapterError>;
    /// ERC-20 `symbol()`/`decimals()`.
    async fn erc20_metadata(&self, token: &str) -> Result<TokenMetadata, ChainAdapterError>;
    /// Broadcasts signed transaction bytes, returning the transaction hash.
    async fn send_raw_transaction(&self, raw: &[u8]) -> Result<String, ChainAdapterError>;
    /// Reads a transaction receipt, or `None` while it is not yet mined.
    async fn transaction_receipt(
        &self,
        reference: &str,
    ) -> Result<Option<ReceiptObservation>, ChainAdapterError>;
}

#[async_trait]
impl<T: EvmChainTransport + ?Sized> EvmChainTransport for std::sync::Arc<T> {
    async fn chain_id(&self) -> Result<u64, ChainAdapterError> {
        (**self).chain_id().await
    }

    async fn block_number(&self) -> Result<u64, ChainAdapterError> {
        (**self).block_number().await
    }

    async fn call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
        (**self).call(to, data).await
    }

    async fn erc20_balance(&self, token: &str, owner: &str) -> Result<u128, ChainAdapterError> {
        (**self).erc20_balance(token, owner).await
    }

    async fn erc20_metadata(&self, token: &str) -> Result<TokenMetadata, ChainAdapterError> {
        (**self).erc20_metadata(token).await
    }

    async fn send_raw_transaction(&self, raw: &[u8]) -> Result<String, ChainAdapterError> {
        (**self).send_raw_transaction(raw).await
    }

    async fn transaction_receipt(
        &self,
        reference: &str,
    ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
        (**self).transaction_receipt(reference).await
    }
}

/// Compatibility alias: the original Base-only transport name now denotes the
/// shared EVM-family transport.
pub use EvmChainTransport as BaseChainTransport;

/// Injected encoder/decoder for market-state reads.
pub trait MarketCodec: Send + Sync {
    /// Encodes a pool-state read for `pool_ref`.
    fn encode_pool_state(&self, pool_ref: &str) -> Result<Vec<u8>, ChainAdapterError>;
}

/// Injected encoder/decoder for exact quote simulation.
pub trait QuoteCodec: Send + Sync {
    /// Encodes an exact quote/simulation call for an explicit call target.
    fn encode_quote(
        &self,
        target: &str,
        route_calldata: &[u8],
    ) -> Result<Vec<u8>, ChainAdapterError>;
    /// Decodes a simulation return into gross/net output.
    fn decode_quote(&self, returned: &[u8]) -> Result<(u128, u128), ChainAdapterError>;
}

/// Maps authoritative health into the relay's cached chain-health value.
fn health_code(health: ChainHealth) -> u8 {
    match health {
        ChainHealth::Healthy => 0,
        ChainHealth::Degraded => 1,
        ChainHealth::Unavailable => 2,
    }
}

fn code_health(code: u8) -> ChainHealth {
    match code {
        0 => ChainHealth::Healthy,
        1 => ChainHealth::Degraded,
        _ => ChainHealth::Unavailable,
    }
}

/// Authoritative EVM market-state adapter (chain-agnostic `eth_call` reads).
pub struct EvmMarketStateAdapter<T: EvmChainTransport, C: MarketCodec> {
    transport: T,
    codec: C,
}

impl<T: EvmChainTransport, C: MarketCodec> EvmMarketStateAdapter<T, C> {
    /// Wires the adapter from its injected transport and codec.
    pub fn new(transport: T, codec: C) -> Self {
        Self { transport, codec }
    }

    /// Reads authoritative pool-state bytes at the current head.
    pub async fn read_pool_state(
        &self,
        pool_ref: &str,
    ) -> Result<PoolStateObservation, ChainAdapterError> {
        let data = self.codec.encode_pool_state(pool_ref)?;
        let block_number = self.transport.block_number().await?;
        let data = self.transport.call(pool_ref, &data).await?;
        Ok(PoolStateObservation {
            pool_ref: pool_ref.to_string(),
            block_number,
            data,
        })
    }
}

/// Compatibility alias for the original Base-only market-state adapter name.
pub type BaseMarketStateAdapter<T, C> = EvmMarketStateAdapter<T, C>;

/// Authoritative EVM balances and token-metadata adapter.
///
/// The adapter is bound to one [`EvmChain`] and rejects an asset from any other
/// chain, so a Base read can never be served by an Ethereum or BNB binding and
/// vice versa.
pub struct EvmWalletAdapter<T: EvmChainTransport> {
    transport: T,
    chain: EvmChain,
}

impl<T: EvmChainTransport> EvmWalletAdapter<T> {
    /// Wires the adapter to Base (the historical default).
    pub fn new(transport: T) -> Self {
        Self::for_chain(transport, EvmChain::Base)
    }

    /// Wires the adapter to an explicit EVM chain.
    pub fn for_chain(transport: T, chain: EvmChain) -> Self {
        Self { transport, chain }
    }

    /// The EVM chain this adapter is bound to.
    pub fn chain(&self) -> EvmChain {
        self.chain
    }

    /// Reads an authoritative token balance for `owner`.
    pub async fn balance(
        &self,
        token: &AssetId,
        owner: &str,
    ) -> Result<BalanceObservation, ChainAdapterError> {
        if token.chain != self.chain.chain() {
            return Err(ChainAdapterError::UnsupportedChain);
        }
        let block_number = self.transport.block_number().await?;
        let atomic = self.transport.erc20_balance(&token.address, owner).await?;
        Ok(BalanceObservation {
            asset: token.clone(),
            atomic,
            block_number,
        })
    }

    /// Reads authoritative token metadata.
    pub async fn token_metadata(
        &self,
        token: &AssetId,
    ) -> Result<TokenMetadata, ChainAdapterError> {
        if token.chain != self.chain.chain() {
            return Err(ChainAdapterError::UnsupportedChain);
        }
        self.transport.erc20_metadata(&token.address).await
    }
}

/// Compatibility alias for the original Base-only wallet adapter name.
pub type BaseWalletAdapter<T> = EvmWalletAdapter<T>;

/// Exact quote/simulation adapter over an injected codec.
pub struct EvmQuoteAdapter<T: EvmChainTransport, Q: QuoteCodec> {
    transport: T,
    codec: Q,
}

impl<T: EvmChainTransport, Q: QuoteCodec> EvmQuoteAdapter<T, Q> {
    /// Wires the adapter from its injected transport and quote codec.
    pub fn new(transport: T, codec: Q) -> Self {
        Self { transport, codec }
    }

    /// Simulates a route against an explicit call target and returns the exact
    /// gross/net output.
    pub async fn exact_quote(
        &self,
        target: &str,
        route_calldata: &[u8],
    ) -> Result<QuoteObservation, ChainAdapterError> {
        let encoded = self.codec.encode_quote(target, route_calldata)?;
        let block_number = self.transport.block_number().await?;
        let returned = self.transport.call(target, &encoded).await?;
        let (gross_output, net_output) = self.codec.decode_quote(&returned)?;
        Ok(QuoteObservation {
            gross_output,
            net_output,
            block_number,
        })
    }
}

/// Compatibility alias for the original Base-only quote adapter name.
pub type BaseQuoteAdapter<T, Q> = EvmQuoteAdapter<T, Q>;

/// One in-process submission admission, keyed by the request idempotency key.
enum SubmitAdmission {
    /// A submission with this payload digest is being broadcast right now.
    InFlight([u8; 32]),
    /// A submission with this payload digest completed with this reference.
    Done([u8; 32], String),
}

/// Concrete EVM chain submission/reconciliation adapter over a shared injected
/// RPC transport.
///
/// It implements the relay's [`ChainSubmissionAdapter`], so it can be injected
/// into `ExecutionRelay::production_with_chain`. One adapter instance is bound
/// to exactly one [`EvmChain`] and verifies the endpoint's `eth_chainId` against
/// that binding, so the same shared transport serves Base, Ethereum and BNB
/// Chain without a per-chain copy.
///
/// `submit` broadcasts exactly the bound payload once (no retry) and is
/// idempotent on `(idempotency_key, payload_digest)`: a replay returns the
/// already-observed reference without a second broadcast, while a reused key
/// with a different payload fails closed with
/// [`RelayError::IdempotencyConflict`]. `query`/`reconcile` are read-only and
/// reject a request bound to a different chain. Health is cached and refreshed
/// by [`Self::refresh_health`] because the trait's `health` method is
/// synchronous.
pub struct EvmChainSubmissionAdapter<T: EvmChainTransport> {
    transport: T,
    chain: EvmChain,
    health: AtomicU8,
    submissions: Mutex<HashMap<String, SubmitAdmission>>,
}

impl<T: EvmChainTransport> EvmChainSubmissionAdapter<T> {
    /// Wires the adapter to Base (the historical default).
    ///
    /// The cached health starts `Unavailable`; a composition root must call
    /// [`Self::refresh_health`] before any execution is attempted.
    pub fn new(transport: T) -> Self {
        Self::for_chain(transport, EvmChain::Base)
    }

    /// Wires the adapter to an explicit EVM chain.
    pub fn for_chain(transport: T, chain: EvmChain) -> Self {
        Self {
            transport,
            chain,
            health: AtomicU8::new(health_code(ChainHealth::Unavailable)),
            submissions: Mutex::new(HashMap::new()),
        }
    }

    /// The EVM chain this adapter is bound to.
    pub fn chain(&self) -> EvmChain {
        self.chain
    }

    /// Verifies the endpoint's reported chain id against the binding, failing
    /// closed with [`ChainAdapterError::WrongChain`] on a mismatch.
    pub async fn verify_chain_identity(&self) -> Result<(), ChainAdapterError> {
        let observed = self.transport.chain_id().await?;
        if observed == self.chain.expected_chain_id() {
            Ok(())
        } else {
            Err(ChainAdapterError::WrongChain)
        }
    }

    /// Refreshes the cached health from the transport's verified chain id.
    pub async fn refresh_health(&self) {
        let healthy = match self.verify_chain_identity().await {
            Ok(()) => ChainHealth::Healthy,
            Err(_) => ChainHealth::Unavailable,
        };
        self.health.store(health_code(healthy), Ordering::SeqCst);
    }
}

/// Compatibility alias for the original Base-only submission adapter name.
///
/// `BaseChainSubmissionAdapter::new(transport)` binds Base, exactly as before;
/// use [`EvmChainSubmissionAdapter::for_chain`] for Ethereum or BNB Chain.
pub type BaseChainSubmissionAdapter<T> = EvmChainSubmissionAdapter<T>;

/// Maps a transport error on the submit (write) path to a redacted relay error.
fn map_submit_error(error: ChainAdapterError) -> RelayError {
    match error {
        ChainAdapterError::Rejected => RelayError::AdapterRejected,
        ChainAdapterError::Timeout => RelayError::AdapterTimeout,
        _ => RelayError::AdapterUnavailable,
    }
}

/// Maps a transport error on the read (query/reconcile) path.
fn map_query_error(error: ChainAdapterError) -> RelayError {
    match error {
        ChainAdapterError::Timeout => RelayError::AdapterTimeout,
        _ => RelayError::AdapterUnavailable,
    }
}

/// Acquires a mutex, recovering from poisoning (plain map; never panics).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[async_trait]
impl<T: EvmChainTransport> ChainSubmissionAdapter for EvmChainSubmissionAdapter<T> {
    async fn submit(&self, request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError> {
        if request.chain() != &self.chain.chain() {
            return Err(RelayError::ChainMismatch);
        }
        if request.payload().is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        let key = request.idempotency_key().as_str().to_string();
        let digest = *request.payload_digest().as_bytes();
        {
            let mut ledger = lock(&self.submissions);
            match ledger.get(&key) {
                Some(SubmitAdmission::Done(existing, reference)) if *existing == digest => {
                    return SubmissionReceipt::new(reference.clone());
                }
                Some(SubmitAdmission::Done(..)) => {
                    return Err(RelayError::IdempotencyConflict);
                }
                Some(SubmitAdmission::InFlight(existing)) if *existing == digest => {
                    // A concurrent duplicate is not allowed to broadcast again.
                    return Err(RelayError::AdapterUnavailable);
                }
                Some(SubmitAdmission::InFlight(..)) => {
                    return Err(RelayError::IdempotencyConflict);
                }
                None => {
                    ledger.insert(key.clone(), SubmitAdmission::InFlight(digest));
                }
            }
        }
        match self.transport.send_raw_transaction(request.payload()).await {
            Ok(reference) => {
                let mut ledger = lock(&self.submissions);
                ledger.insert(key, SubmitAdmission::Done(digest, reference.clone()));
                SubmissionReceipt::new(reference)
            }
            Err(error) => {
                // The admission is released so a later explicit retry is not
                // permanently wedged; the relay itself never auto-retries.
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
        if request.chain() != &self.chain.chain() {
            return Err(RelayError::ChainMismatch);
        }
        // Prefer the chain acknowledgement reference when one was recorded;
        // the signer reference is not necessarily the transaction hash.
        let reference = request.reconciliation_reference();
        let receipt = self
            .transport
            .transaction_receipt(reference)
            .await
            .map_err(map_query_error)?;
        Ok(observation_from_receipt(receipt, reference))
    }

    async fn reconcile(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        // Reconciliation is read-only and shares the query path; it can never
        // submit a second time.
        self.query(request, now_ms).await
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        code_health(self.health.load(Ordering::SeqCst))
    }
}

fn observation_from_receipt(
    receipt: Option<ReceiptObservation>,
    reference: &str,
) -> ChainObservation {
    match receipt {
        None => ChainObservation::Pending,
        Some(ReceiptObservation {
            status: ReceiptStatus::Pending,
            ..
        }) => ChainObservation::Pending,
        Some(ReceiptObservation {
            status: ReceiptStatus::Reverted,
            ..
        }) => ChainObservation::Rejected {
            final_reason: "transaction reverted".to_string(),
        },
        Some(ReceiptObservation {
            status: ReceiptStatus::Success,
            net_input,
            net_output,
        }) => {
            let fill = match (net_input, net_output) {
                (Some(input), Some(output)) => Some(ObservedFill {
                    net_input: input,
                    net_output: output,
                }),
                // A confirmation without both exact amounts is real but
                // unresolved; never fabricate a fill.
                _ => None,
            };
            ChainObservation::Confirmed {
                reference: reference.to_string(),
                fill,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic transport double. Records calls; performs no I/O.
    #[derive(Default)]
    struct MockTransport {
        chain_id: u64,
        block: u64,
        call_result: Vec<u8>,
        balance: u128,
        sends: AtomicU8,
        calls: Mutex<Vec<String>>,
        receipt_refs: Mutex<Vec<String>>,
        receipt: Option<ReceiptObservation>,
        send_error: Option<ChainAdapterError>,
        receipt_error: Option<ChainAdapterError>,
    }

    #[async_trait]
    impl BaseChainTransport for MockTransport {
        async fn chain_id(&self) -> Result<u64, ChainAdapterError> {
            Ok(self.chain_id)
        }

        async fn block_number(&self) -> Result<u64, ChainAdapterError> {
            Ok(self.block)
        }

        async fn call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
            self.calls.lock().expect("calls").push(to.to_string());
            let _ = data;
            Ok(self.call_result.clone())
        }

        async fn erc20_balance(
            &self,
            _token: &str,
            _owner: &str,
        ) -> Result<u128, ChainAdapterError> {
            Ok(self.balance)
        }

        async fn erc20_metadata(&self, _token: &str) -> Result<TokenMetadata, ChainAdapterError> {
            Ok(TokenMetadata {
                symbol: "USDC".to_string(),
                decimals: 6,
            })
        }

        async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = self.send_error {
                return Err(error);
            }
            Ok("0xreceipt".to_string())
        }

        async fn transaction_receipt(
            &self,
            reference: &str,
        ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
            self.receipt_refs
                .lock()
                .expect("receipt refs")
                .push(reference.to_string());
            if let Some(error) = self.receipt_error {
                return Err(error);
            }
            Ok(self.receipt.clone())
        }
    }

    struct MockCodec;

    impl MarketCodec for MockCodec {
        fn encode_pool_state(&self, _pool_ref: &str) -> Result<Vec<u8>, ChainAdapterError> {
            Ok(vec![0x01])
        }
    }

    impl QuoteCodec for MockCodec {
        fn encode_quote(
            &self,
            _target: &str,
            _route_calldata: &[u8],
        ) -> Result<Vec<u8>, ChainAdapterError> {
            Ok(vec![0x02])
        }

        fn decode_quote(&self, _returned: &[u8]) -> Result<(u128, u128), ChainAdapterError> {
            Ok((250, 240))
        }
    }

    #[tokio::test]
    async fn market_state_and_quote_use_the_injected_transport() {
        let transport = MockTransport {
            chain_id: 8453,
            block: 123,
            call_result: vec![0xaa, 0xbb],
            ..MockTransport::default()
        };
        let market = BaseMarketStateAdapter::new(transport, MockCodec);
        let state = market.read_pool_state("0xpool").await.expect("pool state");
        assert_eq!(state.block_number, 123);
        assert_eq!(state.data, vec![0xaa, 0xbb]);
    }

    #[tokio::test]
    async fn wallet_reads_balance_and_metadata() {
        let transport = MockTransport {
            block: 7,
            balance: 42,
            ..MockTransport::default()
        };
        let wallet = BaseWalletAdapter::new(transport);
        let asset = AssetId::new(ChainId::Base, "0xusdc").expect("asset");
        let balance = wallet.balance(&asset, "0xowner").await.expect("balance");
        assert_eq!(balance.atomic, 42);
        assert_eq!(balance.block_number, 7);
        let metadata = wallet.token_metadata(&asset).await.expect("metadata");
        assert_eq!(metadata.decimals, 6);
    }

    #[tokio::test]
    async fn quote_returns_exact_net_output() {
        let transport = MockTransport::default();
        let quote = BaseQuoteAdapter::new(transport, MockCodec);
        let observation = quote
            .exact_quote("0xrouter", b"swap-calldata")
            .await
            .expect("quote");
        assert_eq!(observation.gross_output, 250);
        assert_eq!(observation.net_output, 240);
    }

    #[test]
    fn submission_health_starts_unavailable_until_refreshed() {
        let adapter = BaseChainSubmissionAdapter::new(MockTransport::default());
        assert_eq!(adapter.health(0), ChainHealth::Unavailable);
    }

    #[tokio::test]
    async fn submission_adapter_broadcasts_once_and_reconciles_read_only() {
        let adapter = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt: Some(ReceiptObservation {
                status: ReceiptStatus::Success,
                net_input: Some(10),
                net_output: Some(20),
            }),
            ..MockTransport::default()
        });
        adapter.refresh_health().await;
        assert_eq!(adapter.health(0), ChainHealth::Healthy);

        let payload = execution_relay::SignedPayload::new(vec![1, 2, 3]).expect("payload");
        let signing = privy::SigningRequest::bind(
            &fixture_engine(),
            &fixture_approved(),
            &fixture_prepared(),
            &fixture_intent(),
            &fixture_route(),
            &fixture_preview(),
            *payload.digest(),
            1_000,
        )
        .expect("bind");
        let signed = execution_relay::SignedExecutionRef::new(
            "0xtx",
            *signing.request_digest(),
            signing.intent_id().clone(),
            signing.idempotency_key().clone(),
        )
        .expect("signed");
        let request = SubmitRequest::bind(&signing, &signed, &payload, &ChainId::Base)
            .expect("submit request")
            .with_chain_reference("0xbroadcast-hash");

        let receipt = adapter.submit(&request).await.expect("submit");
        assert!(!receipt.reference.is_empty());
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);
        assert_eq!(request.reconciliation_reference(), "0xbroadcast-hash");

        let observation = adapter.reconcile(&request, 0).await.expect("reconcile");
        assert!(matches!(
            observation,
            ChainObservation::Confirmed { fill: Some(_), .. }
        ));
        // Reconciliation never broadcasts, and it queries by the chain
        // acknowledgement hash rather than the signer reference.
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);
        assert_eq!(
            adapter
                .transport
                .receipt_refs
                .lock()
                .expect("receipt refs")
                .as_slice(),
            ["0xbroadcast-hash".to_string()]
        );
    }

    /// Builds a fully bound Base submit request with the shared fixture identity.
    fn fixture_bound_request(payload: Vec<u8>) -> SubmitRequest {
        let payload = execution_relay::SignedPayload::new(payload).expect("payload");
        let signing = privy::SigningRequest::bind(
            &fixture_engine(),
            &fixture_approved(),
            &fixture_prepared(),
            &fixture_intent(),
            &fixture_route(),
            &fixture_preview(),
            *payload.digest(),
            1_000,
        )
        .expect("bind");
        let signed = execution_relay::SignedExecutionRef::new(
            "0xtx",
            *signing.request_digest(),
            signing.intent_id().clone(),
            signing.idempotency_key().clone(),
        )
        .expect("signed");
        SubmitRequest::bind(&signing, &signed, &payload, &ChainId::Base).expect("submit request")
    }

    #[tokio::test]
    async fn submission_adapter_verifies_the_bound_chain_id() {
        // A Base binding against a chain-1 endpoint fails closed.
        let wrong = BaseChainSubmissionAdapter::for_chain(
            MockTransport {
                chain_id: 1,
                ..MockTransport::default()
            },
            EvmChain::Base,
        );
        assert_eq!(
            wrong.verify_chain_identity().await,
            Err(ChainAdapterError::WrongChain)
        );
        wrong.refresh_health().await;
        assert_eq!(wrong.health(0), ChainHealth::Unavailable);

        // The matching binding verifies and becomes healthy.
        let right = BaseChainSubmissionAdapter::for_chain(
            MockTransport {
                chain_id: 8453,
                ..MockTransport::default()
            },
            EvmChain::Base,
        );
        assert_eq!(right.verify_chain_identity().await, Ok(()));
        right.refresh_health().await;
        assert_eq!(right.health(0), ChainHealth::Healthy);
    }

    #[tokio::test]
    async fn submission_adapter_prevents_duplicate_submits() {
        let adapter = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            ..MockTransport::default()
        });
        let request = fixture_bound_request(vec![1, 2, 3]);
        let first = adapter.submit(&request).await.expect("first");
        let replay = adapter.submit(&request).await.expect("replay");
        assert_eq!(first.reference, replay.reference);
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);

        // The same idempotency key with a different payload is a conflict, and
        // never reaches the transport.
        let conflicting = fixture_bound_request(vec![9, 9, 9]);
        assert_eq!(
            adapter.submit(&conflicting).await,
            Err(RelayError::IdempotencyConflict)
        );
        assert_eq!(adapter.transport.sends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn submission_adapter_separates_evm_chains() {
        let bnb = BaseChainSubmissionAdapter::for_chain(
            MockTransport {
                chain_id: 56,
                ..MockTransport::default()
            },
            EvmChain::BnbChain,
        );
        assert_eq!(bnb.verify_chain_identity().await, Ok(()));
        // A Base-bound request is refused by the BNB-bound adapter on both the
        // write and read paths.
        let request = fixture_bound_request(vec![1, 2, 3]);
        assert_eq!(bnb.submit(&request).await, Err(RelayError::ChainMismatch));
        assert_eq!(bnb.query(&request, 0).await, Err(RelayError::ChainMismatch));
        assert_eq!(bnb.transport.sends.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn evm_chain_family_mapping_is_explicit() {
        assert_eq!(EvmChain::Base.expected_chain_id(), 8453);
        assert_eq!(EvmChain::Ethereum.expected_chain_id(), 1);
        assert_eq!(EvmChain::BnbChain.expected_chain_id(), 56);
        assert_eq!(
            EvmChain::from_chain_id(&ChainId::Base),
            Some(EvmChain::Base)
        );
        assert_eq!(
            EvmChain::from_chain_id(&ChainId::Ethereum),
            Some(EvmChain::Ethereum)
        );
        assert_eq!(
            EvmChain::from_chain_id(&ChainId::BnbChain),
            Some(EvmChain::BnbChain)
        );
        // Solana is a different family, and Robinhood-associated is not guessed
        // into the EVM family.
        assert_eq!(EvmChain::from_chain_id(&ChainId::Solana), None);
        assert_eq!(EvmChain::from_chain_id(&ChainId::RobinhoodAssociated), None);
        assert_eq!(
            EvmChain::from_chain_id(&ChainId::Other("hypercore".to_string())),
            None
        );
    }

    #[tokio::test]
    async fn submission_adapter_maps_transport_failures() {
        // Malformed response on the write path.
        let malformed = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            send_error: Some(ChainAdapterError::InvalidResponse),
            ..MockTransport::default()
        });
        let request = fixture_bound_request(vec![1, 2, 3]);
        assert_eq!(
            malformed.submit(&request).await,
            Err(RelayError::AdapterUnavailable)
        );
        // A timeout on the write path is a typed timeout.
        let timeout = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            send_error: Some(ChainAdapterError::Timeout),
            ..MockTransport::default()
        });
        assert_eq!(
            timeout.submit(&request).await,
            Err(RelayError::AdapterTimeout)
        );
        // Malformed and timed-out reads are read-only failures.
        let bad_read = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt_error: Some(ChainAdapterError::InvalidResponse),
            ..MockTransport::default()
        });
        assert_eq!(
            bad_read.query(&request, 0).await,
            Err(RelayError::AdapterUnavailable)
        );
        let slow_read = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt_error: Some(ChainAdapterError::Timeout),
            ..MockTransport::default()
        });
        assert_eq!(
            slow_read.query(&request, 0).await,
            Err(RelayError::AdapterTimeout)
        );
        assert_eq!(slow_read.transport.sends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn submission_adapter_maps_unknown_and_unresolved_receipts() {
        let request = fixture_bound_request(vec![1, 2, 3]).with_chain_reference("0xhash");

        // An unmined/unknown receipt is pending, never a confirmation.
        let unknown = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            ..MockTransport::default()
        });
        assert_eq!(
            unknown.reconcile(&request, 0).await.expect("unknown"),
            ChainObservation::Pending
        );

        // A success receipt without exact amounts confirms but leaves the fill
        // unresolved instead of fabricating one.
        let unresolved = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt: Some(ReceiptObservation {
                status: ReceiptStatus::Success,
                net_input: None,
                net_output: None,
            }),
            ..MockTransport::default()
        });
        assert!(matches!(
            unresolved.reconcile(&request, 0).await.expect("unresolved"),
            ChainObservation::Confirmed { fill: None, .. }
        ));

        // A reverted receipt is a definitive rejection.
        let reverted = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt: Some(ReceiptObservation {
                status: ReceiptStatus::Reverted,
                net_input: None,
                net_output: None,
            }),
            ..MockTransport::default()
        });
        assert!(matches!(
            reverted.reconcile(&request, 0).await.expect("reverted"),
            ChainObservation::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn restart_reconciliation_never_resubmits() {
        let first = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt: Some(ReceiptObservation {
                status: ReceiptStatus::Success,
                net_input: Some(1),
                net_output: Some(2),
            }),
            ..MockTransport::default()
        });
        let request = fixture_bound_request(vec![1, 2, 3]);
        first.submit(&request).await.expect("submit");
        assert_eq!(first.transport.sends.load(Ordering::SeqCst), 1);

        // A fresh adapter over the same endpoint (empty in-process ledger) must
        // reconcile a broadcast attempt without resubmitting it.
        let restarted = BaseChainSubmissionAdapter::new(MockTransport {
            chain_id: 8453,
            receipt: Some(ReceiptObservation {
                status: ReceiptStatus::Success,
                net_input: Some(1),
                net_output: Some(2),
            }),
            ..MockTransport::default()
        });
        let observation = restarted
            .reconcile(&request.with_chain_reference("0xbroadcast-hash"), 0)
            .await
            .expect("reconcile");
        assert!(matches!(
            observation,
            ChainObservation::Confirmed { fill: Some(_), .. }
        ));
        assert_eq!(restarted.transport.sends.load(Ordering::SeqCst), 0);
    }

    fn fixture_intent() -> domain::TradeIntent {
        fixture_intent_with_nonce(7)
    }

    fn fixture_intent_with_nonce(nonce: u64) -> domain::TradeIntent {
        use domain::{
            AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeIntent,
            TradeSide, TradeSource, UserId, WalletRef,
        };
        use market_types::{AtomicAmount, Bps};
        TradeIntent {
            id: IntentId::new("intent-1").expect("intent"),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").expect("user"),
            wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
            chain: ChainId::Base,
            token_in: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            token_out: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
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
            nonce,
            idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
        }
    }

    fn fixture_route() -> domain::RoutePlan {
        use domain::{RouteLeg, RoutePlan};
        use market_types::{AssetAmount, AtomicAmount, Freshness, Sequence};
        let token_in = AssetId::new(ChainId::Base, "USDC").expect("asset");
        let token_out = AssetId::new(ChainId::Base, "TOKEN").expect("asset");
        RoutePlan {
            legs: vec![RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "0xpool1".to_string(),
                token_in,
                token_out: token_out.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(250),
            }],
            expected_net_output: AssetAmount {
                asset: token_out,
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: 1_000,
                chain_height: 100,
                sequence: Sequence(1),
            },
        }
    }

    fn fixture_engine() -> policy::PolicyEngine {
        use market_types::Bps;
        use policy::{PolicyEngine, PolicyLimits, TradingGate, UsdMicros};
        let mut chains = std::collections::HashSet::new();
        chains.insert(ChainId::Base);
        PolicyEngine::new(
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
                allowed_venues: std::collections::HashSet::from(["uniswap".to_string()]),
            },
        )
        .expect("policy")
    }

    fn fixture_context() -> policy::PolicyContext {
        use policy::{PolicyContext, TurnoverSnapshot, UsdMicros};
        PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".to_string()),
        )
        .expect("context")
    }

    fn fixture_approved() -> policy::ApprovedExecution {
        fixture_engine()
            .authorize_trade(&fixture_intent(), &fixture_context())
            .expect("approved")
    }

    fn fixture_prepared() -> privy::PreparedExecutionRef {
        privy::PreparedExecutionRef::new(
            "prepared-1",
            fixture_intent().id.clone(),
            fixture_intent().idempotency_key.clone(),
        )
        .expect("prepared")
    }

    fn fixture_preview() -> domain::ValidatedExecutionPreview {
        use domain::{ExecutionCostComponents, ExecutionPreview};
        use market_types::AssetAmount;
        ExecutionPreview {
            intent_id: fixture_intent().id.clone(),
            chain: ChainId::Base,
            token_in: fixture_intent().token_in.clone(),
            token_out: fixture_intent().token_out.clone(),
            side: fixture_intent().side,
            simulated_net_input: AssetAmount {
                asset: fixture_intent().token_in.clone(),
                amount: market_types::AtomicAmount::new(1_000),
            },
            simulated_net_output: AssetAmount {
                asset: fixture_intent().token_out.clone(),
                amount: market_types::AtomicAmount::new(240),
            },
            gross_output: AssetAmount {
                asset: fixture_intent().token_out.clone(),
                amount: market_types::AtomicAmount::new(250),
            },
            cost_components: ExecutionCostComponents::default(),
            local_state_freshness: market_types::FreshnessStatus::Fresh,
        }
        .validate(&fixture_intent(), &fixture_route(), 1_000)
        .expect("preview")
    }
}
