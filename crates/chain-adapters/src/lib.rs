//! One-chain live adapter foundation (remediation D6) — Base.
//!
//! # Why Base is the first chain
//!
//! `docs/PRD.md` lists the initial chains as Solana, Base, BNB Chain,
//! Robinhood-associated, and Ethereum, and the build order mandates "one chain
//! end-to-end first" without naming a priority. Base is the narrowest
//! highest-priority supported chain that composes correctly with the code that
//! already exists:
//!
//! - `ChainId::Base` already has a canonical signing tag (`1`) in `privy`, and
//!   the locked execution fixtures, route venues (`uniswap_v3`), policy
//!   allowlists, and limit-engine tests are all EVM/Base shaped.
//! - The private execution pipeline (`policy` → `execution-preview` →
//!   `execution-relay` → `execution-store`) is chain-neutral and already exercised
//!   against Base, so no pipeline rewrite is needed.
//! - Solana's Token-2022 extension safety (transfer fees/hooks, permanent
//!   delegate, freeze/mint authority) is first-class PRD work but requires
//!   net-new inspection and simulation code; starting there would add risk before
//!   the one-chain vertical is proven. Solana remains the next chain, and the
//!   adapters here are trait-based so it slots in without changing the pipeline.
//!
//! This does not contradict the PRD: it selects the narrowest chain that can be
//! composed *correctly* with current code, which is what Phase 3 requires.
//!
//! # Boundaries
//!
//! Every network capability is an injected seam ([`BaseChainTransport`],
//! [`MarketCodec`], [`QuoteCodec`]); this crate owns no HTTP client, no
//! credentials, and no signing key. [`BaseChainSubmissionAdapter::new`] takes an
//! operator-injected transport, and the deterministic tests use fixtures only —
//! no real broadcast, no real credentials.
//!
//! This crate is a foundation: it composes concrete ports but is **not** wired
//! into a running service here, and it does not advertise live capability.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU8, Ordering};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use execution_relay::{
    ChainHealth, ChainObservation, ChainSubmissionAdapter, ObservedFill, RelayError,
    SubmissionReceipt, SubmitRequest,
};
use thiserror::Error;

/// Fail-closed adapter error. Redacted: no endpoints, addresses, or payloads.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ChainAdapterError {
    /// The injected transport is unavailable or failed ambiguously.
    #[error("chain transport unavailable")]
    TransportUnavailable,
    /// The transport definitively rejected the request.
    #[error("chain transport rejected request")]
    Rejected,
    /// The requested chain is not Base.
    #[error("unsupported chain")]
    UnsupportedChain,
    /// A response could not be decoded.
    #[error("chain response invalid")]
    InvalidResponse,
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

/// Injected chain transport. No implementation in this crate performs I/O.
///
/// A production implementation owns the RPC endpoint, credentials, and
/// retry-free policy; the adapters below never retry and never broadcast on a
/// read path.
#[async_trait]
pub trait BaseChainTransport: Send + Sync {
    /// Chain id; must be Base's (`8453`) for the adapters to be healthy.
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
impl<T: BaseChainTransport + ?Sized> BaseChainTransport for std::sync::Arc<T> {
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

/// Authoritative Base market-state adapter.
pub struct BaseMarketStateAdapter<T: BaseChainTransport, C: MarketCodec> {
    transport: T,
    codec: C,
}

impl<T: BaseChainTransport, C: MarketCodec> BaseMarketStateAdapter<T, C> {
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

/// Authoritative Base balances and token-metadata adapter.
pub struct BaseWalletAdapter<T: BaseChainTransport> {
    transport: T,
}

impl<T: BaseChainTransport> BaseWalletAdapter<T> {
    /// Wires the adapter from its injected transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Reads an authoritative token balance for `owner`.
    pub async fn balance(
        &self,
        token: &AssetId,
        owner: &str,
    ) -> Result<BalanceObservation, ChainAdapterError> {
        if token.chain != ChainId::Base {
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
        if token.chain != ChainId::Base {
            return Err(ChainAdapterError::UnsupportedChain);
        }
        self.transport.erc20_metadata(&token.address).await
    }
}

/// Exact quote/simulation adapter over an injected codec.
pub struct BaseQuoteAdapter<T: BaseChainTransport, Q: QuoteCodec> {
    transport: T,
    codec: Q,
}

impl<T: BaseChainTransport, Q: QuoteCodec> BaseQuoteAdapter<T, Q> {
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

/// Concrete Base chain submission/reconciliation adapter over an injected RPC
/// transport.
///
/// It implements the relay's [`ChainSubmissionAdapter`], so it can be injected
/// into `ExecutionRelay::production_with_chain`. `submit` broadcasts exactly the
/// bound payload once (no retry); `query`/`reconcile` are read-only. Health is
/// cached and refreshed by [`Self::refresh_health`] because the trait's `health`
/// method is synchronous.
pub struct BaseChainSubmissionAdapter<T: BaseChainTransport> {
    transport: T,
    health: AtomicU8,
}

impl<T: BaseChainTransport> BaseChainSubmissionAdapter<T> {
    /// Wires the adapter from an operator-injected transport.
    ///
    /// The cached health starts `Unavailable`; a composition root must call
    /// [`Self::refresh_health`] before any execution is attempted.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            health: AtomicU8::new(health_code(ChainHealth::Unavailable)),
        }
    }

    /// Refreshes the cached health from the transport's chain id.
    pub async fn refresh_health(&self) {
        let healthy = match self.transport.chain_id().await {
            Ok(8453) => ChainHealth::Healthy,
            Ok(_) => ChainHealth::Unavailable,
            Err(_) => ChainHealth::Unavailable,
        };
        self.health.store(health_code(healthy), Ordering::SeqCst);
    }
}

#[async_trait]
impl<T: BaseChainTransport> ChainSubmissionAdapter for BaseChainSubmissionAdapter<T> {
    async fn submit(&self, request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError> {
        if request.chain() != &ChainId::Base {
            return Err(RelayError::ChainMismatch);
        }
        if request.payload().is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        let reference = self
            .transport
            .send_raw_transaction(request.payload())
            .await
            .map_err(|error| match error {
                ChainAdapterError::Rejected => RelayError::AdapterRejected,
                _ => RelayError::AdapterUnavailable,
            })?;
        SubmissionReceipt::new(reference)
    }

    async fn query(
        &self,
        request: &SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        // Prefer the chain acknowledgement reference when one was recorded;
        // the signer reference is not necessarily the transaction hash.
        let reference = request.reconciliation_reference();
        let receipt = self
            .transport
            .transaction_receipt(reference)
            .await
            .map_err(|_| RelayError::AdapterUnavailable)?;
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
