//! D6 — one-chain live composition over the Base adapter with deterministic
//! mock transports.
//!
//! This drives `ExecutionRelay::production_with_chain` with the concrete
//! [`BaseChainSubmissionAdapter`] and a real [`PrivySigningBoundary`] over an
//! injected mock signing transport. It proves the production composition path
//! exists end to end while performing **no real broadcast and no real
//! credentials**:
//!
//! - the kill switch blocks before the signer or the chain adapter is reached;
//! - an enabled attempt signs once, submits once, and reconciles read-only;
//! - a restart over the same durable store reconciles without a second submit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chain_adapters::{
    BaseChainSubmissionAdapter, BaseChainTransport, ChainAdapterError, ReceiptObservation,
    ReceiptStatus,
};
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, OrderType,
    RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId,
    ValidatedExecutionPreview, WalletRef,
};
use execution_relay::{
    ChainHealth, ChainHealthBreaker, ChainSubmissionAdapter, DeterministicDurableStore,
    ExecutionRelay, PrivySigningBoundaryAdapter, RelayError, RelayExecutionInput, RelayOutcome,
    SignedPayload, SignedPayloadSource,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
use policy::{
    ApprovedExecution, PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot,
    UsdMicros,
};
use privy::{PreparedExecutionRef, ProviderIdempotencyId, SigningRequest, SigningTransport};

const NOW_MS: i64 = 1_000;

/// Mock Base transport: records sends, performs no I/O.
#[derive(Default)]
struct MockBaseTransport {
    sends: AtomicUsize,
    receipts: Mutex<Vec<ReceiptObservation>>,
    receipt_refs: Mutex<Vec<String>>,
}

#[async_trait]
impl BaseChainTransport for MockBaseTransport {
    async fn chain_id(&self) -> Result<u64, ChainAdapterError> {
        Ok(8453)
    }

    async fn block_number(&self) -> Result<u64, ChainAdapterError> {
        Ok(100)
    }

    async fn call(&self, _to: &str, _data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
        Ok(Vec::new())
    }

    async fn erc20_balance(&self, _token: &str, _owner: &str) -> Result<u128, ChainAdapterError> {
        Ok(0)
    }

    async fn erc20_metadata(
        &self,
        _token: &str,
    ) -> Result<chain_adapters::TokenMetadata, ChainAdapterError> {
        Ok(chain_adapters::TokenMetadata {
            symbol: "MOCK".to_string(),
            decimals: 18,
        })
    }

    async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok("0xsubmitted-hash".to_string())
    }

    async fn transaction_receipt(
        &self,
        reference: &str,
    ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
        self.receipt_refs
            .lock()
            .expect("receipt refs")
            .push(reference.to_string());
        // The reconciliation key must be the broadcast hash, never the signer's
        // opaque reference. Returning `None` for anything else makes the
        // regression observable.
        if reference != "0xsubmitted-hash" {
            return Ok(None);
        }
        Ok(self.receipts.lock().expect("receipts").pop())
    }
}

/// Mock signing transport that returns a fixed reference and counts calls.
struct CountingSigningTransport {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SigningTransport for CountingSigningTransport {
    async fn submit_signing_request(
        &self,
        _request: &SigningRequest,
        idempotency: &ProviderIdempotencyId,
    ) -> Result<String, privy::PrivyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(idempotency.as_str().starts_with("pep-sign-v1-"));
        Ok("0xsigned-ref".to_string())
    }
}

/// Constant payload source.
struct ConstantPayloadSource {
    payload: SignedPayload,
}

#[async_trait]
impl SignedPayloadSource for ConstantPayloadSource {
    async fn payload_to_sign(
        &self,
        _key: &IdempotencyKey,
        _intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        Ok(self.payload.clone())
    }

    async fn signed_payload(
        &self,
        _signed: &execution_relay::SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        Ok(self.payload.clone())
    }
}

struct Fixtures {
    intent: TradeIntent,
    context: PolicyContext,
    prepared: PreparedExecutionRef,
    approved: ApprovedExecution,
    route: RoutePlan,
    preview: ValidatedExecutionPreview,
}

fn fixtures() -> Fixtures {
    let intent = fixture_intent();
    let route = fixture_route();
    let engine = fixture_engine();
    let context = fixture_context();
    let approved = engine.authorize_trade(&intent, &context).expect("approved");
    let prepared = PreparedExecutionRef::new(
        "prepared-1",
        intent.id.clone(),
        intent.idempotency_key.clone(),
    )
    .expect("prepared");
    let preview = fixture_preview(&intent, &route);
    Fixtures {
        intent,
        context,
        prepared,
        approved,
        route,
        preview,
    }
}

fn fixture_intent() -> TradeIntent {
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
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn fixture_route() -> RoutePlan {
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
            observed_at_ms: NOW_MS,
            chain_height: 100,
            sequence: Sequence(1),
        },
    }
}

fn fixture_engine() -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).expect("gate"),
        fixture_limits(),
    )
    .expect("engine")
}

fn fixture_context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("context")
}

fn fixture_preview(intent: &TradeIntent, route: &RoutePlan) -> ValidatedExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: ChainId::Base,
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: intent.side,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(1_000),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(240),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(250),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: market_types::FreshnessStatus::Fresh,
    }
    .validate(intent, route, NOW_MS)
    .expect("preview")
}

type LiveRelay = ExecutionRelay<
    Arc<DeterministicDurableStore>,
    Arc<BaseChainSubmissionAdapter<Arc<MockBaseTransport>>>,
    Arc<ConstantPayloadSource>,
    PrivySigningBoundaryAdapter,
>;

struct Harness {
    relay: LiveRelay,
    store: Arc<DeterministicDurableStore>,
    adapter: Arc<BaseChainSubmissionAdapter<Arc<MockBaseTransport>>>,
    transport: Arc<MockBaseTransport>,
    signer_calls: Arc<AtomicUsize>,
    fixtures: Fixtures,
}

fn harness_with_policy(
    policy: PolicyEngine,
    store: Arc<DeterministicDurableStore>,
    receipt: Option<ReceiptObservation>,
) -> Harness {
    let mut receipts = Vec::new();
    if let Some(receipt) = receipt {
        receipts.push(receipt);
    }
    let transport = Arc::new(MockBaseTransport {
        sends: AtomicUsize::new(0),
        receipts: Mutex::new(receipts),
        receipt_refs: Mutex::new(Vec::new()),
    });
    let adapter = Arc::new(BaseChainSubmissionAdapter::new(Arc::clone(&transport)));
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let payload = SignedPayload::new(b"mock-signed-transaction".to_vec()).expect("payload");
    let relay = ExecutionRelay::production_with_chain(
        policy,
        Arc::clone(&store),
        Arc::clone(&adapter),
        Arc::new(ConstantPayloadSource { payload }),
        Box::new(CountingSigningTransport {
            calls: Arc::clone(&signer_calls),
        }),
        ChainHealthBreaker::new(2, 5_000),
    );
    Harness {
        relay,
        store,
        adapter,
        transport,
        signer_calls,
        fixtures: fixtures(),
    }
}

impl Harness {
    fn input(&self) -> RelayExecutionInput<'_> {
        RelayExecutionInput {
            intent: &self.fixtures.intent,
            policy_context: &self.fixtures.context,
            prepared: &self.fixtures.prepared,
            approved: &self.fixtures.approved,
            route: &self.fixtures.route,
            preview: &self.fixtures.preview,
            now_ms: NOW_MS,
        }
    }
}

#[tokio::test]
async fn kill_switch_blocks_before_signer_and_chain() {
    // Disabled policy: the live composition must stop at the kill switch.
    let disabled = PolicyEngine::new(TradingGate::default(), fixture_limits()).expect("engine");
    let store = Arc::new(DeterministicDurableStore::new());
    let h = harness_with_policy(disabled, store, None);
    h.adapter.refresh_health().await;
    assert_eq!(h.adapter.health(NOW_MS), ChainHealth::Healthy);

    let result = h.relay.execute(h.input()).await;
    assert_eq!(result, Err(RelayError::TradingDisabled));
    assert_eq!(h.signer_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.transport.sends.load(Ordering::SeqCst), 0);
    assert!(h.store.is_empty());
}

#[tokio::test]
async fn live_one_chain_signs_once_submits_once_and_reconciles() {
    let store = Arc::new(DeterministicDurableStore::new());
    let h = harness_with_policy(
        fixture_engine(),
        Arc::clone(&store),
        Some(ReceiptObservation {
            status: ReceiptStatus::Success,
            net_input: Some(1_000),
            net_output: Some(240),
        }),
    );
    h.adapter.refresh_health().await;

    let outcome = h.relay.execute(h.input()).await;
    assert!(matches!(outcome, Ok(RelayOutcome::Submitted { .. })));
    assert_eq!(h.signer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.transport.sends.load(Ordering::SeqCst), 1);

    // Duplicate execute returns the stored outcome without a second sign/submit.
    let duplicate = h.relay.execute(h.input()).await;
    assert!(matches!(duplicate, Ok(RelayOutcome::Submitted { .. })));
    assert_eq!(h.signer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.transport.sends.load(Ordering::SeqCst), 1);

    // Reconciliation is read-only and observes the exact fill.
    let reconciled = h
        .relay
        .reconcile(&h.fixtures.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert!(matches!(
        reconciled,
        RelayOutcome::Confirmed { fill: Some(_), .. }
    ));
    assert_eq!(h.transport.sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.transport
            .receipt_refs
            .lock()
            .expect("receipt refs")
            .as_slice(),
        ["0xsubmitted-hash".to_string()],
        "reconciliation must query by the broadcast hash"
    );
}

#[tokio::test]
async fn restart_over_the_same_durable_store_reconciles_without_resubmit() {
    let store = Arc::new(DeterministicDurableStore::new());
    let first = harness_with_policy(
        fixture_engine(),
        Arc::clone(&store),
        Some(ReceiptObservation {
            status: ReceiptStatus::Success,
            net_input: Some(1_000),
            net_output: Some(240),
        }),
    );
    first.adapter.refresh_health().await;
    assert!(matches!(
        first.relay.execute(first.input()).await,
        Ok(RelayOutcome::Submitted { .. })
    ));
    assert_eq!(first.transport.sends.load(Ordering::SeqCst), 1);

    // A brand-new relay over the same store has an empty journal and must
    // reconcile from durable state.
    let second = harness_with_policy(
        fixture_engine(),
        Arc::clone(&store),
        Some(ReceiptObservation {
            status: ReceiptStatus::Success,
            net_input: Some(1_000),
            net_output: Some(240),
        }),
    );
    second.adapter.refresh_health().await;
    let reconciled = second
        .relay
        .reconcile(&second.fixtures.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert!(matches!(
        reconciled,
        RelayOutcome::Confirmed { fill: Some(_), .. }
    ));
    assert_eq!(
        second.transport.sends.load(Ordering::SeqCst),
        0,
        "restart reconciliation must never resubmit"
    );
    assert_eq!(second.signer_calls.load(Ordering::SeqCst), 0);
}

/// Mirrors `fixture_engine` limits for the disabled harness.
fn fixture_limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        allowed_chains: std::collections::HashSet::from([ChainId::Base]),
        allowed_venues: std::collections::HashSet::from(["uniswap".to_string()]),
    }
}
