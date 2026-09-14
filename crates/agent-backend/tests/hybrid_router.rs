//! P84B hybrid OKX/Local routing integration tests.
//!
//! These exercise the additive router preference end to end through the agent
//! backend: OKX is the default source, an OKX outage fails closed without
//! invoking the Local router, an injected OKX source composes the exact net
//! economics through the locked provider bridge, the derived identity is
//! source-bound, and the normalized OKX quote can be compared against a local
//! basis with the P80 comparator.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_backend::{
    AgentReadBackend, FixedClock, MarketExecutionError, MarketExecutionOutcome,
    MarketExecutionPort, MarketExecutionRequest, MarketPreviewError, MarketSnapshot,
    MarketSnapshotSource, OkxQuoteSource, OrderReadModel, OrderSummary, TradingAgentBackend,
    TradingBackendConfig, UnavailableOrderValuation, UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentChannel, AgentCommand, AmountSpec, AssetRef, ReadCommand, RouterSource, TradeCommand,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{OrderStatus, TradeIntent, TradeSide};
use limit_engine::InMemoryLimitOrderStore;
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessPolicy, FreshnessStatus, PoolId, PoolKindState,
    PoolStateEnvelope, SafeFreshnessMeta, Sequence,
};
use mcp_server::{AgentBackend, BackendOutcome};
use okx_client::{
    OkxAuthHeaders, OkxClient, OkxCredentials, OkxHttpResponse, OkxQuoteRequest, OkxRequest,
    OkxTransport, OkxTransportError,
};
use routing::{
    compare_route, BenchmarkDirection, BenchmarkPolicy, BenchmarkSource, BenchmarkVerdict,
    LocalRouteQuote, PoolDescriptor, PoolRefLabel, RouteQuote, ScoringInputs, VenueLabel,
};
use serde_json::Value;
use tax_engine::TaxAssessment;

const NOW: i64 = 1_000_000;
const AMOUNT: u128 = 1_000_000_000;
/// Deterministic provider gross output for one fixture quote.
const OKX_GROSS_OUT: u128 = 2_000_000_000;
/// 250 bps buy tax on the provider gross output (the assessment below).
const OKX_TAX: u128 = 50_000_000;
/// Composed post-tax net output for the OKX fixture.
const OKX_NET_OUT: u128 = OKX_GROSS_OUT - OKX_TAX;

fn token_in() -> AssetId {
    AssetId::new(ChainId::Base, "0xaaaa").expect("asset")
}

fn token_out() -> AssetId {
    AssetId::new(ChainId::Base, "0xbbbb").expect("asset")
}

fn config() -> TradingBackendConfig {
    TradingBackendConfig {
        owner: domain::UserId::new("u1").expect("owner"),
        wallet_ref: domain::WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        risk: domain::RiskConstraints {
            max_buy_tax: Bps::new(1_000).expect("bps"),
            max_sell_tax: Bps::new(1_000).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        min_fill: AtomicAmount::new(1),
    }
}

#[derive(Default)]
struct FakeOrders;

#[async_trait]
impl OrderReadModel for FakeOrders {
    async fn list_orders(
        &self,
        _status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, agent_backend::BackendError> {
        Ok(Vec::new())
    }
}

fn pool() -> PoolDescriptor {
    PoolDescriptor {
        envelope: PoolStateEnvelope {
            pool_id: PoolId::new(ChainId::Base, "pool-1").expect("pool id"),
            sequence: Sequence(1),
            observed_at_ms: NOW,
            state: PoolKindState::Cpmm(CpmmPoolState {
                token_0: token_in(),
                token_1: token_out(),
                decimals_0: 6,
                decimals_1: 18,
                reserve_0: AtomicAmount::new(5_000_000_000_000),
                reserve_1: AtomicAmount::new(10_000_000_000_000),
                total_lp_supply: None,
                fee_bps: Bps::new(30).expect("fee"),
            }),
        },
        venue: VenueLabel::new("uniswap").expect("venue"),
        leg_pool_ref: PoolRefLabel::new("pool-1").expect("pool ref"),
        impact_override_bps: None,
    }
}

fn assessment(asset: AssetId, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    TaxAssessment::new(
        asset,
        ChainId::Base,
        Bps::new(buy_tax).expect("buy"),
        Bps::new(sell_tax).expect("sell"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: NOW,
            evaluated_at_ms: NOW,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    )
}

fn scoring() -> ScoringInputs {
    ScoringInputs {
        expected_slippage_bps: Bps::new(20).expect("bps"),
        mev_risk_bps: Bps::new(5).expect("bps"),
        failure_probability_bps: Bps::new(1).expect("bps"),
        provider_reliability_bps: Bps::new(9_900).expect("bps"),
        latency_ms: 42,
    }
}

fn policy() -> FreshnessPolicy {
    FreshnessPolicy::new(60_000, 2_000).expect("policy")
}

/// Snapshot source that counts consults and records every intent it is asked to
/// quote, so a test can prove the Local router was (or was not) reached.
struct CountingSnapshot {
    descriptors: Vec<PoolDescriptor>,
    assessment: TaxAssessment,
    calls: AtomicUsize,
    seen: Mutex<Vec<TradeIntent>>,
}

impl CountingSnapshot {
    fn new() -> Self {
        Self {
            descriptors: vec![pool()],
            // Buy USDC -> TOKEN: 250 bps output tax, 100 bps input tax.
            assessment: assessment(token_out(), 250, 100),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<TradeIntent> {
        self.seen.lock().expect("lock").clone()
    }
}

impl MarketSnapshotSource for CountingSnapshot {
    fn snapshot(
        &self,
        intent: &TradeIntent,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> Result<MarketSnapshot, MarketPreviewError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("lock").push(intent.clone());
        Ok(MarketSnapshot {
            descriptors: self.descriptors.clone(),
            assessment: self.assessment.clone(),
            scoring: scoring(),
            freshness_policy: policy(),
            max_hops: 1,
            gas_price_in_output: None,
        })
    }
}

/// Records the exact request handed to the execution port.
struct RecordingExecution {
    result: Result<MarketExecutionOutcome, MarketExecutionError>,
    seen: Mutex<Vec<(TradeIntent, RouteQuote, i64, RouterSource)>>,
}

impl RecordingExecution {
    fn submitted() -> Self {
        Self {
            result: Ok(MarketExecutionOutcome::Submitted),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.seen.lock().expect("lock").len()
    }

    fn last(&self) -> (TradeIntent, RouteQuote, i64, RouterSource) {
        self.seen
            .lock()
            .expect("lock")
            .last()
            .expect("call")
            .clone()
    }
}

#[async_trait]
impl MarketExecutionPort for RecordingExecution {
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.seen.lock().expect("lock").push((
            request.intent,
            request.quote,
            request.now_ms,
            request.router_source,
        ));
        self.result
    }
}

/// Scripted OKX transport: one bounded fixture response, no network.
struct FixtureTransport {
    responses: Mutex<VecDeque<Result<OkxHttpResponse, OkxTransportError>>>,
    calls: AtomicUsize,
}

impl FixtureTransport {
    fn single(response: OkxHttpResponse) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from([Ok(response)])),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl OkxTransport for FixtureTransport {
    async fn send(
        &self,
        _request: OkxRequest,
        _auth: &OkxAuthHeaders,
    ) -> Result<OkxHttpResponse, OkxTransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.responses
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or(Err(OkxTransportError::Failed))
    }
}

fn okx_quote_body() -> Vec<u8> {
    format!(
        r#"{{"code":"0","msg":"","data":[{{
            "chainIndex":"8453",
            "fromTokenAddress":"0xaaaa",
            "toTokenAddress":"0xbbbb",
            "fromTokenAmount":"{AMOUNT}",
            "toTokenAmount":"{OKX_GROSS_OUT}",
            "quoteId":"quote-1",
            "priceImpactPercentage":"0.5"
        }}]}}"#
    )
    .into_bytes()
}

/// A fixture whose reported impact (500 bps) exceeds the configured 300 bps cap.
fn okx_high_impact_body() -> Vec<u8> {
    format!(
        r#"{{"code":"0","msg":"","data":[{{
            "chainIndex":"8453",
            "fromTokenAddress":"0xaaaa",
            "toTokenAddress":"0xbbbb",
            "fromTokenAmount":"{AMOUNT}",
            "toTokenAmount":"{OKX_GROSS_OUT}",
            "quoteId":"quote-1",
            "priceImpactPercentage":"5"
        }}]}}"#
    )
    .into_bytes()
}

/// A fixture with no reported impact at all.
fn okx_unmodeled_impact_body() -> Vec<u8> {
    format!(
        r#"{{"code":"0","msg":"","data":[{{
            "chainIndex":"8453",
            "fromTokenAddress":"0xaaaa",
            "toTokenAddress":"0xbbbb",
            "fromTokenAmount":"{AMOUNT}",
            "toTokenAmount":"{OKX_GROSS_OUT}",
            "quoteId":"quote-1"
        }}]}}"#
    )
    .into_bytes()
}

fn okx_client() -> OkxClient<FixtureTransport> {
    okx_client_with(okx_quote_body())
}

fn okx_client_with(body: Vec<u8>) -> OkxClient<FixtureTransport> {
    let transport = FixtureTransport::single(OkxHttpResponse::new(200, body));
    OkxClient::new(
        transport,
        OkxCredentials::new("api-key-value", "signing-secret-value", "passphrase-value")
            .expect("creds"),
    )
}

fn okx_request() -> OkxQuoteRequest {
    OkxQuoteRequest::new(
        ChainId::Base,
        token_in(),
        token_out(),
        AtomicAmount::new(AMOUNT),
        None,
    )
    .expect("request")
}

type Backend =
    TradingAgentBackend<FakeOrders, UnavailablePortfolioReadModel, InMemoryLimitOrderStore>;

fn backend(snapshot: Arc<CountingSnapshot>, execution: Arc<RecordingExecution>) -> Backend {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    )
    .with_market_snapshot(snapshot)
    .with_market_execution(execution)
}

fn preview_command(router: RouterSource) -> TradeCommand {
    TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "0xaaaa").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "0xbbbb").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: None,
        max_price_impact_bps: None,
        router,
    }
}

fn execute_command(router: RouterSource) -> TradeCommand {
    TradeCommand::ExecuteMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "0xaaaa").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "0xbbbb").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: None,
        max_price_impact_bps: None,
        router,
    }
}

fn get_quote_command(router: RouterSource) -> AgentCommand {
    AgentCommand::Read(ReadCommand::GetQuote {
        token_in: AssetRef::new(ChainId::Base, "0xaaaa").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "0xbbbb").expect("out"),
        amount: AmountSpec::TokenAtomic(AMOUNT),
        router,
    })
}

async fn run(backend: &Backend, command: TradeCommand) -> BackendOutcome {
    backend
        .execute(AgentChannel::Mcp, AgentCommand::Trade(command))
        .await
}

async fn run_read(backend: &Backend, command: AgentCommand) -> BackendOutcome {
    backend.execute(AgentChannel::Mcp, command).await
}

fn amount_at(value: &Value, path: &[&str]) -> u128 {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key).expect("path");
    }
    cursor.as_u64().expect("u64 amount") as u128
}

#[tokio::test]
async fn okx_without_provider_fails_closed_and_never_uses_the_local_router() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend(snapshot.clone(), port.clone());

    // OKX is the default source but no provider is installed: fail closed.
    assert_eq!(
        run(&backend, preview_command(RouterSource::Okx)).await,
        BackendOutcome::Unavailable
    );

    // The identical command on Local succeeds against the same snapshot, so the
    // OKX result above really was a fail-closed and not a silent Local fallback.
    assert!(matches!(
        run(&backend, preview_command(RouterSource::Local)).await,
        BackendOutcome::Value(_)
    ));

    // Both paths consulted the shared snapshot, but the derived source-bound
    // intents differ (see the dedicated identity test for the full assertion).
    let seen = snapshot.seen();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0].idempotency_key, seen[1].idempotency_key);
    // Each path consulted the trusted snapshot exactly once; the OKX arm never
    // re-entered the Local planner (which would have produced a `Value`).
    assert_eq!(snapshot.calls(), 2);

    // execute_market_order fails closed too and never reaches the port.
    assert_eq!(
        run(&backend, execute_command(RouterSource::Okx)).await,
        BackendOutcome::Unavailable
    );
    assert_eq!(port.calls(), 0, "an OKX outage must never reach the port");
}

#[tokio::test]
async fn get_quote_okx_without_provider_fails_closed_and_local_still_serves() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend(snapshot, port.clone());

    assert_eq!(
        run_read(&backend, get_quote_command(RouterSource::Okx)).await,
        BackendOutcome::Unavailable
    );
    assert!(matches!(
        run_read(&backend, get_quote_command(RouterSource::Local)).await,
        BackendOutcome::Value(_)
    ));
    assert_eq!(port.calls(), 0);
}

#[tokio::test]
async fn okx_preview_with_an_injected_source_composes_the_exact_net_economics() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let source: Arc<dyn OkxQuoteSource> = Arc::new(okx_client());
    let backend = backend(snapshot, port).with_okx_quote_source(source);

    let outcome = run(&backend, preview_command(RouterSource::Okx)).await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected an OKX preview, got {outcome:?}");
    };
    let preview = &value["preview"];
    assert_eq!(preview["router_source"], Value::String("okx".to_string()));
    assert_eq!(preview["truncated"], Value::Bool(false));

    // Exact composed economics: gross provider output, the assessment buy tax,
    // and the resulting net output on the same full-wallet-debit net input.
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_input", "amount"]),
        AMOUNT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "gross_output", "amount"]),
        OKX_GROSS_OUT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_output", "amount"]),
        OKX_NET_OUT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "tax_cost", "amount"]),
        OKX_TAX
    );
    // A provider route has no local pool fee and no local gas model.
    assert!(preview["quote"]["net_delta"]["dex_fee"].is_null());
    assert_eq!(
        amount_at(preview, &["score", "simulated_net_output", "amount"]),
        OKX_NET_OUT
    );
    assert!(preview["score"]["gas_cost"].is_null());
    assert!(preview["score"]["provider_fee"].is_null());
    // The provider impact is the parsed 0.5% (50 bps), never a fabricated zero.
    assert_eq!(preview["score"]["price_impact"], Value::from(50));
    assert_eq!(preview["quote"]["route_impact_bps"], Value::from(50));
}

#[tokio::test]
async fn okx_route_enforces_the_price_impact_cap() {
    // `config()` sets a 300 bps hard price-impact cap. Both an above-cap impact
    // and an unmodeled impact must fail closed before the execution port. A fresh
    // scripted client is used per call because each carries one fixture response.
    for body in [okx_high_impact_body(), okx_unmodeled_impact_body()] {
        let port = Arc::new(RecordingExecution::submitted());
        let b = backend(Arc::new(CountingSnapshot::new()), port.clone())
            .with_okx_quote_source(Arc::new(okx_client_with(body.clone())));
        assert_eq!(
            run(&b, preview_command(RouterSource::Okx)).await,
            BackendOutcome::Denied
        );
        assert_eq!(
            port.calls(),
            0,
            "a price-impact denial must never reach the execution port"
        );

        let port = Arc::new(RecordingExecution::submitted());
        let b = backend(Arc::new(CountingSnapshot::new()), port.clone())
            .with_okx_quote_source(Arc::new(okx_client_with(body)));
        assert_eq!(
            run(&b, execute_command(RouterSource::Okx)).await,
            BackendOutcome::Denied
        );
        assert_eq!(
            port.calls(),
            0,
            "a price-impact denial must never reach the execution port"
        );
    }
}

#[tokio::test]
async fn source_bound_identity_differs_between_okx_preview_and_local_execution() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let source: Arc<dyn OkxQuoteSource> = Arc::new(okx_client());
    let backend = backend(snapshot.clone(), port.clone()).with_okx_quote_source(source);

    // A successful OKX preview records its trusted intent on the snapshot source.
    assert!(matches!(
        run(&backend, preview_command(RouterSource::Okx)).await,
        BackendOutcome::Value(_)
    ));
    let seen_after_okx = snapshot.seen();
    assert_eq!(seen_after_okx.len(), 1);
    let okx_intent = &seen_after_okx[0];

    // A Local execution for the same pair/amount records its intent at the port.
    assert!(matches!(
        run(&backend, execute_command(RouterSource::Local)).await,
        BackendOutcome::Value(_)
    ));
    let (local_intent, _quote, _now, local_router) = port.last();
    assert_eq!(local_router, RouterSource::Local);

    assert_ne!(
        okx_intent.idempotency_key, local_intent.idempotency_key,
        "the selected source must be bound into the derived identity"
    );
    assert_ne!(okx_intent.id, local_intent.id);
}

#[tokio::test]
async fn okx_normalized_quote_compares_against_a_local_basis_via_compare_route() {
    let client = okx_client();
    let normalized = client.quote(&okx_request(), NOW).await.expect("normalized");
    let provider = normalized
        .to_provider_quote(BenchmarkSource::new("okx").expect("source"))
        .expect("provider quote");
    assert_eq!(provider.amount_in, AMOUNT);
    assert_eq!(provider.amount_out, OKX_GROSS_OUT);

    let policy = BenchmarkPolicy::new(Bps::new(50).expect("bps"), 60_000, 60_000, 0);

    // The composed OKX net output (post 250 bps buy tax) against the provider
    // gross output is a deterministic 250 bps provider-better disagreement.
    let net_local = LocalRouteQuote::new(
        ChainId::Base,
        token_in(),
        token_out(),
        AMOUNT,
        OKX_NET_OUT,
        NOW,
    );
    assert_eq!(
        compare_route(&net_local, &provider, &policy, NOW).expect("compare"),
        BenchmarkVerdict::Disagree {
            deviation_bps: 250,
            direction: BenchmarkDirection::ProviderBetter,
        }
    );

    // The identical basis agrees exactly (ties count as LocalBetter).
    let gross_local = LocalRouteQuote::new(
        ChainId::Base,
        token_in(),
        token_out(),
        AMOUNT,
        OKX_GROSS_OUT,
        NOW,
    );
    assert_eq!(
        compare_route(&gross_local, &provider, &policy, NOW).expect("compare"),
        BenchmarkVerdict::Agree {
            deviation_bps: 0,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
    // The fixture transport was consumed exactly once; there is no network path.
    assert_eq!(client.transport().calls(), 1);
}

#[tokio::test]
async fn local_preview_reports_local_source_and_stable_shape() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend(snapshot, port);

    let outcome = run(&backend, preview_command(RouterSource::Local)).await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a Local preview, got {outcome:?}");
    };
    let preview = &value["preview"];
    assert_eq!(preview["router_source"], Value::String("local".to_string()));
    assert_eq!(preview["truncated"], Value::Bool(false));
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_input", "amount"]),
        AMOUNT
    );
    // The Local route exposes a pool fee (unlike the provider route).
    assert!(!preview["quote"]["net_delta"]["dex_fee"].is_null());
}

#[tokio::test]
async fn get_quote_okx_with_an_injected_source_serves_provider_economics() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let source: Arc<dyn OkxQuoteSource> = Arc::new(okx_client());
    let backend = backend(snapshot, port.clone()).with_okx_quote_source(source);

    let outcome = run_read(&backend, get_quote_command(RouterSource::Okx)).await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected an OKX get_quote, got {outcome:?}");
    };
    assert_eq!(
        value["quote"]["router_source"],
        Value::String("okx".to_string())
    );
    assert_eq!(
        amount_at(
            &value,
            &["quote", "quote", "net_delta", "net_output", "amount"]
        ),
        OKX_NET_OUT
    );
    // The real provider impact is reported on the get_quote path too.
    assert_eq!(value["quote"]["score"]["price_impact"], Value::from(50));
    assert_eq!(value["quote"]["quote"]["route_impact_bps"], Value::from(50));
    assert_eq!(
        port.calls(),
        0,
        "get_quote must never reach the execution port"
    );
}

#[tokio::test]
async fn mcp_preview_without_a_router_preference_defaults_to_okx() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let source: Arc<dyn OkxQuoteSource> = Arc::new(okx_client());
    let backend = backend(snapshot, port.clone()).with_okx_quote_source(source);

    // A tool call that omits `router_preference` entirely (the MCP default).
    let json = r#"{"tool":"preview_market_order",
        "token_in":{"chain":{"kind":"base"},"address":"0xaaaa"},
        "token_out":{"chain":{"kind":"base"},"address":"0xbbbb"},
        "side":"buy",
        "amount":{"unit":"token_atomic","value":1000000000}}"#;
    let command = AgentCommand::parse(json).expect("parse");

    let outcome = backend.execute(AgentChannel::Mcp, command).await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected an OKX preview, got {outcome:?}");
    };
    assert_eq!(
        value["preview"]["router_source"],
        Value::String("okx".to_string())
    );
    assert_eq!(
        amount_at(
            &value,
            &["preview", "quote", "net_delta", "gross_output", "amount"]
        ),
        OKX_GROSS_OUT
    );
    assert_eq!(port.calls(), 0);
}

#[tokio::test]
async fn local_identity_is_pinned_and_unchanged_by_the_router_field() {
    let snapshot = Arc::new(CountingSnapshot::new());
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend(snapshot.clone(), port);

    assert!(matches!(
        run(&backend, preview_command(RouterSource::Local)).await,
        BackendOutcome::Value(_)
    ));
    let seen = snapshot.seen();
    assert_eq!(seen.len(), 1);
    // Golden pre-P84B Local identity: the router discriminant is appended only
    // for OKX, so a Local intent id is unchanged when the router field is added.
    // (Value captured from the conditional implementation; an unconditional
    // append for Local would change it and fail this test.)
    assert_eq!(
        seen[0].id.as_str(),
        "intent-b64831b8cbb800aab611784bb2db4c69b2dbdc99d8ca42e6877e5c5aec3365c2"
    );
}
