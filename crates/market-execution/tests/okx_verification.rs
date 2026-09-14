//! P84C tests for the verified OKX provider execution port.
//!
//! Pure and deterministic: a scripted OKX transport, a fixed trust source, and a
//! recording sink. No network, signer, chain, or real funds are involved.

mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
};
use agent_commands::RouterSource;
use async_trait::async_trait;
use market_execution::{
    ApprovedProviderSink, OkxExecutionConfig, ProviderRevalidationGate,
    UnavailableApprovedProviderSink, UnavailableProviderProposalSource,
    UnavailableProviderRevalidationGate, VerifiedProviderExecutionPort,
};
use market_types::{AtomicAmount, Bps};
use okx_client::{
    OkxAuthHeaders, OkxClient, OkxCredentials, OkxHttpResponse, OkxRequest, OkxTransport,
    OkxTransportError,
};
use provider_verification::{ApprovedProviderPayload, ProviderVerificationPolicy};
use support::{request_with, trust, FakeTrust};

/// Scripted OKX transport: one bounded fixture response, no network.
struct FixtureTransport {
    responses: Mutex<VecDeque<Result<OkxHttpResponse, OkxTransportError>>>,
    calls: AtomicUsize,
}

impl FixtureTransport {
    fn single(body: Vec<u8>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from([Ok(OkxHttpResponse::new(200, body))])),
            calls: AtomicUsize::new(0),
        }
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

fn source(body: Vec<u8>) -> OkxClient<FixtureTransport> {
    OkxClient::new(
        FixtureTransport::single(body),
        OkxCredentials::new("key", "secret", "pass").expect("creds"),
    )
}

fn config() -> OkxExecutionConfig {
    OkxExecutionConfig {
        policy: ProviderVerificationPolicy {
            allowed_routers: vec!["0xrouter".to_string()],
            allowed_spenders: vec!["0xspender".to_string()],
            expected_wallet: "wallet-1".to_string(),
            expected_receiver: "wallet-1".to_string(),
            max_value: 0,
            max_approval: 0,
            min_receive: 0,
            max_slippage_bps: Bps::new(500).expect("bps"),
            max_age_ms: 60_000,
        },
        user_wallet: "wallet-1".to_string(),
        slippage_bps: None,
    }
}

/// A request whose route leg output equals the delta gross output, so the
/// verifier's `amount_out` binding is satisfiable by the fixture.
fn okx_request() -> MarketExecutionRequest {
    let mut request = request_with(240, 240, 100);
    request.router_source = RouterSource::Okx;
    request.quote.plan.legs[0].expected_amount_out = AtomicAmount::new(240);
    request
}

fn valid_body() -> Vec<u8> {
    br#"{"code":"0","data":[{
        "chainIndex":"8453",
        "fromTokenAddress":"USDC",
        "toTokenAddress":"TOKEN",
        "fromTokenAmount":"1000",
        "toTokenAmount":"240",
        "minReceiveAmount":"240",
        "receiver":"wallet-1",
        "spender":"0xspender",
        "tx":{"from":"wallet-1","to":"0xrouter","data":"0xdeadbeef","value":"0"}
    }]}"#
        .to_vec()
}

fn body_with_router(router: &str) -> Vec<u8> {
    String::from_utf8(valid_body())
        .expect("utf8")
        .replace("0xrouter", router)
        .into_bytes()
}

fn body_with_min_receive(min_receive: &str) -> Vec<u8> {
    String::from_utf8(valid_body())
        .expect("utf8")
        .replace(
            "\"minReceiveAmount\":\"240\"",
            &format!("\"minReceiveAmount\":\"{min_receive}\""),
        )
        .into_bytes()
}

struct RecordingSink {
    calls: AtomicUsize,
    last: Mutex<Option<(u128, u128, String)>>,
}

impl RecordingSink {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last(&self) -> (u128, u128, String) {
        self.last.lock().expect("lock").clone().expect("call")
    }
}

#[async_trait]
impl ApprovedProviderSink for RecordingSink {
    async fn submit(
        &self,
        payload: ApprovedProviderPayload,
        _request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().expect("lock") = Some((
            payload.amount_in(),
            payload.amount_out(),
            payload.router().to_string(),
        ));
        Ok(MarketExecutionOutcome::Submitted)
    }
}

fn trust_source() -> FakeTrust {
    FakeTrust {
        trust: trust(),
        calls: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn valid_proposal_is_verified_then_reaches_the_sink() {
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        source(valid_body()),
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        PermissiveGate,
        config(),
    );

    let outcome = port.execute(okx_request()).await.expect("submitted");
    assert_eq!(outcome, MarketExecutionOutcome::Submitted);
    assert_eq!(sink.calls(), 1);
    assert_eq!(sink.last(), (1_000, 240, "0xrouter".to_string()));
}

/// Thin newtype so the sink can be observed after the port owns it.
struct RecordingSinkAdapter(Arc<RecordingSink>);

#[async_trait]
impl ApprovedProviderSink for RecordingSinkAdapter {
    async fn submit(
        &self,
        payload: ApprovedProviderPayload,
        request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.0.submit(payload, request).await
    }
}

/// Permissive pre-sign gate for tests whose focus is not the gate itself.
struct PermissiveGate;

#[async_trait]
impl ProviderRevalidationGate for PermissiveGate {
    async fn revalidate(
        &self,
        _request: &MarketExecutionRequest,
        _trust: &market_execution::MarketExecutionTrust,
        _min_out: &market_types::AssetAmount,
    ) -> Result<(), MarketExecutionError> {
        Ok(())
    }
}

#[tokio::test]
async fn non_allowlisted_router_is_denied_and_never_reaches_the_sink() {
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        source(body_with_router("0xevil")),
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        PermissiveGate,
        config(),
    );

    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Denied)
    );
    assert_eq!(sink.calls(), 0);
}

#[tokio::test]
async fn min_receive_below_the_pep_floor_is_denied() {
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        source(body_with_min_receive("1")),
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        PermissiveGate,
        config(),
    );

    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Denied)
    );
    assert_eq!(sink.calls(), 0);
}

#[tokio::test]
async fn local_source_is_denied_before_any_work() {
    let sink = Arc::new(RecordingSink::new());
    let trust_calls = Arc::new(AtomicUsize::new(0));
    let port = VerifiedProviderExecutionPort::new(
        source(valid_body()),
        RecordingSinkAdapter(sink.clone()),
        FakeTrust {
            trust: trust(),
            calls: trust_calls.clone(),
        },
        PermissiveGate,
        config(),
    );

    let mut local = okx_request();
    local.router_source = RouterSource::Local;
    assert_eq!(port.execute(local).await, Err(MarketExecutionError::Denied));
    assert_eq!(sink.calls(), 0);
    assert_eq!(
        trust_calls.load(Ordering::SeqCst),
        0,
        "a source mismatch must be denied before the trust read"
    );
}

#[tokio::test]
async fn unavailable_proposal_source_fails_closed() {
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        UnavailableProviderProposalSource,
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        PermissiveGate,
        config(),
    );

    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Unavailable)
    );
    assert_eq!(sink.calls(), 0);
}

#[tokio::test]
async fn default_sink_keeps_live_submission_unavailable() {
    // Verification succeeds (otherwise the result would be `Denied`), and the
    // fail-closed default sink then refuses to act.
    let port = VerifiedProviderExecutionPort::new(
        source(valid_body()),
        UnavailableApprovedProviderSink,
        trust_source(),
        PermissiveGate,
        config(),
    );
    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Unavailable)
    );
}

/// Gate that always denies, to prove the port cannot bypass revalidation.
struct DenyingGate;

#[async_trait]
impl ProviderRevalidationGate for DenyingGate {
    async fn revalidate(
        &self,
        _request: &MarketExecutionRequest,
        _trust: &market_execution::MarketExecutionTrust,
        _min_out: &market_types::AssetAmount,
    ) -> Result<(), MarketExecutionError> {
        Err(MarketExecutionError::Denied)
    }
}

#[tokio::test]
async fn default_revalidation_gate_keeps_signing_unavailable() {
    // A valid, verifiable proposal still cannot reach the sink until an
    // authoritative pre-sign gate is installed.
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        source(valid_body()),
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        UnavailableProviderRevalidationGate,
        config(),
    );
    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Unavailable)
    );
    assert_eq!(sink.calls(), 0);
}

#[tokio::test]
async fn failing_revalidation_gate_denies_and_never_reaches_the_sink() {
    let sink = Arc::new(RecordingSink::new());
    let port = VerifiedProviderExecutionPort::new(
        source(valid_body()),
        RecordingSinkAdapter(sink.clone()),
        trust_source(),
        DenyingGate,
        config(),
    );
    assert_eq!(
        port.execute(okx_request()).await,
        Err(MarketExecutionError::Denied)
    );
    assert_eq!(sink.calls(), 0);
}
