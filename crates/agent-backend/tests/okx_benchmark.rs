//! P92 adapter tests: the read-only OKX quote source driving the P87
//! provider-benchmark service seam.
//!
//! These reuse the scripted OKX transport pattern from `hybrid_router.rs`: a
//! bounded in-memory transport with no network path. They cover the exact binding
//! of a successful quote, the two error classes, the fail-closed default,
//! `Debug` redaction, and composition with the benchmark service.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use agent_backend::{OkxBenchmarkQuoteSource, UnavailableOkxQuoteSource};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use okx_client::{
    OkxAuthHeaders, OkxClient, OkxCredentials, OkxHttpResponse, OkxRequest, OkxTransport,
    OkxTransportError,
};
use provider_benchmark::{
    BenchmarkServicePolicy, ProviderBenchmarkService, ProviderQuoteRequest, ProviderQuoteSource,
    ProviderQuoteSourceError,
};
use routing::BenchmarkSource;

const NOW: i64 = 1_000_000;
const AMOUNT: u128 = 1_000_000_000;
/// Deterministic provider gross output for the fixture quote.
const OKX_GROSS_OUT: u128 = 2_000_000_000;

fn token_in() -> AssetId {
    AssetId::new(ChainId::Base, "0xaaaa").expect("asset")
}

fn token_out() -> AssetId {
    AssetId::new(ChainId::Base, "0xbbbb").expect("asset")
}

fn label(value: &str) -> BenchmarkSource {
    BenchmarkSource::new(value).expect("valid source label")
}

fn request() -> ProviderQuoteRequest {
    ProviderQuoteRequest {
        chain: ChainId::Base,
        token_in: token_in(),
        token_out: token_out(),
        amount_in: AMOUNT,
        observed_at_ms: NOW,
    }
}

/// Scripted OKX transport: bounded fixture responses, no network.
struct FixtureTransport {
    responses: Mutex<VecDeque<Result<OkxHttpResponse, OkxTransportError>>>,
}

impl FixtureTransport {
    fn scripted(responses: Vec<Result<OkxHttpResponse, OkxTransportError>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
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
        self.responses
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or(Err(OkxTransportError::Failed))
    }
}

fn credentials() -> OkxCredentials {
    OkxCredentials::new("api-key-value", "signing-secret-value", "passphrase-value").expect("creds")
}

fn client_with(body: Vec<u8>) -> OkxClient<FixtureTransport> {
    let transport = FixtureTransport::scripted(vec![Ok(OkxHttpResponse::new(200, body))]);
    OkxClient::new(transport, credentials())
}

fn unavailable_client() -> OkxClient<FixtureTransport> {
    let transport = FixtureTransport::scripted(vec![Err(OkxTransportError::Unavailable)]);
    OkxClient::new(transport, credentials())
}

/// A success envelope matching the requested Base basis.
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

/// A provider-rejected envelope (`code != "0"`).
fn okx_rejection_body() -> Vec<u8> {
    br#"{"code":"51000","msg":"request rejected","data":[]}"#.to_vec()
}

#[tokio::test]
async fn successful_fetch_binds_request_basis_and_source_label() {
    let adapter = OkxBenchmarkQuoteSource::new(client_with(okx_quote_body()), label("bench-okx"));

    let quote = adapter.fetch_quote(&request()).await.expect("quote");

    assert_eq!(quote.source, label("bench-okx"));
    assert_eq!(quote.chain, ChainId::Base);
    assert_eq!(quote.token_in, token_in());
    assert_eq!(quote.token_out, token_out());
    assert_eq!(quote.amount_in, AMOUNT);
    // The output, observation instant, and opaque reference come from the
    // underlying normalized quote.
    assert_eq!(quote.amount_out, OKX_GROSS_OUT);
    assert_eq!(quote.observed_at_ms, NOW);
    assert_eq!(quote.reference(), "quote-1");
}

#[tokio::test]
async fn transport_unavailability_maps_to_unavailable() {
    let adapter = OkxBenchmarkQuoteSource::new(unavailable_client(), label("bench-okx"));

    assert_eq!(
        adapter.fetch_quote(&request()).await,
        Err(ProviderQuoteSourceError::Unavailable)
    );
}

#[tokio::test]
async fn structural_rejection_maps_to_rejected() {
    let adapter =
        OkxBenchmarkQuoteSource::new(client_with(okx_rejection_body()), label("bench-okx"));

    assert_eq!(
        adapter.fetch_quote(&request()).await,
        Err(ProviderQuoteSourceError::Rejected)
    );
}

#[tokio::test]
async fn fail_closed_default_never_fabricates_a_quote() {
    let adapter = OkxBenchmarkQuoteSource::new(UnavailableOkxQuoteSource, label("bench-okx"));

    for _ in 0..3 {
        assert_eq!(
            adapter.fetch_quote(&request()).await,
            Err(ProviderQuoteSourceError::Unavailable)
        );
    }
}

#[test]
fn debug_renders_no_payload() {
    let adapter = OkxBenchmarkQuoteSource::new(client_with(okx_quote_body()), label("bench-src-x"));

    let debug = format!("{adapter:?}");
    assert!(debug.starts_with("OkxBenchmarkQuoteSource"));
    assert!(!debug.contains("bench-src-x"), "label must not render");
    assert!(!debug.contains("0xaaaa"), "token_in must not render");
    assert!(!debug.contains("0xbbbb"), "token_out must not render");
    assert!(!debug.contains("1000000000"), "amount_in must not render");
    assert!(!debug.contains("2000000000"), "amount_out must not render");
    assert!(!debug.contains("8453"), "chain must not render");
}

#[tokio::test]
async fn adapter_composes_with_the_benchmark_service() {
    // Construction alone proves the adapter satisfies the service's
    // `ProviderQuoteSource` seam without modifying either crate; TRADING_ENABLED
    // stays false, so this is analytics-only.
    let adapter = OkxBenchmarkQuoteSource::new(client_with(okx_quote_body()), label("okx"));
    let source: Arc<dyn ProviderQuoteSource> = Arc::new(adapter);
    let policy = BenchmarkServicePolicy::okx().expect("policy");
    let service = ProviderBenchmarkService::new(source, policy, 0).expect("service");
    let _ = service;

    const {
        assert!(!provider_benchmark::TRADING_ENABLED);
    }
}
