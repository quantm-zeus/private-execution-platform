//! Integration tests for the OKX quote client boundary (P84A).
//!
//! Every test drives the public API through an injected scripted transport; no
//! network access is performed.

use std::collections::VecDeque;
use std::sync::Mutex;

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps};
use okx_client::{
    okx_chain_index, sign_request, OkxApiConfig, OkxClient, OkxClientError, OkxCredentials,
    OkxHttpMethod, OkxHttpResponse, OkxQuoteRequest, OkxRequest, OkxTransport, OkxTransportError,
    UnavailableOkxTransport,
};
use routing::{compare_route, BenchmarkPolicy, BenchmarkSource, BenchmarkVerdict, LocalRouteQuote};

#[derive(Clone)]
struct CapturedCall {
    method: OkxHttpMethod,
    path: String,
    signed_path: String,
    query: Vec<(String, String)>,
    auth: Vec<(String, String)>,
}

struct ScriptedTransport {
    responses: Mutex<VecDeque<Result<OkxHttpResponse, OkxTransportError>>>,
    calls: Mutex<Vec<CapturedCall>>,
}

impl ScriptedTransport {
    fn new(responses: Vec<Result<OkxHttpResponse, OkxTransportError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn single(response: OkxHttpResponse) -> Self {
        Self::new(vec![Ok(response)])
    }

    fn captured(&self) -> Vec<CapturedCall> {
        self.calls.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl OkxTransport for ScriptedTransport {
    async fn send(
        &self,
        request: OkxRequest,
        auth: &okx_client::OkxAuthHeaders,
    ) -> Result<OkxHttpResponse, OkxTransportError> {
        self.calls.lock().expect("lock").push(CapturedCall {
            method: request.method(),
            path: request.path().to_string(),
            signed_path: request.signed_path(),
            query: request.query().to_vec(),
            auth: auth
                .pairs()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        });
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

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn base_request() -> OkxQuoteRequest {
    OkxQuoteRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        None,
    )
    .expect("request")
}

fn quote_body(from: &str, to: &str, amount_in: &str, amount_out: &str) -> String {
    format!(
        r#"{{"code":"0","msg":"","data":[{{
            "chainIndex":"8453",
            "fromTokenAddress":"{from}",
            "toTokenAddress":"{to}",
            "fromTokenAmount":"{amount_in}",
            "toTokenAmount":"{amount_out}",
            "quoteId":"quote-1"
        }}]}}"#
    )
}

fn valid_response() -> OkxHttpResponse {
    OkxHttpResponse::new(
        200,
        quote_body("0xaaaa", "0xbbbb", "1000", "2500").into_bytes(),
    )
}

#[tokio::test]
async fn quote_normalizes_and_signs_exact_request() {
    let transport = ScriptedTransport::single(valid_response());
    let client = OkxClient::new(transport, credentials());
    let normalized = client.quote(&base_request(), 1_000).await.expect("quote");

    assert_eq!(normalized.chain(), &ChainId::Base);
    assert_eq!(normalized.token_in(), &base_asset("0xaaaa"));
    assert_eq!(normalized.token_out(), &base_asset("0xbbbb"));
    assert_eq!(normalized.amount_in(), 1_000);
    assert_eq!(normalized.amount_out(), 2_500);
    assert_eq!(normalized.reference(), "quote-1");

    let calls = client.transport().captured();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.method, OkxHttpMethod::Get);
    assert_eq!(call.path, "/api/v5/dex/aggregator/quote");
    assert_eq!(
        call.signed_path,
        "/api/v5/dex/aggregator/quote?chainIndex=8453&fromTokenAddress=0xaaaa&toTokenAddress=0xbbbb&amount=1000"
    );
    assert_eq!(
        call.query,
        vec![
            ("chainIndex".to_string(), "8453".to_string()),
            ("fromTokenAddress".to_string(), "0xaaaa".to_string()),
            ("toTokenAddress".to_string(), "0xbbbb".to_string()),
            ("amount".to_string(), "1000".to_string()),
        ]
    );
    // The transport saw exactly the four auth headers, with the bound API key.
    assert_eq!(call.auth.len(), 4);
    assert!(call
        .auth
        .iter()
        .any(|(name, value)| name == "OK-ACCESS-KEY" && value == "api-key-value"));

    // Re-signing the captured signed path with the same instant reproduces the
    // exact signature the client sent.
    let resigned =
        sign_request(&credentials(), "GET", &call.signed_path, &[], 1_000).expect("resign");
    let expected: Vec<(String, String)> = resigned
        .pairs()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    assert_eq!(call.auth, expected);
}

#[tokio::test]
async fn default_config_uses_v5_aggregator_prefix() {
    let transport = ScriptedTransport::single(valid_response());
    let client = OkxClient::new(transport, credentials());
    assert_eq!(client.config().prefix(), "/api/v5/dex/aggregator");
    client.quote(&base_request(), 0).await.expect("quote");
}

#[tokio::test]
async fn custom_prefix_is_used_and_signed() {
    let transport = ScriptedTransport::single(valid_response());
    let config = OkxApiConfig::new("/api/v6/dex/aggregator").expect("config");
    let client = OkxClient::with_config(transport, credentials(), config);
    client.quote(&base_request(), 0).await.expect("quote");
    let calls = client.transport().captured();
    assert!(calls[0]
        .signed_path
        .starts_with("/api/v6/dex/aggregator/quote?"));
}

#[tokio::test]
async fn unavailable_default_transport_fails_closed() {
    let client = OkxClient::new(UnavailableOkxTransport, credentials());
    let result = client.quote(&base_request(), 0).await;
    assert_eq!(result.err(), Some(OkxClientError::TransportUnavailable));
}

#[tokio::test]
async fn transport_failure_maps_to_redacted_failure() {
    let transport = ScriptedTransport::new(vec![Err(OkxTransportError::Timeout)]);
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::TransportFailure)
    );
}

#[tokio::test]
async fn non_200_status_fails_closed() {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(500, b"oops".to_vec()));
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::ProviderError)
    );
}

#[tokio::test]
async fn provider_error_envelope_fails_closed() {
    let body = br#"{"code":"51000","msg":"params error","data":[]}"#.to_vec();
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body));
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::ProviderError)
    );
}

#[tokio::test]
async fn malformed_and_truncated_bodies_fail_closed() {
    for body in [
        b"not json".to_vec(),
        b"{}".to_vec(),
        br#"{"code":"0","data":[{"fromTokenAmount":"1000"}]}"#.to_vec(),
        // Numeric amounts are rejected: the wire contract is a decimal string.
        br#"{"code":"0","data":[{"fromTokenAddress":"0xaaaa","toTokenAddress":"0xbbbb","fromTokenAmount":1000,"toTokenAmount":2500}]}"#.to_vec(),
    ] {
        let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body));
        let client = OkxClient::new(transport, credentials());
        assert_eq!(
            client.quote(&base_request(), 0).await.err(),
            Some(OkxClientError::MalformedResponse)
        );
    }
}

#[tokio::test]
async fn oversized_body_fails_closed_before_parsing() {
    let transport =
        ScriptedTransport::single(OkxHttpResponse::new(200, valid_response().body().to_vec()));
    let config = OkxApiConfig::default()
        .with_max_response_bytes(16)
        .expect("config");
    let client = OkxClient::with_config(transport, credentials(), config);
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::OversizedResponse)
    );
}

#[tokio::test]
async fn mismatched_amount_pair_and_chain_fail_closed() {
    let cases = [
        quote_body("0xaaaa", "0xbbbb", "999", "2500"),
        quote_body("0xaaaa", "0xcccc", "1000", "2500"),
        quote_body("0xcccc", "0xbbbb", "1000", "2500"),
        quote_body("0xaaaa", "0xbbbb", "1000", "0"),
    ];
    for body in cases {
        let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body.into_bytes()));
        let client = OkxClient::new(transport, credentials());
        assert_eq!(
            client.quote(&base_request(), 0).await.err(),
            Some(OkxClientError::QuoteMismatch)
        );
    }
}

#[tokio::test]
async fn nested_token_shape_is_supported() {
    let body = br#"{"code":"0","data":[{
        "chainIndex":"8453",
        "fromToken":{"tokenContractAddress":"0xaaaa"},
        "toToken":{"tokenContractAddress":"0xbbbb"},
        "fromTokenAmount":"1000",
        "toTokenAmount":"2500"
    }]}"#
        .to_vec();
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body));
    let client = OkxClient::new(transport, credentials());
    let normalized = client.quote(&base_request(), 0).await.expect("quote");
    assert_eq!(normalized.amount_out(), 2_500);
    // No quote id present: the opaque reference degrades to the fixed label.
    assert_eq!(normalized.reference(), "okx");
}

#[tokio::test]
async fn multi_row_or_wrong_chain_index_fails_closed() {
    let multi = br#"{"code":"0","data":[
        {"fromTokenAddress":"0xaaaa","toTokenAddress":"0xbbbb","fromTokenAmount":"1000","toTokenAmount":"2500"},
        {"fromTokenAddress":"0xaaaa","toTokenAddress":"0xbbbb","fromTokenAmount":"1000","toTokenAmount":"2600"}
    ]}"#;
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, multi.to_vec()));
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::MalformedResponse)
    );

    let wrong_chain = br#"{"code":"0","data":[
        {"chainIndex":"1","fromTokenAddress":"0xaaaa","toTokenAddress":"0xbbbb","fromTokenAmount":"1000","toTokenAmount":"2500"}
    ]}"#;
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, wrong_chain.to_vec()));
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.quote(&base_request(), 0).await.err(),
        Some(OkxClientError::QuoteMismatch)
    );
}

#[tokio::test]
async fn normalized_quote_drives_p80_benchmark_comparison() {
    let transport = ScriptedTransport::single(valid_response());
    let client = OkxClient::new(transport, credentials());
    let normalized = client.quote(&base_request(), 1_000).await.expect("quote");

    let provider = normalized
        .to_provider_quote(BenchmarkSource::new("okx").expect("source"))
        .expect("provider quote");
    let local = LocalRouteQuote::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        1_000,
        2_500,
        1_000,
    );
    let verdict =
        compare_route(&local, &provider, &BenchmarkPolicy::default(), 1_000).expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Agree {
            deviation_bps: 0,
            direction: routing::BenchmarkDirection::LocalBetter,
        }
    );
}

#[tokio::test]
async fn quote_is_deterministic_for_identical_inputs() {
    let transport = ScriptedTransport::new(vec![Ok(valid_response()), Ok(valid_response())]);
    let client = OkxClient::new(transport, credentials());
    let first = client.quote(&base_request(), 42).await.expect("first");
    let second = client.quote(&base_request(), 42).await.expect("second");
    assert_eq!(first, second);
    let calls = client.transport().captured();
    assert_eq!(calls[0].signed_path, calls[1].signed_path);
    assert_eq!(calls[0].auth, calls[1].auth);
}

#[tokio::test]
async fn slippage_and_chain_mapping_are_bound_into_the_request() {
    let transport = ScriptedTransport::single(valid_response());
    let client = OkxClient::new(transport, credentials());
    let request = OkxQuoteRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        Some(Bps::new(50).expect("bps")),
    )
    .expect("request");
    client.quote(&request, 0).await.expect("quote");
    let calls = client.transport().captured();
    assert_eq!(
        calls[0].query.last(),
        Some(&("slippage".to_string(), "0.5".to_string()))
    );
    assert_eq!(okx_chain_index(&ChainId::Base).expect("index"), 8_453);
}

#[test]
fn credentials_and_errors_never_render_secrets() {
    let creds = credentials();
    let debug = format!("{creds:?}");
    assert!(!debug.contains("api-key-value"));
    assert!(!debug.contains("signing-secret-value"));
    assert!(!debug.contains("passphrase-value"));

    let request = base_request();
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("0xaaaa"));

    // A transport that always captures, exercised synchronously for the debug
    // hygiene assertion on the request/auth types only.
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let transport = ScriptedTransport::single(valid_response());
    let client = OkxClient::new(transport, credentials());
    let normalized = runtime
        .block_on(client.quote(&base_request(), 0))
        .expect("quote");
    for rendered in [format!("{normalized:?}"), format!("{client:?}")] {
        assert!(!rendered.contains("0xaaaa"));
        assert!(!rendered.contains("2500"));
        assert!(!rendered.contains("api-key-value"));
        assert!(!rendered.contains("signing-secret-value"));
    }
    for error in [
        OkxClientError::InvalidCredentials,
        OkxClientError::ProviderError,
        OkxClientError::QuoteMismatch,
    ] {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("api-key-value"));
        assert!(!rendered.contains("0xaaaa"));
    }
}
