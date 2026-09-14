//! Integration tests for the OKX typed swap-proposal boundary (P84C part 1).
//!
//! Every test drives the public API through an injected scripted transport; no
//! network access is performed. The proposal is untrusted data: these tests pin
//! the strict parse, request binding, fail-closed matrix, redaction, and
//! determinism.

use std::collections::VecDeque;
use std::sync::Mutex;

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps};
use okx_client::{
    sign_request, OkxApiConfig, OkxClient, OkxClientError, OkxCredentials, OkxHttpMethod,
    OkxHttpResponse, OkxRequest, OkxSwapProposal, OkxSwapRequest, OkxTransport, OkxTransportError,
    MAX_CALLDATA_BYTES,
};

const WALLET: &str = "0x1111111111111111111111111111111111111111";
const ROUTER: &str = "0x2222222222222222222222222222222222222222";
const SPENDER: &str = "0x3333333333333333333333333333333333333333";
const RECEIVER: &str = "0x4444444444444444444444444444444444444444";

/// SHA-256 of the decoded bytes of `0xdeadbeef`.
const DEADBEEF_DIGEST_HEX: &str =
    "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953";

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

fn swap_request() -> OkxSwapRequest {
    OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        None,
        WALLET,
    )
    .expect("request")
}

/// A structurally valid `/swap` response envelope.
fn valid_value() -> serde_json::Value {
    serde_json::json!({
        "code": "0",
        "msg": "",
        "data": [{
            "chainIndex": "8453",
            "fromTokenAddress": "0xaaaa",
            "toTokenAddress": "0xbbbb",
            "fromTokenAmount": "1000",
            "toTokenAmount": "2500",
            "minReceiveAmount": "2400",
            "spender": SPENDER,
            "tx": {
                "from": WALLET,
                "to": ROUTER,
                "data": "0xdeadbeef",
                "value": "0",
                "gas": "21000",
                "gasPrice": "1000000000",
                "minReceiveAmount": "2400"
            }
        }]
    })
}

fn body_with(mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value = valid_value();
    mutate(&mut value);
    value.to_string().into_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

async fn run_swap(body: Vec<u8>) -> Result<OkxSwapProposal, OkxClientError> {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body));
    let client = OkxClient::new(transport, credentials());
    client.swap(&swap_request(), 777).await
}

#[tokio::test]
async fn valid_fixture_parses_exact_fields_and_digest() {
    let proposal = run_swap(body_with(|_| {})).await.expect("proposal");

    assert_eq!(proposal.chain(), &ChainId::Base);
    assert_eq!(proposal.wallet(), WALLET);
    // No receiver is reported: it falls back to the wallet.
    assert_eq!(proposal.receiver(), WALLET);
    assert_eq!(proposal.router(), ROUTER);
    assert_eq!(proposal.spender(), Some(SPENDER));
    assert_eq!(proposal.token_in(), &base_asset("0xaaaa"));
    assert_eq!(proposal.token_out(), &base_asset("0xbbbb"));
    assert_eq!(proposal.amount_in(), 1_000);
    assert_eq!(proposal.amount_out(), 2_500);
    assert_eq!(proposal.min_receive_amount(), Some(2_400));
    assert_eq!(proposal.value(), 0);
    assert_eq!(proposal.calldata(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(to_hex(&proposal.calldata_digest()), DEADBEEF_DIGEST_HEX);
    assert_eq!(proposal.observed_at_ms(), 777);
}

#[tokio::test]
async fn explicit_and_nested_receivers_are_used() {
    // Top-level `receiver`.
    let top_level = run_swap(body_with(|value| {
        value["data"][0]["receiver"] = serde_json::json!(RECEIVER);
    }))
    .await
    .expect("proposal");
    assert_eq!(top_level.receiver(), RECEIVER);

    // Nested `toToken.receiver`, with the top-level address spelling agreeing.
    let nested = run_swap(body_with(|value| {
        value["data"][0]["toToken"] = serde_json::json!({
            "tokenContractAddress": "0xbbbb",
            "receiver": RECEIVER,
        });
    }))
    .await
    .expect("proposal");
    assert_eq!(nested.receiver(), RECEIVER);
}

#[tokio::test]
async fn optional_fields_may_be_absent() {
    let proposal = run_swap(body_with(|value| {
        value["data"][0]
            .as_object_mut()
            .expect("row")
            .remove("minReceiveAmount");
        value["data"][0]["tx"]
            .as_object_mut()
            .expect("tx")
            .remove("minReceiveAmount");
        value["data"][0]
            .as_object_mut()
            .expect("row")
            .remove("spender");
    }))
    .await
    .expect("proposal");
    assert_eq!(proposal.min_receive_amount(), None);
    assert_eq!(proposal.spender(), None);
    assert_eq!(proposal.receiver(), WALLET);
}

#[tokio::test]
async fn unknown_router_result_fields_are_tolerated() {
    let proposal = run_swap(body_with(|value| {
        value["data"][0]["routerResult"] = serde_json::json!({"fromTokenAmount": "1000"});
        value["data"][0]["dexRouterList"] = serde_json::json!([{"router": ROUTER}]);
        value["data"][0]["approval"] = serde_json::json!({"spender": SPENDER});
    }))
    .await
    .expect("proposal");
    assert_eq!(proposal.spender(), Some(SPENDER));
}

#[tokio::test]
async fn swap_request_and_query_are_exact() {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body_with(|_| {})));
    let client = OkxClient::new(transport, credentials());
    client.swap(&swap_request(), 1_000).await.expect("swap");

    let calls = client.transport().captured();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.method, OkxHttpMethod::Get);
    assert_eq!(call.path, "/api/v5/dex/aggregator/swap");
    assert_eq!(
        call.signed_path,
        "/api/v5/dex/aggregator/swap?chainIndex=8453&fromTokenAddress=0xaaaa&toTokenAddress=0xbbbb&amount=1000&userWalletAddress=0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        call.query,
        vec![
            ("chainIndex".to_string(), "8453".to_string()),
            ("fromTokenAddress".to_string(), "0xaaaa".to_string()),
            ("toTokenAddress".to_string(), "0xbbbb".to_string()),
            ("amount".to_string(), "1000".to_string()),
            ("userWalletAddress".to_string(), WALLET.to_string()),
        ]
    );

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
async fn swap_request_query_includes_optional_slippage() {
    let request = OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        Some(Bps::new(50).expect("bps")),
        WALLET,
    )
    .expect("request");
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body_with(|_| {})));
    let client = OkxClient::new(transport, credentials());
    client.swap(&request, 0).await.expect("swap");
    let calls = client.transport().captured();
    assert_eq!(
        calls[0].signed_path,
        "/api/v5/dex/aggregator/swap?chainIndex=8453&fromTokenAddress=0xaaaa&toTokenAddress=0xbbbb&amount=1000&slippage=0.5&userWalletAddress=0x1111111111111111111111111111111111111111"
    );
}

#[tokio::test]
async fn fail_closed_matrix() {
    let cases: Vec<(Vec<u8>, OkxClientError)> = vec![
        // Provider code is not "0".
        (
            br#"{"code":"51000","msg":"params error","data":[]}"#.to_vec(),
            OkxClientError::ProviderError,
        ),
        // Not JSON at all.
        (b"not json".to_vec(), OkxClientError::MalformedResponse),
        // Numeric fromTokenAmount (the wire contract is a decimal string).
        (
            body_with(|value| value["data"][0]["fromTokenAmount"] = serde_json::json!(1000)),
            OkxClientError::MalformedResponse,
        ),
        // Numeric toTokenAmount.
        (
            body_with(|value| value["data"][0]["toTokenAmount"] = serde_json::json!(2500)),
            OkxClientError::MalformedResponse,
        ),
        // Numeric native value.
        (
            body_with(|value| value["data"][0]["tx"]["value"] = serde_json::json!(0)),
            OkxClientError::MalformedResponse,
        ),
        // Missing tx object.
        (
            body_with(|value| {
                value["data"][0].as_object_mut().expect("row").remove("tx");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Missing tx.data.
        (
            body_with(|value| {
                value["data"][0]["tx"]
                    .as_object_mut()
                    .expect("tx")
                    .remove("data");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Missing tx.value.
        (
            body_with(|value| {
                value["data"][0]["tx"]
                    .as_object_mut()
                    .expect("tx")
                    .remove("value");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Empty calldata.
        (
            body_with(|value| value["data"][0]["tx"]["data"] = serde_json::json!("0x")),
            OkxClientError::MalformedResponse,
        ),
        // Odd-length hex calldata.
        (
            body_with(|value| value["data"][0]["tx"]["data"] = serde_json::json!("0xabc")),
            OkxClientError::MalformedResponse,
        ),
        // Non-hex calldata.
        (
            body_with(|value| value["data"][0]["tx"]["data"] = serde_json::json!("0xzz")),
            OkxClientError::MalformedResponse,
        ),
        // Missing 0x prefix.
        (
            body_with(|value| value["data"][0]["tx"]["data"] = serde_json::json!("deadbeef")),
            OkxClientError::MalformedResponse,
        ),
        // Oversized calldata.
        (
            body_with(|value| {
                value["data"][0]["tx"]["data"] =
                    serde_json::json!(format!("0x{}", "ab".repeat(MAX_CALLDATA_BYTES + 1)));
            }),
            OkxClientError::MalformedResponse,
        ),
        // Missing wallet (tx.from).
        (
            body_with(|value| {
                value["data"][0]["tx"]
                    .as_object_mut()
                    .expect("tx")
                    .remove("from");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Missing router (tx.to).
        (
            body_with(|value| {
                value["data"][0]["tx"]
                    .as_object_mut()
                    .expect("tx")
                    .remove("to");
            }),
            OkxClientError::MalformedResponse,
        ),
        // amount_out overflow (2^128).
        (
            body_with(|value| {
                value["data"][0]["toTokenAmount"] =
                    serde_json::json!("340282366920938463463374607431768211456");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Duplicate/ambiguous top-level vs nested input address spellings.
        (
            body_with(|value| {
                value["data"][0]["fromToken"] =
                    serde_json::json!({"tokenContractAddress": "0xdddd"});
            }),
            OkxClientError::MalformedResponse,
        ),
        // Ambiguous minReceiveAmount between row and tx.
        (
            body_with(|value| {
                value["data"][0]["minReceiveAmount"] = serde_json::json!("2401");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Wrong chain index.
        (
            body_with(|value| value["data"][0]["chainIndex"] = serde_json::json!("1")),
            OkxClientError::QuoteMismatch,
        ),
        // Wrong output pair.
        (
            body_with(|value| value["data"][0]["toTokenAddress"] = serde_json::json!("0xcccc")),
            OkxClientError::QuoteMismatch,
        ),
        // Wrong input amount.
        (
            body_with(|value| value["data"][0]["fromTokenAmount"] = serde_json::json!("999")),
            OkxClientError::QuoteMismatch,
        ),
        // Zero quoted output.
        (
            body_with(|value| value["data"][0]["toTokenAmount"] = serde_json::json!("0")),
            OkxClientError::QuoteMismatch,
        ),
        // Missing chainIndex.
        (
            body_with(|value| {
                value["data"][0]
                    .as_object_mut()
                    .expect("row")
                    .remove("chainIndex");
            }),
            OkxClientError::MalformedResponse,
        ),
        // Missing data row.
        (
            body_with(|value| value["data"] = serde_json::json!([])),
            OkxClientError::MalformedResponse,
        ),
        // Multiple rows are ambiguous.
        (
            body_with(|value| {
                let row = value["data"][0].clone();
                value["data"] = serde_json::json!([row.clone(), row]);
            }),
            OkxClientError::MalformedResponse,
        ),
    ];

    for (body, expected) in cases {
        assert_eq!(
            run_swap(body).await.err(),
            Some(expected),
            "case should fail closed as {expected:?}"
        );
    }
}

#[tokio::test]
async fn non_200_fails_closed() {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(500, b"oops".to_vec()));
    let client = OkxClient::new(transport, credentials());
    assert_eq!(
        client.swap(&swap_request(), 0).await.err(),
        Some(OkxClientError::ProviderError)
    );
}

#[tokio::test]
async fn oversized_body_fails_closed_before_parsing() {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body_with(|_| {})));
    let config = OkxApiConfig::default()
        .with_max_response_bytes(16)
        .expect("config");
    let client = OkxClient::with_config(transport, credentials(), config);
    assert_eq!(
        client.swap(&swap_request(), 0).await.err(),
        Some(OkxClientError::OversizedResponse)
    );
}

#[tokio::test]
async fn request_construction_fails_closed() {
    assert!(OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        None,
        "",
    )
    .is_err());
    assert!(OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        None,
        "has space",
    )
    .is_err());
    assert!(OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::new(1_000),
        None,
        "a".repeat(okx_client::MAX_ADDRESS_BYTES + 1),
    )
    .is_err());
    // Same-asset and zero-amount requests fail closed.
    assert!(OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xaaaa"),
        AtomicAmount::new(1_000),
        None,
        WALLET,
    )
    .is_err());
    assert!(OkxSwapRequest::new(
        ChainId::Base,
        base_asset("0xaaaa"),
        base_asset("0xbbbb"),
        AtomicAmount::ZERO,
        None,
        WALLET,
    )
    .is_err());
}

#[tokio::test]
async fn proposal_and_errors_are_redacted() {
    let transport = ScriptedTransport::single(OkxHttpResponse::new(200, body_with(|_| {})));
    let client = OkxClient::new(transport, credentials());
    let proposal = client.swap(&swap_request(), 777).await.expect("proposal");

    let rendered = format!("{proposal:?}");
    for sentinel in [
        WALLET,
        ROUTER,
        SPENDER,
        "0xaaaa",
        "0xbbbb",
        "1000",
        "2500",
        "2400",
        "deadbeef",
        DEADBEEF_DIGEST_HEX,
    ] {
        assert!(
            !rendered.contains(sentinel),
            "proposal Debug leaked {sentinel:?}: {rendered}"
        );
    }

    let request_debug = format!("{:?}", swap_request());
    assert!(!request_debug.contains(WALLET));
    assert!(!request_debug.contains("0xaaaa"));

    for error in [
        OkxClientError::InvalidRequest,
        OkxClientError::UnsupportedChain,
        OkxClientError::InvalidCredentials,
        OkxClientError::TransportUnavailable,
        OkxClientError::TransportFailure,
        OkxClientError::OversizedResponse,
        OkxClientError::MalformedResponse,
        OkxClientError::ProviderError,
        OkxClientError::QuoteMismatch,
        OkxClientError::NormalizationFailed,
    ] {
        let shown = format!("{error} {error:?}");
        for sentinel in [WALLET, ROUTER, SPENDER, "0xaaaa", "deadbeef"] {
            assert!(
                !shown.contains(sentinel),
                "error render leaked {sentinel:?}: {shown}"
            );
        }
    }
}

#[tokio::test]
async fn swap_is_deterministic_for_identical_inputs() {
    let transport = ScriptedTransport::new(vec![
        Ok(OkxHttpResponse::new(200, body_with(|_| {}))),
        Ok(OkxHttpResponse::new(200, body_with(|_| {}))),
    ]);
    let client = OkxClient::new(transport, credentials());
    let first = client.swap(&swap_request(), 42).await.expect("first");
    let second = client.swap(&swap_request(), 42).await.expect("second");
    assert_eq!(first, second);

    let calls = client.transport().captured();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].signed_path, calls[1].signed_path);
    assert_eq!(calls[0].auth, calls[1].auth);
}
