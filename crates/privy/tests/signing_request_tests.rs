//! P40 signing-request boundary tests.
//!
//! The pinned digest hexes below were derived from an independent Python
//! `hashlib` reference implementing the byte layout documented in
//! `privy::signing` (tag bytes, u32/u64/u128/i64 big-endian fields,
//! length-prefixed UTF-8, and the chain-tag / asset encoding).

use std::collections::HashSet;

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, LimitPrice,
    OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId,
    ValidatedExecutionPreview, WalletRef,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, PriceRatio, Sequence};
use policy::{
    ApprovedExecution, PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot,
    UsdMicros,
};
use privy::{
    PayloadDigest, PreparedExecutionRef, PrivyError, PrivySigningBoundary, SigningRequest,
};

const NOW_MS: i64 = 1_000;

// --- Pinned canonical request digests (from the Python hashlib reference) ---
// The digest commits to the COMPLETE intent via `intent_digest`, so any change to
// an intent field (amount, order type, risk caps, fill policy) moves the digest
// even when the intent id is unchanged.
const HAPPY: &str = "88421554b32629b213046a76c626a486610ff5d1d5ef70aef76ea1f57ac78c55";
const S_NONCE: &str = "f4541f6b6e23bf6c522a26b273195bdfb5fb6682bd75d94517b6b46ca49e677f";
const S_PAYLOAD: &str = "d5f6697f55384f3ce8eefb64aea907c4a8496e1b955506b05422cc45d29c7e7f";
const S_POOL: &str = "8df62058474f833de41ff9c64d67d3093cac494f47c78ada6a80f9f6f55ac49b";
const S_ROUTE_OUT: &str = "549c804bd56bbdc5f8c2c5635564381e906f306eb4b935093cb16058b0bc957c";
const S_NO_EXPIRES: &str = "609d9f30c4fd3484e9db91bf4f5076fb0b11b2665defa794cad7af819cc2b13d";
const S_TOKEN: &str = "a6a67bccfb1dd195cec3d1c3db183d6e55d14ae43476e3ced76c23c421073430";
const S_AMOUNT: &str = "195cae58d1c62bbe1b2033bf331e05ca33280cbcb685dd485fb5b02f53b7a6a1";

// Same-id mutated-intent vectors: the intent id is unchanged, so these can only
// differ because `intent_digest` commits the full intent.
const M_AMOUNT: &str = "34c9975ae0c8919efd0cb7378c811ca2e824dab4525f3464bac9e083d0db6b7b";
const M_LIMIT: &str = "e115ce7e6c35b876d607b0038d9f875889a5ac32b7d8c73537d6d1a5234b6478";
const M_RISK: &str = "f00741bdb3310eeea239c6129031561ed365598c7d74017558df04e6b6aefcf5";
const M_AON: &str = "5968a54938de5b70589aa34cf41ceff9a9066d296a58ee134f9592de17afeda5";
const M_MTC: &str = "2798ebe72663ea378316261d9b3f86bc6c53894f9be71d925781962467b8d476";

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Fixture-derived substrings that must never leak through `Display`/`Debug`.
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    // amounts
    "1000",
    "250",
    "240",
    // asset addresses
    "USDC",
    "USDCX",
    "TOKEN",
    // wallet / intent / idempotency / prepared strings
    "wallet-1",
    "intent-1",
    "idem-1",
    "prepared-1",
    // endpoint-like substrings
    "http",
    "://",
    "grpc",
    "tcp",
    "unix",
    "0x",
];

/// Detects a run of at least `min_len` ASCII hex digits, i.e. leaked digest bytes.
fn has_hex_run(value: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn assert_redacted(label: &str, value: &str) {
    for forbidden in FORBIDDEN_SUBSTRINGS {
        assert!(
            !value.contains(forbidden),
            "redaction leak in `{label}`: `{value}` contains `{forbidden}`"
        );
    }
    assert!(
        !has_hex_run(value, 8),
        "redaction leak in `{label}`: `{value}` contains a hex run of length >= 8"
    );
}

fn limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).unwrap(),
        max_sell_tax: Bps::new(500).unwrap(),
        max_price_impact: Bps::new(300).unwrap(),
        max_slippage: Bps::new(200).unwrap(),
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::from(["uniswap".to_string()]),
    }
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).unwrap(),
        limits(),
    )
    .unwrap()
}

fn context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .unwrap()
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-1").unwrap(),
        wallet_ref: WalletRef::new("wallet-1").unwrap(),
        chain: ChainId::Base,
        token_in: AssetId::new(ChainId::Base, "USDC").unwrap(),
        token_out: AssetId::new(ChainId::Base, "TOKEN").unwrap(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(100).unwrap(),
            max_sell_tax: Bps::new(100).unwrap(),
            max_price_impact: Bps::new(100).unwrap(),
            max_slippage: Bps::new(100).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: Some(10_000),
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
    }
}

fn route() -> RoutePlan {
    let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
    let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
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

fn approved(engine: &PolicyEngine, intent: &TradeIntent) -> ApprovedExecution {
    engine.authorize_trade(intent, &context()).unwrap()
}

fn prepared(intent: &TradeIntent) -> PreparedExecutionRef {
    PreparedExecutionRef::new(
        "prepared-1",
        intent.id.clone(),
        intent.idempotency_key.clone(),
    )
    .unwrap()
}

fn payload() -> PayloadDigest {
    PayloadDigest::from_bytes(std::array::from_fn(|i| i as u8))
}

fn build_preview(
    intent: &TradeIntent,
    route: &RoutePlan,
    net_in: u128,
    gross: u128,
    net: u128,
) -> ValidatedExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: intent.chain.clone(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: intent.side,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(net_in),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(net),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(gross),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: market_types::FreshnessStatus::Fresh,
    }
    .validate(intent, route, NOW_MS)
    .unwrap()
}

fn bind_with(
    intent: &TradeIntent,
    route: &RoutePlan,
    preview: &ValidatedExecutionPreview,
    approved: &ApprovedExecution,
    prepared: &PreparedExecutionRef,
    payload: PayloadDigest,
    now_ms: i64,
) -> Result<SigningRequest, PrivyError> {
    let engine = engine();
    SigningRequest::bind(
        &engine, approved, prepared, intent, route, preview, payload, now_ms,
    )
}

fn bind_request(
    intent: &TradeIntent,
    route: &RoutePlan,
    payload: PayloadDigest,
    now_ms: i64,
) -> Result<SigningRequest, PrivyError> {
    let engine = engine();
    let approved = approved(&engine, intent);
    let prepared = prepared(intent);
    let preview = build_preview(intent, route, 1_000, 250, 240);
    SigningRequest::bind(
        &engine, &approved, &prepared, intent, route, &preview, payload, now_ms,
    )
}

fn digest_of(intent: &TradeIntent, route: &RoutePlan) -> String {
    let request = bind_request(intent, route, payload(), NOW_MS).unwrap();
    hex(request.request_digest().as_bytes())
}

#[test]
fn happy_path_binds_and_pins_request_digest() {
    let intent = intent();
    let route = route();
    let request = bind_request(&intent, &route, payload(), NOW_MS).unwrap();

    assert_eq!(hex(request.request_digest().as_bytes()), HAPPY);
    assert_eq!(digest_of(&intent, &route), HAPPY);
    assert_eq!(request.intent_id(), &intent.id);
    assert_eq!(request.idempotency_key(), &intent.idempotency_key);
    assert_eq!(request.wallet_ref(), &intent.wallet_ref);
    assert_eq!(request.chain(), &ChainId::Base);
    assert_eq!(request.nonce(), 7);
    assert_eq!(request.payload_digest(), &payload());
}

#[test]
fn sensitivity_vectors_change_request_digest_with_pinned_hexes() {
    let base_route = route();
    assert_eq!(digest_of(&intent(), &base_route), HAPPY);

    // nonce
    let mut nonce_intent = intent();
    nonce_intent.nonce = 8;
    assert_eq!(digest_of(&nonce_intent, &base_route), S_NONCE);

    // a single payload byte
    let mut payload_bytes = [0u8; 32];
    for (i, byte) in payload_bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    payload_bytes[31] = 0x20;
    let preview = build_preview(&intent(), &base_route, 1_000, 250, 240);
    let engine = engine();
    let base_intent = intent();
    let request = bind_with(
        &base_intent,
        &base_route,
        &preview,
        &approved(&engine, &base_intent),
        &prepared(&base_intent),
        PayloadDigest::from_bytes(payload_bytes),
        NOW_MS,
    )
    .unwrap();
    assert_eq!(hex(request.request_digest().as_bytes()), S_PAYLOAD);

    // route pool reference
    let mut pool_route = base_route.clone();
    pool_route.legs[0].pool_ref = "0xpool2".to_string();
    assert_eq!(digest_of(&intent(), &pool_route), S_POOL);

    // route expected leg output
    let mut out_route = base_route.clone();
    out_route.legs[0].expected_amount_out = AtomicAmount::new(251);
    assert_eq!(digest_of(&intent(), &out_route), S_ROUTE_OUT);

    // approval expiry presence
    let mut no_expiry = intent();
    no_expiry.expiry_ms = None;
    assert_eq!(digest_of(&no_expiry, &base_route), S_NO_EXPIRES);

    // a token address
    let mut token_intent = intent();
    token_intent.token_in = AssetId::new(ChainId::Base, "USDCX").unwrap();
    let mut token_route = base_route.clone();
    token_route.legs[0].token_in = token_intent.token_in.clone();
    assert_eq!(digest_of(&token_intent, &token_route), S_TOKEN);

    // an amount (gross output)
    let amount_intent = intent();
    let amount_preview = build_preview(&amount_intent, &base_route, 1_000, 251, 240);
    let request = bind_with(
        &amount_intent,
        &base_route,
        &amount_preview,
        &approved(&engine, &amount_intent),
        &prepared(&amount_intent),
        payload(),
        NOW_MS,
    )
    .unwrap();
    assert_eq!(hex(request.request_digest().as_bytes()), S_AMOUNT);
}

#[test]
fn same_id_mutated_intent_changes_request_digest() {
    let base_route = route();
    let base = intent();
    assert_eq!(digest_of(&base, &base_route), HAPPY);

    // Changed amount, same id: previously unbound by the request digest.
    let mut amount_mut = base.clone();
    amount_mut.amount = AtomicAmount::new(2_000);
    assert_eq!(digest_of(&amount_mut, &base_route), M_AMOUNT);

    // Changed order_type (Market -> Limit) with a consistent limit price.
    let mut limit_mut = base.clone();
    limit_mut.order_type = OrderType::Limit;
    limit_mut.limit_price = Some(LimitPrice {
        numerator_asset: base.token_in.clone(),
        denominator_asset: base.token_out.clone(),
        ratio: PriceRatio::new(5_000, 1_000).unwrap(),
    });
    assert_eq!(digest_of(&limit_mut, &base_route), M_LIMIT);

    // Changed risk cap.
    let mut risk_mut = base.clone();
    risk_mut.risk.max_slippage = Bps::new(101).unwrap();
    assert_eq!(digest_of(&risk_mut, &base_route), M_RISK);

    // Flipped allow_partial_fill (the amount still matches the net input).
    let mut aon_mut = base.clone();
    aon_mut.allow_partial_fill = false;
    assert_eq!(digest_of(&aon_mut, &base_route), M_AON);

    // Added max_total_cost.
    let mut cost_mut = base.clone();
    cost_mut.risk.max_total_cost = Some(AssetAmount {
        asset: base.token_in.clone(),
        amount: AtomicAmount::new(1_000),
    });
    assert_eq!(digest_of(&cost_mut, &base_route), M_MTC);

    // Every mutation shares the id but yields a distinct digest.
    for digest in [M_AMOUNT, M_LIMIT, M_RISK, M_AON, M_MTC] {
        assert_ne!(digest, HAPPY);
    }
}

#[test]
fn disabled_gate_is_rejected_before_domain_revalidation() {
    let engine = engine();
    let intent = intent();
    let route = route();
    let approved = approved(&engine, &intent);
    let prepared = prepared(&intent);
    let preview = build_preview(&intent, &route, 1_000, 250, 240);

    // A stale route would fail domain revalidation, but the live kill switch is
    // checked first and wins.
    let mut stale_route = route.clone();
    stale_route.state.observed_at_ms = 0;
    engine.disable_trading();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent,
            &stale_route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::TradingDisabled)
    );
}

#[test]
fn expired_approval_is_rejected_before_domain_revalidation() {
    let engine = engine();
    let original = intent();
    let route = route();
    let approved = approved(&engine, &original);
    let prepared = prepared(&original);
    let preview = build_preview(&original, &route, 1_000, 250, 240);

    // now_ms == approval.expires_at_ms == intent.expiry_ms. The domain validator
    // would report `Expired` for the intent (and the route below is stale), but
    // the approval-expiry check runs first.
    let mut stale_route = route.clone();
    stale_route.state.observed_at_ms = 0;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &original,
            &stale_route,
            &preview,
            payload(),
            10_000,
        ),
        Err(PrivyError::ApprovalExpired)
    );
}

#[test]
fn approval_binding_mismatches_are_rejected() {
    let engine = engine();
    let base = intent();
    let route = route();
    let approved = approved(&engine, &base);
    let prepared = prepared(&base);
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    let mut wrong_id = base.clone();
    wrong_id.id = IntentId::new("other-intent").unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &wrong_id,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );

    let mut wrong_wallet = base.clone();
    wrong_wallet.wallet_ref = WalletRef::new("other-wallet").unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &wrong_wallet,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );

    let wrong_prepared = PreparedExecutionRef::new(
        "prepared-other",
        IntentId::new("other-intent").unwrap(),
        base.idempotency_key.clone(),
    )
    .unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &wrong_prepared,
            &base,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );
}

#[test]
fn preview_revalidation_failures_are_rejected() {
    let engine = engine();
    let base = intent();
    let route = route();
    let approved = approved(&engine, &base);
    let prepared = prepared(&base);
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    // Preview side disagrees with the intent.
    let mut opposite_side = base.clone();
    opposite_side.side = TradeSide::Sell;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &opposite_side,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // Route economics no longer match the validated preview net output.
    let mut net_mismatch = route.clone();
    net_mismatch.expected_net_output.amount = AtomicAmount::new(241);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &base,
            &net_mismatch,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // Stale route state.
    let mut stale_route = route.clone();
    stale_route.state.observed_at_ms = 0;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &base,
            &stale_route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );
}

#[test]
fn limit_violation_and_all_or_nothing_mismatch_are_revalidation_failures() {
    let engine = engine();
    let base = intent();
    let route = route();
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    // A limit the exact net economics violate (1000/240 > 4.0).
    let mut limited = base.clone();
    limited.order_type = OrderType::Limit;
    limited.limit_price = Some(LimitPrice {
        numerator_asset: base.token_in.clone(),
        denominator_asset: base.token_out.clone(),
        ratio: PriceRatio::new(400, 100).unwrap(),
    });
    let limited_approved = approved(&engine, &limited);
    let limited_prepared = prepared(&limited);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &limited_approved,
            &limited_prepared,
            &limited,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // All-or-nothing intent whose amount does not match the simulated net input.
    let mut all_or_nothing = base.clone();
    all_or_nothing.allow_partial_fill = false;
    all_or_nothing.amount = AtomicAmount::new(2_000);
    let aon_approved = approved(&engine, &all_or_nothing);
    let aon_prepared = prepared(&all_or_nothing);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &aon_approved,
            &aon_prepared,
            &all_or_nothing,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );
}

#[test]
fn zero_payload_digest_is_rejected() {
    assert_eq!(
        bind_request(
            &intent(),
            &route(),
            PayloadDigest::from_bytes([0u8; 32]),
            NOW_MS
        ),
        Err(PrivyError::MissingPayloadDigest)
    );
}

#[tokio::test]
async fn default_boundary_fails_closed() {
    let boundary = PrivySigningBoundary::default();
    let request = bind_request(&intent(), &route(), payload(), NOW_MS).unwrap();
    assert_eq!(
        boundary.submit_signing_request(&request).await,
        Err(PrivyError::SigningUnavailable)
    );
}

#[test]
fn errors_and_digests_reveal_no_fixture_secrets() {
    let errors = [
        PrivyError::SigningUnavailable,
        PrivyError::InvalidExecutionReference,
        PrivyError::ApprovalBindingMismatch,
        PrivyError::UnsupportedChain,
        PrivyError::ApprovalExpired,
        PrivyError::TradingDisabled,
        PrivyError::PreviewRevalidationFailed,
        PrivyError::MissingPayloadDigest,
        PrivyError::DuplicateSigningRequest,
        PrivyError::IdempotencyConflict,
        PrivyError::SignerRejected,
    ];
    for error in errors {
        assert_redacted("PrivyError Display", &error.to_string());
        assert_redacted("PrivyError Debug", &format!("{error:?}"));
    }

    let payload = payload();
    assert_redacted("PayloadDigest Debug", &format!("{payload:?}"));

    let request = bind_request(&intent(), &route(), payload, NOW_MS).unwrap();
    assert_redacted(
        "RequestDigest Debug",
        &format!("{:?}", request.request_digest()),
    );
    assert_redacted("SigningRequest Debug", &format!("{request:?}"));
}
