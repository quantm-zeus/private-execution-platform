//! Focused tests for the P84C provider-proposal verifier.
//!
//! Every case is pure: no network, clock, RNG, or signing is involved.

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeIntent, TradeSide,
    TradeSource, UserId, WalletRef,
};
use execution_preview::NetDelta;
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use provider_verification::{
    calldata_digest, verify_provider_proposal, ProviderSwapProposal, ProviderVerificationError,
    ProviderVerificationPolicy,
};
use tax_engine::TaxAssessment;

const NOW: i64 = 1_000_000;
const AMOUNT_IN: u128 = 1_000_000;
const GROSS_OUT: u128 = 2_000_000;
const TAX: u128 = 50_000;
const NET_OUT: u128 = GROSS_OUT - TAX;

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn token_in() -> AssetId {
    asset("0xtokenin")
}

fn token_out() -> AssetId {
    asset("0xtokenout")
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("id"),
        source: TradeSource::Internal,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        token_in: token_in(),
        token_out: token_out(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(AMOUNT_IN),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(500).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn route() -> domain::RoutePlan {
    domain::RoutePlan {
        legs: vec![domain::RouteLeg {
            venue: "okx".to_string(),
            pool_ref: "okx".to_string(),
            token_in: token_in(),
            token_out: token_out(),
            amount_in: AtomicAmount::new(AMOUNT_IN),
            expected_amount_out: AtomicAmount::new(GROSS_OUT),
        }],
        expected_net_output: AssetAmount {
            asset: token_out(),
            amount: AtomicAmount::new(NET_OUT),
        },
        state: Freshness {
            observed_at_ms: NOW,
            chain_height: 0,
            sequence: Sequence(1),
        },
    }
}

fn delta() -> NetDelta {
    NetDelta {
        token_in: token_in(),
        token_out: token_out(),
        net_input: AssetAmount {
            asset: token_in(),
            amount: AtomicAmount::new(AMOUNT_IN),
        },
        gross_output: AssetAmount {
            asset: token_out(),
            amount: AtomicAmount::new(GROSS_OUT),
        },
        net_output: AssetAmount {
            asset: token_out(),
            amount: AtomicAmount::new(NET_OUT),
        },
        dex_fee: None,
        tax_cost: Some(AssetAmount {
            asset: token_out(),
            amount: AtomicAmount::new(TAX),
        }),
    }
}

fn assessment() -> TaxAssessment {
    TaxAssessment::new(
        token_out(),
        ChainId::Base,
        Bps::new(250).expect("buy tax"),
        Bps::new(0).expect("sell tax"),
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

fn calldata() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04]
}

fn proposal() -> ProviderSwapProposal {
    let bytes = calldata();
    ProviderSwapProposal {
        chain: ChainId::Base,
        wallet: "wallet-1".to_string(),
        receiver: "wallet-1".to_string(),
        router: "0xrouter".to_string(),
        spender: Some("0xspender".to_string()),
        token_in: token_in(),
        token_out: token_out(),
        amount_in: AMOUNT_IN,
        amount_out: GROSS_OUT,
        min_receive_amount: Some(NET_OUT),
        value: 0,
        approval_amount: None,
        calldata_digest: calldata_digest(&bytes),
        calldata: bytes,
        observed_at_ms: NOW,
    }
}

fn policy() -> ProviderVerificationPolicy {
    ProviderVerificationPolicy {
        allowed_routers: vec!["0xrouter".to_string()],
        allowed_spenders: vec!["0xspender".to_string()],
        expected_wallet: "wallet-1".to_string(),
        expected_receiver: "wallet-1".to_string(),
        max_value: 0,
        max_approval: 0,
        min_receive: NET_OUT,
        max_slippage_bps: Bps::new(500).expect("bps"),
        max_age_ms: 60_000,
    }
}

fn verify(
    proposal: &ProviderSwapProposal,
    policy: &ProviderVerificationPolicy,
) -> Result<provider_verification::ApprovedProviderPayload, ProviderVerificationError> {
    verify_provider_proposal(
        &intent(),
        &route(),
        &delta(),
        &assessment(),
        proposal,
        policy,
        NOW,
    )
}

#[test]
fn valid_proposal_is_approved_and_redacted() {
    let approved = verify(&proposal(), &policy()).expect("approved");
    assert_eq!(approved.chain(), &ChainId::Base);
    assert_eq!(approved.router(), "0xrouter");
    assert_eq!(approved.spender(), Some("0xspender"));
    assert_eq!(approved.amount_in(), AMOUNT_IN);
    assert_eq!(approved.amount_out(), GROSS_OUT);
    assert_eq!(approved.min_receive_amount(), NET_OUT);
    assert_eq!(approved.value(), 0);
    assert_eq!(approved.calldata_digest(), calldata_digest(&calldata()));

    let debug = format!("{approved:?}");
    assert!(!debug.contains("0xrouter"));
    assert!(!debug.contains("2000000"));

    let proposal_debug = format!("{:?}", proposal());
    assert!(!proposal_debug.contains("0xrouter"));
    assert!(!proposal_debug.contains("0xspender"));

    let policy_debug = format!("{:?}", policy());
    assert!(!policy_debug.contains("0xrouter"));
    assert!(!policy_debug.contains("wallet-1"));
}

#[test]
#[allow(clippy::type_complexity)]
fn tamper_matrix_fails_closed_with_the_exact_class() {
    let policy = policy();

    let cases: Vec<(
        &str,
        Box<dyn Fn(&mut ProviderSwapProposal)>,
        ProviderVerificationError,
    )> = vec![
        (
            "chain",
            Box::new(|p| p.chain = ChainId::Solana),
            ProviderVerificationError::ChainMismatch,
        ),
        (
            "token_in",
            Box::new(|p| p.token_in = asset("0xother")),
            ProviderVerificationError::TokenMismatch,
        ),
        (
            "token_out",
            Box::new(|p| p.token_out = asset("0xother")),
            ProviderVerificationError::TokenMismatch,
        ),
        (
            "wallet",
            Box::new(|p| p.wallet = "0xattacker".to_string()),
            ProviderVerificationError::WalletMismatch,
        ),
        (
            "receiver",
            Box::new(|p| p.receiver = "0xattacker".to_string()),
            ProviderVerificationError::ReceiverMismatch,
        ),
        (
            "router",
            Box::new(|p| p.router = "0xevil".to_string()),
            ProviderVerificationError::RouterNotAllowed,
        ),
        (
            "spender",
            Box::new(|p| p.spender = Some("0xevil".to_string())),
            ProviderVerificationError::SpenderNotAllowed,
        ),
        (
            "approval",
            Box::new(|p| p.approval_amount = Some(1)),
            ProviderVerificationError::ApprovalExceeded,
        ),
        (
            "amount_in",
            Box::new(|p| p.amount_in = AMOUNT_IN + 1),
            ProviderVerificationError::AmountInMismatch,
        ),
        (
            "amount_out",
            Box::new(|p| p.amount_out = GROSS_OUT + 1),
            ProviderVerificationError::AmountOutMismatch,
        ),
        (
            "min_receive_missing",
            Box::new(|p| p.min_receive_amount = None),
            ProviderVerificationError::MinReceiveMissing,
        ),
        (
            "min_receive_low",
            Box::new(|p| p.min_receive_amount = Some(NET_OUT - 1)),
            ProviderVerificationError::MinReceiveTooLow,
        ),
        (
            "min_receive_above_output",
            Box::new(|p| p.min_receive_amount = Some(GROSS_OUT + 1)),
            ProviderVerificationError::SlippageExceeded,
        ),
        (
            "value",
            Box::new(|p| p.value = 1),
            ProviderVerificationError::ValueExceeded,
        ),
        (
            "calldata_empty",
            Box::new(|p| {
                p.calldata = Vec::new();
                p.calldata_digest = calldata_digest(&[]);
            }),
            ProviderVerificationError::CalldataEmpty,
        ),
        (
            "calldata_digest",
            Box::new(|p| p.calldata_digest = [0u8; 32]),
            ProviderVerificationError::CalldataDigestMismatch,
        ),
        (
            "future",
            Box::new(|p| p.observed_at_ms = NOW + 1),
            ProviderVerificationError::ProposalFromFuture,
        ),
        (
            "stale",
            Box::new(|p| p.observed_at_ms = NOW - 60_001),
            ProviderVerificationError::ProposalStale,
        ),
    ];

    for (name, mutate, expected) in cases {
        let mut tampered = proposal();
        mutate(&mut tampered);
        assert_eq!(
            verify(&tampered, &policy),
            Err(expected),
            "tamper {name} must fail with the expected class"
        );
    }
}

#[test]
fn slippage_cap_is_enforced_independently_of_the_absolute_floor() {
    // The absolute floor is lowered so the implied-slippage cap is the binding
    // check: (2_000_000 - 1_950_000) / 2_000_000 = 250 bps > 100 bps cap.
    let mut tight = policy();
    tight.min_receive = 1_000_000;
    tight.max_slippage_bps = Bps::new(100).expect("bps");
    assert_eq!(
        verify(&proposal(), &tight),
        Err(ProviderVerificationError::SlippageExceeded)
    );

    // A minimum receive below the quoted output but inside the cap is admitted.
    let mut at_cap = policy();
    at_cap.min_receive = 1_000_000;
    at_cap.max_slippage_bps = Bps::new(250).expect("bps");
    let mut proposal = proposal();
    proposal.min_receive_amount = Some(GROSS_OUT - (GROSS_OUT * 250 / 10_000));
    assert!(verify(&proposal, &at_cap).is_ok());
}

#[test]
fn calldata_size_bound_fails_closed() {
    let mut oversized = proposal();
    oversized.calldata = vec![0u8; provider_verification::MAX_CALLDATA_BYTES + 1];
    oversized.calldata_digest = calldata_digest(&oversized.calldata);
    assert_eq!(
        verify(&oversized, &policy()),
        Err(ProviderVerificationError::CalldataTooLarge)
    );
}

#[test]
fn assessment_binding_is_enforced() {
    let mut wrong = assessment();
    wrong.chain = ChainId::Solana;
    assert_eq!(
        verify_provider_proposal(
            &intent(),
            &route(),
            &delta(),
            &wrong,
            &proposal(),
            &policy(),
            NOW
        ),
        Err(ProviderVerificationError::AssessmentMismatch)
    );

    let mut asset_wrong = assessment();
    asset_wrong.assessed_asset = token_in();
    assert_eq!(
        verify_provider_proposal(
            &intent(),
            &route(),
            &delta(),
            &asset_wrong,
            &proposal(),
            &policy(),
            NOW
        ),
        Err(ProviderVerificationError::AssessmentMismatch)
    );
}

#[test]
fn route_and_delta_asset_binding_is_enforced() {
    // The proposal echoes the intent pair, but a caller-trusted route/delta that
    // names a different asset must be rejected.
    let mut mutated_route = route();
    mutated_route.legs[0].token_out = asset("0xother");
    assert_eq!(
        verify_provider_proposal(
            &intent(),
            &mutated_route,
            &delta(),
            &assessment(),
            &proposal(),
            &policy(),
            NOW
        ),
        Err(ProviderVerificationError::TokenMismatch)
    );

    let mut delta = delta();
    delta.token_in = asset("0xother");
    assert_eq!(
        verify_provider_proposal(
            &intent(),
            &route(),
            &delta,
            &assessment(),
            &proposal(),
            &policy(),
            NOW
        ),
        Err(ProviderVerificationError::TokenMismatch)
    );
}

#[test]
fn approved_payload_carries_the_exact_calldata() {
    let approved = verify(&proposal(), &policy()).expect("approved");
    assert_eq!(approved.calldata(), calldata().as_slice());
    assert_eq!(approved.calldata_digest(), calldata_digest(&calldata()));
    // The approved payload renders no calldata.
    assert!(!format!("{approved:?}").contains("1, 2, 3"));
}

#[test]
fn empty_route_fails_closed() {
    let mut empty = route();
    empty.legs.clear();
    assert_eq!(
        verify_provider_proposal(
            &intent(),
            &empty,
            &delta(),
            &assessment(),
            &proposal(),
            &policy(),
            NOW
        ),
        Err(ProviderVerificationError::RouteMissing)
    );
}

#[test]
fn blank_expected_wallet_or_receiver_fails_closed() {
    let mut blank_wallet = policy();
    blank_wallet.expected_wallet = String::new();
    assert_eq!(
        verify(&proposal(), &blank_wallet),
        Err(ProviderVerificationError::WalletMismatch)
    );

    let mut blank_receiver = policy();
    blank_receiver.expected_receiver = String::new();
    assert_eq!(
        verify(&proposal(), &blank_receiver),
        Err(ProviderVerificationError::ReceiverMismatch)
    );
}
