//! Private signing-request boundary: canonical, redacted, fail-closed.
//!
//! This module carries a fully bound [`SigningRequest`] from the private core to
//! the signing boundary. `privy` never sees raw transaction bytes: the only
//! chain-facing input is the caller-supplied 32-byte [`PayloadDigest`], which is
//! produced outside this crate (future chain adapter over unsigned tx bytes) and
//! is only carried and compared here.
//!
//! ## Canonical byte layout
//!
//! The request digest is a deterministic, versioned, length-prefixed encoding
//! hashed with SHA-256. No serde, `HashMap`, floats, or platform-dependent
//! widths are involved. Variable-length fields are length-prefixed
//! (`lp(x) = u32-be(len(x)) || x`), fixed-width integers are big-endian, and
//! assets are `chain_tag(a.chain) || lp(a.address)`.
//!
//! ### `route_digest = SHA-256(route_bytes)`
//!
//! ```text
//! route_bytes =
//!   b"privy.signing.route.v1"
//!   u32-be leg_count
//!   for each leg:
//!     lp(venue)
//!     lp(pool_ref)
//!     asset(token_in)
//!     asset(token_out)
//!     u128-be amount_in
//!     u128-be expected_amount_out
//!   asset(expected_net_output.asset)
//!   u128-be expected_net_output.amount
//! ```
//!
//! ### `intent_digest = SHA-256(intent_bytes)`
//!
//! The request commits to the COMPLETE [`TradeIntent`] so that a mutated public
//! intent sharing the same id (dropped limit price, changed amount, order type,
//! risk caps, or partial-fill policy) cannot keep the same request digest.
//!
//! ```text
//! intent_bytes =
//!   b"privy.signing.intent.v1"
//!   lp(id)
//!   u8 source (Web = 0, Mcp = 1, Telegram = 2, Internal = 3)
//!   lp(user_id)
//!   lp(wallet_ref)
//!   chain_tag(chain)
//!   asset(token_in)
//!   asset(token_out)
//!   u8 side (Buy = 0, Sell = 1)
//!   u8 amount_type (InputAssetAtomic = 0, OutputAssetAtomic = 1, UsdMicros = 2)
//!   u128-be amount
//!   u8 order_type (Market = 0, Limit = 1)
//!   i8 has_limit_price (0 | 1)
//!   asset(limit_price.numerator_asset)      (only when has_limit_price = 1)
//!   asset(limit_price.denominator_asset)    (only when has_limit_price = 1)
//!   u128-be limit_price.ratio.numerator_atomic   (only when has_limit_price = 1)
//!   u128-be limit_price.ratio.denominator_atomic (only when has_limit_price = 1)
//!   u16-be risk.max_buy_tax
//!   u16-be risk.max_sell_tax
//!   u16-be risk.max_price_impact
//!   u16-be risk.max_slippage
//!   i8 has_max_total_cost (0 | 1)
//!   asset(risk.max_total_cost.asset)        (only when has_max_total_cost = 1)
//!   u128-be risk.max_total_cost.amount      (only when has_max_total_cost = 1)
//!   u8 allow_partial_fill (0 | 1)
//!   i8 has_expiry (0 | 1)
//!   i64-be expiry_ms                        (only when has_expiry = 1)
//!   u64-be nonce
//!   lp(idempotency_key)
//! ```
//!
//! ### `request_digest = SHA-256(request_bytes)`
//!
//! ```text
//! request_bytes =
//!   b"privy.signing.request.v1"
//!   u16-be schema_version (= 1)
//!   lp(intent_id)
//!   lp(idempotency_key)
//!   lp(wallet_ref)
//!   chain_tag(intent.chain)
//!   u64-be intent.nonce
//!   u8 side (Buy = 0, Sell = 1)
//!   asset(token_in)
//!   asset(token_out)
//!   u128-be preview.simulated_net_input.amount
//!   u128-be preview.gross_output.amount
//!   u128-be preview.simulated_net_output.amount
//!   [32 bytes] payload_digest
//!   i8 has_expiry (0 | 1)
//!   i64-be approval.expires_at_ms   (only when has_expiry = 1)
//!   i64-be approval.approved_at_ms
//!   u64-be approval.approved_trade_usd
//!   lp(prepared.reference())
//!   [32 bytes] route_digest
//!   [32 bytes] intent_digest
//! ```
//!
//! `chain_tag`: Solana = 0, Base = 1, BnbChain = 2, Ethereum = 3,
//! RobinhoodAssociated = 4. Operator-defined ([`ChainId::Other`]) chains have no
//! canonical tag and are rejected fail-closed with
//! [`crate::PrivyError::UnsupportedChain`] rather than assigned an invented
//! encoding.
//!
//! The [`PayloadDigest`] is an internal binding token, not the chain's own
//! signature hash.

use std::fmt;

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RoutePlan, TradeIntent, TradeSide,
    TradeSource, ValidatedExecutionPreview, WalletRef,
};
use policy::{ApprovedExecution, PolicyEngine};
use sha2::{Digest, Sha256};

use crate::{PreparedExecutionRef, PrivyError};

const ROUTE_TAG: &[u8] = b"privy.signing.route.v1";
const REQUEST_TAG: &[u8] = b"privy.signing.request.v1";
const INTENT_TAG: &[u8] = b"privy.signing.intent.v1";
const SCHEMA_VERSION: u16 = 1;

/// SHA-256 digest of the unsigned transaction payload.
///
/// Produced outside `privy`; carried and compared here only. Debug output never
/// reveals the bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PayloadDigest([u8; 32]);

impl PayloadDigest {
    /// Wraps already-computed payload digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reports whether the digest is entirely zero (an absent payload).
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for PayloadDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the digest bytes.
        f.debug_struct("PayloadDigest").finish_non_exhaustive()
    }
}

/// Canonical digest binding every signed-request field.
///
/// Constructed only inside this crate. Debug output never reveals the bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    /// Borrows the canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the digest bytes.
        f.debug_struct("RequestDigest").finish_non_exhaustive()
    }
}

/// A fully bound signing request. Fields are private; callers can only read the
/// bound metadata and the canonical request digest.
#[derive(PartialEq, Eq)]
pub struct SigningRequest {
    request_digest: RequestDigest,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
    wallet_ref: WalletRef,
    chain: ChainId,
    nonce: u64,
    payload_digest: PayloadDigest,
}

impl SigningRequest {
    /// Binds a policy approval, prepared execution, intent, route, and validated
    /// preview into a canonical signing request.
    ///
    /// Every check fails closed, in order:
    /// 1. intent / approval / preview identities agree;
    /// 2. intent wallet + chain agree with the approval and preview;
    /// 3. idempotency key agrees across intent / approval / prepared, and the
    ///    prepared intent matches;
    /// 4. preview token pair and side match the intent;
    /// 5. the trading gate is enabled (the live kill switch is checked *before*
    ///    domain revalidation so it always wins and is reachable);
    /// 6. the approval has not expired (absent or strictly in the future, checked
    ///    before domain revalidation so an expired approval yields
    ///    `ApprovalExpired`, not the domain `Expired`);
    /// 7. the locked preview validator re-runs;
    /// 8. the payload digest is present (non-zero).
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        policy: &PolicyEngine,
        approval: &ApprovedExecution,
        prepared: &PreparedExecutionRef,
        intent: &TradeIntent,
        route: &RoutePlan,
        preview: &ValidatedExecutionPreview,
        payload_digest: PayloadDigest,
        now_ms: i64,
    ) -> Result<Self, PrivyError> {
        // 1. Identity binding.
        if intent.id != *approval.intent_id() || intent.id != preview.intent_id {
            return Err(PrivyError::ApprovalBindingMismatch);
        }
        // 2. Wallet and chain binding.
        if intent.wallet_ref != *approval.wallet_ref()
            || intent.chain != *approval.chain()
            || intent.chain != preview.chain
        {
            return Err(PrivyError::ApprovalBindingMismatch);
        }
        // 3. Idempotency + prepared-execution binding.
        if intent.idempotency_key != *approval.idempotency_key()
            || intent.idempotency_key != *prepared.idempotency_key()
            || prepared.intent_id() != &intent.id
        {
            return Err(PrivyError::ApprovalBindingMismatch);
        }
        // 4. Preview must describe the same pair and side as the intent.
        if preview.token_in != intent.token_in
            || preview.token_out != intent.token_out
            || preview.side != intent.side
        {
            return Err(PrivyError::PreviewRevalidationFailed);
        }
        // 5. Global kill switch. Checked before domain revalidation so the
        // live kill switch always wins and stays reachable.
        if !policy.is_trading_enabled() {
            return Err(PrivyError::TradingDisabled);
        }
        // 6. Approval expiry (an absent expiry never expires). Checked before
        // domain revalidation so an expired approval yields `ApprovalExpired`
        // rather than the domain `Expired`.
        if matches!(approval.expires_at_ms(), Some(expires) if expires <= now_ms) {
            return Err(PrivyError::ApprovalExpired);
        }
        // 7. Re-run the locked deterministic validator. Any domain failure is a
        // revalidation failure; no payload is attached.
        preview
            .validate(intent, route, now_ms)
            .map_err(|_| PrivyError::PreviewRevalidationFailed)?;
        // 8. A zero digest is an absent payload.
        if payload_digest.is_zero() {
            return Err(PrivyError::MissingPayloadDigest);
        }

        let route_digest = compute_route_digest(route)?;
        let intent_digest = compute_intent_digest(intent)?;
        let request_digest = compute_request_digest(
            approval,
            prepared,
            intent,
            preview,
            &payload_digest,
            &route_digest,
            &intent_digest,
        )?;

        Ok(Self {
            request_digest,
            intent_id: intent.id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: intent.chain.clone(),
            nonce: intent.nonce,
            payload_digest,
        })
    }

    /// Canonical digest binding every request field.
    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    pub fn wallet_ref(&self) -> &WalletRef {
        &self.wallet_ref
    }

    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn payload_digest(&self) -> &PayloadDigest {
        &self.payload_digest
    }
}

impl fmt::Debug for SigningRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit identifiers, references, and digest bytes.
        f.debug_struct("SigningRequest").finish_non_exhaustive()
    }
}

/// Opaque reference to an execution signed through this boundary.
///
/// External crates cannot construct this type; only a successful submission
/// yields one. Debug output never reveals the reference.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedExecutionRef {
    reference: String,
    request_digest: RequestDigest,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
}

impl SignedExecutionRef {
    /// Crate-private constructor; an empty reference is rejected.
    pub(crate) fn new(
        reference: String,
        request_digest: RequestDigest,
        intent_id: IntentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, PrivyError> {
        if reference.trim().is_empty() {
            return Err(PrivyError::InvalidExecutionReference);
        }
        Ok(Self {
            reference,
            request_digest,
            intent_id,
            idempotency_key,
        })
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl fmt::Debug for SignedExecutionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit the reference, identifiers, and digest bytes.
        f.debug_struct("SignedExecutionRef").finish_non_exhaustive()
    }
}

/// Maps a chain to its canonical one-byte tag. Unknown/operator-defined chains
/// cannot be encoded deterministically and are rejected fail-closed.
fn chain_tag(chain: &ChainId) -> Result<u8, PrivyError> {
    match chain {
        ChainId::Solana => Ok(0),
        ChainId::Base => Ok(1),
        ChainId::BnbChain => Ok(2),
        ChainId::Ethereum => Ok(3),
        ChainId::RobinhoodAssociated => Ok(4),
        ChainId::Other(_) => Err(PrivyError::UnsupportedChain),
    }
}

/// Canonical enum tags for the intent encoding (declaration order).
fn trade_source_tag(source: TradeSource) -> u8 {
    match source {
        TradeSource::Web => 0,
        TradeSource::Mcp => 1,
        TradeSource::Telegram => 2,
        TradeSource::Internal => 3,
    }
}

fn amount_type_tag(amount_type: AmountType) -> u8 {
    match amount_type {
        AmountType::InputAssetAtomic => 0,
        AmountType::OutputAssetAtomic => 1,
        AmountType::UsdMicros => 2,
    }
}

fn order_type_tag(order_type: OrderType) -> u8 {
    match order_type {
        OrderType::Market => 0,
        OrderType::Limit => 1,
    }
}

fn side_tag(side: TradeSide) -> u8 {
    match side {
        TradeSide::Buy => 0,
        TradeSide::Sell => 1,
    }
}

/// `lp(x) = u32-be(len(x)) || x`, with the length overflow checked fail-closed.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PrivyError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PrivyError::ApprovalBindingMismatch)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// `asset(a) = chain_tag(a.chain) || lp(a.address)`.
fn push_asset(out: &mut Vec<u8>, asset: &AssetId) -> Result<(), PrivyError> {
    out.push(chain_tag(&asset.chain)?);
    push_len_prefixed(out, asset.address.as_bytes())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn compute_route_digest(route: &RoutePlan) -> Result<RequestDigest, PrivyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ROUTE_TAG);
    let leg_count =
        u32::try_from(route.legs.len()).map_err(|_| PrivyError::ApprovalBindingMismatch)?;
    bytes.extend_from_slice(&leg_count.to_be_bytes());
    for leg in &route.legs {
        push_len_prefixed(&mut bytes, leg.venue.as_bytes())?;
        push_len_prefixed(&mut bytes, leg.pool_ref.as_bytes())?;
        push_asset(&mut bytes, &leg.token_in)?;
        push_asset(&mut bytes, &leg.token_out)?;
        bytes.extend_from_slice(&leg.amount_in.get().to_be_bytes());
        bytes.extend_from_slice(&leg.expected_amount_out.get().to_be_bytes());
    }
    push_asset(&mut bytes, &route.expected_net_output.asset)?;
    bytes.extend_from_slice(&route.expected_net_output.amount.get().to_be_bytes());
    Ok(RequestDigest(sha256(&bytes)))
}

/// `intent_digest = SHA-256(intent_bytes)`, committing the request to the
/// COMPLETE intent so a mutated public intent with the same id cannot reuse the
/// digest. See the module-level layout.
fn compute_intent_digest(intent: &TradeIntent) -> Result<RequestDigest, PrivyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INTENT_TAG);
    push_len_prefixed(&mut bytes, intent.id.as_str().as_bytes())?;
    bytes.push(trade_source_tag(intent.source));
    push_len_prefixed(&mut bytes, intent.user_id.as_str().as_bytes())?;
    push_len_prefixed(&mut bytes, intent.wallet_ref.as_str().as_bytes())?;
    bytes.push(chain_tag(&intent.chain)?);
    push_asset(&mut bytes, &intent.token_in)?;
    push_asset(&mut bytes, &intent.token_out)?;
    bytes.push(side_tag(intent.side));
    bytes.push(amount_type_tag(intent.amount_type));
    bytes.extend_from_slice(&intent.amount.get().to_be_bytes());
    bytes.push(order_type_tag(intent.order_type));
    match &intent.limit_price {
        Some(limit) => {
            bytes.push(1);
            push_asset(&mut bytes, &limit.numerator_asset)?;
            push_asset(&mut bytes, &limit.denominator_asset)?;
            bytes.extend_from_slice(&limit.ratio.numerator_atomic().to_be_bytes());
            bytes.extend_from_slice(&limit.ratio.denominator_atomic().to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&intent.risk.max_buy_tax.get().to_be_bytes());
    bytes.extend_from_slice(&intent.risk.max_sell_tax.get().to_be_bytes());
    bytes.extend_from_slice(&intent.risk.max_price_impact.get().to_be_bytes());
    bytes.extend_from_slice(&intent.risk.max_slippage.get().to_be_bytes());
    match &intent.risk.max_total_cost {
        Some(total) => {
            bytes.push(1);
            push_asset(&mut bytes, &total.asset)?;
            bytes.extend_from_slice(&total.amount.get().to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.push(u8::from(intent.allow_partial_fill));
    match intent.expiry_ms {
        Some(expiry) => {
            bytes.push(1);
            bytes.extend_from_slice(&expiry.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&intent.nonce.to_be_bytes());
    push_len_prefixed(&mut bytes, intent.idempotency_key.as_str().as_bytes())?;
    Ok(RequestDigest(sha256(&bytes)))
}

fn compute_request_digest(
    approval: &ApprovedExecution,
    prepared: &PreparedExecutionRef,
    intent: &TradeIntent,
    preview: &ValidatedExecutionPreview,
    payload_digest: &PayloadDigest,
    route_digest: &RequestDigest,
    intent_digest: &RequestDigest,
) -> Result<RequestDigest, PrivyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REQUEST_TAG);
    bytes.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    push_len_prefixed(&mut bytes, intent.id.as_str().as_bytes())?;
    push_len_prefixed(&mut bytes, intent.idempotency_key.as_str().as_bytes())?;
    push_len_prefixed(&mut bytes, intent.wallet_ref.as_str().as_bytes())?;
    bytes.push(chain_tag(&intent.chain)?);
    bytes.extend_from_slice(&intent.nonce.to_be_bytes());
    bytes.push(side_tag(intent.side));
    push_asset(&mut bytes, &intent.token_in)?;
    push_asset(&mut bytes, &intent.token_out)?;
    bytes.extend_from_slice(&preview.simulated_net_input.amount.get().to_be_bytes());
    bytes.extend_from_slice(&preview.gross_output.amount.get().to_be_bytes());
    bytes.extend_from_slice(&preview.simulated_net_output.amount.get().to_be_bytes());
    bytes.extend_from_slice(payload_digest.as_bytes());
    match approval.expires_at_ms() {
        Some(expires) => {
            bytes.push(1);
            bytes.extend_from_slice(&expires.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&approval.approved_at_ms().to_be_bytes());
    bytes.extend_from_slice(&approval.approved_trade_usd().get().to_be_bytes());
    push_len_prefixed(&mut bytes, prepared.reference().as_bytes())?;
    bytes.extend_from_slice(route_digest.as_bytes());
    bytes.extend_from_slice(intent_digest.as_bytes());
    Ok(RequestDigest(sha256(&bytes)))
}

/// In-crate test doubles. Never compiled into a production artifact; there is no
/// public way to install a real transport.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::SigningRequest;
    use crate::{PrivyError, SigningTransport};

    /// Records how many times the transport was invoked.
    pub(crate) struct CountingTransport {
        calls: Arc<AtomicUsize>,
    }

    impl CountingTransport {
        pub(crate) fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    #[async_trait]
    impl SigningTransport for CountingTransport {
        async fn submit_signing_request(
            &self,
            request: &SigningRequest,
        ) -> Result<String, PrivyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("signed-{}", request.intent_id().as_str()))
        }
    }

    /// Always rejects, exercising the redacted signer-rejection path.
    pub(crate) struct RejectingTransport;

    #[async_trait]
    impl SigningTransport for RejectingTransport {
        async fn submit_signing_request(
            &self,
            _request: &SigningRequest,
        ) -> Result<String, PrivyError> {
            Err(PrivyError::SignerRejected)
        }
    }

    /// Returns an empty reference, which the boundary must reject.
    pub(crate) struct EmptyRefTransport;

    #[async_trait]
    impl SigningTransport for EmptyRefTransport {
        async fn submit_signing_request(
            &self,
            _request: &SigningRequest,
        ) -> Result<String, PrivyError> {
            Ok(String::new())
        }
    }
}

/// Unit-test fixtures. Compiled only under `cfg(test)`.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::HashSet;

    use chain_types::{AssetId, ChainId};
    use domain::{
        AmountType, ExecutionCostComponents, ExecutionPreview, OrderType, RiskConstraints,
        RouteLeg, TradeSource, UserId,
    };
    use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
    use policy::{PolicyContext, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};

    use super::{
        ApprovedExecution, PayloadDigest, PolicyEngine, PreparedExecutionRef, RoutePlan,
        SigningRequest, TradeIntent, TradeSide, ValidatedExecutionPreview,
    };

    pub(crate) const NOW_MS: i64 = 1_000;

    pub(crate) fn intent() -> TradeIntent {
        TradeIntent {
            id: domain::IntentId::new("intent-1").unwrap(),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").unwrap(),
            wallet_ref: domain::WalletRef::new("wallet-1").unwrap(),
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
            idempotency_key: domain::IdempotencyKey::new("idem-1").unwrap(),
        }
    }

    pub(crate) fn route() -> RoutePlan {
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

    pub(crate) fn engine() -> PolicyEngine {
        PolicyEngine::new(
            TradingGate::from_trusted_startup(Some("true")).unwrap(),
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
            },
        )
        .unwrap()
    }

    pub(crate) fn context() -> PolicyContext {
        PolicyContext::from_trusted_backend_state(
            NOW_MS,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".to_string()),
        )
        .unwrap()
    }

    pub(crate) fn approved(engine: &PolicyEngine, intent: &TradeIntent) -> ApprovedExecution {
        engine.authorize_trade(intent, &context()).unwrap()
    }

    pub(crate) fn prepared(intent: &TradeIntent) -> PreparedExecutionRef {
        PreparedExecutionRef::new(
            "prepared-1",
            intent.id.clone(),
            intent.idempotency_key.clone(),
        )
        .unwrap()
    }

    pub(crate) fn payload() -> PayloadDigest {
        PayloadDigest::from_bytes(std::array::from_fn(|i| i as u8))
    }

    pub(crate) fn execution_preview(
        intent: &TradeIntent,
        route: &RoutePlan,
    ) -> ValidatedExecutionPreview {
        ExecutionPreview {
            intent_id: intent.id.clone(),
            chain: intent.chain.clone(),
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
        .unwrap()
    }

    pub(crate) fn signing_request() -> SigningRequest {
        let engine = engine();
        let intent = intent();
        let route = route();
        let approved = approved(&engine, &intent);
        let prepared = prepared(&intent);
        let preview = execution_preview(&intent, &route);
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent,
            &route,
            &preview,
            payload(),
            NOW_MS,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures;
    use super::*;

    #[test]
    fn digest_debug_output_is_redacted() {
        let payload = PayloadDigest::from_bytes([0xab; 32]);
        assert_eq!(format!("{payload:?}"), "PayloadDigest { .. }");
        let request = fixtures::signing_request();
        assert_eq!(
            format!("{:?}", request.request_digest()),
            "RequestDigest { .. }"
        );
    }

    #[test]
    fn zero_payload_digest_is_missing() {
        let engine = fixtures::engine();
        let intent = fixtures::intent();
        let route = fixtures::route();
        let approved = fixtures::approved(&engine, &intent);
        let prepared = fixtures::prepared(&intent);
        let preview = fixtures::execution_preview(&intent, &route);
        assert_eq!(
            SigningRequest::bind(
                &engine,
                &approved,
                &prepared,
                &intent,
                &route,
                &preview,
                PayloadDigest::from_bytes([0u8; 32]),
                fixtures::NOW_MS,
            ),
            Err(PrivyError::MissingPayloadDigest)
        );
    }

    #[test]
    fn operator_defined_chain_is_unsupported() {
        // Operator-defined chains have no canonical tag, so encoding fails closed
        // with a dedicated payload-free error rather than a binding mismatch.
        let mut intent = fixtures::intent();
        intent.chain = ChainId::Other("custom-chain".to_string());
        assert_eq!(
            compute_intent_digest(&intent),
            Err(PrivyError::UnsupportedChain)
        );
    }
}
