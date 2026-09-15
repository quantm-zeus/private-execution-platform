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
    AmountType, IdempotencyKey, IntentId, OrderType, RoutePlan, SplitPlan, TradeIntent, TradeSide,
    TradeSource, ValidatedExecutionPreview, WalletRef,
};
use policy::{ApprovedExecution, PolicyEngine};
use sha2::{Digest, Sha256};

use crate::{PreparedExecutionRef, PrivyError};

const ROUTE_TAG: &[u8] = b"privy.signing.route.v1";
const SPLIT_ROUTE_TAG: &[u8] = b"privy.signing.split_route.v1";
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

    /// Rehydrates a persisted canonical digest.
    ///
    /// This is a durable-adapter seam: a store that persisted a request digest
    /// uses it to rebuild a bound submission during restart reconciliation. It
    /// cannot invent a digest that [`SigningRequest::bind`] did not produce,
    /// because callers only persist digests read from a bound request.
    #[doc(hidden)]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the digest bytes.
        f.debug_struct("RequestDigest").finish_non_exhaustive()
    }
}

/// Stable, deterministic provider-side idempotency identifier for a signing
/// request.
///
/// It is derived from the canonical [`RequestDigest`], so a retry of the exact
/// same bound request reuses the identifier and the provider can collapse it,
/// while any changed bound field yields a different identifier. It carries no
/// key material: it is a domain-separated hex encoding of a SHA-256 digest.
///
/// `Debug` is redacted; only the transport that sends it to the provider reads
/// [`ProviderIdempotencyId::as_str`].
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderIdempotencyId(String);

impl ProviderIdempotencyId {
    /// Borrows the opaque identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rehydrates an identifier from its persisted string form.
    ///
    /// This is a durable-adapter seam: a store that persisted the provider
    /// idempotency identifier as text (for restart reconciliation) rebuilds the
    /// type here. It does not create a signing capability.
    #[doc(hidden)]
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Debug for ProviderIdempotencyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the identifier.
        f.debug_struct("ProviderIdempotencyId")
            .finish_non_exhaustive()
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

    /// Binds a policy approval, prepared execution, intent, split plan, and
    /// validated aggregate preview into a canonical signing request.
    ///
    /// The checks are the same ordered fail-closed sequence as [`SigningRequest::bind`];
    /// step 7 re-runs the locked split validator, and the split route digest is
    /// domain-separated from the single-route digest inside the unchanged 32-byte
    /// `route_digest` slot of `compute_request_digest`. `SCHEMA_VERSION` and the
    /// request byte layout are unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_split(
        policy: &PolicyEngine,
        approval: &ApprovedExecution,
        prepared: &PreparedExecutionRef,
        intent: &TradeIntent,
        split: &SplitPlan,
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
        // 5. Global kill switch.
        if !policy.is_trading_enabled() {
            return Err(PrivyError::TradingDisabled);
        }
        // 6. Approval expiry.
        if matches!(approval.expires_at_ms(), Some(expires) if expires <= now_ms) {
            return Err(PrivyError::ApprovalExpired);
        }
        // 7. Re-run the locked split validator (intent + split + preview).
        preview
            .validate_split(intent, split, now_ms)
            .map_err(|_| PrivyError::PreviewRevalidationFailed)?;
        // 8. A zero digest is an absent payload.
        if payload_digest.is_zero() {
            return Err(PrivyError::MissingPayloadDigest);
        }

        let route_digest = compute_split_route_digest(split)?;
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

    /// Returns the stable provider-side idempotency identifier for this request.
    ///
    /// The identifier is `pep-sign-v1-<hex(request_digest)>`: it is stable for
    /// identical bound requests and changes if any bound field changes, so a
    /// transport can forward it to a provider that supports idempotent signing
    /// without ever receiving private signing material.
    pub fn provider_idempotency_id(&self) -> ProviderIdempotencyId {
        ProviderIdempotencyId(format!(
            "pep-sign-v1-{}",
            hex_lower(self.request_digest.as_bytes())
        ))
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

/// Public accessor for the canonical chain tag used by the signing digest.
///
/// A durable execution store persists this stable tag for restart
/// reconciliation; exposing it here keeps a single source of truth for the
/// mapping rather than duplicating it.
pub fn canonical_chain_tag(chain: &ChainId) -> Result<u8, PrivyError> {
    chain_tag(chain)
}

/// Inverse of [`canonical_chain_tag`]; `None` for an unknown tag so a corrupt
/// persisted row fails closed.
pub fn chain_from_canonical_tag(tag: u8) -> Option<ChainId> {
    match tag {
        0 => Some(ChainId::Solana),
        1 => Some(ChainId::Base),
        2 => Some(ChainId::BnbChain),
        3 => Some(ChainId::Ethereum),
        4 => Some(ChainId::RobinhoodAssociated),
        _ => None,
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

/// Lowercase hex encoding used only for the public provider idempotency id.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

/// `split_route_digest = SHA-256(split_route_bytes)`.
///
/// The split encoding is domain-separated from the single-route encoding by a
/// distinct first tag, so a signature request bound to a split can never be
/// replayed as a single-route request (or vice versa) with the same
/// `route_digest`. See the module-level layout.
///
/// ```text
/// split_route_bytes =
///   b"privy.signing.split_route.v1"
///   u32-be branch_count
///   for each branch:
///     u128-be branch.amount_in
///     u32-be branch.route.leg_count
///     for each route leg:
///       lp(venue) lp(pool_ref) asset(token_in) asset(token_out)
///       u128-be amount_in  u128-be expected_amount_out
///     asset(branch.route.expected_net_output.asset)
///     u128-be branch.route.expected_net_output.amount
///   asset(split.expected_net_output.asset)
///   u128-be aggregate_input                  (checked sum of branch.amount_in)
///   u128-be split.expected_net_output.amount
/// ```
fn compute_split_route_digest(split: &SplitPlan) -> Result<RequestDigest, PrivyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SPLIT_ROUTE_TAG);
    let branch_count =
        u32::try_from(split.legs.len()).map_err(|_| PrivyError::ApprovalBindingMismatch)?;
    bytes.extend_from_slice(&branch_count.to_be_bytes());
    let mut aggregate_input: u128 = 0;
    for branch in &split.legs {
        bytes.extend_from_slice(&branch.amount_in.get().to_be_bytes());
        let route_legs = u32::try_from(branch.route.legs.len())
            .map_err(|_| PrivyError::ApprovalBindingMismatch)?;
        bytes.extend_from_slice(&route_legs.to_be_bytes());
        for leg in &branch.route.legs {
            push_len_prefixed(&mut bytes, leg.venue.as_bytes())?;
            push_len_prefixed(&mut bytes, leg.pool_ref.as_bytes())?;
            push_asset(&mut bytes, &leg.token_in)?;
            push_asset(&mut bytes, &leg.token_out)?;
            bytes.extend_from_slice(&leg.amount_in.get().to_be_bytes());
            bytes.extend_from_slice(&leg.expected_amount_out.get().to_be_bytes());
        }
        push_asset(&mut bytes, &branch.route.expected_net_output.asset)?;
        bytes.extend_from_slice(&branch.route.expected_net_output.amount.get().to_be_bytes());
        aggregate_input = aggregate_input
            .checked_add(branch.amount_in.get())
            .ok_or(PrivyError::ApprovalBindingMismatch)?;
    }
    push_asset(&mut bytes, &split.expected_net_output.asset)?;
    bytes.extend_from_slice(&aggregate_input.to_be_bytes());
    bytes.extend_from_slice(&split.expected_net_output.amount.get().to_be_bytes());
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
    use crate::{PrivyError, ProviderIdempotencyId, SigningTransport};

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
            _idempotency: &ProviderIdempotencyId,
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
            _idempotency: &ProviderIdempotencyId,
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
            _idempotency: &ProviderIdempotencyId,
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
        RouteLeg, SplitLeg, SplitPlan, TradeSource, UserId,
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
        aggregate_preview(intent)
            .validate(intent, route, NOW_MS)
            .unwrap()
    }

    fn aggregate_preview(intent: &TradeIntent) -> ExecutionPreview {
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
    }

    /// One branch of the standard fixture split.
    fn split_branch(amount_in: u128, expected_out: u128, pool_ref: &str) -> SplitLeg {
        let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
        let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
        SplitLeg {
            amount_in: AtomicAmount::new(amount_in),
            route: RoutePlan {
                legs: vec![RouteLeg {
                    venue: "uniswap_v3".to_string(),
                    pool_ref: pool_ref.to_string(),
                    token_in,
                    token_out: token_out.clone(),
                    amount_in: AtomicAmount::new(amount_in),
                    expected_amount_out: AtomicAmount::new(expected_out + 6),
                }],
                expected_net_output: AssetAmount {
                    asset: token_out,
                    amount: AtomicAmount::new(expected_out),
                },
                state: Freshness {
                    observed_at_ms: NOW_MS,
                    chain_height: 100,
                    sequence: Sequence(1),
                },
            },
        }
    }

    /// A two-leg split whose aggregate economics equal [`aggregate_preview`]:
    /// 1000 in, 250 gross, 240 net.
    pub(crate) fn split_two() -> SplitPlan {
        SplitPlan {
            legs: vec![
                split_branch(600, 144, "0xpool1"),
                split_branch(400, 96, "0xpool2"),
            ],
            expected_net_output: AssetAmount {
                asset: AssetId::new(ChainId::Base, "TOKEN").unwrap(),
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: NOW_MS,
                chain_height: 100,
                sequence: Sequence(1),
            },
        }
    }

    pub(crate) fn split_execution_preview(
        intent: &TradeIntent,
        split: &SplitPlan,
    ) -> ValidatedExecutionPreview {
        aggregate_preview(intent)
            .validate_split(intent, split, NOW_MS)
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
    fn provider_idempotency_id_is_stable_and_request_bound() {
        let first = fixtures::signing_request();
        let again = fixtures::signing_request();
        assert_eq!(
            first.provider_idempotency_id().as_str(),
            again.provider_idempotency_id().as_str(),
            "same bound request yields the same provider idempotency id"
        );
        assert!(first
            .provider_idempotency_id()
            .as_str()
            .starts_with("pep-sign-v1-"));

        let engine = fixtures::engine();
        let mut other = fixtures::intent();
        other.nonce = 8;
        let approved = fixtures::approved(&engine, &other);
        let prepared = fixtures::prepared(&other);
        let route = fixtures::route();
        let preview = fixtures::execution_preview(&other, &route);
        let changed = SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &other,
            &route,
            &preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("changed request binds");
        assert_ne!(
            first.provider_idempotency_id().as_str(),
            changed.provider_idempotency_id().as_str(),
            "a changed bound field changes the provider idempotency id"
        );

        // The identifier is opaque through `Debug`.
        assert_eq!(
            format!("{:?}", first.provider_idempotency_id()),
            "ProviderIdempotencyId { .. }"
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

    #[test]
    fn split_digest_field_sensitivity() {
        use market_types::AtomicAmount;
        type SplitMutation = Box<dyn Fn(&mut SplitPlan)>;
        let base = fixtures::split_two();
        let baseline = compute_split_route_digest(&base).expect("digest");
        let mutations: Vec<SplitMutation> = vec![
            Box::new(|split: &mut SplitPlan| split.legs[0].amount_in = AtomicAmount::new(601)),
            Box::new(|split: &mut SplitPlan| {
                split.legs[0].route.legs[0].venue = "other".to_string()
            }),
            Box::new(|split: &mut SplitPlan| {
                split.legs[0].route.legs[0].pool_ref = "0xother".to_string()
            }),
            Box::new(|split: &mut SplitPlan| {
                split.legs[0].route.legs[0].token_in =
                    AssetId::new(ChainId::Base, "OTHER").expect("asset")
            }),
            Box::new(|split: &mut SplitPlan| {
                split.legs[0].route.legs[0].expected_amount_out = AtomicAmount::new(151)
            }),
            Box::new(|split: &mut SplitPlan| {
                split.legs[0].route.legs[0].amount_in = AtomicAmount::new(599)
            }),
            Box::new(|split: &mut SplitPlan| {
                split.expected_net_output.amount = AtomicAmount::new(241)
            }),
            Box::new(|split: &mut SplitPlan| {
                split.legs.pop();
                split.expected_net_output.amount = AtomicAmount::new(144)
            }),
        ];
        for mutate in mutations {
            let mut candidate = base.clone();
            mutate(&mut candidate);
            let digest = compute_split_route_digest(&candidate).expect("digest");
            assert_ne!(
                baseline.as_bytes(),
                digest.as_bytes(),
                "a bound split field change must change the split route digest"
            );
        }
    }

    #[test]
    fn bind_split_positive_and_intent_sensitive() {
        let engine = fixtures::engine();
        let intent = fixtures::intent();
        let split = fixtures::split_two();
        let approved = fixtures::approved(&engine, &intent);
        let prepared = fixtures::prepared(&intent);
        let preview = fixtures::split_execution_preview(&intent, &split);
        let request = SigningRequest::bind_split(
            &engine,
            &approved,
            &prepared,
            &intent,
            &split,
            &preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("split binds");
        let again = SigningRequest::bind_split(
            &engine,
            &approved,
            &prepared,
            &intent,
            &split,
            &preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("split rebinds");
        assert_eq!(request.request_digest(), again.request_digest());

        let mut other = fixtures::intent();
        other.nonce = 8;
        let other_approved = fixtures::approved(&engine, &other);
        let other_prepared = fixtures::prepared(&other);
        let other_preview = fixtures::split_execution_preview(&other, &split);
        let other_request = SigningRequest::bind_split(
            &engine,
            &other_approved,
            &other_prepared,
            &other,
            &split,
            &other_preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("other intent binds");
        assert_ne!(request.request_digest(), other_request.request_digest());
    }

    #[test]
    fn single_vs_split_tag_separation() {
        let engine = fixtures::engine();
        let intent = fixtures::intent();
        let route = fixtures::route();
        let approved = fixtures::approved(&engine, &intent);
        let prepared = fixtures::prepared(&intent);
        let single_preview = fixtures::execution_preview(&intent, &route);
        let single = SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent,
            &route,
            &single_preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("single binds");

        let one_leg = SplitPlan {
            legs: vec![domain::SplitLeg {
                amount_in: market_types::AtomicAmount::new(1_000),
                route: route.clone(),
            }],
            expected_net_output: route.expected_net_output.clone(),
            state: route.state,
        };
        let split_preview = fixtures::split_execution_preview(&intent, &one_leg);
        let split = SigningRequest::bind_split(
            &engine,
            &approved,
            &prepared,
            &intent,
            &one_leg,
            &split_preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("split binds");

        assert_ne!(single.request_digest(), split.request_digest());
        assert!(!ROUTE_TAG.starts_with(SPLIT_ROUTE_TAG));
        assert!(!SPLIT_ROUTE_TAG.starts_with(ROUTE_TAG));
        assert_ne!(ROUTE_TAG, SPLIT_ROUTE_TAG);
    }

    #[test]
    fn bind_split_rejects_preview_that_fails_split_validation() {
        let engine = fixtures::engine();
        let intent = fixtures::intent();
        let mut split = fixtures::split_two();
        split.legs[0].amount_in = market_types::AtomicAmount::new(601);
        let approved = fixtures::approved(&engine, &intent);
        let prepared = fixtures::prepared(&intent);
        // Preview bound to the untouched aggregate conservation (1000 in).
        let preview = fixtures::split_execution_preview(&intent, &fixtures::split_two());
        assert_eq!(
            SigningRequest::bind_split(
                &engine,
                &approved,
                &prepared,
                &intent,
                &split,
                &preview,
                fixtures::payload(),
                fixtures::NOW_MS,
            ),
            Err(PrivyError::PreviewRevalidationFailed)
        );
    }

    #[test]
    fn bind_split_zero_payload_rejected() {
        let engine = fixtures::engine();
        let intent = fixtures::intent();
        let split = fixtures::split_two();
        let approved = fixtures::approved(&engine, &intent);
        let prepared = fixtures::prepared(&intent);
        let preview = fixtures::split_execution_preview(&intent, &split);
        assert_eq!(
            SigningRequest::bind_split(
                &engine,
                &approved,
                &prepared,
                &intent,
                &split,
                &preview,
                PayloadDigest::from_bytes([0u8; 32]),
                fixtures::NOW_MS,
            ),
            Err(PrivyError::MissingPayloadDigest)
        );
    }
}
