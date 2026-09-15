//! Pure, fail-closed verification of an untrusted provider swap proposal.
//!
//! A provider (for example OKX) returns a transaction proposal: a router
//! contract, calldata, a native value, and the quoted input/output amounts. None
//! of it is trusted. [`verify_provider_proposal`] binds the proposal to the
//! approved intent, route, and net delta, checks a trusted allowlist/spend
//! policy, recomputes the calldata digest, and only then returns an
//! [`ApprovedProviderPayload`]. No signing, submission, network, clock, RNG, or
//! floating point is involved; the reference time is supplied by the caller.

use std::cmp::Ordering;
use std::fmt;

use chain_types::{AssetId, ChainId};
use domain::{cmp_u128_products, RoutePlan, TradeIntent};
use execution_preview::NetDelta;
use market_types::{Bps, FreshnessStatus};
use sha2::{Digest, Sha256};
use tax_engine::{assessed_asset_for_intent, TaxAssessment};

use crate::error::ProviderVerificationError;

/// Maximum accepted provider calldata length in bytes.
pub const MAX_CALLDATA_BYTES: usize = 32 * 1024;

/// Maximum accepted address/label length in bytes.
pub const MAX_LABEL_BYTES: usize = 128;

/// Untrusted provider swap proposal.
///
/// The fields are deliberately public so an adapter can project a provider
/// response into this shape, but the value must never be trusted or rendered
/// until [`verify_provider_proposal`] accepts it. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderSwapProposal {
    /// Chain the proposal executes on.
    pub chain: ChainId,
    /// Owner wallet (`tx.from`).
    pub wallet: String,
    /// Output recipient.
    pub receiver: String,
    /// Router/spender contract the transaction calls (`tx.to`).
    pub router: String,
    /// Approval spender, when the proposal includes an approval.
    pub spender: Option<String>,
    /// Approved input asset.
    pub token_in: AssetId,
    /// Approved output asset.
    pub token_out: AssetId,
    /// DEX input amount in `token_in` atomic units.
    pub amount_in: u128,
    /// Quoted output amount in `token_out` atomic units.
    pub amount_out: u128,
    /// Minimum output enforced by the transaction, when provided.
    pub min_receive_amount: Option<u128>,
    /// Native value attached to the transaction.
    pub value: u128,
    /// Approval amount, when the proposal includes an approval.
    pub approval_amount: Option<u128>,
    /// Raw transaction calldata.
    pub calldata: Vec<u8>,
    /// Digest of `calldata` the proposal commits to.
    pub calldata_digest: [u8; 32],
    /// Caller reference instant the proposal was observed at, in milliseconds.
    pub observed_at_ms: i64,
}

impl fmt::Debug for ProviderSwapProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Addresses, amounts, calldata, and the digest are execution economics.
        formatter
            .debug_struct("ProviderSwapProposal")
            .finish_non_exhaustive()
    }
}

/// Trusted verification policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderVerificationPolicy {
    /// Exact router contracts that may be called.
    pub allowed_routers: Vec<String>,
    /// Exact approval spenders that may be approved.
    pub allowed_spenders: Vec<String>,
    /// The trusted owner wallet.
    pub expected_wallet: String,
    /// The trusted output recipient.
    pub expected_receiver: String,
    /// Hard cap on the native value.
    pub max_value: u128,
    /// Hard cap on any approval amount.
    pub max_approval: u128,
    /// Absolute minimum output the transaction must enforce.
    pub min_receive: u128,
    /// Hard cap on the proposal's implied slippage.
    pub max_slippage_bps: Bps,
    /// Maximum accepted proposal age in milliseconds.
    pub max_age_ms: u64,
}

impl fmt::Debug for ProviderVerificationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Allowlists/wallets/amounts are capability semantics.
        formatter
            .debug_struct("ProviderVerificationPolicy")
            .field("routers", &self.allowed_routers.len())
            .field("spenders", &self.allowed_spenders.len())
            .field("max_age_ms", &self.max_age_ms)
            .finish_non_exhaustive()
    }
}

/// An approved, fully bound provider payload.
///
/// This is the ONLY shape that may be handed to a signing boundary. Manual
/// redacted `Debug`; deliberately not `Serialize` so it never crosses a wire or
/// telemetry boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedProviderPayload {
    chain: ChainId,
    router: String,
    spender: Option<String>,
    token_in: AssetId,
    token_out: AssetId,
    amount_in: u128,
    amount_out: u128,
    min_receive_amount: u128,
    value: u128,
    approval_amount: Option<u128>,
    calldata: Vec<u8>,
    calldata_digest: [u8; 32],
}

impl ApprovedProviderPayload {
    /// The approved chain.
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }
    /// The allowlisted router.
    pub fn router(&self) -> &str {
        &self.router
    }
    /// The allowlisted approval spender, when present.
    pub fn spender(&self) -> Option<&str> {
        self.spender.as_deref()
    }
    /// The approved input asset.
    pub fn token_in(&self) -> &AssetId {
        &self.token_in
    }
    /// The approved output asset.
    pub fn token_out(&self) -> &AssetId {
        &self.token_out
    }
    /// The approved DEX input amount.
    pub fn amount_in(&self) -> u128 {
        self.amount_in
    }
    /// The approved quoted output amount.
    pub fn amount_out(&self) -> u128 {
        self.amount_out
    }
    /// The approved minimum receive amount.
    pub fn min_receive_amount(&self) -> u128 {
        self.min_receive_amount
    }
    /// The approved native value.
    pub fn value(&self) -> u128 {
        self.value
    }
    /// The approved approval amount, when present.
    pub fn approval_amount(&self) -> Option<u128> {
        self.approval_amount
    }
    /// The committed calldata digest (32 bytes).
    pub fn calldata_digest(&self) -> [u8; 32] {
        self.calldata_digest
    }
    /// The exact verified calldata a signing boundary must sign.
    ///
    /// Never rendered by `Debug`; the digest accessor commits these bytes.
    pub fn calldata(&self) -> &[u8] {
        &self.calldata
    }
}

impl fmt::Debug for ApprovedProviderPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedProviderPayload")
            .finish_non_exhaustive()
    }
}

/// Verifies an untrusted provider proposal against the approved intent.
///
/// Checks run in a fixed, fail-closed order. Any failure returns a redacted
/// [`ProviderVerificationError`] and no [`ApprovedProviderPayload`]; a payload is
/// produced only after every binding, allowlist, spend, digest, and freshness
/// check passes.
pub fn verify_provider_proposal(
    intent: &TradeIntent,
    route: &RoutePlan,
    delta: &NetDelta,
    assessment: &TaxAssessment,
    proposal: &ProviderSwapProposal,
    policy: &ProviderVerificationPolicy,
    now_ms: i64,
) -> Result<ApprovedProviderPayload, ProviderVerificationError> {
    let leg = route
        .legs
        .first()
        .ok_or(ProviderVerificationError::RouteMissing)?;

    if proposal.chain != intent.chain {
        return Err(ProviderVerificationError::ChainMismatch);
    }
    if proposal.token_in != intent.token_in || proposal.token_out != intent.token_out {
        return Err(ProviderVerificationError::TokenMismatch);
    }
    if policy.expected_wallet.is_empty() || proposal.wallet != policy.expected_wallet {
        return Err(ProviderVerificationError::WalletMismatch);
    }
    if policy.expected_receiver.is_empty() || proposal.receiver != policy.expected_receiver {
        return Err(ProviderVerificationError::ReceiverMismatch);
    }
    if !policy
        .allowed_routers
        .iter()
        .any(|router| router == &proposal.router)
    {
        return Err(ProviderVerificationError::RouterNotAllowed);
    }
    if let Some(spender) = proposal.spender.as_deref() {
        if !policy
            .allowed_spenders
            .iter()
            .any(|allowed| allowed == spender)
        {
            return Err(ProviderVerificationError::SpenderNotAllowed);
        }
    }
    if let Some(approval) = proposal.approval_amount {
        if approval > policy.max_approval {
            return Err(ProviderVerificationError::ApprovalExceeded);
        }
    }

    if proposal.amount_in != leg.amount_in.get() {
        return Err(ProviderVerificationError::AmountInMismatch);
    }
    if proposal.amount_out != leg.expected_amount_out.get()
        || proposal.amount_out != delta.gross_output.amount.get()
    {
        return Err(ProviderVerificationError::AmountOutMismatch);
    }
    // Bind the route/delta assets to the intent, not just the proposal: a
    // caller-trusted route whose leg or delta names a different asset must be
    // rejected even though the provider echoed the intent pair.
    if leg.token_in != intent.token_in
        || leg.token_out != intent.token_out
        || delta.token_in != intent.token_in
        || delta.token_out != intent.token_out
        || delta.gross_output.asset != intent.token_out
    {
        return Err(ProviderVerificationError::TokenMismatch);
    }

    let min_receive = proposal
        .min_receive_amount
        .ok_or(ProviderVerificationError::MinReceiveMissing)?;
    if min_receive < policy.min_receive {
        return Err(ProviderVerificationError::MinReceiveTooLow);
    }
    if proposal.amount_out == 0 || min_receive > proposal.amount_out {
        return Err(ProviderVerificationError::SlippageExceeded);
    }
    let deviation = proposal.amount_out - min_receive;
    if slippage_exceeds(
        deviation,
        proposal.amount_out,
        policy.max_slippage_bps.get(),
    ) {
        return Err(ProviderVerificationError::SlippageExceeded);
    }

    if proposal.value > policy.max_value {
        return Err(ProviderVerificationError::ValueExceeded);
    }

    if proposal.calldata.is_empty() {
        return Err(ProviderVerificationError::CalldataEmpty);
    }
    if proposal.calldata.len() > MAX_CALLDATA_BYTES {
        return Err(ProviderVerificationError::CalldataTooLarge);
    }
    let digest: [u8; 32] = Sha256::digest(&proposal.calldata).into();
    if digest != proposal.calldata_digest {
        return Err(ProviderVerificationError::CalldataDigestMismatch);
    }

    if proposal.observed_at_ms > now_ms {
        return Err(ProviderVerificationError::ProposalFromFuture);
    }
    let age_ms = now_ms
        .checked_sub(proposal.observed_at_ms)
        .ok_or(ProviderVerificationError::ProposalStale)?;
    if age_ms as u64 > policy.max_age_ms {
        return Err(ProviderVerificationError::ProposalStale);
    }

    if assessment.chain != intent.chain
        || assessment.assessed_asset != *assessed_asset_for_intent(intent)
        || assessment.freshness.status != FreshnessStatus::Fresh
    {
        return Err(ProviderVerificationError::AssessmentMismatch);
    }

    Ok(ApprovedProviderPayload {
        chain: proposal.chain.clone(),
        router: proposal.router.clone(),
        spender: proposal.spender.clone(),
        token_in: proposal.token_in.clone(),
        token_out: proposal.token_out.clone(),
        amount_in: proposal.amount_in,
        amount_out: proposal.amount_out,
        min_receive_amount: min_receive,
        value: proposal.value,
        approval_amount: proposal.approval_amount,
        calldata: proposal.calldata.clone(),
        calldata_digest: digest,
    })
}

/// Computes the canonical calldata digest an adapter must commit to.
pub fn calldata_digest(calldata: &[u8]) -> [u8; 32] {
    Sha256::digest(calldata).into()
}

/// Returns `true` when `deviation / amount_out` exceeds `cap_bps`.
///
/// Computed with an exact 256-bit cross-multiplication (`deviation * 10_000 >
/// amount_out * cap`) so the cap cannot be exceeded by a fraction of a basis
/// point, which floor division would hide.
fn slippage_exceeds(deviation: u128, amount_out: u128, cap_bps: u16) -> bool {
    if amount_out == 0 {
        return true;
    }
    cmp_u128_products(deviation, 10_000, amount_out, u128::from(cap_bps)) == Ordering::Greater
}

/// Validates a trusted policy label (address/identifier) structurally.
///
/// Printable non-space ASCII, non-empty, and bounded. A malformed label is
/// rejected by the caller before it reaches the verifier.
pub fn is_valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_basis_point_slippage_overflow_is_rejected() {
        // 10_099 / 1_000_000 = 100.99 bps: floor division would hide the excess.
        assert!(slippage_exceeds(10_099, 1_000_000, 100));
        // Exactly 100 bps is admitted; one atomic unit above is rejected.
        assert!(!slippage_exceeds(10_000, 1_000_000, 100));
        assert!(slippage_exceeds(10_001, 1_000_000, 100));
        // Zero output is always rejected.
        assert!(slippage_exceeds(0, 0, 100));
        assert!(!slippage_exceeds(0, 1_000, 0));
    }

    #[test]
    fn digit_rendering_hides_calldata() {
        let payload = ApprovedProviderPayload {
            chain: ChainId::Base,
            router: "0xrouter".to_string(),
            spender: None,
            token_in: AssetId::new(ChainId::Base, "0xin").expect("asset"),
            token_out: AssetId::new(ChainId::Base, "0xout").expect("asset"),
            amount_in: 1,
            amount_out: 2,
            min_receive_amount: 2,
            value: 0,
            approval_amount: None,
            calldata: vec![0xde, 0xad],
            calldata_digest: [7u8; 32],
        };
        let rendered = format!("{payload:?}");
        assert_eq!(rendered, "ApprovedProviderPayload { .. }");
        assert!(!rendered.contains("0xrouter"));
        assert!(!rendered.contains("222"));
        assert!(!rendered.contains("[7, 7"));
    }
}
