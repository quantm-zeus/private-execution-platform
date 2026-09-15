//! P39 — pure, deterministic pre-sign revalidation gate.
//!
//! This module is the last local check executed immediately before an order is
//! signed. It re-reads the trusted state that P38's bridge already bound to an
//! [`ExecutionPreview`] and proves the pre-sign facts have not regressed:
//! trading remains enabled, the policy approval still binds, the recipient and
//! route are unchanged, wallet/allowance state is fresh and sufficient, tax has
//! not drifted, and the minimum-out floor still holds. Only then does it
//! delegate to the locked P38 bridge and canonical
//! [`domain::ExecutionPreview::validate`] contract.
//!
//! # Purity
//! There is no wall clock, RPC, filesystem, randomness, or any other I/O:
//! every timestamp is an explicit `now_ms` supplied by the caller. Inputs are
//! never mutated. No signing or transfer surface exists here.
//!
//! # Fail-closed
//! [`RevalidationOutcome::Valid`] is returned only when the P38 bridge
//! [`validate_delta_preview_with_assessment`] succeeded and wrapped a
//! [`domain::ValidatedExecutionPreview`]. Every other path returns a redacted
//! [`RevalidationReason`] and never weakens `ExecutionPreview::validate` or
//! `evaluate_tax_safety`.
//!
//! [`validate_delta_preview_with_assessment`]: crate::validate_delta_preview_with_assessment

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use chain_types::{AssetId, ChainId};
use domain::{
    cmp_u128_products, DomainError, RoutePlan, SplitPlan, TaxObservation, TradeIntent,
    ValidatedExecutionPreview, WalletRef,
};
use market_types::{
    evaluate_freshness, AssetAmount, AtomicAmount, Freshness, FreshnessPolicy, FreshnessStatus,
};
use policy::{ApprovedExecution, PolicyLimits};
use serde::{Deserialize, Serialize};
use tax_engine::{evaluate_tax_safety, TaxAssessment, TaxSafetyError};

use crate::{
    validate_delta_preview_with_assessment, validate_split_delta_preview_with_assessment,
    BridgeError, NetDelta,
};

/// Trusted wallet balance snapshot for the trade's input asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBalance {
    pub wallet_ref: WalletRef,
    pub chain: ChainId,
    pub asset: AssetId,
    pub available: AtomicAmount,
    pub freshness: Freshness,
}

/// Trusted ERC-20 / SPL allowance snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceState {
    pub wallet_ref: WalletRef,
    pub chain: ChainId,
    pub asset: AssetId,
    pub spender_ref: String,
    pub amount: AtomicAmount,
    pub freshness: Freshness,
}

/// Whether the selected route requires a spender allowance at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllowanceObservation {
    NotRequired,
    Required(AllowanceState),
}

impl AllowanceObservation {
    /// Returns the allowance state when one is required.
    pub fn state(&self) -> Option<&AllowanceState> {
        match self {
            Self::NotRequired => None,
            Self::Required(state) => Some(state),
        }
    }
}

/// Structural identity of a single route leg, excluding amounts and freshness.
///
/// Amounts are intentionally excluded from this structural binding: the bridge
/// independently binds the realized net delta to the route economics
/// (`route.expected_net_output` for a single route; each branch delta's gross
/// budget and expected output for a split), so revalidation only needs to prove
/// the selected route/branches are the approved ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteLegRef {
    pub venue: String,
    pub pool_ref: String,
    pub token_in: AssetId,
    pub token_out: AssetId,
}

/// Structural identity of the whole selected route.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBinding {
    pub legs: Vec<RouteLegRef>,
}

impl RouteBinding {
    /// Projects a route plan onto its amount-free structural identity.
    pub fn from_route(route: &RoutePlan) -> Self {
        Self {
            legs: route
                .legs
                .iter()
                .map(|leg| RouteLegRef {
                    venue: leg.venue.clone(),
                    pool_ref: leg.pool_ref.clone(),
                    token_in: leg.token_in.clone(),
                    token_out: leg.token_out.clone(),
                })
                .collect(),
        }
    }
}

/// All inputs required by [`revalidate_pre_sign`].
///
/// All trusted facts are passed by reference and are never mutated. The caller
/// supplies an explicit `now_ms`; this module never reads a clock.
pub struct RevalidationInput<'a> {
    pub intent: &'a TradeIntent,
    pub approval: Option<&'a ApprovedExecution>,
    pub policy_limits: &'a PolicyLimits,
    pub allowed_programs: &'a HashSet<String>,
    /// Explicit kill-switch snapshot; never the shared mutable gate.
    pub trading_enabled: bool,
    pub now_ms: i64,
    pub freshness_policy: &'a FreshnessPolicy,
    pub route: &'a RoutePlan,
    pub net_delta: &'a NetDelta,
    /// Assessment that was used to simulate `net_delta`.
    pub basis_assessment: &'a TaxAssessment,
    pub tax_observation: Option<&'a TaxObservation>,
    pub approved_route_binding: &'a RouteBinding,
    /// Minimum acceptable output, denominated in `token_out`.
    pub min_out: &'a AssetAmount,
    pub wallet_balance: &'a WalletBalance,
    pub allowance: &'a AllowanceObservation,
}

/// Payload-free, redacted revalidation failure reason.
///
/// [`Display`](fmt::Display) and [`Debug`](fmt::Debug) contain no amounts,
/// assets, addresses, pool refs, router refs, or endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevalidationReason {
    TradingDisabled,
    ApprovalMissing,
    ApprovalBindingMismatch,
    PolicyExpired,
    RecipientMismatch,
    VenueNotAllowlisted,
    ProgramNotAllowlisted,
    SelectedRouteMismatch,
    StateRegression,
    StaleState,
    ResyncRequired,
    TaxObservationStale,
    TaxChanged,
    TaxCapExceeded,
    TokenNotSellable,
    MissingTaxObservation,
    InsufficientBalance,
    InsufficientAllowance,
    AllowanceSpenderMismatch,
    MissingAllowanceObservation,
    MinOutNotMet,
    AmountPolicyViolation,
    UnsupportedAmountType,
    NetDeltaInconsistent,
    DomainInvalid,
    BridgeInvalid,
}

impl fmt::Display for RevalidationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TradingDisabled => "trading disabled",
            Self::ApprovalMissing => "policy approval missing",
            Self::ApprovalBindingMismatch => "policy approval binding mismatch",
            Self::PolicyExpired => "policy approval expired",
            Self::RecipientMismatch => "recipient or chain mismatch",
            Self::VenueNotAllowlisted => "venue not allowlisted",
            Self::ProgramNotAllowlisted => "program not allowlisted",
            Self::SelectedRouteMismatch => "selected route mismatch",
            Self::StateRegression => "trusted state regression",
            Self::StaleState => "trusted state stale",
            Self::ResyncRequired => "trusted state requires resync",
            Self::TaxObservationStale => "tax observation stale",
            Self::TaxChanged => "tax changed since simulation",
            Self::TaxCapExceeded => "tax cap exceeded",
            Self::TokenNotSellable => "token not sellable",
            Self::MissingTaxObservation => "tax observation missing",
            Self::InsufficientBalance => "insufficient balance",
            Self::InsufficientAllowance => "insufficient allowance",
            Self::AllowanceSpenderMismatch => "allowance spender mismatch",
            Self::MissingAllowanceObservation => "required allowance observation missing",
            Self::MinOutNotMet => "minimum output not met",
            Self::AmountPolicyViolation => "amount policy violation",
            Self::UnsupportedAmountType => "unsupported amount type",
            Self::NetDeltaInconsistent => "net delta inconsistent",
            Self::DomainInvalid => "domain validation failed",
            Self::BridgeInvalid => "bridge validation failed",
        };
        formatter.write_str(text)
    }
}

/// Result of pre-sign revalidation.
///
/// `Valid` can only be produced by the P38 bridge plus canonical domain
/// validation, so holding it proves that locked validation ran.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum RevalidationOutcome {
    Valid(ValidatedExecutionPreview),
    AbortRequote(RevalidationReason),
    AbortFinal(RevalidationReason),
}

/// Redacted `Debug`: `Valid` never prints its inner [`ExecutionPreview`] (which
/// carries assets, amounts, and intent ids); aborts print only the payload-free
/// [`RevalidationReason`].
impl fmt::Debug for RevalidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid(_) => formatter.write_str("Valid"),
            Self::AbortRequote(reason) => {
                formatter.debug_tuple("AbortRequote").field(reason).finish()
            }
            Self::AbortFinal(reason) => formatter.debug_tuple("AbortFinal").field(reason).finish(),
        }
    }
}

/// Revalidates all pre-sign facts and returns a validated execution preview.
///
/// Checks run in a fixed order and fail closed on the first violation. The
/// `Valid` arm is reachable only through
/// [`validate_delta_preview_with_assessment`], which enforces the intent tax
/// caps and delegates to [`domain::ExecutionPreview::validate`].
pub fn revalidate_pre_sign(input: &RevalidationInput<'_>) -> RevalidationOutcome {
    use RevalidationOutcome::{AbortFinal, AbortRequote, Valid};
    use RevalidationReason as Reason;

    // 0. Explicit kill-switch snapshot.
    if !input.trading_enabled {
        return AbortFinal(Reason::TradingDisabled);
    }

    // 1. Approval must be present and bind identity, chain, and idempotency.
    let Some(approval) = input.approval else {
        return AbortFinal(Reason::ApprovalMissing);
    };
    if approval.intent_id() != &input.intent.id
        || approval.wallet_ref() != &input.intent.wallet_ref
        || approval.chain() != &input.intent.chain
        || approval.idempotency_key() != &input.intent.idempotency_key
    {
        return AbortFinal(Reason::ApprovalBindingMismatch);
    }
    if matches!(approval.expires_at_ms(), Some(expires) if expires <= input.now_ms) {
        return AbortFinal(Reason::PolicyExpired);
    }

    // 2. Recipient and chain binding across every present trusted snapshot.
    if input.wallet_balance.wallet_ref != input.intent.wallet_ref
        || input.wallet_balance.chain != input.intent.chain
    {
        return AbortFinal(Reason::RecipientMismatch);
    }
    if let Some(observation) = input.tax_observation {
        if observation.wallet_ref != input.intent.wallet_ref
            || observation.chain != input.intent.chain
        {
            return AbortFinal(Reason::RecipientMismatch);
        }
    }
    if let Some(allowance) = input.allowance.state() {
        if allowance.wallet_ref != input.intent.wallet_ref || allowance.chain != input.intent.chain
        {
            return AbortFinal(Reason::RecipientMismatch);
        }
    }

    // 3. Venue and program allowlists. The venue set is skipped only when empty,
    //    matching policy semantics. Solana program refs are always allowlisted.
    if !input.policy_limits.allowed_venues.is_empty() {
        for leg in &input.route.legs {
            if !input.policy_limits.allowed_venues.contains(&leg.venue) {
                return AbortFinal(Reason::VenueNotAllowlisted);
            }
        }
    }
    for leg in &input.route.legs {
        let is_solana =
            leg.token_in.chain == ChainId::Solana || leg.token_out.chain == ChainId::Solana;
        if is_solana && !input.allowed_programs.contains(&leg.pool_ref) {
            return AbortFinal(Reason::ProgramNotAllowlisted);
        }
    }
    if let Some(observation) = input.tax_observation {
        if observation.chain == ChainId::Solana {
            if !input.allowed_programs.contains(&observation.router_ref) {
                return AbortFinal(Reason::ProgramNotAllowlisted);
            }
        } else if expected_spender_ref(input.approved_route_binding, &input.intent.chain)
            != Some(observation.router_ref.as_str())
        {
            // The EVM router ref is the allowance spender; it must be the
            // approved route's first-leg venue, never an attacker-supplied value.
            return AbortFinal(Reason::AllowanceSpenderMismatch);
        }
    }

    // 4. The selected route must be structurally identical to the approved one.
    if RouteBinding::from_route(input.route) != *input.approved_route_binding {
        return AbortRequote(Reason::SelectedRouteMismatch);
    }

    // 4b. Route state must also be fresh under the caller-supplied policy. The
    //     P38 bridge pins `FreshnessPolicy::default()` internally, so evaluating
    //     it explicitly here honors the caller's policy instead of ignoring it.
    match classify_freshness(input.freshness_policy, &input.route.state, input.now_ms) {
        Some(FreshnessStatus::Fresh) => {}
        Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
        Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
        None => return AbortFinal(Reason::StateRegression),
    }

    // 5. Wallet and (when required) allowance freshness.
    match classify_freshness(
        input.freshness_policy,
        &input.wallet_balance.freshness,
        input.now_ms,
    ) {
        Some(FreshnessStatus::Fresh) => {}
        Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
        Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
        None => return AbortFinal(Reason::StateRegression),
    }
    if let Some(allowance) = input.allowance.state() {
        match classify_freshness(input.freshness_policy, &allowance.freshness, input.now_ms) {
            Some(FreshnessStatus::Fresh) => {}
            Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
            Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
            None => return AbortFinal(Reason::StateRegression),
        }
    }

    // 6. A tax observation is mandatory; re-run the locked tax safety kernel and
    //    require the fresh assessment to reproduce the simulated basis exactly.
    let Some(observation) = input.tax_observation else {
        return AbortFinal(Reason::MissingTaxObservation);
    };
    let fresh_assessment = match evaluate_tax_safety(
        input.intent,
        Some(observation),
        input.now_ms,
        input.freshness_policy,
    ) {
        Ok(assessment) => assessment,
        Err(error) => return map_tax_error(error),
    };
    if fresh_assessment.buy_tax != input.basis_assessment.buy_tax
        || fresh_assessment.sell_tax != input.basis_assessment.sell_tax
    {
        return AbortRequote(Reason::TaxChanged);
    }

    // 7. Wallet balance must cover the full simulated wallet debit.
    if input.wallet_balance.asset != input.net_delta.net_input.asset {
        return AbortFinal(Reason::StateRegression);
    }
    if input.wallet_balance.available < input.net_delta.net_input.amount {
        return AbortRequote(Reason::InsufficientBalance);
    }

    // 8. Allowance, when the route requires one. The spender must be the
    //    approved route's expected spender on every chain.
    if let Some(allowance) = input.allowance.state() {
        if expected_spender_ref(input.approved_route_binding, &input.intent.chain)
            != Some(allowance.spender_ref.as_str())
        {
            return AbortFinal(Reason::AllowanceSpenderMismatch);
        }
        if allowance.asset != input.net_delta.net_input.asset {
            return AbortFinal(Reason::StateRegression);
        }
        if allowance.amount < input.net_delta.net_input.amount {
            return AbortRequote(Reason::InsufficientAllowance);
        }
    }

    // 9. Minimum output floor. The asset binding is decisive; the amount and the
    //    intent slippage floor are requoteable. Floor arithmetic uses exact
    //    256-bit product comparison, never a raw multiply.
    if input.min_out.asset != input.intent.token_out {
        return AbortFinal(Reason::MinOutNotMet);
    }
    if input.net_delta.net_output.amount < input.min_out.amount {
        return AbortRequote(Reason::MinOutNotMet);
    }
    let slippage_floor_bps =
        10_000u128.saturating_sub(u128::from(input.intent.risk.max_slippage.get()));
    let expected_output = input.route.expected_net_output.amount.get();
    if cmp_u128_products(
        input.min_out.amount.get(),
        10_000,
        expected_output,
        slippage_floor_bps,
    ) == Ordering::Less
    {
        return AbortFinal(Reason::AmountPolicyViolation);
    }

    // 10. Delegate to the P38 bridge, which enforces the intent tax caps and the
    //     locked canonical domain validation. `Valid` is only produced here.
    match validate_delta_preview_with_assessment(
        input.intent,
        input.route,
        input.net_delta,
        &fresh_assessment,
        input.now_ms,
    ) {
        Ok(preview) => Valid(preview),
        Err(error) => map_bridge_error(error),
    }
}

/// Structural identity of one split branch, excluding freshness.
///
/// The gross branch budget is included because it is part of the approved
/// execution binding; the branch route is amount-free, mirroring [`RouteLegRef`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitLegRef {
    pub amount_in: AtomicAmount,
    pub legs: Vec<RouteLegRef>,
}

/// Structural identity of the whole approved split.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRouteBinding {
    pub branches: Vec<SplitLegRef>,
}

impl SplitRouteBinding {
    /// Projects a split plan onto its amount-explicit structural identity.
    pub fn from_split(split: &SplitPlan) -> Self {
        Self {
            branches: split
                .legs
                .iter()
                .map(|branch| SplitLegRef {
                    amount_in: branch.amount_in,
                    legs: branch
                        .route
                        .legs
                        .iter()
                        .map(|leg| RouteLegRef {
                            venue: leg.venue.clone(),
                            pool_ref: leg.pool_ref.clone(),
                            token_in: leg.token_in.clone(),
                            token_out: leg.token_out.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// All inputs required by [`revalidate_split_pre_sign`].
///
/// Every trusted fact is passed by reference and never mutated; the caller
/// supplies the explicit `now_ms` and this module never reads a clock.
pub struct SplitRevalidationInput<'a> {
    pub intent: &'a TradeIntent,
    pub approval: Option<&'a ApprovedExecution>,
    pub policy_limits: &'a PolicyLimits,
    pub allowed_programs: &'a HashSet<String>,
    /// Explicit kill-switch snapshot; never the shared mutable gate.
    pub trading_enabled: bool,
    pub now_ms: i64,
    pub freshness_policy: &'a FreshnessPolicy,
    pub split: &'a SplitPlan,
    /// Per-branch exact deltas; aggregated inside. Length == `split.legs.len()`.
    pub branch_deltas: &'a [NetDelta],
    /// Assessment that was used to simulate the branch deltas.
    pub basis_assessment: &'a TaxAssessment,
    pub tax_observation: Option<&'a TaxObservation>,
    pub approved_split_binding: &'a SplitRouteBinding,
    /// Minimum acceptable aggregate output, in `token_out`.
    pub min_out: &'a AssetAmount,
    pub wallet_balance: &'a WalletBalance,
    /// One observation per required spender; `NotRequired` only when no branch
    /// needs an allowance.
    pub allowances: &'a [AllowanceObservation],
}

/// Revalidates all pre-sign facts for an aggregate split and returns a validated
/// aggregate execution preview.
///
/// The check order mirrors [`revalidate_pre_sign`] and fails closed on the first
/// violation. `Valid` is reachable only through
/// [`validate_split_delta_preview_with_assessment`], which applies the intent
/// tax caps to every branch and delegates to the locked split validator.
pub fn revalidate_split_pre_sign(input: &SplitRevalidationInput<'_>) -> RevalidationOutcome {
    use RevalidationOutcome::{AbortFinal, AbortRequote, Valid};
    use RevalidationReason as Reason;

    // 0. Explicit kill-switch snapshot.
    if !input.trading_enabled {
        return AbortFinal(Reason::TradingDisabled);
    }

    // 1. Approval must bind identity, chain, and idempotency.
    let Some(approval) = input.approval else {
        return AbortFinal(Reason::ApprovalMissing);
    };
    if approval.intent_id() != &input.intent.id
        || approval.wallet_ref() != &input.intent.wallet_ref
        || approval.chain() != &input.intent.chain
        || approval.idempotency_key() != &input.intent.idempotency_key
    {
        return AbortFinal(Reason::ApprovalBindingMismatch);
    }
    if matches!(approval.expires_at_ms(), Some(expires) if expires <= input.now_ms) {
        return AbortFinal(Reason::PolicyExpired);
    }

    // 2. Recipient / chain binding across every present trusted snapshot.
    if input.wallet_balance.wallet_ref != input.intent.wallet_ref
        || input.wallet_balance.chain != input.intent.chain
    {
        return AbortFinal(Reason::RecipientMismatch);
    }
    if let Some(observation) = input.tax_observation {
        if observation.wallet_ref != input.intent.wallet_ref
            || observation.chain != input.intent.chain
        {
            return AbortFinal(Reason::RecipientMismatch);
        }
    }
    for observation in input.allowances {
        let Some(allowance) = observation.state() else {
            continue;
        };
        if allowance.wallet_ref != input.intent.wallet_ref || allowance.chain != input.intent.chain
        {
            return AbortFinal(Reason::RecipientMismatch);
        }
    }

    // 3. Venue / program allowlists over every branch route leg.
    if !input.policy_limits.allowed_venues.is_empty() {
        for branch in &input.split.legs {
            for leg in &branch.route.legs {
                if !input.policy_limits.allowed_venues.contains(&leg.venue) {
                    return AbortFinal(Reason::VenueNotAllowlisted);
                }
            }
        }
    }
    for branch in &input.split.legs {
        for leg in &branch.route.legs {
            let is_solana =
                leg.token_in.chain == ChainId::Solana || leg.token_out.chain == ChainId::Solana;
            if is_solana && !input.allowed_programs.contains(&leg.pool_ref) {
                return AbortFinal(Reason::ProgramNotAllowlisted);
            }
        }
    }

    // Required spenders derive ONLY from the approved binding, never from the
    // untrusted observation slice.
    let Some(required) = required_split_spenders(input.approved_split_binding, &input.intent.chain)
    else {
        return AbortFinal(Reason::AmountPolicyViolation);
    };

    if let Some(observation) = input.tax_observation {
        if observation.chain == ChainId::Solana {
            if !input.allowed_programs.contains(&observation.router_ref) {
                return AbortFinal(Reason::ProgramNotAllowlisted);
            }
        } else if !required
            .iter()
            .any(|(spender, _)| *spender == observation.router_ref)
        {
            return AbortFinal(Reason::AllowanceSpenderMismatch);
        }
    }

    // 3b. Exactly one required allowance observation per distinct spender.
    if required.is_empty() {
        if !input.allowances.is_empty() {
            return AbortFinal(Reason::AllowanceSpenderMismatch);
        }
    } else {
        let mut seen: Vec<&str> = Vec::new();
        for observation in input.allowances {
            match observation {
                AllowanceObservation::NotRequired => {
                    return AbortFinal(Reason::MissingAllowanceObservation);
                }
                AllowanceObservation::Required(state) => {
                    if !required
                        .iter()
                        .any(|(spender, _)| *spender == state.spender_ref)
                    {
                        return AbortFinal(Reason::AllowanceSpenderMismatch);
                    }
                    if seen.contains(&state.spender_ref.as_str()) {
                        return AbortFinal(Reason::AllowanceSpenderMismatch);
                    }
                    seen.push(state.spender_ref.as_str());
                }
            }
        }
        if required
            .iter()
            .any(|(spender, _)| !seen.contains(&spender.as_str()))
        {
            return AbortFinal(Reason::MissingAllowanceObservation);
        }
    }

    // 4. The selected split must be structurally identical to the approved one.
    if SplitRouteBinding::from_split(input.split) != *input.approved_split_binding {
        return AbortRequote(Reason::SelectedRouteMismatch);
    }

    // 4b. Aggregate split state must be fresh under the caller policy.
    match classify_freshness(input.freshness_policy, &input.split.state, input.now_ms) {
        Some(FreshnessStatus::Fresh) => {}
        Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
        Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
        None => return AbortFinal(Reason::StateRegression),
    }

    // 5. Wallet and every allowance must be fresh.
    match classify_freshness(
        input.freshness_policy,
        &input.wallet_balance.freshness,
        input.now_ms,
    ) {
        Some(FreshnessStatus::Fresh) => {}
        Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
        Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
        None => return AbortFinal(Reason::StateRegression),
    }
    for observation in input.allowances {
        if let Some(allowance) = observation.state() {
            match classify_freshness(input.freshness_policy, &allowance.freshness, input.now_ms) {
                Some(FreshnessStatus::Fresh) => {}
                Some(FreshnessStatus::Stale) => return AbortRequote(Reason::StaleState),
                Some(FreshnessStatus::ResyncRequired) => return AbortFinal(Reason::ResyncRequired),
                None => return AbortFinal(Reason::StateRegression),
            }
        }
    }

    // 6. A tax observation is mandatory; the fresh assessment must reproduce the
    //    simulated basis exactly.
    let Some(observation) = input.tax_observation else {
        return AbortFinal(Reason::MissingTaxObservation);
    };
    let fresh_assessment = match evaluate_tax_safety(
        input.intent,
        Some(observation),
        input.now_ms,
        input.freshness_policy,
    ) {
        Ok(assessment) => assessment,
        Err(error) => return map_tax_error(error),
    };
    if fresh_assessment.buy_tax != input.basis_assessment.buy_tax
        || fresh_assessment.sell_tax != input.basis_assessment.sell_tax
    {
        return AbortRequote(Reason::TaxChanged);
    }

    // 7. Aggregate the exact branch deltas; the wallet must cover the aggregate
    //    gross debit in `token_in`.
    let aggregate = match NetDelta::aggregate(input.branch_deltas) {
        Ok(delta) => delta,
        Err(_) => return AbortFinal(Reason::NetDeltaInconsistent),
    };
    if input.wallet_balance.asset != aggregate.net_input.asset {
        return AbortFinal(Reason::StateRegression);
    }
    if input.wallet_balance.available < aggregate.net_input.amount {
        return AbortRequote(Reason::InsufficientBalance);
    }

    // 8. Every required spender's allowance must cover the gross input routed
    //    through that spender, not the whole aggregate.
    for (spender, attributed) in &required {
        let state = input
            .allowances
            .iter()
            .filter_map(AllowanceObservation::state)
            .find(|state| state.spender_ref == *spender);
        let Some(state) = state else {
            return AbortFinal(Reason::MissingAllowanceObservation);
        };
        if state.asset != aggregate.net_input.asset {
            return AbortFinal(Reason::StateRegression);
        }
        if state.amount < AtomicAmount::new(*attributed) {
            return AbortRequote(Reason::InsufficientAllowance);
        }
    }

    // 9. Aggregate minimum-output floor and slippage floor, exactly as the
    //    single-route gate.
    if input.min_out.asset != input.intent.token_out {
        return AbortFinal(Reason::MinOutNotMet);
    }
    if aggregate.net_output.amount < input.min_out.amount {
        return AbortRequote(Reason::MinOutNotMet);
    }
    let slippage_floor_bps =
        10_000u128.saturating_sub(u128::from(input.intent.risk.max_slippage.get()));
    let expected_output = input.split.expected_net_output.amount.get();
    if cmp_u128_products(
        input.min_out.amount.get(),
        10_000,
        expected_output,
        slippage_floor_bps,
    ) == Ordering::Less
    {
        return AbortFinal(Reason::AmountPolicyViolation);
    }

    // 10. Delegate to the aggregate bridge, which enforces the intent tax caps on
    //     every branch and the locked split validator. `Valid` is only here.
    match validate_split_delta_preview_with_assessment(
        input.intent,
        input.split,
        input.branch_deltas,
        &fresh_assessment,
        input.now_ms,
    ) {
        Ok(preview) => Valid(preview),
        Err(error) => map_bridge_error(error),
    }
}

/// Distinct allowance spenders required by an approved split binding, with the
/// summed gross branch input attributed to each (deterministic branch order).
/// `None` means the attribution sum overflowed `u128`.
fn required_split_spenders(
    binding: &SplitRouteBinding,
    chain: &ChainId,
) -> Option<Vec<(String, u128)>> {
    let mut required: Vec<(String, u128)> = Vec::new();
    for branch in &binding.branches {
        let first = branch.legs.first()?;
        let spender = if matches!(chain, ChainId::Solana) {
            first.pool_ref.clone()
        } else {
            first.venue.clone()
        };
        match required
            .iter_mut()
            .find(|(existing, _)| *existing == spender)
        {
            Some((_, total)) => {
                *total = total.checked_add(branch.amount_in.get())?;
            }
            None => required.push((spender, branch.amount_in.get())),
        }
    }
    Some(required)
}

/// The approved route's expected spender/router ref.
///
/// Solana routes delegate to the FIRST leg's program (`pool_ref`) — the program
/// that pulls `token_in`; every other chain uses the FIRST leg's venue (the
/// router contract). Deriving this from the approved route binding (rather than
/// from the untrusted tax observation) is what binds the allowance spender and
/// the EVM router ref to the route that policy actually approved.
fn expected_spender_ref<'a>(
    approved_route_binding: &'a RouteBinding,
    chain: &ChainId,
) -> Option<&'a str> {
    let first = approved_route_binding.legs.first()?;
    if matches!(chain, ChainId::Solana) {
        Some(first.pool_ref.as_str())
    } else {
        Some(first.venue.as_str())
    }
}

/// Classifies explicit freshness metadata; `None` means it could not be evaluated.
///
/// A zero sequence means no valid data exists yet, so it fails closed as
/// `ResyncRequired` before the timestamp is even considered.
fn classify_freshness(
    policy: &FreshnessPolicy,
    freshness: &Freshness,
    now_ms: i64,
) -> Option<FreshnessStatus> {
    if freshness.sequence.is_zero() {
        return Some(FreshnessStatus::ResyncRequired);
    }
    evaluate_freshness(
        policy,
        freshness.observed_at_ms,
        now_ms,
        freshness.sequence,
        false,
    )
    .ok()
    .map(|meta| meta.status)
}

/// Maps a locked tax-safety error to a redacted, conservatively-classified outcome.
fn map_tax_error(error: TaxSafetyError) -> RevalidationOutcome {
    use RevalidationOutcome::{AbortFinal, AbortRequote};
    use RevalidationReason as Reason;
    match error {
        TaxSafetyError::MissingObservation => AbortFinal(Reason::MissingTaxObservation),
        TaxSafetyError::StaleObservation | TaxSafetyError::FreshnessEvaluationFailed => {
            AbortRequote(Reason::TaxObservationStale)
        }
        TaxSafetyError::ResyncRequired => AbortFinal(Reason::ResyncRequired),
        TaxSafetyError::TokenNotSellable => AbortFinal(Reason::TokenNotSellable),
        TaxSafetyError::BuyTaxExceedsCap | TaxSafetyError::SellTaxExceedsCap => {
            AbortFinal(Reason::TaxCapExceeded)
        }
        TaxSafetyError::InvalidTradeIntent(_)
        | TaxSafetyError::InvalidTaxObservation(_)
        | TaxSafetyError::ChainMismatch
        | TaxSafetyError::AssessedAssetMismatch
        | TaxSafetyError::BuySimulationFailed
        | TaxSafetyError::SellSimulationFailed
        | TaxSafetyError::ZeroGrossOutput
        | TaxSafetyError::ZeroNetOutput
        | TaxSafetyError::ZeroGrossInput
        | TaxSafetyError::ZeroNetInput => AbortFinal(Reason::DomainInvalid),
    }
}

/// Maps a P38 bridge error to a redacted, conservatively-classified outcome.
///
/// Freshness, limit-price, and net-economics failures are requoteable; asset,
/// chain, direction, cap, and not-sellable failures are final; a structurally
/// inconsistent delta is always final.
fn map_bridge_error(error: BridgeError) -> RevalidationOutcome {
    use RevalidationOutcome::{AbortFinal, AbortRequote};
    use RevalidationReason as Reason;
    match error {
        BridgeError::NetDeltaInconsistent(_) => AbortFinal(Reason::NetDeltaInconsistent),
        BridgeError::FreshnessUnavailable => AbortRequote(Reason::StaleState),
        BridgeError::TaxCapExceeded => AbortFinal(Reason::TaxCapExceeded),
        BridgeError::Domain(domain_error) => match domain_error {
            DomainError::StaleMarketState => AbortRequote(Reason::StaleState),
            DomainError::ResyncRequired => AbortFinal(Reason::ResyncRequired),
            DomainError::LimitPriceViolated => AbortRequote(Reason::MinOutNotMet),
            DomainError::InconsistentNetEconomics(_) => AbortRequote(Reason::AmountPolicyViolation),
            DomainError::UnsupportedAmountType => AbortFinal(Reason::UnsupportedAmountType),
            _ => AbortFinal(Reason::DomainInvalid),
        },
        BridgeError::AssessedAssetMismatch
        | BridgeError::AssessmentDeltaMismatch
        | BridgeError::ChainMismatch
        | BridgeError::InputAssetMismatch
        | BridgeError::OutputAssetMismatch
        | BridgeError::DirectionMismatch => AbortFinal(Reason::DomainInvalid),
        BridgeError::Cpmm(_) | BridgeError::Clmm(_) | BridgeError::Bin(_) | BridgeError::Tax(_) => {
            AbortFinal(Reason::BridgeInvalid)
        }
    }
}
