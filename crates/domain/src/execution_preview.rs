//! Deterministic execution preview contracts and validation.
//!
//! Phase-3 execution-preview seam binding `TradeIntent` to `RoutePlan`,
//! market-state freshness, and exact simulated net balance deltas.

use chain_types::{AssetId, ChainId};
use market_types::{
    evaluate_freshness, AssetAmount, AtomicAmount, FreshnessPolicy, FreshnessStatus, PriceRatio,
};
use serde::{Deserialize, Serialize};

use crate::{AmountType, DomainError, IntentId, LimitPrice, RoutePlan, TradeIntent, TradeSide};

/// Exact 256-bit multiplication of two `u128` values: `a * b -> (hi_128, lo_128)`.
/// Free of floating point, wall clock, or external dependencies.
#[inline]
pub const fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64 as u128;
    let a_hi = a >> 64;
    let b_lo = b as u64 as u128;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let p0_hi = p0 >> 64;
    let mid1 = p1 + p0_hi;
    let (mid, carry) = mid1.overflowing_add(p2);

    let lo = (p0 as u64 as u128) | ((mid as u64 as u128) << 64);
    let carry_term = if carry { 1u128 << 64 } else { 0 };
    let hi = p3 + (mid >> 64) + carry_term;
    (hi, lo)
}

/// Exact comparison of `a * b` vs `c * d` for four `u128` values using 256-bit arithmetic.
#[inline]
pub fn cmp_u128_products(a: u128, b: u128, c: u128, d: u128) -> std::cmp::Ordering {
    let (hi1, lo1) = mul_u128_wide(a, b);
    let (hi2, lo2) = mul_u128_wide(c, d);
    hi1.cmp(&hi2).then_with(|| lo1.cmp(&lo2))
}

/// Explicit cost components associated with an execution simulation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCostComponents {
    pub gas_cost: Option<AssetAmount>,
    pub dex_fee: Option<AssetAmount>,
    pub provider_fee: Option<AssetAmount>,
    pub tax_cost: Option<AssetAmount>,
}

impl ExecutionCostComponents {
    /// Validates internal consistency of cost components against the execution chain and pair assets.
    pub fn validate(
        &self,
        chain: &ChainId,
        token_in: &AssetId,
        token_out: &AssetId,
    ) -> Result<(), DomainError> {
        if let Some(gas) = &self.gas_cost {
            gas.validate_nonzero()
                .map_err(|_| DomainError::ZeroCostComponent)?;
            if gas.asset.chain != *chain {
                return Err(DomainError::ChainMismatch);
            }
        }
        if let Some(dex) = &self.dex_fee {
            dex.validate_nonzero()
                .map_err(|_| DomainError::ZeroCostComponent)?;
            if dex.asset.chain != *chain {
                return Err(DomainError::ChainMismatch);
            }
            if dex.asset != *token_in && dex.asset != *token_out {
                return Err(DomainError::InconsistentNetEconomics(
                    "dex fee must be denominated in token_in or token_out",
                ));
            }
        }
        if let Some(provider) = &self.provider_fee {
            provider
                .validate_nonzero()
                .map_err(|_| DomainError::ZeroCostComponent)?;
            if provider.asset.chain != *chain {
                return Err(DomainError::ChainMismatch);
            }
            if provider.asset != *token_in && provider.asset != *token_out {
                return Err(DomainError::InconsistentNetEconomics(
                    "provider fee must be denominated in token_in or token_out",
                ));
            }
        }
        if let Some(tax) = &self.tax_cost {
            tax.validate_nonzero()
                .map_err(|_| DomainError::ZeroCostComponent)?;
            if tax.asset.chain != *chain {
                return Err(DomainError::ChainMismatch);
            }
            if tax.asset != *token_in && tax.asset != *token_out {
                return Err(DomainError::InconsistentNetEconomics(
                    "tax cost must be denominated in token_in or token_out",
                ));
            }
        }
        Ok(())
    }

    /// Sums all cost components denominated in `asset`.
    pub fn sum_for_asset(&self, asset: &AssetId) -> Result<AtomicAmount, DomainError> {
        let mut total: u128 = 0;
        for cost in [
            &self.gas_cost,
            &self.dex_fee,
            &self.provider_fee,
            &self.tax_cost,
        ]
        .into_iter()
        .flatten()
        {
            if cost.asset == *asset {
                total = total.checked_add(cost.amount.get()).ok_or(
                    DomainError::InconsistentNetEconomics("cost component sum overflowed u128"),
                )?;
            }
        }
        Ok(AtomicAmount::new(total))
    }
}

/// Deterministic, serialization-safe execution-preview model binding a TradeIntent
/// to a RoutePlan, local market-state freshness, and exact simulated net balance deltas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPreview {
    pub intent_id: IntentId,
    pub chain: ChainId,
    pub token_in: AssetId,
    pub token_out: AssetId,
    pub side: TradeSide,
    pub simulated_net_input: AssetAmount,
    pub simulated_net_output: AssetAmount,
    pub gross_output: AssetAmount,
    pub cost_components: ExecutionCostComponents,
    pub local_state_freshness: FreshnessStatus,
}

impl ExecutionPreview {
    /// Computes the exact simulated executable net price ratio for this preview.
    ///
    /// BUY: net_input / net_output (quote units paid per base unit bought).
    /// SELL: net_output / net_input (quote units received per base unit sold).
    pub fn executable_net_price(&self) -> Result<PriceRatio, DomainError> {
        match self.side {
            TradeSide::Buy => PriceRatio::new(
                self.simulated_net_input.amount.get(),
                self.simulated_net_output.amount.get(),
            )
            .map_err(|_| {
                DomainError::InvalidNetPriceDecision(
                    "simulated net amounts cannot form a valid buy price ratio",
                )
            }),
            TradeSide::Sell => PriceRatio::new(
                self.simulated_net_output.amount.get(),
                self.simulated_net_input.amount.get(),
            )
            .map_err(|_| {
                DomainError::InvalidNetPriceDecision(
                    "simulated net amounts cannot form a valid sell price ratio",
                )
            }),
        }
    }

    /// Computes the gross quote price ratio (informational only; never used for execution limits).
    pub fn gross_quote_price(&self) -> Result<PriceRatio, DomainError> {
        match self.side {
            TradeSide::Buy => PriceRatio::new(
                self.simulated_net_input.amount.get(),
                self.gross_output.amount.get(),
            )
            .map_err(|_| {
                DomainError::InvalidNetPriceDecision(
                    "gross quote amounts cannot form a valid buy price ratio",
                )
            }),
            TradeSide::Sell => PriceRatio::new(
                self.gross_output.amount.get(),
                self.simulated_net_input.amount.get(),
            )
            .map_err(|_| {
                DomainError::InvalidNetPriceDecision(
                    "gross quote amounts cannot form a valid sell price ratio",
                )
            }),
        }
    }

    /// Checks whether the exact simulated net economics satisfy the user's limit price constraint.
    ///
    /// BUY: net_input / net_output <= limit_numerator / limit_denominator
    ///      <=> net_input * limit_denominator <= limit_numerator * net_output
    /// SELL: net_output / net_input >= limit_numerator / limit_denominator
    ///      <=> net_output * limit_denominator >= limit_numerator * net_input
    pub fn satisfies_limit_price(&self, limit: &LimitPrice) -> Result<bool, DomainError> {
        let expected_assets = match self.side {
            TradeSide::Buy => (&self.token_in, &self.token_out),
            TradeSide::Sell => (&self.token_out, &self.token_in),
        };
        if limit.numerator_asset != *expected_assets.0
            || limit.denominator_asset != *expected_assets.1
        {
            return Err(DomainError::LimitPriceAssetMismatch);
        }

        let net_in = self.simulated_net_input.amount.get();
        let net_out = self.simulated_net_output.amount.get();
        let limit_num = limit.ratio.numerator_atomic();
        let limit_den = limit.ratio.denominator_atomic();

        match self.side {
            TradeSide::Buy => {
                // net_in / net_out <= limit_num / limit_den
                // lhs = net_in * limit_den; rhs = limit_num * net_out
                let ord = cmp_u128_products(net_in, limit_den, limit_num, net_out);
                Ok(ord.is_le())
            }
            TradeSide::Sell => {
                // net_out / net_in >= limit_num / limit_den
                // lhs = net_out * limit_den; rhs = limit_num * net_in
                let ord = cmp_u128_products(net_out, limit_den, limit_num, net_in);
                Ok(ord.is_ge())
            }
        }
    }

    /// Validates the internal consistency of the preview fields without external intent/route bindings.
    pub fn validate_internal(&self) -> Result<(), DomainError> {
        self.intent_id.validate()?;
        self.chain
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_in
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_out
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;

        if self.token_in == self.token_out {
            return Err(DomainError::SameAssetPair);
        }
        if self.token_in.chain != self.chain || self.token_out.chain != self.chain {
            return Err(DomainError::ChainMismatch);
        }

        if self.simulated_net_input.asset != self.token_in {
            return Err(DomainError::InputAssetMismatch);
        }
        if self.simulated_net_output.asset != self.token_out {
            return Err(DomainError::OutputAssetMismatch);
        }
        if self.gross_output.asset != self.token_out {
            return Err(DomainError::OutputAssetMismatch);
        }

        if self.simulated_net_input.amount.is_zero() || self.simulated_net_output.amount.is_zero() {
            return Err(DomainError::ZeroSimulatedDelta);
        }
        if self.gross_output.amount.is_zero() {
            return Err(DomainError::ZeroSimulatedDelta);
        }

        // Exact simulated net output cannot exceed gross output quote
        if self.simulated_net_output.amount.get() > self.gross_output.amount.get() {
            return Err(DomainError::InconsistentNetEconomics(
                "simulated net output cannot exceed gross output quote",
            ));
        }

        self.cost_components
            .validate(&self.chain, &self.token_in, &self.token_out)?;

        // Output-denominated costs must not exceed gross output, and simulated net output
        // plus output costs must not exceed gross output quote.
        let output_costs = self.cost_components.sum_for_asset(&self.token_out)?;
        if output_costs.get() > self.gross_output.amount.get() {
            return Err(DomainError::InconsistentNetEconomics(
                "output-denominated costs exceed gross output quote",
            ));
        }
        let total_accounted_output = self
            .simulated_net_output
            .amount
            .get()
            .checked_add(output_costs.get())
            .ok_or(DomainError::InconsistentNetEconomics(
                "net output and output costs sum overflowed u128",
            ))?;
        if total_accounted_output > self.gross_output.amount.get() {
            return Err(DomainError::InconsistentNetEconomics(
                "sum of simulated net output and output costs exceeds gross quote",
            ));
        }

        Ok(())
    }

    /// Fully validates the execution preview against an existing `TradeIntent` and `RoutePlan`,
    /// enforcing strict fail-closed semantics.
    pub fn validate(
        &self,
        intent: &TradeIntent,
        route: &RoutePlan,
        now_ms: i64,
    ) -> Result<ValidatedExecutionPreview, DomainError> {
        // 1. Intent and route internal validation
        intent.validate(now_ms)?;
        route.validate()?;

        // 2. Preview internal structural and economic validation
        self.validate_internal()?;

        // 3. Exact binding to intent
        if self.intent_id != intent.id {
            return Err(DomainError::IntentIdMismatch);
        }
        if self.chain != intent.chain {
            return Err(DomainError::ChainMismatch);
        }
        if self.token_in != intent.token_in {
            return Err(DomainError::InputAssetMismatch);
        }
        if self.token_out != intent.token_out {
            return Err(DomainError::OutputAssetMismatch);
        }
        if self.side != intent.side {
            return Err(DomainError::TradeSideMismatch);
        }

        // 4. Exact binding to route
        let first_leg = route.legs.first().ok_or(DomainError::EmptyRoute)?;
        let last_leg = route.legs.last().ok_or(DomainError::EmptyRoute)?;
        if first_leg.token_in != self.token_in {
            return Err(DomainError::RouteTokenMismatch);
        }
        if last_leg.token_out != self.token_out {
            return Err(DomainError::RouteOutputAssetMismatch);
        }
        if route.expected_net_output.asset != self.token_out {
            return Err(DomainError::RouteOutputAssetMismatch);
        }
        for leg in &route.legs {
            if leg.token_in.chain != self.chain || leg.token_out.chain != self.chain {
                return Err(DomainError::ChainMismatch);
            }
        }

        // 5. Freshness evaluation: local state must be Fresh
        match self.local_state_freshness {
            FreshnessStatus::Fresh => {}
            FreshnessStatus::Stale => return Err(DomainError::StaleMarketState),
            FreshnessStatus::ResyncRequired => return Err(DomainError::ResyncRequired),
        }

        // 6. Freshness evaluation: route state must be Fresh at now_ms
        if route.state.observed_at_ms <= 0 {
            return Err(DomainError::StaleMarketState);
        }
        if route.state.sequence.is_zero() {
            return Err(DomainError::ResyncRequired);
        }
        let route_freshness = evaluate_freshness(
            &FreshnessPolicy::default(),
            route.state.observed_at_ms,
            now_ms,
            route.state.sequence,
            false,
        )
        .map_err(|_| DomainError::StaleMarketState)?;
        match route_freshness.status {
            FreshnessStatus::Fresh => {}
            FreshnessStatus::Stale => return Err(DomainError::StaleMarketState),
            FreshnessStatus::ResyncRequired => return Err(DomainError::ResyncRequired),
        }

        // 7. Risk constraints: max_total_cost limit
        if let Some(max_cost) = &intent.risk.max_total_cost {
            if self.simulated_net_input.asset != max_cost.asset {
                return Err(DomainError::MaxTotalCostAssetMismatch);
            }
            if self.simulated_net_input.amount > max_cost.amount {
                return Err(DomainError::InconsistentNetEconomics(
                    "simulated net input exceeds intent max_total_cost",
                ));
            }
        }

        // 8. Fill policy: all-or-nothing check for InputAssetAtomic
        if !intent.allow_partial_fill
            && intent.amount_type == AmountType::InputAssetAtomic
            && self.simulated_net_input.amount.get() < intent.amount.get()
        {
            return Err(DomainError::InconsistentNetEconomics(
                "all-or-nothing intent cannot accept partial simulated input",
            ));
        }

        // 9. Exact simulated net limit check (never using gross quote)
        if let Some(limit) = &intent.limit_price {
            if !self.satisfies_limit_price(limit)? {
                return Err(DomainError::LimitPriceViolated);
            }
        }

        Ok(ValidatedExecutionPreview(self.clone()))
    }
}

/// An execution preview that has passed deterministic domain validation.
///
/// Encapsulated to prevent unauthorized construction or mutation of preview execution facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ValidatedExecutionPreview(ExecutionPreview);

impl ValidatedExecutionPreview {
    pub fn preview(&self) -> &ExecutionPreview {
        &self.0
    }

    pub fn into_inner(self) -> ExecutionPreview {
        self.0
    }

    pub fn executable_net_price(&self) -> Result<PriceRatio, DomainError> {
        self.0.executable_net_price()
    }
}

impl std::ops::Deref for ValidatedExecutionPreview {
    type Target = ExecutionPreview;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Functional entry point validating an execution preview against intent and route inputs.
pub fn validate_execution_preview(
    intent: &TradeIntent,
    route: &RoutePlan,
    preview: &ExecutionPreview,
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, DomainError> {
    preview.validate(intent, route, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IdempotencyKey, OrderType, RiskConstraints, RouteLeg, TradeSource, UserId, WalletRef,
    };
    use market_types::{Bps, Freshness, Sequence};

    fn sample_asset(chain: ChainId, address: &str) -> AssetId {
        AssetId::new(chain, address).unwrap()
    }

    fn sample_risk() -> RiskConstraints {
        RiskConstraints {
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            max_total_cost: None,
        }
    }

    fn sample_intent(
        side: TradeSide,
        order_type: OrderType,
        limit_price: Option<LimitPrice>,
    ) -> TradeIntent {
        let chain = ChainId::Base;
        let token_in = sample_asset(chain.clone(), "0xusdc");
        let token_out = sample_asset(chain.clone(), "0xtoken");
        TradeIntent {
            id: IntentId::new("intent-p24-1").unwrap(),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").unwrap(),
            wallet_ref: WalletRef::new("wallet-1").unwrap(),
            chain,
            token_in,
            token_out,
            side,
            amount_type: AmountType::InputAssetAtomic,
            amount: AtomicAmount::new(1_000),
            order_type,
            limit_price,
            risk: sample_risk(),
            allow_partial_fill: true,
            expiry_ms: None,
            nonce: 1,
            idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
        }
    }

    fn sample_route(token_in: &AssetId, token_out: &AssetId, observed_at_ms: i64) -> RoutePlan {
        RoutePlan {
            legs: vec![RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "0xpool1".to_string(),
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(250),
            }],
            expected_net_output: AssetAmount {
                asset: token_out.clone(),
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms,
                chain_height: 100,
                sequence: Sequence(1),
            },
        }
    }

    fn sample_preview(
        intent: &TradeIntent,
        net_in: u128,
        net_out: u128,
        gross_out: u128,
        freshness: FreshnessStatus,
    ) -> ExecutionPreview {
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
                amount: AtomicAmount::new(net_out),
            },
            gross_output: AssetAmount {
                asset: intent.token_out.clone(),
                amount: AtomicAmount::new(gross_out),
            },
            cost_components: ExecutionCostComponents {
                gas_cost: None,
                dex_fee: None,
                provider_fee: None,
                tax_cost: if gross_out > net_out {
                    Some(AssetAmount {
                        asset: intent.token_out.clone(),
                        amount: AtomicAmount::new(gross_out - net_out),
                    })
                } else {
                    None
                },
            },
            local_state_freshness: freshness,
        }
    }

    #[test]
    fn wide_mul_u128_correctness_and_max_bounds() {
        assert_eq!(mul_u128_wide(0, 100), (0, 0));
        assert_eq!(mul_u128_wide(1, 1), (0, 1));
        assert_eq!(mul_u128_wide(10, 20), (0, 200));

        let two_64 = 1u128 << 64;
        assert_eq!(mul_u128_wide(two_64, two_64), (1, 0));

        let (hi, lo) = mul_u128_wide(u128::MAX, u128::MAX);
        assert_eq!(hi, u128::MAX - 1);
        assert_eq!(lo, 1);

        assert_eq!(cmp_u128_products(10, 20, 10, 20), std::cmp::Ordering::Equal);
        assert_eq!(cmp_u128_products(10, 20, 10, 21), std::cmp::Ordering::Less);
        assert_eq!(
            cmp_u128_products(10, 25, 10, 20),
            std::cmp::Ordering::Greater
        );
    }

    // Required regression 1: valid BUY and SELL previews use exact simulated net economics
    // for executable price / limit evaluation, not gross quote fields.
    #[test]
    fn regression_1_buy_and_sell_use_exact_net_economics_not_gross_quote() {
        let now_ms = 1_000;

        // --- BUY TEST ---
        // Payment token_in = USDC, Target token_out = TOKEN.
        // User sets LimitPrice: max 4.0 USDC per TOKEN (num = 400 USDC, den = 100 TOKEN).
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let buy_limit = LimitPrice {
            numerator_asset: token_in.clone(),
            denominator_asset: token_out.clone(),
            ratio: PriceRatio::new(400, 100).unwrap(), // limit price = 4.0
        };
        let buy_intent = sample_intent(TradeSide::Buy, OrderType::Limit, Some(buy_limit));
        let route = sample_route(&token_in, &token_out, now_ms);

        // Case 1A: Net input = 1000 USDC.
        // Gross output = 260 TOKEN (gross price = 1000/260 = 3.846 <= 4.0, which passes limit).
        // Tax = 20 TOKEN => Simulated Net output = 240 TOKEN.
        // Simulated Net price = 1000/240 = 4.167 > 4.0 (VIOLATES LIMIT!).
        // The preview MUST reject with LimitPriceViolated, proving gross quote is NOT used.
        let gross_passing_net_failing_buy = sample_preview(
            &buy_intent,
            1_000,
            240, // net output: price 1000/240 = 4.167 > 4.0
            260, // gross output: price 1000/260 = 3.846 <= 4.0
            FreshnessStatus::Fresh,
        );
        assert_eq!(
            gross_passing_net_failing_buy.validate(&buy_intent, &route, now_ms),
            Err(DomainError::LimitPriceViolated),
            "BUY must fail-closed on exact net economics even when gross quote passes"
        );

        // Case 1B: Valid BUY where exact net economics pass limit.
        // Net input = 1000 USDC. Gross output = 270 TOKEN. Tax = 10 TOKEN => Net output = 260 TOKEN.
        // Simulated Net price = 1000/260 = 3.846 <= 4.0.
        let valid_buy = sample_preview(&buy_intent, 1_000, 260, 270, FreshnessStatus::Fresh);
        let validated_buy = valid_buy.validate(&buy_intent, &route, now_ms).unwrap();
        assert_eq!(
            validated_buy.executable_net_price().unwrap(),
            PriceRatio::new(1_000, 260).unwrap()
        );
        assert_eq!(
            valid_buy.gross_quote_price().unwrap(),
            PriceRatio::new(1_000, 270).unwrap()
        );

        // --- SELL TEST ---
        // Sold token_in = TOKEN, Proceeds token_out = USDC.
        // User sets LimitPrice: min 4.0 USDC per TOKEN (num = 400 USDC, den = 100 TOKEN).
        let sell_token_in = sample_asset(ChainId::Base, "0xtoken");
        let sell_token_out = sample_asset(ChainId::Base, "0xusdc");
        let sell_limit = LimitPrice {
            numerator_asset: sell_token_out.clone(),
            denominator_asset: sell_token_in.clone(),
            ratio: PriceRatio::new(400, 100).unwrap(), // limit price = 4.0
        };
        let mut sell_intent = sample_intent(TradeSide::Sell, OrderType::Limit, Some(sell_limit));
        sell_intent.token_in = sell_token_in.clone();
        sell_intent.token_out = sell_token_out.clone();
        let sell_route = sample_route(&sell_token_in, &sell_token_out, now_ms);

        // Case 1C: Net input = 100 TOKEN.
        // Gross output = 420 USDC (gross price = 420/100 = 4.2 >= 4.0, which passes limit).
        // Tax = 30 USDC => Simulated Net output = 390 USDC.
        // Simulated Net price = 390/100 = 3.9 < 4.0 (VIOLATES LIMIT!).
        // The preview MUST reject with LimitPriceViolated, proving gross quote is NOT used.
        let gross_passing_net_failing_sell = sample_preview(
            &sell_intent,
            100,
            390, // net output: price 390/100 = 3.9 < 4.0
            420, // gross output: price 420/100 = 4.2 >= 4.0
            FreshnessStatus::Fresh,
        );
        assert_eq!(
            gross_passing_net_failing_sell.validate(&sell_intent, &sell_route, now_ms),
            Err(DomainError::LimitPriceViolated),
            "SELL must fail-closed on exact net economics even when gross quote passes"
        );

        // Case 1D: Valid SELL where exact net economics pass limit.
        // Net input = 100 TOKEN. Gross output = 430 USDC. Tax = 10 USDC => Net output = 420 USDC.
        // Simulated Net price = 420/100 = 4.2 >= 4.0.
        let valid_sell = sample_preview(&sell_intent, 100, 420, 430, FreshnessStatus::Fresh);
        let validated_sell = valid_sell
            .validate(&sell_intent, &sell_route, now_ms)
            .unwrap();
        assert_eq!(
            validated_sell.executable_net_price().unwrap(),
            PriceRatio::new(420, 100).unwrap()
        );
        assert_eq!(
            valid_sell.gross_quote_price().unwrap(),
            PriceRatio::new(430, 100).unwrap()
        );
    }

    // Required regression 2: stale and resync-required route/local state reject.
    #[test]
    fn regression_2_stale_and_resync_required_states_reject() {
        let now_ms = 100_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);

        // 2A: Stale local state on preview rejects
        let stale_local_preview = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Stale);
        let fresh_route = sample_route(&token_in, &token_out, now_ms);
        assert_eq!(
            stale_local_preview.validate(&intent, &fresh_route, now_ms),
            Err(DomainError::StaleMarketState)
        );

        // 2B: ResyncRequired local state on preview rejects
        let resync_local_preview =
            sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::ResyncRequired);
        assert_eq!(
            resync_local_preview.validate(&intent, &fresh_route, now_ms),
            Err(DomainError::ResyncRequired)
        );

        // 2C: Stale route state (route observed_at_ms exceeds default max staleness 10s)
        let fresh_preview = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Fresh);
        let stale_route = sample_route(&token_in, &token_out, now_ms - 20_000);
        assert_eq!(
            fresh_preview.validate(&intent, &stale_route, now_ms),
            Err(DomainError::StaleMarketState)
        );

        // 2D: Resync-required route state (zero sequence)
        let mut resync_route = sample_route(&token_in, &token_out, now_ms);
        resync_route.state.sequence = Sequence::ZERO;
        assert_eq!(
            fresh_preview.validate(&intent, &resync_route, now_ms),
            Err(DomainError::ResyncRequired)
        );

        // 2E: Resync-required route state (future clock skew > 2000ms)
        let future_skew_route = sample_route(&token_in, &token_out, now_ms + 5_000);
        assert_eq!(
            fresh_preview.validate(&intent, &future_skew_route, now_ms),
            Err(DomainError::ResyncRequired)
        );
    }

    // Required regression 3: mismatched chains/assets and zero/invalid deltas reject.
    #[test]
    fn regression_3_mismatched_chains_assets_and_invalid_deltas_reject() {
        let now_ms = 1_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        let route = sample_route(&token_in, &token_out, now_ms);

        // 3A: Chain mismatch between preview and intent
        let mut bad_chain = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Fresh);
        bad_chain.chain = ChainId::Solana;
        assert_eq!(
            bad_chain.validate(&intent, &route, now_ms),
            Err(DomainError::ChainMismatch)
        );

        // 3B: Token in mismatch
        let mut bad_token_in = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Fresh);
        bad_token_in.token_in = sample_asset(ChainId::Base, "0xweth");
        assert_eq!(
            bad_token_in.validate(&intent, &route, now_ms),
            Err(DomainError::InputAssetMismatch)
        );

        // 3C: Token out mismatch
        let mut bad_token_out = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Fresh);
        bad_token_out.token_out = sample_asset(ChainId::Base, "0xdai");
        assert_eq!(
            bad_token_out.validate(&intent, &route, now_ms),
            Err(DomainError::OutputAssetMismatch)
        );

        // 3D: Zero simulated net input delta
        let zero_in = sample_preview(&intent, 0, 250, 250, FreshnessStatus::Fresh);
        assert_eq!(
            zero_in.validate(&intent, &route, now_ms),
            Err(DomainError::ZeroSimulatedDelta)
        );

        // 3E: Zero simulated net output delta
        let zero_out = sample_preview(&intent, 1_000, 0, 250, FreshnessStatus::Fresh);
        assert_eq!(
            zero_out.validate(&intent, &route, now_ms),
            Err(DomainError::ZeroSimulatedDelta)
        );

        // 3F: Zero gross output delta
        let mut zero_gross = sample_preview(&intent, 1_000, 250, 250, FreshnessStatus::Fresh);
        zero_gross.gross_output.amount = AtomicAmount::ZERO;
        assert_eq!(
            zero_gross.validate(&intent, &route, now_ms),
            Err(DomainError::ZeroSimulatedDelta)
        );

        // 3G: Internally inconsistent economics (net output > gross output)
        let inconsistent_net = sample_preview(&intent, 1_000, 300, 250, FreshnessStatus::Fresh);
        assert!(matches!(
            inconsistent_net.validate(&intent, &route, now_ms),
            Err(DomainError::InconsistentNetEconomics(_))
        ));

        // 3H: Cost components sum exceeds gross quote output
        let mut cost_overflow = sample_preview(&intent, 1_000, 200, 250, FreshnessStatus::Fresh);
        cost_components_with_high_fee(&mut cost_overflow, &token_out, 100);
        assert!(matches!(
            cost_overflow.validate(&intent, &route, now_ms),
            Err(DomainError::InconsistentNetEconomics(_))
        ));
    }

    fn cost_components_with_high_fee(
        preview: &mut ExecutionPreview,
        token_out: &AssetId,
        fee: u128,
    ) {
        preview.cost_components.dex_fee = Some(AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(fee),
        });
    }

    // Required regression 4: serialization round-trip preserves a valid preview and invalid input
    // cannot produce a validated preview.
    #[test]
    fn regression_4_serialization_round_trip_and_invalid_input_rejection() {
        let now_ms = 1_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        let route = sample_route(&token_in, &token_out, now_ms);
        let valid_preview = sample_preview(&intent, 1_000, 240, 250, FreshnessStatus::Fresh);

        // 4A: Valid preview serializes and round-trips losslessly
        let encoded = serde_json::to_string(&valid_preview).unwrap();
        let decoded: ExecutionPreview = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, valid_preview);

        let validated = decoded.validate(&intent, &route, now_ms).unwrap();
        assert_eq!(validated.preview(), &valid_preview);

        // 4B: ValidatedExecutionPreview serializes transparently to the same JSON representation
        let val_encoded = serde_json::to_string(&validated).unwrap();
        assert_eq!(val_encoded, encoded);

        // 4C: Invalid JSON cannot deserialize into ExecutionPreview
        let invalid_json = "{\"intent_id\":\"\",\"chain\":{\"kind\":\"base\"}}";
        assert!(serde_json::from_str::<ExecutionPreview>(invalid_json).is_err());

        // 4D: Deserialized invalid preview cannot produce a ValidatedExecutionPreview
        let mut bad_data = valid_preview.clone();
        bad_data.simulated_net_input.amount = AtomicAmount::ZERO;
        let bad_json = serde_json::to_string(&bad_data).unwrap();
        let decoded_bad: ExecutionPreview = serde_json::from_str(&bad_json).unwrap();
        assert_eq!(
            decoded_bad.validate(&intent, &route, now_ms),
            Err(DomainError::ZeroSimulatedDelta)
        );
    }

    // Required regression 5: all validation failures are pure: they cannot mutate
    // the intent, route, or preview inputs.
    #[test]
    fn regression_5_validation_failures_are_pure_and_cannot_mutate_inputs() {
        let now_ms = 1_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        let route = sample_route(&token_in, &token_out, now_ms);
        let preview = sample_preview(&intent, 1_000, 240, 250, FreshnessStatus::Fresh);

        // Snapshot copies before running failure cases
        let orig_intent = intent.clone();
        let orig_route = route.clone();
        let orig_preview = preview.clone();

        // Failure Case 1: Mismatched preview chain
        let mut bad_preview = preview.clone();
        bad_preview.chain = ChainId::Ethereum;
        let res1 = bad_preview.validate(&intent, &route, now_ms);
        assert_eq!(res1, Err(DomainError::ChainMismatch));
        assert_eq!(intent, orig_intent);
        assert_eq!(route, orig_route);
        assert_eq!(preview, orig_preview);

        // Failure Case 2: Zero delta in preview
        let mut zero_preview = preview.clone();
        zero_preview.simulated_net_output.amount = AtomicAmount::ZERO;
        let res2 = zero_preview.validate(&intent, &route, now_ms);
        assert_eq!(res2, Err(DomainError::ZeroSimulatedDelta));
        assert_eq!(intent, orig_intent);
        assert_eq!(route, orig_route);
        assert_eq!(preview, orig_preview);

        // Failure Case 3: Stale route
        let stale_route = sample_route(&token_in, &token_out, now_ms - 25_000);
        let res3 = preview.validate(&intent, &stale_route, now_ms);
        assert_eq!(res3, Err(DomainError::StaleMarketState));
        assert_eq!(intent, orig_intent);
        assert_eq!(route, orig_route);
        assert_eq!(preview, orig_preview);

        // Failure Case 4: Free function validation call preserves purity
        let res4 = validate_execution_preview(&intent, &stale_route, &preview, now_ms);
        assert_eq!(res4, Err(DomainError::StaleMarketState));
        assert_eq!(intent, orig_intent);
        assert_eq!(route, orig_route);
        assert_eq!(preview, orig_preview);
    }

    #[test]
    fn market_order_preview_passes_cleanly_and_computes_net_price() {
        let now_ms = 1_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        let route = sample_route(&token_in, &token_out, now_ms);
        let preview = sample_preview(&intent, 1_000, 250, 260, FreshnessStatus::Fresh);

        let validated = preview.validate(&intent, &route, now_ms).unwrap();
        assert_eq!(
            validated.executable_net_price().unwrap(),
            PriceRatio::new(1_000, 250).unwrap()
        );
    }

    #[test]
    fn max_total_cost_and_partial_fill_policies_enforced() {
        let now_ms = 1_000;
        let token_in = sample_asset(ChainId::Base, "0xusdc");
        let token_out = sample_asset(ChainId::Base, "0xtoken");
        let mut intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        intent.risk.max_total_cost = Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(999),
        });
        let route = sample_route(&token_in, &token_out, now_ms);
        let preview = sample_preview(&intent, 1_000, 250, 260, FreshnessStatus::Fresh);

        // Input 1000 exceeds max_total_cost 999
        assert!(matches!(
            preview.validate(&intent, &route, now_ms),
            Err(DomainError::InconsistentNetEconomics(_))
        ));

        // Partial fill false rejects smaller input
        let mut all_or_nothing = sample_intent(TradeSide::Buy, OrderType::Market, None);
        all_or_nothing.allow_partial_fill = false;
        all_or_nothing.amount = AtomicAmount::new(2_000);
        let small_preview =
            sample_preview(&all_or_nothing, 1_000, 250, 260, FreshnessStatus::Fresh);
        assert!(matches!(
            small_preview.validate(&all_or_nothing, &route, now_ms),
            Err(DomainError::InconsistentNetEconomics(_))
        ));
    }

    #[test]
    fn regression_route_chain_consistency_rejects_contiguous_cross_chain_route_and_preserves_inputs(
    ) {
        let now_ms = 1_000;
        let token_base_in = sample_asset(ChainId::Base, "0xusdc");
        let token_solana_mid = sample_asset(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        );
        let token_base_out = sample_asset(ChainId::Base, "0xtoken");

        let intent = sample_intent(TradeSide::Buy, OrderType::Market, None);
        let preview = sample_preview(&intent, 1_000, 240, 250, FreshnessStatus::Fresh);

        // Contiguous 2-leg cross-chain route:
        // Leg 1: Base USDC -> Solana SOL
        // Leg 2: Solana SOL -> Base TOKEN
        let cross_chain_route = RoutePlan {
            legs: vec![
                RouteLeg {
                    venue: "cross_bridge_1".to_string(),
                    pool_ref: "pool-base-sol".to_string(),
                    token_in: token_base_in.clone(),
                    token_out: token_solana_mid.clone(),
                    amount_in: AtomicAmount::new(1_000),
                    expected_amount_out: AtomicAmount::new(500),
                },
                RouteLeg {
                    venue: "cross_bridge_2".to_string(),
                    pool_ref: "pool-sol-base".to_string(),
                    token_in: token_solana_mid.clone(),
                    token_out: token_base_out.clone(),
                    amount_in: AtomicAmount::new(500),
                    expected_amount_out: AtomicAmount::new(250),
                },
            ],
            expected_net_output: AssetAmount {
                asset: token_base_out.clone(),
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: now_ms,
                chain_height: 100,
                sequence: Sequence(1),
            },
        };

        // 1. Generic route plan validation succeeds because legs are contiguous
        // and individually valid.
        assert!(cross_chain_route.validate().is_ok());

        // 2. The old flawed check verified only first leg token_in and last leg token_out chains.
        // Prove that this cross-chain route would have satisfied that old check:
        let first_leg = cross_chain_route.legs.first().unwrap();
        let last_leg = cross_chain_route.legs.last().unwrap();
        assert_eq!(first_leg.token_in.chain, preview.chain);
        assert_eq!(last_leg.token_out.chain, preview.chain);
        assert_eq!(first_leg.token_in, preview.token_in);
        assert_eq!(last_leg.token_out, preview.token_out);
        assert_eq!(first_leg.token_out.chain, ChainId::Solana);
        assert_eq!(last_leg.token_in.chain, ChainId::Solana);

        // 3. Snapshot copies before validation to prove inputs remain unmodified.
        let orig_intent = intent.clone();
        let orig_route = cross_chain_route.clone();
        let orig_preview = preview.clone();

        // 4. ExecutionPreview::validate rejects fail-closed with DomainError::ChainMismatch.
        let res = preview.validate(&intent, &cross_chain_route, now_ms);
        assert_eq!(res, Err(DomainError::ChainMismatch));

        // Prove failure leaves intent, route, and preview inputs unchanged.
        assert_eq!(intent, orig_intent);
        assert_eq!(cross_chain_route, orig_route);
        assert_eq!(preview, orig_preview);

        // Also verify the free function entrypoint behaves identically and purely.
        let res2 = validate_execution_preview(&intent, &cross_chain_route, &preview, now_ms);
        assert_eq!(res2, Err(DomainError::ChainMismatch));
        assert_eq!(intent, orig_intent);
        assert_eq!(cross_chain_route, orig_route);
        assert_eq!(preview, orig_preview);

        // Also verify a 3-leg contiguous route: Base -> Solana -> Solana -> Base
        let token_solana_mid2 = sample_asset(
            ChainId::Solana,
            "So22222222222222222222222222222222222222222",
        );
        let cross_chain_route_3leg = RoutePlan {
            legs: vec![
                RouteLeg {
                    venue: "bridge_in".to_string(),
                    pool_ref: "pool-1".to_string(),
                    token_in: token_base_in.clone(),
                    token_out: token_solana_mid.clone(),
                    amount_in: AtomicAmount::new(1_000),
                    expected_amount_out: AtomicAmount::new(500),
                },
                RouteLeg {
                    venue: "dex_sol".to_string(),
                    pool_ref: "pool-2".to_string(),
                    token_in: token_solana_mid.clone(),
                    token_out: token_solana_mid2.clone(),
                    amount_in: AtomicAmount::new(500),
                    expected_amount_out: AtomicAmount::new(400),
                },
                RouteLeg {
                    venue: "bridge_out".to_string(),
                    pool_ref: "pool-3".to_string(),
                    token_in: token_solana_mid2.clone(),
                    token_out: token_base_out.clone(),
                    amount_in: AtomicAmount::new(400),
                    expected_amount_out: AtomicAmount::new(250),
                },
            ],
            expected_net_output: AssetAmount {
                asset: token_base_out,
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: now_ms,
                chain_height: 100,
                sequence: Sequence(1),
            },
        };
        assert!(cross_chain_route_3leg.validate().is_ok());
        let orig_route_3leg = cross_chain_route_3leg.clone();
        let res3 = preview.validate(&intent, &cross_chain_route_3leg, now_ms);
        assert_eq!(res3, Err(DomainError::ChainMismatch));
        assert_eq!(cross_chain_route_3leg, orig_route_3leg);
        assert_eq!(intent, orig_intent);
        assert_eq!(preview, orig_preview);
    }
}
