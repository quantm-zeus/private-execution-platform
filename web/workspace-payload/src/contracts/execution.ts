// Web-side view of the canonical execution contracts. Mirrors `domain`
// TradeIntent and the execution-preview `NetDelta` (docs/PRD.md lines 18–34, 49).
// The displayed raw quote is informational; `netOutput` is execution truth.

export type TradeSide = "buy" | "sell";
export type AmountType = "usd" | "stablecoin" | "token";
export type OrderType = "market" | "limit" | "twap" | "rfq";

export interface TradeIntentView {
  readonly id: string;
  readonly chain: string;
  readonly tokenIn: string;
  readonly tokenOut: string;
  readonly side: TradeSide;
  readonly amountType: AmountType;
  readonly amount: string;
  readonly orderType: OrderType;
  readonly limitPrice: string | null;
  readonly maxBuyTaxBps: number | null;
  readonly maxSellTaxBps: number | null;
  readonly maxPriceImpactBps: number | null;
  readonly maxSlippageBps: number | null;
  readonly maxTotalCostUsd: number | null;
  readonly allowPartialFill: boolean;
  readonly expiryMs: number | null;
}

export interface RouteLeg {
  readonly index: number;
  readonly venue: string;
  readonly kind: "direct" | "bridge" | "split";
  readonly tokenIn: string;
  readonly tokenOut: string;
  readonly sharePct: number;
}

/** Full net economics. Every cost is part of the route score (invariant #4). */
export interface NetEconomics {
  readonly grossOutput: number | null;
  readonly netOutput: number | null;
  readonly taxBps: number | null;
  readonly dexFeeBps: number | null;
  readonly gasUsd: number | null;
  readonly priceImpactBps: number | null;
  readonly expectedSlippageBps: number | null;
  readonly mevRiskBps: number | null;
  readonly failureProbability: number | null;
  readonly minReceived: string | null;
}

export interface QuotePreview {
  readonly quoteId: string;
  readonly intent: TradeIntentView;
  readonly route: readonly RouteLeg[];
  readonly economics: NetEconomics;
  readonly slot: number | null;
  readonly sourceAgeMs: number;
  readonly expiresAtMs: number | null;
  /** Authoritative signal that a fresh revalidation is required before submit. */
  readonly revalidationRequired: boolean;
}

export type OrderState =
  | "CREATED"
  | "ACTIVE"
  | "TRIGGER_CANDIDATE"
  | "QUOTING"
  | "SIMULATING"
  | "EXECUTING"
  | "PARTIALLY_FILLED"
  | "FILLED"
  | "CANCELLED"
  | "EXPIRED"
  | "FAILED_RETRYABLE"
  | "FAILED_FINAL"
  | "UNKNOWN";

export interface OrderFill {
  readonly executionId: string;
  readonly amountIn: string;
  readonly amountOut: string;
  readonly atMs: number;
}

export interface LimitOrderView {
  readonly orderId: string;
  readonly intent: TradeIntentView;
  readonly state: OrderState;
  readonly filledAmount: string;
  readonly remainingAmount: string;
  readonly fills: readonly OrderFill[];
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly nextActionMs: number | null;
  readonly failureReason: string | null;
}

export interface BalanceView {
  readonly chain: string;
  readonly token: string;
  readonly symbol: string;
  readonly amount: string;
  readonly usdValue: number | null;
  readonly ageMs: number | null;
}

export interface PortfolioView {
  readonly walletRef: string;
  readonly balances: readonly BalanceView[];
  readonly equityUsd: number | null;
  readonly slot: number | null;
  readonly sourceAgeMs: number;
}

export interface ExecutionProgress {
  readonly executionId: string;
  readonly kind: "twap" | "rfq";
  readonly state: "planning" | "running" | "halted" | "completed" | "failed" | "unknown";
  readonly chunksTotal: number | null;
  readonly chunksDone: number | null;
  readonly filledAmount: string | null;
  readonly remainingAmount: string | null;
  readonly realizedVsEstimateBps: number | null;
  readonly haltReason: string | null;
}

export interface TwapRequest {
  readonly chain: string;
  readonly tokenIn: string;
  readonly tokenOut: string;
  readonly side: TradeSide;
  readonly totalAmount: string;
  readonly amountType: AmountType;
  readonly maxSlippageBps: number;
  readonly maxPriceImpactBps: number;
  readonly intervalMs: number;
  readonly maxChunks: number;
}

export interface RfqLegView {
  readonly solver: string;
  readonly amountOut: string;
  readonly netOutput: number | null;
  readonly latencyMs: number | null;
  readonly viable: boolean;
}

export interface RfqView {
  readonly rfqId: string;
  readonly legs: readonly RfqLegView[];
  readonly bestSolver: string | null;
  readonly state: ExecutionProgress["state"];
}

export interface AlertView {
  readonly alertId: string;
  readonly kind: string;
  readonly severity: "info" | "warning" | "critical";
  readonly summary: string;
  readonly createdAtMs: number;
  readonly stale: boolean;
}

export interface WithdrawalReview {
  readonly chain: string;
  readonly token: string;
  readonly amount: string;
  readonly destination: string;
  readonly feeUsd: number | null;
  readonly requiresStepUp: boolean;
}
