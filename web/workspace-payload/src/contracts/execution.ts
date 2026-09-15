// Web-side view of the canonical execution contracts. Mirrors `domain`
// TradeIntent and the execution-preview `NetDelta` (docs/PRD.md lines 18–34, 49).
// The displayed raw quote is informational; `netOutput` is execution truth.

import { workspaceError } from "../core/errors";

export type TradeSide = "buy" | "sell";
export type AmountType = "usd" | "stablecoin" | "token";
export type OrderType = "market" | "limit" | "twap" | "rfq";

/**
 * Routing source preference for a swap. `okx` asks the explicit PEP hybrid
 * router/benchmark; `local` asks our own exact local router. The browser sends
 * this only to the neutral first-party quote/preview/execute contract and never
 * talks to a provider directly (architecture lock L2). The preference is
 * memory-only session state — never persisted.
 */
export type RouterPreference = "okx" | "local";

/**
 * The routing source the backend actually used for a quote. `okx` is never
 * silently substituted for `local` (or vice versa): a mismatched or missing
 * source is a protocol violation the UI refuses to execute.
 */
export interface RouterSourceView {
  readonly id: RouterPreference;
  /** Optional neutral note (no URLs, credentials or provider internals). */
  readonly detail: string | null;
}

/**
 * Canonical wire form of the routing discriminant.
 *
 * The landed `agent-backend` P84B/P84C contract (`MarketPreview::router_source`)
 * serialises the discriminant as the bare string `"okx"` / `"local"` — see
 * `crates/agent-backend/src/market.rs` and `tests/hybrid_router.rs`
 * (`assert_eq!(preview["router_source"], Value::String("okx".to_string()))`).
 * The private web contract's `QuotePreview` requested the same value wrapped in
 * an object `{ id, detail }` (BR-10), so the client accepts either exact form and
 * normalises to {@link RouterSourceView}. Both must carry an exact `okx`/`local`
 * discriminant; anything else is refused rather than guessed (no silent
 * fallback).
 */
export type RouterSourceWire = RouterSourceView | RouterPreference;

export function routerSourceLabel(id: RouterPreference): string {
  return id === "okx" ? "OKX" : "Local Router";
}

/**
 * Strictly normalise an untrusted `router_source` value to a
 * {@link RouterSourceView}, accepting both the canonical string discriminant and
 * the object form. Returns `null` for anything that does not name exactly `okx`
 * or `local` (case/whitespace sensitive); a missing or malformed source is never
 * treated as a default.
 */
export function parseRouterSource(value: unknown): RouterSourceView | null {
  // Canonical P84B/P84C form: the bare wire label.
  if (value === "okx" || value === "local") return { id: value, detail: null };
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const id = (value as { id?: unknown }).id;
  if (id !== "okx" && id !== "local") return null;
  const detail = (value as { detail?: unknown }).detail;
  return { id, detail: typeof detail === "string" ? detail : null };
}

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
  /** The routing source the backend was asked to use (echo of the request). */
  readonly routerPreference: RouterPreference;
  /**
   * The routing source actually used. Must equal `routerPreference`. Accepts the
   * canonical string discriminant (`RouterSourceWire`) or the object form; parse
   * it with {@link parseRouterSource} before use.
   */
  readonly routerSource: RouterSourceWire;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate a `get_orders` success document before the renderer consumes it.
 *
 * The private API is authoritative for the shape. A document the client cannot
 * render (for example the canonical snake_case `OrderSummary` before the web
 * projection exists) must become a typed protocol error, never a `ready` state
 * whose value throws inside the renderer. This is deliberately strict: it
 * checks exactly the fields the order list reads, so an unknown shape fails
 * closed instead of producing a partial or fabricated view.
 */
export function parseOrdersResponse(value: unknown): { readonly orders: readonly LimitOrderView[] } {
  if (!isRecord(value) || !Array.isArray(value.orders)) {
    throw workspaceError("protocol", "Malformed order list.");
  }
  for (const order of value.orders) {
    if (!isRecord(order)) throw workspaceError("protocol", "Malformed order entry.");
    if (typeof order.orderId !== "string" || order.orderId.length === 0) {
      throw workspaceError("protocol", "Order is missing an id.");
    }
    if (typeof order.state !== "string" || order.state.length === 0) {
      throw workspaceError("protocol", "Order is missing a state.");
    }
    if (!isRecord(order.intent) || typeof order.intent.side !== "string") {
      throw workspaceError("protocol", "Order is missing its intent.");
    }
    if (!Array.isArray(order.fills)) {
      throw workspaceError("protocol", "Order is missing its fills.");
    }
  }
  return value as unknown as { readonly orders: readonly LimitOrderView[] };
}

/**
 * Validate a `get_portfolio` success document before the renderer consumes it.
 *
 * Same rationale as {@link parseOrdersResponse}: the canonical document nests
 * the summary under `portfolio` with `{asset, amount}` balances, which the
 * portfolio view cannot render, so it must surface as a typed protocol error
 * rather than a `ready` value that throws on `balances`.
 */
export function parsePortfolioView(value: unknown): PortfolioView {
  if (!isRecord(value) || !Array.isArray(value.balances)) {
    throw workspaceError("protocol", "Malformed portfolio document.");
  }
  for (const balance of value.balances) {
    if (!isRecord(balance) || typeof balance.amount !== "string") {
      throw workspaceError("protocol", "Malformed balance entry.");
    }
  }
  return value as unknown as PortfolioView;
}
