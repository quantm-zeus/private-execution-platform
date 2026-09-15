import { describe, expect, it } from "vitest";
import {
  parseOrdersResponse,
  parsePortfolioView,
  parseRouterSource,
  routerSourceLabel,
  type RouterPreference,
  type RouterSourceView,
} from "./execution";

/**
 * W15 contract-conformance tests: the routing discriminant is reconciled with the
 * landed `agent-backend` P84B/P84C contract on canonical `origin/main`.
 *
 * `crates/agent-commands/src/command.rs` serialises `RouterSource` with
 * `#[serde(rename_all = "snake_case")]` as the bare strings `"okx"` / `"local"`,
 * and `crates/agent-backend/tests/hybrid_router.rs` asserts the response JSON:
 *   preview["router_source"]  == Value::String("okx")
 *   value["quote"]["router_source"] == Value::String("local")
 * The private web contract accepts that canonical string form as well as the
 * object `{ id, detail }` form it originally requested (BR-10), and normalises
 * both to {@link RouterSourceView}.
 */
describe("parseRouterSource (W15 canonical + object wire forms)", () => {
  it.each([
    ["okx", "okx"],
    ["local", "local"],
  ] as const)("accepts the canonical string %s", (wire, id) => {
    expect(parseRouterSource(wire)).toEqual({ id, detail: null } satisfies RouterSourceView);
  });

  it("accepts the object form and preserves a neutral detail string", () => {
    expect(parseRouterSource({ id: "local", detail: "pep-local" })).toEqual({
      id: "local",
      detail: "pep-local",
    } satisfies RouterSourceView);
    expect(parseRouterSource({ id: "okx" })).toEqual({ id: "okx", detail: null });
    expect(parseRouterSource({ id: "okx", detail: null })).toEqual({ id: "okx", detail: null });
  });

  it("does not coerce a non-string detail into a rendered value", () => {
    // A hostile relay could try to smuggle an object/array into `detail`; only a
    // string survives, everything else normalises to null.
    expect(parseRouterSource({ id: "okx", detail: { html: "<img>" } })).toEqual({
      id: "okx",
      detail: null,
    });
    expect(parseRouterSource({ id: "okx", detail: 42 })).toEqual({ id: "okx", detail: null });
  });

  it("rejects non-canonical labels (case, whitespace, unknown, sentinels)", () => {
    const rejected = ["OKX", "Local", " okx", "okx ", "", "solana", "none"];
    for (const wire of rejected) {
      expect(parseRouterSource(wire), wire).toBeNull();
    }
  });

  it.each([
    [null, "null"],
    [undefined, "undefined"],
    [42, "number"],
    [true, "boolean"],
    [["okx"], "array"],
    [{}, "missing id"],
    [{ id: "OKX" }, "non-canonical id"],
    [{ id: 1 }, "non-string id"],
    [{ detail: "okx" }, "detail without id"],
  ] as const)("rejects malformed input %# (%s)", (value, _label) => {
    expect(parseRouterSource(value)).toBeNull();
  });

  it("reconstructs the view instead of spreading unknown fields", () => {
    expect(parseRouterSource({ id: "okx", detail: "x", extra: true })).toEqual({
      id: "okx",
      detail: "x",
    });
  });

  it("parses the exact landed P84B/P84C response JSON discriminants", () => {
    // Verbatim shapes from crates/agent-backend/tests/hybrid_router.rs.
    const previewOkx = { preview: { router_source: "okx", truncated: false } };
    const previewLocal = { preview: { router_source: "local", truncated: false } };
    const getQuoteOkx = { quote: { router_source: "okx" } };
    const getQuoteLocal = { quote: { router_source: "local" } };

    expect(parseRouterSource(previewOkx.preview.router_source)?.id).toBe<RouterPreference>("okx");
    expect(parseRouterSource(previewLocal.preview.router_source)?.id).toBe<RouterPreference>("local");
    expect(parseRouterSource(getQuoteOkx.quote.router_source)?.id).toBe<RouterPreference>("okx");
    expect(parseRouterSource(getQuoteLocal.quote.router_source)?.id).toBe<RouterPreference>("local");
  });

  it("labels the canonical ids for display without leaking provider internals", () => {
    expect(routerSourceLabel("okx")).toBe("OKX");
    expect(routerSourceLabel("local")).toBe("Local Router");
  });
});

/**
 * F2/F3: the private API is authoritative for the orders/portfolio shapes. A
 * document the view cannot render must fail as a typed protocol error, never a
 * `ready` value whose render throws. The canonical `agent-backend` document is
 * the concrete hostile example (snake_case, nested under `portfolio`, no
 * `intent`/`fills`).
 */
describe("parseOrdersResponse", () => {
  const validIntent = {
    id: "intent-1",
    chain: "base",
    tokenIn: "0x1",
    tokenOut: "0x2",
    side: "buy",
    amountType: "token",
    amount: "5",
    orderType: "limit",
    limitPrice: "2.50",
    maxBuyTaxBps: null,
    maxSellTaxBps: null,
    maxPriceImpactBps: 50,
    maxSlippageBps: 50,
    maxTotalCostUsd: null,
    allowPartialFill: true,
    expiryMs: 1_700_000_000_000,
  };
  const validOrder = {
    orderId: "order-1",
    intent: validIntent,
    state: "ACTIVE",
    filledAmount: "0",
    remainingAmount: "10",
    fills: [],
    createdAtMs: 1,
    updatedAtMs: 2,
    nextActionMs: null,
    failureReason: null,
  };

  it("accepts the web order document", () => {
    expect(parseOrdersResponse({ orders: [validOrder] }).orders).toHaveLength(1);
    expect(parseOrdersResponse({ orders: [] }).orders).toEqual([]);
  });

  it("accepts a fully formed fill", () => {
    const withFill = {
      ...validOrder,
      fills: [{ executionId: "exec-1", amountIn: "1", amountOut: "2", atMs: 3 }],
    };
    expect(parseOrdersResponse({ orders: [withFill] }).orders).toHaveLength(1);
  });

  it.each([
    [null, "null"],
    [{}, "missing orders"],
    [{ orders: {} }, "non-array orders"],
    [{ orders: [null] }, "null entry"],
    [{ orders: [{ ...validOrder, orderId: "" }] }, "empty id"],
    [{ orders: [{ ...validOrder, state: "" }] }, "empty state"],
    [{ orders: [{ ...validOrder, filledAmount: 0 }] }, "non-string fill amount"],
    [{ orders: [{ ...validOrder, intent: null }] }, "missing intent"],
    [{ orders: [{ ...validOrder, intent: {} }] }, "intent without side"],
    [{ orders: [{ ...validOrder, intent: { ...validIntent, amount: null } }] }, "intent without amount"],
    [{ orders: [{ ...validOrder, fills: null }] }, "missing fills"],
    // A shape-passing-but-unrenderable fill must be rejected here, not crash the
    // order list on `fill.executionId`.
    [{ orders: [{ ...validOrder, fills: [null] }] }, "null fill entry"],
    [
      { orders: [{ ...validOrder, fills: [{ executionId: "e", amountIn: "1", amountOut: "2" }] }] },
      "fill without atMs",
    ],
    [
      { orders: [{ ...validOrder, fills: [{ executionId: "", amountIn: "1", amountOut: "2", atMs: 3 }] }] },
      "fill without id",
    ],
  ] as const)("rejects malformed document %# (%s)", (value, _label) => {
    expect(() => parseOrdersResponse(value)).toThrowError(/order/i);
  });

  it("rejects the canonical snake_case OrderSummary document", () => {
    // Verbatim shape of crates/agent-backend/src/order.rs OrderSummary.
    expect(() =>
      parseOrdersResponse({
        orders: [
          {
            order_id: "order-1",
            wallet_ref: "w",
            status: "active",
            filled_input: "0",
            expires_at_ms: 1,
          },
        ],
      }),
    ).toThrowError(/order/i);
  });
});

describe("parsePortfolioView", () => {
  it("accepts the web portfolio document", () => {
    const view = parsePortfolioView({
      walletRef: "w",
      balances: [{ chain: "base", token: "t", symbol: "T", amount: "1", usdValue: null, ageMs: null }],
      equityUsd: null,
      slot: null,
      sourceAgeMs: 0,
    });
    expect(view.balances).toHaveLength(1);
    expect(parsePortfolioView({ walletRef: "w", balances: [], equityUsd: null, slot: null, sourceAgeMs: 0 }).balances).toEqual([]);
  });

  it.each([
    [null, "null"],
    [{}, "missing balances"],
    [{ balances: {} }, "non-array balances"],
    [{ balances: [], equityUsd: null, slot: null, sourceAgeMs: 0 }, "missing walletRef"],
    [{ walletRef: 1, balances: [], equityUsd: null, slot: null, sourceAgeMs: 0 }, "non-string walletRef"],
    [{ walletRef: "w", balances: [], equityUsd: null, slot: null, sourceAgeMs: "0" }, "non-numeric sourceAgeMs"],
    [{ balances: [null] }, "null balance"],
    [{ balances: [{ asset: "x" }] }, "balance without amount"],
    [{ balances: [{ chain: "base", token: "t", amount: "1" }] }, "balance without symbol"],
  ] as const)("rejects malformed document %# (%s)", (value, _label) => {
    expect(() => parsePortfolioView(value)).toThrowError(/portfolio|balance/i);
  });

  it("rejects the canonical nested PortfolioSummary document", () => {
    // Verbatim shape of crates/agent-backend/src/portfolio.rs PortfolioSummary.
    expect(() =>
      parsePortfolioView({
        portfolio: {
          balances: [{ asset: { chain: "base", address: "0x0" }, amount: "1" }],
          open_orders: 0,
          filled_orders: 0,
          total_orders: 0,
        },
      }),
    ).toThrowError(/portfolio/i);
  });
});
