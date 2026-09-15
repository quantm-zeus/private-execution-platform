import { describe, expect, it } from "vitest";
import {
  MAX_LIMIT_VALUE,
  MAX_SOURCE_AGE_MS,
  diffWalletLimits,
  hasRelaxation,
  limitsFromView,
  parseLimitInput,
  parseListInput,
  parseWalletLimits,
  validateListInput,
  walletLimitsPayload,
  type WalletLimitsEditable,
} from "./wallet-limits";

const VALID = {
  wallet_ref: "0xwallet",
  max_trade_usd: 5_000,
  hourly_turnover_usd: 20_000,
  daily_turnover_usd: 100_000,
  max_buy_tax_bps: 500,
  max_sell_tax_bps: 400,
  max_price_impact_bps: 150,
  max_slippage_bps: 100,
  allowed_chains: ["base", "solana", "base"],
  allowed_routers: ["okx"],
  allowed_programs: ["0xrouter"],
  source_age_ms: 1_200,
  slot: 7,
};

function editable(overrides: Partial<WalletLimitsEditable> = {}): WalletLimitsEditable {
  return {
    maxTradeUsd: 5_000,
    hourlyTurnoverUsd: 20_000,
    dailyTurnoverUsd: 100_000,
    maxBuyTaxBps: 500,
    maxSellTaxBps: 400,
    maxPriceImpactBps: 150,
    maxSlippageBps: 100,
    allowedChains: ["base"],
    allowedRouters: ["okx"],
    allowedPrograms: ["0xrouter"],
    ...overrides,
  };
}

describe("parseWalletLimits", () => {
  it("parses a complete response and de-duplicates list entries", () => {
    const view = parseWalletLimits(VALID);
    expect(view.maxTradeUsd).toBe(5_000);
    expect(view.maxSellTaxBps).toBe(400);
    expect(view.allowedChains).toEqual(["base", "solana"]);
    expect(view.allowedRouters).toEqual(["okx"]);
    expect(view.walletRef).toBe("0xwallet");
    expect(view.sourceAgeMs).toBe(1_200);
    expect(view.slot).toBe(7);
  });

  it("keeps an explicit null cap as 'no configured cap'", () => {
    const view = parseWalletLimits({ ...VALID, max_trade_usd: null });
    expect(view.maxTradeUsd).toBeNull();
  });

  it.each([
    ["negative cap", { max_trade_usd: -1 }],
    ["missing cap key", { max_trade_usd: undefined }],
    ["non-numeric cap", { max_trade_usd: "5000" }],
    ["non-finite cap", { max_slippage_bps: Number.POSITIVE_INFINITY }],
    ["oversized cap", { max_buy_tax_bps: MAX_LIMIT_VALUE + 1 }],
    ["missing chain list", { allowed_chains: undefined }],
    ["non-array chain list", { allowed_chains: "base" }],
    ["oversized list", { allowed_chains: Array.from({ length: 257 }, (_, i) => `c${i}`) }],
    ["over-long list entry", { allowed_programs: ["x".repeat(500)] }],
    ["empty list entry", { allowed_routers: [""] }],
    ["missing source age", { source_age_ms: undefined }],
    ["negative source age", { source_age_ms: -5 }],
    ["absurd source age", { source_age_ms: MAX_SOURCE_AGE_MS + 1 }],
    ["non-finite source age", { source_age_ms: Number.POSITIVE_INFINITY }],
  ])("fails closed on a %s", (_label, patch) => {
    expect(() => parseWalletLimits({ ...VALID, ...patch })).toThrow();
  });

  it("drops an over-long wallet reference rather than echoing it", () => {
    const view = parseWalletLimits({ ...VALID, wallet_ref: "x".repeat(200) });
    expect(view.walletRef).toBeNull();
  });
});

describe("input helpers", () => {
  it("treats an empty cap input as 'no cap' and rejects malformed values", () => {
    expect(parseLimitInput("")).toEqual({ value: null, error: null });
    expect(parseLimitInput(" 250 ")).toEqual({ value: 250, error: null });
    expect(parseLimitInput("0.5")).toEqual({ value: 0.5, error: null });
    expect(parseLimitInput(".5")).toEqual({ value: 0.5, error: null });
    expect(parseLimitInput("abc").error).toMatch(/decimal/);
    expect(parseLimitInput("-3").error).toMatch(/decimal/);
    expect(parseLimitInput(String(MAX_LIMIT_VALUE + 1)).error).toMatch(/too large/);
  });

  it("rejects non-decimal literals Number() would silently reinterpret", () => {
    // Every one of these parses to a *different* value under Number(), which
    // would silently apply a materially different security cap.
    for (const raw of ["0x100", "0b101", "0o17", "1e3", "+5", "5.", "1_000", "Infinity"]) {
      const result = parseLimitInput(raw);
      expect(result.value, raw).toBeNull();
      expect(result.error, raw).not.toBeNull();
    }
  });

  it("splits and de-duplicates a program list", () => {
    expect(parseListInput("0xa, 0xb\n0xa")).toEqual(["0xa", "0xb"]);
    expect(parseListInput("   ")).toEqual([]);
  });

  it("bounds a pasted program list instead of submitting an unbounded payload", () => {
    const tooMany = Array.from({ length: 257 }, (_, i) => `0x${i}`).join(",");
    const bounded = validateListInput(tooMany);
    expect(bounded.value).toHaveLength(256);
    expect(bounded.error).toMatch(/Too many entries/);

    const tooLong = validateListInput("x".repeat(200));
    expect(tooLong.error).toMatch(/longer than/);

    expect(validateListInput("0xa, 0xb")).toEqual({ value: ["0xa", "0xb"], error: null });
  });
});

describe("diffWalletLimits", () => {
  it("classifies cap increases as relaxations and decreases as tightenings", () => {
    const changes = diffWalletLimits(editable(), editable({ maxTradeUsd: 9_000 }));
    expect(changes).toEqual([
      { field: "maxTradeUsd", label: "Max trade (USD)", direction: "relax", from: "5000", to: "9000" },
    ]);
    expect(hasRelaxation(changes)).toBe(true);

    const tightened = diffWalletLimits(editable(), editable({ maxSlippageBps: 50 }));
    expect(tightened[0]).toMatchObject({ field: "maxSlippageBps", direction: "tighten" });
    expect(hasRelaxation(tightened)).toBe(false);
  });

  it("classifies dropping a cap as a relaxation and adding one as a tightening", () => {
    expect(
      diffWalletLimits(editable(), editable({ maxTradeUsd: null }))[0].direction,
    ).toBe("relax");
    expect(
      diffWalletLimits(editable({ maxTradeUsd: null }), editable({ maxTradeUsd: 1 }))[0].direction,
    ).toBe("tighten");
  });

  it("classifies list additions as relaxations and removals as tightenings", () => {
    const added = diffWalletLimits(editable(), editable({ allowedChains: ["base", "solana"] }));
    expect(added).toHaveLength(1);
    expect(added[0]).toMatchObject({ field: "allowedChains", direction: "relax" });

    const removed = diffWalletLimits(
      editable({ allowedChains: ["base", "solana"] }),
      editable({ allowedChains: ["base"] }),
    );
    expect(removed[0]).toMatchObject({ field: "allowedChains", direction: "tighten" });

    // A swap both adds and removes: the newly permitted entry dominates.
    const swapped = diffWalletLimits(
      editable({ allowedRouters: ["okx"] }),
      editable({ allowedRouters: ["local"] }),
    );
    expect(swapped[0].direction).toBe("relax");
  });

  it("omits unchanged fields and reports no relaxation for a no-op", () => {
    const changes = diffWalletLimits(editable(), editable());
    expect(changes).toEqual([]);
    expect(hasRelaxation(changes)).toBe(false);
  });

  it("builds a snake_case payload and round-trips through limitsFromView", () => {
    const view = parseWalletLimits(VALID);
    const payload = walletLimitsPayload(limitsFromView(view));
    expect(payload).toMatchObject({
      max_trade_usd: 5_000,
      allowed_chains: ["base", "solana"],
      allowed_programs: ["0xrouter"],
    });
  });
});
