import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  serverState,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * W13 in a real browser: the market ticket offers an OKX / Local Router source
 * selector, defaults to OKX for a new session, sends the preference only to the
 * neutral first-party command contract, refuses a silent source substitution and
 * invalidates a source-bound preview when the source changes.
 *
 * The ticket needs a resolved pair, and the only UI path that sets the shared
 * memory-only target is a top-bar search selection, so the spec selects a
 * candidate first (a regression guard: without a target the Preview control is
 * disabled and W13 is never exercised). The right ticket defaults to Market.
 */

const OKX_PREVIEW_RESPONSE = {
  result: {
    quoteId: "q-e2e-1",
    intent: {
      id: "intent-e2e-1",
      chain: "base",
      tokenIn: "USDC",
      tokenOut: "SOL",
      side: "buy",
      amountType: "usd",
      amount: "100",
      orderType: "market",
      limitPrice: null,
      maxBuyTaxBps: null,
      maxSellTaxBps: null,
      maxPriceImpactBps: 150,
      maxSlippageBps: 100,
      maxTotalCostUsd: null,
      allowPartialFill: true,
      expiryMs: null,
    },
    route: [
      { index: 0, venue: "aerodrome", kind: "direct", tokenIn: "USDC", tokenOut: "SOL", sharePct: 100 },
    ],
    economics: {
      grossOutput: 98.5,
      netOutput: 96.2,
      taxBps: 50,
      dexFeeBps: 30,
      gasUsd: 0.42,
      priceImpactBps: 12,
      expectedSlippageBps: 20,
      mevRiskBps: 5,
      failureProbability: 0.01,
      minReceived: "95.0",
    },
    slot: 1,
    sourceAgeMs: 0,
    expiresAtMs: null,
    revalidationRequired: false,
    routerPreference: "okx",
    routerSource: { id: "okx", detail: null },
  },
};

/**
 * One body serves both `search_token` and `get_token` so selecting the result
 * renders the detail surface without needing per-operation mock routing.
 */
const DISCOVER_RESPONSE = {
  result: {
    results: [
      {
        chain: "base",
        address: "0x00000000000000000000000000000000000000a1",
        symbol: "SOL",
        name: "Wrapped SOL",
      },
    ],
    token: {
      chain: "base",
      address: "0x00000000000000000000000000000000000000a1",
      symbol: "SOL",
      name: "Wrapped SOL",
      decimals: 9,
    },
    stats: {
      priceUsd: 150,
      priceChange24h: 1.5,
      marketCapUsd: 1_000_000,
      liquidityUsd: 250_000,
      volume24hUsd: 50_000,
      holders: 1_200,
    },
    risk: {
      score: 12,
      factors: [],
      buyTaxBps: 0,
      sellTaxBps: 0,
      transferFeeBps: 0,
      sellRestricted: false,
      simulated: true,
    },
    evidence: [],
    slot: 1,
    sourceAgeMs: 0,
  },
};

test.describe("routing source selector (W13)", () => {
  test("defaults to OKX, sends the preference to the neutral contract, and refuses a silent fallback", async ({
    page,
    request,
  }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await setCommandResponse(request, DISCOVER_RESPONSE);

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    // Resolve the ticket target through the real top-bar search before opening
    // the ticket. Results render as `role=option` rows in the popover.
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");

    // Install the W13 preview response only once the target is resolved.
    await setCommandResponse(request, OKX_PREVIEW_RESPONSE);

    // The right ticket defaults to the Market tab; no navigation is required.
    await expect(page.getByTestId("ticket-tab-market")).toHaveAttribute("aria-selected", "true");
    // Route choice and risk caps are behind the collapsed Advanced section; the
    // bound route stays visible, and expanding Advanced reveals the real control.
    await expect(page.getByTestId("ticket-advanced")).not.toHaveAttribute("open", "");
    await page.getByTestId("ticket-advanced").locator("summary").click();
    await expect(page.getByTestId("ticket-advanced")).toHaveAttribute("open", "");
    await expect(page.getByRole("button", { name: "OKX" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    await page.getByLabel("Amount", { exact: true }).fill("100");
    await page.getByRole("button", { name: "Review order" }).click();
    await expect(page.getByText(/route source OKX/)).toBeVisible();

    // The preference travelled only to the neutral first-party contract; the
    // browser never contacted a provider directly.
    const state = await serverState(request);
    const preview = state.commands.find((command) => command.op === "preview_market_order");
    expect(preview?.payload).toMatchObject({ router_preference: "okx" });

    // Switching source invalidates the source-bound preview immediately.
    await page.getByRole("button", { name: "Local Router" }).click();
    await expect(page.getByText("No preview yet")).toBeVisible();

    // The mock always answers with an OKX source; a Local request must refuse it
    // rather than accept a silent substitution.
    await page.getByRole("button", { name: "Review order" }).click();
    await expect(page.getByText(/silent fallback/i)).toBeVisible();

    const after = await serverState(request);
    const previews = after.commands.filter((command) => command.op === "preview_market_order");
    expect(previews.at(-1)?.payload).toMatchObject({ router_preference: "local" });
  });
});
