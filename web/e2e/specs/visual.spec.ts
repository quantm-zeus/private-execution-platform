import { expect, test, type APIRequestContext, type Page, type TestInfo } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvDelta,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  sendFrames,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Workstation visual contract.
 *
 * This is deliberately NOT a pixel/baseline comparison. It pins the layout
 * invariants of the 100vw x 100dvh multi-pane shell (no outer scrollbar, every
 * primary pane in-grid and within the viewport, the market rail collapsed at
 * <=1180px) across the required operator viewports, and captures screenshot
 * attachments for the primary workstation states so a human/CI artifact shows
 * what each state looked like. The attachments are diagnostics, not assertions.
 */

const VIEWPORTS = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
  { width: 1024, height: 720 },
] as const;

/** The single market rail is auto-collapsed at or below this width. */
const RAIL_COLLAPSE_MAX_WIDTH = 1180;

const TOKEN_ADDRESS = "0x00000000000000000000000000000000000000a1";

const TARGET_RESPONSE = {
  result: {
    results: [
      { chain: "base", address: TOKEN_ADDRESS, symbol: "SOL", name: "Wrapped SOL" },
    ],
    token: {
      chain: "base",
      address: TOKEN_ADDRESS,
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

const PREVIEW_RESPONSE = {
  result: {
    quoteId: "q-visual-1",
    intent: {
      id: "intent-visual-1",
      chain: "base",
      tokenIn: "USDC",
      tokenOut: TOKEN_ADDRESS,
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
      {
        index: 0,
        venue: "aerodrome",
        kind: "direct",
        tokenIn: "USDC",
        tokenOut: "SOL",
        sharePct: 100,
      },
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
    routerSource: "okx",
  },
};

const ORDERS_RESPONSE = {
  result: {
    orders: [
      {
        orderId: "order-visual-1",
        state: "ACTIVE",
        filledAmount: "0",
        remainingAmount: "100",
        fills: [],
        createdAtMs: 1_700_000_000_000,
        updatedAtMs: 1_700_000_000_000,
        nextActionMs: null,
        failureReason: null,
        intent: {
          id: "intent-order-1",
          chain: "base",
          tokenIn: "USDC",
          tokenOut: TOKEN_ADDRESS,
          side: "buy",
          amountType: "usd",
          amount: "100",
          orderType: "limit",
          limitPrice: "145",
          maxBuyTaxBps: null,
          maxSellTaxBps: null,
          maxPriceImpactBps: 150,
          maxSlippageBps: 100,
          maxTotalCostUsd: null,
          allowPartialFill: true,
          expiryMs: null,
        },
      },
    ],
  },
};

async function bootLive(page: Page, request: APIRequestContext): Promise<void> {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
}

async function attach(page: Page, testInfo: TestInfo, name: string): Promise<void> {
  await testInfo.attach(name, {
    body: await page.screenshot(),
    contentType: "image/png",
  });
}

/**
 * No outer scrollbar and every primary pane laid out inside the viewport. The
 * three panes are measured in viewport coordinates; the +/-1px tolerance
 * absorbs sub-pixel rounding.
 */
async function assertWorkstationFits(
  page: Page,
  viewport: { width: number; height: number },
): Promise<void> {
  const metrics = await page.evaluate(() => {
    const root = document.querySelector(".terminal.workspace");
    if (!(root instanceof HTMLElement)) throw new Error("terminal root is missing");
    return {
      documentOverflowX:
        document.documentElement.scrollWidth - document.documentElement.clientWidth,
      bodyOverflowX: document.body.scrollWidth - document.body.clientWidth,
      rootOverflowY: root.scrollHeight - root.clientHeight,
    };
  });
  expect(metrics.documentOverflowX, "document horizontal overflow").toBeLessThanOrEqual(1);
  expect(metrics.bodyOverflowX, "body horizontal overflow").toBeLessThanOrEqual(1);
  expect(metrics.rootOverflowY, "terminal root vertical overflow").toBeLessThanOrEqual(1);

  const panes: readonly (readonly [string, string])[] = [
    [".chart-pane", "chart pane"],
    ['[data-testid="bottom-dock"]', "bottom dock"],
    ['[data-testid="trade-ticket"]', "trade ticket"],
  ];
  for (const [selector, label] of panes) {
    const box = await page.locator(selector).boundingBox();
    expect(box, `${label} has a bounding box`).not.toBeNull();
    expect(box!.width, `${label} width`).toBeGreaterThan(0);
    expect(box!.height, `${label} height`).toBeGreaterThan(0);
    expect(box!.x, `${label} left edge`).toBeGreaterThanOrEqual(-1);
    expect(box!.y, `${label} top edge`).toBeGreaterThanOrEqual(-1);
    expect(box!.x + box!.width, `${label} right edge`).toBeLessThanOrEqual(viewport.width + 1);
    expect(box!.y + box!.height, `${label} bottom edge`).toBeLessThanOrEqual(viewport.height + 1);
  }
}

test.describe("workstation layout across operator viewports", () => {
  for (const viewport of VIEWPORTS) {
    test(`no outer scroll and panes in-grid at ${viewport.width}x${viewport.height}`, async ({
      page,
      request,
    }, testInfo) => {
      await bootLive(page, request);
      await page.setViewportSize(viewport);

      // ---- no token selected -------------------------------------------------
      await expect(page.getByTestId("selected-instrument")).toHaveText("No token selected");
      await assertWorkstationFits(page, viewport);

      const root = page.locator(".terminal.workspace");
      const rail = page.locator("aside.rail");
      if (viewport.width <= RAIL_COLLAPSE_MAX_WIDTH) {
        // The rail folds first; the ticket stays in-grid because the ticket
        // breakpoint is narrower (<=980px).
        await expect(root).toHaveAttribute("data-rail", "collapsed");
        await expect(rail).toBeHidden();
        expect(await rail.boundingBox()).toBeNull();
        await expect(page.getByTestId("trade-ticket")).toBeVisible();
      } else {
        await expect(root).toHaveAttribute("data-rail", "expanded");
        expect(await rail.boundingBox()).not.toBeNull();
      }
      await attach(page, testInfo, `no-token-${viewport.width}x${viewport.height}`);

      // ---- selected token, live market --------------------------------------
      await setCommandResponse(request, TARGET_RESPONSE);
      await searchAndSelectToken(page, "SOL", "SOL");
      await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
      await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
      await expect(page.getByTestId("connection-phase")).toHaveText("LIVE");
      await assertWorkstationFits(page, viewport);
      await attach(page, testInfo, `selected-live-market-${viewport.width}x${viewport.height}`);
    });
  }
});

test.describe("workstation state gallery (attachments only)", () => {
  test("captures the primary workstation states at 1440x900", async ({ page, request }, testInfo) => {
    await bootLive(page, request);
    await page.setViewportSize({ width: 1440, height: 900 });

    // No token selected.
    await attach(page, testInfo, "no-token-selected");

    // Selected token, live market.
    await setCommandResponse(request, TARGET_RESPONSE);
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await expect(page.getByTestId("connection-phase")).toHaveText("LIVE");
    await attach(page, testInfo, "selected-token-live-market");

    // Market quote.
    await setCommandResponse(request, PREVIEW_RESPONSE);
    await page.getByLabel("Amount", { exact: true }).fill("100");
    await page.getByRole("button", { name: "Preview" }).click();
    await expect(page.getByText(/route source OKX/)).toBeVisible();
    await attach(page, testInfo, "market-quote");

    // Limit form.
    await page.getByTestId("ticket-tab-limit").click();
    await expect(page.getByLabel("Limit net price")).toBeVisible();
    await attach(page, testInfo, "limit-form");
    await page.getByTestId("ticket-tab-market").click();

    // Open orders in the bottom dock.
    await setCommandResponse(request, ORDERS_RESPONSE);
    await page.getByTestId("dock-tab-orders").click();
    await page.locator(".orders").getByRole("button", { name: "Refresh" }).click();
    await expect(page.locator(".order-card").first()).toBeVisible();
    await attach(page, testInfo, "open-orders");

    // Degraded market: a sequence gap flips the live stream to DEGRADED until a
    // fresh authenticated snapshot arrives (none is sent here, so it holds).
    await sendFrames(request, { skip: 3, frames: [ohlcvDelta(500)] });
    await expect(page.getByTestId("connection-phase")).toHaveText("DEGRADED");
    await attach(page, testInfo, "degraded-market");

    // Security drawer.
    await page.getByRole("button", { name: "Security and settings" }).click();
    await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
    await attach(page, testInfo, "security-drawer");
  });
});
