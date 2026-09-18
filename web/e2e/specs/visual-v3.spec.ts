import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvDelta,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  selectedEntityKey,
  sendFrames,
  serverState,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * V3 visual evidence + design gate.
 *
 * Captures the operator review screenshots to
 * `.dsh/terminal-v2/visual-evidence-v3/` at the three required desktop
 * viewports and fails closed if the workstation is cramped, empty or a debug
 * console: outer overflow, a sub-220px chart, fewer than two selected-token
 * candles, or an address used as the primary row value.
 */

const EVIDENCE_DIR = fileURLToPath(
  new URL("../../../.dsh/terminal-v2/visual-evidence-v3/", import.meta.url),
);

const VIEWPORTS = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
] as const;

const TOKEN_ADDRESS = "0x00000000000000000000000000000000000000a1";
const ENTITY_KEY = selectedEntityKey("base", TOKEN_ADDRESS);

const TARGET_RESPONSE = {
  result: {
    results: [
      {
        chain: "base",
        address: TOKEN_ADDRESS,
        symbol: "SOL",
        name: "Wrapped SOL",
        priceUsd: 150.25,
        marketCapUsd: 68_000_000,
        rank: 4,
      },
    ],
    token: { chain: "base", address: TOKEN_ADDRESS, symbol: "SOL", name: "Wrapped SOL" },
    stats: {
      priceUsd: 150.25,
      priceChange24h: 1.5,
      marketCapUsd: 68_000_000,
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
    quoteId: "q-v3-1",
    intent: {
      id: "intent-v3-1",
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
    routerSource: "okx",
  },
};

const ORDERS_RESPONSE = {
  result: {
    orders: [
      {
        orderId: "order-v3-1",
        state: "ACTIVE",
        filledAmount: "0",
        remainingAmount: "100",
        fills: [],
        createdAtMs: 1_700_000_000_000,
        updatedAtMs: 1_700_000_000_000,
        nextActionMs: null,
        failureReason: null,
        intent: {
          id: "intent-order-v3",
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

async function capture(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  await page.screenshot({ path: `${EVIDENCE_DIR}${name}.png`, fullPage: false });
}

async function assertNoOverflow(page: Page): Promise<void> {
  const metrics = await page.evaluate(() => {
    const root = document.querySelector(".terminal.workspace");
    if (!(root instanceof HTMLElement)) throw new Error("terminal root missing");
    return {
      docX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      bodyX: document.body.scrollWidth - document.body.clientWidth,
      rootY: root.scrollHeight - root.clientHeight,
    };
  });
  expect(metrics.docX, "document horizontal overflow").toBeLessThanOrEqual(1);
  expect(metrics.bodyX, "body horizontal overflow").toBeLessThanOrEqual(1);
  expect(metrics.rootY, "terminal vertical overflow").toBeLessThanOrEqual(1);
}

/**
 * Candle-coloured ink actually painted on the KLineChart Pro canvases. A buffer
 * count (`data-candles`) is not proof that the renderer drew a series, so the
 * gate reads the canvas pixels directly: a multi-candle chart has candle-coloured
 * pixels spread across many distinct columns.
 */
async function chartCandleInk(page: Page): Promise<{ colored: number; columns: number }> {
  return page.evaluate(() => {
    const canvases = Array.from(
      document.querySelectorAll<HTMLCanvasElement>(".pep-pro-chart canvas"),
    );
    let colored = 0;
    const columns = new Set<number>();
    for (const canvas of canvases) {
      const ctx = canvas.getContext("2d");
      if (!ctx || canvas.width === 0 || canvas.height === 0) continue;
      let data: Uint8ClampedArray;
      try {
        data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
      } catch {
        continue;
      }
      for (let y = 0; y < canvas.height; y += 2) {
        for (let x = 0; x < canvas.width; x += 2) {
          const o = (y * canvas.width + x) * 4;
          const r = data[o]!;
          const g = data[o + 1]!;
          const b = data[o + 2]!;
          const a = data[o + 3]!;
          if (a < 16) continue;
          const mx = Math.max(r, g, b);
          const mn = Math.min(r, g, b);
          if (mx - mn > 40 && mx > 70) {
            colored += 1;
            columns.add(Math.round(x / 8));
          }
        }
      }
    }
    return { colored, columns: columns.size };
  });
}

async function selectAndStream(page: Page, request: APIRequestContext): Promise<void> {
  await setCommandResponse(request, TARGET_RESPONSE);
  await searchAndSelectToken(page, "SOL", "SOL");
  await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
  await sendFrames(request, {
    frames: [ohlcvSnapshot(100, 40, { entityKey: ENTITY_KEY }), depthSnapshot(100, 101)],
  });
  await expect(page.getByTestId("chart-target")).toContainText("LOCAL DATA");
  const candles = Number(await page.getByTestId("chart-target").getAttribute("data-candles"));
  expect(candles, "selected-token candles").toBeGreaterThan(1);
  // Renderer-level proof: the Pro canvas actually painted a multi-candle series.
  await expect
    .poll(async () => (await chartCandleInk(page)).columns, { timeout: 7_000 })
    .toBeGreaterThan(4);
  expect((await chartCandleInk(page)).colored).toBeGreaterThan(200);
}

test.describe("V3 workstation design gate + evidence", () => {
  for (const viewport of VIEWPORTS) {
    test(`design gate at ${viewport.width}x${viewport.height}`, async ({ page, request }, testInfo) => {
      await bootLive(page, request);
      await page.setViewportSize(viewport);

      await capture(page, `no-token-${viewport.width}x${viewport.height}`);
      await assertNoOverflow(page);

      // Pane geometry: rail ~240-280px, ticket ~320-360px, chart dominant.
      const railBox = await page.locator("aside.rail").boundingBox();
      const ticketBox = await page.locator("aside.ticket-pane").boundingBox();
      const chartPaneBox = await page.locator(".chart-pane").boundingBox();
      expect(railBox, "rail").not.toBeNull();
      expect(ticketBox, "ticket").not.toBeNull();
      expect(chartPaneBox, "chart pane").not.toBeNull();
      expect(railBox!.width, "rail width").toBeGreaterThanOrEqual(240);
      expect(railBox!.width, "rail width").toBeLessThanOrEqual(280);
      expect(ticketBox!.width, "ticket width").toBeGreaterThanOrEqual(320);
      expect(ticketBox!.width, "ticket width").toBeLessThanOrEqual(360);
      expect(chartPaneBox!.width, "chart widest pane").toBeGreaterThan(railBox!.width);
      expect(chartPaneBox!.width, "chart widest pane").toBeGreaterThan(ticketBox!.width);

      await selectAndStream(page, request);
      await assertNoOverflow(page);

      // The chart is dominant: at least 220px of render surface at every desktop
      // viewport, and clearly taller than the bounded bottom dock.
      const chartBox = await page.locator(".chart-frame").boundingBox();
      const dockBox = await page.locator('[data-testid="bottom-dock"]').boundingBox();
      expect(chartBox, "chart frame").not.toBeNull();
      expect(chartBox!.height, "chart frame height").toBeGreaterThanOrEqual(220);
      expect(dockBox, "dock").not.toBeNull();
      expect(chartBox!.height, "chart taller than dock").toBeGreaterThan(dockBox!.height);

      // Volume pane + professional drawing toolbar: the Pro root must stay
      // inside the frame (its 80vh default once clipped the volume pane) and
      // both the price and volume panes must be painted.
      await expect(page.locator(".klinecharts-pro-drawing-bar")).toBeVisible();
      await expect(page.getByTestId("draw-tool-ruler")).toBeVisible();
      // Pro adds its own `.klinecharts-pro` class to the container we create, so
      // the root is the `.pep-pro-chart` element itself.
      const proBox = await page.locator(".pep-pro-chart").boundingBox();
      expect(proBox, "pro chart root").not.toBeNull();
      expect(proBox!.height, "pro chart within frame").toBeLessThanOrEqual(chartBox!.height + 2);
      const canvasCount = await page.locator(".pep-pro-chart canvas").count();
      expect(canvasCount, "price + volume panes").toBeGreaterThanOrEqual(2);

      // Spacing tokens: the ticket/panel content must breathe (10-16px) rather
      // than hug the pane edges, and the top bar must not be compressed.
      const ticketPad = await page
        .locator(".trade-ticket__body .panel__body")
        .first()
        .evaluate((element) => parseFloat(getComputedStyle(element).paddingLeft));
      expect(ticketPad, "ticket content padding").toBeGreaterThanOrEqual(10);
      expect(ticketPad, "ticket content padding").toBeLessThanOrEqual(16);
      const topbarBox2 = await page.getByTestId("terminal-topbar").boundingBox();
      expect(topbarBox2, "topbar").not.toBeNull();
      expect(topbarBox2!.height, "topbar height").toBeGreaterThanOrEqual(48);

      // The first-party ruler activates against the real KLineChart instance and
      // Escape cancels it without disturbing the chart.
      const ruler = page.getByTestId("draw-tool-ruler");
      await ruler.click();
      await expect(ruler).toHaveAttribute("aria-pressed", "true");
      await page.keyboard.press("Escape");
      await expect(ruler).toHaveAttribute("aria-pressed", "false");

      // The market rail row shows a price, never the address as its value.
      const firstRow = page.locator(".market-rail .market-item").first();
      await expect(firstRow.locator('[data-testid="market-row-price"]')).toBeVisible();

      await capture(page, `selected-live-${viewport.width}x${viewport.height}`);

      // Exactly one deduplicated realtime target for the selected token.
      const commands = (await serverState(request)).commands.filter(
        (command) => command.op === "set_realtime_target",
      );
      expect(commands.length, "set_realtime_target count").toBe(1);
      expect(commands[0]!.payload).toMatchObject({
        chain: "base",
        address: TOKEN_ADDRESS,
        timeframe: "1m",
      });

      // Changing the timeframe issues exactly one more target and no duplicate.
      await page.getByLabel("Chart timeframe").selectOption("15m");
      await expect
        .poll(
          async () =>
            (await serverState(request)).commands.filter(
              (command) => command.op === "set_realtime_target",
            ).length,
          { timeout: 7_000 },
        )
        .toBe(2);
      await page.getByLabel("Chart timeframe").selectOption("15m");
      await page.waitForTimeout(200);
      const after = (await serverState(request)).commands.filter(
        (command) => command.op === "set_realtime_target",
      );
      expect(after.length, "no duplicate target for the same timeframe").toBe(2);
      expect(after.at(-1)?.payload).toMatchObject({ timeframe: "15m" });

      testInfo.attach(`selected-live-${viewport.width}x${viewport.height}`, {
        body: await page.screenshot(),
        contentType: "image/png",
      });
    });
  }

  test("state gallery at 1440x900", async ({ page, request }) => {
    await bootLive(page, request);
    await page.setViewportSize({ width: 1440, height: 900 });

    await capture(page, "gallery-no-token");
    await selectAndStream(page, request);
    await capture(page, "gallery-selected-live");

    await setCommandResponse(request, PREVIEW_RESPONSE);
    await page.getByLabel("Amount", { exact: true }).fill("100");
    await page.getByRole("button", { name: "Review order" }).click();
    await expect(page.getByText(/route source OKX/)).toBeVisible();
    await capture(page, "gallery-market-quote");

    await page.getByTestId("ticket-tab-limit").click();
    await expect(page.getByLabel("Limit net price")).toBeVisible();
    await capture(page, "gallery-limit-form");
    await page.getByTestId("ticket-tab-market").click();

    await setCommandResponse(request, ORDERS_RESPONSE);
    await page.getByTestId("dock-tab-orders").click();
    await page.locator(".orders").getByRole("button", { name: "Refresh" }).click();
    await expect(page.locator(".order-card").first()).toBeVisible();
    await capture(page, "gallery-open-orders");

    await sendFrames(request, { skip: 3, frames: [ohlcvDelta(500, { entityKey: ENTITY_KEY })] });
    await expect(page.getByTestId("connection-phase")).toHaveText("DEGRADED");
    await capture(page, "gallery-degraded-market");

    await page.getByRole("button", { name: "Security and settings" }).click();
    await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
    await capture(page, "gallery-security-drawer");
  });
});
