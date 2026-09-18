import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Deep Vault contract audit.
 *
 * The reference model cannot eyeball the screenshots, so this spec asserts the
 * design contract programmatically at every required desktop tier: the amber
 * budget, the neutral selection family, pane geometry, the five-tab dock, the
 * status bar, the stat-strip fold and the absence of any outer overflow.
 */

const VIEWPORTS = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
] as const;

const TOKEN_ADDRESS = "0x00000000000000000000000000000000000000a1";

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
    risk: { score: 12, factors: [], simulated: true },
    evidence: [],
    slot: 1,
    sourceAgeMs: 0,
  },
};

const AMBER = "rgb(233, 180, 76)";
const TEXT_1 = "rgb(232, 238, 242)";
const TEXT_2 = "rgb(159, 176, 189)";
const SURFACE_3 = "rgb(24, 34, 45)";

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

test.describe("Deep Vault contract audit", () => {
  for (const viewport of VIEWPORTS) {
    test(`contract at ${viewport.width}x${viewport.height}`, async ({ page, request }) => {
      await bootLive(page, request);
      await page.setViewportSize(viewport);
      await setCommandResponse(request, TARGET_RESPONSE);
      await searchAndSelectToken(page, "SOL", "SOL");
      await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
      // Let hover/selection transitions settle before reading computed styles.
      await page.waitForTimeout(350);

      const report = await page.evaluate(() => {
        const accent = (element: Element): boolean =>
          getComputedStyle(element).backgroundColor === "rgb(233, 180, 76)";
        const rect = (selector: string) => {
          const element = document.querySelector(selector);
          return element ? element.getBoundingClientRect() : null;
        };
        const selectedRow = document.querySelector('.market-item[aria-pressed="true"]');
        const selectedTicket = document.querySelector('.trade-ticket__tab[aria-selected="true"]');
        const selectedDock = document.querySelector('.dock__tab[aria-selected="true"]');
        const legend = document.querySelector(".chart-pane__legend");
        const liquidity = document.querySelector('[data-testid="token-stat-liquidity"]');
        return {
          amberCount: Array.from(document.querySelectorAll("*")).filter(accent).length,
          topbarHeight: rect(".topbar")?.height ?? 0,
          statusbarHeight: rect(".statusbar")?.height ?? 0,
          dockTabs: document.querySelectorAll("[data-testid^='dock-tab-']").length,
          tradesTabs: document.querySelectorAll('[data-testid="dock-tab-trades"]').length,
          railWidth: rect("aside.rail")?.width ?? 0,
          ticketWidth: rect("aside.ticket-pane")?.width ?? 0,
          chartWidth: rect(".chart-pane")?.width ?? 0,
          chartFrameHeight: rect(".chart-frame")?.height ?? 0,
          docOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          bodyOverflow: document.body.scrollWidth - document.body.clientWidth,
          selectedRowBg: selectedRow ? getComputedStyle(selectedRow).backgroundColor : null,
          selectedRowMarker: selectedRow ? getComputedStyle(selectedRow).borderLeftColor : null,
          selectedTicketUnderline: selectedTicket
            ? getComputedStyle(selectedTicket).borderBottomColor
            : null,
          selectedDockUnderline: selectedDock ? getComputedStyle(selectedDock).borderBottomColor : null,
          legendVisible: legend ? getComputedStyle(legend).display !== "none" : false,
          liquidityVisible: liquidity ? getComputedStyle(liquidity.closest("div")!).display !== "none" : false,
        };
      });

      // Amber appears exactly twice at rest: the brand mark and the price rule.
      expect(report.amberCount, "amber budget").toBe(2);
      // Pane geometry.
      expect(report.topbarHeight).toBe(56);
      expect(report.statusbarHeight).toBe(24);
      expect(report.railWidth).toBeGreaterThanOrEqual(240);
      expect(report.railWidth).toBeLessThanOrEqual(280);
      expect(report.ticketWidth).toBeGreaterThanOrEqual(320);
      expect(report.ticketWidth).toBeLessThanOrEqual(360);
      expect(report.chartWidth).toBeGreaterThan(report.railWidth);
      expect(report.chartFrameHeight).toBeGreaterThanOrEqual(220);
      // Exactly five dock tabs; the UI Trades tab is gone.
      expect(report.dockTabs).toBe(5);
      expect(report.tradesTabs).toBe(0);
      // No outer overflow.
      expect(report.docOverflow).toBeLessThanOrEqual(1);
      expect(report.bodyOverflow).toBeLessThanOrEqual(1);
      // Selection is neutral: never the accent.
      expect(report.selectedRowBg).toBe(SURFACE_3);
      expect(report.selectedRowMarker).toBe(TEXT_2);
      expect(report.selectedTicketUnderline).toBe(TEXT_1);
      expect(report.selectedDockUnderline).toBe(TEXT_1);
      // The stat strip folds whole stats, and the crosshair legend leaves first.
      expect(report.liquidityVisible).toBe(viewport.width >= 1440);
      expect(report.legendVisible).toBe(viewport.width >= 1360);
    });
  }

  test("expanding the dock at 1366x768 keeps the chart pane floor", async ({ page, request }) => {
    await bootLive(page, request);
    await page.setViewportSize({ width: 1366, height: 768 });
    await setCommandResponse(request, TARGET_RESPONSE);
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
    await page.waitForTimeout(350);

    await page.getByTestId("dock-expand").click();
    await expect(page.locator(".terminal.workspace")).toHaveAttribute("data-dock-size", "expanded");
    await page.waitForTimeout(120);

    const geometry = await page.evaluate(() => ({
      chart: document.querySelector(".chart-pane")?.getBoundingClientRect().height ?? 0,
      frame: document.querySelector(".chart-frame")?.getBoundingClientRect().height ?? 0,
      dock: document.querySelector('[data-testid="bottom-dock"]')?.getBoundingClientRect().height ?? 0,
      workarea: document.querySelector(".workarea")?.getBoundingClientRect().height ?? 0,
      banner: document.querySelector(".offline-banner")?.getBoundingClientRect().height ?? 0,
      separator: (() => {
        const element = document.querySelector('[role="separator"]');
        if (!element) return null;
        return {
          now: Number(element.getAttribute("aria-valuenow")),
          max: Number(element.getAttribute("aria-valuemax")),
          min: Number(element.getAttribute("aria-valuemin")),
        };
      })(),
    }));

    // The clamp on the grid track holds the chart pane at >= 392px and the dock
    // at its computed ceiling, whatever the operator does.
    expect(geometry.chart).toBeGreaterThanOrEqual(392);
    expect(geometry.frame).toBeGreaterThanOrEqual(220);
    expect(geometry.dock).toBeLessThanOrEqual(geometry.separator!.max + 1);
    expect(geometry.separator!.now).toBeLessThanOrEqual(geometry.separator!.max);
    expect(geometry.separator!.now).toBeGreaterThanOrEqual(geometry.separator!.min);
  });
});
