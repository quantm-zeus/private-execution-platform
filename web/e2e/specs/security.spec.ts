import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  searchTokens,
  sendFrames,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/** A search + detail body so the shared ticket target can be resolved. */
const TARGET_RESPONSE = {
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

async function bootLive(
  page: import("@playwright/test").Page,
  request: import("@playwright/test").APIRequestContext,
) {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
  return { s2c, c2s };
}

test.describe("private-state hygiene", () => {
  test("persists no private plaintext before or after a live session", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100)] });
    await expect(page.getByTestId("connection-phase")).toHaveText("LIVE");

    const audit = await page.evaluate(async () => {
      const databases =
        typeof indexedDB.databases === "function" ? (await indexedDB.databases()).length : 0;
      return {
        local: window.localStorage.length,
        session: window.sessionStorage.length,
        cookie: document.cookie,
        databases,
      };
    });
    expect(audit).toEqual({ local: 0, session: 0, cookie: "", databases: 0 });
  });

  test("renders hostile token metadata as inert text (no DOM XSS)", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    const payload = '<img src=x onerror="window.__xss=1">';
    await setCommandResponse(request, {
      result: {
        results: [
          { chain: "base", address: "0xBONKtokenAddress000000000000000000000000", symbol: payload },
        ],
      },
    });

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    // Search results now render in the top-bar popover, not a Discover view.
    // The same token also appears in the rail's search-results section, so the
    // hostile-metadata assertion is scoped to the popover to stay unambiguous.
    await searchTokens(page, "bonk");

    await expect(page.locator(".search-popover").getByText(payload)).toBeVisible();
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss ?? null)).toBeNull();
    // The string must be escaped, not parsed into an element.
    expect(await page.locator('img[src="x"]').count()).toBe(0);
  });

  test("does not leak trading semantics into the URL, title or history", async ({ page, request }) => {
    await bootLive(page, request);
    await setCommandResponse(request, TARGET_RESPONSE);
    await sendFrames(request, { frames: [ohlcvSnapshot(100)] });

    // The ticket defaults to Market and only renders once a target is resolved.
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByLabel("Amount", { exact: true })).toBeVisible();

    const before = page.url();
    const historyBefore = await page.evaluate(() => history.length);
    await page.getByLabel("Amount", { exact: true }).fill("1234.56");
    await page.getByRole("button", { name: "Buy", exact: true }).click();

    expect(page.url()).toBe(before);
    expect(await page.title()).not.toMatch(/\d/);
    // No navigation/state may be encoded in history: the length must not change.
    expect(await page.evaluate(() => history.length)).toBe(historyBefore);
  });
});
