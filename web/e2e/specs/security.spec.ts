import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  sendFrames,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

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
    await expect(page.getByText("LIVE", { exact: true })).toBeVisible();

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
    await request.post("/__test__/command-response", {
      data: {
        response: {
          result: {
            results: [
              { chain: "base", address: "0xBONKtokenAddress000000000000000000000000", symbol: payload },
            ],
          },
        },
      },
    });

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);
    await page.locator('button[data-view="discover"]').click();
    await page.getByLabel("Search token").fill("bonk");
    await page.getByRole("button", { name: "Search" }).click();

    await expect(page.getByText(payload)).toBeVisible();
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss ?? null)).toBeNull();
    // The string must be escaped, not parsed into an element.
    expect(await page.locator('img[src="x"]').count()).toBe(0);
  });

  test("does not leak trading semantics into the URL, title or history", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100)] });
    await page.locator('button[data-view="trade"]').click();
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
