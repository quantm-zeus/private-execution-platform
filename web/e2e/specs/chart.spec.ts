import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  sendFrames,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Real-browser smoke for the KLineChart Pro renderer and its local datafeed.
 *
 * Deliberately no canvas pixel snapshots: the assertions are the renderer
 * lifecycle (mount + resize + period switch), the vendor period bar, a live
 * canvas with real dimensions, and the absence of chart-related page errors.
 */

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

/** Only chart/Pro runtime errors fail this smoke; unrelated harness noise is ignored. */
function chartErrors(errors: string[]): string[] {
  return errors.filter((error) => /klinechart|pro-chart|ChartPanel|chart renderer|ResizeObserver/i.test(error));
}

test.describe("private chart (KLineChart Pro)", () => {
  test("mounts the renderer, survives a period switch and container resizes", async ({ page, request }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(String(error)));

    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await page.locator('button[data-view="terminal"]').click();

    const host = page.locator(".pep-pro-chart-host");
    await expect(host).toBeVisible();
    const canvas = host.locator("canvas").first();
    await expect(canvas).toBeVisible();
    const box = await canvas.boundingBox();
    expect(box?.width ?? 0).toBeGreaterThan(100);
    expect(box?.height ?? 0).toBeGreaterThan(100);

    // The first-party timeframe control is the keyboard/AT path; Pro 0.1.1's
    // own period items are non-focusable spans and its bar is hidden.
    const timeframe = page.locator("#chart-timeframe");
    await expect(timeframe).toBeVisible();
    await expect(timeframe.locator("option")).toHaveCount(6);
    await timeframe.selectOption("5m");
    await expect(timeframe).toHaveValue("5m");
    await expect(canvas).toBeVisible();
    await expect(page.locator(".pep-pro-chart .klinecharts-pro-period-bar")).toBeHidden();

    // A layout-only resize must not detach or break the chart (the adapter
    // drives Pro's captured resize handler from a ResizeObserver).
    await page.setViewportSize({ width: 1024, height: 720 });
    await expect(canvas).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(canvas).toBeVisible();

    expect(chartErrors(errors)).toEqual([]);
  });

  test("ignores a malformed OHLCV frame without crashing the renderer", async ({ page, request }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(String(error)));

    await bootLive(page, request);
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.locator(".pep-pro-chart-host canvas").first()).toBeVisible();

    await sendFrames(request, {
      frames: [
        {
          op: "delta",
          channel: "ohlcv",
          priority: 1,
          entity_key: "ohlcv:default",
          slot: 3,
          source_age_ms: 0,
          payload: {
            timeframe: "1m",
            candle: { time_ms: 1, open: 1, high: 0, low: 1, close: 1, volume: 1 },
          },
        },
      ],
    });
    await page.waitForTimeout(250);
    await expect(page.locator(".pep-pro-chart-host canvas").first()).toBeVisible();
    expect(chartErrors(errors)).toEqual([]);
  });
});
