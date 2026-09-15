import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { randomBytes } from "node:crypto";

export const KID = "kid-e2e";

export function randomKeyB64(): string {
  return randomBytes(32).toString("base64");
}

export async function resetServer(request: APIRequestContext): Promise<void> {
  await request.post("/__test__/reset");
}

export async function configureSession(
  request: APIRequestContext,
  s2cKeyB64: string,
  c2sKeyB64?: string,
): Promise<void> {
  await request.post("/__test__/session", {
    data: { kid: KID, s2cKeyB64, c2sKeyB64: c2sKeyB64 ?? null },
  });
}

export async function setCommandResponse(
  request: APIRequestContext,
  response: unknown,
): Promise<void> {
  await request.post("/__test__/command-response", { data: { response } });
}

export async function sendFrames(
  request: APIRequestContext,
  body: Record<string, unknown>,
): Promise<void> {
  const result = await request.post("/__test__/send", { data: body });
  expect(result.ok()).toBeTruthy();
}

export async function serverState(request: APIRequestContext): Promise<{
  resyncCount: number;
  socketCount: number;
  activeSockets: number;
  commands: { op: string; payload: unknown; sequence: number }[];
  events: unknown[];
}> {
  const response = await request.get("/__test__/state");
  return response.json();
}

/** Post the BR-5 host session-key handoff into the payload document. */
export async function handoffKey(page: Page, s2cKeyB64: string, c2sKeyB64?: string): Promise<void> {
  await page.evaluate(
    (payload) => {
      window.postMessage(payload, "*");
    },
    {
      type: "evergreen:session-key",
      kid: KID,
      s2cKeyB64,
      ...(c2sKeyB64 ? { c2sKeyB64 } : {}),
    },
  );
}

export async function waitForSocket(request: APIRequestContext): Promise<void> {
  await expect
    .poll(async () => (await serverState(request)).activeSockets, { timeout: 7_000 })
    .toBeGreaterThan(0);
}

export async function waitForResync(request: APIRequestContext): Promise<void> {
  await expect
    .poll(async () => (await serverState(request)).resyncCount, { timeout: 7_000 })
    .toBeGreaterThan(0);
}

export async function waitForResyncIncrease(
  request: APIRequestContext,
  before: number,
): Promise<void> {
  await expect
    .poll(async () => (await serverState(request)).resyncCount, { timeout: 7_000 })
    .toBeGreaterThan(before);
}

export function candle(timeMs: number, close: number, volume = 10) {
  return {
    time_ms: timeMs,
    open: close - 1,
    high: close + 1,
    low: close - 2,
    close,
    volume,
  };
}

export function ohlcvSnapshot(close = 100, bars = 40) {
  const start = 1_700_000_000_000;
  return {
    op: "snapshot",
    channel: "ohlcv",
    priority: 1,
    entity_key: "ohlcv:default",
    slot: 1,
    source_age_ms: 0,
    payload: {
      timeframe: "1m",
      candles: Array.from({ length: bars }, (_, index) =>
        candle(start + index * 60_000, close + index),
      ),
    },
  };
}

export function depthSnapshot(bestBid = 100, bestAsk = 101) {
  return {
    op: "snapshot",
    channel: "depth",
    priority: 1,
    entity_key: "depth:default",
    slot: 1,
    source_age_ms: 0,
    payload: {
      bids: [
        { price: bestBid, size: 5 },
        { price: bestBid - 1, size: 3 },
      ],
      asks: [
        { price: bestAsk, size: 4 },
        { price: bestAsk + 1, size: 2 },
      ],
      slot: 1,
    },
  };
}

export function ohlcvDelta(close: number) {
  return {
    op: "delta",
    channel: "ohlcv",
    priority: 1,
    entity_key: "ohlcv:default",
    slot: 2,
    source_age_ms: 0,
    payload: { timeframe: "1m", candle: candle(1_700_000_000_000 + 40 * 60_000, close) },
  };
}

/** Wait until the payload has completed bootstrap and rendered the shell. */
export async function waitForWorkspace(page: Page): Promise<void> {
  await expect(page.locator(".workspace")).toBeVisible();
}
