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

const TIMEFRAME_MS: Record<string, number> = {
  "1m": 60_000,
  "5m": 300_000,
  "15m": 900_000,
  "1h": 3_600_000,
  "4h": 14_400_000,
  "1d": 86_400_000,
};

export interface OhlcvSnapshotOptions {
  /** Exact sealed entity key, e.g. `ohlcv:base:0x…`. Defaults to `ohlcv:default`. */
  readonly entityKey?: string;
  readonly timeframe?: string;
  /** Explicit start time; defaults to a recent window ending at the test clock. */
  readonly startMs?: number;
}

/**
 * A production-faithful OHLCV snapshot. The bars end at/just before `Date.now()`
 * on the requested timeframe, so KLineChart Pro's *current* history window
 * actually contains them (a fixed 2023 epoch renders as a single right-edge bar
 * because Pro asks for the live window).
 */
export function ohlcvSnapshot(close = 100, bars = 40, options: OhlcvSnapshotOptions = {}) {
  const timeframe = options.timeframe ?? "1m";
  const stepMs = TIMEFRAME_MS[timeframe] ?? 60_000;
  const end = Math.floor(Date.now() / stepMs) * stepMs;
  const start = options.startMs ?? end - (bars - 1) * stepMs;
  return {
    op: "snapshot",
    channel: "ohlcv",
    priority: 1,
    entity_key: options.entityKey ?? "ohlcv:default",
    slot: 1,
    source_age_ms: 0,
    payload: {
      timeframe,
      candles: Array.from({ length: bars }, (_, index) =>
        candle(start + index * stepMs, close + index),
      ),
    },
  };
}

/** The exact entity key the chart uses for a selected instrument. */
export function selectedEntityKey(chain: string, address: string): string {
  return `ohlcv:${chain}:${address}`;
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

export function ohlcvDelta(
  close: number,
  options: { entityKey?: string; timeframe?: string } = {},
) {
  const timeframe = options.timeframe ?? "1m";
  const stepMs = TIMEFRAME_MS[timeframe] ?? 60_000;
  const timestamp = Math.floor(Date.now() / stepMs) * stepMs;
  return {
    op: "delta",
    channel: "ohlcv",
    priority: 1,
    entity_key: options.entityKey ?? "ohlcv:default",
    slot: 2,
    source_age_ms: 0,
    payload: { timeframe, candle: candle(timestamp, close) },
  };
}

export interface MarketTokenRow {
  readonly chain: string;
  readonly address: string;
  readonly symbol?: string;
  readonly name?: string;
  readonly priceUsd?: number;
  readonly priceChange24h?: number;
  readonly marketCapUsd?: number;
  readonly liquidityUsd?: number;
  readonly volume24hUsd?: number;
  readonly rank?: number;
}

/** A pushed normalized trending frame on the `market` channel. */
export function marketTrendingFrame(
  tokens: readonly MarketTokenRow[],
  options: { source?: string; category?: string } = {},
) {
  return {
    op: "delta",
    channel: "market",
    priority: 2,
    entity_key: "market:trending",
    slot: 1,
    source_age_ms: 0,
    payload: {
      kind: "trending",
      category: options.category ?? "trending",
      tokens,
      source: options.source ?? "fomo-ws",
      observedAtMs: Date.now(),
    },
  };
}

/** A pushed selected-token price tick for one exact entity. */
export function marketPriceFrame(
  chain: string,
  address: string,
  priceUsd: number,
  options: Partial<Omit<MarketTokenRow, "chain" | "address" | "priceUsd">> & {
    source?: string;
  } = {},
) {
  const payload: Record<string, unknown> = {
    kind: "price",
    chain,
    address,
    priceUsd,
    source: options.source ?? "fomo-ws",
    observedAtMs: Date.now(),
  };
  if (options.priceChange24h !== undefined) payload.priceChange24h = options.priceChange24h;
  if (options.marketCapUsd !== undefined) payload.marketCapUsd = options.marketCapUsd;
  if (options.liquidityUsd !== undefined) payload.liquidityUsd = options.liquidityUsd;
  if (options.volume24hUsd !== undefined) payload.volume24hUsd = options.volume24hUsd;
  return {
    op: "delta",
    channel: "market",
    priority: 2,
    entity_key: `market:price:${chain}:${address}`,
    slot: 1,
    source_age_ms: 0,
    payload,
  };
}

/** A pushed realtime provenance status frame. */
export function marketStatusFrame(realtimeSource: "fomo-ws" | "fomo-polling" | "unavailable") {
  return {
    op: "snapshot",
    channel: "market",
    priority: 2,
    entity_key: "market:status",
    slot: null,
    source_age_ms: 0,
    payload: { kind: "status", realtimeSource },
  };
}

/** Wait until the payload has completed bootstrap and rendered the shell. */
export async function waitForWorkspace(page: Page): Promise<void> {
  await expect(page.locator(".workspace")).toBeVisible();
}

/**
 * Type a query into the top-bar global token search. The input is debounced
 * (300ms) before the encrypted `search_token` command is dispatched, so callers
 * should await the rendered `.search-popover` result rather than a submit.
 */
export async function searchTokens(page: Page, query: string): Promise<void> {
  await page.getByLabel("Search token").fill(query);
}

/**
 * Search and click a result in the top-bar combobox. Results are `<li
 * role="option">` rows; the symbol cell is clicked (its click bubbles to the
 * option), which is the only selection path that resolves the shared target.
 */
export async function selectSearchResult(page: Page, symbol: string): Promise<void> {
  const cell = page
    .locator(".search-popover .search-results__symbol")
    .filter({ hasText: symbol })
    .first();
  await expect(cell).toBeVisible();
  await cell.click();
}

/** Search the top bar and select the first rendered result. */
export async function searchAndSelectToken(page: Page, query: string, symbol: string): Promise<void> {
  await searchTokens(page, query);
  await selectSearchResult(page, symbol);
}
