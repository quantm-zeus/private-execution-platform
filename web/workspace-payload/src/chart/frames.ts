import type { Candle, DepthLevel } from "../contracts/market";
import { DepthBookStore, type DepthSnapshot } from "../market/depth";
import { CandleSeries, timeframeById } from "../market/ohlcv";
import type { DecodedFrame } from "../realtime/types";

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function parseCandle(raw: unknown): Candle | null {
  const record = asRecord(raw);
  if (!record) return null;
  const timeMs = num(record.time_ms ?? record.timeMs);
  const open = num(record.open);
  const high = num(record.high);
  const low = num(record.low);
  const close = num(record.close);
  const volume = num(record.volume) ?? 0;
  if (timeMs === null || open === null || high === null || low === null || close === null) return null;
  if (high < low || volume < 0) return null;
  return { timeMs, open, high, low, close, volume };
}

function parseLevels(raw: unknown): DepthLevel[] | null {
  if (!Array.isArray(raw)) return null;
  const out: DepthLevel[] = [];
  for (const entry of raw) {
    const record = asRecord(entry);
    if (!record) continue;
    const price = num(record.price);
    const size = num(record.size);
    if (price === null || size === null || price <= 0 || size <= 0) continue;
    out.push({ price, size });
  }
  return out;
}

export function parseDepthSnapshot(raw: unknown): DepthSnapshot | null {
  const record = asRecord(raw);
  if (!record) return null;
  const bids = parseLevels(record.bids);
  const asks = parseLevels(record.asks);
  if (!bids || !asks) return null;
  const slot = num(record.slot);
  return { bids, asks, slot };
}

export interface MarketFrameStores {
  /** Candle series keyed by `${entityKey}#${timeframeId}`. */
  readonly series: Map<string, CandleSeries>;
  readonly depth: DepthBookStore;
  readonly maxSeries: number;
}

export function createMarketFrameStores(maxSeries = 24, depthCapacity = 200): MarketFrameStores {
  return { series: new Map(), depth: new DepthBookStore(depthCapacity), maxSeries };
}

export interface FrameApplyResult {
  readonly changed: boolean;
  readonly kind: "ohlcv" | "depth" | null;
  readonly seriesKey: string | null;
}

/** Bounded eviction so a hostile feed cannot create unbounded series. */
function seriesFor(stores: MarketFrameStores, key: string, timeframeMs: number): CandleSeries {
  const existing = stores.series.get(key);
  if (existing) return existing;
  if (stores.series.size >= stores.maxSeries) {
    const oldest = stores.series.keys().next().value as string | undefined;
    if (oldest !== undefined) stores.series.delete(oldest);
  }
  const created = new CandleSeries(timeframeMs);
  stores.series.set(key, created);
  return created;
}

/**
 * Normalize and apply one decoded realtime frame into local market stores.
 * Malformed payloads are ignored (never throw into the render loop).
 */
export function applyMarketFrame(stores: MarketFrameStores, frame: DecodedFrame): FrameApplyResult {
  if (frame.channel === "ohlcv") {
    const payload = asRecord(frame.payload);
    if (!payload) return { changed: false, kind: null, seriesKey: null };
    const timeframeId = typeof payload.timeframe === "string" ? payload.timeframe : null;
    const timeframe = timeframeId ? timeframeById(timeframeId) : undefined;
    if (!timeframe) return { changed: false, kind: null, seriesKey: null };
    const key = `${frame.entityKey}#${timeframe.id}`;
    const series = seriesFor(stores, key, timeframe.ms);
    if (frame.op === "snapshot") {
      const rawCandles = Array.isArray(payload.candles) ? payload.candles : [];
      const candles: Candle[] = [];
      for (const raw of rawCandles) {
        const candle = parseCandle(raw);
        if (candle) candles.push(candle);
      }
      series.applySnapshot(candles);
      return { changed: true, kind: "ohlcv", seriesKey: key };
    }
    const candle = parseCandle(payload.candle ?? payload);
    if (!candle) return { changed: false, kind: null, seriesKey: null };
    const changed = series.upsert(candle);
    return { changed, kind: "ohlcv", seriesKey: key };
  }

  if (frame.channel === "depth") {
    const snapshot = parseDepthSnapshot(frame.payload);
    if (!snapshot) return { changed: false, kind: null, seriesKey: null };
    stores.depth.applySnapshot(snapshot);
    return { changed: true, kind: "depth", seriesKey: null };
  }

  return { changed: false, kind: null, seriesKey: null };
}
