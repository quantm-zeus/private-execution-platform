// Renderer-agnostic chart data boundary.
//
// Domain, session and realtime code must not depend on KLineChart Pro (or any
// other renderer): this module defines the small local contract a renderer
// adapter talks to. History and the realtime bus are injected, so the renderer
// can be replaced without touching market/session code.
//
// Everything here is bounded and fail-closed: history is sorted/deduped and
// capped, malformed bars are dropped (never fabricated), and a subscriber only
// ever receives bars that were applied from an authenticated decoded frame.

import type { Candle } from "../contracts/market";
import { applyMarketFrame, createMarketFrameStores, upsertPriceTick } from "./frames";
import type { Timeframe } from "../market/ohlcv";
import type { DecodedFrame } from "../realtime/types";

export interface ChartSubject {
  readonly chain: string;
  readonly address: string;
  readonly symbol: string;
}

/** Neutral target shown before an instrument is selected (matches `ohlcv:default`). */
export const DEFAULT_CHART_SUBJECT: ChartSubject = { chain: "", address: "", symbol: "—" };

/** Stable, non-secret renderer symbol id: `<chain>:<address>`. */
export function chartTicker(subject: ChartSubject): string {
  return subject.chain && subject.address ? `${subject.chain}:${subject.address}` : "ohlcv:default";
}

/** Entity key the realtime feed uses for an instrument's OHLCV frames. */
export function chartEntityKey(subject: ChartSubject): string {
  return subject.chain && subject.address
    ? `ohlcv:${subject.chain}:${subject.address}`
    : "ohlcv:default";
}

export interface ChartHistoryQuery {
  readonly subject: ChartSubject;
  readonly timeframe: Timeframe;
  readonly fromMs: number;
  readonly toMs: number;
  readonly limit: number;
}

export interface ChartHistoryPage {
  readonly candles: readonly Candle[];
  /** Provenance of a non-empty page; consumers must not treat `local` as live. */
  readonly source: "network" | "local";
}

export interface ChartHistoryProvider {
  /** Resolve history. Must resolve `[]` (never fabricated bars) when unavailable. */
  load(query: ChartHistoryQuery, signal?: AbortSignal): Promise<ChartHistoryPage>;
}

export type ChartCandleSink = (candle: Candle) => void;

/** Already-decrypted realtime bars. `subscribe` returns its unsubscribe fn. */
export interface ChartRealtimeSource {
  subscribe(subject: ChartSubject, timeframe: Timeframe, sink: ChartCandleSink): () => void;
}

export const DEFAULT_HISTORY_LIMIT = 1_500;
export const MAX_HISTORY_LIMIT = 4_096;

export function clampHistoryLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit) || limit <= 0) return DEFAULT_HISTORY_LIMIT;
  return Math.min(Math.floor(limit), MAX_HISTORY_LIMIT);
}

function isValidCandle(candle: Candle): boolean {
  return (
    Number.isFinite(candle.timeMs) &&
    candle.timeMs > 0 &&
    Number.isFinite(candle.open) &&
    Number.isFinite(candle.high) &&
    Number.isFinite(candle.low) &&
    Number.isFinite(candle.close) &&
    Number.isFinite(candle.volume) &&
    // Same OHLC envelope as `frames.ts`/`history.ts`: open/close must lie within
    // [low, high], so no renderer accepts a bar the parsers would reject.
    candle.high >= candle.low &&
    candle.high >= candle.open &&
    candle.high >= candle.close &&
    candle.low <= candle.open &&
    candle.low <= candle.close &&
    candle.volume >= 0
  );
}

/**
 * Sort ascending, drop malformed rows, dedupe by timestamp (last wins), and
 * cap the result. A hostile/broken source can never produce an unbounded or
 * mis-ordered series.
 */
export function normalizeCandles(raw: readonly Candle[]): Candle[] {
  const sorted = raw.filter(isValidCandle).slice().sort((a, b) => a.timeMs - b.timeMs);
  const out: Candle[] = [];
  for (const candle of sorted) {
    const last = out[out.length - 1];
    if (last && last.timeMs === candle.timeMs) out[out.length - 1] = candle;
    else out.push(candle);
  }
  if (out.length > MAX_HISTORY_LIMIT) out.splice(0, out.length - MAX_HISTORY_LIMIT);
  return out;
}

/** Normalize, clip to the requested window when it is coherent, then keep the newest `limit`. */
export function boundCandles(
  raw: readonly Candle[],
  fromMs: number,
  toMs: number,
  limit: number,
): Candle[] {
  const normalized = normalizeCandles(raw);
  const bounded =
    Number.isFinite(fromMs) && Number.isFinite(toMs) && fromMs <= toMs
      ? normalized.filter((candle) => candle.timeMs >= fromMs && candle.timeMs <= toMs)
      : normalized;
  const capped = clampHistoryLimit(limit);
  return bounded.length > capped ? bounded.slice(bounded.length - capped) : bounded;
}

/**
 * Owns the bounded local candle/depth stores the worker frames feed into, and
 * fans applied OHLCV bars out to renderer subscribers.
 *
 * This is the "already-decrypted local realtime frame bus" the Pro datafeed
 * subscribes to: it never talks to the network and never invents a bar.
 */
export class ChartFrameRouter {
  readonly stores = createMarketFrameStores();
  private readonly sinks = new Map<string, Set<ChartCandleSink>>();

  /** Apply decoded frames; returns true when any store changed. */
  apply(frames: readonly DecodedFrame[]): boolean {
    let changed = false;
    for (const frame of frames) {
      if (frame.channel !== "ohlcv" && frame.channel !== "depth") continue;
      const result = applyMarketFrame(this.stores, frame);
      if (!result.changed) continue;
      changed = true;
      if (frame.channel === "ohlcv" && result.seriesKey) {
        this.broadcast(frame.entityKey, result.seriesKey);
      }
    }
    return changed;
  }

  /**
   * Build/upsert the current candle for the exact selected subject from a
   * verified price tick. The neutral `ohlcv:default` series is never touched,
   * and the entity key is derived from the subject itself, so another token's
   * tick can never reach this series.
   */
  applyPriceTick(
    subject: ChartSubject,
    timeframe: Timeframe,
    tick: { readonly priceUsd: number; readonly observedAtMs: number | null },
    nowMs: number = Date.now(),
  ): boolean {
    const entityKey = chartEntityKey(subject);
    if (entityKey === "ohlcv:default") return false;
    const result = upsertPriceTick(
      this.stores,
      entityKey,
      timeframe.id,
      timeframe.ms,
      tick.priceUsd,
      tick.observedAtMs,
      nowMs,
    );
    if (result.changed && result.seriesKey) this.broadcast(entityKey, result.seriesKey);
    return result.changed;
  }

  private broadcast(frameEntityKey: string, seriesKey: string): void {
    const hash = seriesKey.lastIndexOf("#");
    if (hash < 0) return;
    const timeframeId = seriesKey.slice(hash + 1);
    const candle = this.stores.series.get(seriesKey)?.last();
    if (!candle) return;
    for (const [key, sinks] of this.sinks) {
      const keyHash = key.lastIndexOf("#");
      if (keyHash < 0) continue;
      if (key.slice(keyHash + 1) !== timeframeId) continue;
      const sinkEntity = key.slice(0, keyHash);
      // Exact entity match only: a `ohlcv:default` frame belongs to the neutral
      // chart, never to a selected instrument (which would surface another
      // instrument's bar under the selected symbol).
      if (sinkEntity !== frameEntityKey) continue;
      for (const sink of sinks) sink(candle);
    }
  }

  /** Subscribe to applied bars. Returns a clean teardown fn. */
  subscribe(subject: ChartSubject, timeframe: Timeframe, sink: ChartCandleSink): () => void {
    const key = `${chartEntityKey(subject)}#${timeframe.id}`;
    let sinks = this.sinks.get(key);
    if (!sinks) {
      sinks = new Set();
      this.sinks.set(key, sinks);
    }
    // Replay the newest local bar so a late subscriber is not empty; no bar is
    // ever synthesized.
    const last = this.localCandles(subject, timeframe).at(-1);
    if (last) sink(last);
    sinks.add(sink);
    return () => {
      const current = this.sinks.get(key);
      if (!current) return;
      current.delete(sink);
      if (current.size === 0) this.sinks.delete(key);
    };
  }

  /**
   * Local bars for a subject/timeframe. The neutral `ohlcv:default` series is
   * only returned for the neutral subject; a selected instrument never inherits
   * another entity's bars.
   */
  localCandles(subject: ChartSubject, timeframe: Timeframe): Candle[] {
    return this.stores.series.get(`${chartEntityKey(subject)}#${timeframe.id}`)?.toArray() ?? [];
  }
}

/** History from the bounded local frame buffer (the offline/degraded path). */
export function createLocalHistoryProvider(router: ChartFrameRouter): ChartHistoryProvider {
  return {
    async load(query: ChartHistoryQuery): Promise<ChartHistoryPage> {
      const candles = boundCandles(
        router.localCandles(query.subject, query.timeframe),
        query.fromMs,
        query.toMs,
        query.limit,
      );
      return { candles, source: "local" };
    },
  };
}
