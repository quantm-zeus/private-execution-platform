// Chart history providers.
//
// The primary path is the PEP authenticated/encrypted command channel
// (`get_chart`), which is capability-gated server-side on `market`. When that
// capability is absent, the command channel is not ready, or the response is
// malformed, the provider falls back to the bounded local buffer from the
// already-decrypted realtime frames. It never fabricates a candle.

import type { Candle } from "../contracts/market";
import type { CommandClient } from "../transport/command";
import {
  boundCandles,
  clampHistoryLimit,
  normalizeCandles,
  type ChartHistoryPage,
  type ChartHistoryProvider,
  type ChartHistoryQuery,
} from "./chart-datafeed";

/**
 * Frontend timeframe id -> canonical `ChartWindow` wire value.
 * The canonical vocabulary (`m5`/`m15`/`h1`/`h4`/`d1`) intentionally differs
 * from the frontend ids; unsupported ids stay local-only.
 */
export const WINDOW_BY_TIMEFRAME: Readonly<Record<string, string>> = {
  "5m": "m5",
  "15m": "m15",
  "1h": "h1",
  "4h": "h4",
  "1d": "d1",
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Accept a finite JSON number, a numeric string, or `{ value: number }`. */
function finiteNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  const record = asRecord(value);
  if (record) {
    const inner = record.value;
    if (typeof inner === "number" && Number.isFinite(inner)) return inner;
    if (typeof inner === "string" && inner.trim() !== "") {
      const parsed = Number(inner);
      return Number.isFinite(parsed) ? parsed : null;
    }
  }
  return null;
}

/**
 * Parse one server/canonical candle. Accepts the web shape (`time_ms`) and the
 * canonical `market-types::Candle` shape (`open_time_ms` + `close_time_ms`).
 */
export function parseChartCandle(raw: unknown): Candle | null {
  const record = asRecord(raw);
  if (!record) return null;
  const timeMs = finiteNumber(record.time_ms ?? record.timeMs ?? record.open_time_ms ?? record.openTimeMs);
  const open = finiteNumber(record.open);
  const high = finiteNumber(record.high);
  const low = finiteNumber(record.low);
  const close = finiteNumber(record.close);
  const volume = finiteNumber(record.volume) ?? 0;
  if (timeMs === null || open === null || high === null || low === null || close === null) return null;
  if (timeMs <= 0 || high < low || volume < 0) return null;
  return { timeMs, open, high, low, close, volume };
}

/**
 * Extract bars from an untyped backend result. The `get_chart` arm has no
 * response schema yet, so accept the shapes the market layer is expected to
 * expose and drop anything unrecognized (fail closed).
 */
export function parseChartHistoryResult(result: unknown): Candle[] {
  const record = asRecord(result);
  const list = Array.isArray(result)
    ? result
    : Array.isArray(record?.candles)
      ? (record?.candles as unknown[])
      : Array.isArray(record?.bars)
        ? (record?.bars as unknown[])
        : Array.isArray(record?.klines)
          ? (record?.klines as unknown[])
          : null;
  if (!list) return [];
  const out: Candle[] = [];
  for (const entry of list) {
    const candle = parseChartCandle(entry);
    if (candle) out.push(candle);
  }
  return normalizeCandles(out);
}

export interface ServerHistoryDeps {
  readonly command: CommandClient;
  /** True once the authenticated encrypted command channel is installed. */
  readonly ready: () => boolean;
  /** True when the authoritative `chart` capability is advertised. */
  readonly chartAllowed: () => boolean;
}

/** Authenticated/encrypted server history. Resolves `[]` on any failure. */
export function createServerHistoryProvider(deps: ServerHistoryDeps): ChartHistoryProvider {
  return {
    async load(query: ChartHistoryQuery, signal?: AbortSignal): Promise<ChartHistoryPage> {
      const window = WINDOW_BY_TIMEFRAME[query.timeframe.id];
      if (
        !window ||
        !query.subject.chain ||
        !query.subject.address ||
        !deps.ready() ||
        !deps.chartAllowed()
      ) {
        return { candles: [], source: "network" };
      }
      try {
        // Forward the renderer's requested window so `loadMore`/scroll-back can
        // page; the server clamps `countBack` and treats `from`/`to` as unix
        // seconds. Omitted bounds preserve the default "latest N bars" read.
        const payload: Record<string, unknown> = {
          chain: query.subject.chain,
          address: query.subject.address,
          window,
          countBack: clampHistoryLimit(query.limit),
        };
        if (Number.isFinite(query.fromMs) && query.fromMs > 0) {
          payload.from = Math.floor(query.fromMs / 1000);
        }
        if (Number.isFinite(query.toMs) && query.toMs > 0) {
          payload.to = Math.ceil(query.toMs / 1000);
        }
        const result = await deps.command.send<unknown>(
          "get_chart",
          payload,
          signal ? { signal } : undefined,
        );
        const candles = boundCandles(
          parseChartHistoryResult(result),
          query.fromMs,
          query.toMs,
          clampHistoryLimit(query.limit),
        );
        return { candles, source: "network" };
      } catch {
        // Capability missing / offline / malformed: fall through to local.
        return { candles: [], source: "network" };
      }
    },
  };
}

/** Prefer authoritative history; fall back to the bounded local buffer. */
export function createPepHistoryProvider(
  server: ChartHistoryProvider,
  local: ChartHistoryProvider,
): ChartHistoryProvider {
  return {
    async load(query: ChartHistoryQuery, signal?: AbortSignal): Promise<ChartHistoryPage> {
      const remote = await server.load(query, signal);
      const localPage = await local.load(query, signal);
      if (remote.candles.length === 0) return localPage;
      if (localPage.candles.length === 0) return remote;
      // Realtime bars applied after the server page can be newer than its last
      // bar; Pro subscribes only after the history load, so merge those newer
      // local bars into the page instead of leaving a hole in the rendered
      // series. Bars at or before the server's last timestamp stay server-owned.
      const lastRemote = remote.candles[remote.candles.length - 1]!.timeMs;
      const newer = localPage.candles.filter((candle) => candle.timeMs > lastRemote);
      if (newer.length === 0) return remote;
      const merged = [...remote.candles, ...newer];
      const limit = clampHistoryLimit(query.limit);
      return {
        candles: merged.length > limit ? merged.slice(merged.length - limit) : merged,
        source: "network",
      };
    },
  };
}
