import { describe, expect, it, vi } from "vitest";
import type { Candle } from "../contracts/market";
import type { DecodedFrame } from "../realtime/types";
import { timeframeById } from "../market/ohlcv";
import {
  ChartFrameRouter,
  DEFAULT_CHART_SUBJECT,
  MAX_HISTORY_LIMIT,
  boundCandles,
  chartEntityKey,
  clampHistoryLimit,
  createLocalHistoryProvider,
  normalizeCandles,
  type ChartSubject,
} from "./chart-datafeed";

const subject: ChartSubject = { chain: "BASE", address: "0xabc", symbol: "PEP" };
const tf1m = timeframeById("1m")!;

function candle(timeMs: number, close = 10): Candle {
  return { timeMs, open: close - 0.5, high: close + 0.5, low: close - 1, close, volume: 5 };
}

function ohlcvSnapshot(candles: Candle[], entityKey = chartEntityKey(subject)): DecodedFrame {
  return {
    seq: 1,
    op: "snapshot",
    channel: "ohlcv",
    priority: 2,
    entityKey,
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: {
      timeframe: "1m",
      candles: candles.map((c) => ({
        time_ms: c.timeMs,
        open: c.open,
        high: c.high,
        low: c.low,
        close: c.close,
        volume: c.volume,
      })),
    },
  };
}

function ohlcvDelta(value: Candle, entityKey = chartEntityKey(subject)): DecodedFrame {
  return {
    seq: 2,
    op: "delta",
    channel: "ohlcv",
    priority: 2,
    entityKey,
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: { timeframe: "1m", candle: { time_ms: value.timeMs, open: value.open, high: value.high, low: value.low, close: value.close, volume: value.volume } },
  };
}

describe("candle normalization", () => {
  it("sorts, dedupes last-wins, and drops malformed rows", () => {
    const normalized = normalizeCandles([
      candle(3_000, 30),
      { timeMs: 1_000, open: 1, high: Number.NaN, low: 1, close: 1, volume: 1 },
      candle(2_000, 20),
      candle(2_000, 25),
      { timeMs: 1_000, open: 1, high: 0.5, low: 1, close: 1, volume: 1 },
      { timeMs: 4_000, open: 1, high: 2, low: 0.5, close: 1, volume: -1 },
      { timeMs: 0, open: 1, high: 2, low: 0.5, close: 1, volume: 1 },
    ]);
    expect(normalized.map((c) => c.timeMs)).toEqual([2_000, 3_000]);
    expect(normalized[0]!.close).toBe(25);
  });

  it("caps the series at MAX_HISTORY_LIMIT and keeps the newest bars", () => {
    const raw = Array.from({ length: MAX_HISTORY_LIMIT + 100 }, (_, i) => candle(i + 1));
    const normalized = normalizeCandles(raw);
    expect(normalized).toHaveLength(MAX_HISTORY_LIMIT);
    expect(normalized[0]!.timeMs).toBe(101);
  });

  it("clips to a coherent window then keeps the newest `limit`", () => {
    const raw = [candle(1_000), candle(2_000), candle(3_000), candle(4_000)];
    expect(boundCandles(raw, 2_000, 3_000, 10).map((c) => c.timeMs)).toEqual([2_000, 3_000]);
    expect(boundCandles(raw, 0, 10_000, 2).map((c) => c.timeMs)).toEqual([3_000, 4_000]);
  });

  it("clamps hostile limits", () => {
    expect(clampHistoryLimit(undefined)).toBeGreaterThan(0);
    expect(clampHistoryLimit(-5)).toBeGreaterThan(0);
    expect(clampHistoryLimit(10_000_000)).toBe(MAX_HISTORY_LIMIT);
  });
});

describe("ChartFrameRouter", () => {
  it("routes OHLCV snapshots/deltas into bounded local series", () => {
    const router = new ChartFrameRouter();
    expect(router.apply([ohlcvSnapshot([candle(1_000, 10), candle(2_000, 11)])])).toBe(true);
    expect(router.localCandles(subject, tf1m).map((c) => c.close)).toEqual([10, 11]);

    // Replace last bar, then append a new one.
    router.apply([ohlcvDelta(candle(2_000, 12))]);
    router.apply([ohlcvDelta(candle(3_000, 13))]);
    expect(router.localCandles(subject, tf1m).map((c) => c.close)).toEqual([10, 12, 13]);
  });

  it("replays the newest local bar to a late subscriber and then streams applied bars", () => {
    const router = new ChartFrameRouter();
    router.apply([ohlcvSnapshot([candle(1_000, 10), candle(2_000, 11)])]);
    const sink = vi.fn();
    const unsubscribe = router.subscribe(subject, tf1m, sink);
    expect(sink).toHaveBeenCalledTimes(1);
    expect(sink.mock.calls[0]![0].timeMs).toBe(2_000);

    router.apply([ohlcvDelta(candle(3_000, 13))]);
    expect(sink).toHaveBeenCalledTimes(2);
    expect(sink.mock.calls[1]![0].close).toBe(13);

    unsubscribe();
    router.apply([ohlcvDelta(candle(4_000, 14))]);
    expect(sink).toHaveBeenCalledTimes(2);
  });

  it("does not leak the neutral default series into a selected instrument", () => {
    const router = new ChartFrameRouter();
    router.apply([ohlcvSnapshot([candle(1_000, 42)], "ohlcv:default")]);
    // A selected instrument must not inherit another entity's bar.
    const selected = vi.fn();
    router.subscribe(subject, tf1m, selected);
    expect(selected).not.toHaveBeenCalled();
    // The neutral chart itself still replays its own series.
    const neutral = vi.fn();
    router.subscribe(DEFAULT_CHART_SUBJECT, tf1m, neutral);
    expect(neutral).toHaveBeenCalledTimes(1);
    expect(neutral.mock.calls[0]![0].close).toBe(42);
  });

  it("never broadcasts a malformed or other-timeframe frame", () => {
    const router = new ChartFrameRouter();
    router.apply([ohlcvSnapshot([candle(1_000, 10)])]);
    const sink = vi.fn();
    router.subscribe(subject, tf1m, sink);
    sink.mockClear();

    const malformed = { ...ohlcvDelta(candle(2_000, 11)) };
    malformed.payload = { timeframe: "1m", candle: { time_ms: 2_000, open: 1, high: 0.5, low: 1, close: 1, volume: 1 } };
    expect(router.apply([malformed])).toBe(false);

    const otherTimeframe = { ...ohlcvDelta(candle(3_000, 12)) };
    otherTimeframe.payload = { timeframe: "5m", candle: { time_ms: 3_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 } };
    router.apply([otherTimeframe]);

    expect(sink).not.toHaveBeenCalled();
    expect(router.localCandles(subject, tf1m).map((c) => c.timeMs)).toEqual([1_000]);
  });

  it("creates a local history provider from the bounded buffer", async () => {
    const router = new ChartFrameRouter();
    router.apply([ohlcvSnapshot([candle(1_000, 1), candle(2_000, 2)])]);
    const provider = createLocalHistoryProvider(router);
    const page = await provider.load({
      subject,
      timeframe: tf1m,
      fromMs: 0,
      toMs: 10_000,
      limit: 10,
    });
    expect(page.source).toBe("local");
    expect(page.candles.map((c) => c.timeMs)).toEqual([1_000, 2_000]);
  });
});
