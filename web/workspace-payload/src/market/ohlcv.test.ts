import { describe, expect, it } from "vitest";
import { CandleSeries, aggregateCandles } from "./ohlcv";

const candle = (timeMs: number, open: number, high: number, low: number, close: number, volume = 1) => ({
  timeMs,
  open,
  high,
  low,
  close,
  volume,
});

describe("aggregateCandles", () => {
  it("rolls base candles into floor buckets", () => {
    const out = aggregateCandles(
      [
        candle(1_000, 1, 3, 0.5, 2, 5),
        candle(2_000, 2, 4, 1.5, 3, 6),
        candle(3_600_000, 3, 5, 2, 4, 7),
      ],
      60_000,
    );
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ timeMs: 0, open: 1, high: 4, low: 0.5, close: 3, volume: 11 });
    expect(out[1]).toMatchObject({ timeMs: 3_600_000, open: 3, close: 4, volume: 7 });
  });

  it("rejects invalid timeframes and skips invalid candles", () => {
    expect(() => aggregateCandles([], 0)).toThrowError();
    const out = aggregateCandles([candle(1_000, 1, 0.5, 2, 1)], 60_000);
    expect(out).toHaveLength(0);
  });
});

describe("CandleSeries", () => {
  it("applies a sorted, deduped snapshot", () => {
    const series = new CandleSeries(60_000, 8);
    series.applySnapshot([
      candle(2_000, 2, 3, 1, 2.5),
      candle(1_000, 1, 2, 0.5, 1.5),
      candle(2_000, 2, 4, 1, 3.5),
    ]);
    expect(series.toArray().map((c) => c.timeMs)).toEqual([1_000, 2_000]);
    expect(series.toArray()[1]!.high).toBe(4);
  });

  it("replaces the newest bar and appends newer bars", () => {
    const series = new CandleSeries(60_000, 8);
    series.upsert(candle(1_000, 1, 2, 0.5, 1.5));
    expect(series.upsert(candle(1_000, 1, 3, 0.5, 2.5))).toBe(true);
    expect(series.length).toBe(1);
    expect(series.last()!.close).toBe(2.5);
    expect(series.upsert(candle(2_000, 2, 4, 1.5, 3))).toBe(true);
    expect(series.length).toBe(2);
  });

  it("ignores stale out-of-order bars and invalid bars", () => {
    const series = new CandleSeries(60_000, 8);
    series.upsert(candle(5_000, 1, 2, 0.5, 1.5));
    expect(series.upsert(candle(4_000, 1, 2, 0.5, 1.5))).toBe(false);
    expect(series.upsert(candle(6_000, 1, 0.5, 2, 1.5))).toBe(false);
    expect(series.length).toBe(1);
  });

  it("stays bounded by capacity", () => {
    const series = new CandleSeries(60_000, 3);
    for (let i = 0; i < 10; i++) series.upsert(candle(i * 1_000, 1, 2, 0.5, 1.5));
    expect(series.length).toBe(3);
    expect(series.toArray()[0]!.timeMs).toBe(7_000);
  });

  it("returns a bounded range slice", () => {
    const series = new CandleSeries(60_000, 16);
    for (let i = 0; i < 5; i++) series.upsert(candle(i * 1_000, 1, 2, 0.5, 1.5));
    expect(series.range(1_000, 3_000).map((c) => c.timeMs)).toEqual([1_000, 2_000, 3_000]);
  });
});

describe("served timeframes", () => {
  it("accepts only windows the backend and Pro period bar can serve", async () => {
    const { isServedTimeframe, SERVED_TIMEFRAME_IDS } = await import("./ohlcv");
    for (const id of SERVED_TIMEFRAME_IDS) expect(isServedTimeframe(id)).toBe(true);
    // Seconds are local aggregation primitives only; the backend realtime target
    // rejects them, so the shared workstation timeframe must never accept one.
    expect(isServedTimeframe("1s")).toBe(false);
    expect(isServedTimeframe("5s")).toBe(false);
    expect(isServedTimeframe("nope")).toBe(false);
  });
});
