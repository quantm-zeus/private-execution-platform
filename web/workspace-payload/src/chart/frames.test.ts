import { describe, expect, it } from "vitest";
import type { DecodedFrame } from "../realtime/types";
import {
  applyMarketFrame,
  createMarketFrameStores,
  parseCandle,
  parseDepthSnapshot,
  upsertPriceTick,
} from "./frames";

function frame(partial: Partial<DecodedFrame> = {}): DecodedFrame {
  return {
    seq: 1,
    op: "delta",
    channel: "ohlcv",
    priority: 1,
    entityKey: "ohlcv:BASE:SOL",
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: {},
    ...partial,
  };
}

const rawCandle = (timeMs: number, close: number) => ({
  time_ms: timeMs,
  open: close - 1,
  high: close + 1,
  low: close - 2,
  close,
  volume: 3,
});

describe("parseCandle / parseDepthSnapshot", () => {
  it("accepts a valid candle and rejects an inverted one", () => {
    expect(parseCandle(rawCandle(1_000, 10))).not.toBeNull();
    expect(parseCandle({ ...rawCandle(1_000, 10), high: 1, low: 5 })).toBeNull();
    expect(parseCandle({})).toBeNull();
  });

  it("rejects a non-positive timestamp and an open/close outside [low, high]", () => {
    expect(parseCandle(rawCandle(0, 10))).toBeNull();
    expect(parseCandle(rawCandle(-5, 10))).toBeNull();
    // open above high / close below low are malformed envelopes.
    expect(parseCandle({ ...rawCandle(1_000, 10), open: 100 })).toBeNull();
    expect(parseCandle({ ...rawCandle(1_000, 10), close: 0.5 })).toBeNull();
  });

  it("parses depth and drops invalid levels", () => {
    const snapshot = parseDepthSnapshot({
      bids: [{ price: 10, size: 1 }, { price: 0, size: 1 }],
      asks: [{ price: 11, size: 2 }],
      slot: 5,
    });
    expect(snapshot?.bids).toHaveLength(1);
    expect(snapshot?.asks).toHaveLength(1);
    expect(parseDepthSnapshot({ bids: "nope" })).toBeNull();
  });
});

describe("applyMarketFrame", () => {
  it("applies an OHLCV snapshot into a bounded series", () => {
    const stores = createMarketFrameStores();
    const result = applyMarketFrame(
      stores,
      frame({
        op: "snapshot",
        payload: { timeframe: "1m", candles: [rawCandle(2_000, 12), rawCandle(1_000, 11)] },
      }),
    );
    expect(result.changed).toBe(true);
    const series = stores.series.get("ohlcv:BASE:SOL#1m")!;
    expect(series.toArray().map((c) => c.timeMs)).toEqual([1_000, 2_000]);
  });

  it("applies an OHLCV delta bar", () => {
    const stores = createMarketFrameStores();
    applyMarketFrame(
      stores,
      frame({ op: "snapshot", payload: { timeframe: "1m", candles: [rawCandle(1_000, 11)] } }),
    );
    const result = applyMarketFrame(stores, frame({ payload: { timeframe: "1m", candle: rawCandle(2_000, 12) } }));
    expect(result.changed).toBe(true);
    expect(stores.series.get("ohlcv:BASE:SOL#1m")!.length).toBe(2);
  });

  it("ignores unknown timeframes and malformed payloads", () => {
    const stores = createMarketFrameStores();
    expect(applyMarketFrame(stores, frame({ payload: { timeframe: "7m", candle: rawCandle(1, 1) } })).changed).toBe(false);
    expect(applyMarketFrame(stores, frame({ payload: {} })).changed).toBe(false);
    expect(applyMarketFrame(stores, frame({ channel: "depth", payload: { bids: "no" } })).changed).toBe(false);
  });

  it("a malformed or empty snapshot never wipes an existing series", () => {
    const stores = createMarketFrameStores();
    applyMarketFrame(
      stores,
      frame({ op: "snapshot", payload: { timeframe: "1m", candles: [rawCandle(1_000, 11)] } }),
    );
    // Non-array candles and an all-invalid snapshot are no-ops.
    expect(
      applyMarketFrame(stores, frame({ op: "snapshot", payload: { timeframe: "1m", candles: "nope" } })).changed,
    ).toBe(false);
    expect(
      applyMarketFrame(stores, frame({ op: "snapshot", payload: { timeframe: "1m", candles: [{}] } })).changed,
    ).toBe(false);
    const empty = applyMarketFrame(
      stores,
      frame({ op: "snapshot", payload: { timeframe: "1m", candles: [] } }),
    );
    expect(empty.changed).toBe(false);
    expect(stores.series.get("ohlcv:BASE:SOL#1m")!.toArray().map((c) => c.timeMs)).toEqual([1_000]);
  });

  it("applies depth snapshots and ignores depth deltas", () => {
    const stores = createMarketFrameStores();
    const result = applyMarketFrame(
      stores,
      frame({
        op: "snapshot",
        channel: "depth",
        entityKey: "depth:BASE:SOL",
        payload: { bids: [{ price: 10, size: 1 }], asks: [{ price: 11, size: 1 }] },
      }),
    );
    expect(result.kind).toBe("depth");
    expect(stores.depth.mid()).toBe(10.5);

    // A delta must never wipe the snapshot book.
    const delta = applyMarketFrame(
      stores,
      frame({ op: "delta", channel: "depth", entityKey: "depth:BASE:SOL", payload: { bids: [], asks: [] } }),
    );
    expect(delta.changed).toBe(false);
    expect(stores.depth.mid()).toBe(10.5);
  });

  it("bounds the number of candle series", () => {
    const stores = createMarketFrameStores(2);
    applyMarketFrame(stores, frame({ entityKey: "a", payload: { timeframe: "1m", candle: rawCandle(1, 1) } }));
    applyMarketFrame(stores, frame({ entityKey: "b", payload: { timeframe: "1m", candle: rawCandle(1, 1) } }));
    applyMarketFrame(stores, frame({ entityKey: "c", payload: { timeframe: "1m", candle: rawCandle(1, 1) } }));
    expect(stores.series.size).toBe(2);
    expect(stores.series.has("a#1m")).toBe(false);
  });
});

describe("upsertPriceTick", () => {
  const TIMEFRAME_MS = 60_000;
  // An exact 1-minute bucket start.
  const BUCKET = 1_700_000_040_000;
  const key = "ohlcv:BASE:SOL#1m";

  it("opens a new bucket without inventing volume", () => {
    const stores = createMarketFrameStores();
    const result = upsertPriceTick(
      stores,
      "ohlcv:BASE:SOL",
      "1m",
      TIMEFRAME_MS,
      1.5,
      BUCKET + 1_000,
      BUCKET + 1_000,
    );
    expect(result.changed).toBe(true);
    expect(result.volumeAuthoritative).toBe(false);
    const candle = stores.series.get(key)!.last()!;
    expect(candle.close).toBe(1.5);
    expect(candle.volume).toBe(0);
  });

  it("widens high/low and preserves authoritative volume in the same bucket", () => {
    const stores = createMarketFrameStores();
    applyMarketFrame(
      stores,
      frame({
        payload: {
          timeframe: "1m",
          candle: { time_ms: BUCKET, open: 1, high: 1.2, low: 0.9, close: 1.1, volume: 42 },
        },
      }),
    );
    upsertPriceTick(stores, "ohlcv:BASE:SOL", "1m", TIMEFRAME_MS, 1.3, BUCKET + 1_000, BUCKET + 1_000);
    const candle = stores.series.get(key)!.last()!;
    expect(candle.high).toBe(1.3);
    expect(candle.close).toBe(1.3);
    // A price tick carries no volume, so the authoritative 42 is untouched.
    expect(candle.volume).toBe(42);
  });

  it("refuses a stale bucket and an invalid price", () => {
    const stores = createMarketFrameStores();
    upsertPriceTick(stores, "ohlcv:BASE:SOL", "1m", TIMEFRAME_MS, 1.5, BUCKET + 60_000, BUCKET);
    const stale = upsertPriceTick(
      stores,
      "ohlcv:BASE:SOL",
      "1m",
      TIMEFRAME_MS,
      9,
      BUCKET,
      BUCKET + 60_000,
    );
    expect(stale.changed).toBe(false);
    expect(stores.series.get(key)!.last()!.close).toBe(1.5);
    expect(
      upsertPriceTick(stores, "ohlcv:BASE:SOL", "1m", TIMEFRAME_MS, 0, BUCKET + 61_000, BUCKET).changed,
    ).toBe(false);
  });

  it("is replaced by authoritative OHLCV volume for the same bucket", () => {
    const stores = createMarketFrameStores();
    upsertPriceTick(stores, "ohlcv:BASE:SOL", "1m", TIMEFRAME_MS, 1.5, BUCKET + 1_000, BUCKET);
    applyMarketFrame(
      stores,
      frame({
        payload: {
          timeframe: "1m",
          candle: { time_ms: BUCKET, open: 1.5, high: 1.6, low: 1.4, close: 1.55, volume: 77 },
        },
      }),
    );
    const candle = stores.series.get(key)!.last()!;
    expect(candle.volume).toBe(77);
    expect(candle.close).toBe(1.55);
  });
});
