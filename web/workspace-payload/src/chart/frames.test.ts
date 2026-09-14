import { describe, expect, it } from "vitest";
import type { DecodedFrame } from "../realtime/types";
import { applyMarketFrame, createMarketFrameStores, parseCandle, parseDepthSnapshot } from "./frames";

function frame(partial: Partial<DecodedFrame> = {}): DecodedFrame {
  return {
    seq: 1,
    op: "delta",
    channel: "ohlcv",
    priority: 1,
    entityKey: "ohlcv:BASE:SOL",
    slot: null,
    sourceAgeMs: 0,
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

  it("applies depth snapshots", () => {
    const stores = createMarketFrameStores();
    const result = applyMarketFrame(
      stores,
      frame({ channel: "depth", entityKey: "depth:BASE:SOL", payload: { bids: [{ price: 10, size: 1 }], asks: [{ price: 11, size: 1 }] } }),
    );
    expect(result.kind).toBe("depth");
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
