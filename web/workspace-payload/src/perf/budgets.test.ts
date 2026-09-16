import { describe, expect, it } from "vitest";
import { FrameBatcher } from "../realtime/batcher";
import { decodeInnerFrame } from "../realtime/decoder";
import { applyMarketFrame, createMarketFrameStores } from "../chart/frames";
import { normalizeCandles } from "../chart/chart-datafeed";
import type { DecodedFrame, Priority } from "../realtime/types";

const zeroFlush: Record<Priority, number> = { 0: 0, 1: 0, 2: 0, 3: 0 };

function frame(index: number): DecodedFrame {
  return {
    seq: index,
    op: "delta",
    channel: "ohlcv",
    priority: 2,
    entityKey: `market:${index % 500}`,
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: {},
  };
}

function elapsed(fn: () => void): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

/**
 * Structural performance/boundedness guards. Hard bounds are asserted exactly
 * (memory safety); wall-clock budgets are intentionally generous so a loaded CI
 * host does not flake, while still catching accidental O(n^2) regressions.
 */
describe("performance budgets", () => {
  it("keeps the frame batcher bounded under a 100k-frame burst", () => {
    const batcher = new FrameBatcher({ capacity: 4_096, flushMs: zeroFlush });
    const duration = elapsed(() => {
      for (let i = 0; i < 100_000; i++) {
        const result = batcher.enqueue(frame(i));
        if (i % 1_000 === 0) batcher.drainAll();
        if (result.forcedResync && i % 1_000 !== 0) batcher.drainAll();
      }
    });
    expect(batcher.size()).toBeLessThanOrEqual(4_096);
    expect(duration).toBeLessThan(3_000);
  });

  it("decodes 10k frames within budget without unbounded growth", () => {
    const encoded = new TextEncoder().encode(
      JSON.stringify({ op: "delta", channel: "market", entity_key: "m:1", payload: { p: 1 } }),
    );
    const duration = elapsed(() => {
      for (let i = 0; i < 10_000; i++) decodeInnerFrame(encoded, i);
    });
    expect(duration).toBeLessThan(3_000);
  });

  it("applies 20k market frames into bounded series", () => {
    const stores = createMarketFrameStores(8);
    const payloadFrame: DecodedFrame = {
      seq: 1,
      op: "delta",
      channel: "ohlcv",
      priority: 1,
      entityKey: "ohlcv:BASE:SOL",
      slot: null,
      sourceAgeMs: 0,
      serverTimeMs: null,
      payload: { timeframe: "1m", candle: { time_ms: 0, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 } },
    };
    const duration = elapsed(() => {
      for (let i = 0; i < 20_000; i++) {
        applyMarketFrame(stores, { ...payloadFrame, seq: i, payload: { timeframe: "1m", candle: { time_ms: i * 60_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 } } });
      }
    });
    expect(stores.series.size).toBeLessThanOrEqual(8);
    expect(stores.series.get("ohlcv:BASE:SOL#1m")!.length).toBeLessThanOrEqual(4_096);
    expect(duration).toBeLessThan(3_000);
  });

  it("normalizes 20 000 unordered bars into a bounded, ordered, deduped series", () => {
    const raw = Array.from({ length: 20_000 }, (_, i) => ({
      timeMs: ((i * 7919) % 20_000) * 60_000,
      open: 10,
      high: 10.5,
      low: 9.5,
      close: 10.2,
      volume: 100,
    }));
    const duration = elapsed(() => {
      const normalized = normalizeCandles(raw);
      // bounded by MAX_HISTORY_LIMIT and strictly ascending
      expect(normalized.length).toBeLessThanOrEqual(4_096);
      for (let i = 1; i < normalized.length; i++) {
        expect(normalized[i]!.timeMs).toBeGreaterThan(normalized[i - 1]!.timeMs);
      }
    });
    expect(duration).toBeLessThan(3_000);
  });
});
