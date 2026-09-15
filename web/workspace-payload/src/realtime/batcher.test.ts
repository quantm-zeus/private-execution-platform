import { describe, expect, it } from "vitest";
import { FrameBatcher, DEFAULT_FLUSH_MS } from "./batcher";
import type { DecodedFrame, Priority } from "./types";

function frame(priority: Priority, entityKey: string, seq = 1): DecodedFrame {
  return {
    seq,
    op: "delta",
    channel: priority === 0 ? "execution" : "ohlcv",
    priority,
    entityKey,
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: { value: seq },
  };
}

const zeroFlush: Record<Priority, number> = { 0: 0, 1: 0, 2: 0, 3: 0 };

describe("FrameBatcher", () => {
  it("coalesces visual frames by entity key, keeping the newest", () => {
    const batcher = new FrameBatcher({ capacity: 10, flushMs: zeroFlush });
    batcher.enqueue(frame(1, "ohlcv:BASE:SOL", 1));
    const result = batcher.enqueue(frame(1, "ohlcv:BASE:SOL", 2));
    expect(result.replaced).toBe(true);
    expect(batcher.size()).toBe(1);
    const drained = batcher.drainAll();
    expect(drained).toHaveLength(1);
    expect(drained[0]!.seq).toBe(2);
  });

  it("never coalesces P0 lifecycle transitions", () => {
    const batcher = new FrameBatcher({ capacity: 10, flushMs: zeroFlush });
    batcher.enqueue(frame(0, "order:1", 1));
    batcher.enqueue(frame(0, "order:1", 2));
    expect(batcher.size()).toBe(2);
    expect(batcher.drainAll().map((f) => f.seq)).toEqual([1, 2]);
  });

  it("does not flush before the priority interval elapses", () => {
    const batcher = new FrameBatcher({
      capacity: 10,
      flushMs: { ...DEFAULT_FLUSH_MS, 1: 60 },
    });
    batcher.enqueue(frame(1, "a"));
    expect(batcher.drainDue(1_000)).toHaveLength(1);
    batcher.enqueue(frame(1, "b"));
    expect(batcher.drainDue(1_010)).toHaveLength(0);
    expect(batcher.drainDue(1_061)).toHaveLength(1);
  });

  it("always flushes P0 immediately", () => {
    const batcher = new FrameBatcher({ capacity: 10, flushMs: DEFAULT_FLUSH_MS });
    batcher.enqueue(frame(0, "order:1"));
    expect(batcher.drainDue(5)).toHaveLength(1);
  });

  it("evicts lowest-priority frames first and forces a resync for the lost state", () => {
    const batcher = new FrameBatcher({ capacity: 2, flushMs: zeroFlush });
    batcher.enqueue(frame(3, "meta:a"));
    batcher.enqueue(frame(1, "visual:a"));
    const result = batcher.enqueue(frame(1, "visual:b"));
    // Any eviction loses state, so a resync is forced rather than leaving the
    // surface silently stale.
    expect(result.forcedResync).toBe(true);
    const remaining = batcher.drainAll().map((f) => f.entityKey);
    expect(remaining).toEqual(["visual:a", "visual:b"]);
  });

  it("forces a resync when a P0 frame must be evicted", () => {
    const batcher = new FrameBatcher({ capacity: 1, flushMs: zeroFlush });
    batcher.enqueue(frame(0, "order:1", 1));
    const result = batcher.enqueue(frame(0, "order:2", 2));
    expect(result.forcedResync).toBe(true);
    expect(batcher.size()).toBe(1);
  });

  it("orders drained frames by priority", () => {
    const batcher = new FrameBatcher({ capacity: 10, flushMs: zeroFlush });
    batcher.enqueue(frame(2, "p2"));
    batcher.enqueue(frame(0, "p0"));
    batcher.enqueue(frame(1, "p1"));
    expect(batcher.drainAll().map((f) => f.priority)).toEqual([0, 1, 2]);
  });
});
