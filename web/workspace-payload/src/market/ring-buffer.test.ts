import { describe, expect, it } from "vitest";
import { CandleRingBuffer, NumericRingBuffer } from "./ring-buffer";

describe("NumericRingBuffer", () => {
  it("retains insertion order until capacity", () => {
    const buffer = new NumericRingBuffer(3);
    buffer.push(1);
    buffer.push(2);
    expect(buffer.length).toBe(2);
    expect(buffer.toArray()).toEqual([1, 2]);
    expect(buffer.first()).toBe(1);
    expect(buffer.last()).toBe(2);
  });

  it("overwrites the oldest value when full", () => {
    const buffer = new NumericRingBuffer(3);
    for (const value of [1, 2, 3, 4, 5]) buffer.push(value);
    expect(buffer.length).toBe(3);
    expect(buffer.toArray()).toEqual([3, 4, 5]);
    expect(buffer.get(0)).toBe(3);
  });

  it("returns undefined out of range and clears", () => {
    const buffer = new NumericRingBuffer(2);
    buffer.push(9);
    expect(buffer.get(-1)).toBeUndefined();
    expect(buffer.get(1)).toBeUndefined();
    buffer.clear();
    expect(buffer.length).toBe(0);
  });

  it("rejects invalid capacities", () => {
    expect(() => new NumericRingBuffer(0)).toThrowError();
    expect(() => new NumericRingBuffer(1.5)).toThrowError();
  });
});

describe("CandleRingBuffer", () => {
  const candle = (timeMs: number, close: number) => ({
    timeMs,
    open: close - 1,
    high: close + 1,
    low: close - 2,
    close,
    volume: 10,
  });

  it("stores and reads candles in order", () => {
    const buffer = new CandleRingBuffer(4);
    buffer.push(candle(1_000, 10));
    buffer.push(candle(2_000, 12));
    expect(buffer.length).toBe(2);
    expect(buffer.at(1)?.close).toBe(12);
    expect(buffer.last()?.timeMs).toBe(2_000);
  });

  it("replaces the newest candle in place", () => {
    const buffer = new CandleRingBuffer(4);
    buffer.push(candle(1_000, 10));
    buffer.push(candle(2_000, 12));
    expect(buffer.replaceLast(candle(2_000, 15))).toBe(true);
    expect(buffer.length).toBe(2);
    expect(buffer.last()?.close).toBe(15);
  });

  it("wraps around capacity and keeps the newest window", () => {
    const buffer = new CandleRingBuffer(2);
    buffer.push(candle(1_000, 1));
    buffer.push(candle(2_000, 2));
    buffer.push(candle(3_000, 3));
    expect(buffer.toArray().map((c) => c.timeMs)).toEqual([2_000, 3_000]);
  });
});
