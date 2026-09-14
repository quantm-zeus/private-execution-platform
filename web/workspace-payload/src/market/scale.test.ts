import { describe, expect, it } from "vitest";
import {
  clampViewport,
  computePriceRange,
  niceStep,
  padRange,
  panViewport,
  priceToY,
  timeToX,
  xToTime,
  yToPrice,
  zoomViewport,
} from "./scale";

const candle = (timeMs: number, high: number, low: number) => ({
  timeMs,
  open: low,
  high,
  low,
  close: high,
  volume: 1,
});

describe("computePriceRange / padRange", () => {
  it("returns null for empty or invalid data", () => {
    expect(computePriceRange([])).toBeNull();
    expect(computePriceRange([candle(1, Number.NaN, 0)])).toBeNull();
  });

  it("computes min/max and pads", () => {
    const range = computePriceRange([candle(1, 12, 8), candle(2, 11, 9)]);
    expect(range).toEqual({ min: 8, max: 12 });
    expect(padRange(range!, 0.1)).toEqual({ min: 7.6, max: 12.4 });
  });

  it("never collapses a zero-width range", () => {
    const range = computePriceRange([candle(1, 10, 10)]);
    const padded = padRange(range!);
    expect(padded.max).toBeGreaterThan(padded.min);
  });
});

describe("coordinate mapping", () => {
  const range = { min: 0, max: 100 };
  it("maps price to y and back", () => {
    expect(priceToY(100, range, 200)).toBe(0);
    expect(priceToY(0, range, 200)).toBe(200);
    expect(yToPrice(0, range, 200)).toBe(100);
    expect(yToPrice(200, range, 200)).toBe(0);
    for (const price of [0, 25, 50, 75, 100]) {
      expect(yToPrice(priceToY(price, range, 200), range, 200)).toBeCloseTo(price, 6);
    }
  });

  it("maps time to x and back", () => {
    expect(timeToX(0, 0, 1000, 400)).toBe(0);
    expect(timeToX(1000, 0, 1000, 400)).toBe(400);
    expect(xToTime(0, 0, 1000, 400)).toBe(0);
    expect(xToTime(400, 0, 1000, 400)).toBe(1000);
  });

  it("handles zero spans without dividing by zero", () => {
    expect(priceToY(5, { min: 5, max: 5 }, 100)).toBe(50);
    expect(timeToX(5, 5, 5, 100)).toBe(50);
  });
});

describe("niceStep", () => {
  it("produces 1/2/5 ladder values", () => {
    expect(niceStep(100, 5)).toBe(20);
    expect(niceStep(9, 5)).toBe(2);
    expect(niceStep(0, 5)).toBe(1);
    expect(niceStep(-5, 5)).toBe(1);
  });
});

describe("viewport transforms", () => {
  const dataStart = 0;
  const dataEnd = 10_000;

  it("clamps within the data window", () => {
    const clamped = clampViewport(
      { startMs: -500, endMs: 500, minPrice: 0, maxPrice: 1 },
      dataStart,
      dataEnd,
      1_000,
    );
    expect(clamped.startMs).toBe(0);
    expect(clamped.endMs).toBe(1_000);
  });

  it("pans while keeping span", () => {
    const panned = panViewport(
      { startMs: 2_000, endMs: 4_000, minPrice: 0, maxPrice: 1 },
      1_000,
      dataStart,
      dataEnd,
    );
    expect(panned.startMs).toBe(3_000);
    expect(panned.endMs).toBe(5_000);
  });

  it("zooms around an anchor and respects the minimum span", () => {
    const zoomed = zoomViewport(
      { startMs: 0, endMs: 10_000, minPrice: 0, maxPrice: 1 },
      0.5,
      5_000,
      1_000,
      dataStart,
      dataEnd,
    );
    expect(zoomed.endMs - zoomed.startMs).toBe(5_000);
    expect((zoomed.startMs + zoomed.endMs) / 2).toBeCloseTo(5_000, 6);

    const minZoomed = zoomViewport(
      { startMs: 0, endMs: 10_000, minPrice: 0, maxPrice: 1 },
      0.0001,
      5_000,
      2_000,
      dataStart,
      dataEnd,
    );
    expect(minZoomed.endMs - minZoomed.startMs).toBe(2_000);
  });
});
