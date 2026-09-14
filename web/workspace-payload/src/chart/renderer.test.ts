import { describe, expect, it } from "vitest";
import { renderChart } from "./renderer";
import type { Viewport } from "../market/scale";

function fakeContext() {
  const calls: Record<string, number> = {};
  const record =
    (name: string) =>
    (..._args: unknown[]) => {
      calls[name] = (calls[name] ?? 0) + 1;
    };
  const ctx = {
    clearRect: record("clearRect"),
    fillRect: record("fillRect"),
    strokeRect: record("strokeRect"),
    beginPath: record("beginPath"),
    moveTo: record("moveTo"),
    lineTo: record("lineTo"),
    stroke: record("stroke"),
    fill: record("fill"),
    fillText: record("fillText"),
    setLineDash: record("setLineDash"),
    save: record("save"),
    restore: record("restore"),
    fillStyle: "",
    strokeStyle: "",
    lineWidth: 1,
    font: "",
    textAlign: "left",
    textBaseline: "top",
    globalAlpha: 1,
  } as unknown as CanvasRenderingContext2D;
  return { ctx, calls };
}

const viewport: Viewport = { startMs: 0, endMs: 60_000, minPrice: 9, maxPrice: 13 };

describe("renderChart", () => {
  it("paints a background and an empty-state message with no candles", () => {
    const { ctx, calls } = fakeContext();
    expect(() =>
      renderChart(ctx, { candles: [], viewport, width: 400, height: 240 }),
    ).not.toThrow();
    expect(calls.clearRect).toBeGreaterThan(0);
    expect(calls.fillRect).toBeGreaterThan(0);
    expect(calls.fillText).toBeGreaterThan(0);
    // No candles means no wick lines, no last-price line and no crosshair.
    expect(calls.setLineDash ?? 0).toBe(0);
  });

  it("draws wicks, bodies and volume for candles", () => {
    const { ctx, calls } = fakeContext();
    const candles = Array.from({ length: 5 }, (_, i) => ({
      timeMs: i * 10_000,
      open: 10 + i * 0.1,
      high: 11 + i * 0.1,
      low: 9.5 + i * 0.1,
      close: 10.5 + i * 0.1,
      volume: 100 + i,
    }));
    renderChart(ctx, { candles, viewport, width: 400, height: 240, lastPrice: 10.6 });
    expect(calls.moveTo).toBeGreaterThanOrEqual(candles.length);
    expect(calls.lineTo).toBeGreaterThanOrEqual(candles.length);
    expect(calls.fillRect).toBeGreaterThanOrEqual(candles.length);
    expect(calls.setLineDash).toBeGreaterThan(0);
  });

  it("renders a crosshair when provided", () => {
    const { ctx, calls } = fakeContext();
    renderChart(ctx, {
      candles: [{ timeMs: 0, open: 10, high: 11, low: 9, close: 10.5, volume: 1 }],
      viewport,
      width: 320,
      height: 200,
      crosshair: { x: 100, y: 80 },
    });
    expect(calls.stroke).toBeGreaterThan(1);
  });

  it("handles zero-size canvases without throwing", () => {
    const { ctx } = fakeContext();
    expect(() => renderChart(ctx, { candles: [], viewport, width: 0, height: 0 })).not.toThrow();
  });
});
