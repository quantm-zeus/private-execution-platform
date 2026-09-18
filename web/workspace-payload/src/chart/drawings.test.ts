import { describe, expect, it } from "vitest";
import {
  DRAWING_TOOLS,
  RULER_OVERLAY_NAME,
  createDrawingController,
  createRulerOverlayTemplate,
  drawingScopeKey,
  drawingToolById,
  formatRulerLabel,
  measureRuler,
  type DrawingChartApi,
  type OverlayRemoveLike,
} from "./drawings";

/** Required built-in overlay names from KLineChart v9 / Pro 0.1.1. */
const REQUIRED_OVERLAYS = [
  "segment",
  "horizontalStraightLine",
  "verticalStraightLine",
  "rayLine",
  "rect",
  "fibonacciLine",
];

class FakeChart implements DrawingChartApi {
  readonly created: { id: string; config: Record<string, unknown> }[] = [];
  readonly removed: (string | OverlayRemoveLike | undefined)[] = [];
  private next = 1;

  createOverlay(value: unknown): string | null {
    const config: Record<string, unknown> =
      typeof value === "string" ? { name: value } : { ...(value as Record<string, unknown>) };
    const id = `overlay-${this.next++}`;
    this.created.push({ id, config });
    return id;
  }

  removeOverlay(remove?: string | OverlayRemoveLike): void {
    this.removed.push(remove);
  }

  /** Simulate the vendor firing the merged selection callbacks. */
  emitSelect(id: string): void {
    const entry = this.created.find((item) => item.id === id);
    (entry?.config.onSelected as ((event: unknown) => void) | undefined)?.({ overlay: { id } });
  }

  emitDeselect(id: string): void {
    const entry = this.created.find((item) => item.id === id);
    (entry?.config.onDeselected as ((event: unknown) => void) | undefined)?.({ overlay: { id } });
  }

  emitDrawEnd(id: string): void {
    const entry = this.created.find((item) => item.id === id);
    (entry?.config.onDrawEnd as (() => void) | undefined)?.();
  }
}

describe("drawing tools", () => {
  it("covers every required capability with a real built-in overlay", () => {
    const ids = DRAWING_TOOLS.map((tool) => tool.id);
    expect(ids).toContain("ruler");
    for (const overlay of REQUIRED_OVERLAYS) {
      expect(DRAWING_TOOLS.some((tool) => tool.overlay === overlay)).toBe(true);
    }
    expect(drawingToolById("ruler")?.overlay).toBe(RULER_OVERLAY_NAME);
    expect(drawingToolById("trend")?.overlay).toBe("segment");
  });

  it("scopes drawings to the exact token identity", () => {
    expect(drawingScopeKey({ chain: "base", address: "0xA" })).toBe("base:0xA");
    expect(drawingScopeKey({ chain: "base", address: "0xB" })).not.toBe(
      drawingScopeKey({ chain: "base", address: "0xA" }),
    );
    expect(drawingScopeKey({ chain: "", address: "" })).toBe("ohlcv:default");
  });
});

describe("measureRuler", () => {
  it("computes price, percent, candle and time distance", () => {
    const measurement = measureRuler(
      { value: 100, dataIndex: 10, timestamp: 1_000_000 },
      { value: 110, dataIndex: 14, timestamp: 1_240_000 },
    )!;
    expect(measurement.priceDelta).toBeCloseTo(10);
    expect(measurement.percentDelta).toBeCloseTo(10);
    expect(measurement.candleCount).toBe(4);
    expect(measurement.elapsedMs).toBe(240_000);
    expect(measurement.up).toBe(true);
  });

  it("handles a down move and returns null when a price is unknown", () => {
    const down = measureRuler(
      { value: 100, dataIndex: 0, timestamp: 0 },
      { value: 90, dataIndex: 1, timestamp: 60_000 },
    )!;
    expect(down.priceDelta).toBeCloseTo(-10);
    expect(down.up).toBe(false);
    expect(measureRuler({ value: null, dataIndex: 0, timestamp: 0 }, { value: 90, dataIndex: 1, timestamp: 0 })).toBeNull();
  });

  it("does not fabricate candle/time distance when the points lack them", () => {
    const measurement = measureRuler(
      { value: 100, dataIndex: null, timestamp: null },
      { value: 110, dataIndex: null, timestamp: null },
    )!;
    expect(measurement.candleCount).toBeNull();
    expect(measurement.elapsedMs).toBeNull();
    const label = formatRulerLabel(measurement);
    expect(label).toContain("+10.00%");
    expect(label).not.toContain("0 bars");
    expect(label).not.toContain("0s");
  });

  it("formats a readable label", () => {
    const label = formatRulerLabel({
      priceDelta: 0.1,
      percentDelta: 10,
      candleCount: 3,
      elapsedMs: 180_000,
      up: true,
    });
    expect(label).toContain("+0.1");
    expect(label).toContain("+10.00%");
    expect(label).toContain("3 bars");
    expect(label).toContain("3m");
  });

  it("renders a span plus a measurement label through the overlay template", () => {
    const template = createRulerOverlayTemplate();
    const figures = template.createPointFigures!({
      overlay: {
        points: [
          { value: 1, dataIndex: 0, timestamp: 0 },
          { value: 1.1, dataIndex: 3, timestamp: 180_000 },
        ],
      },
      coordinates: [
        { x: 0, y: 100 },
        { x: 100, y: 0 },
      ],
      precision: { price: 4, volume: 2 },
    } as never);
    const list = Array.isArray(figures) ? figures : [figures];
    expect(list.some((figure) => figure.type === "line")).toBe(true);
    const label = list.find((figure) => figure.type === "rectText");
    expect(label).toBeTruthy();
    expect(String(label!.attrs.text)).toContain("+10.00%");
  });
});

describe("createDrawingController", () => {
  it("activates the ruler and built-in tools with the right overlay names", () => {
    const chart = new FakeChart();
    const controller = createDrawingController(chart);
    expect(controller.activate("ruler")).toBe(true);
    expect(controller.activeTool()).toBe("ruler");
    expect(chart.created[0]!.config.name).toBe(RULER_OVERLAY_NAME);
    expect(controller.activate("trend")).toBe(true);
    expect(chart.created[1]!.config.name).toBe("segment");
    expect(controller.activate("nope")).toBe(false);
    expect(controller.count()).toBe(2);
  });

  it("clears the active tool when the drawing completes", () => {
    const chart = new FakeChart();
    const controller = createDrawingController(chart);
    controller.activate("horizontal");
    const id = chart.created[0]!.id;
    expect(controller.activeTool()).toBe("horizontal");
    chart.emitDrawEnd(id);
    expect(controller.activeTool()).toBeNull();
  });

  it("cancels the in-progress drawing on Escape", () => {
    const chart = new FakeChart();
    const controller = createDrawingController(chart);
    controller.activate("rectangle");
    controller.cancel();
    expect(controller.activeTool()).toBeNull();
    expect(chart.removed.at(-1)).toBeUndefined();
  });

  it("removes the selected drawing on Delete and clears all behind a confirmation", () => {
    const chart = new FakeChart();
    const controller = createDrawingController(chart);
    controller.activate("trend");
    controller.activate("rectangle");
    const [first, second] = chart.created.map((entry) => entry.id);

    // Nothing is selected yet: Delete is a no-op.
    expect(controller.removeSelected()).toBe(false);
    chart.emitSelect(second!);
    expect(controller.selectedId()).toBe(second);
    expect(controller.removeSelected()).toBe(true);
    expect(chart.removed.at(-1)).toBe(second);
    expect(controller.count()).toBe(1);

    // Clear all removes every drawing (the empty filter matches all overlays).
    expect(controller.clearAll()).toBe(1);
    expect(chart.removed.at(-1)).toEqual({});
    expect(controller.count()).toBe(0);
    expect(controller.selectedId()).toBeNull();
    expect(chart.created.map((entry) => entry.id)).toContain(first);
  });

  it("notifies subscribers as state changes", () => {
    const chart = new FakeChart();
    const controller = createDrawingController(chart);
    let notifications = 0;
    const unsubscribe = controller.subscribe(() => {
      notifications += 1;
    });
    controller.activate("fibonacci");
    expect(notifications).toBeGreaterThan(0);
    unsubscribe();
    const before = notifications;
    controller.cancel();
    expect(notifications).toBe(before);
  });
});
