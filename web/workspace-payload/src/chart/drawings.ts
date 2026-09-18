// First-party drawing/measurement layer on top of KLineChart v9 overlays.
//
// KLineChart Pro 0.1.1 ships a professional drawing bar with the built-in
// overlay templates (segment, horizontal/vertical straight lines, ray, rect,
// fibonacci) but no ruler and no keyboard/clear-all affordances. This module
// adds exactly those missing pieces using supported v9 overlay APIs:
//
// - a registered `pepRuler` overlay template that draws a dashed span plus a
//   live price/percent/candle/time label (no DOM hacks);
// - a controller that activates a tool, cancels on Escape, removes the selected
//   drawing on Delete/Backspace, and clears all drawings behind a confirmation.
//
// Drawings are local in-memory UI state only. They are never persisted to
// localStorage/indexedDB, and a token change rebuilds the renderer so drawings
// cannot leak across token identity.

import { registerOverlay, type OverlayFigure, type OverlayTemplate } from "klinecharts";

export const RULER_OVERLAY_NAME = "pepRuler";

export interface DrawingTool {
  readonly id: string;
  /** Overlay template name; built-in v9 names for everything but the ruler. */
  readonly overlay: string;
  readonly label: string;
  readonly hint: string;
}

/** Minimum capabilities required of the toolbar. */
export const DRAWING_TOOLS: readonly DrawingTool[] = [
  {
    id: "ruler",
    overlay: RULER_OVERLAY_NAME,
    label: "Measure",
    hint: "Measure price, percent, candle and time distance",
  },
  { id: "trend", overlay: "segment", label: "Trend line", hint: "Draw a trend line" },
  {
    id: "horizontal",
    overlay: "horizontalStraightLine",
    label: "Horizontal line",
    hint: "Draw a horizontal price level",
  },
  {
    id: "vertical",
    overlay: "verticalStraightLine",
    label: "Vertical line",
    hint: "Draw a vertical time line",
  },
  { id: "ray", overlay: "rayLine", label: "Ray", hint: "Draw a ray" },
  { id: "rectangle", overlay: "rect", label: "Rectangle", hint: "Draw a price/time rectangle" },
  {
    id: "fibonacci",
    overlay: "fibonacciLine",
    label: "Fibonacci",
    hint: "Draw a Fibonacci retracement",
  },
];

export function drawingToolById(id: string): DrawingTool | undefined {
  return DRAWING_TOOLS.find((tool) => tool.id === id);
}

/** Scope key for drawings: one set per exact token identity. */
export function drawingScopeKey(subject: { chain: string; address: string }): string {
  if (!subject.chain || !subject.address) return "ohlcv:default";
  return `${subject.chain}:${subject.address}`;
}

export interface RulerPoint {
  readonly value: number | null;
  readonly dataIndex: number | null;
  readonly timestamp: number | null;
}

export interface RulerMeasurement {
  readonly priceDelta: number;
  readonly percentDelta: number;
  /** Candle distance, or `null` when the points carry no data index. */
  readonly candleCount: number | null;
  /** Elapsed time, or `null` when the points carry no timestamp. */
  readonly elapsedMs: number | null;
  readonly up: boolean;
}

/**
 * Pure measurement math for the ruler. Returns `null` when either endpoint has
 * no price, so the overlay never renders a fabricated zero. A missing candle
 * index or timestamp stays `null` rather than a fabricated `0`.
 */
export function measureRuler(start: RulerPoint, end: RulerPoint): RulerMeasurement | null {
  if (start.value === null || end.value === null) return null;
  if (!Number.isFinite(start.value) || !Number.isFinite(end.value) || start.value === 0) return null;
  const priceDelta = end.value - start.value;
  const percentDelta = (priceDelta / start.value) * 100;
  const candleCount =
    start.dataIndex !== null && end.dataIndex !== null
      ? Math.abs(end.dataIndex - start.dataIndex)
      : null;
  const elapsedMs =
    start.timestamp !== null && end.timestamp !== null
      ? Math.abs(end.timestamp - start.timestamp)
      : null;
  return { priceDelta, percentDelta, candleCount, elapsedMs, up: priceDelta >= 0 };
}

function formatDuration(ms: number): string {
  if (ms <= 0) return "0s";
  if (ms < 60_000) return `${Math.round(ms / 1_000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${Math.round(ms / 3_600_000)}h`;
  return `${Math.round(ms / 86_400_000)}d`;
}

/** Human-readable ruler label, e.g. `+0.0125 (+2.50%) · 4 bars · 4m`. */
export function formatRulerLabel(measurement: RulerMeasurement, pricePrecision = 6): string {
  const sign = measurement.priceDelta >= 0 ? "+" : "";
  const delta = `${sign}${measurement.priceDelta.toFixed(pricePrecision).replace(/\.?0+$/, "")}`;
  const percent = `${measurement.percentDelta >= 0 ? "+" : ""}${measurement.percentDelta.toFixed(2)}%`;
  const parts = [`${delta} (${percent})`];
  if (measurement.candleCount !== null) {
    parts.push(`${measurement.candleCount} bar${measurement.candleCount === 1 ? "" : "s"}`);
  }
  if (measurement.elapsedMs !== null) parts.push(formatDuration(measurement.elapsedMs));
  return parts.join(" · ");
}

let rulerRegistered = false;

/** Idempotently register the ruler overlay template. */
export function registerRulerOverlay(): void {
  if (rulerRegistered) return;
  registerOverlay(createRulerOverlayTemplate());
  rulerRegistered = true;
}

export function createRulerOverlayTemplate(): OverlayTemplate {
  return {
    name: RULER_OVERLAY_NAME,
    totalStep: 2,
    needDefaultPointFigure: true,
    createPointFigures: ({ overlay, coordinates, precision }): OverlayFigure[] => {
      if (coordinates.length < 2) return [];
      const points = overlay.points ?? [];
      const measurement = measureRuler(
        {
          value: points[0]?.value ?? null,
          dataIndex: points[0]?.dataIndex ?? null,
          timestamp: points[0]?.timestamp ?? null,
        },
        {
          value: points[1]?.value ?? null,
          dataIndex: points[1]?.dataIndex ?? null,
          timestamp: points[1]?.timestamp ?? null,
        },
      );
      const figures: OverlayFigure[] = [
        {
          key: "ruler-span",
          type: "line",
          attrs: { coordinates },
          styles: { color: "#e9b44c", size: 1, style: "dashed" },
        },
      ];
      if (measurement) {
        const x = (coordinates[0]!.x + coordinates[1]!.x) / 2;
        const y = Math.min(coordinates[0]!.y, coordinates[1]!.y) - 10;
        figures.push({
          key: "ruler-label",
          type: "rectText",
          attrs: {
            x,
            y,
            text: formatRulerLabel(measurement, precision?.price ?? 6),
            align: "center",
            baseline: "bottom",
          },
          styles: {
            color: measurement.up ? "#3ddc97" : "#ff6b6b",
            size: 12,
            backgroundColor: "rgba(10,15,20,0.92)",
            borderColor: "#243440",
            borderSize: 1,
            borderRadius: 3,
            paddingLeft: 6,
            paddingRight: 6,
            paddingTop: 3,
            paddingBottom: 3,
          },
        });
      }
      return figures;
    },
  };
}

/** Minimal overlay-remove filter shape (KLineChart `OverlayRemove`). */
export interface OverlayRemoveLike {
  readonly id?: string;
  readonly groupId?: string;
  readonly name?: string;
}

/** The subset of the KLineChart `Chart` API the controller depends on. */
export interface DrawingChartApi {
  createOverlay(value: unknown, paneId?: string): string | null;
  removeOverlay(remove?: string | OverlayRemoveLike): void;
}

export interface DrawingController {
  activate(toolId: string): boolean;
  /** Cancel the in-progress drawing and clear the active-tool state. */
  cancel(): void;
  /** Remove the currently selected drawing; returns whether one was removed. */
  removeSelected(): boolean;
  /** Remove every drawing; returns how many were tracked. */
  clearAll(): number;
  activeTool(): string | null;
  selectedId(): string | null;
  count(): number;
  subscribe(listener: () => void): () => void;
}

interface TrackedOverlay {
  readonly name: string | null;
  readonly groupId: string | null;
}

/**
 * Owns drawing activation/selection/removal. It wraps `createOverlay` and
 * `removeOverlay` on the vendor chart instance because KLineChart v9 exposes no
 * public "selected overlay" getter; the wrap only records ids and merges the
 * `onSelected`/`onDeselected` callbacks, so every drawing (including the ones
 * Pro's own bar creates) stays tracked for Delete and Clear all.
 */
export function createDrawingController(chart: DrawingChartApi): DrawingController {
  const tracked = new Map<string, TrackedOverlay>();
  const listeners = new Set<() => void>();
  let selected: string | null = null;
  let active: string | null = null;

  const notify = (): void => {
    for (const listener of listeners) listener();
  };

  const originalCreate = chart.createOverlay.bind(chart);
  const originalRemove = chart.removeOverlay.bind(chart);

  chart.createOverlay = (value: unknown, paneId?: string): string | null => {
    const config: Record<string, unknown> =
      typeof value === "string" ? { name: value } : { ...(value as Record<string, unknown>) };
    const name = typeof config.name === "string" ? config.name : null;
    const groupId = typeof config.groupId === "string" ? config.groupId : null;
    const previousSelected = config.onSelected as ((event: unknown) => boolean) | undefined;
    const previousDeselected = config.onDeselected as ((event: unknown) => boolean) | undefined;
    config.onSelected = (event: unknown): boolean => {
      const id = (event as { overlay?: { id?: string } }).overlay?.id ?? null;
      if (id) selected = id;
      notify();
      return previousSelected ? previousSelected(event) : true;
    };
    config.onDeselected = (event: unknown): boolean => {
      const id = (event as { overlay?: { id?: string } }).overlay?.id ?? null;
      if (id && selected === id) selected = null;
      notify();
      return previousDeselected ? previousDeselected(event) : true;
    };
    const id = originalCreate(config, paneId);
    if (id) {
      tracked.set(id, { name, groupId });
      notify();
    }
    return id;
  };

  chart.removeOverlay = (remove?: string | OverlayRemoveLike): void => {
    originalRemove(remove);
    if (remove === undefined) {
      // Cancels an in-progress drawing only; completed overlays stay.
      selected = null;
    } else if (typeof remove === "string") {
      tracked.delete(remove);
      if (selected === remove) selected = null;
    } else if (remove) {
      for (const [id, meta] of [...tracked]) {
        const matches =
          (remove.id === undefined || remove.id === id) &&
          (remove.groupId === undefined || remove.groupId === meta.groupId) &&
          (remove.name === undefined || remove.name === meta.name);
        if (matches) {
          tracked.delete(id);
          if (selected === id) selected = null;
        }
      }
    }
    notify();
  };

  return {
    activate(toolId: string): boolean {
      const tool = drawingToolById(toolId);
      if (!tool) return false;
      active = tool.id;
      if (tool.id === "ruler") registerRulerOverlay();
      chart.createOverlay({
        name: tool.overlay,
        onDrawEnd: () => {
          active = null;
          notify();
        },
      });
      notify();
      return true;
    },
    cancel(): void {
      active = null;
      chart.removeOverlay();
      notify();
    },
    removeSelected(): boolean {
      if (selected === null || !tracked.has(selected)) return false;
      chart.removeOverlay(selected);
      return true;
    },
    clearAll(): number {
      const count = tracked.size;
      if (count > 0) {
        // An empty filter matches every overlay, including any untracked one.
        chart.removeOverlay({});
      }
      tracked.clear();
      selected = null;
      notify();
      return count;
    },
    activeTool: () => active,
    selectedId: () => selected,
    count: () => tracked.size,
    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
