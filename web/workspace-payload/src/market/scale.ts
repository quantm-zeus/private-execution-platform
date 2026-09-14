import type { CandleLike } from "./ring-buffer";

export interface PriceRange {
  readonly min: number;
  readonly max: number;
}

export interface Viewport {
  readonly startMs: number;
  readonly endMs: number;
  readonly minPrice: number;
  readonly maxPrice: number;
}

/** Price range across a candle slice; null when there is no drawable data. */
export function computePriceRange(candles: readonly CandleLike[]): PriceRange | null {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const candle of candles) {
    if (!Number.isFinite(candle.high) || !Number.isFinite(candle.low)) continue;
    if (candle.high > max) max = candle.high;
    if (candle.low < min) min = candle.low;
  }
  if (!Number.isFinite(min) || !Number.isFinite(max)) return null;
  return { min, max };
}

export function padRange(range: PriceRange, padPct = 0.05): PriceRange {
  const span = range.max - range.min;
  const pad = span === 0 ? Math.abs(range.max) * 0.01 || 1 : span * padPct;
  return { min: range.min - pad, max: range.max + pad };
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function safeRatio(numerator: number, denominator: number): number {
  if (!Number.isFinite(denominator) || denominator === 0) return 0.5;
  const ratio = numerator / denominator;
  if (!Number.isFinite(ratio)) return 0.5;
  return clamp(ratio, 0, 1);
}

export function priceToY(price: number, range: PriceRange, height: number, padding = 0): number {
  const usable = Math.max(1, height - padding * 2);
  const ratio = safeRatio(price - range.min, range.max - range.min);
  return padding + (1 - ratio) * usable;
}

export function yToPrice(y: number, range: PriceRange, height: number, padding = 0): number {
  const usable = Math.max(1, height - padding * 2);
  const ratio = safeRatio(y - padding, usable);
  return range.min + (1 - ratio) * (range.max - range.min);
}

export function timeToX(timeMs: number, startMs: number, endMs: number, width: number, padding = 0): number {
  const usable = Math.max(1, width - padding * 2);
  const ratio = safeRatio(timeMs - startMs, endMs - startMs);
  return padding + ratio * usable;
}

export function xToTime(x: number, startMs: number, endMs: number, width: number, padding = 0): number {
  const usable = Math.max(1, width - padding * 2);
  const ratio = safeRatio(x - padding, usable);
  return startMs + ratio * (endMs - startMs);
}

/** A "nice" axis step (1/2/5 × 10^k) that yields roughly `targetTicks` ticks. */
export function niceStep(span: number, targetTicks = 5): number {
  if (!Number.isFinite(span) || span <= 0) return 1;
  const raw = span / Math.max(1, targetTicks);
  const magnitude = Math.pow(10, Math.floor(Math.log10(raw)));
  const normalized = raw / magnitude;
  let step: number;
  if (normalized <= 1) step = 1;
  else if (normalized <= 2) step = 2;
  else if (normalized <= 5) step = 5;
  else step = 10;
  return step * magnitude;
}

export function clampViewport(
  viewport: Viewport,
  dataStartMs: number,
  dataEndMs: number,
  minSpanMs: number,
): Viewport {
  const span = Math.max(minSpanMs, viewport.endMs - viewport.startMs);
  let start = viewport.startMs;
  if (start < dataStartMs) start = dataStartMs;
  if (start + span > dataEndMs) start = Math.max(dataStartMs, dataEndMs - span);
  return { ...viewport, startMs: start, endMs: start + span };
}

export function panViewport(
  viewport: Viewport,
  deltaMs: number,
  dataStartMs: number,
  dataEndMs: number,
): Viewport {
  const span = viewport.endMs - viewport.startMs;
  return clampViewport(
    { ...viewport, startMs: viewport.startMs + deltaMs, endMs: viewport.startMs + deltaMs + span },
    dataStartMs,
    dataEndMs,
    span,
  );
}

export function zoomViewport(
  viewport: Viewport,
  factor: number,
  anchorMs: number,
  minSpanMs: number,
  dataStartMs: number,
  dataEndMs: number,
): Viewport {
  const currentSpan = viewport.endMs - viewport.startMs;
  const nextSpan = clamp(currentSpan * factor, minSpanMs, Math.max(minSpanMs, dataEndMs - dataStartMs || minSpanMs));
  const anchorRatio = safeRatio(anchorMs - viewport.startMs, currentSpan);
  const start = anchorMs - anchorRatio * nextSpan;
  return clampViewport(
    { ...viewport, startMs: start, endMs: start + nextSpan },
    dataStartMs,
    dataEndMs,
    minSpanMs,
  );
}
