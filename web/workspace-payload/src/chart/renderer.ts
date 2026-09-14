import type { CandleLike } from "../market/ring-buffer";
import { niceStep, priceToY, timeToX, type Viewport } from "../market/scale";

export interface ChartTheme {
  readonly background: string;
  readonly grid: string;
  readonly axis: string;
  readonly text: string;
  readonly up: string;
  readonly down: string;
  readonly lastLine: string;
  readonly crosshair: string;
}

export const DEFAULT_CHART_THEME: ChartTheme = {
  background: "#0d131b",
  grid: "rgba(38,49,63,0.7)",
  axis: "#3a4a5e",
  text: "#8b98a9",
  up: "#3ddc97",
  down: "#ff5d6c",
  lastLine: "#3ad1d9",
  crosshair: "rgba(126,231,255,0.5)",
};

export interface RenderChartOptions {
  readonly candles: readonly CandleLike[];
  readonly viewport: Viewport;
  readonly width: number;
  readonly height: number;
  readonly theme?: ChartTheme;
  readonly volumeHeight?: number;
  readonly axisGutter?: number;
  readonly padding?: number;
  readonly crosshair?: { readonly x: number; readonly y: number } | null;
  readonly lastPrice?: number | null;
  readonly nowMs?: number;
}

/**
 * Immediate-mode Canvas renderer on the main thread. Bounded work: only visible
 * candles are touched and the caller passes a bounded ring-buffer slice.
 */
export function renderChart(ctx: CanvasRenderingContext2D, options: RenderChartOptions): void {
  const theme = options.theme ?? DEFAULT_CHART_THEME;
  const { width, height } = options;
  const padding = options.padding ?? 8;
  const axisGutter = options.axisGutter ?? 54;
  const volumeHeight = options.volumeHeight ?? Math.max(28, Math.round(height * 0.18));
  const plotWidth = Math.max(1, width - axisGutter);
  const priceHeight = Math.max(1, height - volumeHeight - padding);
  const { viewport, candles } = options;

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = theme.background;
  ctx.fillRect(0, 0, width, height);

  const priceRange = { min: viewport.minPrice, max: viewport.maxPrice };
  const priceSpan = viewport.maxPrice - viewport.minPrice;

  // Horizontal price grid + labels.
  const priceStep = niceStep(priceSpan, 5);
  ctx.strokeStyle = theme.grid;
  ctx.lineWidth = 1;
  ctx.font = "10px ui-monospace, monospace";
  ctx.textAlign = "left";
  ctx.textBaseline = "middle";
  const firstPrice = Math.ceil(viewport.minPrice / priceStep) * priceStep;
  for (let price = firstPrice; price <= viewport.maxPrice; price += priceStep) {
    const y = Math.round(priceToY(price, priceRange, priceHeight, padding)) + 0.5;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(plotWidth, y);
    ctx.stroke();
    ctx.fillStyle = theme.text;
    ctx.fillText(formatPrice(price), plotWidth + 4, y);
  }

  // Vertical time grid.
  const timeSpan = viewport.endMs - viewport.startMs;
  const timeStep = niceStep(timeSpan, 6);
  const firstTime = Math.ceil(viewport.startMs / timeStep) * timeStep;
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  for (let time = firstTime; time <= viewport.endMs; time += timeStep) {
    const x = Math.round(timeToX(time, viewport.startMs, viewport.endMs, plotWidth, padding)) + 0.5;
    ctx.strokeStyle = theme.grid;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, priceHeight);
    ctx.stroke();
    ctx.fillStyle = theme.text;
    ctx.fillText(formatTime(time), x, priceHeight + 2);
  }

  if (candles.length === 0) {
    ctx.fillStyle = theme.text;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("No local candles — awaiting encrypted feed", width / 2, priceHeight / 2);
    return;
  }

  // Candle bodies and wicks.
  const spacing = candles.length > 1 ? plotWidth / candles.length : plotWidth;
  const bodyWidth = Math.max(1, Math.min(14, spacing * 0.62));
  let maxVolume = 0;
  for (const candle of candles) maxVolume = Math.max(maxVolume, candle.volume || 0);
  const volumeTop = height - volumeHeight;

  for (let i = 0; i < candles.length; i++) {
    const candle = candles[i]!;
    const x = timeToX(candle.timeMs, viewport.startMs, viewport.endMs, plotWidth, padding);
    const color = candle.close >= candle.open ? theme.up : theme.down;
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 1;
    const highY = priceToY(candle.high, priceRange, priceHeight, padding);
    const lowY = priceToY(candle.low, priceRange, priceHeight, padding);
    ctx.beginPath();
    ctx.moveTo(Math.round(x) + 0.5, highY);
    ctx.lineTo(Math.round(x) + 0.5, lowY);
    ctx.stroke();
    const openY = priceToY(candle.open, priceRange, priceHeight, padding);
    const closeY = priceToY(candle.close, priceRange, priceHeight, padding);
    const top = Math.min(openY, closeY);
    const bodyH = Math.max(1, Math.abs(closeY - openY));
    ctx.fillRect(Math.round(x - bodyWidth / 2), Math.round(top), Math.round(bodyWidth), Math.round(bodyH));

    if (maxVolume > 0) {
      const volumeBar = Math.max(1, Math.round((candle.volume / maxVolume) * (volumeHeight - 4)));
      ctx.globalAlpha = 0.55;
      ctx.fillRect(Math.round(x - bodyWidth / 2), volumeTop + (volumeHeight - volumeBar), Math.round(bodyWidth), volumeBar);
      ctx.globalAlpha = 1;
    }
  }

  // Last price marker.
  const lastPrice = options.lastPrice ?? candles[candles.length - 1]!.close;
  if (Number.isFinite(lastPrice)) {
    const y = Math.round(priceToY(lastPrice, priceRange, priceHeight, padding)) + 0.5;
    ctx.strokeStyle = theme.lastLine;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(plotWidth, y);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Crosshair.
  if (options.crosshair) {
    ctx.strokeStyle = theme.crosshair;
    ctx.beginPath();
    ctx.moveTo(options.crosshair.x + 0.5, 0);
    ctx.lineTo(options.crosshair.x + 0.5, height);
    ctx.moveTo(0, options.crosshair.y + 0.5);
    ctx.lineTo(plotWidth, options.crosshair.y + 0.5);
    ctx.stroke();
  }
}

function formatPrice(price: number): string {
  const abs = Math.abs(price);
  if (abs >= 1_000) return price.toFixed(1);
  if (abs >= 1) return price.toFixed(3);
  if (abs >= 0.01) return price.toFixed(5);
  return price.toExponential(2);
}

function formatTime(ms: number): string {
  const date = new Date(ms);
  return `${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(2, "0")}`;
}
