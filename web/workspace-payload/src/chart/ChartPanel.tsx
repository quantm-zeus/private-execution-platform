import {
  createEffect,
  createSignal,
  onCleanup,
  onMount,
  type Component,
} from "solid-js";
import { parseDepthSnapshot, applyMarketFrame, createMarketFrameStores } from "./frames";
import { DEFAULT_CHART_THEME, renderChart } from "./renderer";
import { formatAmount, formatBps } from "../core/format";
import { TIMEFRAMES, timeframeById } from "../market/ohlcv";
import { computePriceRange, padRange, xToTime, zoomViewport, type Viewport } from "../market/scale";
import { useRealtimeFeedContext } from "../realtime/feed-context";
import type { DecodedFrame } from "../realtime/types";
import { Badge, Panel } from "../components/ui/primitives";
import { EmptyBlock } from "../components/ui/states";

export interface ChartPanelProps {
  /** Entity key from the realtime feed, e.g. `ohlcv:BASE:SOL`. */
  readonly entityKey?: string;
  readonly initialTimeframe?: string;
  readonly bars?: number;
}

/**
 * Main-thread Canvas chart. The worker has already decrypted/normalized frames;
 * this component only applies them to bounded local buffers and paints.
 */
export const ChartPanel: Component<ChartPanelProps> = (props) => {
  const entityKey = () => props.entityKey ?? "ohlcv:default";
  const [timeframeId, setTimeframeId] = createSignal(props.initialTimeframe ?? "1m");
  const [version, setVersion] = createSignal(0);
  const [size, setSize] = createSignal({ width: 640, height: 360 });
  const [endMs, setEndMs] = createSignal<number | null>(null);
  const [spanMs, setSpanMs] = createSignal<number | null>(null);
  const stores = createMarketFrameStores();
  const [dragging, setDragging] = createSignal(false);
  const feed = useRealtimeFeedContext();
  let canvas: HTMLCanvasElement | undefined;
  let container: HTMLDivElement | undefined;
  let dragStartX = 0;
  let dragStartEnd = 0;
  let raf = 0;

  const currentTimeframe = () => timeframeById(timeframeId()) ?? TIMEFRAMES[3]!;

  const series = () => stores.series.get(`${entityKey()}#${timeframeId()}`);

  const scheduleRender = () => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      draw();
    });
  };

  const draw = () => {
    if (!canvas) return;
    const dpr = typeof devicePixelRatio === "number" ? Math.min(devicePixelRatio, 2) : 1;
    const { width, height } = size();
    if (width <= 0 || height <= 0) return;
    const targetWidth = Math.round(width * dpr);
    const targetHeight = Math.round(height * dpr);
    if (canvas.width !== targetWidth) canvas.width = targetWidth;
    if (canvas.height !== targetHeight) canvas.height = targetHeight;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const all = series()?.toArray() ?? [];
    const tfMs = currentTimeframe().ms;
    const bars = props.bars ?? 120;
    const span = spanMs() ?? tfMs * bars;
    const last = all[all.length - 1];
    const end = endMs() ?? (last ? last.timeMs + tfMs : Date.now());
    const start = end - span;
    const visible = all.filter((candle) => candle.timeMs >= start && candle.timeMs <= end);
    const rawRange = computePriceRange(visible);
    const viewport: Viewport = rawRange
      ? { startMs: start, endMs: end, minPrice: padRange(rawRange).min, maxPrice: padRange(rawRange).max }
      : { startMs: start, endMs: end, minPrice: 0, maxPrice: 1 };
    renderChart(ctx, {
      candles: visible,
      viewport,
      width,
      height,
      theme: DEFAULT_CHART_THEME,
      lastPrice: last?.close ?? null,
    });
  };

  const onFrame = (frames: readonly DecodedFrame[]) => {
    let changed = false;
    for (const frame of frames) {
      if (frame.channel !== "ohlcv" && frame.channel !== "depth") continue;
      const result = applyMarketFrame(stores, frame);
      changed = changed || result.changed;
    }
    if (changed) {
      setEndMs(null);
      setVersion((value) => value + 1);
    }
  };

  onMount(() => {
    const unsubscribe = feed?.subscribe(onFrame);
    onCleanup(() => unsubscribe?.());

    if (container && typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver((entries) => {
        const rect = entries[0]?.contentRect;
        if (rect) setSize({ width: rect.width, height: rect.height });
      });
      observer.observe(container);
      onCleanup(() => observer.disconnect());
      const rect = container.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) setSize({ width: rect.width, height: rect.height });
    }
    onCleanup(() => {
      if (raf) cancelAnimationFrame(raf);
    });
    scheduleRender();
  });

  createEffect(() => {
    version();
    size();
    timeframeId();
    spanMs();
    endMs();
    scheduleRender();
  });

  const onWheel = (event: WheelEvent) => {
    event.preventDefault();
    const rect = canvas?.getBoundingClientRect();
    if (!rect) return;
    const all = series()?.toArray() ?? [];
    const tfMs = currentTimeframe().ms;
    const span = spanMs() ?? tfMs * (props.bars ?? 120);
    const last = all[all.length - 1];
    const end = endMs() ?? (last ? last.timeMs + tfMs : Date.now());
    const start = end - span;
    const anchorX = event.clientX - rect.left;
    const anchor = xToTime(anchorX, start, end, rect.width);
    const factor = event.deltaY > 0 ? 1.15 : 0.87;
    const dataStart = all[0]?.timeMs ?? start - span;
    const dataEnd = last ? last.timeMs + tfMs : end;
    const next = zoomViewport(
      { startMs: start, endMs: end, minPrice: 0, maxPrice: 1 },
      factor,
      anchor,
      tfMs * 5,
      Math.min(dataStart, start - span),
      Math.max(dataEnd, end),
    );
    setSpanMs(next.endMs - next.startMs);
    setEndMs(next.endMs);
  };

  const onPointerDown = (event: PointerEvent) => {
    if (!canvas) return;
    const all = series()?.toArray() ?? [];
    if (all.length === 0) return;
    setDragging(true);
    dragStartX = event.clientX;
    const tfMs = currentTimeframe().ms;
    const span = spanMs() ?? tfMs * (props.bars ?? 120);
    dragStartEnd = endMs() ?? (all[all.length - 1]!.timeMs + tfMs);
    canvas.setPointerCapture?.(event.pointerId);
  };

  const onPointerMove = (event: PointerEvent) => {
    if (!dragging() || !canvas) return;
    const rect = canvas.getBoundingClientRect();
    const tfMs = currentTimeframe().ms;
    const span = spanMs() ?? tfMs * (props.bars ?? 120);
    const deltaPx = event.clientX - dragStartX;
    const deltaMs = -(deltaPx / Math.max(1, rect.width)) * span;
    setSpanMs(span);
    setEndMs(dragStartEnd + deltaMs);
  };

  const onPointerUp = (event: PointerEvent) => {
    setDragging(false);
    canvas?.releasePointerCapture?.(event.pointerId);
  };

  const reset = () => {
    setEndMs(null);
    setSpanMs(null);
    scheduleRender();
  };

  const depth = () => {
    // Track the frame version so depth tables re-render with new snapshots.
    version();
    const bids = stores.depth.bidLevels().slice(0, 8);
    const asks = stores.depth.askLevels().slice(0, 8);
    return { bids, asks };
  };

  return (
    <div class="chart-panel">
      <div class="timeframe-row" role="group" aria-label="Chart timeframe">
        {TIMEFRAMES.map((tf) => (
          <button
           
            type="button"
            class="chip-button"
            aria-pressed={timeframeId() === tf.id}
            onClick={() => {
              setTimeframeId(tf.id);
              reset();
            }}
          >
            {tf.label}
          </button>
        ))}
        <button type="button" class="chip-button" onClick={reset}>
          Reset
        </button>
        <Badge tone={version() > 0 ? "positive" : "muted"}>
          {version() > 0 ? "LOCAL DATA" : "AWAITING FEED"}
        </Badge>
      </div>
      <div
        class="chart-frame chart-frame--interactive"
        ref={(element) => {
          container = element;
        }}
      >
        <canvas
          ref={(element) => {
            canvas = element;
          }}
          class="chart-canvas"
          role="img"
          aria-label={`Price chart, ${timeframeId()} timeframe`}
          onWheel={onWheel}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
          onDblClick={reset}
        />
      </div>
      <div class="depth-columns">
        <div class="depth-col">
          <h3>Bids</h3>
          {depth().bids.length === 0 ? (
            <EmptyBlock title="No depth" detail="Depth frames require the encrypted feed (BR-2)." />
          ) : (
            <ul class="depth-list">
              {depth().bids.map((level) => (
                <li class="depth-list__row depth-list__row--bid">
                  <span>{level.price}</span>
                  <span>{formatAmount(level.size)}</span>
                  <span class="muted">{formatAmount(level.cumulativeSize)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div class="depth-col">
          <h3>Asks</h3>
          {depth().asks.length === 0 ? (
            <EmptyBlock title="No depth" detail="Depth frames require the encrypted feed (BR-2)." />
          ) : (
            <ul class="depth-list">
              {depth().asks.map((level) => (
                <li class="depth-list__row depth-list__row--ask">
                  <span>{level.price}</span>
                  <span>{formatAmount(level.size)}</span>
                  <span class="muted">{formatAmount(level.cumulativeSize)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <p class="muted">
        Spread {formatBps(version() >= 0 ? stores.depth.spreadBps() : null)} · imbalance{" "}
        {stores.depth.imbalancePct() === null ? "—" : `${stores.depth.imbalancePct()!.toFixed(1)}%`}
      </p>
    </div>
  );
};

export default ChartPanel;
