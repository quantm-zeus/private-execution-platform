import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
  untrack,
  type Component,
} from "solid-js";
import {
  ChartFrameRouter,
  DEFAULT_CHART_SUBJECT,
  chartTicker,
  createLocalHistoryProvider,
  type ChartSubject,
} from "./chart-datafeed";
import { createPepHistoryProvider, createServerHistoryProvider } from "./history";
import {
  DRAWING_TOOLS,
  createDrawingController,
  type DrawingController,
} from "./drawings";
import { createProChart, type ProChartHandle } from "./pro/pro-chart";
import { PRO_PERIODS, createProDatafeed, type ProDatafeed } from "./pro/pro-datafeed";
import { isServedTimeframe, timeframeById, type Timeframe } from "../market/ohlcv";
import { ActionType } from "klinecharts";
import { formatAmount, formatBps, truncateAddress } from "../core/format";
import type { InstrumentRef } from "../core/types";
import { useRealtimeFeedContext } from "../realtime/feed-context";
import { useWorkspace } from "../state/session";
import { useWorkstation } from "../state/workstation";
import { Badge } from "../components/ui/primitives";
import { EmptyBlock } from "../components/ui/states";

export interface ChartPanelProps {
  /** Explicit entity key from the realtime feed, e.g. `ohlcv:BASE:SOL`. */
  readonly entityKey?: string;
  readonly initialTimeframe?: string;
  readonly bars?: number;
}

/** One crosshair OHLC readout row. Values are provider/candle truth only. */
interface CrosshairReadout {
  readonly open: number;
  readonly high: number;
  readonly low: number;
  readonly close: number;
  readonly volume: number | null;
}

/**
 * Derive the chart entity key from the shared target selection. An explicit
 * `override` (embedding) wins; otherwise a selected instrument targets
 * `ohlcv:${chain}:${address}` and no selection keeps the neutral default.
 */
export function chartEntityKeyFor(
  instrument: InstrumentRef | null,
  override?: string,
): string {
  if (override !== undefined && override.length > 0) return override;
  return instrument === null ? "ohlcv:default" : `ohlcv:${instrument.chain}:${instrument.address}`;
}

function subjectFromInstrument(instrument: InstrumentRef | null): ChartSubject | null {
  if (!instrument) return null;
  return { chain: instrument.chain, address: instrument.address, symbol: instrument.symbol };
}

/** Parse an explicit `ohlcv:<chain>:<address>` override into a chart subject. */
function subjectFromEntityKey(key: string): ChartSubject | null {
  const parts = key.split(":");
  if (parts.length !== 3 || parts[0] !== "ohlcv" || parts[1] === "" || parts[2] === "") return null;
  return { chain: parts[1]!, address: parts[2]!, symbol: parts[2]! };
}

function numOrDash(value: number | null): string {
  return value === null || !Number.isFinite(value) ? "—" : value.toFixed(6);
}

/**
 * KLineChart Pro price chart. The worker has already decrypted and normalized
 * frames; this component only routes them into bounded local buffers and the
 * injected datafeed (authenticated history + the local realtime bar bus).
 *
 * Two 36px pane bars sit above the plot and nothing overlays the plot or either
 * scale: the crosshair readout lives in bar 1, the drawing/timeframe/indicator
 * toolbar in bar 2. Chart data is visual/non-authoritative: execution always
 * depends on exact route simulation, never on a chart crossing.
 */
export const ChartPanel: Component<ChartPanelProps> = (props) => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const feed = useRealtimeFeedContext();
  const router = new ChartFrameRouter();
  const [version, setVersion] = createSignal(0);

  const activeTimeframe = createMemo<string>(() => {
    const shared = station.timeframe();
    if (timeframeById(shared)) return shared;
    if (props.initialTimeframe && timeframeById(props.initialTimeframe)) {
      return props.initialTimeframe;
    }
    return "1m";
  });
  const activeTimeframeDef = createMemo<Timeframe>(
    () => timeframeById(activeTimeframe()) ?? timeframeById("1m")!,
  );

  const explicitSubject = createMemo<ChartSubject | null>(() => {
    if (props.entityKey !== undefined && props.entityKey.length > 0) {
      return subjectFromEntityKey(props.entityKey);
    }
    return null;
  });

  const subject = createMemo<ChartSubject>(
    () => explicitSubject() ?? subjectFromInstrument(ws.selectedInstrument()) ?? DEFAULT_CHART_SUBJECT,
  );

  const hasTarget = createMemo(
    () => explicitSubject() !== null || ws.selectedInstrument() !== null,
  );

  const buildDatafeed = (): ProDatafeed =>
    createProDatafeed({
      history: createPepHistoryProvider(
        createServerHistoryProvider({
          command: ws.command,
          ready: () => ws.commandReady(),
          chartAllowed: () => ws.capabilityDenial("chart") === null,
        }),
        createLocalHistoryProvider(router),
      ),
      realtime: { subscribe: (target, timeframe, sink) => router.subscribe(target, timeframe, sink) },
      resolveSubject: (ticker) => (chartTicker(subject()) === ticker ? subject() : null),
      historyLimit: props.bars,
    });

  onMount(() => {
    const unsubscribe = feed?.subscribe((frames) => {
      if (router.apply(frames)) setVersion((value) => value + 1);
    });
    onCleanup(() => unsubscribe?.());
  });

  let host: HTMLDivElement | undefined;
  let handle: ProChartHandle | null = null;
  let activeDatafeed: ProDatafeed | null = null;
  let drawing: DrawingController | null = null;
  let crosshairHandler: ((data?: unknown) => void) | null = null;
  const [drawingVersion, setDrawingVersion] = createSignal(0);
  const [clearArmed, setClearArmed] = createSignal(false);
  const [crosshair, setCrosshair] = createSignal<CrosshairReadout | null>(null);
  const [indicatorsOn, setIndicatorsOn] = createSignal(true);
  const drawingCount = createMemo(() => {
    drawingVersion();
    return drawing?.count() ?? 0;
  });
  const activeDrawingTool = createMemo(() => {
    drawingVersion();
    return drawing?.activeTool() ?? null;
  });
  // All seven tools the design requires: ruler/measure, trend, horizontal,
  // vertical, ray, rectangle, Fibonacci.
  const drawingTools = DRAWING_TOOLS;
  const onChartKeyDown = (event: KeyboardEvent): void => {
    if (!drawing) return;
    if (event.key === "Escape") {
      drawing.cancel();
      event.preventDefault();
      return;
    }
    if (event.key === "Delete" || event.key === "Backspace") {
      if (drawing.removeSelected()) event.preventDefault();
    }
  };
  // The plot is the product's primary surface, so pan/zoom/reset are operable
  // from the keyboard (DESIGN.md §5.3/§10). Drawing *placement* remains
  // pointer-only and is not claimed otherwise.
  const onPlotKeyDown = (event: KeyboardEvent): void => {
    const api = handle?.chartApi;
    if (!api) return;
    const rect = host?.getBoundingClientRect();
    const center = rect
      ? { x: Math.round(rect.width / 2), y: Math.round(rect.height / 2) }
      : { x: 0, y: 0 };
    switch (event.key) {
      case "ArrowLeft":
        event.preventDefault();
        api.scrollByDistance(-40);
        break;
      case "ArrowRight":
        event.preventDefault();
        api.scrollByDistance(40);
        break;
      case "ArrowUp":
      case "+":
      case "=":
        event.preventDefault();
        api.zoomAtCoordinate(1.1, center);
        break;
      case "ArrowDown":
      case "-":
      case "_":
        event.preventDefault();
        api.zoomAtCoordinate(0.9, center);
        break;
      case "0":
      case "Home":
        event.preventDefault();
        api.scrollToRealTime();
        break;
      default:
        break;
    }
  };
  let createdTicker: string | null = null;
  let createdNonce = -1;
  const [chartError, setChartError] = createSignal(false);
  const [reloadNonce, setReloadNonce] = createSignal(0);
  let hydratedKey: string | null = null;

  const selectedCandleCount = createMemo(() => {
    version();
    return router.localCandles(subject(), activeTimeframeDef()).length;
  });

  const risk = createMemo(() => station.visibleDetail()?.risk ?? null);
  const riskText = createMemo(() => {
    const value = risk();
    if (!value) return null;
    if (typeof value.level === "string" && value.level.length > 0) return value.level;
    return value.score == null ? "—" : String(value.score);
  });

  const applyIndicators = (on: boolean): void => {
    const api = handle?.chartApi;
    if (!api) return;
    try {
      if (on) api.createIndicator("MA", false, { id: "candle_pane" });
      else api.removeIndicator("candle_pane", "MA");
    } catch {
      // Vendor internals changed: the chart stays usable without the toggle.
    }
  };

  createEffect(() => {
    const current = subject();
    const ticker = chartTicker(current);
    const nonce = reloadNonce();
    if (!host) return;
    if (handle !== null && createdTicker === ticker && createdNonce === nonce) return;
    handle?.dispose();
    handle = null;
    activeDatafeed?.dispose();
    activeDatafeed = null;
    drawing = null;
    crosshairHandler = null;
    setClearArmed(false);
    setCrosshair(null);
    const datafeed = buildDatafeed();
    try {
      handle = createProChart(host, {
        subject: current,
        datafeed,
        timeframeId: untrack(activeTimeframe),
        testId: "pro-chart",
      });
      activeDatafeed = datafeed;
      createdTicker = ticker;
      createdNonce = nonce;
      const timeframe = untrack(activeTimeframeDef);
      if (router.localCandles(current, timeframe).length > 0) {
        hydratedKey = `${ticker}#${timeframe.id}`;
      }
      setChartError(false);
    } catch {
      datafeed.dispose();
      createdTicker = null;
      handle = null;
      drawing = null;
      setChartError(true);
      return;
    }
    // Drawing tools are an enhancement layered on the live chart: a failure here
    // must never discard the renderer (which would otherwise rebuild in a loop).
    try {
      drawing = handle.chartApi ? createDrawingController(handle.chartApi) : null;
      drawing?.subscribe(() => setDrawingVersion((value) => value + 1));
    } catch {
      drawing = null;
    }
    // Crosshair readout: it lives in the pane bar, never over the plot.
    try {
      const api = handle.chartApi;
      if (api) {
        crosshairHandler = (data?: unknown) => {
          const candle = (data as { kLineData?: Record<string, unknown> } | undefined)?.kLineData;
          if (
            !candle ||
            typeof candle.open !== "number" ||
            typeof candle.high !== "number" ||
            typeof candle.low !== "number" ||
            typeof candle.close !== "number"
          ) {
            setCrosshair(null);
            return;
          }
          setCrosshair({
            open: candle.open,
            high: candle.high,
            low: candle.low,
            close: candle.close,
            volume: typeof candle.volume === "number" ? candle.volume : null,
          });
        };
        api.subscribeAction(ActionType.OnCrosshairChange, crosshairHandler);
      }
    } catch {
      crosshairHandler = null;
    }
    if (!untrack(indicatorsOn)) applyIndicators(false);
  });

  // Rebuild once per exact entity+window when its first local candles arrive.
  createEffect(() => {
    const current = subject();
    const timeframe = activeTimeframeDef();
    version();
    const key = `${chartTicker(current)}#${timeframe.id}`;
    if (router.localCandles(current, timeframe).length > 0 && hydratedKey !== key) {
      hydratedKey = key;
      setReloadNonce((value) => value + 1);
    }
  });

  createEffect(() => {
    const value = activeTimeframe();
    handle?.setTimeframe(value);
  });

  createEffect(() => {
    const current = subject();
    if (!current.chain || !current.address) return;
    const tick = station.latestPrice(current);
    if (!tick) return;
    if (router.applyPriceTick(current, activeTimeframeDef(), tick, ws.clockMs())) {
      setVersion((value) => value + 1);
    }
  });

  // The indicator toggle is applied to the live renderer.
  let indicatorsInitialised = false;
  createEffect(() => {
    const on = indicatorsOn();
    if (!indicatorsInitialised) {
      indicatorsInitialised = true;
      return;
    }
    applyIndicators(on);
  });

  onCleanup(() => {
    handle?.dispose();
    handle = null;
    drawing = null;
    crosshairHandler = null;
    activeDatafeed?.dispose();
    activeDatafeed = null;
  });

  const depth = () => {
    version();
    return {
      bids: router.stores.depth.bidLevels().slice(0, 8),
      asks: router.stores.depth.askLevels().slice(0, 8),
    };
  };

  const change = createMemo<number | null>(() => {
    const bar = crosshair();
    if (!bar || bar.open === 0) return null;
    return ((bar.close - bar.open) / bar.open) * 100;
  });

  return (
    <div class="chart-panel" onKeyDown={onChartKeyDown}>
      {/* Bar 1 — identity & crosshair readout. Nothing overlays the plot. */}
      <div class="panebar chart-pane__bar1">
        <div class="chart-pane__identity">
          <h2 class="chart-pane__symbol">{hasTarget() ? subject().symbol : "Price"}</h2>
          <Show when={hasTarget()} fallback={<Badge tone="muted">No target selected</Badge>}>
            <Badge tone="muted">{subject().chain}</Badge>
          </Show>
          <Show when={riskText()}>
            {(value) => (
              <span class="chart-pane__stats" data-testid="token-risk">
                <Badge tone={risk()?.level === "hard_risk" ? "danger" : "muted"}>
                  risk {value()}
                </Badge>
                <Show when={risk()?.sellRestricted === true}>
                  <Badge tone="danger">SELL RESTRICTED</Badge>
                </Show>
              </span>
            )}
          </Show>
          <span
            data-testid="chart-target"
            data-candles={String(selectedCandleCount())}
            aria-live="off"
          >
            <Badge tone={selectedCandleCount() > 0 ? "positive" : "muted"}>
              {selectedCandleCount() > 0 ? "LOCAL DATA" : "AWAITING FEED"}
            </Badge>
          </span>
        </div>
        {/* The crosshair readout is a bar element and the toolbar's shrink
            point; it folds before it can crowd the tools. Nothing overlays the
            plot or the scales. */}
        <div class="chart-pane__legend" aria-live="off">
          <span>
            <i>O</i> <b>{crosshair() ? numOrDash(crosshair()!.open) : "—"}</b>
          </span>
          <span>
            <i>H</i> <b>{crosshair() ? numOrDash(crosshair()!.high) : "—"}</b>
          </span>
          <span>
            <i>L</i> <b>{crosshair() ? numOrDash(crosshair()!.low) : "—"}</b>
          </span>
          <span>
            <i>C</i> <b>{crosshair() ? numOrDash(crosshair()!.close) : "—"}</b>
          </span>
          <span>
            <i>Δ</i>{" "}
            <b>{change() === null ? "—" : `${change()! >= 0 ? "+" : ""}${change()!.toFixed(2)}%`}</b>
          </span>
          <span>
            <i>Vol</i> <b>{crosshair()?.volume === null || crosshair()?.volume === undefined ? "—" : formatAmount(crosshair()!.volume)}</b>
          </span>
        </div>
      </div>

      {/* Bar 2 — toolbar. Drawing tools, timeframe, indicators. */}
      <div class="panebar chart-panel__head">
        <div class="toolgroup chart-draw-tools" role="toolbar" aria-label="Drawing tools">
          <For each={drawingTools}>
            {(tool) => (
              <button
                type="button"
                class="chart-tool"
                data-testid={`draw-tool-${tool.id}`}
                aria-pressed={activeDrawingTool() === tool.id}
                title={tool.hint}
                onClick={() => drawing?.activate(tool.id)}
              >
                {tool.label}
              </button>
            )}
          </For>
          <Show
            when={clearArmed()}
            fallback={
              <button
                type="button"
                class="chart-tool"
                data-testid="draw-clear-all"
                disabled={drawingCount() === 0}
                title="Remove every drawing"
                onClick={() => setClearArmed(true)}
              >
                Clear all
              </button>
            }
          >
            <button
              type="button"
              class="chart-tool chart-tool--danger"
              data-testid="draw-clear-confirm"
              onClick={() => {
                drawing?.clearAll();
                setClearArmed(false);
              }}
            >
              Confirm clear
            </button>
            <button
              type="button"
              class="chart-tool"
              data-testid="draw-clear-cancel"
              onClick={() => setClearArmed(false)}
            >
              Cancel
            </button>
          </Show>
        </div>

        <span class="vrule" aria-hidden="true" />

        <div class="toolgroup">
          <label class="chart-toolbar__label" for="chart-timeframe">
            Timeframe
          </label>
          <select
            id="chart-timeframe"
            class="input chart-timeframe"
            aria-label="Chart timeframe"
            value={activeTimeframe()}
            onChange={(event) => {
              // The workstation store owns the window; the effect above applies it
              // to the live renderer and the coordinator re-targets the stream.
              station.setTimeframe(event.currentTarget.value);
            }}
          >
            <For each={PRO_PERIODS}>
              {(period) => (
                <option value={period.text} disabled={!isServedTimeframe(period.text)}>
                  {period.text}
                </option>
              )}
            </For>
          </select>
        </div>

        <div class="toolgroup toolgroup--end">
          <p class="chartpane__hint" role="status">
            Wheel to zoom · drag to pan
          </p>
          <div class="seg seg--toggle" role="group" aria-label="Indicators">
            <button
              type="button"
              class="seg__btn"
              data-testid="indicator-toggle"
              aria-pressed={indicatorsOn()}
              title="Toggle moving averages MA7 / MA25"
              onClick={() => setIndicatorsOn((value) => !value)}
            >
              MA
            </button>
          </div>
        </div>
      </div>

      <Show when={chartError()}>
        <EmptyBlock
          title="Chart unavailable"
          detail="This browser could not start the chart renderer. Market data stays read-only."
        />
      </Show>
      <div class="chart-frame chart-frame--interactive">
        <div
          class="pep-pro-chart-host"
          role="group"
          tabindex="0"
          aria-describedby="chart-keyboard-help"
          aria-label={
            hasTarget()
              ? `Price chart for ${subject().symbol}, ${activeTimeframe()} timeframe`
              : `Price chart, ${activeTimeframe()} timeframe`
          }
          onKeyDown={onPlotKeyDown}
          ref={(element) => {
            host = element;
          }}
        />
        <p class="sr" id="chart-keyboard-help">
          Use Left and Right arrow keys to pan through history, Up and Down (or plus and minus) to
          zoom, and 0 or Home to return to the latest bar. Choose a drawing tool, then drag on the
          chart to draw; Escape cancels and Delete removes the selected drawing.
        </p>
      </div>
      {/* Depth yields to a summary row while the operator expands the dock, so
          the operator's explicit expansion never breaches the chart floor. */}
      <Show
        when={!station.dockExpanded()}
        fallback={
          <p class="depth-summary" role="status" aria-label="Depth summary">
            Depth yields while the dock is expanded · Spread{" "}
            {formatBps(version() >= 0 ? router.stores.depth.spreadBps() : null)} · imbalance{" "}
            {router.stores.depth.imbalancePct() === null
              ? "—"
              : `${router.stores.depth.imbalancePct()!.toFixed(1)}%`}
          </p>
        }
      >
        <div class="depth-columns" tabindex="0" aria-label="Depth of book">
          <div class="depth-col">
            <h2 class="depth-col__title">Bids</h2>
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
            <h2 class="depth-col__title">Asks</h2>
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
          Spread {formatBps(version() >= 0 ? router.stores.depth.spreadBps() : null)} · imbalance{" "}
          {router.stores.depth.imbalancePct() === null
            ? "—"
            : `${router.stores.depth.imbalancePct()!.toFixed(1)}%`}
        </p>
      </Show>
    </div>
  );
};

export default ChartPanel;
