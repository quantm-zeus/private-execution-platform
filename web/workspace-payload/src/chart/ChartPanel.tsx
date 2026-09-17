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
import { createProChart, type ProChartHandle } from "./pro/pro-chart";
import { PRO_PERIODS, createProDatafeed, type ProDatafeed } from "./pro/pro-datafeed";
import { timeframeById, type Timeframe } from "../market/ohlcv";
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

/**
 * KLineChart Pro price chart. The worker has already decrypted and normalized
 * frames; this component only routes them into bounded local buffers and the
 * injected datafeed (authenticated history + the local realtime bar bus).
 *
 * Chart data is visual/non-authoritative: execution always depends on exact
 * route simulation, never on a chart crossing.
 */
export const ChartPanel: Component<ChartPanelProps> = (props) => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const feed = useRealtimeFeedContext();
  const router = new ChartFrameRouter();
  const [version, setVersion] = createSignal(0);

  // The workstation store owns the authoritative timeframe: the chart and the
  // encrypted realtime-target coordinator read the same signal, so switching a
  // window issues exactly one `set_realtime_target` for the selected token.
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
  let createdTicker: string | null = null;
  let createdNonce = -1;
  const [chartError, setChartError] = createSignal(false);
  // Bumped when the exact selected entity+timeframe gains its first local
  // candles after the renderer was created. Pro loads history once at init, so a
  // snapshot that arrives afterwards would otherwise leave only its single
  // replayed bar on screen; the bump rebuilds the renderer so `getHistoryKLineData`
  // runs again against the now-populated local buffer and the full series renders.
  const [reloadNonce, setReloadNonce] = createSignal(0);
  let hydratedKey: string | null = null;

  // The badge reflects the CURRENT exact subject/timeframe only, so an
  // `ohlcv:default` or depth frame can never make a selected token look live
  // (exact entity-key isolation is preserved; nothing is matched loosely).
  const selectedCandleCount = createMemo(() => {
    version();
    return router.localCandles(subject(), activeTimeframeDef()).length;
  });

  createEffect(() => {
    const current = subject();
    const ticker = chartTicker(current);
    const nonce = reloadNonce();
    if (!host) return;
    if (handle !== null && createdTicker === ticker && createdNonce === nonce) return;
    // Pro 0.1.1 can drop the last symbol/period change when two land while a
    // history load is in flight (its loading guard is not reactive), so a
    // subject switch rebuilds the renderer instead of calling `setSymbol`.
    // The datafeed owns every subscription and is torn down with the instance.
    handle?.dispose();
    handle = null;
    activeDatafeed?.dispose();
    activeDatafeed = null;
    // A fresh datafeed per renderer instance: Pro 0.1.1 can call `subscribe()`
    // only after its history `await` resolves, so a disposed instance must never
    // be reused (its terminal guard would otherwise either leak a sink or drop a
    // legitimate late subscribe).
    const datafeed = buildDatafeed();
    try {
      handle = createProChart(host, {
        subject: current,
        datafeed,
        // Read the initial window without tracking it: a timeframe change is
        // applied in place by the effect below, not by rebuilding the chart.
        timeframeId: untrack(activeTimeframe),
        testId: "pro-chart",
      });
      activeDatafeed = datafeed;
      createdTicker = ticker;
      createdNonce = nonce;
      // If the local buffer already has this entity+window, the init history load
      // renders it; mark it hydrated so the effect below does not rebuild again.
      const timeframe = untrack(activeTimeframeDef);
      if (router.localCandles(current, timeframe).length > 0) {
        hydratedKey = `${ticker}#${timeframe.id}`;
      }
      setChartError(false);
    } catch {
      // No usable canvas (unsupported/headless runtime): degrade to a clear
      // message instead of breaking the whole workspace.
      datafeed.dispose();
      createdTicker = null;
      handle = null;
      setChartError(true);
    }
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

  // A timeframe change is applied to the live renderer in place.
  createEffect(() => {
    const value = activeTimeframe();
    handle?.setTimeframe(value);
  });

  onCleanup(() => {
    handle?.dispose();
    handle = null;
    activeDatafeed?.dispose();
    activeDatafeed = null;
  });

  const depth = () => {
    // Track the frame version so depth tables re-render with new snapshots.
    version();
    return {
      bids: router.stores.depth.bidLevels().slice(0, 8),
      asks: router.stores.depth.askLevels().slice(0, 8),
    };
  };

  return (
    <div class="chart-panel">
      <div class="chart-panel__head">
        <div class="chart-target" data-testid="chart-target" data-candles={String(selectedCandleCount())}>
          <Show when={hasTarget()} fallback={<Badge tone="muted">No target selected</Badge>}>
            <Badge tone="info">
              {subject().symbol} · {truncateAddress(subject().address, 6, 6)} · {subject().chain}
            </Badge>
          </Show>
          <Badge tone={selectedCandleCount() > 0 ? "positive" : "muted"}>
            {selectedCandleCount() > 0 ? "LOCAL DATA" : "AWAITING FEED"}
          </Badge>
        </div>
        {/* First-party timeframe control: KLineChart Pro 0.1.1's own period items
            are non-focusable spans, so the keyboard/AT path is owned here. The
            vendor period bar is hidden. */}
        <div class="chart-toolbar">
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
              {(period) => <option value={period.text}>{period.text}</option>}
            </For>
          </select>
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
          aria-label={
            hasTarget()
              ? `Price chart for ${subject().symbol}, ${activeTimeframe()} timeframe`
              : `Price chart, ${activeTimeframe()} timeframe`
          }
          ref={(element) => {
            host = element;
          }}
        />
      </div>
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
    </div>
  );
};

export default ChartPanel;
