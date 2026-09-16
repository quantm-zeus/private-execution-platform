// KLineChart Pro datafeed adapter.
//
// This is the only module that maps Pro's `Period`/`KLineData` vocabulary onto
// the local, renderer-agnostic chart contracts. Everything the datafeed needs
// is injected, so no Pro type leaks into market/session/realtime code.

import type { Datafeed, DatafeedSubscribeCallback, Period, SymbolInfo } from "@klinecharts/pro";
import type { KLineData } from "klinecharts";
import type { Candle } from "../../contracts/market";
import { TIMEFRAMES, timeframeById, type Timeframe } from "../../market/ohlcv";
import {
  clampHistoryLimit,
  type ChartHistoryProvider,
  type ChartRealtimeSource,
  type ChartSubject,
  chartTicker,
} from "../chart-datafeed";

/**
 * Periods offered in the Pro toolbar. The canonical `get_chart` window only
 * supports `m5/m15/h1/h4/d1`; `1m` is local-buffer only. Seconds are excluded:
 * Pro 0.1.1's pagination arithmetic has no `second` branch.
 */
export const PRO_PERIODS: readonly Period[] = [
  { multiplier: 1, timespan: "minute", text: "1m" },
  { multiplier: 5, timespan: "minute", text: "5m" },
  { multiplier: 15, timespan: "minute", text: "15m" },
  { multiplier: 1, timespan: "hour", text: "1h" },
  { multiplier: 4, timespan: "hour", text: "4h" },
  { multiplier: 1, timespan: "day", text: "1d" },
];

export const DEFAULT_PRO_TIMEFRAME = "1m";

function timespanMs(timespan: string): number | null {
  switch (timespan) {
    case "second":
      return 1_000;
    case "minute":
      return 60_000;
    case "hour":
      return 3_600_000;
    case "day":
      return 86_400_000;
    case "week":
      return 604_800_000;
    case "month":
      return 2_592_000_000;
    case "year":
      return 31_536_000_000;
    default:
      return null;
  }
}

/** Map a Pro period to a known frontend timeframe (text first, then arithmetic). */
export function timeframeForPeriod(period: Period): Timeframe | null {
  const byText = timeframeById(period.text);
  if (byText) return byText;
  const base = timespanMs(period.timespan);
  if (base === null || !Number.isFinite(period.multiplier) || period.multiplier <= 0) return null;
  const ms = base * period.multiplier;
  return TIMEFRAMES.find((timeframe) => timeframe.ms === ms) ?? null;
}

export function proPeriodForTimeframe(timeframeId: string): Period {
  return (
    PRO_PERIODS.find((period) => period.text === timeframeId) ??
    PRO_PERIODS.find((period) => period.text === DEFAULT_PRO_TIMEFRAME)!
  );
}

export function toKLineData(candle: Candle): KLineData {
  return {
    timestamp: candle.timeMs,
    open: candle.open,
    high: candle.high,
    low: candle.low,
    close: candle.close,
    volume: candle.volume,
  };
}

export function proSymbolFor(subject: ChartSubject): SymbolInfo {
  return {
    ticker: chartTicker(subject),
    name: subject.symbol,
    shortName: subject.symbol,
    pricePrecision: 8,
    volumePrecision: 2,
  };
}

export interface ProDatafeedDeps {
  readonly history: ChartHistoryProvider;
  readonly realtime: ChartRealtimeSource;
  readonly resolveSubject: (ticker: string) => ChartSubject | null;
  /** Renderer buffer size; bounded by `MAX_HISTORY_LIMIT`. */
  readonly historyLimit?: number;
  /** Injectable clock for deterministic tests; defaults to `Date.now`. */
  readonly now?: () => number;
}

export interface ProDatafeed extends Datafeed {
  /** Tear down every live subscription (Pro 0.1.1 has no dispose hook). */
  dispose(): void;
}

export function createProDatafeed(deps: ProDatafeedDeps): ProDatafeed {
  const subscriptions = new Map<string, () => void>();
  // Pro 0.1.1 calls `subscribe()` only after its history `await` resolves, so a
  // chart disposed mid-load can still re-subscribe after teardown. Once disposed
  // the adapter is terminal: a late subscribe must not register a live sink on a
  // detached renderer. Callers that switch subjects create a fresh datafeed.
  let disposed = false;
  const limit = clampHistoryLimit(deps.historyLimit);
  const keyFor = (ticker: string, period: Period): string => `${ticker}#${period.text}`;

  const teardown = (ticker: string, period: Period): void => {
    const key = keyFor(ticker, period);
    const unsubscribe = subscriptions.get(key);
    if (!unsubscribe) return;
    subscriptions.delete(key);
    unsubscribe();
  };

  return {
    async searchSymbols(): Promise<SymbolInfo[]> {
      // The symbol picker is not used: the workspace target comes from the
      // authenticated Discover selection, never from a search endpoint.
      return [];
    },

    async getHistoryKLineData(symbol, period, from, to): Promise<KLineData[]> {
      const timeframe = timeframeForPeriod(period);
      const subject = deps.resolveSubject(symbol.ticker);
      if (!timeframe || !subject) return [];
      const page = await deps.history.load({
        subject,
        timeframe,
        fromMs: Number.isFinite(from) ? from : 0,
        toMs: Number.isFinite(to) ? to : (deps.now?.() ?? Date.now()),
        limit,
      });
      return page.candles
        .map(toKLineData)
        .sort((a, b) => a.timestamp - b.timestamp);
    },

    subscribe(symbol, period, callback: DatafeedSubscribeCallback): void {
      if (disposed) return;
      // Pro may re-subscribe without an intervening unsubscribe; always drop the
      // previous handler so a period/symbol switch cannot leak a live feed.
      teardown(symbol.ticker, period);
      const timeframe = timeframeForPeriod(period);
      const subject = deps.resolveSubject(symbol.ticker);
      if (!timeframe || !subject) return;
      const unsubscribe = deps.realtime.subscribe(subject, timeframe, (candle) => {
        // A throwing renderer callback must never break the feed loop.
        try {
          callback(toKLineData(candle));
        } catch {
          /* ignored */
        }
      });
      subscriptions.set(keyFor(symbol.ticker, period), unsubscribe);
    },

    unsubscribe(symbol, period): void {
      teardown(symbol.ticker, period);
    },

    dispose(): void {
      disposed = true;
      for (const unsubscribe of subscriptions.values()) unsubscribe();
      subscriptions.clear();
    },
  };
}
