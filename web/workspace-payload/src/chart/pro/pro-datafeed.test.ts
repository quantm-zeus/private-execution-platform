import { describe, expect, it, vi } from "vitest";
import type { SymbolInfo } from "@klinecharts/pro";
import type { Candle } from "../../contracts/market";
import type {
  ChartCandleSink,
  ChartHistoryProvider,
  ChartRealtimeSource,
  ChartSubject,
} from "../chart-datafeed";
import { chartTicker } from "../chart-datafeed";
import {
  DEFAULT_PRO_TIMEFRAME,
  createProDatafeed,
  proPeriodForTimeframe,
  proSymbolFor,
  timeframeForPeriod,
  toKLineData,
} from "./pro-datafeed";

const subject: ChartSubject = { chain: "BASE", address: "0xabc", symbol: "PEP" };
const symbol: SymbolInfo = { ticker: chartTicker(subject) };
const minute = { multiplier: 1, timespan: "minute", text: "1m" };

function candle(timeMs: number, close = 10): Candle {
  return { timeMs, open: close - 1, high: close + 1, low: close - 2, close, volume: 2 };
}

function fakeRealtime(): {
  source: ChartRealtimeSource;
  push(value: Candle): void;
  active(): number;
  unsubscribed(): number;
} {
  const active = new Set<ChartCandleSink>();
  let unsubscribed = 0;
  return {
    source: {
      subscribe(_subject, _timeframe, sink) {
        active.add(sink);
        return () => {
          unsubscribed += 1;
          active.delete(sink);
        };
      },
    },
    push(value) {
      for (const sink of [...active]) sink(value);
    },
    active: () => active.size,
    unsubscribed: () => unsubscribed,
  };
}

describe("period mapping", () => {
  it("maps Pro periods to frontend timeframes text-first and arithmetically", () => {
    expect(timeframeForPeriod(minute)?.id).toBe("1m");
    expect(timeframeForPeriod({ multiplier: 4, timespan: "hour", text: "4h" })?.id).toBe("4h");
    expect(timeframeForPeriod({ multiplier: 1, timespan: "hour", text: "??" })?.id).toBe("1h");
    expect(timeframeForPeriod({ multiplier: 3, timespan: "fortnight", text: "??" })).toBeNull();
  });

  it("falls back to the default period for unknown ids", () => {
    expect(proPeriodForTimeframe("15m").text).toBe("15m");
    expect(proPeriodForTimeframe("nonsense").text).toBe(DEFAULT_PRO_TIMEFRAME);
  });

  it("maps a candle to a kline row and a subject to a symbol", () => {
    expect(toKLineData(candle(1_000, 7))).toEqual({
      timestamp: 1_000,
      open: 6,
      high: 8,
      low: 5,
      close: 7,
      volume: 2,
    });
    expect(proSymbolFor(subject).ticker).toBe("BASE:0xabc");
  });
});

describe("createProDatafeed", () => {
  function make(history: ChartHistoryProvider, realtime = fakeRealtime(), now = () => 5_000) {
    return {
      realtime,
      datafeed: createProDatafeed({
        history,
        realtime: realtime.source,
        resolveSubject: (ticker) => (ticker === chartTicker(subject) ? subject : null),
        now,
      }),
    };
  }

  it("returns sorted history and clamps the requested limit", async () => {
    const load = vi.fn(async (query) => {
      expect(query.limit).toBeLessThanOrEqual(4_096);
      return { candles: [candle(2_000, 12), candle(1_000, 11)], source: "network" as const };
    });
    const { datafeed } = make({ load });
    const rows = await datafeed.getHistoryKLineData(symbol, minute, 0, 10_000);
    expect(rows.map((r) => r.timestamp)).toEqual([1_000, 2_000]);
    expect(rows[0]!.close).toBe(11);
  });

  it("returns no bars for an unknown symbol or unsupported period", async () => {
    const load = vi.fn(async () => ({ candles: [candle(1_000)], source: "network" as const }));
    const { datafeed } = make({ load });
    expect(await datafeed.getHistoryKLineData({ ticker: "nope" }, minute, 0, 1)).toEqual([]);
    expect(
      await datafeed.getHistoryKLineData(symbol, { multiplier: 3, timespan: "fortnight", text: "x" }, 0, 1),
    ).toEqual([]);
    expect(load).not.toHaveBeenCalled();
  });

  it("uses `now` when Pro passes a non-finite range", async () => {
    const load = vi.fn(async (query) => {
      expect(query.toMs).toBe(5_000);
      expect(query.fromMs).toBe(0);
      return { candles: [], source: "local" as const };
    });
    const { datafeed } = make({ load });
    await datafeed.getHistoryKLineData(symbol, minute, Number.NaN, Number.NaN);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("streams applied bars to the Pro callback and tears down on unsubscribe", () => {
    const { datafeed, realtime } = make({ load: async () => ({ candles: [], source: "local" }) });
    const received: number[] = [];
    datafeed.subscribe(symbol, minute, (row) => received.push(row.timestamp));
    expect(realtime.active()).toBe(1);

    realtime.push(candle(1_000));
    realtime.push(candle(2_000));
    expect(received).toEqual([1_000, 2_000]);

    datafeed.unsubscribe(symbol, minute);
    expect(realtime.active()).toBe(0);
    realtime.push(candle(3_000));
    expect(received).toEqual([1_000, 2_000]);
  });

  it("drops the previous subscription when Pro re-subscribes without unsubscribing", () => {
    const { datafeed, realtime } = make({ load: async () => ({ candles: [], source: "local" }) });
    const first = vi.fn();
    const second = vi.fn();
    datafeed.subscribe(symbol, minute, first);
    datafeed.subscribe(symbol, minute, second);
    expect(realtime.unsubscribed()).toBe(1);
    realtime.push(candle(1_000));
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });

  it("does not let a throwing renderer callback break the feed", () => {
    const { datafeed, realtime } = make({ load: async () => ({ candles: [], source: "local" }) });
    const stable = vi.fn();
    datafeed.subscribe(symbol, minute, () => {
      throw new Error("renderer boom");
    });
    datafeed.subscribe(symbol, { ...minute, text: "5m" }, stable);
    expect(() => realtime.push(candle(1_000))).not.toThrow();
    expect(stable).toHaveBeenCalledTimes(1);
  });

  it("dispose tears down every live subscription", () => {
    const { datafeed, realtime } = make({ load: async () => ({ candles: [], source: "local" }) });
    datafeed.subscribe(symbol, minute, () => {});
    datafeed.subscribe(symbol, { ...minute, text: "5m" }, () => {});
    expect(realtime.active()).toBe(2);
    datafeed.dispose();
    expect(realtime.active()).toBe(0);
  });
});
