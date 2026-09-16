import { describe, expect, it, vi } from "vitest";
import type { Candle } from "../contracts/market";
import type { CommandClient } from "../transport/command";
import { timeframeById } from "../market/ohlcv";
import type { ChartHistoryProvider } from "./chart-datafeed";
import {
  createPepHistoryProvider,
  createServerHistoryProvider,
  parseChartCandle,
  parseChartHistoryResult,
} from "./history";

const subject = { chain: "BASE", address: "0xabc", symbol: "PEP" };
const tf1m = timeframeById("1m")!;
const tf5m = timeframeById("5m")!;

function fakeCommand(send: CommandClient["send"]): CommandClient {
  return { send };
}

describe("parseChartCandle", () => {
  it("accepts the web shape", () => {
    expect(parseChartCandle({ time_ms: 1_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 3 })).toEqual({
      timeMs: 1_000,
      open: 1,
      high: 2,
      low: 0.5,
      close: 1.5,
      volume: 3,
    });
  });

  it("accepts the canonical market-types shape and numeric strings", () => {
    expect(
      parseChartCandle({ open_time_ms: 1_000, close_time_ms: 61_000, open: "1", high: "2", low: "0.5", close: "1.5", volume: "3" }),
    ).toEqual({ timeMs: 1_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 3 });
  });

  it("rejects malformed rows (never fabricates)", () => {
    expect(parseChartCandle(null)).toBeNull();
    expect(parseChartCandle({ time_ms: 0, open: 1, high: 2, low: 0.5, close: 1, volume: 1 })).toBeNull();
    expect(parseChartCandle({ time_ms: 1, open: 1, high: 0.5, low: 1, close: 1, volume: 1 })).toBeNull();
    expect(parseChartCandle({ time_ms: 1, open: 1, high: 2, low: 0.5, close: 1, volume: -1 })).toBeNull();
    // The OHLC envelope must match the realtime parser: a bar whose open/close
    // lies outside [low, high] is malformed, not renderable history.
    expect(parseChartCandle({ time_ms: 1, open: 3, high: 2, low: 0.5, close: 1, volume: 1 })).toBeNull();
    expect(parseChartCandle({ time_ms: 1, open: 1, high: 2, low: 0.5, close: 3, volume: 1 })).toBeNull();
  });
});

describe("parseChartHistoryResult", () => {
  it("extracts bars from the supported envelopes and drops junk", () => {
    const rows = [
      { time_ms: 1_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 },
      { bogus: true },
    ];
    expect(parseChartHistoryResult(rows)).toHaveLength(1);
    expect(parseChartHistoryResult({ candles: rows })).toHaveLength(1);
    expect(parseChartHistoryResult({ bars: rows })).toHaveLength(1);
    expect(parseChartHistoryResult({ klines: rows })).toHaveLength(1);
  });

  it("returns empty for an unrecognized shape", () => {
    expect(parseChartHistoryResult(null)).toEqual([]);
    expect(parseChartHistoryResult({ nope: 1 })).toEqual([]);
  });
});

describe("createServerHistoryProvider", () => {
  const query = { subject, timeframe: tf5m, fromMs: 0, toMs: 10_000, limit: 10 };

  it("does not call the command for a timeframe the canonical window cannot express", async () => {
    const send = vi.fn();
    const provider = createServerHistoryProvider({
      command: fakeCommand(send as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => true,
    });
    const page = await provider.load({ ...query, timeframe: tf1m });
    expect(send).not.toHaveBeenCalled();
    expect(page.candles).toEqual([]);
  });

  it("does not call the command before the channel is ready or without `market`", async () => {
    const send = vi.fn();
    let ready = false;
    const provider = createServerHistoryProvider({
      command: fakeCommand(send as unknown as CommandClient["send"]),
      ready: () => ready,
      chartAllowed: () => true,
    });
    await provider.load(query);
    expect(send).not.toHaveBeenCalled();

    ready = true;
    const denied = createServerHistoryProvider({
      command: fakeCommand(send as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => false,
    });
    await denied.load(query);
    expect(send).not.toHaveBeenCalled();
  });

  it("sends the canonical window, bounds and normalizes a successful response", async () => {
    const send = vi.fn(async (_op: string, payload: unknown) => {
      expect(payload).toEqual({ chain: "BASE", address: "0xabc", window: "m5", countBack: 10, to: 10 });
      return { candles: [
        { open_time_ms: 2_000, close_time_ms: 302_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 },
        { open_time_ms: 1_000, close_time_ms: 301_000, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 },
      ] };
    });
    const provider = createServerHistoryProvider({
      command: fakeCommand(send as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => true,
    });
    const page = await provider.load(query);
    expect(page.source).toBe("network");
    expect(page.candles.map((c: Candle) => c.timeMs)).toEqual([1_000, 2_000]);
  });

  it("forwards a loadMore window (from/to in seconds, clamped countBack)", async () => {
    const send = vi.fn(async (_op: string, payload: unknown) => {
      expect(payload).toEqual({
        chain: "BASE",
        address: "0xabc",
        window: "m5",
        countBack: 2,
        from: 100,
        to: 200,
      });
      return { candles: [] };
    });
    const provider = createServerHistoryProvider({
      command: fakeCommand(send as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => true,
    });
    await provider.load({ subject, timeframe: tf5m, fromMs: 100_000, toMs: 200_000, limit: 2 });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the command rejects or the response is malformed", async () => {
    const rejecting = createServerHistoryProvider({
      command: fakeCommand(vi.fn(async () => {
        throw new Error("capability_missing");
      }) as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => true,
    });
    expect((await rejecting.load(query)).candles).toEqual([]);

    const malformed = createServerHistoryProvider({
      command: fakeCommand(vi.fn(async () => ({ nope: 1 })) as unknown as CommandClient["send"]),
      ready: () => true,
      chartAllowed: () => true,
    });
    expect((await malformed.load(query)).candles).toEqual([]);
  });
});

describe("createPepHistoryProvider", () => {
  const query = { subject, timeframe: tf5m, fromMs: 0, toMs: 10_000, limit: 10 };

  it("prefers network history and falls back to local when empty", async () => {
    const local: ChartHistoryProvider = {
      load: async () => ({
        candles: [{ timeMs: 5, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 }],
        source: "local",
      }),
    };
    const serverWithData: ChartHistoryProvider = {
      load: async () => ({
        candles: [{ timeMs: 9, open: 1, high: 2, low: 0.5, close: 1.5, volume: 1 }],
        source: "network",
      }),
    };
    const preferNetwork = createPepHistoryProvider(serverWithData, local);
    expect((await preferNetwork.load(query)).source).toBe("network");

    const serverEmpty = createPepHistoryProvider({ load: async () => ({ candles: [], source: "network" }) }, local);
    expect((await serverEmpty.load(query)).source).toBe("local");
  });

  it("merges local realtime bars newer than the server page (no gap)", async () => {
    const candle = (timeMs: number) => ({
      timeMs,
      open: 1,
      high: 2,
      low: 0.5,
      close: 1.5,
      volume: 1,
    });
    const local: ChartHistoryProvider = {
      load: async () => ({ candles: [candle(5), candle(20), candle(30)], source: "local" }),
    };
    const server: ChartHistoryProvider = {
      load: async () => ({ candles: [candle(5), candle(10)], source: "network" }),
    };
    const page = await createPepHistoryProvider(server, local).load(query);
    expect(page.source).toBe("network");
    // Server bars stay authoritative; only strictly-newer local bars are added.
    expect(page.candles.map((c) => c.timeMs)).toEqual([5, 10, 20, 30]);
  });
});
