import { describe, expect, it } from "vitest";
import { ChartFrameRouter } from "../chart/chart-datafeed";
import { timeframeById } from "../market/ohlcv";
import {
  MarketEventRouter,
  MARKET_ENTITY_STATUS,
  MARKET_ENTITY_TRENDING,
  MAX_PRICE_ENTITIES,
  marketPriceEntityKey,
  mergeTrendingRows,
  parsePricePush,
  parseStatusPush,
  parseTrendingPush,
  trendingChainCounts,
} from "./market-events";
import type { DecodedFrame } from "./types";

function frame(over: Partial<DecodedFrame>): DecodedFrame {
  return {
    seq: 1,
    op: "delta",
    channel: "market",
    priority: 1,
    entityKey: "",
    slot: null,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: null,
    ...over,
  };
}

const priceFrame = (entityKey: string, payload: Record<string, unknown>, over: Partial<DecodedFrame> = {}) =>
  frame({ entityKey, payload: { kind: "price", ...payload }, ...over });

const KEY_A = marketPriceEntityKey("base", "0xA");
const TIMEFRAME = timeframeById("1m")!;
// An exact 1-minute bucket start, so tick bucketing is deterministic.
const BUCKET = 1_700_000_040_000;

describe("market event parsing", () => {
  it("accepts an exact trending frame and rejects a mismatched entity", () => {
    const good = frame({
      entityKey: MARKET_ENTITY_TRENDING,
      payload: {
        kind: "trending",
        category: "trending",
        source: "fomo-ws",
        tokens: [{ chain: "base", address: "0xA", symbol: "A", priceUsd: 1.5 }],
      },
    });
    const parsed = parseTrendingPush(good);
    expect(parsed?.source).toBe("fomo-ws");
    expect(parsed?.tokens).toHaveLength(1);
    expect(parsed?.tokens[0]!.priceUsd).toBe(1.5);
    expect(parseTrendingPush(frame({ entityKey: "market:other", payload: { kind: "trending", tokens: [] } }))).toBeNull();
    expect(parseTrendingPush(frame({ entityKey: MARKET_ENTITY_TRENDING, channel: "ohlcv", payload: { kind: "trending", tokens: [] } }))).toBeNull();
  });

  it("accepts a price frame only when the payload repeats the exact entity identity", () => {
    const good = priceFrame(KEY_A, { chain: "base", address: "0xA", priceUsd: 2, source: "fomo-ws" });
    expect(parsePricePush(good)?.priceUsd).toBe(2);
    // Payload identity that does not match the entity key is refused.
    expect(parsePricePush(priceFrame(KEY_A, { chain: "base", address: "0xB", priceUsd: 2 }))).toBeNull();
    // A non-positive price is not a price.
    expect(parsePricePush(priceFrame(KEY_A, { chain: "base", address: "0xA", priceUsd: 0 }))).toBeNull();
    expect(parsePricePush(priceFrame(KEY_A, { chain: "base", address: "0xA", priceUsd: -1 }))).toBeNull();
  });

  it("parses provenance status and never upgrades an unknown source to ws", () => {
    expect(
      parseStatusPush(frame({ entityKey: MARKET_ENTITY_STATUS, payload: { kind: "status", realtimeSource: "fomo-polling" } }))?.source,
    ).toBe("fomo-polling");
    expect(
      parseStatusPush(frame({ entityKey: MARKET_ENTITY_STATUS, payload: { kind: "status", realtimeSource: "something-else" } }))?.source,
    ).toBe("unavailable");
  });
});

describe("MarketEventRouter", () => {
  it("keeps per-entity prices isolated and rejects a stale out-of-order tick", () => {
    const router = new MarketEventRouter();
    expect(
      router.apply([
        priceFrame(KEY_A, { chain: "base", address: "0xA", priceUsd: 1, source: "fomo-ws", observedAtMs: 2_000 }),
      ]),
    ).toBe(true);
    expect(router.state.prices.get(KEY_A)?.priceUsd).toBe(1);

    // A newer tick for another entity is stored under its own key only.
    const keyB = marketPriceEntityKey("base", "0xB");
    router.apply([priceFrame(keyB, { chain: "base", address: "0xB", priceUsd: 9, observedAtMs: 3_000 })]);
    expect(router.state.prices.get(KEY_A)?.priceUsd).toBe(1);
    expect(router.state.prices.get(keyB)?.priceUsd).toBe(9);

    // An older tick for A must not rewind the header/current candle.
    expect(
      router.apply([
        priceFrame(KEY_A, { chain: "base", address: "0xA", priceUsd: 0.5, observedAtMs: 1_000 }),
      ]),
    ).toBe(false);
    expect(router.state.prices.get(KEY_A)?.priceUsd).toBe(1);
  });

  it("rejects an absolutely stale price tick re-emitted by the lane", () => {
    const router = new MarketEventRouter();
    const keyB = marketPriceEntityKey("base", "0xB");
    const now = 1_700_000_000_000;
    // A cached lane price observed a minute ago, arriving with a current
    // authenticated server clock: it must never be rendered as current.
    expect(
      router.apply([
        priceFrame(
          keyB,
          { chain: "base", address: "0xB", priceUsd: 5, source: "fomo-ws", observedAtMs: now - 60_000 },
          { serverTimeMs: now },
        ),
      ]),
    ).toBe(false);
    expect(router.state.prices.has(keyB)).toBe(false);
    // A fresh tick is accepted.
    expect(
      router.apply([
        priceFrame(
          keyB,
          { chain: "base", address: "0xB", priceUsd: 5, source: "fomo-ws", observedAtMs: now - 1_000 },
          { serverTimeMs: now },
        ),
      ]),
    ).toBe(true);
  });

  it("tracks provenance and trending state", () => {
    const router = new MarketEventRouter();
    router.apply([
      frame({ entityKey: MARKET_ENTITY_TRENDING, payload: { kind: "trending", category: "trending", source: "fomo-polling", tokens: [{ chain: "base", address: "0xA" }] } }),
    ]);
    expect(router.state.source).toBe("fomo-polling");
    expect(router.state.trending?.tokens).toHaveLength(1);
    router.apply([frame({ entityKey: MARKET_ENTITY_STATUS, payload: { kind: "status", realtimeSource: "fomo-ws" } })]);
    expect(router.state.source).toBe("fomo-ws");
  });

  it("bounds the number of retained price entities", () => {
    const router = new MarketEventRouter();
    const frames = Array.from({ length: MAX_PRICE_ENTITIES + 40 }, (_, index) =>
      priceFrame(marketPriceEntityKey("base", `0x${index}`), {
        chain: "base",
        address: `0x${index}`,
        priceUsd: 1,
        observedAtMs: 1_000 + index,
      }),
    );
    router.apply(frames);
    expect(router.state.prices.size).toBe(MAX_PRICE_ENTITIES);
    // The oldest entity is evicted; the newest survives.
    expect(router.state.prices.has(marketPriceEntityKey("base", "0x0"))).toBe(false);
    expect(
      router.state.prices.has(marketPriceEntityKey("base", `0x${MAX_PRICE_ENTITIES + 39}`)),
    ).toBe(true);
  });
});

describe("mergeTrendingRows", () => {
  const base = [
    { chain: "base", address: "0xA", symbol: "A", priceUsd: 1, priceChange24h: null, marketCapUsd: 100, liquidityUsd: null, volume24hUsd: null, rank: 1 },
    { chain: "solana", address: "So1", symbol: "S", priceUsd: 2, priceChange24h: null, marketCapUsd: null, liquidityUsd: null, volume24hUsd: null, rank: 2 },
  ];

  it("overlays pushed values by exact identity and never invents a value", () => {
    const merged = mergeTrendingRows(base, {
      category: "trending",
      source: "fomo-ws",
      observedAtMs: 1,
      tokens: [
        { chain: "base", address: "0xA", priceUsd: 1.5, priceChange24h: -3, marketCapUsd: null, liquidityUsd: 50, volume24hUsd: 20, rank: 1 },
        { chain: "base", address: "0xNEW", symbol: "N", priceUsd: 7, priceChange24h: null, marketCapUsd: null, liquidityUsd: null, volume24hUsd: null, rank: null },
      ],
    });
    expect(merged).toHaveLength(3);
    const a = merged.find((row) => row.address === "0xA")!;
    expect(a.priceUsd).toBe(1.5);
    expect(a.priceChange24h).toBe(-3);
    expect(a.liquidityUsd).toBe(50);
    // A pushed `null` must not erase the reconciled market cap.
    expect(a.marketCapUsd).toBe(100);
    expect(merged.find((row) => row.address === "So1")!.priceUsd).toBe(2);
    expect(merged.find((row) => row.address === "0xNEW")!.priceUsd).toBe(7);
  });

  it("counts rows per chain honestly", () => {
    const counts = trendingChainCounts(base);
    expect(counts.get("base")).toBe(1);
    expect(counts.get("solana")).toBe(1);
  });

  it("overlays an EVM checksum/lowercase variant instead of duplicating it", () => {
    const baseRows = [
      { chain: "base", address: "0xAbC", symbol: "A", priceUsd: 1, priceChange24h: null, marketCapUsd: null, liquidityUsd: null, volume24hUsd: null, rank: 1 },
    ];
    const merged = mergeTrendingRows(baseRows, {
      category: "trending",
      source: "fomo-ws",
      observedAtMs: 1,
      tokens: [
        { chain: "base", address: "0xabc", priceUsd: 2, priceChange24h: null, marketCapUsd: null, liquidityUsd: null, volume24hUsd: null, rank: null },
      ],
    });
    expect(merged).toHaveLength(1);
    expect(merged[0]!.priceUsd).toBe(2);
  });
});

describe("selected-entity current candle from pushed price ticks", () => {
  const subjectA = { chain: "base", address: "0xA", symbol: "A" };

  const applyTick = (
    market: MarketEventRouter,
    chart: ChartFrameRouter,
    observedAtMs: number,
    priceUsd: number,
  ): boolean => {
    const accepted = market.apply([
      priceFrame(KEY_A, {
        chain: "base",
        address: "0xA",
        priceUsd,
        source: "fomo-ws",
        observedAtMs,
      }),
    ]);
    const push = market.state.prices.get(KEY_A);
    if (push) chart.applyPriceTick(subjectA, TIMEFRAME, push, BUCKET);
    return accepted;
  };

  it("applies multiple sequential updates and never leaks another entity", () => {
    const market = new MarketEventRouter();
    const chart = new ChartFrameRouter();

    expect(applyTick(market, chart, BUCKET + 1_000, 1)).toBe(true);
    let candles = chart.localCandles(subjectA, TIMEFRAME);
    expect(candles).toHaveLength(1);
    expect(candles[0]!.close).toBe(1);
    // No authoritative volume on a price tick: it is not fabricated.
    expect(candles[0]!.volume).toBe(0);

    applyTick(market, chart, BUCKET + 2_000, 1.1);
    candles = chart.localCandles(subjectA, TIMEFRAME);
    expect(candles).toHaveLength(1);
    expect(candles[0]!.close).toBe(1.1);
    expect(candles[0]!.high).toBe(1.1);
    expect(candles[0]!.volume).toBe(0);

    applyTick(market, chart, BUCKET + 3_000, 1.05);
    candles = chart.localCandles(subjectA, TIMEFRAME);
    expect(candles).toHaveLength(1);
    expect(candles[0]!.close).toBe(1.05);
    expect(candles[0]!.high).toBe(1.1);
    expect(candles[0]!.low).toBe(1);

    // A new bucket appends a fresh candle rather than mutating the closed one.
    applyTick(market, chart, BUCKET + 60_000, 1.2);
    candles = chart.localCandles(subjectA, TIMEFRAME);
    expect(candles).toHaveLength(2);
    expect(candles[1]!.close).toBe(1.2);

    // A wrong-entity frame (payload address differs from the entity key) is
    // rejected outright, so the selected entity's price/candle never change.
    const before = chart.localCandles(subjectA, TIMEFRAME).at(-1)!.close;
    expect(
      market.apply([
        priceFrame(KEY_A, {
          chain: "base",
          address: "0xB",
          priceUsd: 99,
          source: "fomo-ws",
          observedAtMs: BUCKET + 61_000,
        }),
      ]),
    ).toBe(false);
    expect(chart.localCandles(subjectA, TIMEFRAME).at(-1)!.close).toBe(before);
  });
});
