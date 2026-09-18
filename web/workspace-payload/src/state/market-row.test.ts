import { describe, expect, it } from "vitest";
import { parseMarketRow, parseMarketRows } from "./workstation";

describe("parseMarketRow", () => {
  it("preserves validated optional financial fields", () => {
    const row = parseMarketRow({
      chain: "base",
      address: "0xBONK",
      symbol: "BONK",
      name: "Bonk",
      priceUsd: 0.0000123,
      marketCapUsd: 1_000_000,
      rank: 12,
    });
    expect(row).toEqual({
      chain: "base",
      address: "0xBONK",
      symbol: "BONK",
      name: "Bonk",
      priceUsd: 0.0000123,
      priceChange24h: null,
      marketCapUsd: 1_000_000,
      liquidityUsd: null,
      volume24hUsd: null,
      rank: 12,
    });
  });

  it("carries liquidity and 24h volume when the provider supplies them", () => {
    const row = parseMarketRow({
      chain: "solana",
      address: "So111",
      symbol: "SOL",
      priceUsd: 150,
      priceChange24h: -2.5,
      marketCapUsd: 70_000_000_000,
      liquidityUsd: 1_500_000,
      volume24hUsd: 900_000,
      rank: 1,
    });
    expect(row!.liquidityUsd).toBe(1_500_000);
    expect(row!.volume24hUsd).toBe(900_000);
    expect(row!.priceChange24h).toBe(-2.5);
  });

  it("renders a missing price as unknown, never as zero or an address", () => {
    const row = parseMarketRow({ chain: "base", address: "0xPEPE", symbol: "PEPE" });
    expect(row).not.toBeNull();
    expect(row!.priceUsd).toBeNull();
    expect(row!.marketCapUsd).toBeNull();
    expect(row!.liquidityUsd).toBeNull();
    expect(row!.volume24hUsd).toBeNull();
    expect(row!.rank).toBeNull();
  });

  it("rejects non-finite, negative and mistyped financial values", () => {
    const row = parseMarketRow({
      chain: "base",
      address: "0xX",
      priceUsd: Number.NaN,
      marketCapUsd: -5,
      rank: 1.5,
      priceChange24h: "10",
    });
    expect(row!.priceUsd).toBeNull();
    expect(row!.marketCapUsd).toBeNull();
    expect(row!.rank).toBeNull();
    expect(row!.priceChange24h).toBeNull();
  });

  it("keeps a signed 24h change so down tokens do not show a fabricated value", () => {
    const row = parseMarketRow({
      chain: "base",
      address: "0xDOWN",
      symbol: "DOWN",
      priceUsd: 1.5,
      priceChange24h: -12.5,
    });
    expect(row!.priceChange24h).toBe(-12.5);
  });

  it("normalizes padded identity so the chart key matches the realtime target", () => {
    const row = parseMarketRow({ chain: " base ", address: " 0xABC ", symbol: "TKN" });
    expect(row!.chain).toBe("base");
    expect(row!.address).toBe("0xABC");
  });

  it("drops entries without a chain/address identity", () => {
    expect(parseMarketRow({ symbol: "NOPE" })).toBeNull();
    expect(parseMarketRow({ chain: "", address: "0x1" })).toBeNull();
    expect(parseMarketRow({ chain: "  ", address: "0x1" })).toBeNull();
    expect(parseMarketRows([{ chain: "base", address: "0x1" }, { chain: "base" }, null])).toHaveLength(1);
  });
});
