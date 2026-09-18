import { describe, expect, it } from "vitest";
import { createRoot } from "solid-js";
import type { CommandClient } from "../transport/command";
import {
  createTokenIntelligenceResources,
  intelligenceMatchesIdentity,
  parseTokenAbout,
  parseTokenActivityPage,
  parseTokenHolders,
  safeHttpUrl,
  MAX_ACTIVITY_ROWS,
  MAX_HOLDER_ROWS,
} from "./token-intelligence";

const A = { chain: "solana", address: "TokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
const B = { chain: "solana", address: "TokenBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" };

describe("safeHttpUrl", () => {
  it("accepts only absolute http/https URLs", () => {
    expect(safeHttpUrl("https://x.com/a")).toBe("https://x.com/a");
    expect(safeHttpUrl("http://example.com")).toBe("http://example.com");
    for (const bad of [
      "javascript:alert(1)",
      "data:text/html,x",
      "/relative",
      "ftp://x",
      "https://",
      "https:// x",
      "https://x.com/\u0001",
      "https://x.com/\u0085",
      "http://?x",
      "http://:80",
      "http://#f",
      "",
      null,
      42,
    ]) {
      expect(safeHttpUrl(bad)).toBeNull();
    }
    expect(safeHttpUrl(`https://x.com/${"a".repeat(600)}`)).toBeNull();
  });
});

describe("parseTokenHolders", () => {
  it("preserves the exact payload identity and null semantics", () => {
    const parsed = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [
        {
          user: {
            handle: "trader",
            displayName: "Trader",
            avatarUrl: "https://cdn.example/a.png",
            verified: true,
            followed: false,
            followers: 1200,
          },
          wallet: "Wallet111",
          amount: 1000.5,
          valueUsd: 12_000,
          costBasisUsd: null,
          averageEntryPriceUsd: 0.5,
          currentPriceUsd: 0.6,
          realizedPnlUsd: -3.5,
          unrealizedPnlUsd: 120,
          totalPnlUsd: 116.5,
          averageHoldTimeSeconds: 3600,
          thesis: { text: "bullish", createdAtMs: 1_700_000_000_000, likes: 4, tradeId: null },
        },
      ],
    });
    expect(parsed).not.toBeNull();
    expect(parsed!.chain).toBe(A.chain);
    expect(parsed!.address).toBe(A.address);
    expect(parsed!.count).toBe(1);
    const holder = parsed!.holders[0]!;
    expect(holder.user.verified).toBe(true);
    expect(holder.user.followed).toBe(false);
    expect(holder.costBasisUsd).toBeNull();
    expect(holder.realizedPnlUsd).toBe(-3.5);
    expect(holder.thesis!.text).toBe("bullish");
  });

  it("renders missing values as unknown, never zero", () => {
    const parsed = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [{ user: { handle: "h" } }],
    });
    const holder = parsed!.holders[0]!;
    expect(holder.amount).toBeNull();
    expect(holder.valueUsd).toBeNull();
    expect(holder.totalPnlUsd).toBeNull();
    expect(holder.thesis).toBeNull();
    expect(holder.user.verified).toBeNull();
    expect(holder.user.followers).toBeNull();
  });

  it("drops non-finite/negative numbers and unsafe avatars", () => {
    const parsed = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [
        {
          user: { handle: "h", avatarUrl: "javascript:alert(1)" },
          amount: Number.NaN,
          valueUsd: -1,
          unrealizedPnlUsd: Number.POSITIVE_INFINITY,
        },
      ],
    });
    const holder = parsed!.holders[0]!;
    expect(holder.user.avatarUrl).toBeNull();
    expect(holder.amount).toBeNull();
    expect(holder.valueUsd).toBeNull();
    expect(holder.unrealizedPnlUsd).toBeNull();
  });

  it("drops an identity-less row rather than rendering an anonymous holder", () => {
    const parsed = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [{ user: { handle: "h1" } }, { amount: 1 }, { wallet: "Wallet111" }],
    });
    expect(parsed!.holders).toHaveLength(2);
    expect(parsed!.holders[1]!.wallet).toBe("Wallet111");
  });

  it("bounds the holder page", () => {
    const rows = Array.from({ length: MAX_HOLDER_ROWS + 25 }, (_, i) => ({
      user: { handle: `h${i}` },
    }));
    const parsed = parseTokenHolders({ chain: A.chain, address: A.address, holders: rows });
    expect(parsed!.holders).toHaveLength(MAX_HOLDER_ROWS);
    expect(parsed!.count).toBe(MAX_HOLDER_ROWS);
  });

  it("does not fabricate provenance, freshness or a future timestamp", () => {
    const holders = parseTokenHolders({ chain: A.chain, address: A.address, holders: [] })!;
    expect(holders.source).toBeNull();
    expect(holders.sourceAgeMs).toBeNull();
    const activity = parseTokenActivityPage({ chain: A.chain, address: A.address, events: [] })!;
    expect(activity.source).toBeNull();
    expect(activity.sourceAgeMs).toBeNull();
    const about = parseTokenAbout({ token: { chain: A.chain, address: A.address } })!;
    expect(about.source).toBeNull();
    expect(about.sourceAgeMs).toBeNull();

    const timestamped = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [
        {
          user: { handle: "h" },
          thesis: { text: "t", createdAtMs: 9_999_999_999_999_999 },
        },
      ],
    })!;
    expect(timestamped.holders[0]!.thesis!.createdAtMs).toBeNull();
  });

  it("rejects a payload without an exact identity", () => {
    expect(parseTokenHolders({ holders: [] })).toBeNull();
    expect(parseTokenHolders({ chain: " ", address: A.address })).toBeNull();
  });
});

describe("A -> B identity race", () => {
  it("never matches a token-A payload against the token-B selection", () => {
    const parsedA = parseTokenHolders({
      chain: A.chain,
      address: A.address,
      holders: [{ user: { handle: "a" } }],
    })!;
    expect(intelligenceMatchesIdentity(parsedA, A)).toBe(true);
    expect(intelligenceMatchesIdentity(parsedA, B)).toBe(false);
  });

  it("compares EVM addresses case-insensitively but Solana byte-exactly", () => {
    expect(
      intelligenceMatchesIdentity(
        { chain: "base", address: "0xABC" },
        { chain: "base", address: "0xabc" },
      ),
    ).toBe(true);
    expect(
      intelligenceMatchesIdentity(
        { chain: "solana", address: "Abc" },
        { chain: "solana", address: "abc" },
      ),
    ).toBe(false);
  });
});

describe("parseTokenAbout", () => {
  it("normalizes social links and keeps absent stats null", () => {
    const parsed = parseTokenAbout({
      token: {
        chain: "base",
        address: "0xabc",
        symbol: "PEP",
        name: "Pep",
        imageUrl: "https://img.example/p.png",
        socialLinks: {
          twitter: "https://x.com/pep",
          website: "javascript:alert(1)",
          telegram: null,
        },
      },
      profile: { launchpad: "pump.fun", graduationPercent: 100, totalSupply: 1_000_000 },
      stats: { priceUsd: 0.01, priceChange24h: -2.5, top10HoldersPercent: 42 },
      trading: {
        "5m": { buyCount: 3, sellCount: 1, buyVolumeUsd: 900, sellVolumeUsd: 100 },
        "1h": null,
        "4h": null,
        "24h": null,
      },
      warnings: ["provider warning"],
      risk: { score: null, factors: [], simulated: false },
    });
    expect(parsed).not.toBeNull();
    expect(parsed!.token.imageUrl).toBe("https://img.example/p.png");
    expect(parsed!.token.socialLinks.twitter).toBe("https://x.com/pep");
    expect(parsed!.token.socialLinks.website).toBeNull();
    expect(parsed!.token.socialLinks.telegram).toBeNull();
    expect(parsed!.token.socialLinks.discord).toBeNull();
    expect(parsed!.profile.launchpad).toBe("pump.fun");
    expect(parsed!.profile.createdAtMs).toBeNull();
    expect(parsed!.stats.priceChange24h).toBe(-2.5);
    expect(parsed!.stats.fdvUsd).toBeNull();
    expect(parsed!.trading["5m"]!.buyCount).toBe(3);
    expect(parsed!.trading["1h"]).toBeNull();
    expect(parsed!.warnings).toEqual(["provider warning"]);
    expect(parsed!.risk!.factors).toEqual([]);
  });

  it("rejects a payload without a token identity", () => {
    expect(parseTokenAbout({ stats: {} })).toBeNull();
  });
});

describe("parseTokenActivityPage", () => {
  it("preserves the closed kind, raw type and pagination cursor", () => {
    const parsed = parseTokenActivityPage({
      chain: A.chain,
      address: A.address,
      events: [
        { type: "buy", rawType: "swap_buy", usdAmount: 12.5, priceUsd: 0.01, createdAtMs: 1_700_000_000_000 },
        { type: "thesis", rawType: "thesis", thesis: "gm" },
        { type: "mystery", rawType: "something_else" },
      ],
      nextCursor: "cursor-1",
      hasNextPage: true,
    });
    expect(parsed).not.toBeNull();
    expect(parsed!.events[0]!.type).toBe("buy");
    expect(parsed!.events[0]!.rawType).toBe("swap_buy");
    expect(parsed!.events[1]!.type).toBe("thesis");
    expect(parsed!.events[1]!.thesis).toBe("gm");
    expect(parsed!.events[2]!.type).toBe("other");
    expect(parsed!.nextCursor).toBe("cursor-1");
    expect(parsed!.hasNextPage).toBe(true);
  });

  it("bounds the event page and rejects an over-long cursor", () => {
    const events = Array.from({ length: MAX_ACTIVITY_ROWS + 40 }, () => ({ type: "buy" }));
    const parsed = parseTokenActivityPage({
      chain: A.chain,
      address: A.address,
      events,
      nextCursor: "c".repeat(300),
    });
    expect(parsed!.events).toHaveLength(MAX_ACTIVITY_ROWS);
    expect(parsed!.nextCursor).toBeNull();
    expect(parsed!.hasNextPage).toBeNull();
  });
});

describe("createTokenIntelligenceResources", () => {
  it("dispatches each op with the token_intelligence capability and validates", async () => {
    const seen: { op: string; payload: unknown }[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload: unknown): Promise<T> {
        seen.push({ op, payload });
        if (op === "get_token_holders") {
          return { chain: A.chain, address: A.address, holders: [] } as T;
        }
        if (op === "get_token_about") {
          return { token: { chain: A.chain, address: A.address } } as T;
        }
        return { chain: A.chain, address: A.address, events: [] } as T;
      },
    };
    await createRoot(async (dispose) => {
      const resources = createTokenIntelligenceResources({ command: client, nowMs: () => 0 });
      expect(resources.capability).toBe("token_intelligence");
      await resources.holders.run({ ...A });
      await resources.about.run({ ...A });
      await resources.activity.run({ ...A, limit: 50 });
      expect(seen.map((entry) => entry.op)).toEqual([
        "get_token_holders",
        "get_token_about",
        "get_token_activity",
      ]);
      expect(seen[0]!.payload).toMatchObject({ chain: A.chain, address: A.address });
      expect(seen[1]!.payload).toMatchObject({ chain: A.chain, address: A.address });
      expect(seen[2]!.payload).toMatchObject({ chain: A.chain, address: A.address, limit: 50 });
      expect(resources.holders.state().kind).toBe("ready");
      expect(resources.about.state().kind).toBe("ready");
      expect(resources.activity.state().kind).toBe("ready");
      dispose();
    });
  });

  it("fails a well-formed success for another token closed as a protocol error", async () => {
    // The adapter, not just the server, must reject a success whose identity is
    // not the requested one: a stale A document requested under B is never ready.
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return { chain: A.chain, address: A.address, holders: [{ user: { handle: "a" } }] } as T;
      },
    };
    await createRoot(async (dispose) => {
      const resources = createTokenIntelligenceResources({ command: client, nowMs: () => 0 });
      await resources.holders.run({ ...B });
      const state = resources.holders.state();
      expect(state.kind).toBe("error");
      if (state.kind === "error") {
        expect(state.error.code).toBe("protocol");
      }
      dispose();
    });
  });

  it("rejects an about success whose nested token identity is not the request", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return {
          token: { chain: A.chain, address: B.address, symbol: "B" },
        } as T;
      },
    };
    await createRoot(async (dispose) => {
      const resources = createTokenIntelligenceResources({ command: client, nowMs: () => 0 });
      await resources.about.run({ ...A });
      const state = resources.about.state();
      expect(state.kind).toBe("error");
      if (state.kind === "error") {
        expect(state.error.code).toBe("protocol");
      }
      dispose();
    });
  });

  it("fails a malformed success closed as a protocol error", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return { unexpected: true } as T;
      },
    };
    await createRoot(async (dispose) => {
      const resources = createTokenIntelligenceResources({ command: client, nowMs: () => 0 });
      await resources.holders.run({ ...A });
      const state = resources.holders.state();
      expect(state.kind).toBe("error");
      if (state.kind === "error") {
        expect(state.error.code).toBe("protocol");
      }
      dispose();
    });
  });
});
