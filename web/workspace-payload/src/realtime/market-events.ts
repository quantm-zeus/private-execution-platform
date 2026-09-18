// Normalized `market` channel events pushed by PEP over the existing encrypted
// WebSocket. Polling is a fallback only: a frame is labelled `fomo-ws` solely
// when the backend observed it on the FOMO realtime lane; otherwise it is
// `fomo-polling` and the UI must say so.
//
// Everything here is identity-exact and fail-closed. A price frame is accepted
// only when its `entityKey` is `market:price:<chain>:<address>` AND the payload
// repeats that same chain/address, so another token's tick can never be applied
// to the selected entity. Absent values stay `null`; nothing is fabricated.

import type { MarketListRow } from "../contracts/market";
import { parseMarketRows, signedFiniteOrNull, finiteOrNull, rankOrNull } from "../state/market-row";
import type { DecodedFrame } from "./types";

export type MarketSource = "fomo-ws" | "fomo-polling" | "unavailable";

/** Entity key for the pushed trending list (broadcast to every session). */
export const MARKET_ENTITY_TRENDING = "market:trending";
/** Entity key for the pushed realtime provenance status. */
export const MARKET_ENTITY_STATUS = "market:status";
/** Prefix for a pushed selected-token price entity. */
export const MARKET_PRICE_PREFIX = "market:price:";

/** Stable entity key for one exact instrument's price tick. */
export function marketPriceEntityKey(chain: string, address: string): string {
  return `${MARKET_PRICE_PREFIX}${chain}:${address}`;
}

/** Parse a pushed provenance value; anything unrecognized is `unavailable`. */
export function parseMarketSource(value: unknown): MarketSource {
  return value === "fomo-ws" || value === "fomo-polling" ? value : "unavailable";
}

export interface TrendingPush {
  readonly category: string;
  readonly tokens: readonly MarketListRow[];
  readonly source: MarketSource;
  readonly observedAtMs: number | null;
}

export interface PricePush {
  readonly chain: string;
  readonly address: string;
  readonly priceUsd: number;
  readonly priceChange24h: number | null;
  readonly marketCapUsd: number | null;
  readonly liquidityUsd: number | null;
  readonly volume24hUsd: number | null;
  readonly source: MarketSource;
  readonly observedAtMs: number | null;
}

export interface MarketStatusPush {
  readonly source: MarketSource;
  readonly reason: string | null;
}

export interface MarketEventState {
  /** Monotonic counter bumped on every accepted batch (for reactive reads). */
  readonly generation: number;
  readonly trending: TrendingPush | null;
  readonly prices: ReadonlyMap<string, PricePush>;
  readonly source: MarketSource;
  readonly statusReason: string | null;
}

export const EMPTY_MARKET_STATE: MarketEventState = {
  generation: 0,
  trending: null,
  prices: new Map(),
  source: "unavailable",
  statusReason: null,
};

/**
 * Upper bound on distinct price entities retained. The server only emits a
 * price frame for the session's bound target, so one entity is the norm; this
 * cap is defense in depth against a compromised/buggy feed growing the map.
 */
export const MAX_PRICE_ENTITIES = 256;

/**
 * Absolute age beyond which a pushed price is refused. The server lane keeps a
 * cached price per entity, so re-selecting a token can re-emit an old tick; an
 * absolute bound (against the AEAD-authenticated server clock) keeps a stale
 * price from being rendered — and badged live — as if it were current.
 */
export const PRICE_FRESHNESS_TTL_MS = 15_000;

/** True when a pushed price is within the absolute freshness window. */
export function isPriceFresh(push: PricePush, nowMs: number): boolean {
  if (push.observedAtMs === null) return true;
  if (!Number.isFinite(nowMs)) return false;
  return nowMs - push.observedAtMs <= PRICE_FRESHNESS_TTL_MS;
}

/** EVM chains whose identity is case-insensitive (mirrors the server rule). */
const CASE_INSENSITIVE_CHAINS: ReadonlySet<string> = new Set([
  "base",
  "ethereum",
  "bnb_chain",
  "bsc",
  "bnb",
]);

/**
 * Identity key for reconciling/merging rows. EVM addresses are compared
 * case-insensitively so a checksum/lowercase variant overlays its row instead
 * of duplicating it; Solana/Robinhood stay exact.
 */
export function marketIdentityKey(chain: string, address: string): string {
  const slug = chain.trim().toLowerCase();
  const normalized = CASE_INSENSITIVE_CHAINS.has(slug) ? address.toLowerCase() : address;
  return `${slug}\u0000${normalized}`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function positiveOrNull(value: unknown): number | null {
  const parsed = finiteOrNull(value);
  return parsed !== null && parsed > 0 ? parsed : null;
}

/**
 * Validate a pushed trending frame. Only the exact `market:trending` entity is
 * accepted; the payload must carry the `trending` discriminator.
 */
export function parseTrendingPush(frame: DecodedFrame): TrendingPush | null {
  if (frame.channel !== "market" || frame.entityKey !== MARKET_ENTITY_TRENDING) return null;
  const payload = asRecord(frame.payload);
  if (!payload || payload.kind !== "trending") return null;
  const category =
    typeof payload.category === "string" && payload.category.length > 0
      ? payload.category
      : "trending";
  return {
    category,
    tokens: parseMarketRows(payload.tokens),
    source: parseMarketSource(payload.source),
    observedAtMs: finiteOrNull(payload.observedAtMs) ?? frame.serverTimeMs ?? null,
  };
}

/**
 * Validate a pushed price frame. The entity key must be exactly
 * `market:price:<chain>:<address>` and the payload must repeat the same
 * chain/address — a mismatch (stale or another entity) is rejected outright.
 */
export function parsePricePush(frame: DecodedFrame): PricePush | null {
  if (frame.channel !== "market") return null;
  if (!frame.entityKey.startsWith(MARKET_PRICE_PREFIX)) return null;
  const rest = frame.entityKey.slice(MARKET_PRICE_PREFIX.length);
  const separator = rest.indexOf(":");
  if (separator <= 0 || separator === rest.length - 1) return null;
  const chain = rest.slice(0, separator);
  const address = rest.slice(separator + 1);
  const payload = asRecord(frame.payload);
  if (!payload || payload.kind !== "price") return null;
  if (payload.chain !== chain || payload.address !== address) return null;
  const priceUsd = positiveOrNull(payload.priceUsd);
  if (priceUsd === null) return null;
  return {
    chain,
    address,
    priceUsd,
    priceChange24h: signedFiniteOrNull(payload.priceChange24h),
    marketCapUsd: finiteOrNull(payload.marketCapUsd),
    liquidityUsd: finiteOrNull(payload.liquidityUsd),
    volume24hUsd: finiteOrNull(payload.volume24hUsd),
    source: parseMarketSource(payload.source),
    observedAtMs: finiteOrNull(payload.observedAtMs) ?? frame.serverTimeMs ?? null,
  };
}

/** Validate a pushed provenance-status frame. */
export function parseStatusPush(frame: DecodedFrame): MarketStatusPush | null {
  if (frame.channel !== "market" || frame.entityKey !== MARKET_ENTITY_STATUS) return null;
  const payload = asRecord(frame.payload);
  if (!payload || payload.kind !== "status") return null;
  return {
    source: parseMarketSource(payload.realtimeSource),
    reason: typeof payload.reason === "string" && payload.reason.length > 0 ? payload.reason : null,
  };
}

/**
 * Overlay pushed (WS-observed) values onto the reconciled command rows by exact
 * `(chain, address)` identity. Ranks/order/identity are preserved; a pushed
 * value fills a field only when the provider actually supplied it, and a pushed
 * row with no reconciled counterpart is appended rather than dropped.
 */
export function mergeTrendingRows(
  base: readonly MarketListRow[],
  pushed: TrendingPush | null,
): readonly MarketListRow[] {
  if (!pushed || pushed.tokens.length === 0) return base;
  const keyOf = (row: MarketListRow): string => marketIdentityKey(row.chain, row.address);
  const pushedByKey = new Map<string, MarketListRow>();
  for (const row of pushed.tokens) pushedByKey.set(keyOf(row), row);
  const out: MarketListRow[] = [];
  const seen = new Set<string>();
  for (const row of base) {
    const key = keyOf(row);
    seen.add(key);
    const live = pushedByKey.get(key);
    out.push(live ? overlayRow(row, live) : row);
  }
  for (const row of pushed.tokens) {
    const key = keyOf(row);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

function overlayRow(base: MarketListRow, live: MarketListRow): MarketListRow {
  return {
    ...base,
    symbol: live.symbol ?? base.symbol,
    name: live.name ?? base.name,
    priceUsd: live.priceUsd ?? base.priceUsd,
    priceChange24h: live.priceChange24h ?? base.priceChange24h,
    marketCapUsd: live.marketCapUsd ?? base.marketCapUsd,
    liquidityUsd: live.liquidityUsd ?? base.liquidityUsd,
    volume24hUsd: live.volume24hUsd ?? base.volume24hUsd,
    rank: live.rank ?? base.rank,
  };
}

/** Count rows per authoritative chain, preserving first-seen order. */
export function trendingChainCounts(rows: readonly MarketListRow[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.chain, (counts.get(row.chain) ?? 0) + 1);
  return counts;
}

/**
 * Holds the latest normalized market state. It is deliberately a plain class
 * (no Solid import) so the workstation store can wrap it in one signal and the
 * router stays unit-testable without a reactive root.
 */
export class MarketEventRouter {
  private current: MarketEventState = EMPTY_MARKET_STATE;

  get state(): MarketEventState {
    return this.current;
  }

  /** Apply a batch of decoded frames; returns true when anything was accepted. */
  apply(frames: readonly DecodedFrame[]): boolean {
    let trending = this.current.trending;
    let source = this.current.source;
    let statusReason = this.current.statusReason;
    let prices: Map<string, PricePush> | null = null;
    let changed = false;

    for (const frame of frames) {
      if (frame.channel !== "market") continue;
      const nextTrending = parseTrendingPush(frame);
      if (nextTrending) {
        trending = nextTrending;
        source = nextTrending.source;
        changed = true;
        continue;
      }
      const price = parsePricePush(frame);
      if (price) {
        // Refuse an absolutely stale tick: a cached lane price re-emitted after
        // a token re-selection must never be rendered as current.
        if (
          frame.serverTimeMs !== null &&
          price.observedAtMs !== null &&
          frame.serverTimeMs - price.observedAtMs > PRICE_FRESHNESS_TTL_MS
        ) {
          continue;
        }
        const key = marketPriceEntityKey(price.chain, price.address);
        const prior = prices?.get(key) ?? this.current.prices.get(key);
        // Reject an out-of-order tick for the same entity: a replayed or late
        // frame must never rewind the header or the current candle.
        if (
          prior &&
          prior.observedAtMs !== null &&
          price.observedAtMs !== null &&
          price.observedAtMs < prior.observedAtMs
        ) {
          continue;
        }
        if (prices === null) prices = new Map(this.current.prices);
        // Refresh insertion order so the oldest entity is evicted first.
        prices.delete(key);
        prices.set(key, price);
        while (prices.size > MAX_PRICE_ENTITIES) {
          const oldest = prices.keys().next().value as string | undefined;
          if (oldest === undefined) break;
          prices.delete(oldest);
        }
        changed = true;
        continue;
      }
      const status = parseStatusPush(frame);
      if (status) {
        source = status.source;
        statusReason = status.reason;
        changed = true;
      }
    }

    if (!changed) return false;
    this.current = {
      generation: this.current.generation + 1,
      trending,
      prices: prices ?? this.current.prices,
      source,
      statusReason,
    };
    return true;
  }
}

/** Parse a raw (unvalidated) market row list, exported for symmetry. */
export function parsePushedRows(value: unknown): readonly MarketListRow[] {
  return parseMarketRows(value);
}

/** Exposed for callers that need the same positive-number rule as the router. */
export { positiveOrNull, rankOrNull };
