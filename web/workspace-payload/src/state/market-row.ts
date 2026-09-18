// Typed parsing for provider market rows. Extracted from the workstation store
// so the realtime market-event router can validate pushed rows without importing
// the Solid store (no cycle) and every surface parses identity/values the same
// way. Nothing here invents a value: an absent or unusable field stays `null`.

import type { MarketListRow, TokenRef } from "../contracts/market";

/**
 * A finite, non-negative provider number, or `null`. Anything else (absent,
 * `NaN`, `Infinity`, a string, a negative) stays unknown so the renderer shows
 * an explicit `—` and never invents a zero.
 */
export function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** A finite signed number (a 24h change may legitimately be negative), or `null`. */
export function signedFiniteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** A positive integer rank, or `null`. */
export function rankOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

export function parseTokenRef(entry: unknown): TokenRef | null {
  if (typeof entry !== "object" || entry === null) return null;
  const token = entry as Record<string, unknown>;
  // Normalize the identity once, so the chart entity key, the coordinator's
  // exact target and the backend's trimmed identity all agree.
  const chain = typeof token.chain === "string" ? token.chain.trim() : "";
  const address = typeof token.address === "string" ? token.address.trim() : "";
  if (chain.length === 0 || address.length === 0) return null;
  const ref: {
    chain: string;
    address: string;
    symbol?: string;
    name?: string;
    decimals?: number;
  } = { chain, address };
  if (typeof token.symbol === "string" && token.symbol.length > 0) ref.symbol = token.symbol;
  if (typeof token.name === "string" && token.name.length > 0) ref.name = token.name;
  if (typeof token.decimals === "number" && Number.isInteger(token.decimals)) {
    ref.decimals = token.decimals;
  }
  return ref;
}

/**
 * Parse one market-list row, preserving the validated optional financial fields
 * the provider supplied. This is the typed row the market rail and search
 * combobox render; it never fabricates a price, market cap, liquidity, volume or
 * rank.
 */
export function parseMarketRow(entry: unknown): MarketListRow | null {
  const token = parseTokenRef(entry);
  if (!token) return null;
  const record = entry as Record<string, unknown>;
  return {
    ...token,
    priceUsd: finiteOrNull(record.priceUsd),
    // A 24h change is signed: a down token must keep its negative value.
    priceChange24h: signedFiniteOrNull(record.priceChange24h),
    marketCapUsd: finiteOrNull(record.marketCapUsd),
    liquidityUsd: finiteOrNull(record.liquidityUsd),
    volume24hUsd: finiteOrNull(record.volume24hUsd),
    rank: rankOrNull(record.rank),
  };
}

/** Upper bound on rows parsed from one provider page. */
export const MAX_MARKET_ROWS = 200;

/** Parse a bounded list of market rows, dropping entries without an identity. */
export function parseMarketRows(value: unknown): readonly MarketListRow[] {
  if (!Array.isArray(value)) return [];
  const rows: MarketListRow[] = [];
  for (const entry of value) {
    if (rows.length >= MAX_MARKET_ROWS) break;
    const row = parseMarketRow(entry);
    if (row) rows.push(row);
  }
  return rows;
}
