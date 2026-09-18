// Typed parsing + state adapters for the FOMO token-intelligence contracts.
//
// The private API is authoritative for the wire shape; these parsers turn the
// untrusted success document into the typed contracts the UI consumes. Nothing
// here invents a value: an absent/non-finite number, a non-boolean flag, an
// unsafe URL or a missing identity stays `null`, and an over-long page is
// bounded before it reaches the DOM.

import type { RiskAssessment, RiskFactor } from "../contracts/market";
import type {
  HolderThesis,
  TokenAboutPayload,
  TokenAboutProfile,
  TokenAboutStats,
  TokenAboutTrading,
  TokenActivityEvent,
  TokenActivityKind,
  TokenActivityPage,
  TokenHolder,
  TokenHoldersPayload,
  TokenIntelUser,
  TokenSocialLinks,
  TradingWindow,
} from "../contracts/token-intelligence";
import { workspaceError } from "../core/errors";
import type { CapabilityKey } from "../core/types";
import type { CommandClient } from "../transport/command";
import { createCommandResource, type CommandResource } from "./command-state";
import { finiteOrNull, signedFiniteOrNull } from "./market-row";

/** Upper bound on holder rows accepted from one provider page. */
export const MAX_HOLDER_ROWS = 200;
/** Upper bound on activity events accepted from one provider page. */
export const MAX_ACTIVITY_ROWS = 100;
/** Upper bound on an activity cursor. */
export const MAX_CURSOR_LEN = 256;
/** Sanity ceiling for an epoch-millisecond timestamp (year 2100), matching Rust. */
const MAX_TIMESTAMP_MS = 4_102_444_800_000;
/** Upper bound on a wallet secondary-identity string, matching the Rust cap. */
const MAX_WALLET_LEN = 128;
/** Freshness TTL for the one-shot token-intelligence reads (DESIGN.md §11). */
export const TOKEN_INTELLIGENCE_TTL_MS = 60_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= 512 ? trimmed : null;
}

function boolOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function walletOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= MAX_WALLET_LEN ? trimmed : null;
}

/** A positive epoch-millisecond timestamp within the year-2100 ceiling, or `null`. */
function timestampOrNull(value: unknown): number | null {
  return typeof value === "number" &&
    Number.isInteger(value) &&
    value > 0 &&
    value <= MAX_TIMESTAMP_MS
    ? value
    : null;
}

/**
 * Normalize an external URL. Only an absolute `http://`/`https://` URL with a
 * host survives; every other scheme, a relative path or an over-long value is
 * dropped. This is the same allowlist the backend applies.
 */
export function safeHttpUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 512) return null;
  if (/\s/.test(trimmed) || /[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return null;
  const lower = trimmed.toLowerCase();
  const rest = lower.startsWith("https://")
    ? trimmed.slice(8)
    : lower.startsWith("http://")
      ? trimmed.slice(7)
      : null;
  if (
    rest === null ||
    rest.length === 0 ||
    rest.startsWith("/") ||
    rest.startsWith("@") ||
    rest.startsWith("?") ||
    rest.startsWith("#") ||
    rest.startsWith(":")
  ) {
    return null;
  }
  return trimmed;
}

function parseUser(value: unknown): TokenIntelUser {
  const record = isRecord(value) ? value : {};
  return {
    handle: stringOrNull(record.handle),
    displayName: stringOrNull(record.displayName),
    avatarUrl: safeHttpUrl(record.avatarUrl),
    verified: boolOrNull(record.verified),
    clan: stringOrNull(record.clan),
    followed: boolOrNull(record.followed),
    dev: boolOrNull(record.dev),
    followers: finiteOrNull(record.followers),
  };
}

function parseThesis(value: unknown): HolderThesis | null {
  if (!isRecord(value)) return null;
  const thesis: HolderThesis = {
    text: stringOrNull(value.text),
    createdAtMs: timestampOrNull(value.createdAtMs),
    likes: finiteOrNull(value.likes),
    tradeId: stringOrNull(value.tradeId),
  };
  if (
    thesis.text === null &&
    thesis.createdAtMs === null &&
    thesis.likes === null &&
    thesis.tradeId === null
  ) {
    return null;
  }
  return thesis;
}

function parseHolder(value: unknown): TokenHolder | null {
  if (!isRecord(value)) return null;
  const user = parseUser(value.user);
  // A holder with no identity at all is not renderable and is dropped rather
  // than shown as an anonymous row.
  if (
    user.handle === null &&
    user.displayName === null &&
    user.avatarUrl === null &&
    walletOrNull(value.wallet) === null
  ) {
    return null;
  }
  return {
    user,
    wallet: walletOrNull(value.wallet),
    amount: finiteOrNull(value.amount),
    valueUsd: finiteOrNull(value.valueUsd),
    costBasisUsd: finiteOrNull(value.costBasisUsd),
    averageEntryPriceUsd: finiteOrNull(value.averageEntryPriceUsd),
    currentPriceUsd: finiteOrNull(value.currentPriceUsd),
    realizedPnlUsd: signedFiniteOrNull(value.realizedPnlUsd),
    unrealizedPnlUsd: signedFiniteOrNull(value.unrealizedPnlUsd),
    totalPnlUsd: signedFiniteOrNull(value.totalPnlUsd),
    averageHoldTimeSeconds: finiteOrNull(value.averageHoldTimeSeconds),
    thesis: parseThesis(value.thesis),
  };
}

/** Parse one bounded `get_token_holders` payload, or `null` when unrenderable. */
export function parseTokenHolders(value: unknown): TokenHoldersPayload | null {
  if (!isRecord(value)) return null;
  const chain = stringOrNull(value.chain);
  const address = stringOrNull(value.address);
  if (chain === null || address === null) return null;
  const raw = Array.isArray(value.holders) ? value.holders : [];
  const holders: TokenHolder[] = [];
  for (const entry of raw) {
    if (holders.length >= MAX_HOLDER_ROWS) break;
    const holder = parseHolder(entry);
    if (holder) holders.push(holder);
  }
  return {
    chain,
    address,
    holders,
    count: holders.length,
    source: stringOrNull(value.source),
    sourceAgeMs: finiteOrNull(value.sourceAgeMs),
  };
}

function parseSocialLinks(value: unknown): TokenSocialLinks {
  const record = isRecord(value) ? value : {};
  return {
    twitter: safeHttpUrl(record.twitter),
    website: safeHttpUrl(record.website),
    telegram: safeHttpUrl(record.telegram),
    discord: safeHttpUrl(record.discord),
  };
}

function parseProfile(value: unknown): TokenAboutProfile {
  const record = isRecord(value) ? value : {};
  return {
    launchpad: stringOrNull(record.launchpad),
    graduationPercent: finiteOrNull(record.graduationPercent),
    createdAtMs: timestampOrNull(record.createdAtMs),
    circulatingSupply: finiteOrNull(record.circulatingSupply),
    totalSupply: finiteOrNull(record.totalSupply),
  };
}

function parseStats(value: unknown): TokenAboutStats {
  const record = isRecord(value) ? value : {};
  return {
    priceUsd: finiteOrNull(record.priceUsd),
    priceChange24h: signedFiniteOrNull(record.priceChange24h),
    marketCapUsd: finiteOrNull(record.marketCapUsd),
    fdvUsd: finiteOrNull(record.fdvUsd),
    liquidityUsd: finiteOrNull(record.liquidityUsd),
    volume24hUsd: finiteOrNull(record.volume24hUsd),
    holders: finiteOrNull(record.holders),
    top10HoldersPercent: finiteOrNull(record.top10HoldersPercent),
  };
}

function parseTradingWindow(value: unknown): TradingWindow | null {
  if (!isRecord(value)) return null;
  return {
    buyCount: finiteOrNull(value.buyCount),
    sellCount: finiteOrNull(value.sellCount),
    buyVolumeUsd: finiteOrNull(value.buyVolumeUsd),
    sellVolumeUsd: finiteOrNull(value.sellVolumeUsd),
    uniqueBuyers: finiteOrNull(value.uniqueBuyers),
    uniqueSellers: finiteOrNull(value.uniqueSellers),
  };
}

function parseTrading(value: unknown): TokenAboutTrading {
  const record = isRecord(value) ? value : {};
  return {
    "5m": parseTradingWindow(record["5m"]),
    "1h": parseTradingWindow(record["1h"]),
    "4h": parseTradingWindow(record["4h"]),
    "24h": parseTradingWindow(record["24h"]),
  };
}

const RISK_SEVERITIES = new Set<RiskFactor["severity"]>([
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);

function parseRisk(value: unknown): RiskAssessment | null {
  if (!isRecord(value)) return null;
  const rawFactors = Array.isArray(value.factors) ? value.factors : [];
  const factors: RiskFactor[] = [];
  for (const entry of rawFactors) {
    if (factors.length >= 64) break;
    if (!isRecord(entry)) continue;
    const severity = entry.severity;
    if (typeof severity !== "string" || !RISK_SEVERITIES.has(severity as RiskFactor["severity"])) {
      continue;
    }
    const id = stringOrNull(entry.id);
    const label = stringOrNull(entry.label);
    const detail = stringOrNull(entry.detail);
    if (id === null || label === null || detail === null) continue;
    factors.push({ id, label, severity: severity as RiskFactor["severity"], detail });
  }
  return {
    score: signedFiniteOrNull(value.score),
    factors,
    buyTaxBps: finiteOrNull(value.buyTaxBps),
    sellTaxBps: finiteOrNull(value.sellTaxBps),
    transferFeeBps: finiteOrNull(value.transferFeeBps),
    sellRestricted: boolOrNull(value.sellRestricted),
    simulated: value.simulated === true,
    level: stringOrNull(value.level),
    disableBuying: boolOrNull(value.disableBuying),
    disableSelling: boolOrNull(value.disableSelling),
  };
}

/** Parse one bounded `get_token_about` payload, or `null` when unrenderable. */
export function parseTokenAbout(value: unknown): TokenAboutPayload | null {
  if (!isRecord(value) || !isRecord(value.token)) return null;
  const chain = stringOrNull(value.token.chain);
  const address = stringOrNull(value.token.address);
  if (chain === null || address === null) return null;
  // Bound the warnings before iterating: an unbounded untrusted array is a cheap
  // OOM and the parsers are exported for direct use.
  const warnings: string[] = [];
  if (Array.isArray(value.warnings)) {
    for (const warning of value.warnings) {
      if (warnings.length >= 64) break;
      const parsed = stringOrNull(warning);
      if (parsed !== null) warnings.push(parsed);
    }
  }
  return {
    token: {
      chain,
      address,
      symbol: stringOrNull(value.token.symbol),
      name: stringOrNull(value.token.name),
      imageUrl: safeHttpUrl(value.token.imageUrl),
      socialLinks: parseSocialLinks(value.token.socialLinks),
    },
    profile: parseProfile(value.profile),
    stats: parseStats(value.stats),
    trading: parseTrading(value.trading),
    warnings,
    risk: parseRisk(value.risk),
    source: stringOrNull(value.source),
    sourceAgeMs: finiteOrNull(value.sourceAgeMs),
  };
}

const ACTIVITY_KINDS = new Set<TokenActivityKind>(["buy", "sell", "transfer", "thesis", "other"]);

function parseActivityEvent(value: unknown): TokenActivityEvent | null {
  if (!isRecord(value)) return null;
  const rawType = stringOrNull(value.rawType);
  const type = typeof value.type === "string" && ACTIVITY_KINDS.has(value.type as TokenActivityKind)
    ? (value.type as TokenActivityKind)
    : "other";
  const direction = value.direction === "in" || value.direction === "out" ? value.direction : null;
  return {
    id: stringOrNull(value.id),
    type,
    rawType,
    direction,
    user: parseUser(value.user),
    usdAmount: finiteOrNull(value.usdAmount),
    priceUsd: finiteOrNull(value.priceUsd),
    marketCapUsd: finiteOrNull(value.marketCapUsd),
    fdvUsd: finiteOrNull(value.fdvUsd),
    createdAtMs: timestampOrNull(value.createdAtMs),
    thesis: stringOrNull(value.thesis),
  };
}

/** Parse one bounded `get_token_activity` page, or `null` when unrenderable. */
export function parseTokenActivityPage(value: unknown): TokenActivityPage | null {
  if (!isRecord(value)) return null;
  const chain = stringOrNull(value.chain);
  const address = stringOrNull(value.address);
  if (chain === null || address === null) return null;
  const raw = Array.isArray(value.events) ? value.events : [];
  const events: TokenActivityEvent[] = [];
  for (const entry of raw) {
    if (events.length >= MAX_ACTIVITY_ROWS) break;
    const event = parseActivityEvent(entry);
    if (event) events.push(event);
  }
  const cursor = stringOrNull(value.nextCursor);
  return {
    chain,
    address,
    events,
    count: events.length,
    nextCursor: cursor !== null && cursor.length <= MAX_CURSOR_LEN ? cursor : null,
    hasNextPage: boolOrNull(value.hasNextPage),
    source: stringOrNull(value.source),
    sourceAgeMs: finiteOrNull(value.sourceAgeMs),
  };
}

function isEvmChain(chain: string): boolean {
  return ["base", "ethereum", "bnb_chain", "bsc", "bnb"].includes(chain.trim().toLowerCase());
}

/**
 * Whether an intelligence payload belongs to the currently selected exact
 * identity. A response for token A is never rendered under token B: the caller
 * gates the payload through this before use.
 */
export function intelligenceMatchesIdentity(
  payload: { readonly chain: string; readonly address: string },
  ref: { readonly chain: string; readonly address: string },
): boolean {
  const payloadChain = payload.chain.trim();
  const refChain = ref.chain.trim();
  if (payloadChain.toLowerCase() !== refChain.toLowerCase()) return false;
  const payloadAddress = payload.address.trim();
  const refAddress = ref.address.trim();
  return isEvmChain(refChain)
    ? payloadAddress.toLowerCase() === refAddress.toLowerCase()
    : payloadAddress === refAddress;
}

function requireParsed<T>(value: unknown, parse: (raw: unknown) => T | null, label: string): T {
  const parsed = parse(value);
  if (parsed === null) {
    throw workspaceError("protocol", `Malformed ${label} response.`);
  }
  return parsed;
}

/**
 * Reject a well-formed success whose identity does not match the exact identity
 * the command requested. The server verifies the provider echo, but the client is
 * the last boundary before render: a stale/misrouted A document must never be
 * marked `ready` for B.
 */
function assertRequestedIdentity(
  parsed: { readonly chain: string; readonly address: string },
  requested: unknown,
): void {
  if (!isRecord(requested)) {
    throw workspaceError("protocol", "Token-intelligence request lost its identity.");
  }
  const chain = stringOrNull(requested.chain);
  const address = stringOrNull(requested.address);
  if (chain === null || address === null) {
    throw workspaceError("protocol", "Token-intelligence request lost its identity.");
  }
  if (!intelligenceMatchesIdentity(parsed, { chain, address })) {
    throw workspaceError(
      "protocol",
      "Token-intelligence response identity did not match the request.",
    );
  }
}

/** The three token-intelligence command resources the About/Holders UI consumes. */
export interface TokenIntelligenceResources {
  readonly capability: CapabilityKey;
  readonly holders: CommandResource<TokenHoldersPayload>;
  readonly about: CommandResource<TokenAboutPayload>;
  readonly activity: CommandResource<TokenActivityPage>;
}

export interface TokenIntelligenceContext {
  readonly command: CommandClient;
  readonly nowMs: () => number;
}

/**
 * Build the lazy, capability-gated resources for the selected exact identity.
 * Each `run({chain, address, ...})` dispatches over the encrypted command
 * channel; a payload the parser cannot render fails closed as a protocol error.
 */
export function createTokenIntelligenceResources(
  ctx: TokenIntelligenceContext,
): TokenIntelligenceResources {
  const capability: CapabilityKey = "token_intelligence";
  return {
    capability,
    holders: createCommandResource<TokenHoldersPayload>(ctx.command, "get_token_holders", {
      capability,
      ttlMs: TOKEN_INTELLIGENCE_TTL_MS,
      clock: ctx.nowMs,
      validate: (value, payload) => {
        const parsed = requireParsed(value, parseTokenHolders, "token holders");
        assertRequestedIdentity(parsed, payload);
        return parsed;
      },
    }),
    about: createCommandResource<TokenAboutPayload>(ctx.command, "get_token_about", {
      capability,
      ttlMs: TOKEN_INTELLIGENCE_TTL_MS,
      clock: ctx.nowMs,
      validate: (value, payload) => {
        const parsed = requireParsed(value, parseTokenAbout, "token about");
        assertRequestedIdentity(parsed.token, payload);
        return parsed;
      },
    }),
    activity: createCommandResource<TokenActivityPage>(ctx.command, "get_token_activity", {
      capability,
      ttlMs: TOKEN_INTELLIGENCE_TTL_MS,
      clock: ctx.nowMs,
      validate: (value, payload) => {
        const parsed = requireParsed(value, parseTokenActivityPage, "token activity");
        assertRequestedIdentity(parsed, payload);
        return parsed;
      },
    }),
  };
}
