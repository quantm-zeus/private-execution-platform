// Trading-wallet limit & policy configuration (PRD line 86: "Trading wallet
// limits are configurable: max trade USD, hourly/daily turnover, max buy/sell
// tax, max price impact, max slippage, allowed chains, routers and programs").
//
// This is a web-only, strongly-confirmed surface. The backend contract is new
// (BR-14) so every value is parsed strictly from an untrusted response and the
// whole surface fails closed on any gap: a missing restriction list must never
// be rendered as "unrestricted", and a malformed cap is never coerced.

import { workspaceError } from "../core/errors";

/** The wallet's current, authoritative limit configuration. */
export interface WalletLimitsView {
  /** Owner/trading-wallet reference; `null` when the backend does not report one. */
  readonly walletRef: string | null;
  /** Maximum notional (USD) of a single trade; `null` = no configured cap. */
  readonly maxTradeUsd: number | null;
  readonly hourlyTurnoverUsd: number | null;
  readonly dailyTurnoverUsd: number | null;
  readonly maxBuyTaxBps: number | null;
  readonly maxSellTaxBps: number | null;
  readonly maxPriceImpactBps: number | null;
  readonly maxSlippageBps: number | null;
  /** Allowlisted chain ids. An empty list means "none allowed", never "all". */
  readonly allowedChains: readonly string[];
  /** Allowlisted routing sources (`okx` / `local`, plus any backend-defined id). */
  readonly allowedRouters: readonly string[];
  /** Allowlisted program/router addresses. */
  readonly allowedPrograms: readonly string[];
  readonly sourceAgeMs: number;
  readonly slot: number | null;
}

/** The subset a user may edit. Mirrors `WalletLimitsView` without freshness. */
export interface WalletLimitsEditable {
  readonly maxTradeUsd: number | null;
  readonly hourlyTurnoverUsd: number | null;
  readonly dailyTurnoverUsd: number | null;
  readonly maxBuyTaxBps: number | null;
  readonly maxSellTaxBps: number | null;
  readonly maxPriceImpactBps: number | null;
  readonly maxSlippageBps: number | null;
  readonly allowedChains: readonly string[];
  readonly allowedRouters: readonly string[];
  readonly allowedPrograms: readonly string[];
}

export type LimitDirection = "tighten" | "relax" | "changed";

export interface WalletLimitsChange {
  readonly field: string;
  readonly label: string;
  readonly direction: LimitDirection;
  readonly from: string;
  readonly to: string;
}

/** Hard ceiling on any numeric limit: rejects overflow/nonsense, not a policy value. */
export const MAX_LIMIT_VALUE = 1e12;
/**
 * Upper bound on the advertised policy age. A value beyond this is treated as a
 * malformed response rather than a merely-stale one, so an absurd timestamp
 * cannot masquerade as a policy read.
 */
export const MAX_SOURCE_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_LIST = 256;
const MAX_ENTRY = 128;
/**
 * Strict decimal literal for form input: `12`, `12.5`, `.5`. Deliberately rejects
 * `0x10`/`0b10`/`0o10`, exponent notation, a leading `+`, and a trailing dot,
 * which `Number()` would otherwise silently reinterpret as a different cap.
 */
const DECIMAL_INPUT = /^(?:\d+(?:\.\d+)?|\.\d+)$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCap(raw: unknown, field: string): number | null {
  // An explicit `null` means "no configured cap". A *missing* key is a
  // malformed response: coercing it to "unlimited" would silently widen the
  // wallet's policy, so it fails closed like the restriction lists.
  if (raw === null) return null;
  if (raw === undefined) {
    throw workspaceError("protocol", `Wallet limit "${field}" was missing.`);
  }
  if (
    typeof raw !== "number" ||
    !Number.isFinite(raw) ||
    raw < 0 ||
    raw > MAX_LIMIT_VALUE
  ) {
    throw workspaceError("protocol", `Wallet limit "${field}" was malformed.`);
  }
  return raw;
}

function parseList(raw: unknown, field: string): readonly string[] {
  if (!Array.isArray(raw)) {
    // A missing restriction list is ambiguous. Never assume "unrestricted":
    // the surface fails closed and asks for a fresh, complete response.
    throw workspaceError("protocol", `Wallet limit list "${field}" was missing or malformed.`);
  }
  if (raw.length > MAX_LIST) {
    throw workspaceError("protocol", `Wallet limit list "${field}" exceeded the size limit.`);
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_ENTRY) {
      throw workspaceError("protocol", `Wallet limit list "${field}" contained a malformed entry.`);
    }
    if (!seen.has(entry)) {
      seen.add(entry);
      out.push(entry);
    }
  }
  return out;
}

/** Strictly validate an untrusted `get_wallet_limits` result. */
export function parseWalletLimits(raw: unknown): WalletLimitsView {
  if (!isRecord(raw)) throw workspaceError("protocol", "Malformed wallet-limits response.");
  const walletRef =
    typeof raw.wallet_ref === "string" && raw.wallet_ref.length > 0 && raw.wallet_ref.length <= MAX_ENTRY
      ? raw.wallet_ref
      : null;
  const sourceAgeMs = raw.source_age_ms;
  if (
    typeof sourceAgeMs !== "number" ||
    !Number.isFinite(sourceAgeMs) ||
    sourceAgeMs < 0 ||
    sourceAgeMs > MAX_SOURCE_AGE_MS
  ) {
    throw workspaceError("protocol", "Wallet-limits response carried no valid source age.");
  }
  const slot =
    typeof raw.slot === "number" && Number.isFinite(raw.slot) && raw.slot >= 0 ? raw.slot : null;
  return {
    walletRef,
    maxTradeUsd: parseCap(raw.max_trade_usd, "max_trade_usd"),
    hourlyTurnoverUsd: parseCap(raw.hourly_turnover_usd, "hourly_turnover_usd"),
    dailyTurnoverUsd: parseCap(raw.daily_turnover_usd, "daily_turnover_usd"),
    maxBuyTaxBps: parseCap(raw.max_buy_tax_bps, "max_buy_tax_bps"),
    maxSellTaxBps: parseCap(raw.max_sell_tax_bps, "max_sell_tax_bps"),
    maxPriceImpactBps: parseCap(raw.max_price_impact_bps, "max_price_impact_bps"),
    maxSlippageBps: parseCap(raw.max_slippage_bps, "max_slippage_bps"),
    allowedChains: parseList(raw.allowed_chains, "allowed_chains"),
    allowedRouters: parseList(raw.allowed_routers, "allowed_routers"),
    allowedPrograms: parseList(raw.allowed_programs, "allowed_programs"),
    sourceAgeMs,
    slot,
  };
}

/** Project the editable fields out of an authoritative view. */
export function limitsFromView(view: WalletLimitsView): WalletLimitsEditable {
  return {
    maxTradeUsd: view.maxTradeUsd,
    hourlyTurnoverUsd: view.hourlyTurnoverUsd,
    dailyTurnoverUsd: view.dailyTurnoverUsd,
    maxBuyTaxBps: view.maxBuyTaxBps,
    maxSellTaxBps: view.maxSellTaxBps,
    maxPriceImpactBps: view.maxPriceImpactBps,
    maxSlippageBps: view.maxSlippageBps,
    allowedChains: [...view.allowedChains],
    allowedRouters: [...view.allowedRouters],
    allowedPrograms: [...view.allowedPrograms],
  };
}

/**
 * Parse a raw numeric form input. An empty string means "no configured cap"
 * (`null`). Any other non-finite/negative/oversized value is an explicit error
 * rather than a silent collapse to "no cap".
 */
export function parseLimitInput(raw: string): { value: number | null; error: string | null } {
  const trimmed = raw.trim();
  if (trimmed === "") return { value: null, error: null };
  if (!DECIMAL_INPUT.test(trimmed)) {
    return { value: null, error: "Enter a plain decimal number (no hex, exponent or sign)." };
  }
  const value = Number(trimmed);
  if (!Number.isFinite(value)) return { value: null, error: "Enter a finite number." };
  if (value < 0) return { value: null, error: "Must be zero or greater." };
  if (value > MAX_LIMIT_VALUE) return { value: null, error: "Value is too large." };
  return { value, error: null };
}

/** Parse a comma/whitespace/newline separated address list into unique entries. */
export function parseListInput(raw: string): readonly string[] {
  return validateListInput(raw).value;
}

/**
 * Parse and bound a pasted allowlist. Returns a field error (rather than
 * silently dropping entries) when the list is too large or an entry is too
 * long, so the panel can block the save and tell the user.
 */
export function validateListInput(raw: string): {
  readonly value: readonly string[];
  readonly error: string | null;
} {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(/[\s,]+/)) {
    const entry = part.trim();
    if (entry.length === 0 || seen.has(entry)) continue;
    if (entry.length > MAX_ENTRY) {
      return { value: out, error: `An entry is longer than ${MAX_ENTRY} characters.` };
    }
    seen.add(entry);
    out.push(entry);
    if (out.length > MAX_LIST) {
      return { value: out.slice(0, MAX_LIST), error: `Too many entries (maximum ${MAX_LIST}).` };
    }
  }
  return { value: out, error: null };
}

export function editableEquals(a: WalletLimitsEditable, b: WalletLimitsEditable): boolean {
  return (
    a.maxTradeUsd === b.maxTradeUsd &&
    a.hourlyTurnoverUsd === b.hourlyTurnoverUsd &&
    a.dailyTurnoverUsd === b.dailyTurnoverUsd &&
    a.maxBuyTaxBps === b.maxBuyTaxBps &&
    a.maxSellTaxBps === b.maxSellTaxBps &&
    a.maxPriceImpactBps === b.maxPriceImpactBps &&
    a.maxSlippageBps === b.maxSlippageBps &&
    listEquals(a.allowedChains, b.allowedChains) &&
    listEquals(a.allowedRouters, b.allowedRouters) &&
    listEquals(a.allowedPrograms, b.allowedPrograms)
  );
}

function listEquals(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((entry, index) => entry === b[index]);
}

function capDirection(from: number | null, to: number | null): LimitDirection | null {
  if (from === to) return null;
  // Dropping a cap (number -> null) widens what the wallet may do: relaxing.
  if (from === null) return "tighten";
  if (to === null) return "relax";
  return to > from ? "relax" : "tighten";
}

function listDirection(from: readonly string[], to: readonly string[]): LimitDirection | null {
  const added = to.some((entry) => !from.includes(entry));
  const removed = from.some((entry) => !to.includes(entry));
  if (!added && !removed) return null;
  // Any newly permitted entry is a relaxation; removals only are a tightening.
  return added ? "relax" : "tighten";
}

function formatCap(value: number | null): string {
  return value === null ? "unlimited" : String(value);
}

function formatList(value: readonly string[]): string {
  return value.length === 0 ? "none" : value.join(", ");
}

/**
 * Classify every changed field as tightening (safer) or relaxing (needs an
 * explicit strong confirmation). Unchanged fields are omitted.
 */
export function diffWalletLimits(
  current: WalletLimitsEditable,
  next: WalletLimitsEditable,
): readonly WalletLimitsChange[] {
  const changes: WalletLimitsChange[] = [];
  const caps: readonly [string, string, number | null, number | null][] = [
    ["maxTradeUsd", "Max trade (USD)", current.maxTradeUsd, next.maxTradeUsd],
    ["hourlyTurnoverUsd", "Hourly turnover (USD)", current.hourlyTurnoverUsd, next.hourlyTurnoverUsd],
    ["dailyTurnoverUsd", "Daily turnover (USD)", current.dailyTurnoverUsd, next.dailyTurnoverUsd],
    ["maxBuyTaxBps", "Max buy tax (bps)", current.maxBuyTaxBps, next.maxBuyTaxBps],
    ["maxSellTaxBps", "Max sell tax (bps)", current.maxSellTaxBps, next.maxSellTaxBps],
    ["maxPriceImpactBps", "Max price impact (bps)", current.maxPriceImpactBps, next.maxPriceImpactBps],
    ["maxSlippageBps", "Max slippage (bps)", current.maxSlippageBps, next.maxSlippageBps],
  ];
  for (const [field, label, from, to] of caps) {
    const direction = capDirection(from, to);
    if (direction) {
      changes.push({ field, label, direction, from: formatCap(from), to: formatCap(to) });
    }
  }
  const lists: readonly [string, string, readonly string[], readonly string[]][] = [
    ["allowedChains", "Allowed chains", current.allowedChains, next.allowedChains],
    ["allowedRouters", "Allowed routers", current.allowedRouters, next.allowedRouters],
    ["allowedPrograms", "Allowed programs", current.allowedPrograms, next.allowedPrograms],
  ];
  for (const [field, label, from, to] of lists) {
    const direction = listDirection(from, to);
    if (direction) {
      changes.push({ field, label, direction, from: formatList(from), to: formatList(to) });
    }
  }
  return changes;
}

export function hasRelaxation(changes: readonly WalletLimitsChange[]): boolean {
  return changes.some((change) => change.direction === "relax");
}

/** Snake_case payload for the `set_wallet_limits` command (BR-14). */
export function walletLimitsPayload(editable: WalletLimitsEditable): Record<string, unknown> {
  return {
    max_trade_usd: editable.maxTradeUsd,
    hourly_turnover_usd: editable.hourlyTurnoverUsd,
    daily_turnover_usd: editable.dailyTurnoverUsd,
    max_buy_tax_bps: editable.maxBuyTaxBps,
    max_sell_tax_bps: editable.maxSellTaxBps,
    max_price_impact_bps: editable.maxPriceImpactBps,
    max_slippage_bps: editable.maxSlippageBps,
    allowed_chains: [...editable.allowedChains],
    allowed_routers: [...editable.allowedRouters],
    allowed_programs: [...editable.allowedPrograms],
  };
}
