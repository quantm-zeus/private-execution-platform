// Typed core contracts for the private workspace payload.
//
// These types are the single source of truth for how the UI reasons about
// backend state. They deliberately model *absence* and *staleness* as
// first-class values so no surface can silently render an unknown value as a
// confident one.

/** Backend capability keys the workspace can probe via `/v1/bootstrap`. */
export type CapabilityKey =
  | "market"
  | "realtime"
  | "quotes"
  | "preview"
  | "execute"
  | "limits"
  | "portfolio"
  | "intelligence"
  | "twitter"
  | "gmgn"
  | "okx"
  | "twap"
  | "rfq"
  | "withdraw";

export const CAPABILITY_KEYS: readonly CapabilityKey[] = [
  "market",
  "realtime",
  "quotes",
  "preview",
  "execute",
  "limits",
  "portfolio",
  "intelligence",
  "twitter",
  "gmgn",
  "okx",
  "twap",
  "rfq",
  "withdraw",
] as const;

export type CapabilitySet = Readonly<Record<CapabilityKey, boolean>>;

/** Human-readable reason a capability-gated control is disabled. */
export interface CapabilityDenial {
  readonly capability: CapabilityKey;
  readonly reason: string;
}

export interface ChainInfo {
  readonly id: string;
  readonly display: string;
  readonly enabled: boolean;
}

export interface KillSwitchState {
  readonly enabled: boolean;
  readonly reason: string | null;
}

/** Freshness metadata attached to every authoritative value. */
export interface Freshness {
  /** Local monotonic-ish wall clock at which the frame was accepted. */
  readonly receivedAtMs: number;
  /** Chain slot/height if the source provides one; `null` when unknown. */
  readonly slot: number | null;
  /** Source-provided age at emission, in ms. */
  readonly sourceAgeMs: number;
  /** Maximum acceptable age before the value is considered stale. */
  readonly ttlMs: number;
}

export type WorkspaceErrorCode =
  | "network"
  | "auth"
  | "capability_missing"
  | "freshness"
  | "protocol"
  | "server"
  | "cancelled"
  | "unknown";

export interface WorkspaceErrorShape {
  readonly code: WorkspaceErrorCode;
  /** Safe, user-facing message. Never contains secrets or key material. */
  readonly message: string;
  readonly retryable: boolean;
  /** Machine-readable detail safe to display/log (no private semantics). */
  readonly detail?: string;
}

export class WorkspaceError extends Error implements WorkspaceErrorShape {
  public readonly code: WorkspaceErrorCode;
  public readonly retryable: boolean;
  public readonly detail?: string;

  constructor(shape: WorkspaceErrorShape) {
    super(shape.message);
    this.name = "WorkspaceError";
    this.code = shape.code;
    this.retryable = shape.retryable;
    this.detail = shape.detail;
  }

  toShape(): WorkspaceErrorShape {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      detail: this.detail,
    };
  }
}

/**
 * The state machine every async surface renders from.
 *
 * `unavailable` is distinct from `error`: it means the backend capability the
 * surface depends on does not exist yet, so no retry can help. `stale` keeps
 * the last known value but marks it untrustworthy for decisions.
 */
export type DataState<T> =
  | { readonly kind: "idle" }
  | { readonly kind: "loading"; readonly sinceMs: number; readonly prior?: T }
  | { readonly kind: "ready"; readonly value: T; readonly freshness: Freshness }
  | {
      readonly kind: "stale";
      readonly value: T;
      readonly freshness: Freshness;
      readonly reason: string;
    }
  | { readonly kind: "error"; readonly error: WorkspaceErrorShape; readonly prior?: T }
  | {
      readonly kind: "unavailable";
      readonly capability: CapabilityKey;
      readonly reason: string;
    };

export const idleState = <T>(): DataState<T> => ({ kind: "idle" });

export const loadingState = <T>(sinceMs: number, prior?: T): DataState<T> =>
  prior === undefined ? { kind: "loading", sinceMs } : { kind: "loading", sinceMs, prior };

export const readyState = <T>(value: T, freshness: Freshness): DataState<T> => ({
  kind: "ready",
  value,
  freshness,
});

export const errorState = <T>(
  error: WorkspaceErrorShape,
  prior?: T,
): DataState<T> => (prior === undefined ? { kind: "error", error } : { kind: "error", error, prior });

export const unavailableState = <T>(
  capability: CapabilityKey,
  reason: string,
): DataState<T> => ({ kind: "unavailable", capability, reason });

/** Returns the value for ready/stale/error-with-prior states, else undefined. */
export function stateValue<T>(state: DataState<T>): T | undefined {
  switch (state.kind) {
    case "ready":
    case "stale":
      return state.value;
    case "loading":
    case "error":
      return state.prior;
    default:
      return undefined;
  }
}

export type ConnectionPhase =
  | "idle"
  | "connecting"
  | "live"
  | "degraded"
  | "reconnecting"
  | "offline";

export interface ConnectionStatus {
  readonly phase: ConnectionPhase;
  /** Local time of the last accepted frame, if any. */
  readonly lastFrameAtMs: number | null;
  /** Current reconnect attempt (0 when live). */
  readonly attempt: number;
  /** Next scheduled retry, when reconnecting. */
  readonly nextRetryAtMs: number | null;
  readonly reason: string | null;
}

/** A value paired with the freshness policy that governs it. */
export interface TtlPolicy {
  readonly ttlMs: number;
}

export const DEFAULT_TTL_MS = 5_000;

export function ageMs(freshness: Freshness, nowMs: number): number {
  return Math.max(0, nowMs - freshness.receivedAtMs + freshness.sourceAgeMs);
}

export function isFresh(freshness: Freshness, nowMs: number): boolean {
  return ageMs(freshness, nowMs) <= freshness.ttlMs;
}
