import { createSignal, getOwner, onCleanup, type Accessor } from "solid-js";
import { isCancellation, toWorkspaceErrorShape } from "../core/errors";
import type { CommandClient } from "../transport/command";

/**
 * An exact realtime chart target. Every field is required and compared
 * byte-for-byte: a target is never derived by loose entity-key matching, so a
 * stale `ohlcv:default` or another token's frame can never satisfy it.
 */
export interface RealtimeTarget {
  readonly chain: string;
  readonly address: string;
  readonly timeframe: string;
}

export type RealtimeTargetState =
  | { readonly kind: "idle" }
  | { readonly kind: "sending"; readonly target: RealtimeTarget }
  | { readonly kind: "bound"; readonly target: RealtimeTarget }
  | { readonly kind: "unavailable"; readonly reason: string }
  | { readonly kind: "error"; readonly target: RealtimeTarget; readonly message: string };

export interface RealtimeTargetCoordinatorOptions {
  readonly command: CommandClient;
  /**
   * True only when both the authenticated command channel and the realtime
   * capability are usable. The coordinator holds the desired target until this
   * becomes true, then sends exactly one update.
   */
  readonly canSend: () => boolean;
  /** Injectable clock (unused for decisions; kept for symmetry/tests). */
  readonly clock?: () => number;
}

export interface RealtimeTargetCoordinator {
  readonly state: Accessor<RealtimeTargetState>;
  /** Set the desired exact target (or `null` to clear). Deduplicated. */
  setDesired(target: RealtimeTarget | null): void;
  /** Re-evaluate after readiness changes. */
  sync(): void;
  /** Forget the bound target and abort any in-flight send (session change/lock). */
  reset(): void;
}

/** Cap automatic retries for one exact target so a transient failure cannot loop. */
export const MAX_TARGET_ATTEMPTS = 2;

function normalize(target: RealtimeTarget | null): RealtimeTarget | null {
  if (!target) return null;
  const chain = target.chain.trim();
  const address = target.address.trim();
  const timeframe = target.timeframe.trim();
  if (chain.length === 0 || address.length === 0 || timeframe.length === 0) return null;
  return { chain, address, timeframe };
}

/** Exact, collision-free key for a validated target. */
export function realtimeTargetKey(target: RealtimeTarget | null): string | null {
  const value = normalize(target);
  return value === null ? null : `${value.chain}\u0000${value.address}\u0000${value.timeframe}`;
}

/**
 * Bounded, deduplicated coordinator for the encrypted `set_realtime_target`
 * command.
 *
 * The backend binds one chart target per authenticated session and then emits a
 * fresh OHLCV snapshot for it. This coordinator guarantees:
 *
 * - **exactly one** send per distinct `(chain, address, timeframe)` while the
 *   binding is held — re-selecting the same target never re-sends;
 * - **bounded** concurrency: at most one in-flight command; a newer target
 *   aborts the older one so a stale response cannot re-bind the session;
 * - **fail closed**: it only sends when `canSend()` is true, and a determinate
 *   rejection (capability/auth/protocol) is not retried for that same target;
 * - **bounded retries** for transient failures ({@link MAX_TARGET_ATTEMPTS}).
 *
 * It never matches frames; the exact entity-key isolation lives in the chart
 * router. This module only owns *which* target the backend should serve.
 */
export function createRealtimeTargetCoordinator(
  options: RealtimeTargetCoordinatorOptions,
): RealtimeTargetCoordinator {
  const [state, setState] = createSignal<RealtimeTargetState>({ kind: "idle" });
  let desired: RealtimeTarget | null = null;
  let pendingKey: string | null = null;
  let boundKey: string | null = null;
  let inFlight: AbortController | null = null;
  let attemptsKey: string | null = null;
  let attempts = 0;
  let generation = 0;

  const finish = (token: number): boolean => token === generation;

  const send = (target: RealtimeTarget, key: string): void => {
    // A newer target supersedes the in-flight command; abort it so a late
    // response cannot overwrite the newer binding.
    inFlight?.abort();
    const controller = new AbortController();
    inFlight = controller;
    pendingKey = key;
    const token = ++generation;
    if (attemptsKey !== key) {
      attemptsKey = key;
      attempts = 0;
    }
    attempts += 1;
    setState({ kind: "sending", target });
    options.command
      .send("set_realtime_target", {
        chain: target.chain,
        address: target.address,
        timeframe: target.timeframe,
      }, { signal: controller.signal })
      .then(() => {
        if (!finish(token) || pendingKey !== key) return;
        inFlight = null;
        pendingKey = null;
        boundKey = key;
        setState({ kind: "bound", target });
      })
      .catch((error: unknown) => {
        if (!finish(token) || pendingKey !== key) return;
        inFlight = null;
        pendingKey = null;
        if (isCancellation(error)) return;
        const shape = toWorkspaceErrorShape(error);
        const determinate =
          shape.code === "capability_missing" ||
          shape.code === "auth" ||
          shape.code === "protocol";
        if (determinate) {
          // The same exact target will not become valid by retrying: remember it
          // as resolved so a re-render cannot spin on a permanent rejection.
          boundKey = key;
          setState({ kind: "unavailable", reason: shape.message });
          return;
        }
        setState({ kind: "error", target, message: shape.message });
      });
  };

  const pump = (): void => {
    if (!options.canSend()) return;
    const target = desired;
    const key = realtimeTargetKey(target);
    if (target === null || key === null) return;
    if (key === boundKey) return;
    if (key === pendingKey) return;
    if (attemptsKey === key && attempts >= MAX_TARGET_ATTEMPTS) return;
    send(target, key);
  };

  const coordinator: RealtimeTargetCoordinator = {
    state,
    setDesired(next: RealtimeTarget | null): void {
      const normalized = normalize(next);
      const key = realtimeTargetKey(normalized);
      // Clearing, or re-selecting the already desired target, must not re-send.
      if (key !== null && key === realtimeTargetKey(desired) && pendingKey === null) {
        desired = normalized;
        pump();
        return;
      }
      desired = normalized;
      if (key === null) {
        // No valid target: drop any in-flight binding request and clear the
        // retry budget so re-selecting the same target later can bind again.
        generation += 1;
        inFlight?.abort();
        inFlight = null;
        pendingKey = null;
        boundKey = null;
        attemptsKey = null;
        attempts = 0;
        setState({ kind: "idle" });
        return;
      }
      pump();
    },
    sync(): void {
      pump();
    },
    reset(): void {
      generation += 1;
      inFlight?.abort();
      inFlight = null;
      desired = null;
      pendingKey = null;
      boundKey = null;
      attemptsKey = null;
      attempts = 0;
      setState({ kind: "idle" });
    },
  };

  if (getOwner()) onCleanup(() => coordinator.reset());
  return coordinator;
}
