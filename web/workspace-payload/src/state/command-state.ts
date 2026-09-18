import { createSignal, getOwner, onCleanup, type Accessor } from "solid-js";
import { isCancellation, toWorkspaceErrorShape } from "../core/errors";
import {
  errorState,
  idleState,
  loadingState,
  readyState,
  unavailableState,
  type CapabilityKey,
  type DataState,
} from "../core/types";
import type { CommandClient } from "../transport/command";

export interface CommandResourceOptions<T = unknown> {
  /** Capability this command depends on, used for the `unavailable` state. */
  readonly capability?: CapabilityKey;
  /** Freshness TTL applied to a successful result. */
  readonly ttlMs?: number;
  /** Local clock, injectable for tests. */
  readonly clock?: () => number;
  /**
   * Validate/parse an untrusted success result. The private API is
   * authoritative for the wire shape, so a document the client cannot consume
   * must be rejected here: a thrown error becomes the resource's `error` state
   * (never a `ready` value that later throws inside a renderer). The optional
   * second argument is the exact request payload, so a validator can also reject
   * a success that does not belong to the requested identity (a stale A response
   * must never render under B).
   */
  readonly validate?: (value: unknown, payload?: unknown) => T;
}

export interface CommandResource<T> {
  readonly state: Accessor<DataState<T>>;
  run(payload?: unknown, options?: CommandRunOptions): Promise<void>;
  reset(): void;
}

export interface CommandRunOptions {
  /** Stable key so a transport retry cannot duplicate a write (INVARIANTS #9). */
  readonly idempotencyKey?: string;
}

/**
 * Drives a `CommandClient` call into the standard `DataState<T>` machine.
 * Capability-missing failures become `unavailable` (no retry can help); other
 * failures keep the last known value as `error.prior` where present.
 */
export function createCommandResource<T>(
  command: CommandClient,
  op: string,
  options: CommandResourceOptions<T> = {},
): CommandResource<T> {
  const clock = options.clock ?? (() => Date.now());
  const [state, setState] = createSignal<DataState<T>>(idleState());
  let controller: AbortController | null = null;
  let generation = 0;

  const run = async (payload?: unknown, runOptions?: CommandRunOptions): Promise<void> => {
    controller?.abort();
    controller = new AbortController();
    const token = ++generation;
    const prior = (() => {
      const current = state();
      if (current.kind === "ready" || current.kind === "stale") return current.value;
      if (current.kind === "loading" || current.kind === "error") return current.prior;
      return undefined;
    })();
    setState(loadingState(clock(), prior));
    try {
      const result = await command.send<unknown>(op, payload, {
        signal: controller.signal,
        idempotencyKey: runOptions?.idempotencyKey,
      });
      if (token !== generation) return;
      // A validator throw is caught below and surfaced as an error state, so a
      // malformed success can never be marked `ready`.
      const value = options.validate ? options.validate(result, payload) : (result as T);
      setState(
        readyState(value, {
          receivedAtMs: clock(),
          slot: null,
          sourceAgeMs: 0,
          ttlMs: options.ttlMs ?? 10_000,
        }),
      );
    } catch (error) {
      if (token !== generation) return;
      if (isCancellation(error)) return;
      const shape = toWorkspaceErrorShape(error);
      const next: DataState<T> =
        shape.code === "capability_missing"
          ? unavailableState<T>(options.capability ?? "market", shape.message)
          : errorState<T>(shape, prior);
      setState(next);
    }
  };

  const reset = (): void => {
    controller?.abort();
    controller = null;
    generation++;
    setState(idleState<T>());
  };

  if (getOwner()) onCleanup(() => controller?.abort());

  return { state, run, reset };
}
