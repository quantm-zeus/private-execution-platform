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

export interface CommandResourceOptions {
  /** Capability this command depends on, used for the `unavailable` state. */
  readonly capability?: CapabilityKey;
  /** Freshness TTL applied to a successful result. */
  readonly ttlMs?: number;
  /** Local clock, injectable for tests. */
  readonly clock?: () => number;
}

export interface CommandResource<T> {
  readonly state: Accessor<DataState<T>>;
  run(payload?: unknown): Promise<void>;
  reset(): void;
}

/**
 * Drives a `CommandClient` call into the standard `DataState<T>` machine.
 * Capability-missing failures become `unavailable` (no retry can help); other
 * failures keep the last known value as `error.prior` where present.
 */
export function createCommandResource<T>(
  command: CommandClient,
  op: string,
  options: CommandResourceOptions = {},
): CommandResource<T> {
  const clock = options.clock ?? (() => Date.now());
  const [state, setState] = createSignal<DataState<T>>(idleState());
  let controller: AbortController | null = null;
  let generation = 0;

  const run = async (payload?: unknown): Promise<void> => {
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
      const result = await command.send<T>(op, payload, { signal: controller.signal });
      if (token !== generation) return;
      setState(
        readyState(result, {
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
