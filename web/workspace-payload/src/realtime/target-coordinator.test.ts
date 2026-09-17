import { describe, expect, it } from "vitest";
import { workspaceError } from "../core/errors";
import type { CommandClient, CommandSendOptions } from "../transport/command";
import { MAX_TARGET_ATTEMPTS, createRealtimeTargetCoordinator } from "./target-coordinator";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

interface Recorded {
  readonly op: string;
  readonly payload: unknown;
  readonly signal: AbortSignal | undefined;
}

function recordingClient(
  handler?: (op: string, payload: unknown) => unknown,
): { client: CommandClient; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const client: CommandClient = {
    async send<T>(op: string, payload: unknown, options?: CommandSendOptions): Promise<T> {
      calls.push({ op, payload, signal: options?.signal });
      if (handler) return handler(op, payload) as T;
      return { accepted: true } as T;
    },
  };
  return { client, calls };
}

const A = { chain: "base", address: "0xAAA", timeframe: "1m" } as const;
const B = { chain: "base", address: "0xBBB", timeframe: "1m" } as const;

describe("createRealtimeTargetCoordinator", () => {
  it("sends exactly one deduplicated target for a repeated selection", async () => {
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    coordinator.setDesired({ ...A });
    coordinator.sync();
    await flush();

    expect(calls).toHaveLength(1);
    expect(calls[0]!.op).toBe("set_realtime_target");
    expect(calls[0]!.payload).toEqual(A);
  });

  it("issues the correct target when the token changes A -> B", async () => {
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    coordinator.setDesired({ ...B });
    await flush();

    expect(calls.map((call) => call.payload)).toEqual([A, B]);
  });

  it("issues the correct target when only the timeframe changes", async () => {
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    coordinator.setDesired({ ...A, timeframe: "15m" });
    await flush();

    expect(calls).toHaveLength(2);
    expect(calls[1]!.payload).toEqual({ ...A, timeframe: "15m" });
  });

  it("holds the desired target until the command and realtime are ready", async () => {
    let ready = false;
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => ready });

    coordinator.setDesired({ ...A });
    await flush();
    expect(calls).toHaveLength(0);

    ready = true;
    coordinator.sync();
    await flush();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.payload).toEqual(A);
  });

  it("does not retry a determinate rejection for the same exact target", async () => {
    const { client, calls } = recordingClient(() => {
      throw workspaceError("capability_missing", "not available");
    });
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    expect(calls).toHaveLength(1);
    expect(coordinator.state().kind).toBe("unavailable");

    coordinator.sync();
    await flush();
    expect(calls).toHaveLength(1);
  });

  it("bounds transient retries for one exact target", async () => {
    const { client, calls } = recordingClient(() => {
      throw workspaceError("server", "temporary", { retryable: true });
    });
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    for (let i = 0; i < 5; i += 1) {
      coordinator.sync();
      await flush();
    }
    expect(calls).toHaveLength(MAX_TARGET_ATTEMPTS);
    expect(coordinator.state().kind).toBe("error");
  });

  it("aborts the in-flight target when a newer one supersedes it", async () => {
    let resolveFirst: (() => void) | undefined;
    const calls: Recorded[] = [];
    const client: CommandClient = {
      send<T>(op: string, payload: unknown, options?: CommandSendOptions): Promise<T> {
        calls.push({ op, payload, signal: options?.signal });
        if (calls.length === 1) {
          return new Promise<T>((resolve) => {
            resolveFirst = () => resolve({ accepted: true } as T);
          });
        }
        return Promise.resolve({ accepted: true } as T);
      },
    };
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    coordinator.setDesired({ ...B });
    await flush();

    expect(calls[0]!.signal?.aborted).toBe(true);
    resolveFirst?.();
    await flush();
    // The late A response must not overwrite B's binding.
    expect(coordinator.state().kind).toBe("bound");
    expect((coordinator.state() as { target?: unknown }).target).toEqual(B);
  });

  it("clears the binding on reset so a later selection re-sends", async () => {
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ ...A });
    await flush();
    coordinator.reset();
    coordinator.setDesired({ ...A });
    await flush();

    expect(calls).toHaveLength(2);
  });

  it("clears the retry budget when the target is cleared so a later re-selection binds", async () => {
    let fail = true;
    const { client, calls } = recordingClient(() => {
      if (fail) throw workspaceError("server", "temporary", { retryable: true });
      return { accepted: true };
    });
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    // Exhaust the retry budget for A.
    coordinator.setDesired({ ...A });
    await flush();
    coordinator.sync();
    await flush();
    expect(calls).toHaveLength(MAX_TARGET_ATTEMPTS);

    // Readiness is lost (clears the target), then A is selected again and the
    // transient failure is gone: it must bind, not stay stuck at the old budget.
    coordinator.setDesired(null);
    await flush();
    fail = false;
    coordinator.setDesired({ ...A });
    await flush();

    expect(calls).toHaveLength(MAX_TARGET_ATTEMPTS + 1);
    expect(coordinator.state().kind).toBe("bound");
  });

  it("rejects an incomplete target without sending", async () => {
    const { client, calls } = recordingClient();
    const coordinator = createRealtimeTargetCoordinator({ command: client, canSend: () => true });

    coordinator.setDesired({ chain: "base", address: "  ", timeframe: "1m" });
    await flush();

    expect(calls).toHaveLength(0);
    expect(coordinator.state().kind).toBe("idle");
  });
});
