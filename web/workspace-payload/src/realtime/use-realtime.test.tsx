import { createSignal } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@solidjs/testing-library";
import { bytesToBase64 } from "../core/base64";
import type { ConnectionStatus } from "../core/types";
import type { RealtimeController, RealtimeStartConfig } from "./controller";
import { useRealtimeFeed, type RealtimeFeed } from "./use-realtime";
import type { DecodedFrame } from "./types";
import { WorkspaceProvider, createWorkspaceStore, useWorkspace, type WorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const S2C_KEY = bytesToBase64(new Uint8Array(32).fill(7));
const C2S_KEY = bytesToBase64(new Uint8Array(32).fill(9));

const CONNECTING: ConnectionStatus = {
  phase: "idle",
  lastFrameAtMs: null,
  attempt: 0,
  nextRetryAtMs: null,
  reason: null,
};

function makeStore(realtime: boolean): WorkspaceStore {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command: { async send<T>(): Promise<T> { throw new Error("unused"); } },
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { realtime, market: true },
      trading_enabled: false,
      kill_switch: { enabled: false, reason: null },
      chains: [],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  return store;
}

function fakeController(started: RealtimeStartConfig[], stopped: { count: number }): RealtimeController {
  return {
    status: () => CONNECTING,
    lastError: () => null,
    start: (config) => started.push(config),
    stop: () => {
      stopped.count += 1;
    },
    dispose: () => {
      stopped.count += 1;
    },
    subscribe: () => () => {},
  };
}

/** Controller whose frames can be pushed in tests, to exercise subscriber replay. */
function emittingController(): RealtimeController & { emit: (frames: DecodedFrame[]) => void } {
  const handlers = new Set<(frames: DecodedFrame[]) => void>();
  return {
    status: () => CONNECTING,
    lastError: () => null,
    start: () => {},
    stop: () => {},
    dispose: () => handlers.clear(),
    subscribe: (handler) => {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    emit: (frames) => {
      for (const handler of handlers) handler(frames);
    },
  };
}

/** Controller whose frames and connection phase can both be driven in tests. */
function phaseController(
  initial: ConnectionStatus,
): RealtimeController & {
  emit: (frames: DecodedFrame[]) => void;
  setPhase: (status: ConnectionStatus) => void;
} {
  const [status, setStatus] = createSignal<ConnectionStatus>(initial);
  const handlers = new Set<(frames: DecodedFrame[]) => void>();
  return {
    status,
    lastError: () => null,
    start: () => {},
    stop: () => {},
    dispose: () => handlers.clear(),
    subscribe: (handler) => {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    emit: (frames) => {
      for (const handler of handlers) handler(frames);
    },
    setPhase: (next) => setStatus(next),
  };
}

function frame(seq: number, op: DecodedFrame["op"] = "snapshot"): DecodedFrame {
  return {
    seq,
    op,
    channel: "ohlcv",
    priority: 1,
    entityKey: "ohlcv:default",
    slot: 1,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: { timeframe: "1m", candles: [] },
  };
}

const originalWorker = (globalThis as { Worker?: unknown }).Worker;

function Harness(props: { store: WorkspaceStore; controller: RealtimeController }) {
  useRealtimeFeed(props.store, { controller: props.controller, keyTimeoutMs: 30 });
  return <div />;
}

function CaptureFeed(props: {
  store: WorkspaceStore;
  controller: RealtimeController;
  onFeed: (feed: RealtimeFeed) => void;
}) {
  const feed = useRealtimeFeed(props.store, { controller: props.controller, keyTimeoutMs: 30 });
  props.onFeed(feed);
  return <div />;
}

/**
 * Reproduces the production wiring: the provider owns the store, so bootstrap
 * resolves *after* the child mounts. The feed must wait for the authoritative
 * capability set rather than latching the pre-bootstrap (all-false) snapshot.
 */
function ProviderHarness(props: { controller: RealtimeController }) {
  const ws = useWorkspace();
  useRealtimeFeed(ws, { controller: props.controller, keyTimeoutMs: 30 });
  return <div />;
}

const REALTIME_BOOTSTRAP = {
  protocol_version: 1,
  capabilities: { realtime: true, market: true },
  trading_enabled: false,
  kill_switch: { enabled: false, reason: null },
  chains: [],
  session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
  server_time_ms: 1_699_999_000_000,
};

function deliver(data: unknown) {
  window.dispatchEvent(
    new MessageEvent("message", { data, source: window, origin: window.location.origin }),
  );
}

describe("useRealtimeFeed", () => {
  afterEach(() => {
    cleanup();
    if (originalWorker === undefined) delete (globalThis as { Worker?: unknown }).Worker;
    else (globalThis as { Worker?: unknown }).Worker = originalWorker;
  });

  it("starts the worker only after a valid host session key arrives", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = makeStore(true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    expect(started).toHaveLength(0);
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY });
    await flush();
    expect(started).toHaveLength(1);
    expect(started[0]).toMatchObject({ kid: "kid-1", keyB64: S2C_KEY });
    expect(started[0]!.url).toContain("/v1/stream");
  });

  it("installs the encrypted command channel when a client->server key is present", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = makeStore(true);
    await flush();
    const setCommand = vi.spyOn(store, "setCommand");
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue({ ok: false, status: 500 } as Response);
    render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY, c2sKeyB64: C2S_KEY });
    await flush();
    expect(setCommand).toHaveBeenCalledTimes(1);
    // The c2s key is also handed to the worker so it can seal opaque syncs.
    expect(started[0]).toMatchObject({ kid: "kid-1", keyB64: S2C_KEY, c2sKeyB64: C2S_KEY });
    // The stable proxy delegates to the encrypted client: a command now leaves
    // the process on the neutral path instead of failing with capability_missing.
    await expect(store.command.send("get_quote", { a: 1 })).rejects.toMatchObject({ code: "server" });
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining("/v1/command"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("stays offline with a reason when the realtime capability is missing", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = makeStore(false);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    await flush();
    expect(started).toHaveLength(0);
    expect(store.connection().phase).toBe("offline");
    expect(store.connection().reason).toMatch(/realtime capability/i);
  });

  it("does not start after unmount even if a key arrives later", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = makeStore(true);
    await flush();
    const result = render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    result.unmount();
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY });
    await flush();
    expect(started).toHaveLength(0);
  });

  it("fails closed with a reason when the handoff key is not valid base64", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = makeStore(true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: "!!!!" });
    await flush();
    expect(started).toHaveLength(0);
    expect(store.connection().reason).toMatch(/rejected/i);
  });

  it("starts after the provider-owned bootstrap resolves (production ordering)", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    render(() => (
      <WorkspaceProvider
        options={{
          manualClock: true,
          clock: () => 1_000,
          session: parseWorkspaceSession(REALTIME_BOOTSTRAP),
        }}
      >
        <ProviderHarness controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    // The session has not settled yet: the feed must not latch "offline".
    expect(started).toHaveLength(0);
    await flush();
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY });
    await flush();
    expect(started).toHaveLength(1);
    expect(started[0]).toMatchObject({ kid: "kid-1", keyB64: S2C_KEY });
  });

  it("replays retained snapshots and deltas to a late subscriber", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const store = makeStore(true);
    await flush();
    const controller = emittingController();
    let feed: RealtimeFeed | undefined;
    render(() => (
      <WorkspaceProvider store={store}>
        <CaptureFeed store={store} controller={controller} onFeed={(value) => (feed = value)} />
      </WorkspaceProvider>
    ));
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY });
    await flush();

    controller.emit([frame(7)]);
    const received: number[] = [];
    feed!.subscribe((frames) => received.push(...frames.map((item) => item.seq)));
    expect(received).toEqual([7]);

    // A late panel gets the snapshot and the deltas that followed, in order.
    controller.emit([frame(8, "delta")]);
    controller.emit([frame(9, "delta")]);
    const receivedLater: number[] = [];
    feed!.subscribe((frames) => receivedLater.push(...frames.map((item) => item.seq)));
    expect(receivedLater).toEqual([7, 8, 9]);
  });

  it("drops retained frames on resync so a late panel cannot replay pre-resync state", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const store = makeStore(true);
    await flush();
    const controller = phaseController(CONNECTING);
    let feed: RealtimeFeed | undefined;
    render(() => (
      <WorkspaceProvider store={store}>
        <CaptureFeed store={store} controller={controller} onFeed={(value) => (feed = value)} />
      </WorkspaceProvider>
    ));
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY });
    await flush();

    controller.emit([frame(7)]);
    const first: number[] = [];
    feed!.subscribe((frames) => first.push(...frames.map((item) => item.seq)));
    expect(first).toEqual([7]);

    // A gap/resync invalidates the retained epoch; the pre-resync delta must not
    // be replayed on top of the fresh baseline.
    controller.setPhase({ ...CONNECTING, phase: "degraded", reason: "Resync (gap)" });
    await flush();
    const afterResync: number[] = [];
    feed!.subscribe((frames) => afterResync.push(...frames.map((item) => item.seq)));
    expect(afterResync).toEqual([]);

    // Frames from the recovered epoch are retained normally.
    controller.emit([frame(20)]);
    const recovered: number[] = [];
    feed!.subscribe((frames) => recovered.push(...frames.map((item) => item.seq)));
    expect(recovered).toEqual([20]);
  });

  it("does not report realtime offline before the session settles", async () => {
    (globalThis as { Worker?: unknown }).Worker = class {};
    const started: RealtimeStartConfig[] = [];
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      // Bootstrap stays pending for the duration of the assertion.
      fetchFn: () => new Promise<Response>(() => {}),
    });
    store.reload();
    render(() => (
      <WorkspaceProvider store={store}>
        <ProviderHarness controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    await flush();
    expect(started).toHaveLength(0);
    expect(store.connection().phase).toBe("connecting");
    expect(store.connection().reason).toBeNull();
  });
});
