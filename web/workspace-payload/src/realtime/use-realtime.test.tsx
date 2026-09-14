import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@solidjs/testing-library";
import { bytesToBase64 } from "../core/base64";
import type { ConnectionStatus } from "../core/types";
import type { RealtimeController, RealtimeStartConfig } from "./controller";
import { useRealtimeFeed } from "./use-realtime";
import { WorkspaceProvider, createWorkspaceStore, type WorkspaceStore } from "../state/session";
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

const originalWorker = (globalThis as { Worker?: unknown }).Worker;

function Harness(props: { store: WorkspaceStore; controller: RealtimeController }) {
  useRealtimeFeed(props.store, { controller: props.controller, keyTimeoutMs: 30 });
  return <div />;
}

function deliver(data: unknown) {
  window.dispatchEvent(new MessageEvent("message", { data, source: window }));
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
    const before = store.command;
    render(() => (
      <WorkspaceProvider store={store}>
        <Harness store={store} controller={fakeController(started, { count: 0 })} />
      </WorkspaceProvider>
    ));
    deliver({ type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C_KEY, c2sKeyB64: C2S_KEY });
    await flush();
    expect(store.command).not.toBe(before);
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
});
