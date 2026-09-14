import { describe, expect, it } from "vitest";
import { parseWorkspaceSession } from "../transport/bootstrap";
import { createWorkspaceStore } from "./session";

const BASE_PAYLOAD = {
  protocol_version: 1,
  capabilities: { market: true, realtime: true, execute: true, withdraw: false },
  trading_enabled: false,
  kill_switch: { enabled: true, reason: "foundation phase" },
  chains: [{ id: "base", display: "Base", enabled: true }],
  session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
  server_time_ms: 1_699_999_000_000,
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("createWorkspaceStore", () => {
  it("exposes capabilities from an injected session and fails mutations closed", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession(BASE_PAYLOAD),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();

    expect(store.state().kind).toBe("ready");
    expect(store.capabilities().market).toBe(true);
    expect(store.capabilityDenial("market")).toBeNull();
    expect(store.capabilityDenial("withdraw")?.capability).toBe("withdraw");
    expect(store.tradingEnabled()).toBe(false);
    const denial = store.mutationDenial("execute");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/kill switch|disabled/i);
    expect(store.connection().phase).toBe("connecting");
  });

  it("allows a mutation only when capability, trading gate and kill switch agree", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
      }),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();
    expect(store.mutationDenial("execute")).toBeNull();
  });

  it("maps a missing backend contract to unavailable, not a fabricated ready state", async () => {
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      baseUrl: "https://workspace.example",
      fetchFn: (async () => ({ ok: false, status: 404 })) as unknown as typeof fetch,
    });
    store.reload();
    await flush();
    expect(store.state().kind).toBe("unavailable");
    expect(store.session()).toBeUndefined();
    expect(store.capabilities().market).toBe(false);
    expect(store.connection().phase).toBe("offline");
  });

  it("maps a server failure to a retryable error state", async () => {
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      baseUrl: "https://workspace.example",
      fetchFn: (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch,
    });
    store.reload();
    await flush();
    const state = store.state();
    expect(state.kind).toBe("error");
    if (state.kind === "error") {
      expect(state.error.retryable).toBe(true);
    }
  });
});
