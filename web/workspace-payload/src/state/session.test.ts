import { describe, expect, it } from "vitest";
import { bytesToBase64 } from "../core/base64";
import { FRAME_FRESHNESS_TTL_MS, isConnectionFresh } from "../core/types";
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

/** Await bootstrap settling; key import is async, so one macrotask may not do. */
async function settle(store: ReturnType<typeof createWorkspaceStore>): Promise<void> {
  for (let i = 0; i < 20 && store.state().kind === "loading"; i += 1) await flush();
}

const KEY_B64 = bytesToBase64(new Uint8Array(32).fill(5));
const hostKeyProvider = async () => ({
  kid: "kid-1",
  c2sKeyB64: KEY_B64,
  s2cKeyB64: KEY_B64,
});

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

  it("keeps the selected instrument memory-only and resets it on reload", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession(BASE_PAYLOAD),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();
    expect(store.selectedInstrument()).toBeNull();

    const ref = { chain: "base", address: "0xtoken", symbol: "TKN" };
    store.setSelectedInstrument(ref);
    expect(store.selectedInstrument()).toEqual(ref);

    // A new private session must not inherit the previous target.
    store.reload();
    await flush();
    expect(store.selectedInstrument()).toBeNull();
  });

  it("allows a mutation only when capability, trading gate, kill switch and live state agree", async () => {
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
    // The deployment advertises realtime, so capital-committing mutations also
    // require the authoritative state feed to be live (circuit breaker).
    store.setConnection({
      phase: "live",
      lastFrameAtMs: 1_000,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
    expect(store.mutationDenial("execute")).toBeNull();
  });

  it("halts a capital-committing mutation when the phase is live but frames are stale", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        capabilities: { market: true, realtime: true, execute: true, limits: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
      }),
      manualClock: true,
      clock: () => 10_000,
    });
    store.reload();
    await flush();
    // Phase is latched `live` (a half-open socket never flips it), so only the
    // frame age can fail the circuit breaker closed.
    store.setConnection({
      phase: "live",
      lastFrameAtMs: 10_000 - FRAME_FRESHNESS_TTL_MS - 1,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
    const denial = store.mutationDenial("execute");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/stale/i);
  });

  it("halts capital-committing mutations while the realtime state is not live", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        capabilities: { market: true, realtime: true, execute: true, limits: true, withdraw: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
      }),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();
    store.setConnection({
      phase: "reconnecting",
      lastFrameAtMs: null,
      attempt: 1,
      nextRetryAtMs: 2_000,
      reason: "socket closed",
    });
    const denial = store.mutationDenial("limits");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/reconnecting|halted/i);
    // Web-only withdrawal is not a market-freshness mutation and stays governed
    // by capability/trading-gate/expiry alone.
    expect(store.mutationDenial("withdraw")).toBeNull();
  });

  it("halts capital-committing mutations when the realtime capability is withheld", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        // A relay can clear this one unauthenticated bootstrap bit while keeping
        // the capital capabilities; that must not switch the breaker off.
        capabilities: { market: true, realtime: false, execute: true, limits: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
      }),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();
    store.setConnection({
      phase: "live",
      lastFrameAtMs: 1_000,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
    const denial = store.mutationDenial("execute");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/realtime/i);
  });

  it("fails a mutation closed once the session authorization has expired", async () => {
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        session: { key_id: "kid-1", expires_at_ms: 500 },
      }),
      manualClock: true,
      clock: () => 1_000,
    });
    store.reload();
    await flush();
    const denial = store.mutationDenial("execute");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/expired/i);
  });

  it("maps a missing backend contract to unavailable, not a fabricated ready state", async () => {
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      baseUrl: "https://workspace.example",
      fetchFn: (async () => ({ ok: false, status: 404 })) as unknown as typeof fetch,
      hostKeyProvider,
    });
    store.reload();
    await settle(store);
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
      hostKeyProvider,
    });
    store.reload();
    await settle(store);
    const state = store.state();
    expect(state.kind).toBe("error");
    if (state.kind === "error") {
      expect(state.error.retryable).toBe(true);
    }
  });

  it("anchors session expiry to the server clock, not a skewed local clock", async () => {
    let now = 1_000;
    const store = createWorkspaceStore({
      session: parseWorkspaceSession({
        ...BASE_PAYLOAD,
        capabilities: { execute: true, realtime: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        session: { key_id: "kid-1", expires_at_ms: 100_500 },
        server_time_ms: 100_000,
      }),
      manualClock: true,
      clock: () => now,
    });
    store.reload();
    await flush();
    // A live, fresh feed isolates the expiry clock from the circuit breaker.
    store.setConnection({
      phase: "live",
      lastFrameAtMs: 1_000,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
    // serverNow = local(1_000) + skew(99_000) = 100_000 < 100_500.
    expect(store.mutationDenial("execute")).toBeNull();
    // 500ms of *server* time passes while the local clock stays far behind; a
    // naive local comparison would never expire this session.
    now = 1_500;
    const denial = store.mutationDenial("execute");
    expect(denial).not.toBeNull();
    expect(denial?.reason).toMatch(/expired/i);
  });

  it("treats a negative frame age (lagging decide clock) as stale, not fresh", () => {
    const status = {
      phase: "live" as const,
      lastFrameAtMs: 10_000,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    };
    expect(isConnectionFresh(status, 10_000)).toBe(true);
    expect(isConnectionFresh(status, 10_000 + FRAME_FRESHNESS_TTL_MS)).toBe(true);
    expect(isConnectionFresh(status, 10_000 + FRAME_FRESHNESS_TTL_MS + 1)).toBe(false);
    // The decision clock lagged the frame clock: fail closed.
    expect(isConnectionFresh(status, 9_000)).toBe(false);
  });
});
