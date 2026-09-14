import { describe, expect, it, vi } from "vitest";
import { bootstrapWorkspaceSession, parseWorkspaceSession } from "./bootstrap";
import type { CapabilityKey } from "../core/types";

const VALID = {
  protocol_version: 1,
  capabilities: { market: true, realtime: true, execute: false },
  trading_enabled: false,
  kill_switch: { enabled: true, reason: "foundation" },
  chains: [{ id: "base", display: "Base", enabled: true }],
  session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
  server_time_ms: 1_699_999_000_000,
};

describe("parseWorkspaceSession", () => {
  it("parses a valid bootstrap payload and fills missing capabilities false", () => {
    const session = parseWorkspaceSession(VALID);
    expect(session.protocolVersion).toBe(1);
    expect(session.capabilities.market).toBe(true);
    expect(session.capabilities.realtime).toBe(true);
    expect(session.capabilities.execute).toBe(false);
    expect(session.capabilities.withdraw).toBe(false);
    expect(Object.keys(session.capabilities)).toContain("rfq");
    expect(session.tradingEnabled).toBe(false);
    expect(session.killSwitch).toEqual({ enabled: true, reason: "foundation" });
    expect(session.chains).toEqual([{ id: "base", display: "Base", enabled: true }]);
  });

  it("fails closed on a wrong protocol version", () => {
    expect(() => parseWorkspaceSession({ ...VALID, protocol_version: 2 })).toThrowError(/protocol/i);
  });

  it("fails closed on a missing session block", () => {
    const { session: _drop, ...rest } = VALID;
    expect(() => parseWorkspaceSession(rest)).toThrowError(/session/i);
  });

  it("fails closed on a missing server time anchor", () => {
    const { server_time_ms: _drop, ...rest } = VALID;
    expect(() => parseWorkspaceSession(rest)).toThrowError(/server time/i);
  });

  it("fails closed on non-object input", () => {
    expect(() => parseWorkspaceSession(null)).toThrowError();
    expect(() => parseWorkspaceSession([1, 2, 3])).toThrowError();
  });

  it("defaults the kill switch to engaged when malformed", () => {
    const session = parseWorkspaceSession({ ...VALID, kill_switch: "nope" });
    expect(session.killSwitch.enabled).toBe(true);
  });

  it("does not enable a capability that is not explicitly true", () => {
    const session = parseWorkspaceSession({
      ...VALID,
      capabilities: { market: "yes", realtime: 1, execute: true },
    });
    expect(session.capabilities.market).toBe(false);
    expect(session.capabilities.realtime).toBe(false);
    expect(session.capabilities.execute).toBe(true);
  });
});

describe("bootstrapWorkspaceSession", () => {
  it("returns an injected session without network access", async () => {
    const fetchFn = vi.fn();
    const session = await bootstrapWorkspaceSession({
      session: parseWorkspaceSession(VALID),
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    expect(session.capabilities.market).toBe(true);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("maps 404 to a non-retryable capability_missing failure", async () => {
    const fetchFn = vi.fn(async () => ({ ok: false, status: 404 }) as Response);
    await expect(
      bootstrapWorkspaceSession({ baseUrl: "https://workspace.example", fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: "capability_missing", retryable: false });
  });

  it("maps 401 to a non-retryable auth failure", async () => {
    const fetchFn = vi.fn(async () => ({ ok: false, status: 401 }) as Response);
    await expect(
      bootstrapWorkspaceSession({ baseUrl: "https://workspace.example", fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: "auth", retryable: false });
  });

  it("maps a thrown fetch to a retryable network failure", async () => {
    const fetchFn = vi.fn(async () => {
      throw new TypeError("failed to fetch");
    });
    await expect(
      bootstrapWorkspaceSession({ baseUrl: "https://workspace.example", fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: "network", retryable: true });
  });

  it("fails closed on malformed JSON", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error("bad json");
      },
    }));
    await expect(
      bootstrapWorkspaceSession({ baseUrl: "https://workspace.example", fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("does not contact a non-neutral path for a provider-shaped response", async () => {
    const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toContain("/v1/bootstrap");
      return { ok: true, status: 200, json: async () => VALID } as Response;
    });
    const session = await bootstrapWorkspaceSession({
      baseUrl: "https://workspace.example",
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const caps: CapabilityKey[] = ["market", "execute"];
    expect(session.capabilities[caps[0]]).toBe(true);
  });
});
