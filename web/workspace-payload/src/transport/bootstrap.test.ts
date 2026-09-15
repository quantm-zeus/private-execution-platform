import { describe, expect, it, vi } from "vitest";
import { bytesToBase64, utf8Encode } from "../core/base64";
import type { CapabilityKey } from "../core/types";
import { WebCryptoDecryptor } from "../realtime/decryptor";
import { sealerFromBase64 } from "../realtime/sealer";
import { bootstrapWorkspaceSession, parseWorkspaceSession } from "./bootstrap";

const VALID = {
  protocol_version: 1,
  capabilities: { market: true, realtime: true, execute: false },
  trading_enabled: false,
  kill_switch: { enabled: true, reason: "foundation" },
  chains: [{ id: "base", display: "Base", enabled: true }],
  session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
  server_time_ms: 1_699_999_000_000,
};

const KID = "kid-1";
const rawC2s = new Uint8Array(32).fill(0x11);
const rawS2c = new Uint8Array(32).fill(0x22);
const C2S_B64 = bytesToBase64(rawC2s);
const S2C_B64 = bytesToBase64(rawS2c);

interface EnvelopeBody {
  readonly kid: string;
  readonly nonce: string;
  readonly sequence: number;
  readonly ciphertext: string;
}

function hostKeys() {
  return async () => ({ kid: KID, c2sKeyB64: C2S_B64, s2cKeyB64: S2C_B64 });
}

/** Assert the request is an octet-stream generic envelope and decode it. */
function decodeRequest(init: RequestInit): EnvelopeBody {
  expect(init.headers).toMatchObject({ "Content-Type": "application/octet-stream" });
  expect(init.body).toBeDefined();
  expect(ArrayBuffer.isView(init.body)).toBe(true);
  const bytes = init.body as Uint8Array;
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as EnvelopeBody;
}

async function openRequest(body: EnvelopeBody): Promise<Record<string, unknown>> {
  const decryptor = await WebCryptoDecryptor.fromRawKey(rawC2s, KID);
  const plain = await decryptor.decrypt(body as never);
  try {
    return JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
  } finally {
    plain.fill(0);
  }
}

async function sealResponse(sequence: number, body: unknown): Promise<EnvelopeBody> {
  const sealer = await sealerFromBase64(S2C_B64);
  const sealed = await sealer.seal({ kid: KID, sequence }, utf8Encode(JSON.stringify(body)));
  return { kid: KID, sequence, nonce: sealed.nonce, ciphertext: sealed.ciphertext };
}

/** Fake fetch that opens the request envelope and seals a bound response. */
function responder(
  body: Record<string, unknown>,
  options: { status?: number; sequenceOffset?: number; echoRequestId?: boolean } = {},
): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const envelope = decodeRequest(init);
    const request = await openRequest(envelope);
    const sequence = envelope.sequence + (options.sequenceOffset ?? 0);
    const responseBody =
      options.echoRequestId === false
        ? { ...body }
        : { request_id: request.request_id, ...body };
    const sealed = await sealResponse(sequence, responseBody);
    const status = options.status ?? 200;
    return {
      ok: status < 400,
      status,
      text: async () => JSON.stringify(sealed),
    } as Response;
  }) as unknown as typeof fetch;
}

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
    expect(session.chains).toEqual([
      { id: "base", display: "Base", enabled: true, nativeToken: null },
    ]);
  });

  it("parses an advertised chain native/quote token and defaults it to null", () => {
    const session = parseWorkspaceSession({
      ...VALID,
      chains: [
        { id: "base", display: "Base", enabled: true, native_token: "0xusdc" },
        { id: "eth", display: "Ethereum", enabled: false },
        { id: "sol", display: "Solana", enabled: true, native_token: "" },
        { id: "arb", display: "Arbitrum", enabled: true, native_token: 42 },
      ],
    });
    expect(session.chains.map((chain) => chain.nativeToken)).toEqual([
      "0xusdc",
      null,
      null,
      null,
    ]);
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

  it("fails closed on an oversized chain list", () => {
    const chains = Array.from({ length: 300 }, (_, index) => ({ id: `chain-${index}`, enabled: true }));
    expect(() => parseWorkspaceSession({ ...VALID, chains })).toThrowError(/size limit/i);
  });

  it("defaults the kill switch to engaged when malformed", () => {
    const session = parseWorkspaceSession({ ...VALID, kill_switch: "nope" });
    expect(session.killSwitch.enabled).toBe(true);
  });

  it("fails the kill switch closed on an object without a boolean enabled flag", () => {
    for (const kill_switch of [{}, { reason: "halted" }, { enabled: "true" }, { enabled: 1 }]) {
      const session = parseWorkspaceSession({ ...VALID, kill_switch });
      expect(session.killSwitch.enabled).toBe(true);
    }
    // Only an explicit boolean may clear the halt.
    expect(parseWorkspaceSession({ ...VALID, kill_switch: { enabled: false } }).killSwitch.enabled).toBe(
      false,
    );
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

  it("fails closed with a typed error when no host key is available", async () => {
    const fetchFn = vi.fn();
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: async () => null,
      }),
    ).rejects.toMatchObject({ code: "capability_missing", retryable: false });
    // No key: the opaque request must never be replaced by a cleartext probe.
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("fails closed when no key source is configured at all", async () => {
    const fetchFn = vi.fn();
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: "capability_missing" });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("seals an octet-stream envelope request and decrypts the bound response", async () => {
    let captured: RequestInit | null = null;
    const fetchFn = (async (_url: string, init: RequestInit) => {
      captured = init;
      const envelope = decodeRequest(init);
      expect(envelope.kid).toBe(KID);
      expect(envelope.sequence).toBe(0);
      // No cleartext operation type or payload anywhere on the wire.
      const wire = JSON.stringify(envelope);
      expect(wire).not.toContain("bootstrap");
      expect(wire).not.toContain("protocol_version");
      expect(Object.keys(envelope).sort()).toEqual(["ciphertext", "kid", "nonce", "sequence"]);
      const request = await openRequest(envelope);
      expect(request).toMatchObject({ op: "bootstrap", protocol_version: 1 });
      expect(typeof request.request_id).toBe("string");
      const sealed = await sealResponse(0, { ...VALID, request_id: request.request_id });
      return { ok: true, status: 200, text: async () => JSON.stringify(sealed) } as Response;
    }) as unknown as typeof fetch;

    const session = await bootstrapWorkspaceSession({
      baseUrl: "https://workspace.example",
      fetchFn,
      hostKeyProvider: hostKeys(),
    });
    expect(captured).not.toBeNull();
    expect(session.capabilities.market).toBe(true);
    expect(session.capabilities.realtime).toBe(true);
    expect(session.keyId).toBe("kid-1");
  });

  it("seals bootstrap at the supplied sequence so a retry cannot replay 0", async () => {
    // The server's replay window never resets for a `kid`, so a reload/retry must
    // advance the bootstrap sequence; the response must bind that same sequence.
    const fetchFn = (async (_url: string, init: RequestInit) => {
      const envelope = decodeRequest(init);
      expect(envelope.sequence).toBe(7);
      const request = await openRequest(envelope);
      const sealed = await sealResponse(7, { ...VALID, request_id: request.request_id });
      return { ok: true, status: 200, text: async () => JSON.stringify(sealed) } as Response;
    }) as unknown as typeof fetch;
    const session = await bootstrapWorkspaceSession({
      baseUrl: "https://workspace.example",
      fetchFn,
      hostKeyProvider: hostKeys(),
      sequence: 7,
    });
    expect(session.keyId).toBe("kid-1");
  });

  it("accepts a wrapped {envelope} response for compatibility", async () => {
    const fetchFn = (async (_url: string, init: RequestInit) => {
      const envelope = decodeRequest(init);
      const request = await openRequest(envelope);
      const sealed = await sealResponse(0, { ...VALID, request_id: request.request_id });
      return { ok: true, status: 200, text: async () => JSON.stringify({ envelope: sealed }) } as Response;
    }) as unknown as typeof fetch;
    const session = await bootstrapWorkspaceSession({
      baseUrl: "https://workspace.example",
      fetchFn,
      hostKeyProvider: hostKeys(),
    });
    expect(session.capabilities.market).toBe(true);
  });

  it("rejects a response whose sequence does not match the request", async () => {
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: responder(VALID, { sequenceOffset: 5 }),
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("rejects a response that is not bound to the request id", async () => {
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: responder(VALID, { echoRequestId: false }),
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("maps 404 to a non-retryable capability_missing failure", async () => {
    const fetchFn = vi.fn(async () => ({ ok: false, status: 404 }) as Response);
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "capability_missing", retryable: false });
  });

  it("maps 401 to a non-retryable auth failure", async () => {
    const fetchFn = vi.fn(async () => ({ ok: false, status: 401 }) as Response);
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "auth", retryable: false });
  });

  it("maps a thrown fetch to a retryable network failure", async () => {
    const fetchFn = vi.fn(async () => {
      throw new TypeError("failed to fetch");
    });
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "network", retryable: true });
  });

  it("fails closed on a malformed response body", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "not json",
    }));
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("fails closed on a response that is not a valid envelope", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ result: "not an envelope" }),
    }));
    await expect(
      bootstrapWorkspaceSession({
        baseUrl: "https://workspace.example",
        fetchFn: fetchFn as unknown as typeof fetch,
        hostKeyProvider: hostKeys(),
      }),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("uses the neutral bootstrap path and no cleartext request", async () => {
    const fetchFn = vi.fn(async (input: RequestInfo | URL, init: RequestInit) => {
      expect(String(input)).toContain("/v1/bootstrap");
      const envelope = decodeRequest(init);
      const request = await openRequest(envelope);
      const sealed = await sealResponse(0, { ...VALID, request_id: request.request_id });
      return { ok: true, status: 200, text: async () => JSON.stringify(sealed) } as Response;
    });
    const session = await bootstrapWorkspaceSession({
      baseUrl: "https://workspace.example",
      fetchFn: fetchFn as unknown as typeof fetch,
      hostKeyProvider: hostKeys(),
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const caps: CapabilityKey[] = ["market", "execute"];
    expect(session.capabilities[caps[0]]).toBe(true);
  });
});
