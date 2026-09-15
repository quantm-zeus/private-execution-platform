import { describe, expect, it } from "vitest";
import { bytesToBase64, utf8Encode } from "../core/base64";
import { WebCryptoDecryptor } from "../realtime/decryptor";
import { validateEnvelope } from "../realtime/envelope";
import { WebCryptoSealer } from "../realtime/sealer";
import { EncryptedCommandClient } from "./command";

const KID = "kid-1";
const rawKey = new Uint8Array(32).map((_, index) => (index + 1) & 0xff);

interface EnvelopeBody {
  readonly kid: string;
  readonly nonce: string;
  readonly sequence: number;
  readonly ciphertext: string;
}

/** Tests seal both directions with the same raw key, so the request is readable. */
async function readRequest(body: EnvelopeBody): Promise<Record<string, unknown>> {
  const decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, KID);
  const plain = await decryptor.decrypt(body as never);
  try {
    return JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
  } finally {
    plain.fill(0);
  }
}

async function sealResponse(
  sealer: WebCryptoSealer,
  sequence: number,
  body: unknown,
): Promise<EnvelopeBody> {
  const sealed = await sealer.seal(
    { kid: KID, sequence },
    utf8Encode(JSON.stringify(body)),
  );
  return { kid: KID, sequence, nonce: sealed.nonce, ciphertext: sealed.ciphertext };
}

async function buildClient(fetchFn: typeof fetch) {
  const sealer = await WebCryptoSealer.fromRawKey(rawKey);
  const decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, KID);
  return new EncryptedCommandClient({
    sealer,
    decryptor,
    kid: KID,
    baseUrl: "https://workspace.example",
    fetchFn,
  });
}

/** A responder that echoes the request challenge and wraps `result`. */
function responder(result: unknown, respondAt?: (body: EnvelopeBody) => number) {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body)) as EnvelopeBody;
    const request = await readRequest(body);
    const sealer = await WebCryptoSealer.fromRawKey(rawKey);
    const envelope = await sealResponse(
      sealer,
      respondAt ? respondAt(body) : body.sequence,
      { request_id: request.request_id, result },
    );
    return { ok: true, status: 200, json: async () => envelope } as Response;
  }) as unknown as typeof fetch;
}

describe("EncryptedCommandClient", () => {
  it("posts only generic envelope fields and decrypts the response", async () => {
    const requestDecryptor = await WebCryptoDecryptor.fromRawKey(rawKey, KID);
    let captured: { url: string; init: RequestInit } | null = null;
    const fetchFn = (async (url: string, init: RequestInit) => {
      captured = { url, init };
      const body = JSON.parse(String(init.body)) as EnvelopeBody;
      expect(body.kid).toBe(KID);
      // No operation type or payload may appear in cleartext.
      expect(String(init.body)).not.toContain("get_quote");
      expect(String(init.body)).not.toContain("secret-value");
      const request = JSON.parse(
        new TextDecoder().decode(await requestDecryptor.decrypt(body as never)),
      ) as { request_id: string };
      const sealer = await WebCryptoSealer.fromRawKey(rawKey);
      const envelope = await sealResponse(sealer, body.sequence, {
        request_id: request.request_id,
        result: { ok: true },
      });
      return { ok: true, status: 200, json: async () => envelope } as Response;
    }) as unknown as typeof fetch;

    const client = await buildClient(fetchFn);
    const result = await client.send<{ ok: boolean }>("get_quote", { secret: "secret-value" });
    expect(result).toEqual({ ok: true });
    expect(captured).not.toBeNull();
    expect(captured!.url).toBe("https://workspace.example/v1/command");
    expect(captured!.init.method).toBe("POST");
    expect(captured!.init.credentials).toBe("same-origin");
  });

  it("maps 401 to a non-retryable auth error for a read", async () => {
    const fetchFn = (async () => ({ ok: false, status: 401 })) as unknown as typeof fetch;
    const client = await buildClient(fetchFn);
    await expect(client.send("get_portfolio", {})).rejects.toMatchObject({
      code: "auth",
      retryable: false,
    });
  });

  it("maps 501 to capability_missing and 409 to retryable freshness for reads", async () => {
    const missing = (async () => ({ ok: false, status: 501 })) as unknown as typeof fetch;
    await expect((await buildClient(missing)).send("get_quote", {})).rejects.toMatchObject({
      code: "capability_missing",
    });
    const conflict = (async () => ({ ok: false, status: 409 })) as unknown as typeof fetch;
    await expect((await buildClient(conflict)).send("get_quote", {})).rejects.toMatchObject({
      code: "freshness",
      retryable: true,
    });
  });

  it("treats a status-only failure on a write as indeterminate", async () => {
    // A relay can forge the status line; it must not prove the write did not
    // commit, or the caller would rotate its idempotency key and double-submit.
    // Every capital-committing op must be in WRITE_OPS — including the
    // security-policy write, which is otherwise only exercised through a fake
    // CommandClient in component tests.
    for (const status of [401, 400, 404, 409]) {
      const fetchFn = (async () => ({ ok: false, status })) as unknown as typeof fetch;
      await expect(
        (await buildClient(fetchFn)).send("execute_market_order", {}),
      ).rejects.toMatchObject({ code: "unknown", retryable: true });
      await expect(
        (await buildClient(fetchFn)).send("set_wallet_limits", {}),
      ).rejects.toMatchObject({ code: "unknown", retryable: true });
    }
  });

  it("classifies a rejection carried inside the authenticated envelope", async () => {
    const fetchFn = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as EnvelopeBody;
      const request = await readRequest(body);
      const sealer = await WebCryptoSealer.fromRawKey(rawKey);
      const envelope = await sealResponse(sealer, body.sequence, {
        request_id: request.request_id,
        error: { code: "freshness", message: "state moved", retryable: true },
      });
      return { ok: false, status: 409, json: async () => envelope } as Response;
    }) as unknown as typeof fetch;
    await expect(
      (await buildClient(fetchFn)).send("execute_market_order", {}),
    ).rejects.toMatchObject({ code: "freshness", retryable: true });
  });

  it("keeps a write indeterminate when an authenticated error omits the retryable flag", async () => {
    // A 5xx body missing `retryable` must not be read as a determinate rejection:
    // callers rotate their idempotency key on a determinate rejection, so the
    // absent flag would let a possibly-committed write be re-submitted.
    const writeFailure = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as EnvelopeBody;
      const request = await readRequest(body);
      const sealer = await WebCryptoSealer.fromRawKey(rawKey);
      const envelope = await sealResponse(sealer, body.sequence, {
        request_id: request.request_id,
        error: { code: "server", message: "upstream failed" },
      });
      return { ok: false, status: 500, json: async () => envelope } as Response;
    }) as unknown as typeof fetch;
    await expect(
      (await buildClient(writeFailure)).send("execute_market_order", {}),
    ).rejects.toMatchObject({ code: "server", retryable: true });
    // A read is not capital-committing, so the same body stays determinate.
    await expect(
      (await buildClient(writeFailure)).send("get_quote", {}),
    ).rejects.toMatchObject({ code: "server", retryable: false });
  });

  it("does not honor an authenticated error that is not bound to the request", async () => {
    // Stream frames and command responses share the s2c key and AAD (BR-3 asks
    // the backend to domain-separate them). Until then, a captured envelope whose
    // cleartext sequence matches — e.g. a stream frame carrying a top-level
    // `error`, or a replayed response after the per-instance sequence restarts at
    // 0 — must not be accepted as a determinate rejection: the caller would
    // rotate its idempotency key and double-submit a possibly-committed write.
    const respondWith = (echo: (requestId: string) => unknown) =>
      (async (_url: string, init: RequestInit) => {
        const body = JSON.parse(String(init.body)) as EnvelopeBody;
        const request = await readRequest(body);
        const sealer = await WebCryptoSealer.fromRawKey(rawKey);
        const envelope = await sealResponse(sealer, body.sequence, {
          request_id: echo(String(request.request_id)),
          error: { code: "auth", message: "forged rejection", retryable: false },
        });
        return { ok: false, status: 401, json: async () => envelope } as Response;
      }) as unknown as typeof fetch;

    // No request_id at all (a stream-frame shape).
    await expect(
      (await buildClient(respondWith(() => undefined))).send("execute_market_order", {}),
    ).rejects.toMatchObject({ code: "unknown", retryable: true });
    // A different request_id (a replayed older response).
    await expect(
      (await buildClient(respondWith(() => "some-other-request"))).send("execute_market_order", {}),
    ).rejects.toMatchObject({ code: "unknown", retryable: true });
  });

  it("rejects a response that is not bound to the request", async () => {
    // A captured stream frame (or an older command response) at the right
    // cleartext sequence must not be accepted as the answer to this request.
    const fetchFn = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as EnvelopeBody;
      const sealer = await WebCryptoSealer.fromRawKey(rawKey);
      const envelope = await sealResponse(sealer, body.sequence, {
        op: "delta",
        channel: "orders",
        priority: 0,
        seq: body.sequence,
        payload: { forged: true },
      });
      return { ok: true, status: 200, json: async () => envelope } as Response;
    }) as unknown as typeof fetch;
    await expect(
      (await buildClient(fetchFn)).send("execute_market_order", {}),
    ).rejects.toMatchObject({ code: "protocol" });
  });

  it("fails closed on a malformed response envelope", async () => {
    const fetchFn = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({ result: "not an envelope" }),
    })) as unknown as typeof fetch;
    await expect((await buildClient(fetchFn)).send("get_quote", {})).rejects.toMatchObject({
      code: "protocol",
    });
  });

  it("does not reuse a nonce/sequence across commands", async () => {
    const sealer = await WebCryptoSealer.fromRawKey(rawKey);
    const sequences: number[] = [];
    const nonces: string[] = [];
    const fetchFn = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as EnvelopeBody;
      sequences.push(body.sequence);
      nonces.push(body.nonce);
      const request = await readRequest(body);
      const envelope = await sealResponse(sealer, body.sequence, {
        request_id: request.request_id,
        result: null,
      });
      return { ok: true, status: 200, json: async () => envelope } as Response;
    }) as unknown as typeof fetch;
    const client = await buildClient(fetchFn);
    await client.send("get_quote", {});
    await client.send("get_quote", {});
    expect(sequences).toEqual([0, 1]);
    expect(new Set(nonces).size).toBe(2);
  });
});

describe("cleartext envelope boundary", () => {
  it("strips any extra/private fields to the generic four and rejects a malformed nonce", () => {
    const generic = {
      kid: "kid-1",
      nonce: bytesToBase64(new Uint8Array(12)),
      sequence: 1,
      ciphertext: bytesToBase64(new Uint8Array(20)),
    };
    expect(validateEnvelope({ ...generic, op: "get_quote", amount: "100" })).toEqual(generic);
    expect(() => validateEnvelope({ ...generic, nonce: "not-base64!" })).toThrowError();
  });

  it("rejects a replayed response whose sequence does not match the request", async () => {
    const client = await buildClient(responder({ ok: true }, (body) => body.sequence + 5));
    await expect(client.send("get_quote", {})).rejects.toMatchObject({ code: "protocol" });
  });

  it("rejects an oversized response envelope", async () => {
    const fetchFn = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        kid: KID,
        sequence: 0,
        nonce: bytesToBase64(new Uint8Array(12)),
        ciphertext: bytesToBase64(new Uint8Array(1024 * 1024 + 1)),
      }),
    })) as unknown as typeof fetch;
    const client = await buildClient(fetchFn);
    await expect(client.send("get_quote", {})).rejects.toMatchObject({ code: "protocol" });
  });
});
