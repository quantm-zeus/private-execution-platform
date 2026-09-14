import { describe, expect, it } from "vitest";
import { utf8Encode } from "../core/base64";
import type { StreamEnvelope } from "../realtime/types";
import { WebCryptoDecryptor } from "../realtime/decryptor";
import { WebCryptoSealer } from "../realtime/sealer";
import { EncryptedCommandClient } from "./command";

const KID = "kid-1";
const rawKey = new Uint8Array(32).map((_, index) => (index + 1) & 0xff);

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

describe("EncryptedCommandClient", () => {
  it("posts only generic envelope fields and decrypts the response", async () => {
    const sealer = await WebCryptoSealer.fromRawKey(rawKey);
    let captured: { url: string; init: RequestInit } | null = null;
    const fetchFn = (async (url: string, init: RequestInit) => {
      captured = { url, init };
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      expect(body.kid).toBe(KID);
      // No operation type or payload may appear in cleartext.
      expect(String(init.body)).not.toContain("get_quote");
      expect(String(init.body)).not.toContain("secret-value");
      const sealed = await sealer.seal(
        { kid: KID, sequence: body.sequence as number },
        utf8Encode(JSON.stringify({ result: { ok: true } })),
      );
      return {
        ok: true,
        status: 200,
        json: async () => ({
          kid: KID,
          sequence: body.sequence,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
        }),
      } as Response;
    }) as unknown as typeof fetch;

    const client = await buildClient(fetchFn);
    const result = await client.send<{ ok: boolean }>("get_quote", { secret: "secret-value" });
    expect(result).toEqual({ ok: true });
    expect(captured).not.toBeNull();
    expect(captured!.url).toBe("https://workspace.example/v1/command");
    expect(captured!.init.method).toBe("POST");
    expect(captured!.init.credentials).toBe("same-origin");
  });

  it("maps 401 to a non-retryable auth error", async () => {
    const fetchFn = (async () => ({ ok: false, status: 401 })) as unknown as typeof fetch;
    const client = await buildClient(fetchFn);
    await expect(client.send("get_portfolio", {})).rejects.toMatchObject({
      code: "auth",
      retryable: false,
    });
  });

  it("maps 501 to capability_missing and 409 to retryable freshness", async () => {
    const missing = (async () => ({ ok: false, status: 501 })) as unknown as typeof fetch;
    await expect((await buildClient(missing)).send("get_quote", {})).rejects.toMatchObject({
      code: "capability_missing",
    });
    const conflict = (async () => ({ ok: false, status: 409 })) as unknown as typeof fetch;
    await expect((await buildClient(conflict)).send("execute_market_order", {})).rejects.toMatchObject({
      code: "freshness",
      retryable: true,
    });
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
      const body = JSON.parse(String(init.body)) as { sequence: number; nonce: string };
      sequences.push(body.sequence);
      nonces.push(body.nonce);
      const sealed = await sealer.seal(
        { kid: KID, sequence: body.sequence },
        utf8Encode(JSON.stringify({ result: null })),
      );
      return {
        ok: true,
        status: 200,
        json: async () => ({
          kid: KID,
          sequence: body.sequence,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
        }),
      } as Response;
    }) as unknown as typeof fetch;
    const client = await buildClient(fetchFn);
    await client.send("get_quote", {});
    await client.send("get_quote", {});
    expect(sequences).toEqual([0, 1]);
    expect(new Set(nonces).size).toBe(2);
  });
});

describe("StreamEnvelope shape", () => {
  it("exposes only generic fields", () => {
    const envelope: StreamEnvelope = {
      kid: "k",
      nonce: "n",
      sequence: 1,
      ciphertext: "c",
    };
    expect(Object.keys(envelope).sort()).toEqual(["ciphertext", "kid", "nonce", "sequence"]);
  });
});
