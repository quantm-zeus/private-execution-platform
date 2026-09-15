// @vitest-environment node
//
// Focused unit test for the realtime Worker module. The worker owns the socket
// and the only in-memory session key, so it is the highest-value place to assert
// the wire-size ceiling, the "never send a cleartext control frame" invariant and
// the stop fence. It is exercised here with a fake `self`/`WebSocket` because a
// DedicatedWorkerGlobalScope is not available under jsdom.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebCryptoDecryptor } from "./decryptor";

interface WorkerContext {
  postMessage: ReturnType<typeof vi.fn>;
  onmessage: ((event: { data: unknown }) => void) | null;
}

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  binaryType = "blob";
  readonly sent: unknown[] = [];

  constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  send(data: unknown): void {
    this.sent.push(data);
  }

  close(): void {
    // no-op fake
  }
}

let context: WorkerContext;

function keyB64(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = i + 1;
  return Buffer.from(bytes).toString("base64");
}

async function startWorker(c2sKeyB64?: string): Promise<void> {
  context.onmessage?.({
    data: {
      type: "start",
      url: "ws://localhost/v1/stream",
      baseUrl: "http://localhost",
      kid: "kid-test",
      keyB64: keyB64(),
      ...(c2sKeyB64 ? { c2sKeyB64 } : {}),
    },
  });
  await vi.waitFor(() => {
    expect(context.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: "ready" }));
  });
}

function latestSocket(): FakeWebSocket {
  const socket = FakeWebSocket.instances.at(-1);
  if (!socket) throw new Error("worker never opened a socket");
  return socket;
}

beforeEach(async () => {
  vi.resetModules();
  FakeWebSocket.instances = [];
  context = { postMessage: vi.fn(), onmessage: null };
  (globalThis as { self?: unknown }).self = context;
  (globalThis as { WebSocket?: unknown }).WebSocket = FakeWebSocket;
  await import("./worker");
});

afterEach(() => {
  context.onmessage?.({ data: { type: "stop" } });
  delete (globalThis as { self?: unknown }).self;
  delete (globalThis as { WebSocket?: unknown }).WebSocket;
});

describe("realtime worker", () => {
  it("starts, opens the neutral stream socket and never sends a cleartext frame", async () => {
    await startWorker();
    const socket = latestSocket();
    expect(socket.url).toBe("ws://localhost/v1/stream");
    socket.onopen?.();
    // The worker resyncs over POST /v1/sync; it must never write to the
    // binary-only relay (the opaque edge closes on any client frame).
    expect(socket.sent).toHaveLength(0);
  });

  it("rejects an over-limit wire frame before decoding, with no send", async () => {
    await startWorker();
    const socket = latestSocket();
    const oversized = "x".repeat(2 * 1024 * 1024 + 1);
    expect(() => socket.onmessage?.({ data: oversized })).not.toThrow();
    expect(context.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "error",
        error: expect.objectContaining({ code: "protocol" }),
      }),
    );
    expect(socket.sent).toHaveLength(0);
  });

  it("accepts an in-limit binary frame and drops in-flight work after stop", async () => {
    await startWorker();
    const socket = latestSocket();
    const frame = new TextEncoder().encode(
      JSON.stringify({ kid: "kid-test", sequence: 1, nonce: "AA==", ciphertext: "AA==" }),
    );
    expect(() => socket.onmessage?.({ data: frame.buffer })).not.toThrow();
    // Stop fences the worker: a late frame must not be processed after teardown.
    context.onmessage?.({ data: { type: "stop" } });
    expect(() => socket.onmessage?.({ data: frame.buffer })).not.toThrow();
    expect(socket.sent).toHaveLength(0);
  });

  it("seals the resync as an octet-stream envelope when a c2s key is present", async () => {
    const c2sB64 = keyB64();
    const calls: { url: string; init: RequestInit }[] = [];
    const originalFetch = (globalThis as { fetch?: unknown }).fetch;
    (globalThis as { fetch?: unknown }).fetch = async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return { ok: true, status: 200 } as Response;
    };
    try {
      await startWorker(c2sB64);
      const socket = latestSocket();
      socket.onopen?.();
      await vi.waitFor(() => expect(calls).toHaveLength(1));
      const call = calls[0]!;
      expect(call.url).toContain("/v1/sync");
      expect(call.init.headers).toMatchObject({ "Content-Type": "application/octet-stream" });
      const bytes = call.init.body as Uint8Array;
      expect(bytes).toBeDefined();
      expect(ArrayBuffer.isView(bytes)).toBe(true);
      const wire = new TextDecoder().decode(bytes);
      // No cleartext control semantics on the wire.
      expect(wire).not.toContain("sync");
      expect(wire).not.toContain("from_seq");
      const envelope = JSON.parse(wire) as {
        kid: string;
        nonce: string;
        sequence: number;
        ciphertext: string;
      };
      expect(Object.keys(envelope).sort()).toEqual(["ciphertext", "kid", "nonce", "sequence"]);
      expect(envelope.sequence).toBe(0);
      const decryptor = await WebCryptoDecryptor.fromRawKey(
        Buffer.from(c2sB64, "base64"),
        "kid-test",
      );
      const plain = await decryptor.decrypt(envelope);
      try {
        const request = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
        expect(request.op).toBe("sync");
      } finally {
        plain.fill(0);
      }
    } finally {
      (globalThis as { fetch?: unknown }).fetch = originalFetch;
    }
  });

  it("skips the sync POST entirely when no c2s key is supplied", async () => {
    const calls: unknown[] = [];
    const originalFetch = (globalThis as { fetch?: unknown }).fetch;
    (globalThis as { fetch?: unknown }).fetch = async (...args: unknown[]) => {
      calls.push(args);
      return { ok: true, status: 200 } as Response;
    };
    try {
      await startWorker();
      latestSocket().onopen?.();
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(calls).toHaveLength(0);
    } finally {
      (globalThis as { fetch?: unknown }).fetch = originalFetch;
    }
  });
});
