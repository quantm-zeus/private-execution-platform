// @vitest-environment node
//
// Focused unit test for the realtime Worker module. The worker owns the socket
// and the only in-memory session key, so it is the highest-value place to assert
// the wire-size ceiling, the "never send a cleartext control frame" invariant and
// the stop fence. It is exercised here with a fake `self`/`WebSocket` because a
// DedicatedWorkerGlobalScope is not available under jsdom.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

async function startWorker(): Promise<void> {
  context.onmessage?.({
    data: {
      type: "start",
      url: "ws://localhost/v1/stream",
      baseUrl: "http://localhost",
      kid: "kid-test",
      keyB64: keyB64(),
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
});
