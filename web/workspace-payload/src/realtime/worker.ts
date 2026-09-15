/// <reference lib="webworker" />
//
// Realtime Web Worker: owns the websocket, AEAD decryption, frame decoding,
// batching and normalization. The main thread never touches the socket or the
// session key. Keys live only in this worker's memory and are dropped on stop.

import { base64ToBytes } from "../core/base64";
import { toWorkspaceErrorShape } from "../core/errors";
import { assertNeutralUrl, assertNeutralStreamUrl } from "../transport/paths";
import { FrameBatcher, DEFAULT_FLUSH_MS } from "./batcher";
import { RealtimeClient } from "./client";
import { WebCryptoDecryptor, UnavailableDecryptor, type SessionDecryptor } from "./decryptor";
import { backoffDelay } from "./reconnect";
import type { MainToWorker, WorkerToMain } from "./worker-protocol";
import type { ResyncReason } from "./types";

const ctx = self as unknown as DedicatedWorkerGlobalScope;
const FLUSH_INTERVAL_MS = 25;
/**
 * Hard cap on an inbound wire frame *before* decoding/JSON parsing. The envelope
 * validator's `MAX_CIPHERTEXT_BYTES` only runs after the whole message has been
 * materialized, so a compromised relay could otherwise hand the worker a huge
 * buffer and exhaust its memory (the worker holds the only session key).
 */
const MAX_WIRE_BYTES = 2 * 1024 * 1024;

let socket: WebSocket | null = null;
let client: RealtimeClient | null = null;
let flushTimer: ReturnType<typeof setInterval> | null = null;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let stopped = true;
let attempt = 0;
let streamUrl = "";
let baseUrl = "";
let syncUrl = "";
let hasSessionKey = false;
let startGeneration = 0;

function post(message: WorkerToMain): void {
  ctx.postMessage(message);
}

function clearTimers(): void {
  if (flushTimer !== null) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
  if (retryTimer !== null) {
    clearTimeout(retryTimer);
    retryTimer = null;
  }
}

function teardownSocket(): void {
  if (socket) {
    socket.onopen = null;
    socket.onmessage = null;
    socket.onclose = null;
    socket.onerror = null;
    try {
      socket.close();
    } catch {
      // already closed
    }
    socket = null;
  }
}

function stop(reason: string): void {
  stopped = true;
  clearTimers();
  teardownSocket();
  hasSessionKey = false;
  if (client) {
    client.stop();
    // Do NOT flush buffered frames on stop/lock: private frames must not reach
    // the main thread after the workspace is locked.
    client = null;
  }
  post({ type: "status", status: { phase: "offline", lastFrameAtMs: null, attempt: 0, nextRetryAtMs: null, reason } });
}

function scheduleReconnect(): void {
  if (stopped) return;
  const delay = backoffDelay(attempt);
  attempt += 1;
  const nextRetryAtMs = Date.now() + delay;
  // Tell the client the socket is gone so a frame that is still decrypting cannot
  // latch the phase back to `live` (the client fences late frames while
  // disconnected) and so its sequencer enters resync on the close.
  if (client) {
    client.noteDisconnected("Stream disconnected; reconnecting with backoff", nextRetryAtMs);
  } else {
    post({
      type: "status",
      status: {
        phase: "reconnecting",
        lastFrameAtMs: null,
        attempt,
        nextRetryAtMs,
        reason: "Stream disconnected; reconnecting with backoff",
      },
    });
  }
  retryTimer = setTimeout(openSocket, delay);
}

function openSocket(): void {
  if (stopped || !hasSessionKey) return;
  teardownSocket();
  try {
    socket = new WebSocket(streamUrl);
  } catch (error) {
    post({ type: "error", error: toWorkspaceErrorShape(error), fatal: false });
    scheduleReconnect();
    return;
  }
  socket.onopen = () => {
    client?.noteConnected();
    // Reconnect always resyncs, but through the client's coalescing window so a
    // relay that accepts and immediately closes cannot drive unbounded /v1/sync.
    client?.requestSnapshot("reconnect");
  };
  socket.binaryType = "arraybuffer";
  socket.onmessage = (event) => {
    ingestSocketData(event.data);
  };
  socket.onclose = () => scheduleReconnect();
  socket.onerror = () => {
    post({
      type: "error",
      error: { code: "network", message: "Realtime stream error.", retryable: true },
      fatal: false,
    });
  };
}

/**
 * The opaque edge relays binary frames only (it closes on any `Message::Text`),
 * so accept the UTF-8 JSON envelope from an `ArrayBuffer` as well as from a text
 * frame (used by local/mock transports). Ordering is preserved because
 * `RealtimeClient.ingest` serializes internally.
 */
function ingestSocketData(data: unknown): void {
  if (typeof data === "string") {
    if (data.length > MAX_WIRE_BYTES) return rejectOversizedFrame(data.length);
    void client?.ingest(data);
    return;
  }
  if (data instanceof ArrayBuffer) {
    if (data.byteLength > MAX_WIRE_BYTES) return rejectOversizedFrame(data.byteLength);
    void client?.ingest(new TextDecoder().decode(new Uint8Array(data)));
    return;
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    if (data.size > MAX_WIRE_BYTES) return rejectOversizedFrame(data.size);
    // Capture the client the Blob arrived under. `Blob.text()` is async, so a
    // stop/restart can install a new client (new session/key) before it settles;
    // reading the module-global `client` then would seed the *new* sequencer with
    // an old snapshot. Only ingest when the client is still the same instance.
    const target = client;
    void data
      .text()
      .then((text) => {
        if (target !== null && client === target) void target.ingest(text);
      })
      .catch(() => undefined);
  }
}

/** Drop an over-limit frame before it is decoded and force a resync, since the
 * stream is now missing at least one frame and must not stay "fresh". */
function rejectOversizedFrame(bytes: number): void {
  post({
    type: "error",
    error: {
      code: "protocol",
      message: "Realtime frame exceeded the wire size limit.",
      retryable: false,
      detail: `bytes ${bytes}`,
    },
    fatal: false,
  });
  // The dropped frame leaves a sequence hole; request recovery explicitly rather
  // than relying on the next frame to reveal the gap (a silent relay could leave
  // the client live on pre-drop state until the 30s watchdog).
  client?.requestSnapshot("protocol");
}

function requestResync(reason: ResyncReason, fromSeq: number | null): void {
  post({ type: "resync", reason, fromSeq });
  // Neutral resync path (BR-2). Best effort: the stream snapshot is the
  // authoritative recovery signal, so a failed POST must not wedge the client.
  //
  // The request is generic: only `from_seq` (a sequence number, never a trading
  // semantic) crosses in cleartext. We deliberately do NOT emit a cleartext
  // control frame on the websocket: the opaque edge relays binary ciphertext
  // only and closes on any `Message::Text` frame, and the architecture lock
  // requires that the actual operation type never leaves the AEAD envelope.
  if (syncUrl.length === 0) return;
  try {
    void fetch(syncUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ from_seq: fromSeq }),
    }).catch(() => undefined);
  } catch {
    // fetch unavailable in this runtime
  }
}

async function start(message: Extract<MainToWorker, { type: "start" }>): Promise<void> {
  const generation = ++startGeneration;
  stop("restarting");
  stopped = false;
  attempt = 0;
  baseUrl = message.baseUrl;
  streamUrl = assertNeutralStreamUrl(message.url, message.baseUrl).toString();
  syncUrl = assertNeutralUrl("/v1/sync", message.baseUrl).toString();
  hasSessionKey = true;

  let decryptor: SessionDecryptor = new UnavailableDecryptor();
  let rawKey: Uint8Array | undefined;
  try {
    rawKey = base64ToBytes(message.keyB64);
    decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, message.kid);
  } catch (error) {
    post({ type: "error", error: toWorkspaceErrorShape(error), fatal: true });
    stop("Session key rejected");
    return;
  } finally {
    rawKey?.fill(0);
  }

  // A stop/restart may have arrived while the key was being imported; never
  // install the client, decryptor or flush timer after a stop or a newer start.
  if (stopped || generation !== startGeneration) return;

  client = new RealtimeClient({
    decryptor,
    expectedKid: message.kid,
    // Reject replayed frames by their AEAD-authenticated server clock (BR-15).
    // Without a backend `server_time_ms` this is a no-op and the client keeps the
    // previous behaviour.
    serverNow: () => Date.now() + (message.serverSkewMs ?? 0),
    batcher: new FrameBatcher({
      capacity: message.capacity ?? 4_096,
      flushMs: message.flushMs ?? DEFAULT_FLUSH_MS,
    }),
    onFrames: (frames) => post({ type: "frames", frames }),
    onStatus: (status) => {
      // Reset backoff only once the session is actually live (first authenticated
      // snapshot). Resetting on socket open let an accept-then-close relay keep
      // the delay at backoff(0) and hammer reconnects.
      if (status.phase === "live") attempt = 0;
      post({ type: "status", status });
    },
    onResync: (reason, fromSeq) => requestResync(reason, fromSeq),
    onError: (error, fatal) => post({ type: "error", error, fatal }),
  });
  client.start();
  flushTimer = setInterval(() => {
    client?.flushDue();
    // Also decay a latched `live` phase when the socket stops delivering frames.
    client?.watchdog();
  }, FLUSH_INTERVAL_MS);
  openSocket();
  post({ type: "ready" });
}

ctx.onmessage = (event: MessageEvent<MainToWorker>) => {
  const message = event.data;
  if (!message || typeof message !== "object") return;
  if (message.type === "start") {
    // `start` asserts the neutral stream URL before opening the socket, so it can
    // reject. Surface a fatal error and stop cleanly instead of leaving an
    // unhandled rejection with a silently stopped worker (no offline reason).
    start(message).catch((error: unknown) => {
      post({ type: "error", error: toWorkspaceErrorShape(error), fatal: true });
      stop("Stream start failed");
    });
  } else if (message.type === "stop") {
    stop("Stopped");
  }
};
