/// <reference lib="webworker" />
//
// Realtime Web Worker: owns the websocket, AEAD decryption, frame decoding,
// batching and normalization. The main thread never touches the socket or the
// session key. Keys live only in this worker's memory and are dropped on stop.

import { base64ToBytes } from "../core/base64";
import { toWorkspaceErrorShape } from "../core/errors";
import type { ConnectionStatus } from "../core/types";
import { assertNeutralUrl, assertNeutralStreamUrl } from "../transport/paths";
import { FrameBatcher, DEFAULT_FLUSH_MS } from "./batcher";
import { RealtimeClient } from "./client";
import { WebCryptoDecryptor, UnavailableDecryptor, type SessionDecryptor } from "./decryptor";
import { backoffDelay } from "./reconnect";
import type { MainToWorker, WorkerToMain } from "./worker-protocol";
import type { ResyncReason } from "./types";

const ctx = self as unknown as DedicatedWorkerGlobalScope;
const FLUSH_INTERVAL_MS = 25;

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
  const status: ConnectionStatus = {
    phase: "reconnecting",
    lastFrameAtMs: null,
    attempt,
    nextRetryAtMs: Date.now() + delay,
    reason: "Stream disconnected; reconnecting with backoff",
  };
  post({ type: "status", status });
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
    attempt = 0;
    client?.noteConnected();
    // Reconnect always resyncs: the sequencer must not resume a stale baseline.
    requestResync("reconnect", client?.expectedSeq ?? null);
  };
  socket.onmessage = (event) => {
    if (typeof event.data === "string") {
      void client?.ingest(event.data);
    }
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

function requestResync(reason: ResyncReason, fromSeq: number | null): void {
  post({ type: "resync", reason, fromSeq });
  // Neutral resync path (BR-2). Best effort: the stream snapshot is the
  // authoritative recovery signal, so a failed POST must not wedge the client.
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
  try {
    socket?.send(JSON.stringify({ control: "resync" }));
  } catch {
    // socket already closed
  }
}

async function start(message: Extract<MainToWorker, { type: "start" }>): Promise<void> {
  stop("restarting");
  stopped = false;
  attempt = 0;
  baseUrl = message.baseUrl;
  streamUrl = assertNeutralStreamUrl(message.url, message.baseUrl).toString();
  syncUrl = assertNeutralUrl("/v1/sync", message.baseUrl).toString();
  hasSessionKey = true;

  let decryptor: SessionDecryptor = new UnavailableDecryptor();
  const rawKey = base64ToBytes(message.keyB64);
  try {
    decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, message.kid);
  } catch (error) {
    post({ type: "error", error: toWorkspaceErrorShape(error), fatal: true });
    stop("Session key rejected");
    return;
  } finally {
    rawKey.fill(0);
  }

  client = new RealtimeClient({
    decryptor,
    expectedKid: message.kid,
    batcher: new FrameBatcher({
      capacity: message.capacity ?? 4_096,
      flushMs: message.flushMs ?? DEFAULT_FLUSH_MS,
    }),
    onFrames: (frames) => post({ type: "frames", frames }),
    onStatus: (status) => post({ type: "status", status }),
    onResync: (reason, fromSeq) => requestResync(reason, fromSeq),
    onError: (error, fatal) => post({ type: "error", error, fatal }),
  });
  client.start();
  flushTimer = setInterval(() => client?.flushDue(), FLUSH_INTERVAL_MS);
  openSocket();
  post({ type: "ready" });
}

ctx.onmessage = (event: MessageEvent<MainToWorker>) => {
  const message = event.data;
  if (!message || typeof message !== "object") return;
  if (message.type === "start") {
    void start(message);
  } else if (message.type === "stop") {
    stop("Stopped");
  }
};
