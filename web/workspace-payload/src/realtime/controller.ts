import { createSignal, type Accessor } from "solid-js";
import type { ConnectionStatus, WorkspaceErrorShape } from "../core/types";
import type { DecodedFrame, Priority } from "./types";
import type { MainToWorker, WorkerToMain } from "./worker-protocol";
import RealtimeWorker from "./worker?worker&inline";

export interface RealtimeStartConfig {
  readonly url: string;
  readonly baseUrl: string;
  readonly kid: string;
  readonly keyB64: string;
  /** Base64 raw 32-byte client->server key for opaque `/v1/sync` sealing. */
  readonly c2sKeyB64?: string;
  readonly serverSkewMs?: number;
  readonly flushMs?: Record<Priority, number>;
  readonly capacity?: number;
}

export interface RealtimeController {
  readonly status: Accessor<ConnectionStatus>;
  readonly lastError: Accessor<WorkspaceErrorShape | null>;
  start(config: RealtimeStartConfig): void;
  stop(): void;
  /** Stop and terminate the worker thread, releasing all handlers. */
  dispose(): void;
  /** Subscribe to batched frames; returns an unsubscribe function. */
  subscribe(handler: (frames: DecodedFrame[]) => void): () => void;
}

const OFFLINE: ConnectionStatus = {
  phase: "offline",
  lastFrameAtMs: null,
  attempt: 0,
  nextRetryAtMs: null,
  reason: null,
};

/**
 * Main-thread half of the realtime boundary. It never touches the socket or the
 * session key: it only forwards start/stop to the worker and consumes batched,
 * already-decoded frames.
 */
export function createRealtimeController(
  factory: () => Worker = () => new RealtimeWorker(),
): RealtimeController {
  const [status, setStatus] = createSignal<ConnectionStatus>(OFFLINE);
  const [lastError, setLastError] = createSignal<WorkspaceErrorShape | null>(null);
  const handlers = new Set<(frames: DecodedFrame[]) => void>();
  let worker: Worker | null = null;

  const handleMessage = (event: MessageEvent<WorkerToMain>): void => {
    const message = event.data;
    if (!message || typeof message !== "object") return;
    switch (message.type) {
      case "status":
        setStatus(message.status);
        break;
      case "frames":
        for (const handler of handlers) handler(message.frames);
        break;
      case "error":
        setLastError(message.error);
        break;
      case "resync":
        setStatus((prev) => ({
          ...prev,
          phase: prev.phase === "live" ? "degraded" : prev.phase,
          reason: `Resync (${message.reason})`,
        }));
        break;
      case "ready":
        break;
    }
  };

  const ensureWorker = (): Worker | null => {
    if (worker) return worker;
    if (typeof Worker === "undefined") return null;
    try {
      worker = factory();
    } catch {
      setLastError({
        code: "capability_missing",
        message: "Realtime worker could not be created in this runtime.",
        retryable: false,
      });
      return null;
    }
    worker.onmessage = handleMessage;
    worker.onerror = () => {
      setLastError({ code: "unknown", message: "Realtime worker crashed.", retryable: false });
    };
    return worker;
  };

  return {
    status,
    lastError,
    start(config) {
      const active = ensureWorker();
      if (!active) return;
      const message: MainToWorker = { type: "start", ...config };
      active.postMessage(message);
    },
    stop() {
      if (!worker) return;
      worker.postMessage({ type: "stop" } satisfies MainToWorker);
      setStatus(OFFLINE);
    },
    dispose() {
      if (worker) {
        worker.onmessage = null;
        worker.onerror = null;
        worker.terminate();
        worker = null;
      }
      handlers.clear();
      setStatus(OFFLINE);
    },
    subscribe(handler) {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
  };
}
