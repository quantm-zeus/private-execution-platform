import { createEffect, createSignal, onCleanup, onMount, type Accessor } from "solid-js";
import { base64ToBytes } from "../core/base64";
import type { ConnectionStatus } from "../core/types";
import type { WorkspaceStore } from "../state/session";
import { EncryptedCommandClient, UnavailableCommandClient } from "../transport/command";
import { createRealtimeController, type RealtimeController } from "./controller";
import { WebCryptoDecryptor } from "./decryptor";
import { WebCryptoSealer } from "./sealer";
import { awaitHostSessionKey, type HostSessionKey } from "./session-key";
import type { DecodedFrame } from "./types";

export interface RealtimeFeed {
  readonly status: Accessor<ConnectionStatus>;
  readonly started: Accessor<boolean>;
  subscribe(handler: (frames: DecodedFrame[]) => void): () => void;
}

/**
 * Bridges the workspace session to the realtime worker.
 *
 * The feed waits for the authoritative session (`/v1/bootstrap`) to settle and
 * only starts when the backend advertises the realtime capability AND the shell
 * hands over a session key; otherwise the workspace stays explicitly offline —
 * never a fake "live".
 *
 * The host key listener is armed immediately (before bootstrap resolves) so a
 * key the shell posts as soon as the payload announces readiness is not missed,
 * while the decision to *start* waits for the capability set. If the feed
 * decided at mount time it would always observe the pre-bootstrap capability
 * snapshot (all false) and never start.
 */
export function useRealtimeFeed(
  ws: WorkspaceStore,
  options: { readonly keyTimeoutMs?: number; readonly controller?: RealtimeController } = {},
): RealtimeFeed {
  const controller = options.controller ?? createRealtimeController();
  const [started, setStarted] = createSignal(false);
  let disposed = false;
  let startRequested = false;
  let keyPromise: Promise<HostSessionKey | null> | null = null;
  const keyAbort = new AbortController();
  let lastOfflineReason: string | null = null;

  createEffect(() => {
    if (started()) ws.setConnection(controller.status());
  });

  const reportOffline = (reason: string): void => {
    if (lastOfflineReason === reason) return;
    lastOfflineReason = reason;
    ws.setConnection({
      phase: "offline",
      lastFrameAtMs: null,
      attempt: 0,
      nextRetryAtMs: null,
      reason,
    });
  };

  /**
   * Resolve the BR-5 handoff. The listener is armed at mount so an early shell
   * post is not missed; if that window times out (slow bootstrap or a late
   * handoff) it is re-armed once the authoritative session is ready instead of
   * permanently latching offline.
   */
  const resolveHostKey = async (): Promise<HostSessionKey | null> => {
    if (keyPromise) {
      const first = await keyPromise;
      if (first) return first;
    }
    if (disposed) return null;
    keyPromise = awaitHostSessionKey(options.keyTimeoutMs ?? 2_000, window, keyAbort.signal);
    return keyPromise;
  };

  const startFeed = async (): Promise<void> => {
    if (disposed) return;
    if (typeof Worker === "undefined") {
      reportOffline("Realtime worker is unsupported in this runtime.");
      return;
    }
    const key = await resolveHostKey();
    if (disposed) return;
    if (!key) {
      reportOffline("Session key handoff unavailable (BR-5).");
      return;
    }
    if (
      typeof location === "undefined" ||
      location.origin.length === 0 ||
      // A sandboxed opaque document reports the string origin "null", which is
      // not a usable base URL: `new URL("/v1/stream", "null")` throws.
      location.origin === "null"
    ) {
      reportOffline("Private API origin is unavailable in this runtime.");
      return;
    }
    const origin = location.origin;
    let decryptor: WebCryptoDecryptor;
    try {
      // Decoding can throw on malformed base64; keep it inside the guard so a
      // bad handoff yields an explicit offline reason instead of an unhandled
      // rejection that leaves the workspace wedged.
      const s2cKey = base64ToBytes(key.s2cKeyB64);
      try {
        decryptor = await WebCryptoDecryptor.fromRawKey(s2cKey, key.kid);
      } finally {
        s2cKey.fill(0);
      }
    } catch {
      reportOffline("Session key was rejected.");
      return;
    }
    if (disposed) return;

    // Wire the encrypted command channel only when a distinct client->server key
    // is supplied (never reuse the stream key: nonce-reuse safety).
    if (key.c2sKeyB64) {
      try {
        const c2sKey = base64ToBytes(key.c2sKeyB64);
        try {
          const sealer = await WebCryptoSealer.fromRawKey(c2sKey);
          ws.setCommand(
            new EncryptedCommandClient({ sealer, decryptor, kid: key.kid, baseUrl: origin }),
          );
        } finally {
          c2sKey.fill(0);
        }
      } catch {
        // Command channel stays fail-closed on the unavailable client.
      }
    }
    if (disposed) return;

    let streamUrl: URL;
    try {
      streamUrl = new URL("/v1/stream", origin);
    } catch {
      // A malformed/opaque origin must render an explicit offline reason instead
      // of an unhandled rejection that leaves the workspace wedged.
      reportOffline("Private API origin is unavailable in this runtime.");
      return;
    }
    streamUrl.protocol = streamUrl.protocol === "https:" ? "wss:" : "ws:";
    controller.start({
      url: streamUrl.toString(),
      baseUrl: origin,
      kid: key.kid,
      keyB64: key.s2cKeyB64,
      // The worker seals its own opaque `/v1/sync` envelopes with the c2s key.
      // Absent the key the worker skips the best-effort sync POST.
      ...(key.c2sKeyB64 ? { c2sKeyB64: key.c2sKeyB64 } : {}),
      // Server-minus-local clock offset from bootstrap, so the worker can reject
      // replayed frames by their authenticated `server_time_ms` (BR-15).
      serverSkewMs: ws.serverNowMs() - ws.clockMs(),
    });
    setStarted(true);
    // The base64 handoff secret is only needed to import the CryptoKeys and
    // hand the stream key to the worker; drop the main-thread reference so it
    // is not retained for the lifetime of the feed.
    keyPromise = null;
  };

  // Arm the host key listener before bootstrap resolves; a synthetic event with
  // a null source (tests) or a real parent-frame message both arrive here.
  onMount(() => {
    keyPromise = awaitHostSessionKey(options.keyTimeoutMs ?? 2_000, window, keyAbort.signal);
  });

  createEffect(() => {
    const current = ws.state();
    if (current.kind !== "ready" && current.kind !== "stale") return;
    if (startRequested) return;
    if (!ws.capabilities().realtime) {
      reportOffline("Realtime capability is not available on this deployment.");
      return;
    }
    startRequested = true;
    void startFeed();
  });

  // Bounded recent-frame retention. Views mount lazily (per navigation), so a
  // panel that mounts after frames have already been decoded must still receive
  // the current snapshot *and the deltas that followed it* instead of an empty
  // "awaiting feed" state until the backend happens to resend a snapshot.
  const retained: DecodedFrame[] = [];
  const RETAIN_LIMIT = 128;
  const retainFrames = (frames: readonly DecodedFrame[]): void => {
    for (const frame of frames) {
      if (frame.op !== "snapshot" && frame.op !== "delta") continue;
      retained.push(frame);
    }
    if (retained.length > RETAIN_LIMIT) {
      retained.splice(0, retained.length - RETAIN_LIMIT);
    }
  };
  const unsubscribeRetain = controller.subscribe(retainFrames);

  // Retained frames are epoch-local. A resync or reconnect invalidates the
  // previous baseline, so keeping them would let a late-mounting panel replay
  // pre-resync state (with higher sequence numbers) on top of a fresh snapshot.
  createEffect(() => {
    const phase = controller.status().phase;
    if (phase === "reconnecting" || phase === "degraded" || phase === "offline") {
      retained.length = 0;
    }
  });

  onCleanup(() => {
    disposed = true;
    keyAbort.abort();
    unsubscribeRetain();
    retained.length = 0;
    // Drop the encrypted command client (and its main-thread decryptor, which
    // holds a session key) so it cannot outlive the feed/store.
    ws.setCommand(new UnavailableCommandClient());
    controller.dispose();
  });

  return {
    status: controller.status,
    started,
    subscribe: (handler) => {
      // Replay synchronously before subscribing: no frame can be delivered
      // between the two calls (single-threaded), so nothing is lost or doubled.
      if (retained.length > 0) {
        handler([...retained].sort((a, b) => a.seq - b.seq));
      }
      return controller.subscribe(handler);
    },
  };
}
