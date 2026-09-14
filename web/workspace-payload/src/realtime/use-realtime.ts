import { createEffect, createSignal, onCleanup, onMount, type Accessor } from "solid-js";
import { base64ToBytes } from "../core/base64";
import type { ConnectionStatus } from "../core/types";
import type { WorkspaceStore } from "../state/session";
import { EncryptedCommandClient } from "../transport/command";
import { createRealtimeController, type RealtimeController } from "./controller";
import { WebCryptoDecryptor } from "./decryptor";
import { WebCryptoSealer } from "./sealer";
import { awaitHostSessionKey } from "./session-key";
import type { DecodedFrame } from "./types";

export interface RealtimeFeed {
  readonly status: Accessor<ConnectionStatus>;
  readonly started: Accessor<boolean>;
  subscribe(handler: (frames: DecodedFrame[]) => void): () => void;
}

/**
 * Bridges the workspace session to the realtime worker. It only starts when the
 * backend advertises the realtime capability AND the shell hands over a session
 * key; otherwise the workspace stays explicitly offline — never a fake "live".
 */
export function useRealtimeFeed(
  ws: WorkspaceStore,
  options: { readonly keyTimeoutMs?: number; readonly controller?: RealtimeController } = {},
): RealtimeFeed {
  const controller = options.controller ?? createRealtimeController();
  const [started, setStarted] = createSignal(false);
  let disposed = false;

  createEffect(() => {
    if (started()) ws.setConnection(controller.status());
  });

  onMount(async () => {
    if (!ws.capabilities().realtime) {
      ws.setConnection({
        phase: "offline",
        lastFrameAtMs: null,
        attempt: 0,
        nextRetryAtMs: null,
        reason: "Realtime capability is not available on this deployment.",
      });
      return;
    }
    if (typeof Worker === "undefined") {
      ws.setConnection({
        phase: "offline",
        lastFrameAtMs: null,
        attempt: 0,
        nextRetryAtMs: null,
        reason: "Realtime worker is unsupported in this runtime.",
      });
      return;
    }
    const key = await awaitHostSessionKey(options.keyTimeoutMs ?? 2_000);
    if (disposed) return;
    if (!key) {
      ws.setConnection({
        phase: "offline",
        lastFrameAtMs: null,
        attempt: 0,
        nextRetryAtMs: null,
        reason: "Session key handoff unavailable (BR-5).",
      });
      return;
    }
    const origin = location.origin;
    const s2cKey = base64ToBytes(key.s2cKeyB64);
    let decryptor: WebCryptoDecryptor;
    try {
      decryptor = await WebCryptoDecryptor.fromRawKey(s2cKey, key.kid);
    } catch {
      ws.setConnection({
        phase: "offline",
        lastFrameAtMs: null,
        attempt: 0,
        nextRetryAtMs: null,
        reason: "Session key was rejected.",
      });
      return;
    } finally {
      s2cKey.fill(0);
    }
    if (disposed) return;

    // Wire the encrypted command channel only when a distinct client->server key
    // is supplied (never reuse the stream key: nonce-reuse safety).
    if (key.c2sKeyB64) {
      const c2sKey = base64ToBytes(key.c2sKeyB64);
      try {
        const sealer = await WebCryptoSealer.fromRawKey(c2sKey);
        ws.setCommand(
          new EncryptedCommandClient({ sealer, decryptor, kid: key.kid, baseUrl: origin }),
        );
      } catch {
        // Command channel stays fail-closed on the unavailable client.
      } finally {
        c2sKey.fill(0);
      }
    }

    const streamUrl = new URL("/v1/stream", origin);
    streamUrl.protocol = streamUrl.protocol === "https:" ? "wss:" : "ws:";
    controller.start({
      url: streamUrl.toString(),
      baseUrl: origin,
      kid: key.kid,
      keyB64: key.s2cKeyB64,
    });
    setStarted(true);
  });

  onCleanup(() => {
    disposed = true;
    controller.dispose();
  });

  return {
    status: controller.status,
    started,
    subscribe: (handler) => controller.subscribe(handler),
  };
}
