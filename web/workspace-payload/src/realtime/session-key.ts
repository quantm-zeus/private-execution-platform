/**
 * Host session-key handoff (BR-5). The cleartext shell establishes the HPKE
 * session and decrypts the artifact; it must then hand the payload directional
 * AEAD keys over the same-document channel, never persisted.
 *
 * Both directions are derived independently by the handshake, so the payload
 * never reuses one key for stream decrypt and command seal (nonce-reuse safe).
 *
 * This module only *accepts* a key that arrives in the expected shape and
 * rejects everything else. Nothing is stored globally or written to disk.
 */
export interface HostSessionKey {
  readonly kid: string;
  /** server -> client key for stream/response decryption (required). */
  readonly s2cKeyB64: string;
  /** client -> server key for command sealing (optional). */
  readonly c2sKeyB64?: string;
}

export const SESSION_KEY_MESSAGE = "evergreen:session-key";

function isB64(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function parseHostKey(data: unknown): HostSessionKey | null {
  if (typeof data !== "object" || data === null) return null;
  const record = data as Record<string, unknown>;
  if (record.type !== SESSION_KEY_MESSAGE) return null;
  if (typeof record.kid !== "string" || record.kid.length === 0 || record.kid.length > 64) return null;
  if (!isB64(record.s2cKeyB64, 128)) return null;
  if (record.c2sKeyB64 !== undefined && !isB64(record.c2sKeyB64, 128)) return null;
  return {
    kid: record.kid,
    s2cKeyB64: record.s2cKeyB64,
    c2sKeyB64: record.c2sKeyB64 as string | undefined,
  };
}

/**
 * Wait for the shell to deliver session keys. Resolves `null` on timeout or
 * abort so the caller can surface an explicit offline state instead of hanging.
 *
 * Only same-document messages, or messages whose source is exactly this
 * document's parent frame, are accepted. `event.source === null` is refused:
 * it can be synthesized by other code in the page and must never be able to
 * install attacker-chosen session keys.
 */
export function awaitHostSessionKey(
  timeoutMs: number,
  target: Window = window,
  signal?: AbortSignal,
): Promise<HostSessionKey | null> {
  return new Promise((resolve) => {
    let settled = false;
    const onMessage = (event: MessageEvent) => {
      const sourceOk = event.source === target || event.source === target.parent;
      if (!sourceOk) return;
      // Same-origin only: the shell and the payload share an origin (the payload
      // is framed with `allow-same-origin`). A cross-origin frame must never be
      // able to install attacker-chosen session keys, even if it somehow obtains
      // a handle to this window.
      const expectedOrigin = target.location ? target.location.origin : "";
      if (event.origin !== expectedOrigin) return;
      const key = parseHostKey(event.data);
      if (key) finish(key);
    };
    const onAbort = () => finish(null);
    const cleanup = () => {
      if (typeof target.removeEventListener === "function") {
        target.removeEventListener("message", onMessage);
      }
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (value: HostSessionKey | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    if (signal?.aborted) {
      finish(null);
      return;
    }
    target.addEventListener("message", onMessage);
    signal?.addEventListener("abort", onAbort);
  });
}
