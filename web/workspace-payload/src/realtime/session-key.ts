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
 * Wait for the shell to deliver session keys. Resolves `null` on timeout so the
 * caller can surface an explicit offline state instead of hanging. The listener
 * only accepts same-document messages from this window or its parent frame;
 * a synthetic event with a null source (tests) is also accepted because only
 * code already running in this document can dispatch one.
 */
export function awaitHostSessionKey(
  timeoutMs: number,
  target: Window = window,
): Promise<HostSessionKey | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: HostSessionKey | null) => {
      if (settled) return;
      settled = true;
      target.removeEventListener("message", onMessage);
      clearTimeout(timer);
      resolve(value);
    };
    const onMessage = (event: MessageEvent) => {
      const sourceOk =
        event.source === null || event.source === target || event.source === target.parent;
      if (!sourceOk) return;
      const key = parseHostKey(event.data);
      if (key) finish(key);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    target.addEventListener("message", onMessage);
  });
}
