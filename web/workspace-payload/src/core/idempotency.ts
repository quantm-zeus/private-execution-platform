/**
 * Idempotency helpers for every write path (INVARIANTS #9, BR-3).
 *
 * A logical user submission must carry a *stable* key so a transport retry or a
 * timeout cannot create a duplicate trade. A *new* submission of the same
 * parameters must get a *fresh* key, otherwise the backend would silently
 * dedupe a legitimate second order and the UI would show the first result as if
 * it were the new one.
 */

import { workspaceError } from "./errors";
import type { WorkspaceErrorCode } from "./types";

/**
 * True when a command failure does not prove the backend rejected the write, so
 * the outcome is genuinely unknown. Such failures keep the idempotency key so
 * that retrying the same logical submission dedupes.
 *
 * `retryable` disambiguates `server`: a non-retryable server/validation error
 * (e.g. HTTP 400/422) is a determinate rejection, so the key must be rotated
 * and a corrected retry must be a genuinely new order rather than a replay of
 * the backend's cached rejection. A retryable server error (5xx/timeout) is
 * ambiguous and keeps the key.
 *
 * An explicit `retryable: true` is authoritative for *every* code, not just
 * `server`. The backend marks a transient failure that may still have committed
 * (e.g. `BackendOutcome::Unavailable` surfaced as `capability_missing`) as
 * retryable precisely so the write stays ambiguous; treating it as determinate
 * because the code is not `server` would rotate the idempotency key and let the
 * next submission create a duplicate order (INVARIANTS #9). Determinacy must be
 * proven, never inferred from the code alone.
 */
export function isIndeterminateOutcome(code: WorkspaceErrorCode, retryable?: boolean): boolean {
  if (retryable === true) return true;
  if (code === "server") return retryable !== false;
  return code === "network" || code === "protocol" || code === "unknown" || code === "cancelled";
}

/**
 * A cryptographically random submission token. Write keys must be unguessable —
 * a predictable key lets an observer correlate or replay a user's orders — so a
 * deployment without `crypto` fails closed instead of falling back to
 * `Date.now()`/`Math.random()`.
 */
function randomToken(): string {
  const cryptoObj: Crypto | undefined = globalThis.crypto;
  if (cryptoObj !== undefined && typeof cryptoObj.randomUUID === "function") {
    return cryptoObj.randomUUID();
  }
  if (cryptoObj !== undefined && typeof cryptoObj.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  throw workspaceError(
    "protocol",
    "A cryptographically secure idempotency key could not be generated.",
  );
}

export function newIdempotencyKey(prefix: string): string {
  return `${prefix}-${randomToken()}`;
}

export interface SubmissionKeyTracker {
  /** Stable key while `signature` is unchanged; fresh key once it changes. */
  keyFor(signature: string): string;
  /** Call after a successful submission so the next identical one is distinct. */
  clear(): void;
}

export function createSubmissionKeyTracker(prefix: string): SubmissionKeyTracker {
  let current: { signature: string; key: string } | null = null;
  return {
    keyFor(signature: string): string {
      if (current !== null && current.signature === signature) return current.key;
      current = { signature, key: newIdempotencyKey(prefix) };
      return current.key;
    },
    clear(): void {
      current = null;
    },
  };
}
