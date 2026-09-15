// Host-channel helpers. The private payload runs inside the cleartext shell's
// sandboxed iframe; the only cross-document channel is same-document
// `postMessage`. Nothing here persists or serializes private state.

export interface HostLockMessage {
  readonly type: "evergreen:lock-request";
}

export interface HostReadyMessage {
  readonly type: "evergreen:workspace-ready";
  /**
   * BR-5 handoff binding echoed back to the shell. The shell injects this token
   * into the payload document; returning it proves the ping came from the
   * document the shell instantiated (not a same-origin navigation).
   */
  readonly handoff: string;
}

/**
 * Read the per-unlock handoff token the shell injected into this document.
 * Absent (e.g. the payload loaded standalone in a test) is the empty string, so
 * the shell simply withholds keys rather than delivering them unbound.
 */
export function readHandoffToken(): string {
  if (typeof document === "undefined") return "";
  const meta = document.querySelector('meta[name="evergreen-handoff"]');
  const content = meta?.getAttribute("content");
  return typeof content === "string" ? content : "";
}

export function postToHost(message: HostLockMessage | HostReadyMessage): void {
  if (typeof window === "undefined" || window.parent === window) return;
  // The payload is same-origin with the shell (BR-6), so the parent origin is
  // known. Only fall back to "*" for an opaque origin, where the messages carry
  // no private semantics (lock request / ready ping).
  const targetOrigin =
    typeof location !== "undefined" && location.origin && location.origin !== "null"
      ? location.origin
      : "*";
  try {
    window.parent.postMessage(message, targetOrigin);
  } catch {
    // Cross-document messaging is best effort; the shell also drops the
    // iframe and revokes blob URLs on lock, which is the real boundary.
  }
}

export function requestHostLock(): void {
  postToHost({ type: "evergreen:lock-request" });
}

export function announceWorkspaceReady(): void {
  postToHost({ type: "evergreen:workspace-ready", handoff: readHandoffToken() });
}
