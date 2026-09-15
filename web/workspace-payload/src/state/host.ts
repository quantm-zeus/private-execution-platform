// Host-channel helpers. The private payload runs inside the cleartext shell's
// sandboxed iframe; the only cross-document channel is same-document
// `postMessage`. Nothing here persists or serializes private state.

export interface HostLockMessage {
  readonly type: "evergreen:lock-request";
}

export interface HostReadyMessage {
  readonly type: "evergreen:workspace-ready";
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
  postToHost({ type: "evergreen:workspace-ready" });
}
