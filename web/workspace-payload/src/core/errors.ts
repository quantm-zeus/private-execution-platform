import { WorkspaceError, type WorkspaceErrorCode, type WorkspaceErrorShape } from "./types";

/** Build a redaction-safe workspace error. `detail` must never carry secrets. */
export function workspaceError(
  code: WorkspaceErrorCode,
  message: string,
  options: { retryable?: boolean; detail?: string } = {},
): WorkspaceError {
  return new WorkspaceError({
    code,
    message,
    retryable: options.retryable ?? defaultRetryable(code),
    detail: options.detail,
  });
}

function defaultRetryable(code: WorkspaceErrorCode): boolean {
  switch (code) {
    case "network":
    case "server":
    case "freshness":
      return true;
    case "auth":
    case "capability_missing":
    case "protocol":
    case "cancelled":
    case "unknown":
      return false;
  }
}

/** Coerce any thrown value into a redaction-safe error shape. */
export function toWorkspaceErrorShape(error: unknown): WorkspaceErrorShape {
  if (error instanceof WorkspaceError) return error.toShape();
  if (error instanceof DOMException && error.name === "AbortError") {
    return { code: "cancelled", message: "Request cancelled.", retryable: true };
  }
  return {
    code: "unknown",
    message: "Unexpected workspace error.",
    retryable: false,
  };
}

/** True when an AbortSignal-driven cancellation produced this error. */
export function isCancellation(error: unknown): boolean {
  return (
    (error instanceof WorkspaceError && error.code === "cancelled") ||
    (error instanceof DOMException && error.name === "AbortError")
  );
}
