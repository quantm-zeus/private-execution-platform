// Privacy-safe typed unlock stage failures.
//
// Every failure of the browser unlock path is classified into exactly one
// stage, U1..U7, plus a small machine reason. The original exception text,
// secret, KID, public key, ciphertext, and file paths are never propagated: an
// `UnlockError` carries only a stage and a reason, and its message is a fixed
// generic string. The clear shell turns the pair into human recovery guidance.

export type UnlockStage =
  | "U1_WASM"
  | "U2_ENROLL"
  | "U3_GRANT"
  | "U4_TRANSPORT"
  | "U5_ARTIFACT"
  | "U6_PACKAGE"
  | "U7_BOOT";

export type UnlockReason =
  | "wasm_unavailable"
  | "invalid_secret"
  | "invalid_kid"
  | "descriptor_invalid"
  | "protocol_incompatible"
  | "workspace_key_mismatch"
  | "session_expired"
  | "enrollment_required"
  | "enrollment_conflict"
  | "enrollment_rejected"
  | "grant_invalid"
  | "grant_rejected"
  | "transport_rejected"
  | "artifact_incompatible"
  | "artifact_decrypt_failed"
  | "package_invalid"
  | "boot_failed"
  | "handoff_unavailable"
  | "unknown";

/** The only error type the unlock path may surface. */
export class UnlockError extends Error {
  readonly stage: UnlockStage;
  readonly reason: UnlockReason;

  constructor(stage: UnlockStage, reason: UnlockReason = "unknown") {
    // Deliberately generic; never interpolate a caught exception.
    super("workspace unlock failed");
    this.name = "UnlockError";
    this.stage = stage;
    this.reason = reason;
  }
}

/** True when `error` is one of ours, without coercing foreign errors. */
export function isUnlockError(error: unknown): error is UnlockError {
  return error instanceof UnlockError;
}

/** Classify an unknown caught value into a stage error; never inspects text. */
export function asUnlockError(
  error: unknown,
  stage: UnlockStage,
  reason: UnlockReason = "unknown",
): UnlockError {
  return isUnlockError(error) ? error : new UnlockError(stage, reason);
}

export type RecoveryAction =
  | "reload"
  | "retry"
  | "reenter_recovery"
  | "resume_authentication"
  | "rollback_release"
  | "contact_operator";

export interface UnlockRecovery {
  /** Short human label for the failed stage. */
  readonly stageLabel: string;
  /** What happened, in plain language, without technical secrets. */
  readonly title: string;
  /** What the person should do next. */
  readonly detail: string;
  /** Primary next action the UI should offer. */
  readonly action: RecoveryAction;
  /** `error` for hard failures, `warning` for recoverable ones. */
  readonly severity: "error" | "warning";
  /** Machine reason, so the UI can distinguish an invalid credential. */
  readonly reason: UnlockReason;
}

const STAGE_LABELS: Record<UnlockStage, string> = {
  U1_WASM: "Crypto module",
  U2_ENROLL: "Workspace identity",
  U3_GRANT: "Artifact access",
  U4_TRANSPORT: "Encrypted session",
  U5_ARTIFACT: "Release compatibility",
  U6_PACKAGE: "Release package",
  U7_BOOT: "Workspace start",
};

/**
 * Human recovery guidance for a stage/reason pair. Contains no secret, key,
 * path, KID, or ciphertext, and never echoes an exception.
 */
export function recoveryFor(
  stage: UnlockStage,
  reason: UnlockReason,
): UnlockRecovery {
  return { ...guidanceFor(stage, reason), reason };
}

function guidanceFor(
  stage: UnlockStage,
  reason: UnlockReason,
): Omit<UnlockRecovery, "reason"> {
  const stageLabel = STAGE_LABELS[stage];
  switch (stage) {
    case "U1_WASM":
      return {
        stageLabel,
        title: "The browser crypto module did not load.",
        detail:
          "Reload the page. If this repeats, this device or browser may not support the required WebAssembly crypto.",
        action: "reload",
        severity: "error",
      };
    case "U2_ENROLL":
      if (reason === "workspace_key_mismatch" || reason === "enrollment_conflict") {
        return {
          stageLabel,
          title: "This recovery code is not for the active release.",
          detail:
            "Re-enter the offline recovery code printed for this workspace, or use a recovery passkey. Nothing was sent to the server.",
          action: "reenter_recovery",
          severity: "warning",
        };
      }
      if (reason === "session_expired") {
        return {
          stageLabel,
          title: "Your operator session expired.",
          detail: "Verify your passkey again, then retry the unlock.",
          action: "resume_authentication",
          severity: "warning",
        };
      }
      if (reason === "invalid_secret") {
        return {
          stageLabel,
          title: "The recovery code is not valid.",
          detail:
            "Re-enter the 32-byte offline recovery code exactly as printed, or unlock with a recovery passkey. Nothing was sent to the server.",
          action: "reenter_recovery",
          severity: "error",
        };
      }
      return {
        stageLabel,
        title: "The workspace key could not be bound to this session.",
        detail:
          "Retry once. If it persists, verify your passkey again and confirm the release is published.",
        action: "retry",
        severity: "error",
      };
    case "U3_GRANT":
      return {
        stageLabel,
        title: "The server did not issue artifact access.",
        detail:
          "Retry. If it persists, the release may be offline or the session may have expired.",
        action: "retry",
        severity: "error",
      };
    case "U4_TRANSPORT":
      return {
        stageLabel,
        title: "The encrypted session could not be established.",
        detail:
          "Retry. If it persists, verify your network path to the private origin and try again.",
        action: "retry",
        severity: "error",
      };
    case "U5_ARTIFACT":
      if (reason === "workspace_key_mismatch") {
        return {
          stageLabel,
          title: "This recovery code does not match the published release.",
          detail:
            "The active release was sealed to a different workspace key. Re-enter the recovery code for this release, or restore the release that matches this code.",
          action: "contact_operator",
          severity: "error",
        };
      }
      return {
        stageLabel,
        title: "The active release does not match your workspace key.",
        detail:
          "The released artifact is stale or was sealed for a different key. Ask the operator to roll forward or roll back the release, then try again.",
        action: "contact_operator",
        severity: "error",
      };
    case "U6_PACKAGE":
      return {
        stageLabel,
        title: "The decrypted release payload is malformed.",
        detail:
          "The artifact decrypted but did not contain a valid workspace package. Roll back to the previous immutable release.",
        action: "rollback_release",
        severity: "error",
      };
    case "U7_BOOT":
      return {
        stageLabel,
        title: "The private workspace did not start.",
        detail:
          "Reload and retry. If it persists, this browser may not support the workspace runtime.",
        action: "reload",
        severity: "error",
      };
  }
}
