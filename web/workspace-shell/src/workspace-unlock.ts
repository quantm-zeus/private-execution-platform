// Single-ceremony passkey unlock orchestration.
//
// A normal login already performed exactly ONE WebAuthn ceremony
// (`authenticateWithPasskey`) that both authenticated the operator and returned
// the PRF output. This module turns that one assertion into the stable
// Workspace Root Secret:
//
//   assertion.credentialIdB64  -> select the matching active passkey wrapper
//   assertion.prfOutput        -> unwrap the root locally (never sent anywhere)
//   stable workspace fingerprint -> validate before the release is decrypted
//
// It deliberately has no access to `navigator.credentials`: with zero wrappers,
// with an unmatched credential, or with no PRF output it throws a typed
// `WorkspaceUnlockError` instead of prompting again. The caller then fails
// closed to the explicit `Having trouble signing in?` recovery action.

import { unwrapWithPrfOutput, type RecoveryWrapperRecord } from "./recovery-client.ts";
import {
  selectPasskeyUnlockWrappers,
  workspaceRootMatchesFingerprint,
} from "./workspace-root.ts";
import type { PasskeyAssertionResult } from "./passkey-auth.ts";

export type WorkspaceUnlockFailureCode =
  | "prf_unavailable"
  | "no_matching_wrapper"
  | "fingerprint_mismatch"
  | "unwrap_failed";

export class WorkspaceUnlockError extends Error {
  readonly code: WorkspaceUnlockFailureCode;

  constructor(code: WorkspaceUnlockFailureCode) {
    // Generic message: never carries root, PRF or wrapper material.
    super("workspace passkey unlock unavailable");
    this.name = "WorkspaceUnlockError";
    this.code = code;
  }
}

export interface WorkspaceUnlockDeps {
  unwrapWithPrfOutput?: typeof unwrapWithPrfOutput;
  matchesFingerprint?: typeof workspaceRootMatchesFingerprint;
}

/**
 * Unwrap the stable root from the single login assertion.
 *
 * The assertion's PRF output is zeroized on every path (success or failure) and
 * the caller owns the returned root bytes. The candidate wrapper set is filtered
 * to active passkey records and the one matching the asserted credential id is
 * used; no other wrapper is tried and no second WebAuthn ceremony is possible.
 */
export async function unwrapRootFromAssertion(
  assertion: PasskeyAssertionResult,
  wrappers: readonly RecoveryWrapperRecord[],
  fingerprintB64: string | null | undefined,
  deps: WorkspaceUnlockDeps = {},
): Promise<Uint8Array> {
  const prfOutput = assertion.prfOutput;
  if (!prfOutput || prfOutput.length === 0) {
    throw new WorkspaceUnlockError("prf_unavailable");
  }
  const unwrap = deps.unwrapWithPrfOutput ?? unwrapWithPrfOutput;
  const matches = deps.matchesFingerprint ?? workspaceRootMatchesFingerprint;
  try {
    const owner = selectPasskeyUnlockWrappers(wrappers).find(
      (record) => record.credential_id_b64 === assertion.credentialIdB64,
    );
    if (!owner) {
      throw new WorkspaceUnlockError("no_matching_wrapper");
    }
    let root: Uint8Array;
    try {
      root = await unwrap(prfOutput, owner);
    } catch {
      throw new WorkspaceUnlockError("unwrap_failed");
    }
    let matchesIdentity = false;
    try {
      matchesIdentity = await matches(root, fingerprintB64);
    } catch {
      matchesIdentity = false;
    }
    if (!matchesIdentity) {
      // The unwrapped bytes are a wrong secret (for example a substituted
      // wrapper). Drop them before reporting the mismatch.
      root.fill(0);
      throw new WorkspaceUnlockError("fingerprint_mismatch");
    }
    return root;
  } finally {
    prfOutput.fill(0);
  }
}
