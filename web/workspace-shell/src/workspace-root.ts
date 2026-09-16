// Stable Workspace Root Key contract (v2).
//
// One workspace has exactly one 32-byte **Workspace Root Secret**, generated in
// the browser exactly once during initial setup. The stable workspace recipient
// keypair is derived from that root secret under a **fixed Root-Key-V2 domain**,
// entirely independent of any release id or artifact KID:
//
//   * the workspace public identity is the same for every release;
//   * a future release is sealed to the same public key, with no reseal and no
//     operator involvement;
//   * the artifact KID is release metadata bound into the HPKE envelope, never
//     part of the recipient identity;
//   * per-artifact cryptographic freshness comes from the HPKE envelope
//     randomness plus the release metadata (release id, artifact digest) bound
//     to the artifact over the authenticated channel.
//
// The root secret itself is never persisted anywhere. It is wrapped client-side
// under (a) a passkey WebAuthn PRF output and (b) a separate high-entropy offline
// recovery code; only the opaque wrappers are uploaded. The server can therefore
// never observe the root secret, the recovery code, the PRF output or an unwrap
// key.
//
// The legacy release-bound model (`unlock_secret_v1`) remains parseable only as
// bounded migration code; the normal flow never uses it.

import {
  WORKSPACE_ROOT_CONTEXT_B64,
  WORKSPACE_ROOT_VERSION,
  fromBase64,
  loadWasm,
  toBase64,
} from "./unlock-runtime.ts";
import {
  RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  RecoveryWrappingError,
  unwrapRootKey,
  wrapRootKey,
  type WrappedRootKey,
} from "./recovery-wrapping.ts";
import { WasmWorkspaceRootKey } from "./wasm/crypto-envelope-wasm.js";

export const WORKSPACE_ROOT_SECRET_BYTES = 32;
export { WORKSPACE_ROOT_CONTEXT_B64, WORKSPACE_ROOT_VERSION };
/** Wrapper key source for the stable root; never reinterpreted as `unlock_secret_v1`. */
export const WORKSPACE_ROOT_KEY_SOURCE = RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2;
/** High-entropy offline recovery code length in bytes. */
export const RECOVERY_CODE_BYTES = 32;

/**
 * Stable identifier for the offline-recovery wrapper. It is not a WebAuthn
 * credential; it marks the record the recovery-code form unwraps. Losing the
 * recovery code and every passkey is intentionally unrecoverable.
 */
export const OFFLINE_RECOVERY_CREDENTIAL_B64 = toBase64(
  new TextEncoder().encode("evergreen-offline-recovery/v2"),
);

/** Is this the offline recovery wrapper's reserved credential identifier? */
export function isOfflineRecoveryCredential(credentialIdB64: string): boolean {
  return credentialIdB64 === OFFLINE_RECOVERY_CREDENTIAL_B64;
}

/**
 * The passkey wrappers a normal login may try. Revoked credentials are excluded
 * (a revoked passkey can never unlock), as is the offline recovery record, which
 * is used only by the explicit recovery-code path.
 */
export function selectPasskeyUnlockWrappers<
  T extends { credential_id_b64: string; revoked_at_ms: number | null },
>(records: readonly T[]): T[] {
  return records.filter(
    (record) =>
      record.revoked_at_ms === null &&
      !isOfflineRecoveryCredential(record.credential_id_b64),
  );
}

export type WorkspaceRootErrorCode =
  | "crypto_unavailable"
  | "invalid_root"
  | "invalid_recovery_code"
  | "unwrap_failed";

export class WorkspaceRootError extends Error {
  readonly code: WorkspaceRootErrorCode;

  constructor(code: WorkspaceRootErrorCode) {
    // Generic message: never carries root, recovery or PRF material.
    super("workspace root key operation failed");
    this.name = "WorkspaceRootError";
    this.code = code;
  }
}

function randomBytes(length: number): Uint8Array {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
    throw new WorkspaceRootError("crypto_unavailable");
  }
  const bytes = new Uint8Array(length);
  cryptoObj.getRandomValues(bytes);
  return bytes;
}

/** A valid root/IKM is exactly 32 bytes and not all-zero. */
export function isValidWorkspaceRootSecret(bytes: unknown): bytes is Uint8Array {
  return (
    bytes instanceof Uint8Array &&
    bytes.length === WORKSPACE_ROOT_SECRET_BYTES &&
    !bytes.every((byte) => byte === 0)
  );
}

/** Generate a fresh 32-byte Workspace Root Secret. Never persisted in plaintext. */
export function generateWorkspaceRootSecret(): Uint8Array {
  return randomBytes(WORKSPACE_ROOT_SECRET_BYTES);
}

/**
 * Generate a separate high-entropy offline recovery code. This is shown exactly
 * once during initial setup; it is never the root secret and never sent to the
 * server.
 */
export function generateRecoveryCode(): string {
  return toBase64(randomBytes(RECOVERY_CODE_BYTES));
}

/**
 * Decode an offline recovery code to its 32 bytes. Whitespace is tolerated and
 * stripped, but a non-canonical or wrong-length code is refused so two inputs
 * can never map to the same bytes.
 */
export function decodeRecoveryCode(input: string): Uint8Array {
  const clean = typeof input === "string" ? input.replace(/[\r\n\s]/g, "") : "";
  if (!clean) throw new WorkspaceRootError("invalid_recovery_code");
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(clean);
  } catch {
    throw new WorkspaceRootError("invalid_recovery_code");
  }
  if (!isValidWorkspaceRootSecret(bytes) || toBase64(bytes) !== clean) {
    throw new WorkspaceRootError("invalid_recovery_code");
  }
  return bytes;
}

/**
 * Derive the stable workspace X25519 public key for a root secret.
 *
 * The Root-Key-V2 derivation takes no KID and no release context, so this value
 * is byte-identical across releases and KID rotations. Private key material stays
 * inside WASM and is discarded on free.
 */
export async function deriveWorkspaceRootPublicKey(
  rootSecret: Uint8Array,
): Promise<Uint8Array> {
  if (!isValidWorkspaceRootSecret(rootSecret)) {
    throw new WorkspaceRootError("invalid_root");
  }
  try {
    await loadWasm();
  } catch {
    throw new WorkspaceRootError("crypto_unavailable");
  }
  const rootCopy = new Uint8Array(rootSecret);
  let key: WasmWorkspaceRootKey | null = null;
  try {
    key = new WasmWorkspaceRootKey(rootCopy);
    return new Uint8Array(key.public_key());
  } catch {
    throw new WorkspaceRootError("crypto_unavailable");
  } finally {
    rootCopy.fill(0);
    if (key) {
      try {
        key.free();
      } catch {
        // A throwing free must not mask a typed error already in flight.
      }
    }
  }
}

/** SHA-256 of the stable public key, standard base64 (matches the server). */
export async function deriveWorkspaceRootFingerprint(
  rootSecret: Uint8Array,
): Promise<string> {
  const publicKey = await deriveWorkspaceRootPublicKey(rootSecret);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") {
    throw new WorkspaceRootError("crypto_unavailable");
  }
  try {
    const digest = await subtle.digest(
      "SHA-256",
      publicKey as unknown as BufferSource,
    );
    return toBase64(new Uint8Array(digest));
  } catch {
    throw new WorkspaceRootError("crypto_unavailable");
  }
}

/**
 * Constant-shape helper: does this root secret derive the persisted workspace
 * identity? A wrong recovery code unwraps to the wrong secret and is rejected
 * here, locally, before it can be used.
 */
export async function workspaceRootMatchesFingerprint(
  rootSecret: Uint8Array,
  expectedFingerprintB64: string | null | undefined,
): Promise<boolean> {
  if (typeof expectedFingerprintB64 !== "string" || expectedFingerprintB64.length === 0) {
    return false;
  }
  let derived: string;
  try {
    derived = await deriveWorkspaceRootFingerprint(rootSecret);
  } catch {
    return false;
  }
  return derived === expectedFingerprintB64;
}

/** Wrap the root secret under the offline recovery code (v2 key source). */
export async function wrapWorkspaceRootForRecovery(
  rootSecret: Uint8Array,
  recoveryCodeBytes: Uint8Array,
): Promise<WrappedRootKey> {
  if (!isValidWorkspaceRootSecret(rootSecret) || !isValidWorkspaceRootSecret(recoveryCodeBytes)) {
    throw new WorkspaceRootError("invalid_root");
  }
  try {
    return await wrapRootKey(
      recoveryCodeBytes,
      rootSecret,
      undefined,
      undefined,
      "",
      WORKSPACE_ROOT_KEY_SOURCE,
    );
  } catch (error) {
    throw asWorkspaceRootError(error);
  }
}

/** Unwrap the root secret from an offline-recovery wrapper. Fails closed. */
export async function unwrapWorkspaceRootWithRecovery(
  record: WrappedRootKey,
  recoveryCodeBytes: Uint8Array,
): Promise<Uint8Array> {
  if (!isValidWorkspaceRootSecret(recoveryCodeBytes)) {
    throw new WorkspaceRootError("invalid_recovery_code");
  }
  try {
    return await unwrapRootKey(
      recoveryCodeBytes,
      record,
      undefined,
      "",
      WORKSPACE_ROOT_KEY_SOURCE,
    );
  } catch (error) {
    throw asWorkspaceRootError(error);
  }
}

/** Unwrap the root secret from a passkey-PRF wrapper. Fails closed. */
export async function unwrapWorkspaceRootWithPrf(
  record: WrappedRootKey,
  prfOutput: Uint8Array,
  credentialIdB64: string,
): Promise<Uint8Array> {
  if (!isValidWorkspaceRootSecret(prfOutput)) {
    throw new WorkspaceRootError("unwrap_failed");
  }
  try {
    return await unwrapRootKey(
      prfOutput,
      record,
      undefined,
      credentialIdB64,
      WORKSPACE_ROOT_KEY_SOURCE,
    );
  } catch (error) {
    throw asWorkspaceRootError(error);
  }
}

function asWorkspaceRootError(error: unknown): WorkspaceRootError {
  if (error instanceof WorkspaceRootError) return error;
  if (error instanceof RecoveryWrappingError) {
    return new WorkspaceRootError(
      error.code === "invalid_root_key" ? "invalid_root" : "unwrap_failed",
    );
  }
  return new WorkspaceRootError("unwrap_failed");
}
