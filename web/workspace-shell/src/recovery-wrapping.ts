// Passkey-bound workspace recovery wrapping primitives.
//
// Design: the workspace *root key material* is wrapped locally under each
// recovery credential. In the wired production path that key material is the
// existing 32-byte unlock secret (`key_source = "unlock_secret_v1"`), so the
// artifact and its derivation are unchanged. For a passkey, the wrapping key is
// derived from the WebAuthn PRF extension output:
//
//   PRF output --HKDF-SHA256(salt, info)--> AES-256-GCM wrapping key
//             --AES-GCM(key material)--> wrapped record (stored server-side)
//
// The PRF output, wrapping key and unwrapped key material never leave the browser
// in plaintext. A normal passkey signature is NOT key material and is never used
// here. PRF is optional in WebAuthn, so a mandatory high-entropy offline
// recovery secret remains the fallback.
//
// ROLLOUT STATUS
// Wired into the production unlock path as an ADDITIVE layer: a wrapper protects
// the existing unlock secret (`key_source = "unlock_secret_v1"`), so no
// artifact, KID or derivation changes and the mandatory offline recovery code
// keeps working. PRF support is optional and per-authenticator:
// `extractPrfOutput` returns `null` and the caller falls back to the offline
// code. A future random root key would be a new, explicitly versioned key
// source, not a change to these records. See docs/workspace-recovery.md.

export const RECOVERY_WRAPPER_VERSION = 1;
export const RECOVERY_WRAP_ALGORITHM = "HKDF-SHA256/AES-256-GCM";
export const RECOVERY_KDF_INFO = "evergreen/workspace-recovery/v1";
export const RECOVERY_AAD = "evergreen/workspace-recovery/v1";
export const RECOVERY_SALT_BYTES = 32;
export const RECOVERY_IV_BYTES = 12;
export const ROOT_KEY_BYTES = 32;

export class RecoveryWrappingError extends Error {
  readonly code:
    | "crypto_unavailable"
    | "invalid_root_key"
    | "invalid_record"
    | "prf_unavailable"
    | "unwrap_failed";

  constructor(code: RecoveryWrappingError["code"]) {
    super("workspace recovery wrapping unavailable");
    this.name = "RecoveryWrappingError";
    this.code = code;
  }
}

/** A server-storable wrapped root key. Contains no plaintext key material. */
export interface WrappedRootKey {
  version: number;
  algorithm: string;
  salt_b64: string;
  iv_b64: string;
  wrapped_root_key_b64: string;
}

const encoder = new TextEncoder();

function subtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new RecoveryWrappingError("crypto_unavailable");
  return subtle;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return globalThis.btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = globalThis.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Generate a fresh random workspace root key (never persisted in plaintext). */
export function generateWorkspaceRootKey(): Uint8Array {
  const key = new Uint8Array(ROOT_KEY_BYTES);
  globalThis.crypto.getRandomValues(key);
  return key;
}

/** Generate a random per-wrapper HKDF salt. */
export function generateRecoverySalt(): Uint8Array {
  const salt = new Uint8Array(RECOVERY_SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);
  return salt;
}

/**
 * Extract the WebAuthn PRF first-output from a credential, or `null` when the
 * authenticator did not return one. A null result means support is not verified
 * and the caller must use the offline recovery secret.
 */
export function extractPrfOutput(credential: unknown): Uint8Array | null {
  if (!credential || typeof credential !== "object") return null;
  const getResults = (credential as { getClientExtensionResults?: unknown })
    .getClientExtensionResults;
  if (typeof getResults !== "function") return null;
  let results: unknown;
  try {
    results = (getResults as () => unknown).call(credential);
  } catch {
    return null;
  }
  const prf = (results as { prf?: unknown } | null)?.prf as
    | { results?: { first?: unknown } }
    | undefined;
  const first = prf?.results?.first;
  if (!(first instanceof ArrayBuffer) && !(first instanceof Uint8Array)) return null;
  const bytes = first instanceof Uint8Array ? first : new Uint8Array(first);
  return bytes.length > 0 ? new Uint8Array(bytes) : null;
}

/** Derive the AES-256-GCM wrapping key from high-entropy input key material. */
export async function deriveRecoveryWrappingKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string = RECOVERY_KDF_INFO,
): Promise<CryptoKey> {
  if (ikm.length < 32) throw new RecoveryWrappingError("invalid_root_key");
  const subtle = subtleCrypto();
  const base = await subtle.importKey("raw", ikm as unknown as BufferSource, "HKDF", false, [
    "deriveKey",
  ]);
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as unknown as BufferSource,
      info: encoder.encode(info) as unknown as BufferSource,
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function requireRootKey(rootKey: Uint8Array): void {
  if (rootKey.length !== ROOT_KEY_BYTES || rootKey.every((b) => b === 0)) {
    throw new RecoveryWrappingError("invalid_root_key");
  }
}

/** Wrap a root key under derived key material; returns only the record. */
export async function wrapRootKey(
  ikm: Uint8Array,
  rootKey: Uint8Array,
  salt: Uint8Array = generateRecoverySalt(),
  info: string = RECOVERY_KDF_INFO,
): Promise<WrappedRootKey> {
  requireRootKey(rootKey);
  if (salt.length !== RECOVERY_SALT_BYTES) throw new RecoveryWrappingError("invalid_record");
  const wrappingKey = await deriveRecoveryWrappingKey(ikm, salt, info);
  const iv = new Uint8Array(RECOVERY_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);
  const ciphertext = await subtleCrypto().encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: encoder.encode(RECOVERY_AAD) as unknown as BufferSource,
    },
    wrappingKey,
    rootKey as unknown as BufferSource,
  );
  return {
    version: RECOVERY_WRAPPER_VERSION,
    algorithm: RECOVERY_WRAP_ALGORITHM,
    salt_b64: toBase64(salt),
    iv_b64: toBase64(iv),
    wrapped_root_key_b64: toBase64(new Uint8Array(ciphertext)),
  };
}

/** Unwrap a root key; throws `unwrap_failed` on any wrong key or tamper. */
export async function unwrapRootKey(
  ikm: Uint8Array,
  record: WrappedRootKey,
  info: string = RECOVERY_KDF_INFO,
): Promise<Uint8Array> {
  if (
    !record ||
    record.version !== RECOVERY_WRAPPER_VERSION ||
    record.algorithm !== RECOVERY_WRAP_ALGORITHM
  ) {
    throw new RecoveryWrappingError("invalid_record");
  }
  let salt: Uint8Array;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    salt = fromBase64(record.salt_b64);
    iv = fromBase64(record.iv_b64);
    ciphertext = fromBase64(record.wrapped_root_key_b64);
  } catch {
    throw new RecoveryWrappingError("invalid_record");
  }
  if (salt.length !== RECOVERY_SALT_BYTES || iv.length !== RECOVERY_IV_BYTES) {
    throw new RecoveryWrappingError("invalid_record");
  }
  const wrappingKey = await deriveRecoveryWrappingKey(ikm, salt, info);
  try {
    const plaintext = await subtleCrypto().decrypt(
      {
        name: "AES-GCM",
        iv: iv as unknown as BufferSource,
        additionalData: encoder.encode(RECOVERY_AAD) as unknown as BufferSource,
      },
      wrappingKey,
      ciphertext as unknown as BufferSource,
    );
    const rootKey = new Uint8Array(plaintext);
    requireRootKey(rootKey);
    return rootKey;
  } catch {
    throw new RecoveryWrappingError("unwrap_failed");
  }
}

/**
 * Offline fallback wrapper: the high-entropy recovery code is the input key
 * material. Still HKDF-extracted, so the raw code is never used as an AES key.
 */
export async function wrapWithRecoverySecret(
  rootKey: Uint8Array,
  recoverySecret: Uint8Array,
  salt: Uint8Array = generateRecoverySalt(),
): Promise<WrappedRootKey> {
  return wrapRootKey(recoverySecret, rootKey, salt);
}

export async function unwrapWithRecoverySecret(
  record: WrappedRootKey,
  recoverySecret: Uint8Array,
): Promise<Uint8Array> {
  return unwrapRootKey(recoverySecret, record);
}

/**
 * Passkey-bound wrapper. Returns `null` when the authenticator did not produce a
 * PRF output, so the caller falls back to the offline recovery code instead of
 * treating an ordinary assertion signature as key material.
 */
export async function wrapWithPrf(
  rootKey: Uint8Array,
  credential: unknown,
  salt: Uint8Array = generateRecoverySalt(),
): Promise<WrappedRootKey | null> {
  const prf = extractPrfOutput(credential);
  if (!prf) return null;
  try {
    // `deriveRecoveryWrappingKey` imports the PRF bytes into WebCrypto before
    // the async boundary returns, so the local copy can be zeroized here.
    return await wrapRootKey(prf, rootKey, salt);
  } finally {
    prf.fill(0);
  }
}

export async function unwrapWithPrf(
  record: WrappedRootKey,
  credential: unknown,
): Promise<Uint8Array | null> {
  const prf = extractPrfOutput(credential);
  if (!prf) return null;
  try {
    return await unwrapRootKey(prf, record);
  } finally {
    prf.fill(0);
  }
}
