// Browser client for passkey-bound workspace recovery wrappers.
//
// The server stores only opaque wrapped key material plus public metadata; this
// module lists it, fetches a proof-of-possession challenge, and submits a
// locally derived wrapper. It never receives or sends the PRF output, the
// wrapping key, or the unwrapped workspace secret.
//
// Every failure is a typed, privacy-safe `RecoveryClientError`; no server text,
// path, key, or ciphertext is propagated.

import {
  RECOVERY_IV_BYTES,
  RECOVERY_KEY_SOURCE,
  RECOVERY_SALT_BYTES,
  RECOVERY_WRAPPER_VERSION,
  RECOVERY_WRAPPED_ROOT_KEY_BYTES,
  RECOVERY_WRAP_ALGORITHM,
  unwrapRootKey,
  type WrappedRootKey,
} from "./recovery-wrapping.ts";

export interface RecoveryWrapperRecord extends WrappedRootKey {
  credential_id_b64: string;
  label: string;
  key_source: string;
  created_at_ms: number;
  last_used_at_ms: number | null;
  revoked_at_ms: number | null;
}

export type RecoveryClientErrorCode =
  | "recovery_unavailable"
  | "recovery_unauthorized"
  | "recovery_malformed"
  | "recovery_conflict"
  | "recovery_rejected";

export class RecoveryClientError extends Error {
  readonly code: RecoveryClientErrorCode;
  readonly status: number | undefined;

  constructor(code: RecoveryClientErrorCode, status?: number) {
    super("workspace recovery unavailable");
    this.name = "RecoveryClientError";
    this.code = code;
    this.status = status;
  }
}

export const DEFAULT_RECOVERY_URL = "/internal/workspace/recovery";
export const DEFAULT_RECOVERY_CHALLENGE_URL =
  "/internal/workspace/recovery/challenge";
export const DEFAULT_RECOVERY_REVOKE_URL = "/internal/workspace/recovery/revoke";
export const DEFAULT_RECOVERY_TOUCH_URL = "/internal/workspace/recovery/touch";

/** Upper bound mirroring the server's per-workspace wrapper budget. */
const MAX_WRAPPERS = 32;

/** The server-sealed proof-of-possession nonce is a fixed 32-byte value. */
export const RECOVERY_CHALLENGE_BYTES = 32;

/**
 * The only wrapper key source this shell can unwrap. A record for an unknown
 * source (e.g. a future random-root-key migration) is rejected rather than
 * reinterpreted as the unlock secret. Aliased to the wrapping primitive's
 * constant so the AAD and server-stored value can never drift.
 */
export const SUPPORTED_KEY_SOURCE = RECOVERY_KEY_SOURCE;

export interface RecoveryClientOptions {
  fetchFn?: typeof fetch;
  listUrl?: string;
  challengeUrl?: string;
  revokeUrl?: string;
  touchUrl?: string;
}

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += BASE64_ALPHABET[(triple >> 18) & 63];
    out += BASE64_ALPHABET[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? BASE64_ALPHABET[(triple >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? BASE64_ALPHABET[triple & 63] : "=";
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new RecoveryClientError("recovery_malformed");
  }
  return value;
}

function optionalTimestamp(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new RecoveryClientError("recovery_malformed");
  }
  return value;
}

function parseWrapperRecord(value: unknown): RecoveryWrapperRecord {
  if (!isRecord(value)) throw new RecoveryClientError("recovery_malformed");
  const version = value.version;
  if (version !== RECOVERY_WRAPPER_VERSION) {
    throw new RecoveryClientError("recovery_malformed");
  }
  const createdAt = value.created_at_ms;
  if (typeof createdAt !== "number" || !Number.isFinite(createdAt)) {
    throw new RecoveryClientError("recovery_malformed");
  }
  const keySource = requireString(value.key_source, 64);
  if (keySource !== SUPPORTED_KEY_SOURCE) {
    throw new RecoveryClientError("recovery_malformed");
  }
  // A record for any other algorithm is not something this shell can unwrap, so
  // it is skipped at parse rather than surfaced as a broken credential.
  const algorithm = requireString(value.algorithm, 64);
  if (algorithm !== RECOVERY_WRAP_ALGORITHM) {
    throw new RecoveryClientError("recovery_malformed");
  }
  // Validate decoded lengths here so a truncated or oversized field is rejected
  // at parse (and the malformed record skipped) instead of surfacing later as an
  // opaque unwrap failure that would look like a wrong PRF output.
  const salt = fromBase64(requireString(value.salt_b64, 128));
  if (salt.length !== RECOVERY_SALT_BYTES) {
    throw new RecoveryClientError("recovery_malformed");
  }
  const iv = fromBase64(requireString(value.iv_b64, 64));
  if (iv.length !== RECOVERY_IV_BYTES) {
    throw new RecoveryClientError("recovery_malformed");
  }
  const wrappedRootKey = fromBase64(
    requireString(value.wrapped_root_key_b64, 256),
  );
  if (wrappedRootKey.length !== RECOVERY_WRAPPED_ROOT_KEY_BYTES) {
    throw new RecoveryClientError("recovery_malformed");
  }
  return {
    credential_id_b64: requireString(value.credential_id_b64, 2048),
    label: requireString(value.label, 64),
    version,
    algorithm,
    key_source: keySource,
    salt_b64: requireString(value.salt_b64, 128),
    iv_b64: requireString(value.iv_b64, 64),
    wrapped_root_key_b64: requireString(value.wrapped_root_key_b64, 256),
    created_at_ms: createdAt,
    last_used_at_ms: optionalTimestamp(value.last_used_at_ms),
    revoked_at_ms: optionalTimestamp(value.revoked_at_ms),
  };
}

/** Parse the authenticated wrapper list. Read-only; never mutates the input. */
export function parseRecoveryWrappers(input: unknown): RecoveryWrapperRecord[] {
  if (!isRecord(input) || !Array.isArray(input.wrappers)) {
    throw new RecoveryClientError("recovery_malformed");
  }
  if (input.wrappers.length > MAX_WRAPPERS) {
    throw new RecoveryClientError("recovery_malformed");
  }
  // Parse per record and drop only the offending entry. A single malformed or
  // future-scheme record (corruption, a newer client, a bad write) must not
  // disable passkey recovery through every remaining valid credential; the
  // mandatory offline recovery code stays the fallback either way.
  const records: RecoveryWrapperRecord[] = [];
  for (const wrapper of input.wrappers) {
    try {
      records.push(parseWrapperRecord(wrapper));
    } catch {
      // Skip the invalid record; never surface its content.
    }
  }
  return records;
}

async function classify(response: Response): Promise<never> {
  if (response.status === 401 || response.status === 403) {
    throw new RecoveryClientError("recovery_unauthorized", response.status);
  }
  if (response.status === 409) {
    throw new RecoveryClientError("recovery_conflict", response.status);
  }
  throw new RecoveryClientError("recovery_rejected", response.status);
}

export async function fetchRecoveryWrappers(
  options: RecoveryClientOptions = {},
): Promise<RecoveryWrapperRecord[]> {
  const fetchImpl = options.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(options.listUrl ?? DEFAULT_RECOVERY_URL, {
      method: "GET",
      credentials: "same-origin",
      redirect: "error",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new RecoveryClientError("recovery_unavailable");
  }
  if (!response.ok) return classify(response);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new RecoveryClientError("recovery_malformed");
  }
  return parseRecoveryWrappers(body);
}

export interface RecoveryChallenge {
  challengeId: string;
  sealed: Uint8Array;
}

/** Fetch a server-sealed nonce. Throws typed errors, never server text. */
export async function requestRecoveryChallenge(
  options: RecoveryClientOptions = {},
): Promise<RecoveryChallenge> {
  const fetchImpl = options.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(
      options.challengeUrl ?? DEFAULT_RECOVERY_CHALLENGE_URL,
      {
        method: "POST",
        credentials: "same-origin",
        redirect: "error",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: "",
      },
    );
  } catch {
    throw new RecoveryClientError("recovery_unavailable");
  }
  if (!response.ok) return classify(response);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new RecoveryClientError("recovery_malformed");
  }
  if (!isRecord(body)) throw new RecoveryClientError("recovery_malformed");
  const challengeId = requireString(body.challenge_id, 64);
  const sealedB64 = requireString(body.sealed_challenge_b64, 4096);
  const sealed = fromBase64(sealedB64);
  return { challengeId, sealed };
}

export function fromBase64(value: string): Uint8Array {
  const clean = value.replace(/\s/g, "");
  const revLookup: Record<string, number> = {};
  for (let i = 0; i < 64; i++) revLookup[BASE64_ALPHABET[i]] = i;
  let valid = clean;
  if (clean.endsWith("==")) valid = clean.slice(0, -2);
  else if (clean.endsWith("=")) valid = clean.slice(0, -1);
  const out = new Uint8Array(Math.floor((valid.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (const char of valid) {
    const mapped = revLookup[char];
    if (mapped === undefined) throw new RecoveryClientError("recovery_malformed");
    acc = (acc << 6) | mapped;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (acc >> bits) & 0xff;
    }
  }
  if (index !== out.length) throw new RecoveryClientError("recovery_malformed");
  return out;
}

/**
 * Prove possession of the workspace key. `decrypt` is the in-memory workspace
 * key's artifact decrypt (the server seals a random nonce to the enrolled
 * public key, exactly like the release artifact). The server learns only the
 * challenge it chose, never the secret.
 */
export async function beginRecoveryProof(
  decrypt: (sealed: Uint8Array) => Uint8Array,
  options: RecoveryClientOptions = {},
): Promise<{ challengeId: string; proofB64: string }> {
  const challenge = await requestRecoveryChallenge(options);
  let nonce: Uint8Array;
  try {
    nonce = decrypt(challenge.sealed);
  } catch {
    throw new RecoveryClientError("recovery_rejected");
  }
  if (nonce.length !== RECOVERY_CHALLENGE_BYTES) {
    nonce.fill(0);
    throw new RecoveryClientError("recovery_rejected");
  }
  const proofB64 = toBase64(nonce);
  nonce.fill(0);
  return { challengeId: challenge.challengeId, proofB64 };
}

export interface AddRecoveryWrapperInput {
  challengeId: string;
  proofB64: string;
  credentialIdB64: string;
  label: string;
  record: WrappedRootKey;
}

export async function addRecoveryWrapper(
  input: AddRecoveryWrapperInput,
  options: RecoveryClientOptions = {},
): Promise<void> {
  const fetchImpl = options.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(options.listUrl ?? DEFAULT_RECOVERY_URL, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: input.challengeId,
        proof_b64: input.proofB64,
        wrapper: {
          credential_id_b64: input.credentialIdB64,
          label: input.label,
          version: input.record.version,
          algorithm: input.record.algorithm,
          key_source: input.record.key_source,
          salt_b64: input.record.salt_b64,
          iv_b64: input.record.iv_b64,
          wrapped_root_key_b64: input.record.wrapped_root_key_b64,
        },
      }),
    });
  } catch {
    throw new RecoveryClientError("recovery_unavailable");
  }
  if (!response.ok) return classify(response);
}

export async function revokeRecoveryWrapper(
  input: { challengeId: string; proofB64: string; credentialIdB64: string },
  options: RecoveryClientOptions = {},
): Promise<void> {
  const fetchImpl = options.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(options.revokeUrl ?? DEFAULT_RECOVERY_REVOKE_URL, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: input.challengeId,
        proof_b64: input.proofB64,
        credential_id_b64: input.credentialIdB64,
      }),
    });
  } catch {
    throw new RecoveryClientError("recovery_unavailable");
  }
  if (!response.ok) return classify(response);
}

/**
 * Record a coarse last-used timestamp. Requires the same proof of possession as
 * add/revoke, so an unproven caller cannot forge the device audit signal.
 */
export async function touchRecoveryWrapper(
  input: { challengeId: string; proofB64: string; credentialIdB64: string },
  options: RecoveryClientOptions = {},
): Promise<void> {
  const fetchImpl = options.fetchFn ?? fetch;
  try {
    await fetchImpl(options.touchUrl ?? DEFAULT_RECOVERY_TOUCH_URL, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: input.challengeId,
        proof_b64: input.proofB64,
        credential_id_b64: input.credentialIdB64,
      }),
    });
  } catch {
    // Non-authoritative metadata; a failure never blocks unlock.
  }
}

/**
 * Unwrap the workspace secret with a PRF output and a stored record. Returns the
 * raw secret bytes; the caller must zeroize them.
 */
export async function unwrapWithPrfOutput(
  prfOutput: Uint8Array,
  record: WrappedRootKey & { credential_id_b64?: string },
): Promise<Uint8Array> {
  // Bind the owning credential id into the AAD so a rewritten record cannot be
  // reassigned to another credential without failing authentication.
  return unwrapRootKey(prfOutput, record, undefined, record.credential_id_b64 ?? "");
}
