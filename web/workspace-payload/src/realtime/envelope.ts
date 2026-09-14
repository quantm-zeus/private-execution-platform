import { base64ToBytes } from "../core/base64";
import { workspaceError } from "../core/errors";
import type { StreamEnvelope } from "./types";

const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
const AEAD_TAG_BYTES = 16;
const NONCE_BYTES = 12;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Strictly validate an untrusted cleartext envelope. Rejects oversized bodies,
 * malformed base64 and out-of-range sequences before any decryption happens.
 */
export function validateEnvelope(raw: unknown): StreamEnvelope {
  if (!isRecord(raw)) throw workspaceError("protocol", "Malformed stream envelope.");
  const { kid, nonce, sequence, ciphertext } = raw;
  if (typeof kid !== "string" || kid.length === 0 || kid.length > 64 || !/^[A-Za-z0-9+/=_:-]+$/.test(kid)) {
    throw workspaceError("protocol", "Malformed stream envelope key id.");
  }
  if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > 64) {
    throw workspaceError("protocol", "Malformed stream envelope nonce.");
  }
  let nonceBytes: Uint8Array;
  try {
    nonceBytes = base64ToBytes(nonce);
  } catch {
    throw workspaceError("protocol", "Malformed stream envelope nonce encoding.");
  }
  if (nonceBytes.length !== NONCE_BYTES) {
    throw workspaceError("protocol", "Stream envelope nonce must be 12 bytes.");
  }
  if (
    typeof sequence !== "number" ||
    !Number.isSafeInteger(sequence) ||
    sequence < 0
  ) {
    throw workspaceError("protocol", "Malformed stream envelope sequence.");
  }
  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    throw workspaceError("protocol", "Malformed stream envelope ciphertext.");
  }
  let ciphertextBytes: Uint8Array;
  try {
    ciphertextBytes = base64ToBytes(ciphertext);
  } catch {
    throw workspaceError("protocol", "Malformed stream envelope ciphertext encoding.");
  }
  if (ciphertextBytes.length < AEAD_TAG_BYTES || ciphertextBytes.length > MAX_CIPHERTEXT_BYTES) {
    throw workspaceError("protocol", "Stream envelope ciphertext size out of range.");
  }
  return { kid, nonce, sequence, ciphertext };
}

export function parseEnvelopeText(text: string): StreamEnvelope {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw workspaceError("protocol", "Stream envelope was not valid JSON.");
  }
  return validateEnvelope(raw);
}
