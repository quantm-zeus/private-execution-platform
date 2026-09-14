import { base64ToBytes, bytesEqual, utf8Encode } from "../core/base64";
import { workspaceError } from "../core/errors";
import type { StreamEnvelope } from "./types";

/**
 * Session AEAD boundary owned by the Web Worker.
 *
 * The payload uses the platform WebCrypto AES-256-GCM primitive (audited
 * browser crypto) — never hand-rolled crypto. Keys are imported as
 * non-extractable `CryptoKey`s and are never persisted, exported or logged.
 */
export interface SessionDecryptor {
  decrypt(envelope: StreamEnvelope): Promise<Uint8Array>;
}

/** Default fail-closed decryptor: refuses every frame until a key is installed. */
export class UnavailableDecryptor implements SessionDecryptor {
  async decrypt(): Promise<Uint8Array> {
    throw workspaceError("capability_missing", "Realtime session key is not available.", {
      detail: "BR-5 key handoff missing",
    });
  }
}

export class WebCryptoDecryptor implements SessionDecryptor {
  private constructor(
    private readonly key: CryptoKey,
    private readonly expectedKid: string,
  ) {}

  /** Import a raw 32-byte AES-256-GCM key as non-extractable. */
  static async fromRawKey(raw: Uint8Array, expectedKid: string): Promise<WebCryptoDecryptor> {
    if (raw.length !== 32 || raw.every((byte) => byte === 0)) {
      throw workspaceError("auth", "Realtime session key is invalid.");
    }
    if (!globalThis.crypto?.subtle) {
      throw workspaceError("capability_missing", "WebCrypto is unavailable in this runtime.");
    }
    const keyBytes = new Uint8Array(raw);
    let key: CryptoKey;
    try {
      key = await globalThis.crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, [
        "decrypt",
      ]);
    } finally {
      keyBytes.fill(0);
    }
    return new WebCryptoDecryptor(key, expectedKid);
  }

  async decrypt(envelope: StreamEnvelope): Promise<Uint8Array> {
    if (envelope.kid !== this.expectedKid) {
      throw workspaceError("auth", "Stream envelope key id mismatch.");
    }
    const nonce = base64ToBytes(envelope.nonce);
    const ciphertext = base64ToBytes(envelope.ciphertext);
    // Bind the generic envelope metadata as AEAD associated data so a tampered
    // kid/sequence is rejected by authentication, not by post-hoc checks.
    const associatedData = utf8Encode(`kid=${envelope.kid};seq=${envelope.sequence}`);
    try {
      const plaintext = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: associatedData, tagLength: 128 },
        this.key,
        ciphertext,
      );
      return new Uint8Array(plaintext);
    } catch {
      throw workspaceError("protocol", "Stream frame failed authentication.", { retryable: false });
    } finally {
      nonce.fill(0);
      ciphertext.fill(0);
      associatedData.fill(0);
    }
  }
}

/** True when `kid` matches the configured session key id. */
export function kidMatches(envelope: StreamEnvelope, expectedKid: string): boolean {
  return bytesEqual(utf8Encode(envelope.kid), utf8Encode(expectedKid));
}
