import { base64ToBytes, bytesToBase64, utf8Encode } from "../core/base64";
import { workspaceError } from "../core/errors";

export interface SealContext {
  readonly kid: string;
  readonly sequence: number;
}

export interface SealedFrame {
  readonly nonce: string;
  readonly ciphertext: string;
}

/** Directional AEAD seal for outbound commands (worker/main-thread ownership). */
export interface SessionSealer {
  seal(context: SealContext, plaintext: Uint8Array<ArrayBuffer>): Promise<SealedFrame>;
}

export class WebCryptoSealer implements SessionSealer {
  private constructor(private readonly key: CryptoKey) {}

  static async fromRawKey(raw: Uint8Array): Promise<WebCryptoSealer> {
    if (raw.length !== 32 || raw.every((byte) => byte === 0)) {
      throw workspaceError("auth", "Command session key is invalid.");
    }
    if (!globalThis.crypto?.subtle) {
      throw workspaceError("capability_missing", "WebCrypto is unavailable in this runtime.");
    }
    const keyBytes = new Uint8Array(raw);
    try {
      const key = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"],
      );
      return new WebCryptoSealer(key);
    } finally {
      keyBytes.fill(0);
    }
  }

  async seal(context: SealContext, plaintext: Uint8Array<ArrayBuffer>): Promise<SealedFrame> {
    const nonce = new Uint8Array(12);
    globalThis.crypto.getRandomValues(nonce);
    const associatedData = utf8Encode(`kid=${context.kid};seq=${context.sequence}`);
    try {
      const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: associatedData, tagLength: 128 },
        this.key,
        plaintext,
      );
      return {
        nonce: bytesToBase64(nonce),
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
      };
    } finally {
      nonce.fill(0);
      associatedData.fill(0);
    }
  }
}

/** Test/utility helper: raw-key import from base64. */
export async function sealerFromBase64(keyB64: string): Promise<WebCryptoSealer> {
  return WebCryptoSealer.fromRawKey(base64ToBytes(keyB64));
}
