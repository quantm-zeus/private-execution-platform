import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64, utf8Encode } from "../core/base64";
import { WebCryptoDecryptor } from "./decryptor";
import { WebCryptoSealer } from "./sealer";
import type { StreamEnvelope } from "./types";

const KID = "kid-1";
const rawKey = new Uint8Array(32).map((_, index) => (index + 1) & 0xff);

describe("WebCryptoDecryptor (real AEAD)", () => {
  it("round-trips a sealed frame and rejects tamper and wrong associated data", async () => {
    const sealer = await WebCryptoSealer.fromRawKey(rawKey);
    const decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, KID);
    const sealed = await sealer.seal(
      { kid: KID, sequence: 7 },
      utf8Encode(JSON.stringify({ op: "snapshot", payload: { value: 1 } })),
    );
    const envelope: StreamEnvelope = {
      kid: KID,
      sequence: 7,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
    };

    const plain = await decryptor.decrypt(envelope);
    expect(new TextDecoder().decode(plain)).toContain("snapshot");

    // A single flipped ciphertext bit must fail AES-GCM authentication.
    const tampered = base64ToBytes(sealed.ciphertext);
    tampered[0] ^= 0xff;
    await expect(
      decryptor.decrypt({ ...envelope, ciphertext: bytesToBase64(tampered) }),
    ).rejects.toMatchObject({ code: "protocol" });

    // The sequence is bound as AEAD associated data, so tampering with it must
    // also fail authentication (not merely a post-decryption check).
    await expect(decryptor.decrypt({ ...envelope, sequence: 8 })).rejects.toMatchObject({
      code: "protocol",
    });

    // A wrong key id is rejected before any decryption is attempted.
    await expect(decryptor.decrypt({ ...envelope, kid: "other-kid" })).rejects.toMatchObject({
      code: "auth",
    });
  });

  it("rejects an invalid raw key", async () => {
    await expect(WebCryptoDecryptor.fromRawKey(new Uint8Array(32), KID)).rejects.toMatchObject({
      code: "auth",
    });
    await expect(WebCryptoDecryptor.fromRawKey(new Uint8Array(16), KID)).rejects.toMatchObject({
      code: "auth",
    });
  });
});
