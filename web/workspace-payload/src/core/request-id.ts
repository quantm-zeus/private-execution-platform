import { workspaceError } from "./errors";

/**
 * Per-request random challenge. It travels only inside the AEAD request and is
 * echoed inside the AEAD response, so a captured frame or a replayed older
 * response cannot be substituted for the answer to this request.
 *
 * A predictable value would weaken the authenticated-echo binding, so the
 * absence of a cryptographically secure RNG fails closed rather than falling
 * back to `Math.random()`.
 */
export function randomRequestId(): string {
  const cryptoObj: Crypto | undefined = globalThis.crypto;
  if (cryptoObj !== undefined && typeof cryptoObj.randomUUID === "function") {
    return cryptoObj.randomUUID();
  }
  if (cryptoObj !== undefined && typeof cryptoObj.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  throw workspaceError("protocol", "A cryptographically secure request id could not be generated.");
}
