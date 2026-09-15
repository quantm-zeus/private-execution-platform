// Minimal base64 codecs (no `atob`/`btoa` dependency so the same code runs in
// the worker, main thread and jsdom). Not used for any secret at rest.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += ALPHABET[(triple >> 18) & 63];
    out += ALPHABET[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? ALPHABET[(triple >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? ALPHABET[triple & 63] : "=";
  }
  return out;
}

const LOOKUP: Record<string, number> = (() => {
  const table: Record<string, number> = {};
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET[i]!] = i;
  return table;
})();

export function base64ToBytes(input: string): Uint8Array<ArrayBuffer> {
  const clean = input.replace(/[\r\n\s]/g, "");
  // Strict-enough validation: reject non-canonical alphabets, misplaced
  // padding, and impossible lengths (`length % 4 === 1`) instead of silently
  // decoding garbage. Both padded and unpadded standard base64 are accepted.
  if (clean.length === 0) throw new Error("empty base64 input");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error("invalid base64 character");
  if (clean.length % 4 === 1) throw new Error("invalid base64 length");
  if (clean.includes("=") && clean.length % 4 !== 0) throw new Error("invalid base64 padding");
  let body = clean;
  if (body.endsWith("==")) body = body.slice(0, -2);
  else if (body.endsWith("=")) body = body.slice(0, -1);
  const out = new Uint8Array(Math.floor((body.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (const char of body) {
    const value = LOOKUP[char];
    if (value === undefined) throw new Error("invalid base64 character");
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (acc >> bits) & 0xff;
    }
  }
  if (index !== out.length) throw new Error("invalid base64 length");
  return out;
}

export function utf8Encode(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/** Constant-time-ish equality for small public values (not a secret comparison). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
