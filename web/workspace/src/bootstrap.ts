// Browser-side bootstrap for the encrypted private workspace.
//
// IMPLEMENTED (fail-closed, node-tested):
//   1. POST /internal/artifact/grant with credentials: "include" (same-origin
//      only). Response JSON: { grant_id, kid, recipient_public_key }.
//   2. Server offer validation: kid(16) + recipient_public_key(32), base64,
//      strict lengths.
//   3. Wire-format mirroring of crates/crypto-envelope (documented constants
//      below, byte-for-byte): HPKE info construction, exporter labels,
//      envelope header kid(16) || nonce(12) || sequence(u64 BE), AAD binding
//      kid || sequence.
//   4. POST /internal/artifact body construction and envelope parsing of the
//      response, including strict sequence != 0.
//
// DEFERRED, FAIL-CLOSED (operator decision recorded in TASKS P0-4b and
// docs/decisions/phase0-artifact-delivery.md): the actual HPKE Base-mode
// initiation and ChaCha20-Poly1305 decryption. WebCrypto has no RFC 9180
// key schedule and no ChaCha20-Poly1305; hand-rolling them in JS would be
// unaudited custom crypto. hpkeInitiate() therefore throws until an audited
// implementation (e.g. WASM build of the reviewed crypto-envelope crate)
// lands.
//
// No plaintext, key material, or derived secret is ever written to storage:
// no localStorage, sessionStorage, IndexedDB, or cookies. If any step fails,
// the bootstrap fails closed with a neutral message and no partial state.

const GRANT_ENDPOINT = "/internal/artifact/grant";
const ARTIFACT_ENDPOINT = "/internal/artifact";

const HPKE_VERSION = 1;
const HPKE_SUITE_ID = 1;
const KID_LEN = 16;
const PK_LEN = 32;
const NONCE_LEN = 12;
const ENVELOPE_HEADER_LEN = KID_LEN + NONCE_LEN + 8;

const HANDSHAKE_INFO = new TextEncoder().encode("private-execution/hpke-session/v1");
const EXPORTER_C2S = new TextEncoder().encode("private-execution app session c2s v1");
const EXPORTER_S2C = new TextEncoder().encode("private-execution app session s2c v1");

export interface ServerOffer {
  kid: Uint8Array;
  recipientPublicKey: Uint8Array;
}

interface InitiatedArtifact {
  encapsulated: Uint8Array;
  dhSecret: Uint8Array;
}

export class BootstrapError extends Error {}

function fail(message: string): never {
  throw new BootstrapError(message);
}

function base64ToBytes(value: unknown, expectedLen: number, what: string): Uint8Array {
  if (typeof value !== "string") fail(`invalid ${what}`);
  const normalized = atob(value);
  const bytes = new Uint8Array(normalized.length);
  for (let i = 0; i < normalized.length; i += 1) bytes[i] = normalized.charCodeAt(i);
  if (bytes.length !== expectedLen) fail(`invalid ${what} length`);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function canonicalHandshakeInfo(offer: ServerOffer): Uint8Array {
  const suite = new Uint8Array(2);
  new DataView(suite.buffer).setUint16(0, HPKE_SUITE_ID, false);
  return concat(HANDSHAKE_INFO, new Uint8Array([HPKE_VERSION]), suite, offer.kid, offer.recipientPublicKey);
}

function envelopeAad(kid: Uint8Array, sequence: number): Uint8Array {
  const seq = new Uint8Array(8);
  new DataView(seq.buffer).setBigUint64(0, BigInt(sequence), false);
  return concat(kid, seq);
}

// HPKE initiation is intentionally NOT hand-rolled: WebCrypto exposes X25519
// and HKDF but no RFC 9180 key schedule, and ChaCha20-Poly1305 is absent
// entirely. Reimplementing HPKE in JS would be unaudited custom crypto, which
// the Phase 0 fail-closed rules forbid. This fails closed until an audited
// browser HPKE implementation (e.g. a WASM build of the already-reviewed Rust
// crypto-envelope crate) is provided — an explicit operator decision recorded
// in TASKS P0-4b and docs/decisions/phase0-artifact-delivery.md. Everything
// up to and after that seam (grant fetch, offer validation, wire format,
// envelope parsing) is implemented here and node-tested.
async function hpkeInitiate(_offer: ServerOffer): Promise<InitiatedArtifact> {
  return fail("hpke initiator unavailable") as never;
}

export interface Envelope {
  kid: Uint8Array;
  nonce: Uint8Array;
  sequence: bigint;
  ciphertext: Uint8Array;
}

export function parseEnvelope(wire: Uint8Array): Envelope {
  if (!(wire instanceof Uint8Array) || wire.length <= ENVELOPE_HEADER_LEN) fail("invalid envelope");
  const kid = wire.slice(0, KID_LEN);
  const nonce = wire.slice(KID_LEN, KID_LEN + NONCE_LEN);
  const view = new DataView(wire.buffer, wire.byteOffset + KID_LEN + NONCE_LEN, 8);
  const sequence = view.getBigUint64(0, false);
  if (sequence === 0n) fail("invalid envelope sequence");
  const ciphertext = wire.slice(ENVELOPE_HEADER_LEN);
  return { kid, nonce, sequence, ciphertext };
}

// Full bootstrap: grant -> initiate -> fetch -> parse. Returns the raw
// ciphertext envelope pieces; decryption is a separate step so the crypto
// boundary stays auditable and testable without network access.
export async function bootstrapArtifact() {
  const grantResponse = await fetch(GRANT_ENDPOINT, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
  });
  if (!grantResponse.ok) fail("grant unavailable");
  const grant = await grantResponse.json();
  const offer = {
    kid: base64ToBytes(grant.kid, KID_LEN, "server kid"),
    recipientPublicKey: base64ToBytes(grant.recipient_public_key, PK_LEN, "server key"),
  };
  const initiated: InitiatedArtifact = await hpkeInitiate(offer);
  const artifactResponse = await fetch(ARTIFACT_ENDPOINT, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_id: grant.grant_id,
      kid: bytesToBase64(offer.kid),
      encapsulated_key: bytesToBase64(initiated.encapsulated),
    }),
  });
  if (!artifactResponse.ok) fail("artifact unavailable");
  const wire = new Uint8Array(await artifactResponse.arrayBuffer());
  const envelope = parseEnvelope(wire);
  return { envelope, keyScheduleSeed: initiated.dhSecret, s2cInfo: EXPORTER_S2C };
}
