// Memory-only unlock runtime and payload instantiation for workspace shell.
//
// Invariants:
// - Audited WASM only: derives workspace public key in WASM memory, uses
//   WasmInitiatorSession for transport decrypt and WasmWorkspaceKey for artifact decrypt.
// - Ephemeral: the unlock secret is passed as bytes and zeroized immediately
//   after key derivation in WASM. Callers must not hand over a retained string.
// - No persistence: zero usage of client-side persistent storage, browser databases,
//   cache storage, or document cookies.
// - No leakage: every stage failure is a typed UnlockError carrying only a
//   stage and reason. No secret, key, KID, path, ciphertext, or exception text
//   is interpolated into an error or logged.
// - Compatibility: the artifact KID and expected recipient fingerprint come
//   from the authenticated descriptor, never from user input.
// - Memory-only payload: unpacks payload archive in memory, instantiates via Blob URLs.
// - Cleanup: revokes all Blob URLs and scrubs RAM references on lock/unload/error.

import init, {
  WasmInitiatorSession,
  WasmOffer,
  WasmWorkspaceKey,
} from "./wasm/crypto-envelope-wasm.js";
import { HandoffGate, type ShellSessionKeys } from "./handoff-gate.ts";
import {
  WORKSPACE_PROTOCOL_VERSION,
  type WorkspaceDescriptor,
} from "./descriptor.ts";
import { UnlockError, asUnlockError, type UnlockStage } from "./unlock-stages.ts";

export type { ShellSessionKeys } from "./handoff-gate.ts";

let wasmReady: Promise<unknown> | undefined;

export function loadWasm(moduleOrPath?: unknown): Promise<unknown> {
  if (!wasmReady) {
    wasmReady = init(moduleOrPath as any);
  }
  return wasmReady;
}

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(bytes: Uint8Array): string {
  let out = "";
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += BASE64_ALPHABET[(triple >> 18) & 63];
    out += BASE64_ALPHABET[(triple >> 12) & 63];
    out += i + 1 < len ? BASE64_ALPHABET[(triple >> 6) & 63] : "=";
    out += i + 2 < len ? BASE64_ALPHABET[triple & 63] : "=";
  }
  return out;
}

export function fromBase64(str: string): Uint8Array {
  const clean = str.replace(/[\r\n\s]/g, "");
  let validChars = clean;
  if (clean.endsWith("==")) {
    validChars = clean.slice(0, -2);
  } else if (clean.endsWith("=")) {
    validChars = clean.slice(0, -1);
  }
  const revLookup: { [c: string]: number } = {};
  for (let i = 0; i < 64; i++) {
    revLookup[BASE64_ALPHABET[i]] = i;
  }
  const totalBits = validChars.length * 6;
  const totalBytes = Math.floor(totalBits / 8);
  const out = new Uint8Array(totalBytes);
  let acc = 0;
  let bits = 0;
  let outIdx = 0;
  for (let i = 0; i < validChars.length; i++) {
    const val = revLookup[validChars[i]];
    if (val === undefined) {
      throw new Error("invalid base64 character");
    }
    acc = (acc << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * SHA-256 fingerprint of a workspace public key, standard base64.
 *
 * Matches the server's `public_key_fingerprint_b64`. Returns `null` when
 * WebCrypto is unavailable or the input is rejected. A `null` result is a hard
 * failure wherever a release or enrollment fingerprint is pinned: `unlock()`
 * never treats a missing digest as a reason to skip the check, and the server
 * independently enforces the same fingerprint in its compatibility preflight.
 */
export async function publicKeyFingerprintB64(
  publicKey: Uint8Array,
): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") return null;
  try {
    const digest = await subtle.digest("SHA-256", publicKey as unknown as BufferSource);
    return toBase64(new Uint8Array(digest));
  } catch {
    return null;
  }
}

/** SHA-256 as lowercase hex, or `null` when WebCrypto is unavailable. */
export async function sha256Hex(bytes: Uint8Array): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") return null;
  try {
    const digest = await subtle.digest("SHA-256", bytes as unknown as BufferSource);
    let out = "";
    for (const byte of new Uint8Array(digest)) out += byte.toString(16).padStart(2, "0");
    return out;
  } catch {
    return null;
  }
}

/**
 * Derive the workspace public-key fingerprint for a candidate secret, using the
 * audited WASM key path. Returns `null` when the KID is malformed, the secret is
 * rejected, or WebCrypto is unavailable. The caller's `secret` is not mutated.
 */
export async function deriveWorkspaceFingerprint(
  secret: Uint8Array,
  kidB64: string,
): Promise<string | null> {
  let kidBytes: Uint8Array;
  try {
    kidBytes = fromBase64(kidB64);
  } catch {
    return null;
  }
  if (kidBytes.length !== 16 || kidBytes.every((b) => b === 0)) return null;
  if (secret.length !== 32 || secret.every((b) => b === 0)) return null;
  let key: WasmWorkspaceKey;
  // Copy into an owned buffer so the caller's bytes are never mutated, and
  // zeroize the copy once the key is derived (the WASM ctor does not retain it).
  const secretCopy = new Uint8Array(secret);
  try {
    key = new WasmWorkspaceKey(secretCopy, 1, kidBytes);
  } catch {
    return null;
  } finally {
    secretCopy.fill(0);
  }
  try {
    return await publicKeyFingerprintB64(new Uint8Array(key.public_key()));
  } catch {
    return null;
  } finally {
    try {
      key.free();
    } catch {}
  }
}

export function unpackPackageFromMemory(
  buffer: Uint8Array,
): Map<string, Uint8Array> {
  if (buffer.length < 4 || buffer.length > 256 * 1024 * 1024) {
    throw new Error("invalid artifact package");
  }
  const view = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,
  );
  let offset = 0;
  const count = view.getUint32(offset, false);
  offset += 4;
  if (count === 0 || count > 10_000) {
    throw new Error("invalid artifact file count");
  }
  const files = new Map<string, Uint8Array>();
  const decoder = new TextDecoder("utf-8");
  for (let i = 0; i < count; i++) {
    if (offset + 6 > buffer.length) {
      throw new Error("invalid artifact package");
    }
    const pathLen = view.getUint16(offset, false);
    const dataLen = view.getUint32(offset + 2, false);
    offset += 6;
    if (
      pathLen === 0 ||
      pathLen > 4096 ||
      dataLen > 64 * 1024 * 1024 ||
      offset + pathLen + dataLen > buffer.length
    ) {
      throw new Error("invalid artifact package");
    }
    const pathBytes = buffer.subarray(offset, offset + pathLen);
    const name = decoder.decode(pathBytes);
    offset += pathLen;
    if (
      !name ||
      name.startsWith("/") ||
      name.includes("..") ||
      name.includes("\\") ||
      files.has(name)
    ) {
      throw new Error("invalid artifact path");
    }
    const data = buffer.slice(offset, offset + dataLen);
    files.set(name, data);
    offset += dataLen;
  }
  if (offset !== buffer.length) {
    throw new Error("invalid artifact package");
  }
  return files;
}

function getMimeType(path: string): string {
  if (path.endsWith(".js") || path.endsWith(".mjs")) {
    return "application/javascript";
  }
  if (path.endsWith(".css")) {
    return "text/css";
  }
  if (path.endsWith(".html")) {
    return "text/html";
  }
  if (path.endsWith(".json")) {
    return "application/json";
  }
  if (path.endsWith(".wasm")) {
    return "application/wasm";
  }
  if (path.endsWith(".svg")) {
    return "image/svg+xml";
  }
  if (path.endsWith(".png")) {
    return "image/png";
  }
  if (path.endsWith(".jpg") || path.endsWith(".jpeg")) {
    return "image/jpeg";
  }
  return "application/octet-stream";
}

function createSafeBlobUrl(
  data: Uint8Array | string,
  mimeType: string,
  activeUrls: Set<string>,
): string {
  if (
    typeof URL !== "undefined" &&
    typeof URL.createObjectURL === "function" &&
    typeof Blob !== "undefined"
  ) {
    const blob = new Blob([data as unknown as BlobPart], { type: mimeType });
    const url = URL.createObjectURL(blob);
    activeUrls.add(url);
    return url;
  }
  const mockUrl = `blob:test-${Math.random().toString(36).slice(2)}`;
  activeUrls.add(mockUrl);
  return mockUrl;
}

function revokeSafeBlobUrl(url: string): void {
  if (typeof URL !== "undefined" && typeof URL.revokeObjectURL === "function") {
    try {
      URL.revokeObjectURL(url);
    } catch {}
  }
}

export interface UnlockResult {
  htmlUrl: string;
  files: Map<string, Uint8Array>;
  cleanup: () => void;
}

export interface UnlockOptions {
  enrollUrl?: string;
  grantUrl?: string;
  deliverUrl?: string;
  fetchFn?: typeof fetch;
  /** Progress callback: receives each stage as it begins. */
  onStage?: (stage: UnlockStage) => void;
  /**
   * Test seam for the audited WASM loader. Production never sets this; it lets
   * a focused test prove a loader failure is classified as U1_WASM without
   * weakening the real boundary.
   */
  wasmLoader?: () => Promise<unknown>;
}

/** Read a typed `{ code }` error body without ever throwing or leaking it. */
async function readErrorCode(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { code?: unknown };
    return typeof body?.code === "string" ? body.code : null;
  } catch {
    return null;
  }
}

function artifactKidBytes(descriptor: WorkspaceDescriptor): Uint8Array {
  let kidBytes: Uint8Array;
  try {
    kidBytes = fromBase64(descriptor.artifact_kid_b64);
  } catch {
    throw new UnlockError("U5_ARTIFACT", "descriptor_invalid");
  }
  if (kidBytes.length !== 16 || kidBytes.every((b) => b === 0)) {
    throw new UnlockError("U5_ARTIFACT", "descriptor_invalid");
  }
  return kidBytes;
}

export class WorkspaceUnlockRuntime {
  private activeUrls: Set<string> = new Set();
  private currentKey: WasmWorkspaceKey | null = null;
  private currentPayloadFiles: Map<string, Uint8Array> | null = null;
  /**
   * BR-5 handoff gate. Holds the transport session keys derived from the same
   * authenticated HPKE exchange that decrypts the artifact, and decides the
   * one-shot, token-bound delivery to the payload. `lock()` disarms it so no
   * reference survives, and the payload owns the only durable copy as
   * non-extractable CryptoKeys.
   */
  private handoff = new HandoffGate();
  private isUnlocked: boolean = false;

  constructor() {
    if (typeof window !== "undefined") {
      window.addEventListener("beforeunload", () => this.lock());
      window.addEventListener("unload", () => this.lock());
    }
  }

  public get unlocked(): boolean {
    return this.isUnlocked;
  }

  public getActiveUrlCount(): number {
    return this.activeUrls.size;
  }

  /**
   * One-shot, token-bound BR-5 key delivery.
   *
   * Returns the keys only when `token` matches the per-unlock token injected
   * into the payload document, and only once. There is deliberately no
   * unguarded key accessor.
   */
  public takeSessionKeysForHandoff(token: unknown): ShellSessionKeys | null {
    return this.handoff.take(token);
  }

  /**
   * Decrypt a server-sealed proof-of-possession challenge with the in-memory
   * workspace key (the same HPKE recipient the artifact used). Returns the
   * plaintext nonce; the caller must zeroize it. Fails closed when locked.
   */
  public decryptRecoveryChallenge(sealed: Uint8Array): Uint8Array {
    if (!this.currentKey) {
      throw new UnlockError("U7_BOOT", "handoff_unavailable");
    }
    return this.currentKey.decrypt_artifact(sealed);
  }

  /**
   * Revoke the payload *document* blob URL once the frame has loaded it.
   */
  public releaseDocumentUrl(url: string): void {
    if (!url) return;
    revokeSafeBlobUrl(url);
    this.activeUrls.delete(url);
  }

  /**
   * Unlock the workspace.
   *
   * `secretInput` is a 32-byte byte array; the caller clears the DOM input and
   * its reactive signal before calling. Only bytes cross the async boundary and
   * this method copies them, so the caller's buffer is never zeroized. The KID
   * and expected fingerprint come from the authenticated descriptor, never from
   * user input. Every failure throws a typed `UnlockError`.
   */
  public async unlock(
    secretInput: Uint8Array,
    descriptor: WorkspaceDescriptor,
    options: UnlockOptions = {},
  ): Promise<UnlockResult> {
    this.lock();

    const onStage = options.onStage ?? (() => {});
    // Copy so zeroization never mutates a caller-owned buffer.
    const secretBytes = new Uint8Array(secretInput);
    const fetchImpl = options.fetchFn || fetch;
    const enrollEndpoint = options.enrollUrl || "/internal/auth/enroll";
    const grantEndpoint = options.grantUrl || "/internal/artifact/grant";
    const deliverEndpoint = options.deliverUrl || "/internal/artifact";

    let workspaceKey: WasmWorkspaceKey | null = null;
    let initiator: WasmInitiatorSession | null = null;
    let unlocked = false;

    try {
      if (secretBytes.length !== 32 || secretBytes.every((b) => b === 0)) {
        throw new UnlockError("U2_ENROLL", "invalid_secret");
      }
      if (
        descriptor.artifact_version !== 1 ||
        descriptor.package_format_version !== 1
      ) {
        throw new UnlockError("U5_ARTIFACT", "protocol_incompatible");
      }
      if (
        WORKSPACE_PROTOCOL_VERSION < descriptor.min_shell_protocol ||
        WORKSPACE_PROTOCOL_VERSION > descriptor.max_shell_protocol
      ) {
        throw new UnlockError("U5_ARTIFACT", "protocol_incompatible");
      }
      const kidBytes = artifactKidBytes(descriptor);

      // U1: audited WASM boundary. Not a network await, but still classified.
      onStage("U1_WASM");
      try {
        await (options.wasmLoader ?? loadWasm)();
      } catch {
        throw new UnlockError("U1_WASM", "wasm_unavailable");
      }

      // U2: derive the workspace key and zero the raw secret bytes immediately.
      // The copy is made synchronously before the (memoized) WASM await above;
      // the caller also clears its own buffer, and only bytes ever cross this
      // path.
      onStage("U2_ENROLL");
      try {
        workspaceKey = new WasmWorkspaceKey(secretBytes, 1, kidBytes);
      } catch {
        // Length/zero/KID/version are all validated in JS above and mirrored by
        // the audited WASM constructor, so a throw here is an internal WASM/alloc
        // fault, not an invalid recovery code. Classify it as such instead of
        // telling the person to re-enter a valid code.
        throw new UnlockError("U1_WASM", "wasm_unavailable");
      }
      secretBytes.fill(0);
      let publicKeyBytes: Uint8Array;
      try {
        // A WASM fault here must still surface as a typed stage error.
        publicKeyBytes = new Uint8Array(workspaceKey.public_key());
      } catch {
        throw new UnlockError("U1_WASM", "wasm_unavailable");
      }
      const derivedFingerprint = await publicKeyFingerprintB64(publicKeyBytes);
      const kidB64 = toBase64(kidBytes);

      // Local release-fingerprint preflight: if the server published the
      // expected recipient fingerprint, a mismatch means the recovery code is
      // for a different release. Checked before the first network await so a
      // wrong-key enrollment never leaves the browser when a release manifest
      // is configured. A null derived fingerprint (no WebCrypto) is a hard
      // failure, never a skip: otherwise a wrong code could be enrolled and
      // only fail much later at artifact decrypt.
      if (descriptor.expected_public_key_fingerprint_b64) {
        if (derivedFingerprint === null) {
          throw new UnlockError("U1_WASM", "wasm_unavailable");
        }
        if (derivedFingerprint !== descriptor.expected_public_key_fingerprint_b64) {
          throw new UnlockError("U5_ARTIFACT", "workspace_key_mismatch");
        }
      }
      // The session-enrollment fingerprint covers the no-manifest path: it is
      // derived server-side from the key already bound to this session, so a
      // different recovery code is rejected before it can enroll a wrong key.
      if (descriptor.enrolled && descriptor.enrolled_public_key_fingerprint_b64) {
        if (derivedFingerprint === null) {
          throw new UnlockError("U1_WASM", "wasm_unavailable");
        }
        if (derivedFingerprint !== descriptor.enrolled_public_key_fingerprint_b64) {
          throw new UnlockError("U5_ARTIFACT", "workspace_key_mismatch");
        }
      }

      // U2: bind the workspace key to the session. A page reload or a
      // lock/unlock cycle reuses the same authenticated session and derives the
      // same key, so the descriptor's enrollment lets the identical binding be
      // skipped. The server also treats an identical re-enrollment as
      // idempotent, so a stale pre-unlock descriptor cannot cause a spurious
      // 409 on the second unlock.
      const alreadyEnrolled =
        descriptor.enrolled &&
        descriptor.enrolled_kid_b64 === kidB64 &&
        (derivedFingerprint === null ||
          !descriptor.enrolled_public_key_fingerprint_b64 ||
          derivedFingerprint === descriptor.enrolled_public_key_fingerprint_b64);

      if (!alreadyEnrolled) {
        let enrollResponse: Response;
        try {
          enrollResponse = await fetchImpl(enrollEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            redirect: "error",
            body: JSON.stringify({
              version: 1,
              kid: kidB64,
              public_key: toBase64(publicKeyBytes),
            }),
          });
        } catch {
          throw new UnlockError("U2_ENROLL", "enrollment_rejected");
        }
        if (!enrollResponse.ok) {
          if (enrollResponse.status === 401 || enrollResponse.status === 403) {
            throw new UnlockError("U2_ENROLL", "session_expired");
          }
          if (enrollResponse.status === 409) {
            throw new UnlockError("U2_ENROLL", "enrollment_conflict");
          }
          throw new UnlockError("U2_ENROLL", "enrollment_rejected");
        }
      }

      // U3: artifact grant request (P0-4a HPKE offer).
      onStage("U3_GRANT");
      let grantResponse: Response;
      try {
        grantResponse = await fetchImpl(grantEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          redirect: "error",
          body: "",
        });
      } catch {
        throw new UnlockError("U3_GRANT", "grant_rejected");
      }
      if (!grantResponse.ok) {
        // 401 is the only expired-session signal the private API emits. Any
        // other status (including a 403 from an intermediary/WAF) is a generic
        // grant rejection, not a re-authentication prompt.
        if (grantResponse.status === 401) {
          throw new UnlockError("U2_ENROLL", "session_expired");
        }
        throw new UnlockError("U3_GRANT", "grant_rejected");
      }
      let grantData: {
        grant_id?: unknown;
        kid?: unknown;
        recipient_public_key?: unknown;
      };
      try {
        grantData = await grantResponse.json();
      } catch {
        throw new UnlockError("U3_GRANT", "grant_invalid");
      }
      if (
        !grantData ||
        typeof grantData.grant_id !== "string" ||
        typeof grantData.kid !== "string" ||
        typeof grantData.recipient_public_key !== "string"
      ) {
        throw new UnlockError("U3_GRANT", "grant_invalid");
      }

      // U3: establish the client half of the HPKE exchange.
      let encapsulatedKey: Uint8Array;
      try {
        const grantKid = fromBase64(grantData.kid);
        const grantPk = fromBase64(grantData.recipient_public_key);
        let offer: WasmOffer | null = null;
        try {
          offer = new WasmOffer(grantKid, grantPk);
          initiator = WasmInitiatorSession.establish(offer);
        } finally {
          if (offer) offer.free();
        }
        encapsulatedKey = new Uint8Array(initiator.encapsulated_key());
      } catch {
        throw new UnlockError("U3_GRANT", "grant_invalid");
      }

      // U4: retrieve artifact ciphertext.
      onStage("U4_TRANSPORT");
      let deliverResponse: Response;
      try {
        deliverResponse = await fetchImpl(deliverEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          redirect: "error",
          body: JSON.stringify({
            grant_id: grantData.grant_id,
            kid: grantData.kid,
            encapsulated_key: toBase64(encapsulatedKey),
          }),
        });
      } catch {
        throw new UnlockError("U4_TRANSPORT", "transport_rejected");
      }
      if (!deliverResponse.ok) {
        // 401 is the only expired-session signal the private API emits; a 403
        // (e.g. an intermediary/WAF denial) stays a generic transport rejection.
        if (deliverResponse.status === 401) {
          throw new UnlockError("U2_ENROLL", "session_expired");
        }
        if (deliverResponse.status === 409) {
          const code = await readErrorCode(deliverResponse);
          if (code === "artifact_incompatible") {
            throw new UnlockError("U5_ARTIFACT", "artifact_incompatible");
          }
          if (code === "enrollment_required") {
            throw new UnlockError("U2_ENROLL", "enrollment_required");
          }
        }
        throw new UnlockError("U4_TRANSPORT", "transport_rejected");
      }
      let sessionEnvelopeWire: Uint8Array;
      try {
        sessionEnvelopeWire = new Uint8Array(await deliverResponse.arrayBuffer());
      } catch {
        throw new UnlockError("U4_TRANSPORT", "transport_rejected");
      }

      // U4: decrypt the transport envelope in WASM and extract the BR-5
      // directional app session keys, then drop the transport session. The
      // binding-returned buffers are zeroized in place; wrapping them in another
      // `Uint8Array` would leave the first copy in memory.
      let sealedArtifactBytes: Uint8Array;
      let sessionMaterial: ShellSessionKeys | null = null;
      try {
        sealedArtifactBytes = initiator.decrypt(sessionEnvelopeWire);
        const rawAppKeys = initiator.app_session_keys();
        try {
          const rawKid = initiator.kid();
          try {
            if (rawAppKeys.length !== 64 || rawKid.length !== 16) {
              throw new UnlockError("U4_TRANSPORT", "transport_rejected");
            }
            sessionMaterial = {
              kid: toBase64(rawKid),
              // app_session_keys() returns c2s(32) || s2c(32).
              c2sKeyB64: toBase64(rawAppKeys.subarray(0, 32)),
              s2cKeyB64: toBase64(rawAppKeys.subarray(32, 64)),
            };
          } finally {
            rawKid.fill(0);
          }
        } finally {
          // Zeroized even if initiator.kid() throws, so the 64-byte app-key
          // material never outlives this scope.
          rawAppKeys.fill(0);
        }
      } catch (error) {
        // Classify without ever inspecting foreign exception text.
        throw asUnlockError(error, "U4_TRANSPORT", "transport_rejected");
      } finally {
        // Guarded like the outer free: a throwing wasm free must never replace
        // the typed UnlockError already in flight.
        try {
          initiator.free();
        } catch {}
        initiator = null;
      }

      // U5: verify the authenticated descriptor's size/digest binding before the
      // inner decrypt, so a substituted-but-well-formed artifact is rejected here
      // rather than silently trusted. Missing fields (legacy descriptor) skip
      // the local check and rely on the server preflight. The stage is announced
      // first so the ledger reflects U5 even when this check throws.
      onStage("U5_ARTIFACT");
      if (descriptor.artifact_size > 0 && sealedArtifactBytes.length !== descriptor.artifact_size) {
        throw new UnlockError("U5_ARTIFACT", "artifact_incompatible");
      }
      if (descriptor.artifact_sha256_hex) {
        const actualDigest = await sha256Hex(sealedArtifactBytes);
        if (actualDigest === null || actualDigest !== descriptor.artifact_sha256_hex) {
          throw new UnlockError("U5_ARTIFACT", "artifact_incompatible");
        }
      }

      // U5: decrypt the inner workspace artifact with the in-memory key.
      let decryptedPayloadBytes: Uint8Array;
      try {
        decryptedPayloadBytes = workspaceKey.decrypt_artifact(sealedArtifactBytes);
      } catch {
        throw new UnlockError("U5_ARTIFACT", "artifact_decrypt_failed");
      }

      // U6: unpack the custom package in memory and zero the decrypted payload.
      onStage("U6_PACKAGE");
      let unpackedFiles: Map<string, Uint8Array>;
      try {
        try {
          unpackedFiles = unpackPackageFromMemory(decryptedPayloadBytes);
        } finally {
          decryptedPayloadBytes.fill(0);
        }
      } catch {
        throw new UnlockError("U6_PACKAGE", "package_invalid");
      }
      this.currentPayloadFiles = unpackedFiles;

      // U7: instantiate the payload document and arm the one-shot handoff.
      onStage("U7_BOOT");
      let handoffToken: string;
      let htmlUrl: string;
      try {
        handoffToken = generateHandoffToken();
        htmlUrl = this.instantiatePayload(unpackedFiles, handoffToken);
      } catch {
        throw new UnlockError("U7_BOOT", "boot_failed");
      }
      if (!sessionMaterial) {
        throw new UnlockError("U7_BOOT", "handoff_unavailable");
      }
      // Transfer ownership of the WASM key before arming the handoff, so a throw
      // from `arm` cannot leave both `this.currentKey` and the local
      // `workspaceKey` pointing at the same allocation (a double free).
      this.currentKey = workspaceKey;
      workspaceKey = null;
      this.handoff.arm(sessionMaterial, handoffToken);
      unlocked = true;
      this.isUnlocked = true;

      return {
        htmlUrl,
        files: unpackedFiles,
        cleanup: () => this.lock(),
      };
    } finally {
      secretBytes.fill(0);
      if (initiator) {
        try {
          initiator.free();
        } catch {}
      }
      if (!unlocked) {
        // A thrown fetch/decrypt/instantiate must never leave the WASM key or
        // the decrypted payload resident: lock() revokes blob URLs and zeroizes
        // the unpacked files, then free the workspace key exactly once.
        this.lock();
        if (workspaceKey) {
          try {
            workspaceKey.free();
          } catch {}
        }
      }
    }
  }

  private instantiatePayload(files: Map<string, Uint8Array>, handoffToken: string): string {
    const decoder = new TextDecoder("utf-8");
    let indexHtml = "";
    if (files.has("index.html")) {
      indexHtml = decoder.decode(files.get("index.html")!);
    } else {
      indexHtml = "<!doctype html><html><body><div id=\"root\"></div></body></html>";
    }

    // Rewrite asset references in a SINGLE pass over the original document, so
    // an already-substituted blob URL is never rescanned and corrupted. Only
    // path-like names (the production build emits `assets/<name>.<ext>`)
    // participate, so a bare HTML tag/attribute name (`src`, `style`,
    // `content`) can never be matched and rewritten. The handoff token is
    // injected AFTER rewriting, so no asset name can ever rewrite the token or
    // the meta element that carries it.
    const assetNames = selectRewritableAssetNames(files.keys());
    const urls = new Map<string, string>();
    for (const name of assetNames) {
      urls.set(
        name,
        createSafeBlobUrl(files.get(name)!, getMimeType(name), this.activeUrls),
      );
    }
    indexHtml = buildPayloadDocument(indexHtml, assetNames, urls, handoffToken);
    return createSafeBlobUrl(indexHtml, "text/html", this.activeUrls);
  }

  public lock(): void {
    for (const url of this.activeUrls) {
      revokeSafeBlobUrl(url);
    }
    this.activeUrls.clear();

    if (this.currentPayloadFiles) {
      for (const data of this.currentPayloadFiles.values()) {
        try {
          data.fill(0);
        } catch {}
      }
      this.currentPayloadFiles.clear();
      this.currentPayloadFiles = null;
    }

    if (this.currentKey) {
      try {
        this.currentKey.free();
      } catch {}
      this.currentKey = null;
    }

    // Drop the BR-5 handoff material. Strings cannot be zeroized in JS; the
    // durable copies live only as non-extractable CryptoKeys inside the payload,
    // which is torn down with the iframe on lock.
    this.handoff.disarm();

    this.isUnlocked = false;
  }
}

/**
 * A cryptographically random per-unlock handoff token, or a fail-closed throw.
 */
function generateHandoffToken(): string {
  const cryptoObj: Crypto | undefined = globalThis.crypto;
  if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
    const bytes = new Uint8Array(32);
    cryptoObj.getRandomValues(bytes);
    return toBase64(bytes);
  }
  throw new Error("A secure handoff token could not be generated");
}

/**
 * Only path-like package entries participate in reference rewriting. The
 * production build emits `assets/<name>.<ext>`; a bare HTML tag/attribute name
 * (`src`, `style`, `content`, `meta`) must never be rewritten, or the document
 * itself would be corrupted.
 */
export function selectRewritableAssetNames(names: Iterable<string>): string[] {
  return [...names]
    .filter(
      (name) => name !== "index.html" && (name.includes("/") || name.includes(".")),
    )
    .sort((a, b) => b.length - a.length);
}

/**
 * Single-pass asset-reference rewrite.
 *
 * Every asset name is substituted in one pass over the original document, so an
 * already-inserted blob URL can never be rescanned and corrupted by a later,
 * shorter name. The caller must inject the handoff token *after* this function
 * returns; the token/meta element is never in scope of an asset match.
 */
export function rewriteAssetReferencesInHtml(
  html: string,
  assetNames: string[],
  urlByName: Map<string, string>,
): string {
  if (assetNames.length === 0) return html;
  const alternation = assetNames
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");
  const pattern = new RegExp(
    `(?<![\\w./-])(?:\\./|/)?(${alternation})(?![\\w.-])`,
    "g",
  );
  return html.replace(pattern, (match, name: string) => urlByName.get(name) ?? match);
}

/**
 * Assemble the in-memory payload document: rewrite asset references first, then
 * inject the handoff token. The order is a security property, not a preference —
 * a package file named `content`/`meta` must never be able to rewrite the token
 * meta element that binds key delivery to this document.
 */
export function buildPayloadDocument(
  indexHtml: string,
  assetNames: string[],
  urlByName: Map<string, string>,
  handoffToken: string,
): string {
  return injectHandoffToken(
    rewriteAssetReferencesInHtml(indexHtml, assetNames, urlByName),
    handoffToken,
  );
}

/** Inject the handoff token into the payload document as a `<meta>` element. */
export function injectHandoffToken(html: string, token: string): string {
  const meta = `<meta name="evergreen-handoff" content="${token}">`;
  const head = /<head(?:\s[^>]*)?>/i.exec(html);
  if (head) {
    const at = head.index + head[0].length;
    return html.slice(0, at) + meta + html.slice(at);
  }
  const htmlTag = /<html(?:\s[^>]*)?>/i.exec(html);
  if (htmlTag) {
    const at = htmlTag.index + htmlTag[0].length;
    return html.slice(0, at) + `<head>${meta}</head>` + html.slice(at);
  }
  const doctype = /<!doctype[^>]*>/i.exec(html);
  if (doctype) {
    const at = doctype.index + doctype[0].length;
    return html.slice(0, at) + `<head>${meta}</head>` + html.slice(at);
  }
  return `<head>${meta}</head>${html}`;
}

export const defaultRuntime = new WorkspaceUnlockRuntime();
