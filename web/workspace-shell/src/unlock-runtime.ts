// Memory-only unlock runtime and payload instantiation for workspace shell.
//
// Invariants:
// - Audited WASM only: derives workspace public key in WASM memory, uses
//   WasmInitiatorSession for transport decrypt and WasmWorkspaceKey for artifact decrypt.
// - Ephemeral: unlock secret is zeroized immediately after key derivation in WASM.
// - No persistence: zero usage of client-side persistent storage, browser databases,
//   cache storage, or document cookies.
// - No leakage: no secrets, keys, or plaintext interpolated into errors or logged.
// - Memory-only payload: unpacks payload archive in memory, instantiates via Blob URLs.
// - Cleanup: revokes all Blob URLs and scrubs RAM references on lock/unload/error.

import init, {
  WasmInitiatorSession,
  WasmOffer,
  WasmWorkspaceKey,
} from "./wasm/crypto-envelope-wasm.js";
import { HandoffGate, type ShellSessionKeys } from "./handoff-gate.ts";

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
   * into the payload document, and only once. A document that navigated into the
   * frame (or a repointed `frame.src`) cannot echo the token, so an
   * unauthenticated `workspace-ready` ping can no longer harvest the live
   * session keys. Returns `null` on a missing/mismatched token, before unlock,
   * after lock, or on a repeat call.
   *
   * There is deliberately no unguarded key accessor: the only way to obtain the
   * keys is through this token-and-one-shot gate.
   */
  public takeSessionKeysForHandoff(token: unknown): ShellSessionKeys | null {
    return this.handoff.take(token);
  }

  /**
   * Revoke the payload *document* blob URL once the frame has loaded it.
   *
   * The loaded document stays live in the frame and its subresource blob URLs
   * remain valid, but the document URL is no longer fetchable. That closes the
   * same-origin path where a document that navigated into the frame reads
   * `frame.src` from the parent and re-fetches the still-live document blob to
   * harvest the injected handoff token. The token itself is never the boundary;
   * this removes the copy an attacker could otherwise read.
   */
  public releaseDocumentUrl(url: string): void {
    if (!url) return;
    revokeSafeBlobUrl(url);
    this.activeUrls.delete(url);
  }

  public async unlock(
    secretInput: string | Uint8Array,
    kidInput: string | Uint8Array,
    options: UnlockOptions = {},
  ): Promise<UnlockResult> {
    this.lock();

    await loadWasm();

    const fetchImpl = options.fetchFn || fetch;
    const enrollEndpoint = options.enrollUrl || "/internal/auth/enroll";
    const grantEndpoint = options.grantUrl || "/internal/artifact/grant";
    const deliverEndpoint = options.deliverUrl || "/internal/artifact";

    const secretBytes =
      typeof secretInput === "string"
        ? fromBase64(secretInput)
        : new Uint8Array(secretInput);
    if (secretBytes.length !== 32 || secretBytes.every((b) => b === 0)) {
      secretBytes.fill(0);
      throw new Error("Invalid unlock secret: must be 32 non-zero bytes");
    }

    // Parse the kid inside a guard that zeroizes the already-derived secret if
    // the kid encoding is malformed, so a throw cannot leave it resident.
    let kidBytes: Uint8Array;
    try {
      kidBytes =
        typeof kidInput === "string"
          ? fromBase64(kidInput)
          : new Uint8Array(kidInput);
    } catch (error) {
      secretBytes.fill(0);
      throw error;
    }
    if (kidBytes.length !== 16 || kidBytes.every((b) => b === 0)) {
      secretBytes.fill(0);
      throw new Error("Invalid key ID: must be 16 non-zero bytes");
    }

    let workspaceKey: WasmWorkspaceKey | null = null;
    let initiator: WasmInitiatorSession | null = null;
    let unlocked = false;

    try {
      const version = 1;
      workspaceKey = new WasmWorkspaceKey(secretBytes, version, kidBytes);
      // The raw secret is only needed to derive the workspace key in WASM;
      // zero it immediately rather than leaving it in the JS heap across the
      // network fetches, HPKE decrypt and payload instantiation below.
      secretBytes.fill(0);
      const publicKeyBytes = new Uint8Array(workspaceKey.public_key());

      // 1. Authenticated workspace public key enrollment
      const enrollResponse = await fetchImpl(enrollEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          version: 1,
          kid: toBase64(kidBytes),
          public_key: toBase64(publicKeyBytes),
        }),
      });
      if (!enrollResponse.ok) {
        throw new Error("Workspace enrollment rejected");
      }

      // 2. Artifact grant request (P0-4a HPKE offer)
      const grantResponse = await fetchImpl(grantEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: "",
      });
      if (!grantResponse.ok) {
        throw new Error("Artifact grant request failed");
      }
      const grantData = await grantResponse.json();
      if (
        !grantData ||
        !grantData.grant_id ||
        !grantData.kid ||
        !grantData.recipient_public_key
      ) {
        throw new Error("Malformed artifact grant response");
      }

      // 3. Establish session with server offer
      const grantKid = fromBase64(grantData.kid);
      const grantPk = fromBase64(grantData.recipient_public_key);
      let offer: WasmOffer | null = null;
      try {
        offer = new WasmOffer(grantKid, grantPk);
        initiator = WasmInitiatorSession.establish(offer);
      } finally {
        if (offer) offer.free();
      }

      const encapsulatedKey = initiator.encapsulated_key();

      // 4. Retrieve artifact ciphertext
      const deliverResponse = await fetchImpl(deliverEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          grant_id: grantData.grant_id,
          kid: grantData.kid,
          encapsulated_key: toBase64(new Uint8Array(encapsulatedKey)),
        }),
      });
      if (!deliverResponse.ok) {
        throw new Error("Artifact ciphertext delivery failed");
      }

      const sessionEnvelopeWire = new Uint8Array(await deliverResponse.arrayBuffer());

      // 5. Decrypt transport envelope in WASM, extract the BR-5 directional app
      //    session keys, then drop the transport session. The keys are only
      //    needed for the same-document handoff to the payload; they are never
      //    persisted.
      let sealedArtifactBytes: Uint8Array;
      let sessionMaterial: ShellSessionKeys | null = null;
      try {
        sealedArtifactBytes = new Uint8Array(initiator.decrypt(sessionEnvelopeWire));
        const rawAppKeys = new Uint8Array(initiator.app_session_keys());
        const rawKid = new Uint8Array(initiator.kid());
        try {
          if (rawAppKeys.length !== 64 || rawKid.length !== 16) {
            throw new Error("Session key material was malformed");
          }
          sessionMaterial = {
            kid: toBase64(rawKid),
            // app_session_keys() returns c2s(32) || s2c(32).
            c2sKeyB64: toBase64(rawAppKeys.subarray(0, 32)),
            s2cKeyB64: toBase64(rawAppKeys.subarray(32, 64)),
          };
        } finally {
          rawAppKeys.fill(0);
          rawKid.fill(0);
        }
      } finally {
        initiator.free();
        initiator = null;
      }

      // 6. Decrypt workspace artifact with WasmWorkspaceKey in memory
      const decryptedPayloadBytes = new Uint8Array(
        workspaceKey.decrypt_artifact(sealedArtifactBytes),
      );

      // 7. Unpack in memory and zero decrypted payload
      let unpackedFiles: Map<string, Uint8Array>;
      try {
        unpackedFiles = unpackPackageFromMemory(decryptedPayloadBytes);
      } finally {
        decryptedPayloadBytes.fill(0);
      }
      this.currentPayloadFiles = unpackedFiles;

      // Fresh per-unlock handoff binding. Generated before the payload document
      // is built so the token can be injected into it; the payload must echo the
      // token on its ready ping before the shell releases any key.
      const handoffToken = generateHandoffToken();

      const htmlUrl = this.instantiatePayload(unpackedFiles, handoffToken);
      // Ownership transfers only after the payload is fully instantiated; any
      // earlier failure is reclaimed by the finally below.
      if (!sessionMaterial) {
        throw new Error("Session key handoff unavailable");
      }
      this.currentKey = workspaceKey;
      this.handoff.arm(sessionMaterial, handoffToken);
      workspaceKey = null;
      unlocked = true;
      this.isUnlocked = true;

      return {
        htmlUrl,
        files: unpackedFiles,
        cleanup: () => this.lock(),
      };
    } finally {
      secretBytes.fill(0);
      kidBytes.fill(0);
      if (initiator) {
        try {
          initiator.free();
        } catch {}
      }
      if (!unlocked) {
        // A thrown fetch/decrypt/instantiate must never leave the WASM key or the
        // decrypted payload resident: lock() revokes blob URLs and zeroizes the
        // unpacked files, then free the workspace key exactly once.
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

    // BR-5 handoff binding: inject the per-unlock token into the payload document
    // itself (same-document capability, never persisted, never in a URL). The
    // payload echoes it on `workspace-ready`; the shell revokes the document
    // blob URL once the frame has loaded it, so a same-origin document that
    // navigated into the frame cannot re-fetch the payload to read the token.
    indexHtml = injectHandoffToken(indexHtml, handoffToken);

    const assetNames = [...files.keys()].filter((name) => name !== "index.html");
    // Longest paths first, and only at token boundaries, so a short asset name
    // can never match inside a longer reference and corrupt the HTML.
    assetNames.sort((a, b) => b.length - a.length);
    for (const name of assetNames) {
      const data = files.get(name)!;
      const mime = getMimeType(name);
      const url = createSafeBlobUrl(data, mime, this.activeUrls);

      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const pattern = new RegExp(`(?<![\\w./-])(?:\\./|/)?${escaped}(?![\\w.-])`, "g");
      indexHtml = indexHtml.replace(pattern, url);
    }

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
 *
 * This is a same-document capability, not a long-term secret, but a predictable
 * value would let another same-origin document forge the ready ping, so a
 * deployment without `crypto` must fail closed rather than fall back to
 * `Math.random()`.
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
 * Inject the handoff token into the payload document as a `<meta>` element.
 *
 * The value is base64 (no HTML-special characters), and it is inserted
 * immediately after the document's `<head>` opening tag (creating a `<head>`
 * after `<html>` or the doctype when the build output has none), so it is
 * available to the payload before any script runs. The tag patterns require a
 * tag boundary (`<head>`/`<head ...>`, never `<header>`). It is never placed in
 * a URL or any storage; it lives in the document DOM by design and the document
 * blob URL is revoked once the frame has loaded it.
 */
function injectHandoffToken(html: string, token: string): string {
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
    // After the doctype (not before) so the injected markup cannot force quirks
    // mode.
    const at = doctype.index + doctype[0].length;
    return html.slice(0, at) + `<head>${meta}</head>` + html.slice(at);
  }
  return `<head>${meta}</head>${html}`;
}

export const defaultRuntime = new WorkspaceUnlockRuntime();
