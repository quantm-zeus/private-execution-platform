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

    const kidBytes =
      typeof kidInput === "string"
        ? fromBase64(kidInput)
        : new Uint8Array(kidInput);
    if (kidBytes.length !== 16 || kidBytes.every((b) => b === 0)) {
      secretBytes.fill(0);
      throw new Error("Invalid key ID: must be 16 non-zero bytes");
    }

    let workspaceKey: WasmWorkspaceKey | null = null;
    let publicKeyBytes: Uint8Array | null = null;

    try {
      const version = 1;
      workspaceKey = new WasmWorkspaceKey(secretBytes, version, kidBytes);
      publicKeyBytes = new Uint8Array(workspaceKey.public_key());
    } finally {
      secretBytes.fill(0);
    }

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
      workspaceKey.free();
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
      workspaceKey.free();
      throw new Error("Artifact grant request failed");
    }

    const grantData = await grantResponse.json();
    if (
      !grantData ||
      !grantData.grant_id ||
      !grantData.kid ||
      !grantData.recipient_public_key
    ) {
      workspaceKey.free();
      throw new Error("Malformed artifact grant response");
    }

    // 3. Establish session with server offer
    const grantKid = fromBase64(grantData.kid);
    const grantPk = fromBase64(grantData.recipient_public_key);
    let offer: WasmOffer | null = null;
    let initiator: WasmInitiatorSession | null = null;
    try {
      offer = new WasmOffer(grantKid, grantPk);
      initiator = WasmInitiatorSession.establish(offer);
    } catch {
      if (offer) offer.free();
      workspaceKey.free();
      throw new Error("HPKE handshake failed");
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
      initiator.free();
      workspaceKey.free();
      throw new Error("Artifact ciphertext delivery failed");
    }

    const sessionEnvelopeWire = new Uint8Array(
      await deliverResponse.arrayBuffer(),
    );

    // 5. Decrypt transport envelope in WASM
    let sealedArtifactBytes: Uint8Array;
    try {
      sealedArtifactBytes = new Uint8Array(
        initiator.decrypt(sessionEnvelopeWire),
      );
    } catch {
      initiator.free();
      workspaceKey.free();
      throw new Error("Session envelope decrypt failed");
    } finally {
      initiator.free();
    }

    // 6. Decrypt workspace artifact with WasmWorkspaceKey in memory
    let decryptedPayloadBytes: Uint8Array;
    try {
      decryptedPayloadBytes = new Uint8Array(
        workspaceKey.decrypt_artifact(sealedArtifactBytes),
      );
    } catch {
      workspaceKey.free();
      throw new Error("Workspace artifact decrypt failed");
    }

    this.currentKey = workspaceKey;

    // 7. Unpack in memory and zero decrypted payload
    let unpackedFiles: Map<string, Uint8Array>;
    try {
      unpackedFiles = unpackPackageFromMemory(decryptedPayloadBytes);
    } finally {
      decryptedPayloadBytes.fill(0);
    }
    this.currentPayloadFiles = unpackedFiles;

    const htmlUrl = this.instantiatePayload(unpackedFiles);
    this.isUnlocked = true;

    return {
      htmlUrl,
      files: unpackedFiles,
      cleanup: () => this.lock(),
    };
  }

  private instantiatePayload(files: Map<string, Uint8Array>): string {
    const decoder = new TextDecoder("utf-8");
    let indexHtml = "";
    if (files.has("index.html")) {
      indexHtml = decoder.decode(files.get("index.html")!);
    } else {
      indexHtml = "<!doctype html><html><body><div id=\"root\"></div></body></html>";
    }

    for (const [name, data] of files.entries()) {
      if (name === "index.html") continue;
      const mime = getMimeType(name);
      const url = createSafeBlobUrl(data, mime, this.activeUrls);

      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const pattern = new RegExp(`(?:/|\\./)?${escaped}`, "g");
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

    this.isUnlocked = false;
  }
}

export const defaultRuntime = new WorkspaceUnlockRuntime();
