/* tslint:disable */
/* eslint-disable */

/**
 * WASM-owned HPKE initiator session for transport. The underlying session keys
 * are held only inside this struct in WASM memory and are never exposed.
 */
export class WasmInitiatorSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Authenticated decrypt of a server->client session envelope:
     * `kid(16) || nonce(12) || sequence(u64 BE) || ciphertext`.
     */
    decrypt(envelope_wire: Uint8Array): Uint8Array;
    /**
     * The 32-byte encapsulated key (public wire material) for POSTing to
     * the server.
     */
    encapsulated_key(): Uint8Array;
    /**
     * Runs the audited `initiator_establish` against the validated offer.
     */
    static establish(offer: WasmOffer): WasmInitiatorSession;
}

/**
 * Server-published HPKE offer, validated strictly at construction.
 */
export class WasmOffer {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * `kid`: exactly 16 bytes; `recipient_public_key`: exactly 32 bytes and
     * not all-zero. Structural violations fail with a generic input error.
     */
    constructor(kid: Uint8Array, recipient_public_key: Uint8Array);
    /**
     * The kid as raw bytes (public wire material).
     */
    readonly kid: Uint8Array;
}

/**
 * WASM-held workspace key derived deterministically from an exact 32-byte
 * unlock secret + canonical kid/version context.
 *
 * Private key material lives ONLY in WASM memory, is zeroized on drop,
 * and has no accessor. ONLY the public key is exportable.
 */
export class WasmWorkspaceKey {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Authenticated decrypt of a sealed workspace artifact envelope:
     * `version(1) || kid(16) || encapsulated_key(32) || ciphertext`.
     *
     * Fails closed on wrong secret, wrong kid, wrong version, tampering,
     * or truncation with generic error. Returns plaintext bytes.
     */
    decrypt_artifact(artifact_wire: Uint8Array): Uint8Array;
    /**
     * The key identifier (kid) associated with this workspace key.
     */
    kid(): Uint8Array;
    /**
     * Deterministically derives the workspace keypair.
     *
     * Requirements:
     * - `unlock_secret`: exactly 32 bytes and not all-zero.
     * - `version`: exactly protocol version 1.
     * - `kid`: exactly 16 bytes.
     */
    constructor(unlock_secret: Uint8Array, version: number, kid: Uint8Array);
    /**
     * The derived 32-byte X25519 public key (safe to export to server/build pipeline).
     */
    public_key(): Uint8Array;
    /**
     * The protocol version of this workspace key.
     */
    version(): number;
}

/**
 * Standalone convenience function to decrypt a workspace artifact using unlock secret.
 * Derives key in RAM, decrypts, and zeroizes key material.
 */
export function decrypt_workspace_artifact(unlock_secret: Uint8Array, version: number, kid: Uint8Array, artifact_wire: Uint8Array): Uint8Array;

/**
 * Standalone convenience function to derive workspace public key from unlock secret.
 * Returns ONLY the 32-byte public key. Private key is zeroized and discarded.
 */
export function derive_workspace_public_key(unlock_secret: Uint8Array, version: number, kid: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasminitiatorsession_free: (a: number, b: number) => void;
    readonly __wbg_wasmoffer_free: (a: number, b: number) => void;
    readonly __wbg_wasmworkspacekey_free: (a: number, b: number) => void;
    readonly decrypt_workspace_artifact: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly derive_workspace_public_key: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasminitiatorsession_decrypt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasminitiatorsession_encapsulated_key: (a: number) => [number, number];
    readonly wasminitiatorsession_establish: (a: number) => [number, number, number];
    readonly wasmoffer_kid: (a: number) => [number, number];
    readonly wasmoffer_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmworkspacekey_decrypt_artifact: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacekey_kid: (a: number) => [number, number];
    readonly wasmworkspacekey_new: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmworkspacekey_public_key: (a: number) => [number, number];
    readonly wasmworkspacekey_version: (a: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
