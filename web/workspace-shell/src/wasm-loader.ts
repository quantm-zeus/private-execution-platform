// Loader for audited WASM crypto-envelope bindings.
//
// Invariant & threat model:
// - Audited WASM boundary only; no hand-rolled or ad-hoc browser crypto.
// - No private key or secret material is ever persisted or exposed to JS.
// - Linear memory is isolated to same-origin context under strict CSP.
// - All operations fail closed.

import init, {
  WasmInitiatorSession,
  WasmOffer,
  WasmWorkspaceKey,
  decrypt_workspace_artifact,
  derive_workspace_public_key,
} from "./wasm/crypto-envelope-wasm";

let wasmReady: Promise<unknown> | undefined;

export function loadWasm(): Promise<unknown> {
  if (!wasmReady) {
    wasmReady = init();
  }
  return wasmReady;
}

export {
  WasmInitiatorSession,
  WasmOffer,
  WasmWorkspaceKey,
  decrypt_workspace_artifact,
  derive_workspace_public_key,
};
