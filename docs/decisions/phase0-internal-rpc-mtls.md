# Phase 0 internal RPC and mTLS boundary

Status: locked for Phase 0.

Production internal RPC is mTLS-only. This project does not provide a plaintext production gRPC listener or an insecure fallback mode.

Service TLS private keys are infrastructure identity keys used only for mutually authenticated service transport. They are distinct from wallet/signing keys. Raw wallet private keys are never introduced into this infrastructure; wallet signing remains delegated to Privy.

The untrusted Edge remains ciphertext-only. mTLS authenticates internal service connections and does not authorize Edge to inspect application semantics or plaintext trading state.

Certificate issuance, storage permissions, renewal and rotation are deployment concerns. Runtime code loads bounded PEM inputs, requires a client CA on servers, pins an expected peer DNS name on clients, and fails closed on missing or malformed identity material.
