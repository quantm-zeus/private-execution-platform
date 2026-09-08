# Phase 0 public/private web artifact boundary

The public SolidStart site and private Solid/Vite workspace are physically separate builds with no cross-imports. Public output is scanned for accidental private execution terms and source maps.

The private workspace build is packaged with filenames inside the plaintext package and then encrypted with AES-256-GCM. The build key is supplied only through `WORKSPACE_ARTIFACT_KEY_B64`; the build never generates, stores, or prints that key. The final artifact exposes only a neutral magic/version, nonce, authentication tag, and ciphertext. Plaintext workspace build output is removed after artifact creation.

This build boundary does not deliver the artifact key to browsers. A later authenticated private-api/session flow must authorize key/session material delivery and browser-memory decryption. The CI scanner is defense in depth, not a substitute for cryptographic separation.
