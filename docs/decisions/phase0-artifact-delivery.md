# ADR: Phase 0 authenticated artifact delivery (grant + HPKE envelope)

## Status

Accepted (server side integrated at 6f01479). Browser decryption seam is
fail-closed pending an operator decision (see "Deferred" below).

## Context

The private workspace build is packaged and AES-256-GCM sealed at build time
(`scripts/workspace-artifact.mjs`); the sealing key exists only in the build
environment. Phase 0 audit items D+E required an authenticated delivery path
from private-api to the browser with no plaintext at the edge and no caching.

## Decision (server side — implemented)

- `POST /internal/artifact/grant` (session-cookie authenticated) mints an
  `auth::ArtifactGrant` bound to the live `SessionId` and generates a fresh
  ephemeral X25519 HPKE responder keypair per grant. Only the OFFER half
  (16-byte `kid` + 32-byte public key, base64) is returned. The private half
  lives in RAM inside the pending grant, is never serialized or logged, and
  is dropped at first use. The offer rides the authenticated cookie channel,
  satisfying ADR 0001's requirement that the offer be delivered with
  integrity by the authenticated session.
- `POST /internal/artifact` requires BOTH the grant transport cookie and the
  live session cookie of the grant's bound session. The grant is consumed
  (single-use) before any further work; replay/expiry/mismatch all fail
  closed with 401 and the grant cookie cleared. The request echoes
  `grant_id` and `kid`; mismatch fails closed.
- The sealed artifact is loaded from `WORKSPACE_ARTIFACT_PATH` (fail-closed
  503 if unset/unreadable) and returned as a crypto-envelope s2c
  `Envelope`: wire `kid(16) || nonce(12) || sequence(u64 BE) ||
  ciphertext` with AAD `kid || sequence`. Response is
  `application/octet-stream`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, grant cookie cleared.
- The grant ledger in `AuthState` is TTL-pruned and bounded
  (`MAX_LIVE_ARTIFACT_GRANTS`); beyond budget, minting fails closed (503).
- Edge opaque responses (all of /v1/bootstrap, /v1/sync, /v1/blob) carry
  `no-store`, `CSP: default-src 'none'; frame-ancestors 'none'; base-uri
  'none'`, `nosniff`, `no-referrer`, on success and error paths. Edge
  remains byte-opaque; no routes or semantics were added.

## Decision (browser side — implemented, seam fail-closed)

`web/workspace/src/bootstrap.ts` implements the browser flow up to the
crypto seam: authenticated grant fetch (same-origin, credentials include),
strict server-offer validation, the wire format mirroring, request-body
construction, and strict envelope parsing (including sequence != 0). All of
it is node-tested against fixtures by `scripts/verify-workspace-bootstrap.mjs`
(exercising the actual shipped source via on-the-fly transpilation).

The HPKE initiation and ChaCha20-Poly1305 decryption are deliberately NOT
hand-rolled. WebCrypto provides X25519 and HKDF but no RFC 9180 key
schedule and no ChaCha20-Poly1305; reimplementing either in JavaScript
would introduce unaudited custom crypto, which the Phase 0 fail-closed
rules forbid. `hpkeInitiate()` throws `BootstrapError` until an audited
browser implementation is provided.

## Deferred (operator decision required)

Deliver the audited Rust `crypto-envelope` HPKE/AEAD to the browser as a
WASM build of the already-reviewed crate, then wire `hpkeInitiate()` +
in-memory decryption behind it. Until then the workspace shell renders a
neutral "decryption pending" state and holds no usable plaintext. No
plaintext, key material, or derived secret is ever written to storage
(no localStorage/sessionStorage/IndexedDB/cookies) at any point in the
flow, implemented or deferred.

## Consequences

- The server delivery boundary is complete and reviewed; the browser seam
  is honest about its limits rather than shipping fake crypto.
- Single-use grant consumption means a response lost in transit costs one
  round trip (re-mint), not any security exposure.
- Grant/session binding survives cookie pairing attacks (tested); expiry
  is enforced twice (prune + validation) and tested at the HTTP layer.
