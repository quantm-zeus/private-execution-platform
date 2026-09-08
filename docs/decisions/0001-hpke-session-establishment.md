# ADR 0001: HPKE Session Establishment

## Status

Accepted

## Context

Application sessions require authenticated key establishment and directional
traffic protection without persisting long-term session secrets.

## Decision

- Use HPKE RFC 9180 **Base mode**.
- Use suite `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305`
  (`X25519HkdfSha256` / `HkdfSha256` / `ChaCha20Poly1305`).
- Obtain OS entropy through a fallible API. On success, seed a transient
  `rand_chacha::ChaCha20Rng`; on failure, explicitly zeroize the seed buffer and
  return `EntropyUnavailable`.
- Derive two application session keys using separate HPKE exporter contexts:
  - client-to-server: `c2s`
  - server-to-client: `s2c`
- Retain the existing traffic framing: a 4-byte nonce prefix and a `u64`
  monotonically increasing sequence number.
- Verify AEAD authentication before updating replay/sequence state.
- Use fixed-size public-key and encapsulated-key wire values (32 bytes for
  X25519 in this suite).
- Reject all-zero X25519 low-order results through HPKE/X25519 behavior.
- X25519 private keys use the upstream zeroize-on-drop implementation.
- Application `SessionKey` values are `ZeroizeOnDrop`.
- Do not persist, resume, export, or serialize private keys or session key
  material.

## Residual Risk

`rand_chacha::ChaCha20Rng` has no safe `Zeroize` API, so its transient internal
CSPRNG state is not explicitly scrubbed. That state is short-lived and is never
logged or serialized. Revisit this decision if a zeroizing or fallible RNG API
becomes available.
