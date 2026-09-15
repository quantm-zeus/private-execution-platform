# Workspace recovery: passkey-bound wrapping and offline fallback

Status: **implemented additively.** The passkey-bound recovery flow (enroll,
unwrap, revoke, device management) is wired end-to-end and the mandatory offline
recovery code remains in place. No existing artifact is invalidated: recovery
wraps the *existing* unlock secret, so the artifact, its KID and its
derivation are unchanged. A random-root-key migration remains a future,
explicitly versioned step (see below).

## Invariants

1. Cloudflare Access is perimeter identity only. It can never recover or decrypt
   a workspace, alone or in combination with a PEP session.
2. A normal passkey assertion signature is authentication evidence, **not** key
   material: assertions vary and authenticator private keys are inaccessible.
   Only the WebAuthn PRF extension output may be used, and only when the
   authenticator verifiably returns it. `recovery-passkey.ts` returns
   `prfOutput: null` rather than falling back to the signature.
3. The PRF output, the derived wrapping key and the unwrapped root key never
   leave the browser in plaintext. The server stores only opaque wrapped bytes
   plus public metadata.
4. A high-entropy, offline recovery secret is a mandatory fallback. A workspace
   must always remain recoverable without any passkey.
5. Adding or revoking a recovery credential requires an already-trusted recovery
   factor, not perimeter identity alone (see *Authorization*).
6. No raw private data in persistent browser storage. Only wrapped ciphertext
   and non-secret metadata may be persisted server-side.

## Root-key model

The workspace root key material is the **existing** 32-byte high-entropy unlock
secret. Every recovery credential wraps that same secret:

```
recovery credential ──► wrapping key ──► AES-256-GCM(secret) ──► server-stored record
```

Wrapping-key derivation (`web/workspace-shell/src/recovery-wrapping.ts`):

```
passkey:  PRF output ──HKDF-SHA256(salt, info="evergreen/workspace-recovery/v1")──► AES key
offline:  recovery secret (32 high-entropy bytes) ──same HKDF──► AES key
record:   { version, algorithm, key_source, salt, iv, wrapped_root_key, credential_id, label }
```

The record carries `version = 1`, `algorithm = "HKDF-SHA256/AES-256-GCM"` and
`key_source = "unlock_secret_v1"`. `key_source` records *what* the wrapper
protects; a future random-root-key migration must introduce a new value rather
than reinterpret existing records. Integrity is provided by AES-GCM: the IV, the
wrapped bytes and the salt are all authenticated (a tampered salt derives a
different wrapping key and the tag check fails). The AAD is a constant domain
string; the version/algorithm/key-source fields are additionally checked by
explicit equality before any crypto, so a record cannot be silently
reinterpreted under another scheme. The offline secret is HKDF-extracted before
use, so it is never used as a raw AES key.

## Server storage

Additive table/record per workspace (`apps/private-api/src/recovery.rs`):

| field | meaning |
| --- | --- |
| `credential_id_b64` | WebAuthn credential id (public) |
| `label` | operator-visible device name |
| `version`, `algorithm`, `key_source` | wrapper scheme |
| `salt_b64`, `iv_b64`, `wrapped_root_key_b64` | opaque bytes |
| `created_at_ms`, `last_used_at_ms` | coarse lifecycle only |
| `revoked_at_ms` | soft revoke |

The server never receives the PRF output, wrapping key, or the unlock secret.
Revoking a wrapper deactivates only that record; it does **not** rotate the
secret. The store is file-backed with owner-only atomic writes, refused
symlinks, checked inode/permissions, and a bounded document size — the same
properties as the passkey credential store. Without
`PRIVATE_RECOVERY_WRAPPER_STORE_PATH` the whole surface answers `503` and the
offline recovery code is the only credential.

## Authorization (proof of possession)

A bare authenticated session (or Cloudflare Access) must never be enough to add
or revoke a recovery credential. Mutating a wrapper therefore requires proof of
possession of the workspace private key:

1. `POST /internal/workspace/recovery/challenge` seals a fresh random nonce to
   the **enrolled workspace public key** (HPKE base mode — the same primitive
   that seals the release artifact) and stores it under a single-use,
   session-bound, TTL-bounded challenge id.
2. The browser decrypts that nonce with the in-memory workspace key and returns
   it as `proof_b64`.
3. The server compares it in constant time and consumes the challenge.

The server never validates a guess at the secret and never learns it; it only
checks that the client could open a challenge the server itself produced. A
challenge is issued only when the enrolled key matches the **immutable release
manifest's recipient fingerprint**, so an attacker cannot enroll a key they
control and then self-approve: mutating recovery requires an existing trusted
recovery factor. The cheap public bindings (manifest shape, artifact
version/KID, enrolled key, fingerprint) are checked before the full
manifest-vs-artifact byte validation, so a rejected request never forces a full
artifact hash. `add`, `revoke` and `touch` all require a proof; `list` is
read-only.

### Step-up verification

Adding or editing credentials happens while the shell already holds an
authenticated session. `/internal/auth/verify` therefore treats a ceremony that
arrives with a live session cookie as a **step-up**: it verifies the assertion,
consumes the single-use challenge, and keeps the existing session instead of
minting a replacement. Minting a new session would silently drop the workspace
enrollment bound to the old one (the enrollment ledger is keyed by session), so
the immediately following proof-of-possession call would fail
`enrollment_required`. A ceremony with no live session is an ordinary login and
mints a new session as before.

## New-device flow

```
Cloudflare Access ──► explicit "Open Private Workspace" ──► passkey (user verification)
        │
        ├─ synced, recovery-capable passkey with PRF ──► PRF output ──► unwrap secret transparently
        └─ otherwise ──► one offline recovery-code entry ──► unlock
                              └─► offer "add this passkey" (a fresh passkey ceremony + PRF wrap,
                                  authorized by the recovery code just entered)
```

## Additive root-key migration (future, explicitly versioned)

A random workspace root key would be a *new* key source, not a reinterpretation:

1. Introduce `key_source = ROOT_KEY` and keep accepting `unlock_secret_v1`.
2. Re-seal with a **new KID** and a new immutable release manifest. Never reuse
   a KID across key sources.
3. Keep the prior release directory and `previous` reference for rollback;
   rollback restores the existing artifact and derivation path. Both must be
   tested.
4. The shell selects the derivation from the authenticated descriptor's
   `artifact_version`/`key_source`; an unknown value fails closed (`U5_ARTIFACT`).
5. The manifest's recipient fingerprint is compared against the enrolled key
   before delivery in both modes, so a migration mistake is rejected before any
   transport crypto.

## Credential and device management (UI)

- List trusted credentials by label and last-used coarse bucket.
- Add a recovery passkey (requires a trusted recovery factor).
- Revoke a wrapper without rotating the secret.
- Rotating the secret after suspected compromise is an operator step that
  re-seals the artifact under a new KID and manifest, then re-wraps under every
  remaining credential.

## Tests

- `web/workspace-shell/src/recovery-wrapping.test.ts` — random root key/salt
  generation; offline wrap/unwrap roundtrip; wrong secret, tampered record,
  wrong version/algorithm and wrong salt all fail closed; PRF extraction returns
  `null` unless the authenticator produced output.
- `web/workspace-shell/src/recovery-client.test.ts` — wrapper list parsing and
  rejection, challenge/proof flow, wire bodies, typed error classification.
- `web/workspace-shell/src/recovery-passkey.test.ts` — PRF request shape,
  `null` without PRF, fail-closed unsupported/cancelled/rejected paths.
- `apps/private-api/src/recovery.rs` — input validation, bounded/single-use/
  session-bound challenges, file-store lifecycle and on-disk safety.
- `apps/private-api/src/lib.rs` — endpoint authorization matrix: proof of
  possession required, wrong/expired/replayed proof rejected, surface closed
  without a configured store.
