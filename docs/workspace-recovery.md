# Workspace recovery: passkey-bound wrapping and offline fallback

Status: **primitive implemented and tested; production unlock remains on the
mandatory offline recovery code until PRF support is verified per
authenticator/browser and the additive artifact-key migration below is
published.** No existing artifact is invalidated by this design.

## Invariants

1. Cloudflare Access is perimeter identity only. It can never recover or decrypt
   a workspace, alone or in combination with a PEP session.
2. A normal passkey assertion signature is authentication evidence, **not** key
   material: assertions vary and authenticator private keys are inaccessible.
   Only the WebAuthn PRF extension output may be used, and only when the
   authenticator verifiably returns it.
3. The PRF output, the derived wrapping key and the unwrapped root key never
   leave the browser in plaintext. The server stores only opaque wrapped bytes
   plus public metadata.
4. A high-entropy, offline recovery secret is a mandatory fallback. A workspace
   must always remain recoverable without any passkey.
5. Adding a recovery credential requires an already-trusted recovery factor, not
   perimeter identity alone.
6. No raw private data in persistent browser storage. Only wrapped ciphertext
   and non-secret metadata may be persisted server-side.

## Root-key model

A workspace has a random 32-byte **workspace root key (WRK)**, generated in the
browser on first provisioning and never stored in plaintext. Every recovery
credential wraps the same WRK:

```
recovery credential ──► wrapping key ──► AES-256-GCM(WRK) ──► server-stored record
```

Wrapping-key derivation (`web/workspace-shell/src/recovery-wrapping.ts`):

```
passkey:  PRF output ──HKDF-SHA256(salt, info="evergreen/workspace-recovery/v1")──► AES key
offline:  recovery secret (32 high-entropy bytes) ──same HKDF──► AES key
record:   { version, algorithm, salt, iv, wrapped_root_key, credential_id, label }
```

The record carries `version = 1` and `algorithm = "HKDF-SHA256/AES-256-GCM"` so a
future KDF/algorithm can be introduced without ambiguity. AAD binds the version
string, so a record cannot be reinterpreted under another algorithm. The offline
secret is HKDF-extracted before use, so it is never used as a raw AES key.

## Server storage

Additive table/record per workspace:

| field | meaning |
| --- | --- |
| `credential_id` | WebAuthn credential id (public) |
| `label` | operator-visible device name |
| `version`, `algorithm` | wrapper scheme |
| `salt`, `iv`, `wrapped_root_key` | opaque bytes |
| `created_at_ms`, `last_used_at_ms` | coarse lifecycle only |
| `revoked_at_ms` | soft revoke |

The server never receives the PRF output, wrapping key, or WRK. Revoking a
wrapper deletes/deactivates only that record; it does **not** rotate the WRK.
Rotating the WRK (after suspected compromise or recovery-code use) re-wraps the
new WRK under every remaining credential and republishes the artifact under a
new KID and immutable release manifest.

## New-device flow

```
Cloudflare Access ──► explicit "Open Private Workspace" ──► passkey (user verification)
        │
        ├─ synced, recovery-capable passkey with PRF ──► PRF output ──► unwrap WRK transparently
        └─ otherwise ──► one offline recovery-code entry ──► WRK
                              └─► offer "add this passkey as a recovery credential"
```

Adding a new credential (a new wrapper) requires either an existing trusted
recovery factor that just unwrapped the WRK, or a second-device approval. A bare
Cloudflare Access session is refused.

## Additive artifact-key migration

Today the artifact keypair is derived from the offline unlock secret:
`HKDF(unlock_secret, "private-execution/workspace-unlock/v1" || version || kid)`.
Moving to a WRK is an additive migration:

1. **Artifact format v2** introduces `key_source = ROOT_KEY`. The v1 format and
   its derivation must remain accepted for existing artifacts; a v2 artifact is
   only produced on an explicit re-seal after every recovery credential wraps
   the new WRK.
2. Re-seal with a **new KID** and a new immutable release manifest. Never reuse a
   KID across key sources.
3. Keep the prior release directory and `previous` symlink for rollback. Rollback
   restores the v1 artifact and the old derivation path; both must be tested.
4. The shell selects the derivation from the authenticated descriptor's
   `artifact_version`/`key_source`; an unknown value fails closed (`U5_ARTIFACT`).
5. The `PUBLIC_KEY_FINGERPRINT` in the release manifest is compared against the
   enrolled key before delivery in both modes, so a migration mistake is
   rejected before any transport crypto.

Until step 1–5 are implemented and browser-tested, the shell must not advertise
or attempt passkey recovery; the offline recovery code remains the production
path. `web/workspace-shell/src/recovery-wrapping.ts` exposes the primitives
(`wrapWithPrf`/`unwrapWithPrf` return `null` when PRF is unavailable) so the
migration can land without touching the existing unlock contract.

## Credential and device management (UI)

- List trusted credentials by label and last-used coarse bucket.
- Revoke a wrapper without rotating the root key.
- Add a recovery passkey (requires a trusted recovery factor).
- Rotate the root key after suspected compromise or recovery-code use, then
  republish the artifact + manifest.

## Tests

`web/workspace-shell/src/recovery-wrapping.test.ts` (node:test):

- random root key/salt generation;
- offline wrap/unwrap roundtrip;
- wrong secret, tampered record, wrong version/algorithm and wrong salt all fail
  closed without revealing the key;
- invalid root keys refused before any crypto;
- PRF extraction returns `null` unless the authenticator produced output;
- passkey wrapping returns `null` without PRF and round-trips with it; a
  different authenticator's PRF cannot unwrap.
