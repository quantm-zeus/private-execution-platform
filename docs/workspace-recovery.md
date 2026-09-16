# Workspace Root Key: passkey unlock, offline recovery and release binding

Status: **implemented** as the product path. The previous release-bound
"unlock secret" model is legacy: its wrapper records (`key_source =
"unlock_secret_v1"`) remain parseable only as bounded migration data and are
never selected by the normal flow.

## Model

One workspace has exactly one **32-byte Workspace Root Secret**, generated in
the browser exactly once during initial setup. It is never persisted in
plaintext and never sent to the server.

The stable workspace recipient keypair is derived from that root secret under a
**fixed, release-independent derivation context**
(`base64(sha256("evergreen/workspace-root-key/v2")[0..16])`). The context is a
protocol constant, never a release id or KID. Consequences:

1. The workspace public identity is identical for every release.
2. Every future release is HPKE-sealed to the same stable public key, so there is
   no reseal step and the operator never re-enters a recovery code at deploy.
3. Per-artifact cryptographic freshness comes from the HPKE envelope randomness
   and the release metadata (release id, artifact digest) bound to the artifact
   over the authenticated channel, not from changing the workspace identity.

```
Workspace Root Secret (32B, client-only)
   ├─ HKDF/context ──► stable X25519 recipient keypair ──► public identity (server-stored)
   ├─ passkey PRF output ──HKDF──► AES-256-GCM wrapping key ──► PRF wrapper   (server-stored ciphertext)
   └─ offline recovery code ─HKDF──► AES-256-GCM wrapping key ──► recovery wrapper (server-stored ciphertext)
```

## Invariants

1. Cloudflare Access is perimeter identity only. It can never recover or decrypt
   a workspace, alone or with a PEP session.
2. A normal WebAuthn assertion signature is authentication evidence, **not** key
   material. Only the WebAuthn PRF extension output may be used, and only when
   the authenticator verifiably returns it. `recovery-wrapping.ts` returns
   `prfOutput: null` rather than falling back to the signature.
3. The root secret, the recovery code, the PRF output, the derived wrapping key
   and the unwrapped root never leave the browser in plaintext. The server
   stores only the public identity plus opaque wrappers and public metadata.
4. The offline recovery code is a separate high-entropy secret shown exactly
   once at setup. It is the mandatory fallback when no PRF passkey is available.
   Losing both every passkey and the recovery code is intentionally unrecoverable
   by the server.
5. Adding or revoking a wrapper requires proof of possession of the workspace
   private key (see *Authorization*), not perimeter identity alone.
6. No raw private data in persistent browser storage. Only public identity and
   wrapped ciphertext are stored server-side.

## Initial setup (once per workspace)

After Access + a verified passkey, when `GET /internal/workspace/identity`
reports `configured: false`:

1. Generate the Workspace Root Secret and a separate recovery code locally.
2. Derive the stable public key and its SHA-256 fingerprint.
3. Wrap the root under a passkey-PRF wrapper (when the authenticator supports
   PRF) and under the offline recovery code (always).
4. Upload only the public key + opaque wrappers to
   `POST /internal/workspace/identity` (create-once).
5. Show the recovery code exactly once with an explicit saved-confirmation step.

Setup does **not** require a published release: the stable identity must be
creatable on a clean deployment, after which release tooling seals to it. The
recovery code is shown and gated on confirmation before any unlock attempt, so a
release that is not yet sealed to the new identity cannot cause the code to be
lost.

The public identity is client-generated and uploaded; the operator never
receives or handles the Workspace Root Secret, and no helper page derives a
public key for manual resealing. Release tooling is given only the derived
public key (`WORKSPACE_PUBLIC_KEY_B64`).

## Normal login and new devices

```
Cloudflare Access ─► Passkey ─► auto-unlock ─► Workspace
```

For each stored, non-revoked PRF wrapper the shell requests a PRF assertion,
unwraps the root secret locally, and **validates the derived stable fingerprint
against the durable workspace identity** before decrypting the current release.
A new device with a usable PRF passkey therefore unlocks immediately.

If no PRF wrapper succeeds, the shell offers a small
**Having trouble signing in?** action. The recovery-code path unwraps the same
root, verifies the stable fingerprint, unlocks, and then offers to enroll the
new device's passkey (authorized by the recovery code, without rotating the
root).

## Server storage

The durable store (`apps/private-api/src/recovery.rs`, env
`PRIVATE_RECOVERY_WRAPPER_STORE_PATH`) persists:

| field | meaning |
| --- | --- |
| `identity` | stable public key + server-computed fingerprint (public) |
| `credential_id_b64` | WebAuthn credential id or the reserved offline-recovery id |
| `label` | operator-visible device name |
| `version`, `algorithm`, `key_source` | wrapper scheme (`workspace_root_v2`) |
| `salt_b64`, `iv_b64`, `wrapped_root_key_b64` | opaque bytes |
| `created_at_ms`, `last_used_at_ms` | coarse lifecycle only |
| `revoked_at_ms` | soft revoke |

The identity is create-once and immutable; a second bootstrap is refused. Once a
release has been sealed to the stable context, the bootstrap additionally
requires the submitted public key to match that release manifest's recipient
fingerprint, so an authenticated session cannot squat the identity with a key it
controls (a legacy per-release manifest does not constrain the one-time
migration bootstrap). The bootstrap request uses `deny_unknown_fields`, so a
client can never smuggle a plaintext root secret, recovery code, PRF output or
unwrap key into a write. The store is file-backed with owner-only atomic writes,
refused symlinks, checked inode/permissions, and a bounded document size. A
corrupt identity (public key/fingerprint mismatch) refuses startup.

Without `PRIVATE_RECOVERY_WRAPPER_STORE_PATH` the whole surface answers `503`
and the workspace cannot be set up or unlocked in the stable-root model.

## Authorization (proof of possession)

Mutating a wrapper requires proof of possession of the workspace private key:

1. `POST /internal/workspace/recovery/challenge` seals a fresh random nonce to
   the **durable workspace public identity** under the fixed stable context and
   stores it under a single-use, session-bound, TTL-bounded challenge id.
2. The browser decrypts the nonce with its in-memory stable workspace key and
   returns it as `proof_b64`.
3. The server compares it in constant time and consumes the challenge.

The server never learns or validates a guess at the secret. Because the identity
is create-once and immutable, an attacker cannot enroll a key they control and
self-approve. A normal passkey signature is never key material.

## Release tooling

`scripts/workspace-artifact.mjs` seals every release to the stable context using
only `WORKSPACE_PUBLIC_KEY_B64` from a durable operator-safe source. The build
path never reads `WORKSPACE_UNLOCK_SECRET_B64`; CI and release tooling never need
the root secret. `WORKSPACE_ARTIFACT_KID_B64` is deprecated: absent it defaults
to the stable context, and a foreign value fails closed. The mandatory
operational test (`scripts/workspace-release.test.mjs`) builds releases N and
N+1 from only the public key, switches the descriptor, and proves the same root
unlocks both.

## Credential and device management (UI)

The post-unlock security panel lists credentials by label, revokes a wrapper
(soft, no root rotation), and adds this device's passkey. Revoking the offline
recovery credential is called out as making the workspace unrecoverable if every
passkey is also lost. There is no in-product root rotation; rotating the root is
an operator runbook step that creates a new workspace identity.

## Migration from the release-bound model

Existing preview/release-bound state is legacy. The one-time migration is the
normal initial setup above, performed once in a controlled browser session. The
resulting stable public key is then used by release tooling to seal the current
release, so all future releases share the stable identity. A pre-v2 store has no
`identity`; the create-once bootstrap writes the stable identity and its v2
wrappers, replacing any legacy `unlock_secret_v1` records, which the stable-root
flow never reads and which the bootstrap rejects as inputs.

## Tests

- `web/workspace-shell/src/workspace-root.test.ts` — root generation, recovery
  code round-trip and rejection, stable identity independence, PRF and recovery
  wrapper round-trips, wrong code/tamper/legacy failures, revoked exclusion, and
  a static no-persistent-storage check.
- `web/workspace-shell/src/recovery-client.test.ts` — public identity parsing,
  bootstrap body contains no secret material, wrapper list parsing rejects
  legacy/unknown sources, proof-of-possession flow.
- `web/workspace-shell/src/unlock-runtime.stages.test.ts` — the runtime derives
  from the fixed context and refuses a release sealed under any other KID.
- `apps/private-api/src/recovery.rs` / `lib.rs` — identity validation,
  create-once bootstrap, secret-field rejection, proof-of-possession matrix,
  file-store lifecycle.
- `scripts/workspace-release.test.mjs` — stable-context sealing, foreign-KID
  rejection, and the N/N+1 single-root operational proof.
- `web/e2e/specs/shell.spec.ts` — recovery unlock, wrong-code rejection, and no
  KID/public-key/fingerprint/recovery input on the normal login screen.
