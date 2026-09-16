# ADR 0003: Stable Workspace Root Key (v2)

Status: accepted (implementation in progress on `worker/deepseek-final-release`).

## Context

The previous model bound the workspace recipient keypair to the release: the
keypair was `derive_workspace_keypair(unlock_secret, version, kid)` and the
"offline recovery code" *was* the operator-held unlock secret. A new release
with a new KID changed the recipient identity, so it required a reseal and the
operator to re-enter a recovery code. That is unacceptable product UX and it
conflates release metadata with workspace identity.

## Decision

Introduce a stable Workspace Root Key:

1. One client-generated 32-byte Workspace Root Secret per workspace, created
   exactly once and never persisted in plaintext or sent to the server.
2. A fixed 16-byte derivation context
   (`base64(sha256("evergreen/workspace-root-key/v2")[0..16])`) derives the
   stable workspace recipient keypair. The context is a protocol constant; KID
   and release id are metadata that must not change the identity.
3. Every release is HPKE-sealed to the same stable public key. Freshness comes
   from the HPKE envelope randomness and the signed release manifest, not from a
   changed identity.
4. The browser wraps the root under a passkey WebAuthn PRF output and under a
   separate high-entropy offline recovery code. The server persists only the
   public identity plus opaque wrappers/metadata in a durable, create-once
   store.
5. Normal login is Access -> Passkey -> auto-unlock. Recovery lives behind a
   small "Having trouble signing in?" action. Initial setup shows the recovery
   code once behind a saved-confirmation step.
6. Release tooling obtains only `WORKSPACE_PUBLIC_KEY_B64` from an
   operator-safe source; the root secret is never required in CI or server
   release tooling.

## Alternatives considered

- **Keep the release-bound KID derivation and re-seal per release.** Rejected:
  it requires operator reseal and a recovery-code re-entry, and makes the
  workspace identity a function of release metadata.
- **Add a new unchecked "random root" WASM primitive.** Rejected: the existing
  audited `derive_workspace_keypair` already gives domain-separated
  deterministic derivation; a fixed context constant plus a new wrapper key
  source (`workspace_root_v2`) is a smaller, reviewable change that does not
  alter the audited artifact envelope format.
- **Require a virtual authenticator with PRF for every login.** Rejected: the
  offline recovery code must remain a mandatory fallback, so setup succeeds with
  a recovery wrapper alone and PRF is an optional convenience.

## Consequences

- The workspace recipient identity is release-independent; N and N+1 both
  decrypt with the same root and no reseal.
- The server gains a durable public identity store; recovery proof-of-possession
  no longer depends on a release manifest or session enrollment.
- Losing both every passkey and the recovery code is intentionally
  unrecoverable by the server.
- Legacy `unlock_secret_v1` wrappers are bounded migration data, ignored by the
  normal flow and rejected at bootstrap.

## Invariant impact

Does not change a locked invariant. It strengthens INVARIANTS.md #1 (no inbound
ports/boundaries) and keeps the server unable to recover or decrypt a workspace.
