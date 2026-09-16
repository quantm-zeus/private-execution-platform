# Release / supply-chain helper scripts

Small, dependency-light helpers that produce release-provenance, SBOM, and
license evidence for this workspace.

- `sbom.sh` — emits an SPDX-ish JSON SBOM (`SPDX-2.3`) with one package entry
  per Rust workspace member, plus the source commit.
- `license-check.sh` — fails if any Rust workspace package has no `license`
  field. `UNLICENSED` is allowlisted with a warning (all workspace members use
  `license.workspace = true`, which resolves to `UNLICENSED`).
- `provenance.sh` — emits a JSON record with the source commit, tree hash,
  `Cargo.lock` SHA-256, and whether the working tree is dirty.

## Usage

Run them from anywhere; each script locates the repository root itself.

```sh
sh scripts/release/sbom.sh target/release/sbom.json
sh scripts/release/license-check.sh
sh scripts/release/provenance.sh target/release/provenance.json
```

Pass `-` (or omit the argument for `provenance.sh`) to write to stdout.

## Properties

- **Runnable locally and in CI.** They are plain POSIX `sh`, require only
  `cargo`, `git`, and `node` (or `python3` for `sbom.sh` /
  `license-check.sh`).
- **No credentials.** They read no secrets and make no network calls.
- **Never print secrets.** Output contains only commit hashes, checksums,
  package names/versions, and license identifiers.
- **Unpinned Cargo.lock at the workspace level.** There is no committed
  Cargo.lock pinning policy in the manifest; the lockfile itself must be
  committed and CI/release commands must pass `--locked` so builds resolve to
  exactly the committed dependency graph.

See `.github/workflows/release-supply-chain.yml` for the CI wiring. That
workflow does not build or test the workspace, so it stays fast and
credential-free.
