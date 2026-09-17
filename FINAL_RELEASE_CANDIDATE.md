# Final Release Candidate

**Repository:** `quantm-zeus/private-execution-platform`
**Branch:** `worker/deepseek-final-release`
**Exact release SHA (code):** `a0ee01b914253d030c72757f031ee5d60091864a`
**Base:** `fc725aa` — merge of the reviewed UX/KLine/FOMO candidate `51f7445` and the durable core `89a80ed`
**GitHub Actions CI (exact SHA):** [run 35109740599](https://github.com/quantm-zeus/private-execution-platform/actions/runs/35109740599) — **success** (`rust`, `web-boundary`, `web-e2e`)
**State:** reviewed, exact-SHA CI green, deployable. **Not deployed by this lane. `TRADING_ENABLED=false`. No real funds were touched.**

> **Superseded candidate notice.** This document records the earlier `a0ee01b`
> candidate. The branch `worker/deepseek-final-release` now carries the **stable
> Workspace Root Key v2** architecture (ADR 0003, `docs/workspace-recovery.md`)
> and the concrete-but-disabled Base/Privy transports in
> `apps/private-api/src/live.rs`. The current HEAD is **pending a fresh native
> GPT-5.6 Sol/high audit** and is not deployed.

This candidate is the integration of the merged reviewed slices plus the fail-closed production
private-API / trading composition. It does not enable live signing or submission, and it does not
add optional features.

---

## 1. What this candidate contains

### 1.1 Private web: access, passkey, unlock, recovery (preserved)
- Cloudflare Access is the perimeter identity only; it can never decrypt a workspace.
- Explicit **Open Private Workspace** action: no passkey ceremony on mount. Passkey (WebAuthn) →
  automatic descriptor/KID discovery → local in-browser unlock. A normal user never types a KID.
- Immutable release directory + `manifest.json`, atomic `current`/`previous` switch, `rollback`.
  `WORKSPACE_RELEASE_MANIFEST` is the **normal production mode**: an absent manifest refuses startup
  unless the operator explicitly sets `WORKSPACE_ALLOW_NO_MANIFEST=true`; a present-but-blank path is
  always a misconfiguration, never an opt-out.
- Recovery wrappers (stable Workspace Root Key v2): passkey-PRF and a mandatory
  high-entropy offline recovery code wrap one client-generated root; the recovery
  code is shown once at setup and cleared from the DOM/reactive signal before the
  first network await.
- Verified this candidate does not regress the flow (no web application code changed except one
  comment); the new manifest policy is startup-only.

### 1.2 Chart (reviewed FOMO path preserved)
- `PEP → loopback read-only fomo-mcp bridge → encrypted get_chart / StreamSource → KLineChart Pro`.
- The browser never calls FOMO/MCP directly: the transport allowlist is same-origin and the shell CSP
  is `connect-src 'self'`.
- Realtime is **REST polling of `/market/latest` at ≥5 s only**; a payload whose provenance is not
  `polling` (or that claims a promoted WebSocket) is refused. No WebSocket was promoted.
- `get_chart` is gated server-side on the dedicated `chart` capability. `market` stays false, so
  `search_token`/`get_token` remain determinate `capability_missing` denials.
- A configured, reachable stream is observed by a bounded startup probe; an unreachable bridge leaves
  `realtime` unadvertised, so the browser is never told a dead stream is live.

### 1.3 Trading path (fail-closed, not live)
- `apps/private-api/src/trading.rs` turns injected seams into `trading_core::capability::CapabilityReadiness`.
- `production::build_opaque` advertises a capability only from a typed healthy proof (and the trading gate):
  - `execute` = durable attempt store **and** Base chain **and** Privy signer healthy;
  - `limits` = limit-engine proof **and** the full execution proof (a limit order is a mutation);
  - `twap`/`rfq`/`withdraw`/`wallet_limits` = the execution proof;
  - `market`/`realtime` = their own read-dependency proof; `chart` = the configured dispatcher.
- Concrete Base RPC, Privy HTTP signing and signed-payload transports exist in
  `apps/private-api/src/live.rs` but are composed only behind `TRADING_CORE_LIVE=1`;
  the shipped default injects no live probe, so **`execute` is never advertised**
  and every mutation is an authenticated `capability_missing` denial — never a
  fabricated success.
- Durable exactly-once store: `execution_store::PostgresExecutionAttemptStore`, connected only behind
  the explicit `TRADING_CORE_LIVE=1` opt-in with all endpoints present. Startup connect and the first
  health read are bounded (5 s); health requires migration
  `infra/postgres/migrations/0003_execution_attempts.sql`, so a reachable database without it cannot
  prove execution. A partial live configuration refuses startup.
- `TRADING_ENABLED` defaults to `false` and is parsed strictly; live wiring is presence-only and never
  reads, logs, or serializes a credential value.

---

## 2. Gate evidence

### 2.1 GitHub Actions, exact SHA `a0ee01b` (authoritative)
Run [35109740599](https://github.com/quantm-zeus/private-execution-platform/actions/runs/35109740599) —
**success**:
- `rust`: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- `web-boundary`: `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test:web`, `pnpm test:shell`,
  `node --test scripts/workspace-release.test.mjs`, `pnpm verify:web-boundary`
- `web-e2e`: payload/shell builds, `cargo build -p crypto-envelope --bins --example test-session-host`,
  `playwright install --with-deps chromium firefox`, `playwright test` (both engines)

### 2.2 Local serialized gates (`flock /tmp/deepseek-global-heavy-gate.lock`, exact SHA)
| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace` | PASS |
| `pnpm install --frozen-lockfile` | PASS |
| `pnpm typecheck` | PASS |
| `pnpm test:shell` | PASS |
| `pnpm test:web` | PASS |
| `node --test scripts/workspace-release.test.mjs` | PASS |
| `pnpm build:workspace-payload` | PASS |
| `pnpm build:workspace-shell` | PASS |
| `pnpm verify:web-boundary` | PASS |
| `cargo build -p crypto-envelope --bins --example test-session-host` | PASS |
| `pnpm build:workspace-payload` / `build:workspace-shell` (post-boundary E2E rebuild) | PASS |
| `playwright install chromium firefox` | PASS |
| `playwright test` (chromium + firefox) | 73/74 PASS* |

\* The single local miss is chromium `shell.spec.ts` "decrypts the artifact in memory and boots the
private payload", which asserts that the artifact-grant request always fires. Locally the grant request
was not observed (`valueAtFirstGrant === null`) while the DOM-clearing assertion passed; the same spec
passes in CI on both engines and locally on Firefox. It is a local harness observation, not a code
defect: this candidate changes no web/shell application code, and the authoritative CI `web-e2e` job is
green. Reproduced deterministically only in the local, `--no-sudo` sandbox environment.

---

## 3. Review evidence

- Two independent read-only adversarial reviews of the composition (`e77ee16`) found **no CRITICAL and
  no HIGH** findings; the composition was verified fail-closed (no mutating capability without a typed
  proof; `execute` unprovable in the shipped binary; no credential read/logged; FOMO chart path and
  unlock/recovery preserved).
- A third read-only delta review of the follow-up fix verified the fixes and again found **no
  CRITICAL/HIGH**; the only actionable item (poll-floor wording) was fixed in `a0ee01b`.
- Fixes applied after review: bounded durable-store startup I/O; unconditional partial
  `TRADING_CORE_LIVE` refusal; `limits` additionally requires the execution proof; ≥5 s REST poll floor
  (clamped, not rejected); doc/comment accuracy.

---

## 4. Operator-owned dependencies (no secrets are shipped)

- **Perimeter:** Cloudflare Access in front of a single-origin gateway (`/internal/*` → private-api,
  `/v1/*` → edge-gateway). The edge-gateway refuses a non-loopback `EDGE_BIND_ADDR` until cryptographic
  Access JWT validation exists.
- **Passkey:** `PRIVATE_RP_ID`, `PRIVATE_ORIGIN`, `PRIVATE_PASSKEY_STORE_PATH`,
  `PRIVATE_PASSKEY_ENROLL_SECRET` (≥32 bytes, remove/rotate after bootstrap),
  `PRIVATE_PASSKEY_ALLOW_ADDITIONAL`.
- **Release:** `WORKSPACE_ARTIFACT_PATH`, `WORKSPACE_RELEASE_MANIFEST` (required in normal mode),
  optional `WORKSPACE_ALLOW_NO_MANIFEST=true` (explicit weaker mode), and the operator's artifact
  sealing key material (`WORKSPACE_PUBLIC_KEY_B64`, `WORKSPACE_ARTIFACT_KID_B64`) held outside the repo.
- **Optional relay:** `PRIVATE_API_RELAY_BIND_ADDR` + `PRIVATE_API_TLS_CERT`/`_KEY`/`_CA` (strict
  all-or-none).
- **FOMO bridge:** `PRIVATE_FOMO_MARKET_URL` (loopback), `PRIVATE_FOMO_MARKET_API_KEY_FILE`,
  `PRIVATE_FOMO_STREAM_TARGET`, `PRIVATE_FOMO_STREAM_POLL_MS` (≥5000; faster values are clamped).
  Requires the coordinated `fomo-mcp` read-only `/market/bars` bridge
  (`worker/deepseek-pep-market-source`, commit `dced9624`) to be deployed by the operator.
- **Live trading (residual, not enabled):** `TRADING_CORE_LIVE=1`, `EXECUTION_DATABASE_DSN` (Postgres
  with migration `0003`), `BASE_RPC_ENDPOINT`, `PRIVY_HTTP_ENDPOINT`, plus the concrete chain and
  signing transports in `apps/private-api/src/live.rs` (disabled by default). `TRADING_ENABLED` must stay `false`.
- **Toolchain:** Rust `1.98.1` (`rust-toolchain.toml`), Node 24, pnpm `11.22.0`.

---

## 5. Deploy steps (operator)

1. Check out the exact SHA `a0ee01b914253d030c72757f031ee5d60091864a` and confirm CI run 35109740599 is green.
2. `pnpm install --frozen-lockfile`
3. `pnpm build:workspace-payload` and `pnpm build:workspace-shell`
4. Build and seal the encrypted artifact for the operator's enrolled recipient key and public-key
   fingerprint, then publish the immutable release (writes `manifest.json` + `workspace.artifact`):
   `node scripts/workspace-release.mjs build --root /var/lib/evergreen/releases --source-sha <sha>`
5. `node scripts/workspace-release.mjs validate --root /var/lib/evergreen/releases`
   (and `current` to confirm the active release id), then
   `node scripts/workspace-release.mjs check-deploy --root /var/lib/evergreen/releases --shell <served-shell-dir> --artifact <served-artifact> --manifest <served-manifest>`
   to prove the served shell, manifest and artifact all resolve into that one
   release. Serve the shell from `/releases/current/shell` — never a pinned
   release id or a separately built `web/workspace-shell/dist`.
6. Configure the environment from §4, keeping `TRADING_ENABLED=false` and
   `WORKSPACE_RELEASE_MANIFEST` set. Do not set `TRADING_CORE_LIVE=1` unless a complete live
   composition exists.
7. Start `apps/private-api` bound to loopback (`PRIVATE_API_BIND_ADDR`, default `127.0.0.1:8081`) and
   the edge-gateway on a loopback bind behind Cloudflare Access.
8. Verify `GET /health` (liveness) and `GET /ready` (dependency readiness; `stream` is only required
   when `realtime` is advertised by a reachable bridge).

## 6. Rollback steps (operator)

1. `node scripts/workspace-release.mjs rollback --root /var/lib/evergreen/releases`
   — atomically swaps `current`/`previous`; a released directory is never rewritten.
2. Restart `apps/private-api` so the release manifest and artifact paths resolve to the previous release.
3. Confirm `GET /ready` is healthy and the workspace unlocks in a browser with the previously working
   enrollment/recovery material.

---

## 7. Residual / explicitly not composed

- Live signing, chain submission and balances are **not enabled**. Concrete
  `BaseRpcChainTransport`/`HttpPrivyClient` transports exist in
  `apps/private-api/src/live.rs` but are gated behind the disabled
  `TRADING_CORE_LIVE` opt-in, so `execute` is never advertised and no
  real-funds path exists.
- The deployed `fomo-mcp` image does not yet expose `/market/bars`; the bridge is implemented on the
  coordinated branch and pending operator deployment. Until then a configured PEP leaves `realtime`
  unadvertised and the chart renders only local, already-decrypted frames — never fabricated data.
- Edge perimeter trust is header-presence only (loopback binding is the mitigation); cryptographic
  Cloudflare Access JWT validation is not implemented.
- `main` branch protection and required-status-check enforcement are a repo-governance action.

## 8. Evidence marker

The same directory contains `FINAL_READY`, which records the exact SHA and CI run for automation.
This candidate is **FINAL_READY**; production deployment is an operator action.
