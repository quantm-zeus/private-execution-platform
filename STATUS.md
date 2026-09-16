# Project Status

> This file records what is **implemented, composed, deployed and residual**. It
> is evidence-linked, not a completion claim. The release audit
> (`.dsh/release-remediation/CODEX_SOL_HIGH_AUDIT.md`) remains the authoritative
> findings list; `docs/live-integration.md` records the per-slice contracts.

## Private web: authentication, unlock and release composition

Implemented and composed (exact-SHA CI green):

- Passkey (WebAuthn) operator authentication with a durable, owner-only
  credential store, single-use TTL-bounded ceremonies and comparison against the
  authenticated session.
- Explicit **Open Private Workspace** action: no passkey ceremony on mount; KID
  discovery, artifact grant and delivery are automatic after authentication.
  Normal users never type an artifact KID.
- Encrypted workspace release: immutable release directory + manifest, atomic
  `current`/`previous` switch and rollback, and an authenticated artifact
  descriptor with a server-side compatibility preflight that rejects an
  incompatible artifact/enrollment before any transport crypto.
- Privacy-safe typed unlock failures (`U1_WASM`…`U7_BOOT`) with recovery
  guidance; the recovery code is cleared from the DOM and reactive signal before
  the first network await and only bytes cross the async boundary.
- Production-faithful unlock proof: `verify:web-boundary` builds an artifact with
  the production build script and drives it through the real private-api loader,
  real HPKE delivery, inner decrypt and production package unpack.
- Passkey-bound recovery wrappers (WebAuthn PRF only, requested at enrollment and
  verified at use), proof-of-possession authorization for add/revoke, and
  trusted-credential management UI. The high-entropy offline recovery code stays
  a mandatory fallback and no existing artifact is invalidated. Revocation is
  soft (it deactivates the wrapper, not the stored ciphertext); rotating the
  secret is an operator re-seal runbook. See `docs/workspace-recovery.md`.
- Dependency readiness distinct from liveness, strict all-or-none relay
  configuration, and an edge-gateway refusal to bind a non-loopback address
  while perimeter assertion trust is presence-only.
- Read-only FOMO market bridge for the browser chart: PEP calls the local
  read-only `fomo-mcp` `/market/bars` / `/market/latest` endpoints with the
  bridge's own bearer key (PEP holds no FOMO tokens), serves `get_chart` history
  through a closed chain/window→resolution map with server-side normalization
  and range/bounds validation, and provides a bounded-polling realtime OHLCV
  `StreamSource`. Chart data is visual/non-authoritative. The KLineChart Pro
  renderer sits behind a renderer-agnostic local datafeed boundary. See
  `docs/live-integration.md`.

## Not composed / residual (do not overstate)

- **Trading Core production composition is not complete.** `apps/trading-core`
  remains a Phase-0 shell and the concrete per-user Trading Core backend
  (real `AgentBackend`, `InstrumentRegistry`, `WebContractBackend`) is not built
  by the binary. The private API now derives the advertised trading document
  from typed capability readiness (`apps/private-api/src/trading.rs` ->
  `trading_core::capability`): `market`/`execute`/`limits`/`realtime` require a
  healthy dependency proof, and `twap`/`rfq`/`withdraw`/`wallet_limits` ride the
  execution proof. The durable exactly-once attempt store is a real Postgres
  adapter (`crates/execution-store`, migration `0003`) connected only behind the
  explicit `TRADING_CORE_LIVE=1` opt-in. No concrete `BaseChainTransport` or
  `PrivyHttpClient` exists in-repo, so `execute` is never advertised,
  `live_execution_wired=false`, and every mutation remains an authenticated
  `capability_missing` denial. `TRADING_ENABLED` is parsed strictly and must
  stay `false`.
- Durable exactly-once execution has a concrete adapter
  (`execution_store::PostgresExecutionAttemptStore`) and a wired readiness/store
  seam, but the live relay that would use it is not composed in the deployed
  binary (no chain transport, signer, or payload source), so it is not yet
  release-safe for live funds.
- Live signing, chain submission, balances, persistence and most provider
  transports remain unwired. The PEP-side FOMO market bridge is implemented and
  tested, but the currently deployed `fomo-mcp` image does not yet expose
  `/market/bars`. The coordinated read-only bridge is implemented on the
  `fomo-mcp` branch `worker/deepseek-pep-market-source` (commit `dced9624`,
  backed by the verified-current FOMO `POST /proxy/getBarsNew`) and is pending
  operator deployment; until then a configured PEP fails closed with
  `Unavailable` and the chart renders only the local decrypted frame buffer —
  never fabricated data. The startup reachability probe leaves `realtime`
  unadvertised while the bridge is unreachable, so the browser is never told a
  dead stream is live; a configured-but-unreachable stream is therefore not an
  advertised dependency, and `/ready`'s `stream` check only reports a failure
  once a reachable source was advertised and later stops producing.
- Perimeter trust at the edge is header-presence only; cryptographic Cloudflare
  Access JWT validation is not implemented (loopback binding is the mitigation).
- The immutable release manifest is the normal production mode:
  `WORKSPACE_RELEASE_MANIFEST` binds the artifact to the trusted recipient
  fingerprint, and an absent manifest now refuses startup unless the operator
  explicitly sets `WORKSPACE_ALLOW_NO_MANIFEST=true`. In that weaker opt-in mode
  there is no trusted recipient fingerprint, so delivery of a well-formed
  artifact to a mismatched enrollment is only caught by the browser's
  fail-closed inner decrypt (`U5_ARTIFACT`), not by the server preflight.
  Deployments must configure the manifest; the release/operator steps do. The
  manifest also makes revoke/add recovery authorization possible.
- Cloudflare Access remains perimeter identity only and can never recover or
  decrypt a workspace.
- `main` branch protection and required-status-check enforcement are an
  operator/repo-governance action.
- No real-funds signing or submission has been tested. No production deployment
  has been performed by this lane.

## Phase 0 Foundation
Wave 1 is integrated and verification-clean. Live trading remains DISABLED / NOT IMPLEMENTED.

Completed in this wave:
- Canonical chain/market/domain contracts with validated TradeIntent, LimitOrder FSM, risk/limit-price semantics, route/tax/provider metadata, expiry handling, and all-or-nothing fill policy.
- Application E2EE foundation: ChaCha20-Poly1305 envelopes, monotonic sequence/nonces, 64-frame replay window, tamper/replay protection, directional HPKE session establishment, canonical offer/kid binding, and RAM-only zeroized session material.
- Opaque storage/telemetry foundation: generic objects/events/snapshots/streams, bucketed physical timestamps, closed telemetry vocabulary, Timescale/Postgres + NATS JetStream local infra.

## Security invariants currently enforced
- No live trading or raw wallet-key path exists.
- HPKE Base-mode offer must arrive through an integrity-authenticated bootstrap/passkey channel; Base mode does not authenticate the initiator by itself.
- HPKE c2s/s2c keys are domain-separated, session key ids are bound, raw same-key construction is crate-private, and exporter temporary buffers are RAII-zeroized.
- A 4-byte nonce prefix is safe only under the current fresh, non-persisted, non-resumed per-direction key model. Key reuse/resumption requires a nonce/session redesign before it may be enabled.
- Telemetry labels and metric names are closed typed vocabularies; runtime token/wallet/order strings cannot be exported as metric labels through the public API.
- The workspace unlock secret never leaves the browser and is only ever input key
  material to local derivation; no infrastructure-held raw key material.

Existing `fomo-mcp` and `gmgn-mcp` repositories remain operational and must not be destructively modified or bypassed with duplicate upstream clients.
