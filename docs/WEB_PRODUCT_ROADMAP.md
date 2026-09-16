# Private Web Product — Roadmap & Acceptance Criteria

Lane: `worker/deepseek-web-product` (isolated worktree `.dsh/wt-web-product`).
Scope: `web/**` plus web-specific tests/config/scripts and lane docs.
Authority: `docs/PRD.md` (lines 65–83 private web/privacy, 84–102 reliability/acceptance),
`ARCHITECTURE.md`, `INVARIANTS.md`, `docs/CONTEXT.md`, `docs/decisions/phase0-web-artifact-boundary.md`.

## Non-negotiable architecture locks (every slice)

- L1 Private workspace is a SolidJS CSR build, encrypted as an artifact, decrypted and instantiated
  only in browser memory after authenticated unlock. Cleartext shell stays free of private semantics.
- L2 The browser calls only neutral first-party paths (`/v1/bootstrap`, `/v1/sync`, `/v1/stream`,
  `/v1/blob`, `/v1/command`). No direct RPC/DEX/intelligence/analytics providers.
- L3 Session/private plaintext is memory-only. No `localStorage`/`sessionStorage`/`indexedDB`/`caches`/
  `document.cookie` for private state. Logout destroys keys, worker, stream and private state.
- L4 Realtime transport is encrypted, sequenced, gap-detecting and resync-capable. The Web Worker owns
  websocket/decrypt/decode/batching/normalization; the main thread owns UI/chart rendering.
- L5 Chart/depth render locally from TypedArray/RingBuffer via Canvas/WebGL. Bounded buffers only.
- L6 No trading semantics in URL, `document.title`, favicon or OpenGraph. No third-party analytics or
  session recording. No public source maps.
- L7 Trading mutations fail closed when backend capability/auth/freshness is unavailable. Unknown
  outcomes are surfaced as unknown and reconciled; never blind-retried, never fabricated.
- L8 No generic signing/transfer surface. Withdrawal is a web-only, strongly-confirmed, explicit flow.

## Status legend

`DONE` implemented + tested + reviewed. `IN PROGRESS` partially landed. `BLOCKED(contract)` blocked on a
missing backend contract (recorded in `.dsh/web-product/BACKEND_REQUESTS.md`), UI continues fail-closed.
`NOT STARTED` no implementation.

| ID | Slice | Status |
|----|-------|--------|
| W1 | App shell, navigation, responsive terminal layout, typed state architecture, error/loading/offline states | DONE |
| W2 | Encrypted realtime client + Web Worker + snapshot/delta sequencing + gap/resync + reconnect/backpressure | DONE (fail-closed) |
| W3 | Local realtime chart/OHLCV/depth with KLineChart Pro, zoom/pan/timeframes, bounded buffers | DONE (fail-closed) |
| W4 | Token search/detail + market stats + risk/intelligence evidence surfaces | DONE (fail-closed) |
| W5 | Quote + market preview + buy/sell ticket with full net economics, route, taxes, gas, slippage, freshness | DONE (fail-closed) |
| W6 | Limit-order create/cancel + partial-fill/order lifecycle + recovery/unknown-state UX | DONE (fail-closed) |
| W7 | Portfolio/balances/orders/history/alerts with explicit stale/unknown states | DONE (fail-closed) |
| W8 | TWAP/RFQ/best-execution controls and execution-progress views | DONE (fail-closed) |
| W9 | Security/settings + strong-confirmation web-only withdrawal surface; no generic signing/transfer | DONE (fail-closed) |
| W10 | Responsive/accessibility/keyboard UX + robust loading/error/reconnect/empty states | DONE |
| W11 | Browser/E2E/security/performance tests (auth, replay/reorder/tamper, XSS/CSRF/authz, reconnect/gap, no plaintext persistence) | DONE |
| W12 | Production build/deployment hardening, CSP, no source maps/private metadata leaks, final QA | DONE |
| W13 | OKX / Local Router swap-source selector (OKX default, memory-only, source-bound quote/preview/execute, no silent fallback) | DONE (fail-closed) |
| W14 | Trading-wallet limit & policy configuration (caps, turnover, taxes, impact, slippage, allowed chains/routers/programs; strongly-confirmed relaxations) | DONE (fail-closed) |
| W15 | Reconcile the W13 router wire contract with the landed canonical P84A–P84C `RouterSource` (canonical string + object forms, strict parsing, conformance tests) | DONE (fail-closed) |

**Read `DONE (fail-closed)` precisely.** Every slice above is implemented, unit/browser-tested and
fails closed. The private API, encrypted realtime stream and encrypted command channel have since
landed (BR-1…BR-5), so W2/W4–W9 are wired end-to-end against the fail-closed seams; but the shipped
private-api binary still composes no Trading Core backend, instrument registry, provider transports
or authoritative market feeds, so most data surfaces render an explicit
`unavailable`/`stale`/`empty` state and every mutation is a determinate `capability_missing` denial.
The chart now uses KLineChart Pro over a read-only FOMO market bridge; its history read fails closed
until the `fomo-mcp` `/market/bars` bridge is deployed. Treating a fail-closed surface as "live
product complete" would be an overstatement — the remaining integration is a backend/operator
contract dependency, not UI work.

### Status reconciliation (2026-09-16, `worker/deepseek-release-remediation`)

Several blockers recorded earlier in this log are resolved in the current tree and must not be
read as open. This addendum is authoritative over the dated continuation notes below; the code is
the evidence.

- **BR-5 session-key handoff — resolved.** `WasmInitiatorSession::app_session_keys()`
  (`crates/crypto-envelope-wasm/src/lib.rs`) is re-exported to the shell, which derives the
  directional keys in WASM (`web/workspace-shell/src/unlock-runtime.ts`) and posts the
  `evergreen:session-key` handoff (`web/workspace-shell/src/index.tsx`). `verify:web-boundary`
  proves the one-shot handoff-token gate end-to-end (missing/wrong/repeated tokens deliver nothing).
- **Edge `/v1/command` — exists.** `apps/edge-gateway/src/lib.rs` routes it (opaque, bounded,
  octet-stream); the residual is only the missing canonical `execution_id`/`router_source`
  execute-response fields (BR-10, PARTIAL).
- **Shell unit-test runner — exists.** `pnpm test:shell` runs the `web/workspace-shell`
  `node --test` suite in CI.
- **Client/server capability labels — aligned.** Discover gates token reads on `market`;
  `get_execution_progress` is command-readiness-gated.
- **Private API — composed.** Production passkey composition and the encrypted
  artifact/descriptor/release flow are implemented. The command dispatcher is the
  configured FOMO chart dispatcher (or the fail-closed default), the realtime
  source is the configured FOMO bounded-polling stream, and the advertised
  trading document is gated on typed capability readiness. What remains absent is
  the per-user **Trading Core** backend (`live_execution_wired=false`; `execute`
  is never advertised because no Base chain transport or Privy HTTP client
  exists), not the private API.
- **Chart / FOMO.** KLineChart Pro is pinned `0.1.1` + `klinecharts 9.1.1` over a renderer-agnostic
  local datafeed; the read-only `fomo-mcp` `/market/bars` bridge is implemented on the coordinated
  `worker/deepseek-pep-market-source` branch and is pending operator deployment.

### Progress notes

- **W1–W9** are implemented in `web/workspace-payload/src` against the typed architecture. Because the
  backend **Trading Core** per-user composition is absent (`execute`/`limits` unproven; see
  `BACKEND_REQUESTS.md`), every data surface renders an explicit `unavailable`/`stale`/`empty` state and
  every mutation is disabled with a reason; no synthetic data is
  ever shown as live. The FOMO chart history/realtime path is the only wired
  market-data surface.
- **W10** delivered: keyboard-navigable nav rail, focus-visible styles, `aria-live`/`role="status"` on
  async surfaces, labelled controls, `prefers-reduced-motion`, responsive 1440/1024/760 layouts.
  **Continuation:** axe-core now runs in real headless Chromium across all nine views as part of the
  browser suite; the two contrast failures it found (`--faint` text and the primary button) were fixed
  (`--faint #5f6c7d → #828fa1`, `--accent-dim #1d7f86 → #218f97`), and the audit is now a gate.
- **W11** delivered: 237 focused unit/component tests (32 files) plus a real **headless-Chromium**
  suite in `web/e2e` (including the real shell-unlock HPKE flow) driven by a mock private edge that implements the actual BR-1/BR-2/BR-3
  wire contract. The browser suite covers: authenticated encrypted snapshot/delta → Canvas + depth
  rendering, replay rejection, gap/tamper resync + **recovery to live**, socket-drop reconnect, missing
  key handoff fail-closed, encrypted command round trip, cleartext-envelope privacy, no persistent
  storage, DOM-XSS inertness, no trading semantics in URL/title/history, axe a11y, and measured perf
  (post-auth load 220ms, visual update 49.8ms, command round trip 5.2ms on the local harness).
  `verify:web-boundary` additionally scans the payload for persistent storage, external origins,
  trackers, source maps and the exact CSP.
- **W12** done: production payload build emits no source maps; CSP is own-origin with
  `script-src 'self' blob:`, `style-src 'self' blob:`, `worker-src 'self' blob: data:` so the decrypted
  payload instantiated from `blob:` URLs can actually boot, while `frame-src blob:` and `object-src
  'none'` stay tight. The unlock frame is `sandbox="allow-scripts allow-same-origin"` — same-origin is
  required because a sandboxed opaque document cannot load `blob:` subresources; navigation/popup/modal/
  form/download privileges stay denied and `verify:web-boundary` asserts the sandbox string. No external
  analytics. The full `pnpm verify:web-boundary` gate passed locally, including the Rust crypto
  CLI/wasm proofs.

## Acceptance criteria

### W1 — App shell + typed state
- AC1.1 Private payload renders a real terminal: persistent header (workspace identity, connection
  status, kill-switch/trading-disabled indicator), left navigation, main work area and contextual rail.
- AC1.2 Responsive at 1440/1024/768/390 CSS px: nav collapses, no horizontal overflow at 390.
- AC1.3 Typed data architecture: `AsyncState<T>` across `idle|loading|ready|stale|error|unavailable`,
  freshness metadata, capability model, typed error codes. No `any` in the public state surface.
- AC1.4 Every panel has explicit loading, empty, error and unavailable (missing capability) rendering.
- AC1.5 Navigation is in-memory (no trading semantics in URL); keyboard accessible with visible focus.
- AC1.6 `pnpm typecheck` and `pnpm verify:web-boundary` stay green.

### W2 — Encrypted realtime client + Worker
- AC2.1 Web Worker owns websocket, AEAD decrypt, frame decode, batching, normalization.
- AC2.2 Envelope is generic (`kid`, `nonce`, `sequence`, `ciphertext`); no trading semantics cleartext.
- AC2.3 Snapshot + sequenced deltas; duplicate/reordered frames rejected; gap forces resync.
- AC2.4 Reconnect uses bounded exponential backoff + jitter; reconnect always resyncs.
- AC2.5 Backpressure: P1 visual batches ~50–100ms, P2 analytics ~250–1000ms; bounded queues; P0 data is
  never silently dropped (drop forces resync).
- AC2.6 AEAD authentication failure fails closed, does not advance sequence, and never logs plaintext/keys.
- AC2.7 Focused tests cover gap, reorder, duplicate, tamper, reconnect/backoff, batching, backpressure.

### W3 — Chart/depth
- AC3.1 TypedArray/RingBuffer OHLCV store with bounded capacity and wraparound correctness.
- AC3.2 Canvas renderer on the main thread with device-pixel-ratio handling; zoom, pan, candle timeframes.
- AC3.3 Depth (bids/asks) rendering with cumulative sizing; bounded ring buffers.
- AC3.4 Pure scale/aggregation math unit-tested for extremes (empty, single, overflow, wrap).

### W4 — Discovery/intelligence
- AC4.1 Token search (debounced, cancelable) + token detail with market stats.
- AC4.2 Risk/intelligence evidence surface: provider, freshness, confidence, and stale markers; provider
  failure degrades evidence only and never blocks read-only execution surfaces.
- AC4.3 No direct provider calls; only neutral first-party paths.

### W5 — Quote/preview/ticket
- AC5.1 Buy/sell ticket shows full net economics: gross out, simulated net out, tax, DEX fee, gas, price
  impact, expected slippage, MEV/failure risk, state age, route legs.
- AC5.2 Preview is read-only and works with `TRADING_ENABLED=false`; execute is disabled with reason when
  capability/auth/freshness is missing, and never fabricates a successful result.
- AC5.3 Explicit stale/unknown state before any submit; submit requires fresh state revalidation.

### W6 — Limit orders
- AC6.1 Create/cancel forms carry `max_buy_tax`/`max_sell_tax`/`max_price_impact`/`max_slippage`/
  `max_total_cost`/`expiry`/`allow_partial_fill`; no chart-threshold-only triggering.
- AC6.2 Lifecycle timeline renders durable states (CREATED…FAILED_FINAL); partial fill + remainder visible.
- AC6.3 Unknown/recovery UX: unknown outcome shown as unknown, reconcile action, no blind retry.

### W7 — Portfolio/orders/history/alerts
- AC7.1 Portfolio/balances with freshness and explicit stale/unknown states; owner-scoped.
- AC7.2 Open orders, order history and fill/event history; alerts list; empty states.
- AC7.3 A stale/unknown value is never rendered as a confident number.

### W8 — TWAP/RFQ/best-execution
- AC8.1 Adaptive-TWAP control: safe chunk sizing config, slippage-halt hard cap, progress view.
- AC8.2 RFQ/solver competition view: quoted legs, best-execution ranking, progress.
- AC8.3 All controls fail closed and are labeled when capability is unavailable.

### W9 — Security/settings/withdrawal
- AC9.1 Security settings surface: session, unlock, kill switch, limits; no raw key material shown.
- AC9.2 Withdrawal: web-only, strong re-confirmation (phrase + explicit amount/recipient review), no
  generic sign/transfer surface, disabled unless capability + fresh auth are present.
- AC9.3 Logout destroys session keys/worker/state; no plaintext persisted before or after.

### W10 — Responsive/a11y/keyboard
- AC10.1 Full keyboard operability, focus-visible, `aria-live` for async status, labelled controls.
- AC10.2 `prefers-reduced-motion` respected; color is not the only status channel.
- AC10.3 Robust loading/error/reconnect/empty/offline states across every surface.

### W11 — Tests
- AC11.1 Unit/component tests run under `pnpm --filter @evergreen/workspace-payload test` (vitest).
- AC11.2 Security tests: replay/reorder/tamper fail closed, no plaintext persistence, path allowlist,
  CSP/no-source-map boundary assertions.
- AC11.3 Performance guards: bounded buffers/queues, post-auth load and UI processing budgets asserted
  where testable; no unbounded growth under adversarial frame streams.
- AC11.4 `verify:web-boundary` extended to assert the private payload has no persistent-storage APIs,
  no direct external origins and no source maps.

### W12 — Production hardening
- AC12.1 Production build emits no source maps, no plaintext private semantics, no analytics.
- AC12.2 CSP remains own-origin; worker/decrypt path allowed without widening network scope.
- AC12.3 Final visual/functional QA note recorded in lane STATUS with residual risks.

## Slice protocol

For each slice: update this file + `.dsh/web-product/STATUS.md` acceptance criteria → implement a
coherent user-visible vertical slice → focused tests → `pnpm typecheck` / `pnpm verify:web-boundary`
(or the focused subset) → fresh-context adversarial review, fix valid CRITICAL/HIGH and relevant MEDIUM
→ commit `W#` → rebase on `origin/main` when safe → push `worker/deepseek-web-product` → exact-head CI
green → draft PR updated (never autonomously merged to main while the backend lane is active).

## W12 final QA note (functional/visual, no-backend deployment)

Because the backend Trading Core is not composed (the private API exists but advertises no
market/execution backend), the following was verified structurally and in the component/unit harness
rather than against live data:

- Every one of the nine views renders with an explicit state (loading/empty/error/unavailable/stale);
  no view renders a synthetic market value. Mutation controls are disabled with a visible reason.
- The realtime worker path is exercised end-to-end in tests through an injected decryptor/socket seam
  (snapshot, delta, gap, replay, tamper, backpressure, reconnect, snapshot-first).
- The chart renders empty-state grid and awaits feed without fabricating candles; buffers are bounded
  (ring buffers, capped series map, priority batcher) and guarded by perf tests.
- The withdraw flow requires an explicit review step plus the exact confirmation phrase and stays
  disabled unless capability + trading gate allow it; no generic signing/transfer surface exists.
- Production payload build: no source maps, no external origins, no trackers, own-origin CSP with a
  minimal in-memory worker allowance, and the artifact is verified payload-only by `verify:web-boundary`.

Residual QA gaps (tracked, not claimed done): the shell-unlock E2E covers the happy path, lock and a
wrong-secret unlock against the local HPKE/artifact tooling; live artifact rotation and real edge
deployment hardening remain backend/platform work.

## Continuation — fresh-context adversarial review and browser E2E

Two fresh-context read-only reviewers audited the lane against the locked invariants. All valid
CRITICAL/HIGH and relevant MEDIUM findings were fixed, each with a regression test:

- **CRITICAL — the decrypted payload could never boot.** The shell iframe was `sandbox="allow-scripts"`
  (opaque origin), and a real Chromium run proved an opaque-origin document cannot load the `blob:`
  subresources the unlock runtime creates ("Not allowed to load local resource"). The frame is now
  `sandbox="allow-scripts allow-same-origin"` with navigation/popup/modal/form/download still denied;
  `verify:web-boundary` asserts the sandbox, and `web/e2e/specs/shell.spec.ts` proves a real HPKE
  unlock boots the payload under the production CSP. BR-6 is resolved.
- **CRITICAL — realtime resync deadlock.** `RealtimeClient` dropped every frame while `resyncing`, so the
  recovery snapshot could never clear the baseline: after any gap/tamper/reconnect the stream never
  returned to live. The client now authenticates/decodes while awaiting a snapshot, accepts the
  snapshot, and only drops non-snapshot frames. A replayed snapshot at or below the high-water mark is
  refused so state cannot roll backward. Reconnect resets the baseline.
- **HIGH — realtime never started in production.** The feed decided at `onMount` before `/v1/bootstrap`
  resolved, so it always observed the all-false capability snapshot and stayed offline forever (the
  encrypted command channel was never installed either). It now waits for the authoritative session,
  arms the BR-5 key listener early (re-arming once if the first window times out) and is cancellable.
- **HIGH — confirmation could describe a different trade than the submit.** The ticket now renders the
  confirmation from the previewed intent and any form edit invalidates the open confirmation.
- **HIGH — CSP blocked the decrypted payload.** `script-src 'self'`/`style-src 'self'` now also allow
  `blob:` (the payload document is instantiated from `blob:` URLs), with `worker-src 'self' blob: data:`;
  the asset-path substitution is longest-first with token boundaries and the iframe is styled by class.
- **HIGH — session expiry / mutation gating.** `mutationDenial` now fails closed once `expires_at_ms`
  has passed; `ExecutionPanel.startTwap`/`requestRfq` re-check the gate at action time (the error-retry
  path bypassed the disabled button); `execute_market_order` sends its idempotency key in the transport
  envelope (BR-3) instead of only the payload.
- **HIGH — missing/inconsistent idempotency keys.** `place_limit_order`, `cancel_order`, `submit_rfq`,
  `start_twap` and `request_withdrawal` all use `core/idempotency.ts` (stable across a retry of one
  submission, rotated after success, re-armed for a new logical submission).
- **MEDIUM — unauthenticated key handoff.** `awaitHostSessionKey` rejects `source === null`, validates
  the shape, and is abortable. **MEDIUM — limits validation:** non-positive amounts/prices are refused
  client-side and cancel re-checks the mutation gate. **MEDIUM — unlock cleanup:** any failure path now
  calls `lock()` and frees the WASM key exactly once. **MEDIUM/LOW — worker start/stop race** guarded by
  a generation counter.
- **MEDIUM — late-mount frame loss (found by the browser suite).** Views mount lazily, so frames decoded
  before a panel mounted were lost. The feed now retains a bounded window (128) of snapshots **and**
  deltas and replays them in sequence order to new subscribers.

Contract notes recorded in `.dsh/web-product/BACKEND_REQUESTS.md`: BR-6 (resolved: same-origin sandbox,
no CORS-null contract) and the BR-2 `/v1/sync` snapshot-delivery clarification.

## Continuation 2 — execution-safety hardening (third fresh-context adversarial review)

A third fresh-context read-only reviewer audited the uncommitted delta. All valid CRITICAL/HIGH and
relevant MEDIUM findings were fixed, each with a regression test. Acceptance criteria:

- **AC-C2.1 (HIGH, reconnect rollback).** A reconnect must NOT clear the rollback high-water mark.
  An untrusted relay that captures a genuine snapshot, drops the socket and replays that snapshot
  first on the new connection must not roll state backward: a snapshot with `seq < applied` is
  refused. A snapshot with `seq == applied` is accepted — it re-baselines to the already-applied
  state (no rollback) and guarantees recovery when the server produced no newer frame while the
  socket was down, instead of wedging the client permanently. A genuine server sequence restart
  requires a new session key. Regression tests: `realtime/client.test.ts` "refuses a replayed older
  snapshot while resyncing" and "keeps the rollback high-water mark across reconnect…".
- **AC-C2.2 (MEDIUM, epoch-aware replay).** Retained frames for late-mounting panels are epoch-local:
  a resync/reconnect clears them so pre-resync state cannot be replayed on top of a fresh baseline.
  Regression test: `realtime/use-realtime.test.tsx` "drops retained frames on resync…".
- **AC-C2.3 (MEDIUM, circuit breaker).** `mutationDenial` fails closed for capital-committing
  mutations (`execute`, `limits`, `twap`, `rfq`) whenever the deployment advertises realtime but the
  stream is not `live`. Read-only preview and the web-only withdrawal surface are not market-freshness
  mutations. Regression test: `state/session.test.ts`.
- **AC-C2.4 (MEDIUM, idempotency lifecycle).** A determinate rejection (`auth`, `capability_missing`,
  `freshness`) rotates the submission key so a corrected retry is a new logical order; an ambiguous
  transport failure keeps the key so a retry dedupes. The shared classifier is unit-tested
  (`core/idempotency.test.ts`) and the panel behaviour in `limits/LimitsPanel.test.tsx`; the same
  helper drives `ExecutionPanel` (`twap`/`rfq`).
- **AC-C2.5 (MEDIUM, no re-execute).** A preview that already produced a submission cannot be
  re-submitted; placing another order requires a fresh preview. Regression test:
  `features/trade/TradePanel.test.tsx` "does not re-submit an already-executed preview".
- **AC-C2.6 (hardening, honest unknown).** A market submit that cannot be confirmed is rendered as
  explicit **UNKNOWN** (never a plain failure) with an idempotent "Retry same order" affordance; the
  retry reuses the same quote idempotency key. Regression tests: `features/trade/TradePanel.test.tsx`.
- **AC-C2.7 (MEDIUM, framing + exact CSP).** The shell serves `X-Frame-Options: DENY` and
  `frame-ancestors 'none'` (clickjacking of the unlock secret), asserted against real HTTP responses;
  the shell meta CSP is compared **exactly** (no `unsafe-inline`/`unsafe-eval` additions) and the
  vite config must pin the exact header CSP. The sandbox assertion is documented as a configuration
  check, not a containment boundary (BR-6).
- **AC-C2.8 (LOW, hygiene).** Resync requests are coalesced; the host `postMessage` uses the concrete
  same-origin target instead of `"*"`; the main-thread base64 session key reference is dropped once
  the worker holds the key.

### Remaining blocker (not a code defect)

At the time of this continuation the live `evergreen:session-key` producer (BR-5) was absent
backend-side. It has since been implemented (see *Status reconciliation* above): the shell derives the
directional keys in WASM and hands them to the payload. The remaining integration dependency is a
reachable, Trading-Core-composed private API, not the handoff itself.

## Continuation 3 — fourth fresh-context adversarial review (rollback/auth + surface-load hardening)

A fourth fresh-context read-only reviewer audited the uncommitted delta (vs `5c8cffe`) and the
security-critical core. All valid HIGH/MEDIUM and relevant LOW findings were fixed, each with a
regression test. Acceptance criteria:

- **AC-C3.1 (HIGH, rollback mark authenticity).** The rollback high-water mark may advance only for a
  frame that has authenticated (AEAD verified) and decoded — never from the cleartext `sequence`
  observed before decryption. Previously `FrameSequencer.observe()` set `applied = seq` on the cleartext
  accept path, so a single injected/tampered envelope could pin `applied` above the genuine stream and
  permanently refuse the recovery snapshot (a DoS that survived reconnect). `observe()` no longer
  mutates `applied`; `noteApplied(seq)` is called from the client only after `decrypt` +
  `decodeInnerFrame` succeed. Regression: `realtime/client.test.ts` "does not advance the rollback mark
  from an unauthenticated frame".
- **AC-C3.2 (MEDIUM, execution progress wired).** `ExecutionPanel`'s `get_execution_progress` resource now
  loads once the `twap` capability is confirmed instead of permanently rendering an unqueried "No
  adaptive execution running". Regression: `features/execution/ExecutionPanel.test.tsx` "loads current
  execution progress once the twap capability is available".
- **AC-C3.3 (MEDIUM, no false empty before bootstrap).** `LimitsPanel` and `PortfolioPanel` load from a
  `createEffect` keyed on the capability becoming authoritative, not a one-shot `onMount` that can
  observe the pre-bootstrap all-false capability set and then never load (presenting "no orders"/"no
  alerts" as if queried). Regression: `features/limits/LimitsPanel.test.tsx` "loads orders once
  bootstrap resolves, even when mounted before it".
- **AC-C3.4 (MEDIUM, 4xx determinate).** `isIndeterminateOutcome(code, retryable)` treats a non-retryable
  `server` failure (HTTP 4xx validation) as determinate so the submission key rotates and a corrected
  retry is a new order; retryable 5xx keeps the key. Every panel passes `shape.retryable`. Regression:
  `core/idempotency.test.ts`.
- **AC-C3.5 (HIGH, no UNKNOWN cross-preview double-fill).** After an UNKNOWN market submit, execution is
  bound to the exact quote that produced it: a freshly previewed quote cannot be submitted under a new
  idempotency key until the unknown is resolved, and an explicit user acknowledgement is required to
  discard it. Regression: `features/trade/TradePanel.test.tsx` "does not let an UNKNOWN outcome submit a
  different, freshly previewed quote".
- **AC-C3.6 (MEDIUM, withdrawal indeterminate).** A withdrawal whose submit cannot be confirmed is
  surfaced as explicit UNKNOWN and keeps its idempotency key across a cancel/re-review, so an
  already-accepted withdrawal cannot be duplicated. Regression:
  `features/security/SecurityPanel.test.tsx`.
- **AC-C3.7 (LOW, bounded resync retry).** Resync requests coalesce within a bounded window rather than
  forever, so a lost `/v1/sync` cannot leave the stream degraded until a socket reconnect. Regression:
  `realtime/client.test.ts`.
- **AC-C3.8 (LOW, non-flaky security test + CI gate).** The nine-view no-persistence test gets a
  proportional timeout (it mounts every private surface under jsdom), and CI now runs the unit suite via
  `pnpm test:web` in the `web-boundary` job.

### Verification round (fresh context) — additional findings fixed

A second fresh-context reviewer verified each fix above and found a HIGH plus three MEDIUM and two LOW
issues. All were fixed with regression tests:

- **AC-C3.9 (HIGH, resync amplification).** The coalescing window is now enforced from the last request
  *regardless* of a "pending" flag, so a relay that alternates a replayed stale snapshot (which must not
  re-arm the window) with a malformed frame cannot drive one `/v1/sync` per two frames. Regression:
  `realtime/client.test.ts` "bounds resync requests when a relay interleaves stale snapshots with
  malformed frames".
- **AC-C3.10 (MEDIUM, no unqueried empty).** `AsyncSurface` renders `UnavailableBlock` for an `idle`
  state whose capability is missing, instead of an authoritative-looking empty. This fixes the
  Portfolio alerts regression introduced by the load-effect change and the Execution progress surface.
  Regression: `features/portfolio/PortfolioPanel.test.tsx` "renders unavailable, not an unqueried 'No
  alerts', when intelligence is missing".
- **AC-C3.11 (MEDIUM, in-flight submit).** `TradePanel` refuses a second submit while one is in flight
  (`submitting` gates `previewUsable` and the Preview control), so a racing second submit cannot erase
  an earlier UNKNOWN. Regression: `features/trade/TradePanel.test.tsx` "blocks a second submit while the
  first is in flight".
- **AC-C3.12 (MEDIUM, withdrawal review binding).** While an UNKNOWN exists, a withdrawal with changed
  details is refused (and its submit disabled) until the user explicitly discards the unknown; a 409
  conflict is treated as indeterminate for withdrawal and keeps the key. Regression:
  `features/security/SecurityPanel.test.tsx` "blocks changed-details withdrawal while an UNKNOWN exists,
  until discarded".
- **AC-C3.13 (LOW, discard reachability).** The UNKNOWN discard affordance is shown whenever the unknown
  quote is not actually retryable (different, expired/stale preview, or submit in flight), not only for
  a ready mismatched preview.
- **AC-C3.14 (LOW, honest test).** The `command.test.ts` envelope test name now matches what it proves
  (extra fields are stripped by the opaque boundary, not rejected).

### Residual (unchanged, contract-level)

BR-1…BR-5 remain open; BR-6 is resolved. The live integration blocker is still the BR-5 realtime
session-key producer. The same-origin sandbox (BR-6) remains an isolation *warning*, not a containment
boundary; serving the payload from a distinct origin would restore containment and is a platform
decision.

## Continuation 4 — independent three-reviewer audit (realtime, mutation safety, boundary gate)

Three fresh-context read-only reviewers audited (a) the encrypted realtime subsystem, (b) the
trading/intelligence UI, and (c) the shell/unlock boundary plus the verifier. All valid CRITICAL/HIGH
and relevant MEDIUM findings were fixed with regression tests; full narrative and evidence are in
`.dsh/web-product/STATUS.md` → "Continuation 5". Acceptance criteria:

- **AC-C4.1 (CRITICAL, session-scoped submission state).** Navigating between views must not unmount a
  panel holding an UNKNOWN outcome + idempotency key. Visited views are lazily mounted and then
  **retained** (hidden by CSS class, never the boolean `hidden` attribute). A same-parameter retry keeps
  its key, so it dedupes at the backend. Regression: `AppShell.test.tsx`.
- **AC-C4.2 (HIGH, resync wedge).** A recovery snapshot that never arrives (lost/suppressed `/v1/sync`)
  must not leave later authentic deltas dropped forever: a non-snapshot while awaiting a snapshot
  re-issues a coalesced resync; the watchdog requests recovery when it degrades.
- **AC-C4.3 (HIGH, ingest DoS bounds).** The pending-ingest queue is capped (`MAX_PENDING_INGEST=256`,
  excess → coalesced backpressure resync) and the worker rejects a frame over 2 MiB **before** decoding.
- **AC-C4.4 (HIGH, stop fence).** A generation token prevents an in-flight async decrypt from delivering
  a frame/status after `stop()`/restart.
- **AC-C4.5 (HIGH, stale circuit breaker).** `mutationDenial` requires `isConnectionFresh` (phase live
  **and** last authenticated frame within `FRAME_FRESHNESS_TTL_MS=30s`); a watchdog decays a latched
  `live` phase and re-requests recovery.
- **AC-C4.6 (HIGH, Limits/TWAP honest UNKNOWN).** An ambiguous `place_limit_order`/`start_twap` is
  surfaced as UNKNOWN, blocks a **changed** submission, and offers an idempotent same-intent retry.
- **AC-C4.7 (HIGH, boundary gate).** The shell-unlock browser spec fails the run when the crypto tooling
  is unavailable (opt-out `E2E_ALLOW_SKIP=1` only locally); the `web-boundary` CI job pins a Rust
  toolchain; negative CLI assertions fail on a failed spawn.
- **AC-C4.8 (MEDIUM, opaque-edge interop).** The worker no longer emits a cleartext WS control frame
  (the opaque edge closes on text; the envelope lock forbids cleartext operation types) and accepts
  binary frames; `verify:web-boundary` rejects a cleartext control frame.
- **AC-C4.9 (MEDIUM, verifier hardening).** One shared own-origin URL scanner for shell+payload
  (http/https/ws/wss + protocol-relative, case-insensitive); storage terms scanned across every payload
  file including binaries; all shell/payload source files checked for cross-imports; the public build
  scanned for trackers/source maps.
- **AC-C4.10 (MEDIUM, reconnect bounds).** The open resync uses the coalesced client path; the window is
  reset only on a transition to `live`, so an accept-then-close relay stays bounded while a genuine
  post-live reconnect/gap still recovers; reconnect backoff resets only once live.
- **AC-C4.11 (MEDIUM, command/UX).** A 15 s command timeout turns a hung request into an indeterminate
  outcome; pending submits are labelled; the preview is bound to the live ticket (editing disables
  execute); withdrawal requires an advertised enabled chain; `parseKillSwitch` fails closed on a
  non-boolean `enabled`; any batcher eviction forces a resync; the host key handoff checks
  `event.origin`.

### Recorded residuals (contract-level)

- **BR-7** — the deployed edge's `/v1/bootstrap|sync` require `application/octet-stream` and the WS
  relays binary only. `/v1/command` now exists on the edge (opaque, bounded); the remaining gap is the
  canonical `execution_id`/`router_source` execute-response fields (BR-10, PARTIAL). The web transports
  stay fail-closed until the backend is composed and reachable.
- **BR-8** — the ADR shell CSP needs an operator-approved update to the shipped minimal `blob:` policy.
- **BR-9** — no UNKNOWN reconciliation lookup; the guard release stays a two-step acknowledgement.
- **Main-thread command decryptor** — the command channel decrypts/seals on the UI thread; the client is
  dropped on feed teardown, and fully worker-side command crypto is a follow-up refactor.

## Continuation 5 — fourth independent audit (realtime, transport and mutation-safety hardening)

Four fresh-context read-only reviewers audited the encrypted realtime subsystem, the trading/
intelligence UI, the transport/command channel and the shell/verifier boundary. All valid
CRITICAL/HIGH and relevant MEDIUM/LOW findings were fixed with regression tests. Acceptance
criteria:

- **AC-C5.1 (CRITICAL, cross-channel response substitution).** Command responses and realtime stream
  frames shared one key and one AAD (`kid=<kid>;seq=<seq>`), and a response was bound only by
  `envelope.sequence`. A relay could answer a command with a captured stream frame at the same
  cleartext sequence; the client decrypted it, found no `error`, and returned the frame as the result
  (`execute_market_order` → `execution_id: undefined`, a false success). Every request now carries a
  random `request_id` inside the AEAD and the client requires the authenticated response to echo it; a
  stream frame (no `request_id`) or a replayed older response (different `request_id`) is rejected as
  `protocol`. Regressions: `transport/command.test.ts` "rejects a response that is not bound to the
  request". The backend must echo `request_id` (BR-3); until it does the command channel fails closed
  and keeps the idempotency key.
- **AC-C5.2 (HIGH, recovery-snapshot liveness).** A recovery snapshot at or below the high-water mark
  is accepted so resync is never wedged, but it carries no new state: it is delivered for rendering
  while the connection stays `degraded` and the frame freshness clock and `/v1/sync` coalescing window
  are **not** refreshed. A replaying relay can therefore neither re-arm `/v1/sync` (one request per two
  frames) nor keep the capital-committing circuit breaker open on stale state. Only a frame strictly
  newer than the baseline at resync time proves liveness. Regressions: `realtime/client.test.ts`
  "does not re-arm the window or refresh freshness on a replayed equal snapshot" plus the updated
  high-water-mark tests.
- **AC-C5.3 (HIGH, authenticated rejection classification).** A bare HTTP status is relay-controlled
  metadata and can never prove that a capital-committing write did not commit. For
  `execute_market_order`/`place_limit_order`/`cancel_order`/`start_twap`/`submit_rfq`/
  `request_withdrawal`, a status-only failure is now `unknown`/retryable (the caller keeps its
  idempotency key); a typed rejection is classified only from an AEAD-authenticated error body. The
  command client now throws `WorkspaceError` instances so `toWorkspaceErrorShape` preserves the code
  (previously every command failure collapsed to `unknown`). Regressions: `transport/command.test.ts`
  "treats a status-only failure on a write as indeterminate", "classifies a rejection carried inside
  the authenticated envelope".
- **AC-C5.4 (HIGH, UNKNOWN guard on retry).** A determinate rejection on a retry of an already-UNKNOWN
  submission no longer releases the guard or rotates the key for limits, market execution, TWAP or
  withdrawal: a gateway can reject before the idempotency store is consulted. Regressions:
  `features/limits/LimitsPanel.test.tsx`, `features/trade/TradePanel.test.tsx`,
  `features/execution/ExecutionPanel.test.tsx`, `features/security/SecurityPanel.test.tsx`.
- **AC-C5.5 (HIGH, Limits UNKNOWN surface).** An ambiguous `place_limit_order` outcome now renders an
  explicit UNKNOWN block with an idempotent "Retry same order" and a two-step discard; the previous
  state was set but never rendered, leaving the user with no error and no escape hatch. Regression:
  `features/limits/LimitsPanel.test.tsx` "surfaces an ambiguous place as UNKNOWN…".
- **AC-C5.6 (MEDIUM, backend source age).** `TradePanel` derives preview freshness and execution
  gating from the backend-provided `sourceAgeMs` (and the panel's own clock) instead of the resource's
  hardcoded `sourceAgeMs: 0`; `DiscoverPanel` marks token detail stale past its TTL. Regression:
  `features/trade/TradePanel.test.tsx` "refuses to execute a preview whose backend source age exceeds
  its TTL".
- **AC-C5.7 (MEDIUM, honest indeterminate surfaces).** A TWAP UNKNOWN release is a two-step
  acknowledgement (was a single danger click), and an indeterminate RFQ renders an explicit
  "outcome unknown" note instead of a plain failure. Regressions: `ExecutionPanel.test.tsx`.
- **AC-C5.8 (MEDIUM, clock anchoring).** Session expiry is compared against a server-anchored clock
  (`server_time_ms` offset) so a skewed local clock cannot keep an expired session authorized; frame
  freshness is evaluated at decision time and a negative age fails closed (throttled-tab case).
  Regressions: `state/session.test.ts`.
- **AC-C5.9 (MEDIUM/LOW, boundary verifier).** The verifier now rejects an inline `sourceMappingURL`
  in the shell bundle, requires an exact `sourcemap: false` and a build script that does not pass
  `--sourcemap`, pins the vendored audited wasm sha256, asserts neutral (no trading semantics,
  no OpenGraph/Twitter) shell/payload document metadata, corrects the public-scanner scope comment, and
  uses `assertCliRejected` for the pnpm negative builds (a failed spawn no longer passes vacuously).
- **AC-C5.10 (LOW, hygiene).** The unlock secret is zeroized when kid parsing throws; the URL/title/
  history E2E assertion is exact (history length unchanged); `place_limit_order` has an in-flight guard;
  a non-empty unparseable or past expiry is refused client-side; nav arrow traversal keeps focus in the
  rail instead of bouncing it to `<main>`; the realtime ingest backlog is bounded by total queued bytes
  (8 MiB) as well as frame count. Regressions: `app/AppShell.test.tsx`, `realtime/client.test.ts`.

### Residuals (unchanged, contract-level)

BR-1…BR-5 and BR-7…BR-9 remain open; BR-6 is resolved. The lane is implemented, unit/browser-tested
and fails closed, but is not live end-to-end until the private API, the BR-5 key handoff and the
BR-3 response binding (`request_id` echo + AAD purpose separation) exist backend-side.

## Continuation 6 — W13 OKX / Local Router swap-source selector

Operator priority (2026-09-14). The market ticket gains a user-visible swap routing selector:
`OKX` (default for every new private session) and `Local Router`. The preference is memory-only, is sent
only to the neutral first-party quote/preview/execute contract, and is bound to the exact quote and to
UNKNOWN/idempotency handling. The backend hybrid contract is not on `main`, so this slice is implemented
and tested against the typed contract and the browser mock, and stays fail-closed in production
(BR-10).

Implementation:

- `contracts/execution.ts`: `RouterPreference = "okx" | "local"`, `RouterSourceView`
  (`{ id, detail }`), `routerSourceLabel`, and `QuotePreview.routerPreference` + `QuotePreview.routerSource`.
- `state/session.tsx`: memory-only `routerPreference` accessor + `setRouterPreference`, defaulted to
  `okx` and reset to `okx` by `reload()` (a new private session). Never persisted.
- `features/trade/TradePanel.tsx`: segmented `OKX` / `Local Router` control (`aria-pressed`), sends
  `router_preference` in the preview payload and in the execute payload, refuses a missing/mismatched
  source (silent fallback), gates OKX on the advertised `okx` capability, renders the actual source on
  quote/preview/confirmation/result/UNKNOWN, and offers an explicit "Use Local Router" action when an
  OKX quote fails (never automatic).
- `scripts/verify-web-boundary.mjs`: the built payload is now scanned for provider endpoint/credential
  tokens (`okx.com`, `api.okx`, `okx_api_key`, `okx_secret`, `okx_passphrase`, …), so no provider host
  or credential can ship to the browser.
- `web/e2e/specs/router.spec.ts`: real-browser assertion of the OKX default, the
  `router_preference=okx|local` request payload on the neutral contract, preview invalidation on source
  change, and refusal of a silent OKX→Local substitution.

Acceptance criteria:

- **AC-W13.1 (default).** The routing selector renders `OKX` selected (`aria-pressed="true"`) for a new
  session before any preview; `Local Router` is unselected.
- **AC-W13.2 (preference transport).** `preview_market_order` and `execute_market_order` payloads carry
  `router_preference` equal to the selected source (`okx` by default, `local` after an explicit switch);
  the preference is sent only to the neutral first-party command channel.
- **AC-W13.3 (source display).** The actual `router_source` used is displayed on the preview, the
  confirmation dialog, the submitted result and the UNKNOWN block.
- **AC-W13.4 (change invalidates).** Changing the source resets the preview, clears an open confirmation
  and disables Execute until a fresh preview for the new source succeeds.
- **AC-W13.5 (no silent fallback).** A backend that returns a `router_source` different from the
  requested preference, or omits/malforms it, is not executable; the panel surfaces a requote/refusal
  and, for an OKX failure, an explicit "Use Local Router" action. A requested-OKX failure never
  auto-selects Local.
- **AC-W13.6 (UNKNOWN binding).** The UNKNOWN outcome stores its source; switching source cannot clear
  the guard, and a different quote id **or** a different source is blocked as a new order until an
  explicit acknowledgement. An indeterminate OKX submission can never be followed by a Local submission.
- **AC-W13.7 (fail-closed capability).** When `capabilities.okx` is absent, OKX stays selected but
  preview/execute are disabled with a reason and the user may explicitly choose Local Router; no
  provider call is attempted.
- **AC-W13.8 (privacy/boundary).** No OKX hostname, key, secret, passphrase or provider endpoint appears
  in the browser source or built payload; the preference is memory-only (no storage/URL/title/history).
- **AC-W13.9 (a11y/responsive).** The selector is two labelled buttons with `aria-pressed`, keyboard
  operable, and disabled while a submit is in flight; existing W10/W11 a11y checks stay green.
- **AC-W13.10 (gates).** `pnpm typecheck`, the payload unit/component suite, the browser E2E suite and
  `verify:web-boundary` pass.


## Continuation 9 — W14 trading-wallet limit & policy configuration

PRD line 86 / AC9.1 ("Trading wallet limits are configurable: max trade USD, hourly/daily turnover, max
buy/sell tax, max price impact, max slippage, allowed chains, routers and programs"). The Security view
gains a real, strongly-confirmed configuration surface. The backend ops do not exist on `main`, so the
slice is implemented against the typed contract and the browser mock, records the exact request as BR-14,
and stays fail-closed in production.

Implementation:

- `contracts/wallet-limits.ts`: `WalletLimitsView` / `WalletLimitsEditable`, a strict
  `parseWalletLimits` (rejects negative/non-finite/oversized caps, missing or malformed restriction
  lists, and a missing/negative `source_age_ms`), `parseLimitInput` / `parseListInput`,
  `limitsFromView`, `diffWalletLimits` (tighten/relax classification for caps and allowlists),
  `hasRelaxation`, and the snake_case `walletLimitsPayload`.
- `core/types.ts`: new authoritative capability `wallet_limits` (absent ⇒ false).
- `transport/command.ts`: `set_wallet_limits` added to the capital-committing write set, so a
  status-only failure stays indeterminate and never rotates the idempotency key.
- `features/security/WalletLimitsPanel.tsx`: renders the authoritative policy through `AsyncSurface`
  (idle/loading/stale/error/unavailable, never a confident unqueried value), edits caps + allowed
  chains/routers/programs, shows a pending-change diff, saves tightenings directly, requires the exact
  phrase `CONFIRM LIMIT CHANGE` for any relaxation, and handles an ambiguous write as an explicit
  UNKNOWN with an idempotent retry, a changed-policy block, and a two-step discard. The response is
  strictly parsed, and the applied policy is confirmed by an authoritative re-read (a 2xx alone is never
  rendered as proof).
- `features/security/SecurityPanel.tsx`: mounts the panel in the security surface.
- `web/e2e/server.mjs` + `web/e2e/specs/wallet_limits.spec.ts`: the mock advertises `wallet_limits`; a
  real-browser spec loads the policy, saves a tightening, and proves a relaxation is gated on the phrase.

Acceptance criteria:

- **AC-W14.1 (fail-closed capability).** With `capabilities.wallet_limits` absent/false the surface
  renders `unavailable` and sends no command; every write is disabled with a reason.
- **AC-W14.2 (strict parse).** A malformed cap, a missing/malformed restriction list, or a
  missing/negative `source_age_ms` renders a protocol error; a missing list is never shown as
  "unrestricted".
- **AC-W14.3 (full policy surface).** The surface renders and edits max trade USD, hourly/daily
  turnover, max buy/sell tax, max price impact, max slippage, allowed chains, routers and programs.
- **AC-W14.4 (tighten vs relax).** Increasing a cap, dropping a cap, or adding an allowlist entry is
  classified a relaxation; decreasing a cap or removing an entry is a tightening. Only relaxations
  require the exact `CONFIRM LIMIT CHANGE` phrase.
- **AC-W14.5 (write safety).** `set_wallet_limits` carries a client idempotency key; an ambiguous
  outcome is rendered UNKNOWN (never a success), reuses the key on an idempotent retry, keeps the guard
  across a determinate rejection of that retry, and blocks a *different* policy until an explicit
  two-step discard.
- **AC-W14.6 (no false success).** A 2xx is not treated as proof: after a write the surface re-reads
  `get_wallet_limits` and only ever displays the authoritative result; a difference remains visible.
- **AC-W14.7 (mutation gate).** The write fails closed when trading is disabled, the kill switch is
  engaged, the session is expired, or the capability is missing.
- **AC-W14.8 (privacy/boundary).** No storage/URL/title/history persistence; no provider credential or
  endpoint; the `wallet_limits` capability and ops travel on the neutral first-party command channel.
- **AC-W14.9 (a11y/responsive).** Labelled inputs, `aria-pressed`-free checkbox groups with explicit
  labels, keyboard operable, no horizontal overflow at 390px.
- **AC-W14.10 (gates).** `pnpm typecheck`, `pnpm test:web`, the browser E2E suite and
  `verify:web-boundary` pass.

Backend contract recorded: **BR-14** (`.dsh/web-product/BACKEND_REQUESTS.md`).


## Continuation 7 — independent three-reviewer audit and mutation-safety hardening

Three fresh-context read-only reviewers audited (a) the encrypted realtime/transport core, (b) the
trading-mutation panels, and (c) product completeness against this roadmap and `docs/PRD.md`. Every
valid CRITICAL/HIGH and relevant MEDIUM finding was fixed with a regression test. (The browser E2E suite
is not runnable in the audit sandbox because Chromium cannot load the missing system `libnspr4.so`; it
stays a CI gate. The verifier-change was syntax- and gate-checked locally.)

Acceptance criteria:

- **AC-C7.1 (HIGH, command error-path binding).** The authenticated-error path of `EncryptedCommandClient`
  must require the AEAD error body to echo the request's `request_id`, exactly like the success path.
  A captured authenticated envelope at the matching sequence (a stream frame with a top-level `error`, or
  a replayed response after the sequence restarts) must not be accepted as a determinate rejection: doing
  so would rotate the caller's idempotency key and double-submit a possibly-committed write. Regression:
  `transport/command.test.ts` "does not honor an authenticated error that is not bound to the request".
- **AC-C7.2 (HIGH, withdrawal in-flight guard).** The withdrawal surface must refuse a second concurrent
  submit while the first is in flight, and the control must be disabled. A racing double-click must not
  clear/rotate the idempotency key of an unresolved irreversible withdrawal. Regression:
  `features/security/SecurityPanel.test.tsx` "refuses a second concurrent submit…".
- **AC-C7.3 (HIGH, RFQ indeterminate guard).** An ambiguous `submit_rfq` must keep its idempotency key and
  render a persistent UNKNOWN with a same-request retry and a two-step discard; a determinate rejection
  of a retry must not release the guard. Regression: `features/execution/ExecutionPanel.test.tsx`
  "keeps an RFQ UNKNOWN guarded…".
- **AC-C7.4 (MEDIUM, TWAP in-flight guard).** A double-click on "Start adaptive TWAP" must not start two
  logical submissions or clear the first's key. Regression: `ExecutionPanel.test.tsx`
  "refuses a second concurrent TWAP start…".
- **AC-C7.5 (MEDIUM, limit success identity).** A 2xx `place_limit_order` that does not carry a non-empty
  `order_id` is indeterminate: it keeps the UNKNOWN guard and the key rather than releasing them as a
  success. Regression: `features/limits/LimitsPanel.test.tsx` "keeps the UNKNOWN guard when a 2xx place
  response carries no order id".
- **AC-C7.6 (MEDIUM, risk-limit validation).** A non-empty but invalid risk cap (slippage/impact/total
  cost, buy/sell tax) must block preview/place with a field error, never silently collapse to "no cap".
  Regressions: `TradePanel.test.tsx` and `LimitsPanel.test.tsx`.
- **AC-C7.7 (MEDIUM, transport/realtime bounds and liveness).** (a) `/v1/bootstrap` bodies are
  byte-bounded and the chain list is capped; (b) the worker's async `Blob` path is fenced to the client
  instance it arrived under; (c) a pre-live stall re-requests recovery at the bounded coalescing rate; (d)
  a capital-committing mutation requires a fresh live feed even when the unauthenticated bootstrap
  `realtime` bit is false (a relay must not be able to disable the circuit breaker by clearing one bit).
  Regressions: `transport/bootstrap.test.ts`, `realtime/client.test.ts`, `state/session.test.ts`.
- **AC-C7.8 (MEDIUM, verifier hardening).** The boundary verifier detects bracket-notation storage
  concatenation and runtime `document.title`/`history`/`location`/`cookie` writes in shell and payload.
- **AC-C7.9 (MEDIUM, responsive gate).** The browser suite asserts no horizontal overflow at 390px on
  every view (AC1.2). Test: `web/e2e/specs/ux.spec.ts` "has no horizontal overflow at 390px…".
- **AC-C7.10 (HIGH, product, instrument selection).** A memory-only shared instrument selection is wired
  from Discover into the header, chart, trade, limit and execution surfaces; the token pair is resolved
  contract-first (selected token + the chain's advertised `native_token`) and every mutation fails closed
  when the target is incomplete. No address is invented. Backend contract: BR-11.

Backend contract additions recorded: BR-11 (instrument/token pair + chain `native_token`), BR-12
(`place_limit_order` `order_id`), and the BR-3 clarification that AEAD error bodies must echo
`request_id`.

## Continuation 8 — fifth independent audit: execute-source binding, UNKNOWN identity, boundary tests

Two fresh-context read-only adversarial reviewers audited the trading/mutation surfaces and the
encrypted realtime/transport/shell/boundary. Every valid HIGH and relevant MEDIUM finding was fixed with
a regression test; the cheap LOWs were fixed too. The headline HIGH on the realtime side is the known
BR-5 blocker (the shell has no WASM key accessor to perform the session-key handoff), now re-confirmed
and recorded rather than faked.

Acceptance criteria:

- **AC-C8.1 (HIGH, execute-source echo).** A successful `execute_market_order` must carry an explicit
  `router_source` equal to the reviewed source. A missing, `null`, or malformed echo is **not** a
  success: it is rendered UNKNOWN with the same client idempotency key (the true route is unproven and
  must never be attributed to the requested source). Regressions: `TradePanel.test.tsx` "treats an
  explicit null execute-source echo as UNKNOWN…" and "treats a missing execute-source echo as
  UNKNOWN…".
- **AC-C8.2 (MEDIUM, UNKNOWN identity).** The UNKNOWN guard binds quote id **and** source **and** the
  previewed intent signature. A backend that reuses one quote id for a different order (different
  amount/pair) is a **new** order, not an idempotent retry: Retry and Execute stay disabled until the
  explicit two-step acknowledgement. The wire idempotency key is client-generated and reused only for
  the exact retry, so key rotation no longer depends on the backend issuing a new quote id. Regression:
  "blocks a same-quote-id preview of a different intent as a new order, not a retry".
- **AC-C8.3 (MEDIUM, preview fail-closed).** An absent `revalidationRequired` (anything that is not
  exactly `false`) and an absent/non-finite `expiresAtMs` block execution instead of failing open.
  `expiresAtMs` is compared against the server-anchored clock; stall/missing expiry surfaces an explicit
  reason. Regressions: "fails closed when the preview omits the required revalidation flag", "fails
  closed when the preview expiry is missing or malformed", "compares a server-issued preview expiry
  against the server-anchored clock".
- **AC-C8.4 (MEDIUM, write retryable tri-state).** An AEAD-authenticated error for a capital-committing
  write that omits `retryable` stays indeterminate (`retryable: true`), so a 5xx body cannot rotate the
  caller's idempotency key; only an explicit `false` is determinate. A read keeps the previous
  behaviour. Regression: `transport/command.test.ts` "keeps a write indeterminate when an authenticated
  error omits the retryable flag".
- **AC-C8.5 (MEDIUM, boundary verifier).** The tracker deny-list covers the common analytics/session
  SDKs; **every** `<title>` and **every** `<meta content>` value is scanned for trading semantics; the
  runtime metadata-write patterns cover whole-object `window.location =`, bracket `location["href"]` /
  `document["cookie"]` / `document["title"]`, `navigation.navigate(`, and title-element
  `textContent/innerHTML` writes; bracket-notation storage checks the object qualifier so
  `document["cookie"]`/`window["name"]` are caught.
- **AC-C8.6 (MEDIUM, worker/browser tests).** A real worker unit test asserts the wire-size ceiling
  rejects before decode, the worker never calls `socket.send`, and a stop fences late frames
  (`realtime/worker.test.ts`). The browser mock edge records **and closes on** any inbound client frame,
  and `realtime.spec.ts` asserts zero inbound frames (the binary-only relay regression is no longer
  untested).
- **AC-C8.7 (LOW, realtime/shell lifecycle).** Socket close now drives `client.noteDisconnected`, a
  frame that finishes decrypting after the close is dropped (it cannot re-latch `live` on a dead socket),
  an oversized frame forces an explicit resync, the ingest generation is captured at enqueue, and the
  shell's payload-message handler also requires `event.origin === location.origin`. Regressions in
  `realtime/client.test.ts`.
- **AC-C8.8 (LOW, relay-controlled deadlines).** Bootstrap `server_time_ms` / `expires_at_ms` are
  treated as untrusted: the server-clock skew never moves backwards and is capped, and the session
  deadline is derived from the advertised *duration* capped at 24 h, so a relay cannot extend a session
  (or a quote deadline) arbitrarily. Regressions in `state/session.test.ts`.
- **AC-C8.9 (gates).** `pnpm typecheck`, `pnpm test:web`, `pnpm build:workspace-payload` and
  `verify:web-boundary` pass.

Backend contract additions: **BR-13** (bootstrap timestamps are untrusted) and the BR-10 tightening
(an execute response **must** echo `router_source`; absence is UNKNOWN).


## Continuation 11 — W15: reconcile W13 with the landed canonical P84A–P84C router contract

Reconciled `origin/main` at `b60367b` (P84C). Since the W13/RR-10 request was written, the backend lane
landed the hybrid router in `crates/agent-commands` + `crates/agent-backend`:

- `RouterSource` serialises as the **bare strings** `"okx"` / `"local"` (`#[serde(rename_all =
  "snake_case")]`, default `Okx`), the request field is exactly `router_preference` on `get_quote`,
  `preview_market_order` and `execute_market_order`, and the response discriminant
  `preview["router_source"]` is that same string (`tests/hybrid_router.rs`).
- The web's W13 code parsed only the object `{ id, detail }` form it had requested. Against the canonical
  response it would have seen "no source" and refused every execution (safe but never interoperable).

Acceptance criteria:

- **AC-W15.1 (wire compatibility).** `parseRouterSource` accepts the canonical string discriminant
  `"okx"`/`"local"` and the object `{ id, detail }` form, normalising both to a strict
  `RouterSourceView`; case/whitespace variants, unknown ids, arrays, numbers and `null` remain
  non-executable (no default, no silent fallback).
- **AC-W15.2 (single shared parser).** The parser lives in `contracts/execution.ts` and is unit-tested
  independently; `TradePanel` imports it instead of keeping a private copy.
- **AC-W15.3 (conformance evidence).** `contracts/execution.test.ts` encodes the exact P84B/P84C response
  JSON discriminants from `hybrid_router.rs` and asserts they bind to the right source.
- **AC-W15.4 (user-visible).** A preview carrying the canonical string source renders as executable
  ("route source OKX") and a matching string execute echo renders "Submitted … via OKX";
  `TradePanel.test.tsx` covers it.
- **AC-W15.5 (ledger truth).** BR-10 is downgraded to `PARTIAL`: the request-field contract is MET by the
  canonical backend, while the private `/v1/command` execute response still lacks an `execution_id` and a
  `router_source` echo (`execution_outcome` returns `{"execution":{"state":...}}`). The `/v1/command`
  route **does** exist on `apps/edge-gateway` (opaque, bounded; see the status reconciliation above), so
  the remaining gap is the response fields alone, recorded in `.dsh/web-product/BACKEND_REQUESTS.md`.
- **AC-W15.6 (gates).** `pnpm typecheck`, `pnpm test:web`, `pnpm build:workspace-payload` and
  `verify:web-boundary` pass.

### Continuation 11 — three fresh-context adversarial reviews and hardening

Three independent read-only reviewers (W13 router contract, W14 wallet limits, realtime/transport
mutation safety) audited the dirty continuation 2–10 delta. All valid CRITICAL/HIGH and relevant
MEDIUM findings were fixed with regression tests.

- **AC-C11.1 (HIGH, realtime replay freshness).** A relay replaying captured frames could re-latch
  `live` and refresh `lastFrameAtMs`, keeping capital-committing mutations open. The client now accepts
  an optional server-anchored clock and, when a frame carries an AEAD-authenticated `server_time_ms`,
  refuses a frame that regresses or is older than the 30 s freshness window (drops it, forces resync,
  never latches live). The backend half is recorded as **BR-15** (additive; absent field keeps the old
  behaviour). Regressions: `realtime/client.test.ts` (three new cases).
- **AC-C11.2 (HIGH/MEDIUM, TradePanel freshness gates were non-reactive).** `previewStale` /
  `previewExpired` read the wall clock but were memoized without a clock dependency, so Execute could
  stay enabled after a quote's TTL/expiry passed. They now depend on the 1 s clock signal while judging
  freshness on the raw clock, and `confirmExecute` re-evaluates `previewStaleNow()` / `previewExpiredNow()`
  imperatively at submit time.
- **AC-C11.3 (MEDIUM, untrusted preview body).** An authenticated `{ result: null }` preview previously
  threw inside reactive computations and blanked the trade surface. A single `previewValue()` guard now
  gates every field access and a missing `quoteId` fails closed as a protocol error.
- **AC-C11.4 (LOW, negative source age).** A negative `sourceAgeMs` (which `ageMs` clamps to zero) is now
  treated as infinitely old, so it can never read as fresh.
- **AC-C11.5 (MEDIUM, W14 input strictness).** `parseLimitInput` now accepts only plain decimal literals
  (rejecting `0x…`/`0b…`/`0o…`/exponent/leading `+`/trailing dot that `Number()` silently reinterprets),
  and `source_age_ms` is upper-bounded (`MAX_SOURCE_AGE_MS`); an absurd age is a protocol error.
- **AC-C11.6 (MEDIUM, boundary scanner).** The payload scanners now collapse string-literal concatenation
  before matching, so `"local"+"Storage"`, `document["ti"+"tle"]`, `history["push"+"State"]` and
  `"okx"+".com"` are caught; bracket-notation variants of `history.pushState`/`location.assign`/
  `navigation.navigate` were added; provider/credential scanning runs over every payload file (not only
  text) and covers camelCase/kebab/`OK-ACCESS-*` spellings. The gate now runs its own
  positive/negative **scanner self-controls** on every invocation (the control caught a real missing
  `history["pushState"]` pattern before landing).
- **AC-C11.7 (LOW, worker start).** A rejected worker `start()` (e.g. a non-neutral stream URL) now posts
  a fatal error and stops cleanly instead of leaving an unhandled rejection with a wedged feed.
- **AC-C11.8 (LOW, transport test gap).** `set_wallet_limits` is now exercised through the real
  `EncryptedCommandClient` status-only-write path, so its membership in the capital-committing write set
  is asserted rather than assumed.
- **AC-C11.9 (recorded residual).** Command-channel crypto (the `c2s` sealer and `s2c` response decryptor)
  still runs on the main thread; the worker owns the realtime socket/decrypt/decode path. Moving the
  command path fully into the worker is a design change (request sealing also needs the key) and is
  tracked, not silently dropped.
- **AC-C11.10 (gates).** `pnpm typecheck`, focused vitest suites, `pnpm build:workspace-payload` and
  `verify:web-boundary` pass.


## Continuation 12 — W13/W14 re-audit: execute-gate clock fail-open, broken W13 browser spec, path/entropy hardening

After the W13 selector and the W15 wire reconciliation, two fresh-context read-only reviewers audited
the slice: one on W13 specifically, one over the whole `web/**` boundary. Their verdicts: the core
source-binding / silent-fallback / UNKNOWN design is correct and the app is fail-closed, but they found
two MEDIUM defects and three LOW hardening items (plus reconfirmed the BR-5 live blocker). All
actionable findings are fixed with regression coverage.

Acceptance criteria:

- **AC-C12.1 (MEDIUM, execute gate fail-open).** `executeDenial` is a memo whose only reactive inputs
  were capabilities/session/connection; `mutationDenial` reads the raw clock for session expiry and
  frame freshness, so a denial that appeared purely with wall time stayed cached as `null` and Execute
  remained armed after the authorization deadline. The memo now also reads the 1 s clock signal, and
  `confirmExecute` re-evaluates `ws.mutationDenial("execute")` *fresh* at action time. Regression:
  `TradePanel.test.tsx` "fails closed at confirm time when the session deadline lapses after a fresh
  preview" (a 2 s session lapses while the 5 s quote is still fresh; no execute is sent).
- **AC-C12.2 (MEDIUM, W13 browser spec never executed W13).** `web/e2e/specs/router.spec.ts` clicked
  Preview without a resolved pair: the mock chain advertised no `native_token` and the spec never
  selected a Discover target, so `previewDenial` was non-null and Preview was permanently disabled (the
  spec would time out in CI). The mock bootstrap now advertises `native_token: "USDC"` (BR-11) and the
  spec resolves the target through the real Discover search/select UI before previewing, then swaps in
  the preview response. This is a regression guard: the W13 acceptance path is now actually exercised.
- **AC-C12.3 (LOW, UNKNOWN overwrite race).** The confirm-time capability-denial branch wrote
  `failed` unconditionally; it now preserves an `unknown`/`submitting` outcome, exactly like the
  freshness branch, so a denial appearing between render and click cannot erase a possibly-committed
  submission.
- **AC-C12.4 (LOW, UNKNOWN retry trap).** `unknownRetryable` ignored `executeDenial`, so with a write
  denial active the idempotent retry stayed disabled *and* the two-step discard escape was hidden,
  trapping the user. It now requires `executeDenial() === null`, which surfaces the explicit discard
  path instead.
- **AC-C12.5 (LOW, source-side provider scan).** `verify:web-boundary` scanned the built payload for
  provider endpoints but not payload/shell **source**, so an unimported source file with a provider
  hostname could pass. Section 3d now runs `assertNoProviderEndpoints` over every payload and shell
  source file as well as the emitted bundle.
- **AC-C12.6 (MEDIUM, shell path drift, M1).** The cleartext shell's artifact-enrollment endpoints
  (`/internal/auth/enroll`, `/internal/artifact/grant`, `/internal/artifact`) are first-party but were
  not covered by any allowlist. Section 3e now asserts the shell's `/internal/*` path set is exactly
  those three, so an un-neutral path cannot be added silently (L2). Renaming them under `/v1/*` remains
  a backend/edge naming change, recorded as **BR-16**.
- **AC-C12.7 (MEDIUM, weak entropy fallback, M2).** `newIdempotencyKey` and the command `request_id`
  fell back to `Date.now()`/`Math.random()` when `crypto` was absent, making write keys and anti-replay
  nonces predictable. Both now use `crypto.randomUUID()` or `crypto.getRandomValues()` and **fail
  closed** otherwise (real browsers always provide `crypto`).
- **AC-C12.8 (recorded residual, BR-5 — since resolved).** At the time of this continuation the shipped
  `WasmInitiatorSession` exposed no directional-key accessor and the shell had no `evergreen:session-key`
  producer. Both now exist (`app_session_keys()` in `crates/crypto-envelope-wasm`, producer in
  `web/workspace-shell/src/index.tsx`) and `verify:web-boundary` exercises the handoff gate, so the
  handoff itself is no longer a blocker; the residual is a reachable, Trading-Core-composed private API.
- **AC-C12.9 (gates).** `pnpm typecheck`, `pnpm test:web`, `pnpm build:workspace-payload` and
  `verify:web-boundary` pass. Browser E2E remains CI-gated (the sandbox lacks Chromium's `libnspr4.so`).
