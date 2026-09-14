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
| W2 | Encrypted realtime client + Web Worker + snapshot/delta sequencing + gap/resync + reconnect/backpressure | DONE |
| W3 | Local realtime chart/OHLCV/depth with Canvas/WebGL, zoom/pan/timeframes, bounded buffers | DONE |
| W4 | Token search/detail + market stats + risk/intelligence evidence surfaces | DONE |
| W5 | Quote + market preview + buy/sell ticket with full net economics, route, taxes, gas, slippage, freshness | DONE |
| W6 | Limit-order create/cancel + partial-fill/order lifecycle + recovery/unknown-state UX | DONE |
| W7 | Portfolio/balances/orders/history/alerts with explicit stale/unknown states | DONE |
| W8 | TWAP/RFQ/best-execution controls and execution-progress views | DONE |
| W9 | Security/settings + strong-confirmation web-only withdrawal surface; no generic signing/transfer | DONE |
| W10 | Responsive/accessibility/keyboard UX + robust loading/error/reconnect/empty states | PARTIAL |
| W11 | Browser/E2E/security/performance tests (auth, replay/reorder/tamper, XSS/CSRF/authz, reconnect/gap, no plaintext persistence) | PARTIAL |
| W12 | Production build/deployment hardening, CSP, no source maps/private metadata leaks, final QA | IN PROGRESS |

### Progress notes

- **W1–W9** are implemented in `web/workspace-payload/src` against the typed architecture. Because the backend
  private API is not deployed (see `BACKEND_REQUESTS.md`), every data surface renders an explicit
  `unavailable`/`stale`/`empty` state and every mutation is disabled with a reason; no synthetic data is
  ever shown as live.
- **W10** delivered: keyboard-navigable nav rail, focus-visible styles, `aria-live`/`role="status"` on
  async surfaces, labelled controls, `prefers-reduced-motion`, responsive 1440/1024/760 layouts. Residual:
  a full automated a11y audit (axe) and 390px screenshot QA are not yet wired.
- **W11** delivered: 142+ focused tests (path allowlist, bootstrap validation, sequencer gap/replay,
  batcher backpressure, reconnect backoff, AEAD tamper, snapshot-first, encrypted command channel round
  trip + nonce/sequence monotonicity, XSS escaping, store state transitions, component fail-closed,
  chart math/buffers, limits/portfolio/trade/security/execution panels). `verify:web-boundary` now runs
  the suite and scans the private payload for persistent storage, external origins, trackers and source
  maps. Residual: a real headless-browser E2E/unlock harness and post-auth load P95 measurement require a
  CI browser runner; the performance budgets are asserted structurally (bounded buffers/queues) rather
  than measured in-browser.
- **W12** in progress: production payload build emits no source maps; CSP is own-origin with
  `worker-src 'self' blob: data:` for the in-memory inline worker; no external analytics. Final QA note
  is pending the verifier result.

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

Because the backend private API is not deployed, the following was verified structurally and in the
component/unit harness rather than against live data:

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

Residual QA gaps (tracked, not claimed done): real headless-browser unlock E2E, in-browser P95
measurement of post-auth load / command processing / visual update, and an automated axe a11y audit.
