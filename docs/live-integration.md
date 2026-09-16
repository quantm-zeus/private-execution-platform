# Private Web ↔ Private Backend Live Integration (BR-5/BR-7/BR-1/BR-2/BR-3/BR-9..15)

Lane: `worker/deepseek-live-integration`. This document records the wire contract
implemented for the real browser <-> private-backend path and the explicit
residuals. It is written so the next integration slice can continue without
re-deriving the design.

## Neutral opaque transport (BR-7)

Every `/v1/*` call is an opaque `application/octet-stream` body. The bytes are
the UTF-8 JSON of the generic envelope:

```json
{"kid": "<b64 16-byte id>", "nonce": "<b64 12 bytes>", "sequence": 0, "ciphertext": "<b64>"}
```

- AEAD: AES-256-GCM, fresh random 12-byte nonce per message, associated data
  exactly `kid=<kid>;seq=<sequence>` (UTF-8). This matches the payload's
  WebCrypto `sealer.ts`/`decryptor.ts` byte-for-byte.
- `kid`/`nonce`/`ciphertext` are standard base64. The operation type and every
  trading semantic live only inside `ciphertext`.
- `/v1/stream` is a same-origin WebSocket carrying binary frames whose payload is
  the same UTF-8 JSON envelope. The edge closes on any text frame.
- The edge relays ciphertext only. `/v1/command` is an edge route and internal
  `Route` (`ROUTE_COMMAND = 4`); the edge never parses the envelope and keeps its
  authorization/size/hardening gates.

## BR-5 session key handoff (authenticated key epoch)

The authenticated HPKE exchange that delivers the encrypted artifact also yields
the browser transport session:

1. `/internal/artifact/grant` publishes a per-grant HPKE offer.
2. `/internal/artifact` runs `responder_establish`, seals the artifact, and
   registers a `session-transport::ServerSession` under the grant `kid` with a
   bounded TTL. The registry is shared with the opaque relay.
3. The shell's `WasmInitiatorSession` exposes `kid()` and `app_session_keys()`
   (`c2s(32) || s2c(32)`), derived from dedicated HPKE exporter labels so they are
   distinct from the ChaCha artifact-session keys.
4. The shell retains the session only while unlocked, and posts
   `{type:"evergreen:session-key", kid, s2cKeyB64, c2sKeyB64}` to its own
   sandboxed frame **only** after the payload echoes the per-unlock handoff token
   the shell injected into the payload document (`<meta name="evergreen-handoff">`).
   The delivery is one-shot per unlock and the shell revokes the payload
   document's `blob:` URL once the frame has loaded it, so a same-origin document
   that navigated into the frame (or a repointed `frame.src`) cannot re-fetch the
   payload to read the token, and an unauthenticated `evergreen:workspace-ready`
   ping can no longer harvest live keys. `lock()` drops both the key reference and
   the token.
5. The payload imports the raw keys as **non-extractable** `CryptoKey`s
   (AES-GCM encrypt/decrypt) and zeroizes the base64/byte copies.

The key epoch is retired server-side on a fresh handoff: each `ServerSession` is
bound to the authenticated workspace `SessionId` and a fresh handoff for the same
owner calls `SessionRegistry::retire_owner` before inserting the new `kid`, so a
`kid` from an earlier unlock stops being accepted as soon as the next unlock
completes. A client-side `lock()` sends no server call, so it does not by itself
retire the epoch: the shell drops the keys locally, and the old `kid` is refused
server-side at the next handoff or at its TTL, whichever comes first. The owner
is the auth session, so two tabs sharing one auth session share one epoch and a
fresh unlock in either tab retires the other's `kid`.

No key is persisted. The payload keeps the browser-side byte copies in
zeroizable buffers and drops them after import. On the Rust side
`WireEnvelope`/`AeadKey`/`ServerSession`/`ClientSession` redact their `Debug`
output; the key itself lives in a ring `LessSafeKey` (ring does not expose a
zeroization hook), so "zeroize on drop" is a best-effort property of the
surrounding buffers, not a guarantee of this crate.

**Effective wire size cap:** the browser accepts up to 1 MiB of ciphertext, but
the internal relay contract (`rpc_contracts::MAX_PAYLOAD_BYTES`) bounds the whole
envelope JSON at 1 MiB, so the largest practical ciphertext is ~768 KiB. An
over-limit envelope is rejected `out_of_range`/413 before dispatch; a write stays
indeterminate (idempotency key kept), never a false success.

## Request/response plaintexts

| Route | Request | Response |
|-------|---------|----------|
| `/v1/bootstrap` | `{op:"bootstrap", protocol_version:1, request_id}` | flat session document + `request_id` |
| `/v1/sync` | `{op:"sync", from_seq, request_id}` | `{request_id, result:{accepted, from_seq}}` + a fresh snapshot on the active stream |
| `/v1/command` | `{op, payload, request_id, idempotency_key}` | `{request_id, result}` or `{request_id, error:{code,message,retryable}}` |

- The response envelope `sequence` equals the request `sequence`; the client
  rejects a mismatch.
- Every response (success or typed denial) echoes the request `request_id`
  inside the AEAD (BR-3), defeating stream-frame/response substitution.
- Bootstrap is authoritative and fail-closed: absent configuration, all
  capabilities are `false`, `trading_enabled=false` and the kill switch is
  engaged.
- `/v1/sync`, `/v1/stream` and `/v1/command` c2s windows are tracked
  independently (the browser uses per-endpoint sequence counters).

## BR-2 encrypted realtime stream + opaque sync

- `/v1/stream` has no browser->server frame of its own, so on every (re)connect
  the worker sends one AEAD-sealed `subscribe` frame (`Purpose::Stream`). Its
  cleartext envelope `kid` identifies the session and its encrypted body carries
  the client's applied-sequence high-water mark (`from_seq`). The sequence for
  this purpose persists across reconnects for the life of the key.
- `session_transport::ServerSession` owns the s2c stream sequence: monotonic for
  the lifetime of the `kid`, never reset. A backend that must reset its sequence
  space requires a fresh BR-5 handoff (new `kid`) — the BR-2 epoch rule.
- Inner frames match the web decoder exactly:
  `{op:snapshot|delta|heartbeat|mark|error, channel, priority?, entity_key?, slot?,
  source_age_ms, server_time_ms, payload?}`. `snapshot`/`delta` require a payload.
- `server_time_ms` is inside the AEAD and enforced non-decreasing (BR-15); a
  regression refuses the frame and stops the stream rather than emitting a
  frame a client could misread.
- `StreamDriver` emits a snapshot, then contiguous deltas, and a fresh snapshot
  when the shared `StreamHub` records a `/v1/sync`. A stale connection (old
  generation) can never consume a resync meant for the current one.
- `StreamSource` is injected. The production default `FailClosedStreamSource`
  emits one authenticated `error` frame and no state, so the UI stays degraded
  and mutations stay blocked — never fabricated data.
- `EncryptedStreamService` returns the outbound gRPC half immediately and reads
  the subscribe inside the spawned task; reading before returning would deadlock
  the edge WebSocket upgrade. `PrivateStreamRelay` bridges the edge WebSocket to
  that bidi stream over the pinned mTLS channel (ciphertext only).

## Command binding (BR-3) and web contract layer (BR-9/10/12/14)

`private_api::opaque::AgentCommandDispatcher` translates the authenticated
`{op, payload}` into the canonical `agent-commands` JSON (`{"tool": op, ...}`),
runs the shared `authorize` rule set, and forwards to the injected
`mcp_server::AgentBackend`. `AgentChannel::Web` was added additively and maps to
`domain::TradeSource::Web`.

- Writes require an `idempotency_key`.
- `Denied`/parse failures are determinate refusals; `Unavailable`/`Failed` on a
  write are indeterminate so the client keeps its key.
- `TRADING_ENABLED=false` denies every mutation through the shared policy core;
  reads stay available.
- The default wires `FailClosedDispatcher` + `FailClosedBootstrap`, so with no
  Trading Core composition every mutation returns an authenticated
  `capability_missing` denial — never a false success.

`private_api::web_contract::WebContractDispatcher` adds the operations the
shipped UI needs that the canonical vocabulary does not carry, over an injected
`WebContractBackend` (default `FailClosedWebContract`):

- BR-9 reconciliation reads: `get_order`, `get_order_by_client_id`,
  `get_withdrawal_by_request_id`, `get_execution_progress` (a missing
  `client_request_id` reads the current execution via
  `WebContractBackend::current_execution_progress`).
- BR-14 `get_wallet_limits` / `set_wallet_limits` (the write requires an
  idempotency key; the backend is the authorization boundary). Because this
  web-only write never travels through `agent_commands::authorize`, the
  dispatcher enforces the **same `TRADING_ENABLED` kill switch** itself
  (`ensure_trading_enabled`) before contacting the backend (fresh-review F1).
- BR-12 `place_limit_order` results are projected to a top-level `order_id` from
  the backend's own `order.order_id`; a success without one is indeterminate.
- BR-10 `execute_market_order` requires an `execution.state` of
  `submitted`/`filled`, a `router_source` echo equal to the requested
  `router_preference`, and a non-empty `execution_id`; `unknown`, a missing echo
  or a missing id is an authenticated indeterminate denial. `agent-backend`'s
  `execution_outcome` now emits `router_source` and the intent-id
  `execution_id`, so a real Trading Core satisfies this honestly.

## BR-11 canonical instrument + amount translation, preview projection, quote binding

The browser speaks a human-shaped, neutral contract; `apps/private-api/src/web_integration.rs`
is the only place that bridges it to the canonical `agent-commands` vocabulary.
It derives nothing on its own:

- **`InstrumentRegistry`** is an injected, authoritative seam (chain slug + token
  address → canonical `ChainId` + token decimals). The default
  `FailClosedInstrumentRegistry` resolves nothing, so a token/stablecoin amount
  fails closed with a determinate `capability_missing` instead of trading on a
  client-asserted scale factor. `StaticInstrumentRegistry` serves tests and fixed
  deployments.
- `preview_market_order` (browser payload `{intent:{…}, router_preference}`) and
  `place_limit_order` (flat payload) are translated into lossless canonical
  `AssetRef`s and `AmountSpec`s. `usd` is a **determinate protocol refusal**: the
  canonical backend deliberately has no trusted USD price and accepts only
  input-asset atomics, so the private layer refuses rather than inventing a
  conversion; `stablecoin`/`token` use the token_in decimals. A decimal with more
  precision than the asset supports, exponent notation, a non-positive amount, or
  an over-range value is a **protocol rejection**, never a silent rounding of a
  trade size.
- `place_limit_order`'s human quote-per-base `limit_price` becomes an exact atomic
  `LimitPriceSpec` (`numerator_atomic`/`denominator_atomic`) using the canonical
  orientation: buy → `(token_in, token_out)`, sell → `(token_out, token_in)`.
  A non-null web-only risk cap (`max_buy_tax_bps`/`max_sell_tax_bps`/
  `max_price_impact_bps`/`max_slippage_bps`/`max_total_cost_usd`) is a determinate
  protocol refusal, because the canonical command cannot enforce it and accepting
  it would present an unenforced safety control as applied; an explicit `null`
  means "no cap". `order_type` is dropped (the canonical command owns only the
  eight accepted keys; wallet limits come from backend config), and the canonical
  parser rejects any leaked field.
- `preview_market_order` stores the **translated canonical execute intent** under
  a 128-bit random, memory-only `quote_id`, scoped to the authenticated session
  `kid` (`CommandDispatcher::dispatch_for_session`) with a bounded TTL.
  `execute_market_order {quote_id, router_preference}` resolves that id and
  executes the exact intent the user reviewed. An unknown/expired quote, a
  session mismatch, or a `router_preference` different from the quoted source is
  a determinate rejection — never a silent re-route.
- The canonical `MarketPreview` (`RouteQuote` + `RouteScore`) is projected into
  the web `QuotePreview` (`quoteId`/`intent`/`route`/`economics`/`routerSource`/
  `sourceAgeMs`/`expiresAtMs`). Gross/net output, per-hop route legs, impact/
  slippage/MEV/failure bps and state age come from the authenticated preview; a
  value the backend did not supply is `null`, never fabricated. `minReceived` is
  a **conservative slippage floor** (`net_output × (1 − max_slippage_bps)`), not
  the current net output, and is `null` without an explicit cap. A bps is only
  derived when the cost is denominated in the gross-output asset; a cross-asset
  ratio is `null`, not a wrong number. `expiresAtMs` is the store's absolute
  deadline. `revalidationRequired` is `false` because the server revalidates
  state at execute, so the ticket stays executable; `routerSource` is passed
  through unchanged so a silent source substitution is visible and blocked by the
  client.

`web_command_dispatcher(...)` composes the whole chain
(`AgentCommandDispatcher` → `WebContractDispatcher` → `WebIntegrationDispatcher`)
over the injected `AgentBackend`, `AgentCapabilities`, `WebContractBackend`,
`InstrumentRegistry` and `OpaqueClock`. The production binary still builds the
fail-closed state and never enables trading by itself.

## Tests

- `crates/session-transport`: envelope/AEAD/replay/expiry/sequence-binding plus
  stream-frame schema, monotonic stream sequence, stale-server-time refusal,
  owner-epoch retirement and subscribe purpose-window tests (25).
- `apps/private-api`: 112 lib tests, including the real gRPC bidi
  `RelayStreamService` subscribe + snapshot round-trip, driver fail-closed /
  resync tests, the `WebContractDispatcher` no-false-success + kill-switch tests,
  the capability-map / OKX-preference / seam-derivation production tests, and the
  BR-11 translation / preview projection / quote-binding tests.
- `apps/edge-gateway/tests/opaque_command_e2e.rs`: browser-shaped opaque envelope
  -> edge `/v1/command` + `/v1/bootstrap` -> private-api session service, plus
  replay rejection, JSON-body rejection, and BR-10/BR-12 no-false-success
  assertions through the web-contract layer (9).
- `apps/edge-gateway/tests/opaque_web_integration_e2e.rs`: true end-to-end through
  the **real composed chain** (`web_command_dispatcher` -> `AgentCommandDispatcher`
  -> `WebContractDispatcher` -> `WebIntegrationDispatcher`) to an injected
  Trading Core seam: the browser payload is translated to the exact canonical
  `AssetRef`/`AmountSpec`, preview projects a `quoteId`, execute binds the quote
  and source, `TRADING_ENABLED=false` denies the write, an unknown instrument
  never reaches the backend, and an unattributable execute is indeterminate (5).
- `web/workspace-payload`: the payload unit suite including the worker
  subscribe-frame test (`realtime/worker.test.ts`).

## Fail-closed hardening (fresh-context adversarial review)

Two fresh-context reviewers audited the committed range after the `origin/main`
merge. All valid CRITICAL/HIGH and relevant MEDIUM findings were fixed with
regression tests:

- **Kill-switch authority (BR-1/F4).** The advertised `BootstrapDocument` is now
  an authorization input: `OpaqueServiceState` denies every mutating operation
  while `trading_enabled=false` or the kill switch is engaged, before the injected
  dispatcher runs. `session_transport::is_mutating_op` is the single closed write
  set. Reads and previews stay available. Previously the kill switch was
  client-side only.
- **Web-contract write gate (F3).** `WebContractDispatcher` independently applies
  the shared trading gate to canonical writes (`execute_market_order`,
  `place_limit_order`, `cancel_order`, `start_twap`, `submit_rfq`,
  `request_withdrawal`, plus the web-only `set_wallet_limits`), so a mis-composed
  canonical dispatcher cannot execute while the layer advertises fail-closed
  capabilities.
- **Cross-route replay no longer burns a sequence (F3-crypto).** The relay
  decrypts with `ServerSession::open_unverified`, validates the route/operation,
  and only then calls `accept_sequence` (same ordering for the stream subscribe).
  A captured envelope replayed on another route is a fail-closed no-op instead of
  consuming the first sequence the honest client needs.
- **`max_total_cost_usd` is refused, not silently dropped (F1).** The canonical
  command vocabulary cannot enforce a per-order USD cap, so a non-null value is a
  determinate `protocol` refusal rather than an unenforced safety control the
  preview echoes back as accepted.
- **Write responses must prove a commit (F2).** The browser command client treats
  an authenticated `{request_id, result:null}` (or non-object result) on a
  capital-committing write as an indeterminate `unknown` outcome and keeps the
  idempotency key.
- **`request_id` is required on every route (F5).** `/v1/bootstrap` and `/v1/sync`
  refuse a challenge-less request instead of sealing a replayable success.
- **Bootstrap sequence epoch (F7).** The store supplies a strictly increasing
  bootstrap sequence so a retry/reload under the same `kid` is not rejected as a
  replay (the server never resets the window for a key).
- **Wire bounds aligned (F6).** `session_transport::MAX_WIRE_BYTES` now matches the
  edge/relay 1 MiB body bound and `MAX_CIPHERTEXT_BYTES` (720 KiB) leaves room for
  base64 expansion, so the server never accepts an envelope the edge cannot relay.
- **Real relay coverage (F9).** `apps/edge-gateway/tests/private_relay_integration.rs`
  now drives a browser-shaped `/v1/command` envelope through the real edge HTTP
  route, the pinned mTLS channel and the real `EncryptedRelayService` to a
  fail-closed Trading Core seam.
- **Key-handoff hygiene.** The store no longer exposes the resolved BR-5 base64
  keys through a `hostKey()` accessor and drops the reference on `dispose()`; the
  stream subscribe frame captures the `kid` once across its seal await.

## Third adversarial review (independent verification of the landed lane)

Three fresh-context reviewers audited the exact committed range independently.
All CRITICAL/HIGH and relevant MEDIUM findings were fixed with regression tests:

- **Idempotency key dropped on a maybe-committed write (HIGH).**
  `BackendOutcome::Unavailable` is surfaced as `{code:"capability_missing",
  retryable:true}`, but the web classified only `server` through `retryable`, so
  a transient failure that may still have committed rotated the key and let the
  next submission become a duplicate order. `isIndeterminateOutcome` now honours
  an explicit `retryable:true` for *every* code; the tests that pinned the old
  behavior were corrected and a retryable-freshness UNKNOWN test added.
- **`place_limit_order` silently dropped every user safety cap (HIGH).** The
  form collected `max_buy_tax_bps`/`max_sell_tax_bps`/`max_price_impact_bps`/
  `max_slippage_bps`/`max_total_cost_usd`, but the translator neither forwarded
  nor refused them, so the UI presented unenforced caps as applied.
  `refuse_unenforceable_limit_caps` now makes a non-null cap a determinate
  `protocol` denial (the market path's existing policy); explicit `null` still
  means "no cap" and places.
- **Cross-purpose replay burned a command sequence (MEDIUM).** A captured
  `/v1/stream` `subscribe` envelope replayed on `/v1/command` passed the route
  check and consumed `Purpose::Command` before the dispatcher rejected it,
  letting an observer pre-burn the honest client's replay window. The command
  route now uses a positive allow-list backed by the closed
  `session_transport::is_route_control_op` set, and the check runs before
  `accept_sequence`.
- **Advertised capabilities were not enforced server-side (MEDIUM).** A document
  could advertise `execute=false` while the dispatcher executed it. `CapabilitySet`
  now maps each operation to its capability and `OpaqueServiceState` denies a
  command whose flag is `false` before the dispatcher runs. Harnesses that
  expected an operation to run now advertise the matching capability truthfully.
- **Session expiry was not authoritative (MEDIUM).** Bootstrap recomputed
  `now + ttl` on every request instead of advertising the registered session's
  real deadline, so a re-bootstrap let the client believe the session outlived
  the server's. `ServerSession::expires_at_ms()` is now advertised, and the
  stream driver refuses to emit (and drops the session) once it expires.
- **BR-5 key epoch was never retired (MEDIUM).** A `kid` issued before a lock
  stayed accepted until its TTL, and a fresh handoff did not invalidate the old
  epoch. `ServerSession` now carries an opaque owner binding (the authenticated
  `SessionId`) and the handoff calls `SessionRegistry::retire_owner` before
  inserting the new `kid`.
- **Unbound key delivery (MEDIUM).** The shell handed live keys to any
  same-origin document that sent `workspace-ready`. Delivery is now one-shot and
  gated on a random per-unlock token injected into the payload document.

## Fourth adversarial review (independent verification of this slice)

Two fresh-context reviewers audited the uncommitted production-wiring slice. No
CRITICAL/HIGH false-success or capital-write bypass was found; all CRITICAL/HIGH
and relevant MEDIUM findings were fixed with regression tests:

- **OKX capability was unrepresentable and unenforced (HIGH).** `WiredCapabilities`
  had no `okx` field and `document_for` hardcoded `okx: false`, so a genuinely
  OKX-capable deployment advertised it false (dead default path) while a crafted
  client could still force `router_preference:"okx"`. `okx`/`twitter`/`gmgn` are
  now plumbed through, and `CapabilitySet::permits_router_preference` denies an
  explicit `okx` preference before dispatch unless `okx` is advertised.
- **Capability map was default-allow for unlisted ops (MEDIUM).** An op outside
  the map ran even when its surface was advertised unavailable. `permits` now
  denies an unmapped op unless it is one of the explicitly ungated BR-9
  reconciliation reads (`get_order_by_client_id`, `get_withdrawal_by_request_id`,
  `get_execution_progress`), so an unknown op cannot escape the gate while
  UNKNOWN resolution stays available.
- **Advertised document trusted the caller (MEDIUM).** `build_opaque` now derives
  the document from the seams that are actually present: no dispatcher forces
  every command capability false and engages the kill switch; no stream source
  forces `realtime` false.
- **Edge access assertion could be misconfigured (MEDIUM).** The assertion header
  must now be a custom (`cf-`/`x-`) header; a standard/browser header name
  (`accept`, `cookie`, `authorization`, `content-type`, …) is a startup error, so
  the perimeter assertion cannot accidentally authorize ordinary requests. A
  partial/blank composition (including a single identity variable) refuses
  startup rather than silently serving 503s.
- **Unbounded relay dial held the channel lock (MEDIUM).** The edge relay now
  dials under a dedicated lock with a bounded connect timeout, so a black-holed
  private API cannot block cached-channel readers.
- **Same-origin token re-fetch (MEDIUM).** The shell revokes the payload
  *document* `blob:` URL once the frame has loaded it, so a navigated same-origin
  frame cannot read `frame.src` and re-fetch the payload to recover the handoff
  token; the unguarded `sessionKeys()` accessor was removed. `injectHandoffToken`
  now inserts after the doctype/head (never `<header>`) via tag-boundary patterns.
- **Web-only ops with no canonical tool** and **response-shape projection for
  `get_orders`/`get_portfolio`** remain explicit residuals (below).

## Residuals (explicit)

- **USD-notional amounts (Trading Core capability, not a private-layer bug)**: the
  shipped ticket defaults to `amount_type:"usd"`. The canonical
  `agent-backend` deliberately refuses `usd_micros` (it will not value a
  request-body USD amount as trusted) and accepts only input-asset atomics, so
  the private layer rejects `usd` with a determinate `protocol` refusal instead of
  inventing a price. `token`/`stablecoin` amounts work with authoritative
  decimals. Closing USD-notional requires Trading Core support (an authoritative
  USD price / live market-data seam), not a private-layer workaround.
- **Open-expiry limit orders**: the private layer requires `expiry_ms` (mapped to
  the canonical required `expires_at_ms`); the web allows an empty expiry, which
  becomes a determinate protocol denial. A default policy belongs to the Trading
  Core, not the translator.
- **User risk caps on `place_limit_order`**: the canonical command carries no
  `max_*_bps`/`max_total_cost_usd` fields, so a non-null web cap is a determinate
  `protocol` refusal (never silently dropped) and the backend-configured wallet
  policy governs. A per-order cap contract is a canonical-vocabulary change.
- **Web-only ops with no canonical tool**: `start_twap`, `submit_rfq`,
  `request_withdrawal` (submit), `get_alerts` and `get_provider_health` fall
  through to `capability_missing`. They belong on the injected
  `WebContractBackend` (their typed-denial default is already fail-closed).
- **Response-shape projection for `get_orders`/`get_portfolio`**: the canonical
  `agent-backend` returns snake_case domain documents nested under `orders` /
  `portfolio`, while the web views expect camelCase/top-level fields. The
  projection is not implemented yet; the surfaces stay non-fabricating but
  partially blank.
- **Shell BR-5 handoff test coverage (resolved).** The shell now has a
  `node --test` unit runner (`web/workspace-shell/package.json` `test`, run in CI
  as `pnpm test:shell`) and `unlock-document.test.ts` covers the handoff-token
  injection. `scripts/verify-web-boundary.mjs` additionally proves the shell's
  live gate end-to-end: missing, wrong and repeated `evergreen:lock-request`
  tokens deliver nothing, and a correct token echo arms the one-shot handoff.
- **Client/server capability-label mismatches (resolved).** The shipped UI and
  the server now agree: Discover gates `search_token`/`get_token` on `market`
  (`web/workspace-payload/src/app/views.ts`), and `get_execution_progress` is
  gated on command readiness, not `twap` (`ExecutionPanel.tsx`), matching
  `apps/private-api/src/opaque.rs`.
- **Operator wiring (partially closed)**: the production binaries now compose
  honestly instead of always serving the fail-closed stub:
  - `apps/edge-gateway` builds its router from `production::router_from_env()`.
    With `EDGE_TLS_CERT`/`EDGE_TLS_KEY`/`EDGE_TLS_CA`/`EDGE_PRIVATE_API_DNS`,
    `EDGE_PRIVATE_API_ORIGIN` and `EDGE_ACCESS_ASSERTION_HEADER` all supplied it
    installs the real `PrivateRelay` + `PrivateStreamRelay` over the pinned mTLS
    channel; a partial configuration refuses startup, and no configuration keeps
    `EdgeState::unavailable()` (every `/v1/*` is a `503`). The access-assertion
    header is the operator-owned perimeter seam (Cloudflare Access or an
    equivalent ingress proxy adds and strips it); the edge requires it to be
    explicitly configured and never authorizes an unstamped request.
  - `apps/private-api` parses `TRADING_ENABLED` strictly (`"true"`/`"false"`;
    unset disables; anything else refuses startup) and derives the advertised
    bootstrap document from *what is actually wired and proven*. Enabling
    trading does not advertise a capability whose backend is absent, and the
    kill switch stays engaged until a mutating seam is injected.
  - The trading path is built from typed capability proofs
    (`apps/private-api::trading` -> `trading_core::capability`). `market`,
    `execute` and `limits` are each gated on a healthy dependency proof, and
    `twap`/`rfq`/`withdraw`/`wallet_limits` ride the execution proof; a wired
    dispatcher with no proof cannot advertise them. `realtime` requires the FOMO
    stream source **and** a bounded startup reachability probe of the bridge
    (`probe_realtime`); the shared health flag is updated by every later stream
    read and drives the `/ready` `stream` check. The durable attempt store is a
    real Postgres adapter (`execution_store`), connected only behind the
    explicit `TRADING_CORE_LIVE=1` opt-in; a partial live configuration (opt-in
    missing an endpoint) refuses startup, and `TRADING_CORE_LIVE` itself is
    parsed strictly (`"1"`/`"0"`).
  - Still residual: the concrete Trading Core composition (real `AgentBackend`,
    authoritative `AgentCapabilities`, `InstrumentRegistry` backed by market
    metadata, `WebContractBackend` for wallet limits/reconciliation, real
    `StreamSource`) is injected through `web_command_dispatcher` /
    `production::OpaqueComposition` but not built by the binary. Wiring it needs
    genuinely operator-owned inputs (owner/wallet/chain/risk limits, Privy
    signing, a Base chain transport, live market data), so with none supplied
    the `FailClosed*` defaults remain. There is no concrete `BaseChainTransport`
    or `PrivyHttpClient` in the repository, so the shipped binary can never prove
    execution and every mutation is an authenticated `capability_missing`
    denial — never a fabricated success.
- **Accepted LOW hardening residuals (fresh-context adversarial review)**: the
  s2c AAD is not purpose-separated (the authenticated `request_id` echo blocks the
  substitution today; the cross-route c2s DoS is now fixed by validating before
  consuming a sequence); a shared `Notify` can waste one resync wake-up across
  stream generations; the WASM export path leaves raw key /
  plaintext copies in linear memory because wasm-bindgen `free` does not zeroize
  (the JS copies are zeroized); the base64 key strings in worker `postMessage`
  payloads and the store closure survive until GC / iframe teardown (the imported
  `CryptoKey`s are non-extractable); `RealtimeClient.start()` resets the s2c replay
  high-water mark on a same-`kid` worker restart (bounded by the 30 s frame TTL);
  and a concurrent `prune` can remove a session between command dispatch and seal,
  turning a committed write into an indeterminate 503 (the client keeps its
  idempotency key, so it is never a false success).
- **Input-denominated fee projection**: `dex_fee` (always in `token_in`) and a
  sell-side `tax_cost` (also in `token_in`) cannot be expressed as bps of the
  gross output, so they project as `null` (unknown, never wrong). The second
  adversarial review's quote-store starvation (per-session eviction now), the
  misleading `minReceived` (now the slippage floor), the `proportional_bps`
  saturation, the malformed `client_request_id` fallback, and the JSON-float
  precision hole are fixed.
- **BR-16 naming**: enrollment/artifact paths remain `/internal/*` and are
  asserted by `verify:web-boundary`; neutral-family renaming is a platform
  decision.
- **Git**: the sandbox cannot write the shared worktree git metadata, so commits
  are created in a workspace-local export repo (`<worktree>/.export`) that shares
  object alternates with the main clone and pushes to `origin`. The branch and
  draft PR are real; the worktree's own git index is untouched.

## Fifth review pass (post-main merge) — audit-driven hardening

The branch was merged with the then-current `origin/main` (P91–P93: artifact
rotation scheduler, OKX provider benchmark, observational benchmark loop) and
re-verified: `cargo fmt --check`, `cargo clippy --workspace --all-targets
-- -D warnings`, `cargo test --workspace`, `pnpm typecheck`, the payload suite
(385 tests) and `verify:web-boundary` are green on the merged tree. Three
fresh-context read-only audits (transport/BR-5/BR-7/BR-1, web-contract/BR-9..15,
end-to-end coverage) were run against the exact committed tree. Valid findings
were fixed:

- **BR-5 handoff gate is now a pure, tested module.**
  `web/workspace-shell/src/handoff-gate.ts` owns the one-shot, token-bound
  delivery decision. `verify:web-boundary` captures the real per-unlock token the
  live runtime arms and asserts the live path (missing/wrong token refused, the
  exact injected token released once, repeat refused), then exercises every branch
  of the pure gate including disarm. This closes the last priority-1 security
  control that had no automated regression coverage.
- **Payload ready/token echo is tested.** `state/host.test.ts` pins
  `announceWorkspaceReady` to the exact `{type, handoff}` message at the known
  origin (never `*`), the empty token when no meta is injected, and no post when
  unframed.
- **Client/server capability labels aligned (F4).** Discover gates
  `search_token`/`get_token` on the server's `market` capability, and the
  execution-progress reconcile read is no longer hidden behind `twap` (the
  server leaves it ungated so an UNKNOWN execution stays reconcilable).
- **Unrenderable orders/portfolio successes fail closed (F2/F3).**
  `parseOrdersResponse`/`parsePortfolioView` run through the new
  `createCommandResource({validate})` hook, so a document the view cannot render
  (for example the canonical snake_case `OrderSummary` or the nested
  `PortfolioSummary`) becomes a typed `protocol` error instead of a `ready`
  value that throws inside the renderer. No value is fabricated.
- **One-shot panel reads wait for the authenticated channel.** The re-review
  found that a panel mounted inside the BR-5 handoff window could consume its
  one-shot request against the fail-closed command stub and latch a permanent
  "capability missing". `WorkspaceStore.commandReady` is true only once the
  encrypted command channel is installed (and false again on dispose/replacement);
  the execution-progress read and the Limits/Portfolio/Intelligence/WalletLimits
  auto-load effects gate on it, and the progress surface shows "awaiting the
  authenticated command channel" instead of a false unqueried empty.

The audits confirmed the core guarantees (AAD binds `kid`+`seq`, the response is
bound to the request sequence, the `request_id` echo, per-purpose replay
windows, decrypt-before-accept, the authoritative kill switch/capabilities,
binary-only WebSocket frames, and consistent 1 MiB/720 KiB bounds) and
re-stated the residuals below. Findings that are genuinely operator-owned or
need a canonical-vocabulary/Trading-Core change remain residuals rather than
being worked around:

- **Orders/portfolio projection (F2/F3, canonical gap).** The web views need
  camelCase `LimitOrderView`/`PortfolioView` (intent, fills, createdAt/updatedAt,
  walletRef/equityUsd/slot/sourceAgeMs). The canonical `OrderSummary`/
  `PortfolioSummary` do not carry the intent, the fill list or the timestamps, so
  a faithful projection needs additive canonical fields. Until then the client
  fails closed with a typed protocol error (never a crash, never fabrication).
- **Client-reference reconcile (F9).** The server already exposes the ungated
  `get_order_by_client_id`/`get_withdrawal_by_request_id`/
  `get_execution_progress` reads, but the UI never sends a stable
  `client_order_id`/`client_request_id` on writes and reconciles only by a known
  `order_id`. Wiring the client ids and the UNKNOWN lookup is a web-flow change
  that belongs with the Trading Core wiring.
- **Advertised-vs-backed capabilities (F5/audit[4]).** `document_for` derives the
  document from `WiredCapabilities`, now additionally gated on the typed
  `CapabilityReadiness` proofs: `market`/`execute`/`limits`/`realtime` require a
  healthy dependency proof and the mutating capabilities ride the execution
  proof. An operator that advertises `twap`/`rfq`/`withdraw`/`intelligence`
  without the matching `WebContractBackend` handler still gets a determinate
  `capability_missing` (never a false success); `intelligence`/`twitter`/`gmgn`
  remain presence-declared reads. A `serves(op)` probe on the seams would make
  the remaining advertisement authoritative.
- **Shipped binary composition (F1/F10, operator-owned).** `main.rs` composes the
  configured FOMO chart dispatcher (or the fail-closed default) and the FOMO
  stream source, then derives readiness from `TradingSeams`: the durable
  Postgres attempt store is connected only under `TRADING_CORE_LIVE=1`, and no
  Base chain transport or Privy HTTP client is injected, so `execute` is never
  advertised. The concrete Trading Core read/trade backend, `WebContractBackend`,
  `InstrumentRegistry`, `StreamSource` and chains still need operator inputs
  (owner/wallet/chain/risk limits, Privy signing, live market data). The read
  ports for `search_token`/`get_token`/`get_intelligence` are likewise unwired.
- **Web defaults the server refuses (F6/F7/F8).** A blank limit expiry and the
  default `usd` amount type are determinate server refusals (no canonical USD
  price; the canonical expiry is a required `i64`), and per-order risk caps are
  unenforceable by the canonical command. These need Trading Core support or a
  web-default change; they stay typed, non-fabricating denials.
- **Edge perimeter assertion (audit[2]).** The edge requires a configured custom
  assertion header but only checks its presence; the operator-owned perimeter is
  expected to add and strip it. Verifying a JWT/HMAC needs operator verification
  material and is left to the perimeter.
- **Server-side revoke on lock (audit[3]).** Client `lock()` drops the keys
  locally; the server epoch is TTL-bounded (15 min) and retired on the next
  handoff, but a lock does not by itself revoke the `kid`. An authenticated
  revoke route is a new protocol surface.
- **Origin topology (audit[1]).** The unlocked payload posts to first-party
  `/v1/*` on the shell origin and the shell's own `/internal/*` enrollment calls
  share that origin, so production must serve the shell and reverse-proxy
  `/internal/*` to private-api and `/v1/*` to the edge on one origin
  (`verify:web-boundary` and the e2e host do exactly that). `/internal/*`
  neutral-family renaming stays the BR-16 residual.
- **Full-stack / production-relay test gaps (audit G1/G6/G7/G10).** The strongest
  in-repo E2E drives the real edge HTTP route + the real composed dispatcher + an
  injected Trading Core seam in-process; the pinned-mTLS test drives the real
  relay against a fail-closed dispatcher; the browser e2e drives the real payload
  against a Node AEAD mock. A single cross-process test that wires the real mTLS
  relay to the injected core (and a `wasm-pack test --node` assertion of the WASM
  `app_session_keys()` orientation) is still missing.

## Sixth slice — production passkey composition + clear-shell authentication

The operator reported a release-blocking defect: `PrivateApiState::production`
built `authenticator: None`, and the only production `PasskeyCredentialStore`
returned `VerifierUnavailable`, so `/internal/auth/challenge` answered `503` on
the real deployment even with a valid RP id/origin. Production passkey auth was
impossible. This slice closes it without weakening any fail-closed default.

### Durable, operator-owned credential store

`apps/private-api/src/passkey_store.rs` adds `FilePasskeyCredentialStore`, the
first real `PasskeyCredentialStore`:

- Persists a versioned JSON document of WebAuthn `Passkey` records. A `Passkey`
  is **public** material only (credential id, COSE public key, signature counter,
  transports); no private key material exists in WebAuthn registration and none
  is written. This is consistent with the PRD's "no infrastructure-held key
  material" rule.
- Writes atomically: a per-write **random** same-directory temp file created
  `O_CREAT|O_EXCL|O_NOFOLLOW`, written `0600`, fsynced, then `rename`d over the
  store, then the parent directory is fsynced. A crash cannot leave a truncated
  store and a local user cannot pre-create or follow the temp path.
- Refuses to load a store it does not own, that has any group/other access bit,
  or that sits in a world-writable directory; it opens the path `O_NOFOLLOW`,
  re-checks that the opened inode is the one it inspected (TOCTOU), and bounds
  the document at 1 MiB. A missing file is the documented empty store; every
  other failure refuses startup.
- `apply_authentication_result` persists the updated signature counter **before**
  publishing it in memory; a store that cannot persist returns
  `VerifierUnavailable` (HTTP 503) rather than accepting an authentication it
  cannot durably record.
- Implements `Debug` as `FilePasskeyCredentialStore([REDACTED])` and logs
  nothing.

### Operator bootstrap enrollment

`crates/auth` gains an additive, fail-closed registration contract:

- `PasskeyCredentialStore::register_passkey` has a default that returns
  `VerifierUnavailable`, so a store without enrollment support refuses instead
  of silently dropping the credential.
- `WebAuthnPasskeyAuthenticator::start_registration`/`finish_registration`
  perform the ceremony and only return success after the store persisted the
  record. `has_credentials` exposes the fail-closed empty check.

`apps/private-api` exposes two operator-gated routes:

| Route | Gate | Behavior |
|-------|------|----------|
| `POST /internal/auth/register/challenge` | `x-evergreen-enroll-secret` (constant-time compare against `PRIVATE_PASSKEY_ENROLL_SECRET`) | Begins a WebAuthn registration; `503` when enrollment is unconfigured, `401` on a wrong secret, `409` once a credential exists unless additions are allowed. |
| `POST /internal/auth/register/verify` | same header | Finishes the ceremony and durably registers the credential; returns no credential id. |

The secret must be at least 32 bytes (`MIN_ENROLLMENT_SECRET_LEN`); a shorter one
refuses startup. Additions after the first credential are refused unless
`PRIVATE_PASSKEY_ALLOW_ADDITIONAL=true`, so the secret is a one-time bootstrap
capability by default. The pending ceremony is single-use, TTL-bounded and
budgeted (`MAX_PENDING_REGISTRATIONS`). The secret is held in a `Zeroizing`
buffer, compared in constant time, and never logged or echoed. The "is another
credential allowed?" decision and the durable registration are serialized under
one enrollment mutex with no `.await` between them, so N concurrent verifies of
challenges minted while the store was empty cannot enroll N credentials. A store
read failure during the policy check is a `503` backend condition, not a `409`
policy conflict.

### Production composition

`PrivateApiState::production_with_passkeys(config, store, secret, allow_add)` is
the real production constructor. `main.rs` wires it when
`PRIVATE_PASSKEY_STORE_PATH` is set (and refuses startup if an enrollment secret
or the allow-additional flag is set without a store). With no store configured
the binary keeps the fail-closed `authenticator: None` behavior — every auth
route answers `503` — so the default is unchanged and only an explicit operator
configuration enables auth.

Operator configuration on the deployment
(`PRIVATE_RP_ID=evergreen.foresift.tech`,
`PRIVATE_ORIGIN=https://evergreen.foresift.tech`):

```
PRIVATE_PASSKEY_STORE_PATH=/var/lib/evergreen/passkeys.json
PRIVATE_PASSKEY_ENROLL_SECRET=<>=32 bytes, high entropy>
# optional, only to enroll a second device later
PRIVATE_PASSKEY_ALLOW_ADDITIONAL=false
```

Bootstrap once with a browser that can reach the perimeter: the clear shell's
"Enroll passkey" form calls the registration routes with the typed secret, then
the ordinary "Authenticate with passkey" path establishes the `__Host-` session
cookie. Remove/rotate the secret afterwards.

### Clear-shell passkey client and `/internal/*` reachability

`web/workspace-shell/src/passkey-auth.ts` is the shell's only authentication
client. It converts the server's `RequestChallengeResponse` /
`CreationChallengeResponse` JSON to DOM options, runs
`navigator.credentials.get`/`create`, and posts the serialized credential back to
the same-origin `/internal/auth/verify` / `/internal/auth/register/verify`
routes. It uses `credentials: "same-origin"` (the perimeter session and the
`__Host-` cookies depend on it), persists nothing, and never logs or interpolates
credential material or the enrollment secret. `index.tsx` never triggers a
passkey ceremony on mount: it probes `GET /internal/auth/session` and
`GET /internal/auth/enrollment-status`, and only the explicit **Open Private
Workspace** action starts WebAuthn. Bootstrap enrollment controls render only
when the server reports `enrollment_open: true`. The session is an HttpOnly
cookie the shell cannot read.

Because every request is same-origin, the operator's single-origin gateway
(`127.0.0.1:8090`: `/internal/*` → private-api, `/v1/*` → edge, requiring
`Cf-Access-Jwt-Assertion`) is reachable from the shell with no CORS exception:
Cloudflare Access injects the assertion on the authenticated same-origin
navigation, and `connect-src 'self'` already permits it.

### Tests added

- `crates/auth`: registration round-trip (enroll then authenticate), duplicate
  refusal, and the default-deny registration contract (3 new tests).
- `apps/private-api/src/passkey_store.rs`: owner-only persistence + reload,
  counter persistence, corrupt/symlink/wrong-version refusal, redacted `Debug`,
  and a full register-then-authenticate over the file store (5 tests).
- `apps/private-api` HTTP production path: real enrollment ceremony →
  `/internal/auth/challenge` unavailable while empty → enroll with the operator
  secret → authenticate → session → `/internal/auth/enroll` and
  `/internal/artifact/grant` reachable → one-time bootstrap refusal; enrollment
  disabled without a secret; short-secret refusal; restart durability (4 tests).
- `web/workspace-shell`: `node --test` unit suite for the JSON↔DOM conversion,
  same-origin request shape, fail-closed behavior and secret-header scoping
  (7 tests), wired into CI as `pnpm test:shell`.
- `scripts/verify-web-boundary.mjs`: the shell first-party path allowlist now
  includes the audited `/internal/auth/{challenge,verify}` and
  `/internal/auth/register/{challenge,verify}` routes.

## Workspace unlock contract (descriptor, compatibility, immutable release)

The unlock path no longer requires a manual Key ID and no longer collapses every
failure into one message.

### Authenticated artifact descriptor

`GET /internal/workspace/descriptor` (authenticated session required) returns only
public release metadata: `protocol_version`, `artifact_version`,
`artifact_kid_b64`, `artifact_size`, `artifact_sha256_hex`,
`package_format_version`, `release_id`, `source_sha`,
`expected_public_key_fingerprint_b64` (when a release manifest is configured),
the workspace protocol range, and the current session's enrollment state. A
normal user never types a KID: the shell discovers it from the descriptor,
derives the workspace key locally, and compares its SHA-256 public-key
fingerprint with the published value before the first network call.

`GET /internal/auth/enrollment-status` is an unauthenticated, non-secret probe
returning `{ "enrollment_open": bool }`. It is true only when a bootstrap secret
is configured and either additional credentials are explicitly allowed or the
durable store is still empty. A store read error is a fail-closed `false`.

### Compatibility preflight before delivery

`POST /internal/artifact` now refuses to wrap and deliver an artifact that cannot
be decrypted by the session's published workspace enrollment. It parses the
bounded artifact header and compares it with the session enrollment
(version/KID) and, when a manifest is configured, the recipient public-key
fingerprint. Failures return a bounded typed body `{ "code": ... }`:

- `409 enrollment_required` — the session has not published a workspace key.
- `409 artifact_incompatible` — KID/version/fingerprint mismatch or a release
  manifest that does not describe these exact bytes.

The check consumes only public metadata, so it is never an oracle for validating
the unlock secret. It rejects the production class where the delivered artifact
was sealed under a different KID than the browser enrolled, *before* any
transport crypto runs. Without a configured release manifest the server has no
trusted recipient fingerprint to compare, so a mismatched-but-well-formed
enrollment is caught only by the browser's fail-closed inner decrypt
(`U5_ARTIFACT`); operators should always publish a manifest (the release and
deployment steps do), which is also what makes recovery authorization possible.

Enrollment is idempotent for the *identical* binding: re-posting the same
version/KID/public-key on the same session returns the existing metadata instead
of `409`, so a page reload or a lock/unlock cycle within one session is not
rejected. A different binding for the same session still conflicts. The shell
also skips the enroll request when the descriptor already reports a matching
enrollment.

### Immutable release manifest and atomic publication

`scripts/workspace-release.mjs` builds `releases/<release-id>/` containing
`manifest.json`, `workspace.artifact` (0600) and `shell/`, validates the whole
directory, then atomically renames the `current` symlink onto it. The previous
target is retained as `previous`, so `rollback` is a second atomic rename and a
released directory is never rewritten. `manifest.json` binds the source SHA,
artifact version/KID/size/SHA-256, recipient public-key fingerprint, package
format version, workspace protocol range and shell asset digest.
`validate`/`readRelease` recompute the shell tree digest and compare it with
`manifest.shell.asset_digest_hex`, and `switchCurrent` validates a release before
pointing `current` at it, so a tampered shell tree is refused even though the
private API never serves the shell itself.

`apps/private-api/src/release.rs` reads `WORKSPACE_RELEASE_MANIFEST` on every
request (no in-process cache) and validates it against the exact artifact bytes
read from `WORKSPACE_ARTIFACT_PATH`. The manifest is the normal production mode:
`main.rs` refuses startup when it is absent unless the operator explicitly sets
`WORKSPACE_ALLOW_NO_MANIFEST=true`, and a present-but-blank path is always a
misconfiguration. Shell HTML is served `no-store,
must-revalidate`; hashed assets under `/assets/*` may be `public,
max-age=31536000, immutable` (`_headers` is written into the release).

```
node scripts/workspace-release.mjs build    --root /var/lib/evergreen/releases
node scripts/workspace-release.mjs validate --root /var/lib/evergreen/releases
node scripts/workspace-release.mjs current  --root /var/lib/evergreen/releases
node scripts/workspace-release.mjs rollback --root /var/lib/evergreen/releases
```

### Privacy-safe unlock stages

`web/workspace-shell/src/unlock-stages.ts` classifies every failure as exactly
one stage — `U1_WASM`, `U2_ENROLL`, `U3_GRANT`, `U4_TRANSPORT`, `U5_ARTIFACT`,
`U6_PACKAGE`, `U7_BOOT` — plus a small machine reason. `UnlockError` carries only
the stage/reason and a fixed generic message; caught exception text, secrets,
KIDs, paths and ciphertext are never propagated. `index.tsx` clears the recovery
code input and its reactive signal before the first network await, decodes to a
`Uint8Array` in the shortest possible scope, and passes bytes (not a retained
string) into `WorkspaceUnlockRuntime.unlock`. JavaScript string zeroization
remains best-effort; the byte copy is zeroized in a `finally`.

### Relay readiness and bind guards

`apps/private-api` relay configuration is strict all-or-none: supplying
`PRIVATE_API_RELAY_BIND_ADDR` with an incomplete identity (or any identity value
without a bind) refuses startup. The relay listener is bound before it is
spawned, so a bad address is a startup error, and `/ready` reports dependency
readiness (relay bound, artifact and manifest header valid, configured command
surface present, configured realtime stream usable, passkey store readable,
optional recovery store readable) distinct from `/health` liveness. The artifact
check requires a deliverable file
(`MIN_ARTIFACT_LEN`, version 1, non-zero KID and encapsulated key), so a
truncated or wrong-version file is never reported healthy; the `dispatcher`
check reflects whether the opaque command surface is configured (the production
binary always wires a fail-closed dispatcher before serving and refuses startup
without one), and a future composition that can lose its dispatcher clears it.
The `stream` check is required only when the composition advertises `realtime`,
that is when a FOMO stream source is configured **and** the bounded startup
reachability probe observed it healthy; a configured-but-unreachable source is
not advertised, so it is not a required dependency. `apps/edge-gateway`
refuses a non-loopback `EDGE_BIND_ADDR` until cryptographic Cloudflare Access JWT
validation is implemented; setting `EDGE_ACCESS_JWT_VALIDATION=true` cannot
bypass that, so the loopback deployment mitigation cannot be widened silently.

## Post-review hardening (adversarial review of the unlock slice)

Three fresh-context reviewers audited the uncommitted unlock/release slice. No
CRITICAL/HIGH confidentiality or integrity break was found in the browser path;
the valid findings were fixed with regression tests:

- **Production-faithful unlock proof (P0-C).** `verify:web-boundary` now builds
  an artifact with the production script `scripts/build-workspace-encrypted.mjs`
  and runs the ignored Rust test
  `production_build_script_artifact_loads_delivers_and_unpacks`, which reads
  that exact file through the **real** `load_workspace_artifact` (no loader
  override), drives the real `/internal/artifact` HPKE delivery, decrypts the
  outer transport envelope, decrypts the inner artifact with the
  production-derived workspace key and unpacks the production package. The gate
  also writes the immutable release manifest for those bytes, so the real
  manifest-vs-artifact byte validation and recipient-fingerprint preflight run on
  the matching path in the same request; the rejection path is proven by
  `recovery_challenge_refuses_a_self_enrolled_foreign_key` and the `release.rs`
  unit tests. A substituted-but-well-formed ciphertext is rejected at
  `U5_ARTIFACT` because the shell now enforces the authenticated descriptor's
  `artifact_size` and `artifact_sha256_hex` before the inner decrypt.
- **Release headers.** `scripts/workspace-release.mjs` no longer overwrites the
  shell `_headers`; it preserves the hardened `/*` rule (CSP, nosniff,
  frame-deny, referrer policy) and appends the cache rules, and `publishRelease`
  only treats an existing release as idempotent when both the artifact bytes and
  the shipped-shell digest match. Release ids are validated as single directory
  names and the manifest is cross-checked against its directory.
- **Unlock secret lifetime.** The WASM-binding-returned app-key and decrypted
  payload buffers are zeroized in place instead of being wrapped in a second
  copy that would leave the first resident.
- **Shell recovery paths.** A failed descriptor fetch offers a retry action; an
  `enrollment_required` delivery response refetches the descriptor so the retry
  re-enrolls rather than replaying a stale skip; the raw KID is no longer
  rendered; stage progress marks completed steps.
- **Readiness.** `/ready` bounds the artifact and manifest reads from metadata
  before reading, runs artifact I/O on the blocking pool, and clears the relay
  readiness flag on any task exit (not only `Err`).

## Second adversarial review pass (UX/auth/unlock lane)

Five fresh-context reviewers re-audited the whole slice against current code. No
CRITICAL or HIGH confidentiality/integrity break was found in the browser path.
The confirmed findings were fixed with regression tests:

- **Unlock secret lifetime (MEDIUM).** `deriveWorkspaceFingerprint` now zeroizes
  its owned copy of the recovery code after deriving the key. A WASM constructor
  fault is classified `U1_WASM/wasm_unavailable` rather than blaming a valid
  recovery code, and `HandoffGate.take` drops the shell's copy of the payload
  AEAD keys after the one-shot handoff.
- **Recovery wrapping (LOW hardening).** The AES-GCM AAD is now the canonical
  `version | algorithm | key_source | credential_id` tuple, so a rewritten record
  cannot be reassigned to another credential or downgraded without breaking the
  tag; `key_source` is part of the primitive's validation. `parseRecoveryWrappers`
  skips an invalid record instead of disabling every remaining valid passkey
  wrapper, and the pending proof-of-possession challenge set now has a
  per-session bound in addition to the global one.
- **Readiness (MEDIUM).** `/ready` no longer reports a truncated or
  wrong-version artifact as healthy: the header probe requires
  `MIN_ARTIFACT_LEN` and mirrors the audited envelope's public-header validation
  (version, non-zero KID, non-zero encapsulated key). The dispatcher is an
  explicit readiness check. `apps/edge-gateway` eagerly loads and validates its
  certificate/key/CA at startup (instead of failing later as a permanent 503),
  trims whitespace-only identity values, and has a router-level forged/absent
  assertion test.
- **Release publication (LOW hardening).** Staging uses `mkdtemp` (no
  collision) with an age-bounded stale sweep; directory fsync happens after the
  directory is populated and after every symlink rename; `readRelease` rejects a
  symlinked release or shell directory and one that resolves outside the
  releases root; re-publishing refuses a changed recipient fingerprint even when
  the artifact id collides.
- **UI/accessibility.** The payload reduced-motion rule stops the spinner
  instead of slowing it; the trade-execute and withdrawal-review confirmations
  move focus into a named `alertdialog`, announce assertively, and return focus
  on cancel; mobile `.chip-button` targets reach 44px wide; the workspace scroll
  container and shell programmatic-focus targets keep a visible focus ring; the
  withdrawal confirmation and shell security gateway are axe-gated at
  moderate-or-worse; and the shell has a positive control that bootstrap
  enrollment controls appear when the server reports enrollment open.

## Third adversarial review pass (release-remediation hardening)

Four fresh-context reviewers independently re-audited the browser auth/unlock,
Rust preflight/relay/ingress, release tooling, and WebAuthn-PRF recovery slices
against the current tree. No CRITICAL break was found. The confirmed findings
were fixed with regression tests:

- **Artifact build atomicity (HIGH).** `scripts/build-workspace-encrypted.mjs`
  now seals to a same-directory temporary file (mode 0600), fsyncs it, re-reads
  and verifies exact length and SHA-256, then atomically renames over
  `web/workspace-artifact/blob.bin`. A failed or aborted rebuild removes only the
  temp file; it can no longer delete or truncate the previously published
  artifact (the negative build tests deliberately abort the script).
- **Clear-shell header integrity (HIGH).** `writeShellCacheHeaders` fails
  closed: a shipped `_headers` that lacks a hardened `/*` rule (`no-store`,
  `nosniff`, `DENY`, `no-referrer`, CSP with `default-src`) is refused, and a
  missing `_headers` gets the complete hardened block rather than only
  `Cache-Control`. Explicit `/` and `/index.html` `no-store, must-revalidate`
  and `/assets/*` immutable rules are emitted, and re-running is idempotent.
- **PRF at enrollment (HIGH, functional).** The clear shell requests the
  WebAuthn PRF extension in `buildCreationOptions`, so a passkey enrolled by this
  build can produce the PRF output the recovery wrapper needs. Support is still
  verified at use time: an authenticator that returns no output falls back to the
  mandatory offline recovery code, and a normal assertion signature is never used
  as key material.
- **Release publication interlock.** `current`/`previous` switching, rollback and
  the publish decision tail run under a per-releases-root advisory lock (atomic
  `mkdir`, bounded acquire, stale-age guard, re-entrant). `rollbackCurrent`
  refuses a missing/identical target instead of reporting a no-op rollback, and
  `readRelease` rejects symlinked or non-regular `manifest.json`/`workspace.artifact`
  entries. The CLI removes the default plaintext payload build after sealing;
  an operator-supplied `--payload` path is never deleted.
- **Unlock diagnostics and secret lifetime.** Invalid recovery codes now map to
  `U2_ENROLL/invalid_secret` with re-entry guidance; the three unlock POSTs set
  `redirect: "error"`; `onStage("U5_ARTIFACT")` is emitted before the
  descriptor size/digest checks; a `401` on grant/deliver maps to
  `session_expired` so the UI offers re-authentication (a `403` stays a generic
  rejection, since the private API only uses `401` for session expiry); the inner
  WASM `initiator.free()` is guarded; and the unlock stage list is announced
  through a `role="status"` wrapper (not on the `<ol>`, which axe rejects). The
  release fingerprint block is a labelled `<section>` rather than a named generic
  `<div>`.
- **Recovery hardening.** The credential-bound AAD is preferred and the
  pre-binding bare domain constant is retained as a documented legacy
  compatibility path (earlier builds of this unreleased branch wrote unbound
  wrappers; the two AADs are distinct so a bound record cannot be downgraded).
  `wrapWithPrf`/`unwrapWithPrf` now require the credential id;
  `parseWrapperRecord` validates the algorithm and decoded salt/IV/ciphertext
  lengths; the PRF copy is zeroized on a failed verification; a successful
  decrypt with degenerate plaintext surfaces `invalid_root_key`; and the random
  generators throw a typed `crypto_unavailable`.
- **Readiness and ingress.** `load_workspace_artifact` reads through a
  `take(MAX+1)` bound (no over-limit allocation if the file grows between the
  metadata check and the read); relay "supplied" is `is_some()` so a
  whitespace-only bind refuses startup; `deliver_artifact` seals before mutating
  the transport-session registry; edge authorization rejects genuine
  forwarding/topology headers (`x-forwarded-for/-proto/-host/-port`, `x-real-ip`,
  `cf-connecting-ip`, …) while still accepting the dedicated assertion header and
  the oauth2-proxy identity headers (`x-forwarded-access-token/-user/-email/-groups`);
  `strict_bool_env` refuses a non-Unicode setting instead of defaulting; and
  `/ready` reports `manifest_configured` so operators can see whether the
  explicit no-manifest opt-in is in effect (`WORKSPACE_ALLOW_NO_MANIFEST=true`);
  without it an absent `WORKSPACE_RELEASE_MANIFEST` refuses startup.
- **Non-text contrast (WCAG 2.2 AA 1.4.11).** Interactive `.button` and
  `.field__input` boundaries use a dedicated `--line-interactive` token
  (≈4.5:1) instead of the lower-contrast divider color.
- **Cross-browser E2E.** The Playwright suite adds a Firefox project; the shell
  mocks `navigator.credentials` and reports an existing operator session, so the
  production-faithful unlock host and every payload surface run in a second
  engine as well as Chromium.

## Fourth adversarial review pass (independent delta audit)

Three fresh-context reviewers re-audited the browser shell/unlock/recovery, the
Rust private-api/edge trust anchors, and the release tooling/boundary gate. No
CRITICAL/HIGH runtime defect was found; the confirmed findings were fixed with
regression tests and a fresh-context delta review of the fixes
(`.dsh/release-remediation/REVIEW_V7.md`):

- **Boundary gate: console evasion (MEDIUM).** `assertNoConsoleUsage` now also
  rejects a bare `console` identifier, closing qualified/bracketed/optional-chain
  evasions (`globalThis["console"]["warn"]`, `console?.log`,
  `console["log"]?.(...)`) that the call regex alone missed.
- **Boundary gate: encoded assets (LOW).** A non-UTF-8 asset is refused unless
  its extension is a known binary container, so a UTF-16/encoded text asset can
  no longer carry an endpoint past the text scanners. `assertNoExternalUrls`
  additionally decodes `\/`, `\xNN` and `\uNNNN` escapes before scanning.
- **Release cache policy (MEDIUM).** The hardened `/*` block no longer sets
  `Cache-Control`. Cloudflare Pages inherits every matching rule and comma-joins
  a header set twice, so the old wildcard `no-store` was joined with the
  `/assets/*` immutable value and `no-store` won — hashed assets were never
  cached. HTML stays `no-store, must-revalidate`; `/assets/*` stays immutable.
  `writeShellCacheHeaders` and the boundary verifier now resolve headers with
  Cloudflare join semantics and reject a wildcard `Cache-Control` or any
  path-specific rule that weakens a hardened security header.
- **Trust-anchor open: FIFO swap (MEDIUM, availability).** `open_no_follow`
  (manifest/artifact), the recovery store and the passkey store add
  `O_NONBLOCK`, so a rename-swapped FIFO cannot block a non-following open and
  exhaust Tokio blocking threads. Regular-file reads are unaffected.
- **Unlock UX/a11y (MEDIUM/LOW).** The enrollment and add-recovery inputs now
  carry `aria-invalid`/`aria-describedby` to their message regions; the PRF
  output is zeroized immediately after wrapping instead of across two network
  awaits; and `unlock()` announces `U2_ENROLL`/`U5_ARTIFACT` before the
  pre-network validations so the progress ledger reflects the real failing stage.
- **E2E.** The shell spec now snapshots `#recovery-code` at the first
  `/internal/artifact/grant` request (pinning "cleared before the first await"
  rather than retrying), and axe-scans the authenticated unlock surface and the
  credential-failure alert at moderate-or-worse.

Accepted residuals (unchanged): the recovery proof-of-possession challenge is
single-use, session-bound and TTL-bounded but not bound to a specific operation;
`list_recovery_wrappers` requires only an authenticated session (the wrapped
ciphertext is AES-256-GCM under the PRF/offline secret, and the pre-unlock client
must list it); `/ready` validates the manifest shape/KID/size but not the full
artifact digest on every unauthenticated probe; and edge perimeter trust stays
presence-only with the loopback bind as the compensating control.

## KLineChart Pro private chart (frontend slice)

The handwritten canvas chart is replaced by KLineChart Pro behind a small local
adapter boundary. Pinned to the mutually compatible pair
`@klinecharts/pro@0.1.1` + `klinecharts@9.1.1` (exact versions). Pro 0.1.1's own
upstream dependency is unresolved against klinecharts v10 (the v10 production
build fails with missing exports `FormatDateType`, `DomPosition`, `ActionType`,
`TooltipIconPosition`), so the v9 pair is the only tested combination; v10 must
not be used under Pro 0.1.1.

- **Boundary.** `chart/chart-datafeed.ts` defines the renderer-agnostic
  `ChartHistoryProvider` / `ChartRealtimeSource` contract and the bounded
  `ChartFrameRouter`. `chart/pro/pro-datafeed.ts` is the only module that maps
  Pro's `Period`/`KLineData` vocabulary; `chart/pro/pro-chart.ts` owns the Pro
  lifecycle. No Pro type reaches session/domain/realtime code.
- **History.** `getHistoryKLineData` calls the authenticated/encrypted
  `get_chart` command (capability-gated on the `chart` capability) and normalizes
  the response defensively; when the capability is absent, the channel is not
  ready, the timeframe has no canonical window, or the response is malformed it
  falls back to the bounded local buffer. It never fabricates a candle.
- **Realtime.** `subscribe` consumes the already-decrypted local frame bus
  (`ChartFrameRouter`, fed by the worker's decoded `ohlcv` frames) and
  `unsubscribe`/`dispose` tear every subscription down. Pro may re-subscribe
  without an intervening unsubscribe, so re-subscribe drops the previous handler.
- **Pro lifecycle.** Pro 0.1.1 has no public `dispose()` and registers a
  `window` resize listener while rendering its Solid tree. The adapter captures
  that listener during construction, drives resize from a `ResizeObserver` on
  the host, removes the listener and detaches the host on dispose, and degrades
  to a visible "Chart unavailable" state if a runtime cannot start the canvas.
- **CSP/assets.** The vendor layout CSS is bundled (no external stylesheet/CDN).
  Its iconfont is a `data:` URL that `font-src 'self'` blocks in both the payload
  and the inheriting shell policy, so the four icon slots are re-rendered with
  first-party glyphs instead of requesting the blocked font. The final payload
  still passes the URL/storage/tracker/console boundary scans.
- **Non-authoritative.** Chart data is visual only. Limits and trades continue to
  depend on exact route simulation/net executable economics, never on a chart
  crossing.

Tests: `chart/chart-datafeed.test.ts`, `chart/history.test.ts` and
`chart/pro/pro-datafeed.test.ts` cover normalization/dedup/bounding, malformed
frames, replay and broadcast, subscribe/unsubscribe/re-subscribe/dispose,
capability and outage fallback, and that no path fabricates a candle.
`web/e2e/specs/chart.spec.ts` adds a real-browser smoke (mounted canvas with real
dimensions, Pro period switch, container resize, malformed-frame resilience, no
chart-related page errors) without canvas pixel snapshots.

**FOMO market bridge (backend, read-only).** The backend serves chart history
and realtime OHLCV from the local, read-only `fomo-mcp` bridge behind a small PEP
adapter (`apps/private-api/src/fomo_market.rs`). PEP never holds FOMO
credentials: `fomo-mcp` owns the FOMO session, and PEP calls its loopback
`GET /market/bars` (fresh) and `GET /market/latest` (bounded cadence) endpoints
with the bridge's own bearer key.

- **Configuration (all-or-none).** `PRIVATE_FOMO_MARKET_URL` (loopback
  `http://…`) plus `PRIVATE_FOMO_MARKET_API_KEY_FILE` (owner-only, non-symlink,
  read through the hardened reader) enable the chart read. The dedicated `chart`
  capability is advertised only when this is wired; `market` stays false, so
  `search_token`/`get_token` remain determinate `capability_missing` denials
  because they are not backed by FOMO (capability truth, audit F6).
- **History.** `get_chart` accepts
  `{chain,address,window,countBack?,from?,to?}`. Both the frontend timeframe ids
  and the canonical `m5/m15/h1/h4/d1` windows map through a closed table to a
  FOMO resolution; only `solana`/`base`/`ethereum`/`bnb_chain` have a verified
  FOMO network id, and anything else is refused. `from`/`to` are unix seconds
  and `countBack` is clamped to 1 500. The dispatcher validates the range and
  normalizes every page itself (ascending, unique-millisecond, OHLC-envelope
  valid, capped) so an injected provider cannot return an unordered or duplicate
  series to a renderer.
- **Realtime.** `FomoOhlcvStreamSource` implements the PEP `StreamSource` at a
  bounded poll cadence for one operator-configured target
  (`PRIVATE_FOMO_STREAM_TARGET=chain:address:timeframe`, plus optional
  `PRIVATE_FOMO_STREAM_POLL_MS` and `PRIVATE_FOMO_STREAM_COUNT_BACK`). It emits
  the full normalized series as the snapshot and one latest-bar delta when the
  provider's newest bar changed (the browser replaces the last bar in place or
  appends a new one); a provider outage emits nothing rather than a fabricated
  or interpolated bar. `realtime` is advertised only when a target is
  configured **and** the bounded startup reachability probe observed it healthy.
  The stream has no client-supplied subscription target yet, so this
  first implementation is single-target by construction.
- **Provenance and bounds.** The client accepts a bridge payload only when
  `source.provenance == "polling"` and `wsPromoted` is not true, refuses
  non-2xx / oversized (>2 MiB) / malformed bodies, and maps every failure to a
  fixed, privacy-safe denial or `U`-typed error — never upstream text, the key,
  a path or ciphertext.
- **Non-authoritative.** Chart data stays visual only; limits and trades still
  depend on exact route simulation / net executable economics, never a chart
  crossing.

**Residual (operator / FOMO-lane owned).** The PEP adapter, the descriptor and
the browser chart are implemented and exact-SHA CI green, but the deployed
`fomo-mcp` image does not yet expose `/market/bars`. The coordinated read-only
bridge is implemented on `fomo-mcp` branch `worker/deepseek-pep-market-source`
(implementation commit `dced9624a16e3566679cda560ffcc9a8a0220bff`, backed by the
verified-current FOMO `POST /proxy/getBarsNew`); PEP and that branch agree on the
request shape (`symbol=address:networkId`, `resolution`, `countBack`, `from`/`to`
unix seconds), the ascending/unique-millisecond OHLCV response and
`source.provenance == "polling"`. It is **not deployed**, so a configured PEP
still fails closed with `Unavailable` and the chart renders only the local
decrypted frame buffer — never fabricated data. PEP does not modify `fomo-mcp`
(the sole FOMO upstream owner) and carries no FOMO auth tokens. The FOMO `prices`
WS topic and the `mobula-api.fomo.family` OHLCV stream remain CORROBORATED only
and are deliberately not promoted; the shipped source is bounded REST polling.

**Unlock-proof coverage split (explicit).** The production-faithful unlock proof
is delivered in two halves that together cover the whole chain, because no single
runner has both the Rust loader and a browser DOM:
`scripts/verify-web-boundary.mjs` runs `apps/private-api`'s real default
`load_workspace_artifact` + real HPKE routes over the artifact built by the
production build script and the manifest written by the production writer, then
performs the outer transport decrypt, inner artifact decrypt and production
package unpack (`production_build_script_artifact_loads_delivers_and_unpacks`,
an anti-vacuous `--ignored` test whose exact stdout is asserted). The browser E2E
(`web/e2e/specs/shell.spec.ts`) boots that same production package format with
the real WASM decrypt + `unpackPackageFromMemory` under the production CSP and
asserts the decrypted workspace actually renders. The only unproven composition
is a single runner that does *both* the real Rust loader and a real DOM boot; it
is recorded here rather than implied.

