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
- **Shell BR-5 handoff test coverage**: the shell's token injection and one-shot
  gate are implemented and were verified by the fresh-context review, but
  `web/workspace-shell` has no unit-test runner and the browser e2e delivers the
  session key to the payload directly, so there is no automated regression test
  for "no token / wrong token / repeat ping delivers nothing". Adding one needs a
  shell test setup or a shell-level e2e that asserts delivery only after the
  token echo.
- **Client/server capability-label mismatches (pre-existing)**: the shipped UI
  gates `search_token`/`get_token` on `intelligence` (the server maps them to
  `market`) and `get_execution_progress` on `twap` (the server leaves it
  ungated). The server is authoritative and fail-closed, so this can only hide a
  surface prematurely or return a determinate `capability_missing`; aligning the
  client labels is a small web-only follow-up.
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
    bootstrap document from *what is actually wired*. Enabling trading does not
    advertise a capability whose backend is absent, and the kill switch stays
    engaged until a mutating seam is injected.
  - Still residual: the concrete Trading Core composition (real `AgentBackend`,
    authoritative `AgentCapabilities`, `InstrumentRegistry` backed by market
    metadata, `WebContractBackend` for wallet limits/reconciliation, real
    `StreamSource`) is injected through `web_command_dispatcher` /
    `production::OpaqueComposition` but not built by the binary. Wiring it needs
    genuinely operator-owned inputs (owner/wallet/chain/risk limits, Privy
    signing, chain adapters, live market data), so with none supplied the
    `FailClosed*` defaults remain and every mutation is an authenticated
    `capability_missing` denial — never a fabricated success.
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
  document from `WiredCapabilities`; an operator that advertises
  `twap`/`rfq`/`withdraw`/`intelligence` without the matching
  `WebContractBackend` handler gets a determinate `capability_missing` (never a
  false success). A `serves(op)` probe on the seams would make the advertisement
  authoritative.
- **Shipped binary composition (F1/F10, operator-owned).** `main.rs` still passes
  `dispatcher: None`, so the binary serves the fail-closed default; the concrete
  Trading Core read/trade backend, `WebContractBackend`, `InstrumentRegistry`,
  `StreamSource` and chains need operator inputs (owner/wallet/chain/risk limits,
  Privy signing, live market data). The read ports for
  `search_token`/`get_token`/`get_intelligence`/`get_chart` are likewise
  unwired.
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
