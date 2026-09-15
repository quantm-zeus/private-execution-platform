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
   sandboxed frame when the payload announces readiness. `lock()` drops the
   reference.
5. The payload imports the raw keys as **non-extractable** `CryptoKey`s
   (AES-GCM encrypt/decrypt) and zeroizes the base64/byte copies.

No key is persisted. `ServerSession`/`SessionRegistry` zeroize on drop and their
`Debug` output is redacted.

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
  `get_withdrawal_by_request_id`, `get_execution_progress`.
- BR-14 `get_wallet_limits` / `set_wallet_limits` (the write requires an
  idempotency key; the backend is the authorization boundary).
- BR-12 `place_limit_order` results are projected to a top-level `order_id` from
  the backend's own `order.order_id`; a success without one is indeterminate.
- BR-10 `execute_market_order` requires an `execution.state` of
  `submitted`/`filled`, a `router_source` echo equal to the requested
  `router_preference`, and a non-empty `execution_id`; `unknown`, a missing echo
  or a missing id is an authenticated indeterminate denial. `agent-backend`'s
  `execution_outcome` now emits `router_source` and the intent-id
  `execution_id`, so a real Trading Core satisfies this honestly.

## Tests

- `crates/session-transport`: envelope/AEAD/replay/expiry/sequence-binding plus
  stream-frame schema, monotonic stream sequence, stale-server-time refusal and
  subscribe purpose-window tests (20).
- `apps/private-api`: 67 lib tests, including the real gRPC bidi
  `RelayStreamService` subscribe + snapshot round-trip, driver fail-closed /
  resync tests, and the `WebContractDispatcher` no-false-success tests.
- `apps/edge-gateway/tests/opaque_command_e2e.rs`: browser-shaped opaque envelope
  -> edge `/v1/command` + `/v1/bootstrap` -> private-api session service, plus
  replay rejection, JSON-body rejection, and BR-10/BR-12 no-false-success
  assertions through the web-contract layer (7).
- `web/workspace-payload`: 356 unit tests including the worker subscribe-frame
  test (`realtime/worker.test.ts`).

## Residuals (explicit)

- **BR-11 command payload translation (main blocker to live trades)**: the web
  sends `{chain, token_in, token_out, amount, amount_type}` (human amount plus a
  separate chain id), while the canonical `agent-commands` vocabulary expects
  `token_in`/`token_out` as `{chain, address}` objects and `amount` as atomic
  units (`{unit, value}`). Token amounts require token decimals the web contract
  does not carry, so the private layer does not guess. Until either the web sends
  atomic amounts or the private layer resolves token decimals server-side,
  `get_quote`/`preview_market_order`/`execute_market_order`/`place_limit_order`
  over `/v1/command` fail closed at the canonical parser (`protocol`/`malformed`)
  rather than trading on a guessed amount. The bootstrap `native_token` half of
  BR-11 is implemented.
- **Operator wiring**: the Trading Core composition (real `AgentBackend`,
  authoritative capabilities, dynamic kill switch, real `StreamSource`,
  `WebContractBackend` for wallet limits and reconciliation stores) is not wired;
  `FailClosed*` remain the defaults. The production edge binary still serves
  `default_router()` (unavailable relays, no authorization backend); the operator
  composes `PrivateRelay`/`PrivateStreamRelay` plus an `AuthorizationBackend`.
- **BR-16 naming**: enrollment/artifact paths remain `/internal/*` and are
  asserted by `verify:web-boundary`; neutral-family renaming is a platform
  decision.
- **Git**: the sandbox cannot write the shared worktree git metadata, so commits
  are created in a workspace-local export repo (`<worktree>/.export`) that shares
  object alternates with the main clone and pushes to `origin`. The branch and
  draft PR are real; the worktree's own git index is untouched.
