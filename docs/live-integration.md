# Private Web ↔ Private Backend Live Integration (BR-5/BR-7/BR-1/BR-2/BR-3)

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
- The edge relays ciphertext only. `/v1/command` was added to the edge router and
  the internal `Route` enum (`ROUTE_COMMAND = 4`); the edge never parses the
  envelope and keeps its authorization/size/hardening gates.

## BR-5 session key handoff (authenticated key epoch)

The authenticated HPKE exchange that delivers the encrypted artifact also yields
the browser transport session:

1. `/internal/artifact/grant` publishes a per-grant HPKE offer.
2. `/internal/artifact` runs `responder_establish`, seals the artifact, and
   registers a `session-transport::ServerSession` under the grant `kid` with a
   bounded TTL. The registry is shared with the opaque relay.
3. The shell's `WasmInitiatorSession` exposes `kid()` and `app_session_keys()`
   (`c2s(32) || s2c(32)`), derived from dedicated HPKE exporter labels
   (`private-execution app aead c2s/s2c v1`) so they are distinct from the
   ChaCha artifact-session keys.
4. The shell retains the session only while unlocked, and posts
   `{type:"evergreen:session-key", kid, s2cKeyB64, c2sKeyB64}` to its own
   sandboxed frame when the payload announces readiness. `lock()` drops the
   reference.
5. The payload imports the raw keys as **non-extractable** `CryptoKey`s
   (AES-GCM encrypt/decrypt) and zeroizes the base64/byte copies.

No key is persisted. The `ServerSession`/`SessionRegistry` zeroize on drop and
their `Debug` output is redacted.

## Request/response plaintexts

| Route | Request | Response |
|-------|---------|----------|
| `/v1/bootstrap` | `{op:"bootstrap", protocol_version:1, request_id}` | flat session document + `request_id` |
| `/v1/sync` | `{op:"sync", from_seq, request_id}` | `{request_id, result:{accepted, from_seq}}` |
| `/v1/command` | `{op, payload, request_id, idempotency_key}` | `{request_id, result}` or `{request_id, error:{code,message,retryable}}` |

- The response envelope `sequence` equals the request `sequence`; the client
  rejects a mismatch.
- Every response (success or typed denial) echoes the request `request_id`
  inside the AEAD (BR-3), defeating stream-frame/response substitution.
- Bootstrap is authoritative and fail-closed: absent configuration, all
  capabilities are `false`, `trading_enabled=false` and the kill switch is
  engaged.
- `/v1/sync` and `/v1/bootstrap` c2s windows are tracked independently from
  `/v1/command` because the browser uses per-endpoint sequence counters.

## Command binding (BR-3)

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

## Tests

- `crates/session-transport`: envelope/AEAD/replay/expiry/sequence-binding unit
  tests (14).
- `apps/private-api` unit + `end_to_end_enrollment_and_workspace_artifact_unlock`
  now drives the opaque bootstrap/command surface from the real HPKE initiator
  keys (51 lib tests).
- `apps/edge-gateway/tests/opaque_command_e2e.rs`: browser-shaped opaque envelope
  -> edge `/v1/command` and `/v1/bootstrap` -> private-api session service ->
  fail-closed dispatcher, plus replay rejection and JSON-body rejection (4).

## Residuals (explicit)

- **BR-2 realtime stream server**: the encrypted `/v1/stream` producer and the
  production edge stream relay are not implemented. The envelope, AAD, per-purpose
  windows, sync contract and BR-15 `server_time_ms` handling are in place, but
  with no market-data source the stream stays fail-closed. This is the next
  slice.
- **Operator wiring**: `private-api` can serve the mTLS relay
  (`PRIVATE_API_RELAY_BIND_ADDR` + identity env) but the Trading Core composition
  (real backend, authoritative capabilities, dynamic kill switch) is not wired;
  `FailClosedDispatcher`/`FailClosedBootstrap` remain the default.
- **BR-9/10/11/12/14/15**: client identifiers + UNKNOWN lookup, execute
  `execution_id`/`router_source` echo, canonical instrument contract, wallet
  limit read/write, and the per-frame authenticated clock emission still need
  backend work (the canonical command vocabulary has no such operations today).
- **Git/CI**: this session's sandbox could not write the worktree's git index, so
  the branch could not be committed/pushed from here; changes are on disk in the
  worktree. `apps/private-api/src/opaque.rs` must be `git add -f`'d because the
  repo `.gitignore` contains the literal `private-api`.
