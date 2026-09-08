# Project Status

## Phase 0 Foundation
Wave 1 is integrated and verification-clean. Live trading remains DISABLED / NOT IMPLEMENTED.

Completed in this wave:
- Canonical chain/market/domain contracts with validated TradeIntent, LimitOrder FSM, risk/limit-price semantics, route/tax/provider metadata, expiry handling, and all-or-nothing fill policy.
- Application E2EE foundation: ChaCha20-Poly1305 envelopes, monotonic sequence/nonces, 64-frame replay window, tamper/replay protection, directional HPKE session establishment, canonical offer/kid binding, and RAM-only zeroized session material.
- Opaque storage/telemetry foundation: generic objects/events/snapshots/streams, bucketed physical timestamps, closed telemetry vocabulary, Timescale/Postgres + NATS JetStream local infra.

Verification at this checkpoint:
- `cargo fmt --check`: PASS
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS
- `cargo test --workspace`: 127 tests PASS
- `docker compose -f infra/docker-compose.yml config`: PASS
- Static scans: no raw private/signing APIs, direct FOMO/GMGN/Twitter upstream URLs, debug-print macros, exact SQL timestamps, or public raw HPKE session constructors in the integrated foundation.

## Security invariants currently enforced
- No live trading or raw wallet-key path exists.
- HPKE Base-mode offer must arrive through an integrity-authenticated bootstrap/passkey channel; Base mode does not authenticate the initiator by itself.
- HPKE c2s/s2c keys are domain-separated, session key ids are bound, raw same-key construction is crate-private, and exporter temporary buffers are RAII-zeroized.
- A 4-byte nonce prefix is safe only under the current fresh, non-persisted, non-resumed per-direction key model. Key reuse/resumption requires a nonce/session redesign before it may be enabled.
- Telemetry labels and metric names are closed typed vocabularies; runtime token/wallet/order strings cannot be exported as metric labels through the public API.

## Remaining Phase 0 work
- Privy signing boundary and bounded Trading Wallet policy surface (no live-money enablement yet).
- Passkey/authenticated bootstrap and public/private web split.
- Wire HPKE/encrypted envelopes into opaque Edge `/v1/bootstrap`, `/v1/sync`, `/v1/stream`, `/v1/blob` paths.
- Service identity, global `TRADING_ENABLED=false` kill switch, encrypted audit/runbook/threat-model coverage.
- Internal protobuf/gRPC contracts and service wiring; install/pin protoc tooling as part of that isolated task.

## Next parallel wave
1. Auth/passkey + public/private workspace boundary.
2. Opaque Edge transport integration using the reviewed HPKE/envelope crate.
3. Privy boundary + trading policy/kill-switch skeleton with execution disabled.
4. Reuse `fomo-mcp` and `gmgn-mcp` through internal adapters and begin Provider Intelligence Broker after contract interfaces are stable.

Existing `fomo-mcp` and `gmgn-mcp` repositories remain operational and must not be destructively modified or bypassed with duplicate upstream clients.
