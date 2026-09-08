# Project Status

## Phase 0
Minimal workspace scaffold: READY FOR PARALLEL WORK. Live trading: DISABLED / NOT IMPLEMENTED.

## Worker ownership
- W1 `worker/domain-contracts`: crates/domain, crates/market-types, crates/chain-types, proto/contracts if introduced.
- W2 `worker/security-edge`: crates/crypto-envelope, apps/edge-gateway, private transport/security skeleton introduced by this worker.
- W3 `worker/storage-eventing`: crates/storage, crates/telemetry, infra and NATS/JetStream/storage foundation introduced by this worker.

Cross-scope root changes require maintainer review. Existing fomo-mcp/gmgn-mcp repositories are not worker write targets.

## Next
After W1-W3 integrate: fomo-service reuse, gmgn-service/provider-broker, then local market-state workers.
