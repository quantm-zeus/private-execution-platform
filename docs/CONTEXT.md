# Existing Systems Context

Operator: private owner. New platform must reuse existing intelligence projects instead of rebuilding them.

## Existing FOMO service
Local repo: /home/minhquan_eth/fomo-mcp
GitHub: quantm-zeus/fomo-mcp
Current main observed before bootstrap: 3b0603f, clean except operator-owned untracked prompt/design markdown files. Do not delete or rewrite those files.

Treat fomo-mcp as the FOMO Intelligence Service, not merely an MCP connector. Known capabilities include Rust/Tokio architecture, FOMO REST client, WebSocket supervisor, REST reconciliation/fallback, normalized event pipeline, TimescaleDB journal, dedupe/coverage tracking, bounded TTL cache, trader-quality cache, Hot Token Engine, Alpha Radar, Telegram alert pipeline and read-only MCP tools.

The read-only boundary is intentional. Trading/signing never belongs in fomo-mcp. It remains the single owner of FOMO upstream REST/WS connections.

## Existing GMGN service
Local repo: /home/minhquan_eth/gmgn-mcp
GitHub: quantm-zeus/gmgn-mcp
Current main observed before bootstrap: 030a0e7 and clean.

Treat gmgn-mcp as the GMGN Intelligence Gateway. Known capabilities: SQLite/cache layer, singleflight, weighted global rate gate, persisted cooldown, probation, circuit breaker, stale fallback, strict read-only allowlist and no automatic upstream retry.

Conservative request policy currently uses roughly 8 weighted units/s normal and 4 units/s in probation. Expensive holder/trader endpoints are weighted more heavily and should be called only after candidate gating.

## Integration principle
Do not make destructive changes to either existing repo during bootstrap. New platform consumes them through explicit service/adaptor boundaries first. Reusable crates may be extracted later with compatibility preserved.
