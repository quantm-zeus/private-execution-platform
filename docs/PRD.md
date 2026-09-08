# Private Multi-Chain Best-Execution Platform

Status: Architecture Locked.

Build a private multi-chain smart execution and intelligence terminal with one canonical Trading Core shared by Private Web, MCP/ChatGPT, and Telegram.

Backend: Rust, Tokio, Axum, tonic, prost. EVM: Alloy and revm. Solana: Solana SDK and Yellowstone/Geyser-compatible gRPC. Messaging: NATS Core and JetStream. Database: PostgreSQL and TimescaleDB. Private web: SolidJS/TypeScript/Vite CSR. Public web: SolidStart SSR/SSG. Internal RPC: gRPC/Protobuf/mTLS.

Initial chains: Solana, Base, BNB Chain, Robinhood-associated network where technically supported, and Ethereum. Chain logic must remain adapter-based.

Core rule: displayed prices are informational; exact simulated net wallet balance deltas are execution truth. Route optimization maximizes net received after all taxes, fees, gas, price impact, slippage, MEV and execution risk.

Existing fomo-mcp is the only FOMO upstream owner. Existing gmgn-mcp is reused as the GMGN intelligence gateway. External intelligence sources never become execution-critical dependencies.

Signing is delegated to Privy. Sensitive key material must not be stored by our infrastructure. AI only creates structured TradeIntent objects and cannot access generic signing or transfer capabilities.

Edge is untrusted and opaque. Browser talks only to our domain. Trading semantics stay inside the private core. No blind transaction retry; every write path is idempotent. A global trading kill switch must disable execution while leaving read-only data available.
## Canonical execution model

TradeIntent includes: id, source, user_id, wallet_ref, chain, token_in, token_out, side, amount_type, amount, order_type, limit_price, max_buy_tax, max_sell_tax, max_price_impact, max_slippage, max_total_cost, allow_partial_fill, expiry, nonce, idempotency_key.

Market order flow: TradeIntent -> policy validation -> tax/risk -> route candidates -> exact local quote -> split optimization -> full simulation -> net score -> immediate state revalidation -> Privy signing -> transaction relay -> chain -> reconciliation/audit.

Pre-sign revalidation checks state freshness, balance, allowance, tax, min-out, selected route, recipient, allowlisted router/program, amount and policy. Any mismatch aborts and requotes.

Separate max_slippage and max_price_impact. Dynamic slippage recommendation may consider volatility, state latency, route uncertainty and confirmation latency but never exceeds a user hard maximum.

Limit orders never trigger merely because chart price crosses a threshold. Market signal only creates a trigger candidate; exact route simulation must confirm the user's net executable limit. Partial fill is required. Find the maximum safe fill amount using monotonic search when the executable condition is monotonic, then keep the remainder active.

Durable order states: CREATED, ACTIVE, TRIGGER_CANDIDATE, QUOTING, SIMULATING, EXECUTING, PARTIALLY_FILLED, FILLED, CANCELLED, EXPIRED, FAILED_RETRYABLE, FAILED_FINAL. Every transition is persisted and validated.

Adaptive TWAP for large orders chooses a safe chunk, executes, observes liquidity recovery/price/volatility, recalculates, then continues; fixed cron timing is fallback only.

Execution identifiers include intent_id, order_id, execution_id and idempotency_key. Retry/recovery must never create a duplicate trade.
## Market state, routing and token safety

Backend maintains local realtime state instead of RPC-polling each user quote. Solana uses Yellowstone/Geyser-compatible feeds for slots, blocks, transactions, accounts and pool updates. EVM uses WebSocket RPC/event subscriptions with optional local Reth. Pool state supports constant-product AMM, concentrated-liquidity/tick pools, and bin/DLMM pools.

Never rank concentrated-liquidity pools by TVL alone. Track active liquidity, exact-size depth, and depth near 10/25/50/100/250 bps, including exact tick/bin traversal.

DEX logic is behind adapters with pool discovery, state update, exact-in/out quote, cost estimate, simulation and swap-building responsibilities. Routing supports direct paths, one/two-hop bridge paths, multi-pool and spatial split routes. Do not brute-force the full token graph.

Split objective maximizes the sum of net output across legs subject to total input conservation and minimum leg thresholds. V1 supports continuous two-path optimization, pairwise extension and at most 3-5 legs. Split only when improvement exceeds configurable min_split_improvement_bps and each leg passes minimum USD/fraction dust thresholds.

Tax/safety is first-class. EVM pre-trade pipeline: static inspection -> transfer simulation -> buy simulation -> sell simulation -> buy/sell round-trip simulation. Detect fee-on-transfer, dynamic tax, sell restrictions, blacklist behavior, max transaction/wallet rules and other abnormal behavior.

Solana safety inspects Token-2022 extensions/authorities including transfer fees/hooks, permanent delegate, freeze/mint authority, default account state and non-transferable behavior. Dynamic/custom program behavior requires exact simulation.

Route score records gross output, simulated net output, tax, DEX/provider fee, gas, price impact, expected slippage, MEV risk, failure probability, state age, source reliability and latency. Primary objective is simulated net output, not gross quote.
## Intelligence providers and reuse

Provider roles: FOMO asks what is becoming interesting; GMGN asks who owns/trades it and how risky it is; Twitter asks why attention is moving and whether catalyst/FUD exists; OKX asks whether an independent market/router source disagrees; local on-chain state answers what can actually execute now and at what true net cost.

Provider Intelligence Broker responsibilities: cache, singleflight/request coalescing, negative cache, stale-while-revalidate, provider-specific TTL, weighted rate/cost budgets, priority queues, cooldown, circuit breakers, provider health/reliability/freshness and candidate/position-aware enrichment.

Progressive enrichment: global market -> local on-chain + fomo-mcp -> cheap preliminary score -> stop weak candidates -> GMGN cheap enrichment -> rescore -> stop weak candidates -> GMGN expensive enrichment -> optional OKX benchmark and paid social confirmation -> actionable candidate -> exact local execution simulation.

fomo-mcp remains read-only and should gradually expose reusable internal gRPC without moving trading into it. Reuse its REST/WS supervision, reconciliation, Timescale journal, dedupe, coverage/cache, hot-token and alpha-radar capabilities. Consumers go through fomo-service; no parallel FOMO poller.

gmgn-mcp remains a read-only intelligence gateway. Preserve its cache, singleflight, weighted global rate gate, conservative normal/probation budgets, cooldown, circuit breaker, stale fallback and no automatic upstream retry. Expensive holder/trader endpoints are candidate-gated.

OKX is selective: independent market/route benchmark, large-order comparison, disagreement detection and fallback reference. It is not the chart feed, limit trigger loop or continuous pool-state source. Record our route vs provider route vs actual execution to discover missing direct adapters statistically.

Paid social intelligence is exposed semantically as a SocialIntelService, cached and budgeted. Priority: active-position risk, high-conviction pre-trade, promising candidate if budget permits; broad discovery is prohibited. Budget exhaustion never disables execution.
## Private web and privacy architecture

Public site and private workspace are separate builds. Public site may be an AI/news/knowledge site and must not contain private trading code. Private workspace is a SolidJS CSR application loaded only after authentication.

Recommended access perimeter: Cloudflare Access + Passkey/WebAuthn + optional workspace unlock secret. Private origin has no public ingress and is reachable through private/tunnel networking.

Edge contains only gateway/auth proxy/encrypted envelope relay/stream relay/opaque storage access/health. It must not host route, tax, order, DEX-adapter or wallet orchestration logic.

Private artifact flow: build private workspace -> encrypt artifact -> store ciphertext -> authenticated browser obtains authorized session material -> downloads ciphertext -> decrypts/instantiates in browser memory. Public edge stores ciphertext only.

Private application transport uses TLS plus application encryption. Session establishment uses HPKE; realtime session uses an audited AEAD such as AES-256-GCM or XChaCha20-Poly1305. External envelope contains only generic key id/nonce/sequence/ciphertext; actual operation type is encrypted.

Use neutral public paths such as /v1/bootstrap, /v1/sync, /v1/stream and /v1/blob. Browser never calls TradingView, DEXScreener, DEX aggregators, crypto RPCs or intelligence providers directly. Chart/OHLCV comes from Market Core over encrypted binary frames and renders locally via Canvas/WebGL using TypedArray/RingBuffer.

Frontend receives initial snapshot + sequenced deltas. Sequence gaps force resync. P0 execution-critical updates are immediate; P1 visual updates may batch around 50-100ms; P2 analytics around 250-1000ms; P3 metadata uses minute-scale TTL. Web Worker handles websocket/decrypt/protobuf/batching/normalization; main thread handles UI and chart.

Session crypto state is memory-only; persistent browser cache, if any, is ciphertext only. Logout destroys session keys, workers, streams and private state where practical. No token/order/amount semantics in URL/title/favicon/OpenGraph. Private CSP defaults to own origin; no third-party analytics/session recording; no public source maps.

Untrusted physical persistence uses generic opaque objects/events/snapshots/streams, encrypted content and blind indexes where lookup is required. Edge logs only request id/status/latency/byte counts/generic error; trading audit events are encrypted immediately. Do not export private token/wallet/order semantics as telemetry labels.
## Wallet, interfaces, reliability and acceptance

Wallet model: Treasury/Main Wallet funds a bounded Privy Trading Wallet. Trading wallet limits are configurable: max trade USD, hourly/daily turnover, max buy/sell tax, max price impact, max slippage, allowed chains, routers and programs. Treasury remains outside automated execution.

Withdrawal is Web-only with strong authentication and explicit confirmation. MCP and Telegram may buy, sell, place/cancel limits, show orders/portfolio/alerts, but may not withdraw, change wallet ownership, raise security limits or access generic signing/transfer operations.

MCP tools may include search_token, get_token, get_chart, get_intelligence, get_quote, preview_market_order, execute_market_order, place_limit_order, cancel_order, get_orders and get_portfolio. Natural-language ambiguity fails closed; never guess whether an amount means USD, stablecoin or token quantity.

Provider outages degrade intelligence only: FOMO unavailable -> cached/local history; GMGN limited -> stale cache/no hammering; OKX unavailable -> skip benchmark; social budget exhausted -> cached snapshot. Exact local execution remains independent.

Circuit breakers halt new execution if local state is stale, simulation is unavailable, tax changes unexpectedly, execution failures spike, signing fails, divergence suggests local corruption, or chain health degrades.

Testing includes unit/property/fuzz tests for AMM/tick/bin math, taxes, fees, price impact, split optimizer, serialization, order transitions and critical invariants; differential tests compare internal quote vs DEX SDK/on-chain simulation/optional aggregator; security/privacy tests cover auth/replay/reordering/tamper/XSS/CSRF/authorization and compromised edge/database/log scenarios.

Critical correctness KPIs: limit violations = 0, duplicate executions = 0, unauthorized signing = 0. Track execution success, freshness/market lag, realized vs estimated slippage/tax/gas, provider quote deviation, cache effectiveness, provider budgets and net execution improvement versus a baseline route.

Performance targets are internal SLOs: private post-auth app load P95 <2s, UI command processing <100ms, visual state update P95 <300ms, intra-region gRPC P95 <20ms, local route optimization P95 <100ms, valid limit-trigger to first submit attempt target P95 <750ms where chain conditions allow.

Definition of done includes private workspace auth/encrypted loading, realtime encrypted chart/state, provider intelligence reuse without duplicate upstream calls, market trade preview with full net economics, Privy execution, net-price limit orders with partial fills, restart recovery, unified MCP/Telegram control, provider outage tolerance, unreadable edge/db/log dumps, no infrastructure-held raw key material, zero duplicate trades under retry tests and zero limit-price violations.
## Repository shape and implementation phases

Recommended workspace: apps/{edge-gateway,private-api,trading-core,market-ingestor,provider-broker,fomo-service,gmgn-service,mcp-server,telegram-bot}; crates/{domain,crypto-envelope,market-types,chain-types,pool-state,routing,tax-engine,risk-engine,simulation,execution,provider-common,fomo-client,gmgn-client,okx-client,social-intel,privy,storage,telemetry}; web/{public,workspace}.

Existing fomo-mcp/gmgn-mcp logic should be extracted/reused gradually rather than copied wholesale. Keep those repositories operational and read-only from the trading execution perspective.

Phase 0 Foundation: workspace, canonical domain contracts, Privy integration boundary, public/private split, passkey/auth skeleton, E2EE envelope, opaque edge, NATS, DB, service identity and kill switch. No live trading until foundation security passes.

Phase 1 Reuse intelligence: integrate fomo-mcp and gmgn-mcp through internal adapters/gRPC and implement Provider Intelligence Broker without duplicate upstream requests.

Phase 2 Market data: Solana feed, EVM feed, local pool state, OHLCV/depth, encrypted chart/state stream.

Phase 3 Market execution MVP: one chain end-to-end first, direct route, tax/safety, exact simulation, Privy signing, transaction relay and encrypted audit.

Phase 4 Advanced routing: multi-hop, multi-pool, split optimization, gas-aware scoring, provider benchmark and additional direct DEX adapters.

Phase 5 Limit engine: limit buy/sell based on executable net price, partial fill, durable state and restart recovery.

Phase 6 Unified MCP + Telegram using the same TradeIntent/Trading Core.

Phase 7 Paid social intelligence behind strict budget/candidate gating.

Phase 8 Adaptive TWAP, solver competition/RFQ/private liquidity and smarter relay abstractions.

Phase 9 Optional advanced privacy such as traffic padding, artifact rotation and confidential compute when justified.

Product motto: Discover intelligently. Verify selectively. Execute locally. Optimize NET. Keep keys out. Keep private state private.
