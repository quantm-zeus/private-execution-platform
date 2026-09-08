# ADR 0002: Phase-0 Policy and Privy Boundary

## Status
Accepted for Phase 0 foundation. Live transaction signing remains unavailable.

## Decision
- `TradingGate` defaults disabled and has no runtime enable method.
- Only trusted startup configuration may construct an initially enabled gate.
- `TradingCore` always calls `PolicyEngine::authorize_trade` first, so the global kill switch wins before prepared-execution or signing checks.
- Policy uses fixed-point `UsdMicros`; no floating-point money is accepted.
- USD-denominated intents must exactly match the trusted backend valuation supplied to policy.
- Non-USD valuation and turnover inputs are explicit trusted-backend facts, not Web/MCP/Telegram request fields.

## Privy boundary
- `PrivySigningBoundary` is a concrete type, not a public implementable signing trait.
- Its production backend is unavailable in Phase 0.
- The public surface accepts only a policy-issued `ApprovedExecution` plus `PreparedExecutionRef`.
- It exposes no generic message/transaction signing, raw calldata, transfer, withdrawal, ownership mutation, or private-key import/export API.
- `ApprovedExecution` fields are private and preserve intent, wallet, chain, idempotency, expiry, valuation, and approval time.
- Prepared references must bind intent id and idempotency key before a backend is touched.

## Residual constraints before live execution
- Turnover is currently supplied as a trusted snapshot. It is not an atomic reservation/accounting mechanism; concurrent live authorizations could otherwise race. Live execution must remain disabled until durable atomic turnover/reservation is integrated.
- `PreparedExecutionRef` is an identifier, not proof of transaction correctness. A future real Privy backend must resolve the reference to a canonical internal prepared execution and revalidate wallet, chain, intent/idempotency binding, approval expiry and execution digest before signing.
- A cloned `ApprovedExecution` is not sufficient to bypass execution safety; durable idempotency/execution state and pre-sign revalidation remain mandatory before Phase 3.
- `TRADING_ENABLED=true` in Phase 0 enables policy authorization only. It does not make live execution available because the Privy backend remains unavailable.
- No blind transaction retry is introduced by this boundary.

## Follow-up
Before enabling real money: add durable turnover reservation, canonical prepared-execution storage/digest binding, Privy integration, signing failure circuit breaker, pre-sign revalidation and reconciliation/idempotency tests.