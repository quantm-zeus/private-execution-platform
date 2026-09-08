# Architecture

This repository implements the locked PRD in docs/PRD.md. One canonical Trading Core serves Private Web, MCP and Telegram through structured TradeIntent.

## Boundaries
- Private Core owns authoritative market state, tax/risk, routing, simulation, orders, execution and wallet orchestration.
- Edge is opaque/untrusted and never needs plaintext trading semantics.
- fomo-mcp remains the sole FOMO upstream owner and read-only intelligence service.
- gmgn-mcp remains the read-only GMGN intelligence gateway.
- External intelligence is never execution-critical truth.
- Browser connects only to our domain and renders projections of authoritative backend state.

## Build order
Phase 0 foundation -> provider reuse -> market state -> execution MVP -> advanced routing -> limit engine -> MCP/Telegram -> paid social -> adaptive execution -> optional advanced privacy.
