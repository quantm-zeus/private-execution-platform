# Final semantic correction — Activity > Mine must be read-only activity

Preserve the completed Deep Vault V2 IA and visual design. Fix one semantic flaw found in final review.

Current handoff maps Activity > Mine directly to ExecutionPanel, but ExecutionPanel contains mutating Adaptive TWAP and RFQ/solver forms. That is not activity/history and must not live under a tab named Activity.

## Correct target semantics
- Activity > Token = authoritative FOMO exact-token activity feed.
- Activity > Mine = read-only owner/workspace execution activity/status only.
- Activity is never a place to start a TWAP, request an RFQ, or configure execution.

## Mine subview
Design a compact read-only OwnerExecutionActivityPanel (name may vary) that can render only authoritative information currently available:
- current execution progress / state
- execution lifecycle/status
- filled/remaining amounts
- chunks done/total when applicable
- realized vs estimate when available
- timestamps/source/provenance when available
- compact unavailable/empty state when no authoritative history contract exists.

Do not fabricate historical rows if the backend only has get_execution_progress. A truthful current-status surface is preferable to invented history.

## Mutating TWAP / RFQ controls
Do not render them in Activity.
Target location: Trade Ticket -> Advanced execution, or an explicit Advanced Execution drawer launched from the trade ticket. Keep this as an implementation placement rule; do not redesign the whole ticket.
Execution controls must retain all existing fail-closed, idempotency, UNKNOWN-outcome and TRADING_ENABLED gates.

## Deliverables
Update DESIGN.md, IMPLEMENTATION_HANDOFF.md, evercrest-terminal.html, and critique if needed.
Remove every instruction saying ExecutionPanel itself is the Mine subview.
Replace with a read-only owner activity/status component contract.
Prototype Activity > Mine as read-only status/history state, not a form.
Do not modify application code in this design run.