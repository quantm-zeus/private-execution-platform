# PEP Terminal Deep Vault — information architecture correction V2

This is an owner-approved correction to the completed Deep Vault design. Preserve the visual system, tokens, chart dominance, order-ticket UX, realtime/data-truth invariants and accessibility work. Correct the dock information architecture and prototype/handoff only; do not modify application code in this design run.

## Final bottom-dock IA
Exactly five top-level dock tabs:
1. Positions
2. Open Orders
3. Activity
4. Holders
5. About

Remove the separate Trades tab from the target design. The existing Trades implementation is only a placeholder market-trades capability surface; the richer exact-token activity feed supersedes it. This owner instruction explicitly approves changing the DockTab target union from positions/orders/activity/trades/holders/about to positions/orders/activity/holders/about. Do not preserve a dead placeholder merely because it exists today.

## Activity — one home for event streams
Activity answers: What is happening?

Inside Activity, add a compact two-way scope selector:
- Token
- Mine

### Token scope
Default when an exact token is selected and token-activity capability is available.
Render the authoritative FOMO token activity feed here, not in About.
Support:
- event types Buy / Sell / Transfer In / Transfer Out / Thesis / other provider-supported types
- trader avatar + handle
- USD amount
- execution price
- market cap / FDV when available
- timestamp
- thesis/comment text when applicable
- exact-token identity and provenance
- pagination / Load more with bounded DOM

Secondary filters inside Token scope:
- All
- Buys
- Sells
- Transfers
- Thesis
Optional min-USD control may live behind a compact filter menu.

Initial/reconciliation may come from get_token_activity; exact verified realtime events may prepend without changing the information architecture. Never mix stale events from a prior token.

### Mine scope
Reuse the existing PEP ExecutionPanel semantics for owner/workspace execution activity: TWAP/RFQ/execution progress/history where authoritative.
Do not visually mix Mine rows with Token market rows. Scope selector makes provenance obvious.
When no token is selected, Mine may become the default while Token shows a compact select-a-token state.

Do not create another Trades tab or another transaction feed anywhere else.

## Holders — holders and traders are one concept
Holders answers: Who owns this token and what is their conviction?

Keep one top-level tab named Holders.
The pane is FOMO holder/trader intelligence. Do not add a separate Traders tab.

Suggested internal controls:
- Top holders
- Following / Friends only when backend proves such rows exist
Optional sort:
- Provider order (default)
- Position value
- PnL
- Entry
- Hold time

Each holder/trader row may include:
- avatar, display name, @handle
- verified/clan/followed/dev markers when proven
- position value and token amount
- avg entry vs current price
- unrealized / realized / total PnL
- hold duration
- followers
- thesis/comment + likes
- address as tertiary copyable detail

Thesis belongs with the trader who authored it. Do not duplicate holder theses into About.

## About — token overview only
About answers: What is this token?

Remove Token Activity completely from About.
About contains only relatively stable or aggregate token intelligence:

### Identity & links
- image, name, symbol, chain
- full copyable contract
- launchpad and graduation
- token age/created time when available
- X/Twitter, Website, Telegram, Discord

### Market snapshot
- Price
- 24h change
- Market Cap
- Liquidity
- 24h Volume

### Ownership / supply
- holders
- top 10 holder %
- circulating supply
- total supply

### Flow stats
Compact timeframe selector: 5m / 1h / 4h / 24h.
Show buy count, sell count, buy volume, sell volume, unique buyers, unique sellers, and an honest buy-vs-sell ratio only when denominator is valid.

### Risk / warnings
- provider-truthful warning/allowlist/restricted state
- no invented numeric risk score
- buy/sell tax stays unknown unless a verified provider supplies it

About should fit as a dense overview grid and must not contain pagination, infinite lists, transaction rows or social-feed behavior.

## Prototype behavior
- Update the dock tab strip to exactly Positions / Open Orders / Activity / Holders / About.
- Remove the Trades tab and any market.trades unavailable placeholder from the prototype target.
- Activity must demonstrate both Token and Mine scopes.
- Move the existing token-activity prototype from About into Activity > Token.
- About should become visibly calmer and more scannable after feed removal.
- Holders stays one pane and should visibly combine holder position data with trader identity/thesis.
- Preserve usability at 1366x768, 1440x900, 1920x1080.

## Implementation handoff corrections
Update DESIGN.md, IMPLEMENTATION_HANDOFF.md and evercrest-terminal.html.
Explicitly map:
- DockTab target union -> positions | orders | activity | holders | about
- BottomDock removes Trades and adds About
- ActivityPanel/ActivityWorkspace owns the Token | Mine scope
- TokenActivity component moves out of TokenIntelligencePanel into Activity
- existing ExecutionPanel becomes the Mine subview, not the whole Activity tab by itself
- HolderTradersPanel remains the sole Holders implementation
- TokenIntelligencePanel/About removes all activity query/pagination/filter state
- delete any target requirement for market.trades capability in the dock

Revise tests/handoff expectations accordingly.
Do not modify application code in this design run.