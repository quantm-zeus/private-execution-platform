# OpenDesign revision — FOMO-style Token Intelligence for PEP Terminal

Revise the already-approved Deep Vault design. Preserve its visual system, layout hierarchy, full-viewport workstation, chart dominance, order-entry simplification, accessibility, no-persistence rule, and all fail-closed invariants. This is an additive product-intelligence revision, not a wholesale redesign.

## Goal
Make the token context feel closer to FOMO without cloning FOMO visuals. PEP should combine professional execution/charting with rich FOMO community/trader intelligence.

## 1. Holders tab becomes FOMO Traders intelligence
The existing Holders dock tab should show FOMO token-holder traders, not a generic wallet table.

Each trader row/card should support, when data exists:
- avatar
- display name + @handle
- verified / clan badge
- position value
- token amount
- average entry price
- current price
- unrealized PnL
- realized PnL
- total PnL
- cost basis
- average hold time
- follower count
- optional dev badge
- thesis/comment authored by that trader for this token
- thesis likes
- concise timestamp/age

Information hierarchy:
- trader identity + position value/PnL first
- thesis immediately readable beneath/alongside
- entry/hold/followers secondary
- wallet address tertiary and copyable, never primary
- positive/negative PnL clearly legible but not neon

Provide compact sorting controls: Position value / PnL / Entry / Hold time. Default should preserve FOMO authoritative order unless product owner explicitly chooses another sort.
Optionally show a small Followed or friend indicator when backend proves it.

Clicking a trader may open an in-terminal quick-view drawer with FOMO profile/metrics/history later; do not navigate browser away in the first implementation.

## 2. Add a new About tab — Token Intelligence
Add About as a first-class dock tab next to Holders.

About should have a dense two-column/section layout:

### Token profile
- token image
- name / symbol
- chain
- copyable full contract
- launchpad + graduation if present
- created/age when available
- social links: X/Twitter, Website, Telegram, Discord
- external links open safely in a new tab with rel=noopener noreferrer
- missing links are omitted, not disabled ghost buttons

### Market stats
- Price
- 24h change
- Market Cap
- Liquidity
- 24h Volume
- Holders
- Top 10 holders %
- circulating supply
- total supply

### Buy / Sell stats
Use compact timeframe switcher: 5m / 1h / 4h / 24h.
For selected timeframe show:
- buy count / sell count
- buy volume / sell volume
- unique buyers / unique sellers
- a compact buy-vs-sell visual ratio; never fabricate percentages when denominator is zero

### Token activity / transactions
A live-style chronological feed using authoritative FOMO token activity:
- Buy / Sell / Transfer in/out / Thesis where applicable
- trader avatar + handle
- USD amount
- execution price
- market cap/FDV when provided
- timestamp
- thesis text when event includes it

Controls:
- All / Buys / Sells / Thesis filter
- optional minimum USD filter
- pagination/load more, not unbounded DOM growth
- newest items may append from the existing PEP realtime stream only when identity/provenance is exact; REST remains the reconciliation source

Visual language:
- dense, professional, readable
- not a social-feed clone
- use the existing Deep Vault tokens and pane chrome
- thesis text gets enough width to be useful
- About must not reduce chart height when its dock is closed
- dock may expand when opened but must preserve desktop usability at 1366x768

## 3. Data truth / unavailable states
Design honest states for:
- FOMO holders unavailable
- FOMO activity unavailable
- token metadata/social links missing
- stats stale
- partial data (e.g. holder exists but no thesis)
Do not expose raw command names or backend errors in primary UI.

## 4. Data contract assumptions already live-verified
FOMO holder payload can provide:
user profile, followers, verified/clan, averageEntryPrice, averageHoldTimeSeconds, costBasis, humanAmount, value, realizedPnl, unrealizedPnl, pnl, thesis/comment, likes.

FOMO token activity can provide:
type (swap_buy/swap_sell/transfer/etc), user identity, usdAmount, price, marketCap, fdv, createdAt.

Exact-address FOMO token search can provide:
name, symbol, image, socialLinks.twitter/website/telegram/discord, launchpad, graduationPercent, priceUSD, change24, marketCap, liquidity, volume24, circulatingSupply, totalSupply.

FOMO token details can provide:
holders, top10HoldersPercent, buy/sell count and volume for 5m/1h/4h/24h, unique buyers/sellers, warnings.

Never join by symbol/name when exact networkId+address is available.

## 5. Deliverables
Update:
- DESIGN.md
- IMPLEMENTATION_HANDOFF.md
- evercrest-terminal.html prototype
- critique document if needed

Add exact component mapping for SolidJS:
- BottomDock new About tab
- Holders/FOMO traders pane
- About/Token Intelligence pane
- lazy queries keyed by exact chain+address
- paginated activity
- stale/loading/error compact states
- safe external-link and copy-address interactions

Do not modify application code in this design run.
