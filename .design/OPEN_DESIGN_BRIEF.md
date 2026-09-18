# PEP / EverCrest Terminal — OpenDesign design brief

Design a professional, data-dense DEX trading terminal for desktop. This is a DESIGN phase first: produce a machine-readable DESIGN.md, prototype/design artifacts, and implementation handoff. Do not modify backend, realtime, crypto, auth, execution, or production code in this pass.

## Product posture
- Professional crypto trading workstation, not SaaS dashboard, not marketing page.
- Visual quality target: modern exchange terminals such as OKX / Hyperliquid / Binance / Kraken / Coinbase Advanced / FOMO as references for hierarchy and density, but do NOT clone any one product or brand.
- Identity: EverCrest / PEP. Dark, precise, calm, high signal-to-noise, premium rather than flashy.
- Full viewport after unlock. Security/auth chrome must disappear from the outer workspace after unlock; Lock/Security remain compact inside the terminal.

## Desktop layout
- Optimize 1366x768, 1440x900, 1920x1080.
- Compact top instrument bar: symbol/name, chain, copyable address, live price, 24h, MCap, Liquidity, Volume, connection/source state. Security and trading-disabled status compact at right.
- Left market rail ~240–280px: Search + Trending + network filters. Rows show symbol/name, price as primary numeric value, optional 24h/rank/MCap; address secondary only.
- Center: KLineChart Pro dominates. Visible volume pane, timeframe, indicators, crosshair, drawing toolbar. Required drawings: ruler/measure, trend line, horizontal/vertical, ray, rectangle, Fibonacci. Avoid controls covering scales.
- Right trade ticket ~320–360px: Market / Limit tabs. User-friendly simple mode: Buy/Sell, amount, unit/presets, primary Review/Get quote action. Route/slippage/price-impact/max-cost under collapsed Advanced. Auto-select only an available route. When trading is disabled, preview remains useful and execution is disabled once, clearly.
- Bottom dock: Positions / Open Orders / Activity / portfolio-related read views. If authoritative capability is unavailable, show a compact honest empty state, not a large backend/debug error.

## Data presentation
- Selected token stats must visibly support Price / 24h / MCap / Liquidity / Volume. Unknown values use an em dash; never invent 0.
- Address is a copy button with feedback.
- Risk uses provider-truthful state such as clear/warning/restricted. Do not invent numeric risk. Buy/sell tax remain unknown unless a verified provider supplies them.
- Trending filter: All + networks actually known/present (Solana, Robinhood, Base, BNB, Ethereum; Monad only when present). Filters must stay compact.
- Search supports name, symbol, address; result rows show chain, compact address, price/MCap when available.

## Visual system
- Create coherent spacing tokens; primary panel content generally 10–16px padding while keeping exchange-grade density.
- Clear typographic hierarchy for token identity, price, secondary statistics, labels.
- Avoid excessive cards, rounded-pill overload, gradients, neon glows, giant empty states, developer/debug prose, or generic AI dashboard styling.
- Borders/separators should define panes more than floating cards.
- Strong hover/focus/active states, accessible contrast and keyboard affordances.
- Use monospaced/tabular numerals where appropriate for prices and financial values, but keep UI labels highly readable.

## OpenDesign workflow required
1. Inspect current repo UI and existing components before designing.
2. Inspect OpenDesign reference systems for Binance, Coinbase, Kraken and Linear only as inspiration; derive an original PEP system.
3. Produce THREE distinct design directions (same information architecture, different visual treatment).
4. Self-critique each direction on hierarchy, density, usability, visual polish, order-entry clarity, chart dominance, and fit for a serious trading terminal.
5. Select one winning direction and explain why.
6. Write a final DESIGN.md with palette/tokens, typography, spacing, pane dimensions, interaction states, component rules, anti-patterns, responsive behavior, and implementation mapping to the current SolidJS components.
7. Produce a high-fidelity prototype/artifact for the winning desktop terminal and a concise IMPLEMENTATION_HANDOFF.md mapping the design onto existing files/components. No backend/business code edits.
