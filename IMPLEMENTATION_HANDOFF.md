# IMPLEMENTATION_HANDOFF — Deep Vault onto the existing SolidJS terminal

> **Maps:** `DESIGN.md` (winning direction *Deep Vault*, with the corrections in
> `design-critique-deep-vault.md`) → the existing components under
> `web/workspace-payload/src/**`.
> **Deliverable of this document:** a design handoff. It changes no code.
> **Hard scope limit:** no backend, realtime, auth, crypto, execution, or
> production application logic is touched. Every item below is appearance,
> information hierarchy, or a self-contained UI affordance (a keyboard handler on
> an existing element). Where a change would require a behavioural edit, it is
> marked **[needs owner sign-off]** and given a default.

---

## 0. Non-negotiables — preserve these exactly

These are existing, hard-won decisions in the codebase. The design changes
appearance and hierarchy only. Each is quoted from the source comment that
declares it.

| # | Invariant | Declared in |
|---|---|---|
| 1 | Named grid areas `"rail work ticket"` — a collapsed rail is `display:none` and auto-placement would otherwise slide the work area into the zero-width column and collapse the chart | `style.css` `.terminal__body` |
| 2 | Both ticket panes stay **mounted** (`hidden`, not unmounted) so a half-entered order, an UNKNOWN submission guard or a preview survives a tab switch | `TradeTicket.tsx` |
| 3 | The ticket tab survives an instrument switch — switching token must never bounce the user back to Market | `workstation.tsx` |
| 4 | Pane / drawer state is memory-only, never persisted | `workstation.tsx` |
| 5 | An unserved timeframe is **refused**, never silently substituted — the chart, the backend realtime target and the Pro period set must all agree exactly | `workstation.tsx` |
| 6 | Exact entity-key isolation: a `ohlcv:default` frame belongs to the neutral chart, never to a selected instrument | `chart-datafeed.ts`, `ChartPanel.tsx` |
| 7 | Chart data is visual / non-authoritative — execution never depends on a chart crossing | `ChartPanel.tsx` |
| 8 | Drawings are local in-memory UI state only; never persisted, and a token change rebuilds the renderer so they cannot leak across token identity | `drawings.ts` |
| 9 | A price tick carries no authoritative volume; volume is reconciled from authoritative OHLCV | `frames.ts` |
| 10 | Fail honest: an unconfirmed submit is UNKNOWN, not failed — and an UNKNOWN outcome is deliberately not cleared | `TradePanel.tsx` |
| 11 | A missing capability must never present an unqueried empty ("no orders") as if it had been loaded | `states.tsx` |
| 12 | An absent or non-finite value stays `null` so the renderer shows `—` and never invents a zero | `contracts/market.ts` |
| 13 | Every one of the five `DockTab` members stays reachable; the design does not delete a pane | `workstation.tsx`, `BottomDock.tsx` |
| 14 | No inline `style=` on any element — the payload CSP is `style-src 'self'` with no `unsafe-inline` | `primitives.tsx` |

---

## 1. What changes, in one table

| Region | File | Nature of the change |
|---|---|---|
| Tokens | `style.css` `:root` (lines 11–96) | Replace with `DESIGN.md` §2; keep the legacy aliases resolving |
| Viewport | `app/AppShell.tsx` | Add the 24 px status-bar row; add the `--pane-bar-h` chart identity bar |
| Top bar | `components/layout/TerminalHeader.tsx` | Restructure to brand → identity → price block → stat strip → status cluster; remove `TokenSearch` |
| Rail | `components/layout/MarketRail.tsx` | Take `TokenSearch`; 32 px two-column rows; chip selection goes neutral |
| Search | `components/layout/TokenSearch.tsx` | Relocate into the rail; restyle |
| Chart | `chart/ChartPanel.tsx` | Two 36 px pane bars; render all seven drawing tools; add the crosshair readout; segmented timeframe |
| Ticket | `components/layout/TradeTicket.tsx` | Tab strip restyle + APG keyboard |
| Ticket body | `features/trade/TradePanel.tsx`, `features/limits/LimitsPanel.tsx` | Restyle only — no logic change |
| Dock | `components/layout/BottomDock.tsx` | 34 px tab strip; `—` counts; APG keyboard; 44 px compact unavailable row |
| Primitives | `components/ui/primitives.tsx`, `states.tsx` | Badge tint 12%→8%; `CompactNote` becomes the 44 px row |
| Drawer | `components/layout/SecurityDrawer.tsx` | Restyle only |
| Formatters | `core/format.ts` | **No change** — already em-dash-safe |

---

## 2. Token migration — `web/workspace-payload/src/style.css` lines 11–96

Replace the whole `:root` block with `DESIGN.md` §2 verbatim. The artifact
`evercrest-terminal.html` and `DESIGN.md` §2 are verified to hold **exactly the
same 76 tokens**; treat either as the source of truth.

### 2.1 Three defects in the current build that this design fixes

These are not cosmetic retunes. They are measured failures in the shipped token
set, and they are the strongest reason to land this pass.

| Defect | Current value | Measured | Fixed by |
|---|---|---|---|
| The Sell button label fails 4.5:1 | `--sell: #e5484d` used as a **fill** with a white label | **3.91:1** | Split into `--sell: #ea5a5f` (text) + `--sell-fill: #c9302f` (fill) → white label **5.32:1** |
| Down-change text fails 4.5:1 on raised surfaces | `--sell: #e5484d` as text | 4.48:1 on `--surface-2`, **4.11:1** on `--surface-3` | `--sell: #ea5a5f` → 5.11:1 / 4.69:1 |
| Interactive boundaries are ~1.2:1, far below the 3:1 non-text floor | `--line: #243440` used as a control border | **1.20:1** on `--surface-3` | New `--control-border: #5b7288` → 3.74 / 3.51 / **3.22**:1 |

The third one is the important structural fix: the current build has no token for
"the boundary of an interactive control". `--line` is a *pane chrome* token, and
using it on inputs and buttons is why every control edge disappears. `--line`
stays for pane edges; `--control-border` takes every interactive boundary.

### 2.2 Value migration

| Current token | New | Note |
|---|---|---|
| `--terminal-bg: #0a0f14` | `--surface-0: #080c11` | deeper, cooler |
| `--surface-1: #0e151c` | `--surface-1: #0d131a` | |
| `--surface-2: #131c24` | `--surface-2: #121a23` | |
| `--surface-3: #1a2630` | `--surface-3: #18222d` | |
| `--line: #243440` | `--line: #1e2a36` | pane edges only |
| `--line-strong: #33485a` | `--line-strong: #2c3d4d` | emphasised separators |
| — | `--line-faint: #151d26` | **new** — intra-pane rules, chart gridlines |
| — | `--control-border: #5b7288` | **new** — every interactive boundary |
| `--text-1: #eef4f2` | `--text-1: #e8eef2` | |
| `--text-2: #a6b7b4` | `--text-2: #9fb0bd` | |
| `--text-3: #7e918e` | `--text-3: #7a8d9b` | the floor: 4.68:1 on `--surface-3` |
| `--accent: #e9b44c` | unchanged | but its **role** is cut to two uses (§6 of `DESIGN.md`) |
| `--accent-muted: #3a2e15` | `--accent-soft` (`color-mix`) | no longer a hover/wash token |
| `--buy: #2fbf8f` | unchanged | add `--buy-fill`, `--buy-ink`, `--buy-hover` |
| `--sell: #e5484d` | `--sell: #ea5a5f` + `--sell-fill: #c9302f` | **split** — see §2.1 |
| `--warning: #e5b94a` | `--warn: #e5b94a` | renamed |
| `--info: #5b9dff`, `--focus: #7fb2ff` | unchanged | |
| — | `--risk-clear/warning/restricted/unknown` | **new** — the provider's word, never a score |
| `--space-1…8` | unchanged | |
| `--radius-dense: 4px` | `--radius-sm: 4px` | |
| `--radius-menu: 6px` | `--radius-md: 6px` | |
| `--radius-modal: 8px` | `--radius-lg: 8px` | |
| — | `--radius-xs: 2px`, `--radius-pill: 9999px` | **new** |
| `--control-dense: 28px` | `--control-sm: 28px` | |
| `--control-standard: 34px` | `--control-md: 34px` | |
| — | `--control-xs: 24px`, `--control-lg: 44px` | **new** — AA floor and primary action |
| `--row-h: 32px` | unchanged | add `--row-h-tall: 44px` |
| `--pad-panel: 14px`, `--pad-panel-dense: 12px` | `--space-3` / `--space-4` | the 4 px ladder is the padding contract now |
| `--topbar-h: 52px` | `--topbar-h: 56px` | **+4 px** — the 28 px price block needs it |
| `--rail-w: 264px` | `280px` base, stepped down by media query | see `DESIGN.md` §8 |
| `--ticket-w: 352px` | unchanged as the base | |
| `--dock-h: 216px` | unchanged as the base | |
| — | `--pane-bar-h: 36px`, `--statusbar-h: 24px` | **new** |
| — | `--elev-flat/ring/raised`, `--focus-ring` | **new** — the current build has no elevation or focus-ring token |
| — | `--motion-fast/base/flash`, `--ease-standard` | **new** — the current build has no motion token |

### 2.3 Legacy aliases must keep resolving

`style.css` defines twelve compatibility aliases that no rule in the file
currently reads: `--bg`, `--bg-elev`, `--bg-elev-2`, `--bg-elev-3`, `--border`,
`--border-strong`, `--text`, `--muted`, `--faint`, `--accent-dim`, `--positive`,
`--danger`. **Keep all twelve**, re-pointed at the new tokens, exactly as
`DESIGN.md` §2 does not spell out but §11 requires. Also keep
`--radius-dense`, `--radius-menu`, `--radius-modal`, `--radius`, `--radius-sm`,
`--control-dense`, `--control-standard`, `--pad-panel`, `--pad-panel-dense`,
`--pad-row`, `--gap`, `--terminal-bg` as aliases — the twelve unused ones suggest
something outside this file may still resolve them, and an alias costs one line
while a missing token costs a silent fallback.

The three in-place token overrides stay where they are and keep working:
`--rail-w: 0px` at `.terminal[data-rail="collapsed"]` (line 801), `--rail-w: 0px`
inside `@media (max-width: 1180px)` (line 2083), and `--ticket-w: 0px` inside
`@media (max-width: 980px)` (line 2108).

---

## 3. Two shared primitives to add

### 3.1 APG tablist keyboard navigation

**Problem.** `TradeTicket.tsx` and `BottomDock.tsx` both declare
`role="tablist"` + `role="tab"` + `aria-selected` + `aria-controls`, and both
panels are correctly `role="tabpanel"`. What is missing is the rest of the ARIA
APG tabs pattern: Left/Right/Home/End movement. Declaring the roles promises a
keyboard interaction that does not exist, which is worse than not declaring them.

**Add** one small hook in `components/ui/primitives.tsx` (or a new
`components/ui/tablist.ts`), taking a ref to the tablist root and a selector:

```
wireTablist(root, selector):
  tabs = root.querySelectorAll(selector)
  on keydown:  ArrowRight/ArrowDown → next (wrapping)
               ArrowLeft/ArrowUp    → previous (wrapping)
               Home → first, End → last
               preventDefault, focus the target, then click it (automatic activation)
  on click (bubbled from the tab, so aria-selected is already updated): sync roving tabindex
  sync() once on mount
```

Roving `tabindex` means exactly one stop in the tab order per tablist. Apply it to
`station.ticketTab()` and `station.dockTab()` as the initial selected tab.

**Do not** change `station.setTicketTab` / `station.setDockTab` — the hook calls
`click()` on the existing button, so the existing handlers run unchanged. This is
the whole reason to implement it as a click rather than a store call.

### 3.2 The status bar region

**Add** a new region to `AppShell.tsx`, as the third row of the `.terminal` grid
(`grid-template-rows: var(--topbar-h) minmax(0,1fr) var(--statusbar-h)`):

```jsx
<footer class="statusbar" aria-label="Terminal status">
  <span class="statusbar__item"><span class="statusbar__key">DATA</span>
    <span class="statusbar__val">{station.marketSource() ?? "—"}</span></span>
  <span class="statusbar__item"><span class="statusbar__key">SNAPSHOT</span>
    <span class="statusbar__val">{formatAge(...)}</span></span>
  <span class="statusbar__item"><span class="statusbar__key">FEED</span>
    <span class="statusbar__val">{ws.connection().phase}</span></span>
  <span class="statusbar__item statusbar__item--grow"><span class="statusbar__key">EXECUTION</span>
    <span class="statusbar__val">{ws.tradingEnabled() ? "enabled" : "fail-closed"}</span></span>
  <span class="statusbar__item statusbar__spacer">
    <span class="statusbar__val">{formatClock(ws.clockMs())}</span></span>
</footer>
```

Rules:
- It is **additive**. Nothing is removed from the top bar or the dock by this
  change — the three badges in `.topbar__status` stay, because they are the
  glanceable signal. The status bar is the persistent provenance line.
- Keys are hard-coded ALL-CAPS, so `.statusbar__key` **must** carry
  `letter-spacing: var(--tracking-label)`. That is `DESIGN.md` §3's no-exceptions
  rule and it is the single most common typographic omission in the current build.
- Do not move `capabilityDenial` prose here. Capability reasons belong where the
  surface is (§5.5 of `DESIGN.md`), not in a global footer.
- The existing `.offline-banner` in `AppShell` stays. It is a transient alert; the
  status bar is steady-state. **[needs owner sign-off]** if you would rather fold
  the banner's reason string into the status bar and drop the banner — default is
  to keep both.

---

## 4. File-by-file mapping

### 4.1 `web/workspace-payload/src/style.css` (2 446 lines)

Keep every existing selector. This is a **restyle**, not a rename: the class names
are the contract with the test suite, and a rename would break tests for no design
gain. The full prototype-class → repo-class map is in §5.

Additions to the sheet:
- The `.terminal` grid gains the third row (§3.2).
- `.statusbar`, `.statusbar__item`, `.statusbar__item--grow`, `.statusbar__key`,
  `.statusbar__val`, `.statusbar__spacer` — new, from the prototype.
- `--pane-bar-h` on the chart's two bars.
- The **selection is neutral** rules from `DESIGN.md` §6/§7. In practice this
  means auditing the sheet for every `var(--accent)` used as a selection,
  hover, chip, tab, or icon state and replacing it with the `--surface-3` +
  `--text-1/--text-2` pattern. Grep `var(--accent` in the sheet and classify each
  hit as *brand mark / instrument rule* (keep) or *anything else* (replace).
- `:focus-visible { box-shadow: var(--focus-ring) }` — one global rule, replacing
  whatever focus handling exists today. `--focus-ring` is
  `0 0 0 2px var(--surface-1), 0 0 0 4px var(--focus)`: a 2 px surface-coloured
  spacer plus a 2 px visible ring, so the ring is legible on every surface and
  meets WCAG 2.4.13's 2 px perimeter. **Never** `outline: none` without it.
- `@media (prefers-reduced-motion: reduce)` zeroing the three motion tokens.

### 4.2 `app/AppShell.tsx` (113 lines)

| Change | Detail |
|---|---|
| Add the status-bar row | §3.2 |
| Chart identity bar | The existing `.chart-pane__bar` (`.chart-pane__identity` + `TokenRiskStrip`) becomes **chart pane bar 1** at `--pane-bar-h: 36px`. Keep `TokenRiskStrip` — it is the risk surface and `DESIGN.md` §5.3 places the risk badge in bar 1. |
| Risk values | `TokenRiskStrip` renders `risk {score}`, `buy tax`, `sell tax`. `DESIGN.md` §9 forbids an invented numeric risk score. The existing code already renders `—` for a null score, which is correct; keep it, and drop the numeric score from the badge in favour of the provider's **level** word (`clear` / `warning` / `restricted` / `unknown`) if `RiskAssessment.level` is present. **[needs owner sign-off]** — default is to keep the current score-plus-dashes rendering and only restyle it, because changing it touches how risk is communicated. |
| Keep | `.skip-link`, `.offline-banner`, the `Show` wrappers, the named grid areas |

### 4.3 `components/layout/TerminalHeader.tsx` (226 lines)

Target order, left → right, one row, `overflow: hidden`:

1. **Brand** — a 6 px amber square + wordmark at 13 px/600. The square is one of
   the **two** permitted amber uses in the whole product. The current `◈` glyph
   in `.topbar__mark` is replaced by the square; the `h1.topbar__title`
   ("Evergreen Private Workspace") is replaced by the wordmark, and `h1` moves to
   the instrument symbol (§4.9 accessibility note).
2. **Divider** — 1 px `--line`, 20 px tall.
3. **Instrument identity** — `topbar__symbol` (mono 12 px UPPER, `--tracking-label`)
   over `chain · truncated-address`. `AddressCopy` stays exactly as it is — it
   already copies the full address verbatim and degrades to a no-op without a
   clipboard, which is the correct behaviour and must not change.
4. **Instrument price block** — the flourish. 2 px amber rule, then `PRICE` label,
   28 px mono price, 14 px change. This is the **second** permitted amber use.
   `data-testid="token-stat-price"` and `token-stat-change` must survive on the
   price and change values.
5. **Stat strip** — `.stat` elements become the prototype's `.statstrip__item`:
   10 px UPPER label over 13 px mono value. **Replace the existing
   `stat--optional` class with the design's explicit fold markers**
   `data-fold="1"` (Liquidity, Volume 24h — hidden ≤1439 px) and `data-fold="2"`
   (24h range — hidden ≤1279 px). Mcap always stays. An explicit ordinal is used
   rather than "optional/tertiary" because the fold *order* is the contract and a
   name like "optional" cannot express it. `data-testid="token-stat-marketcap" |
   "token-stat-liquidity" | "token-stat-volume"` all stay.
6. **Right cluster** — `market-source`, `connection-phase` (with `StatusDot`),
   `trading-gate`, optional `kill-switch` / `degraded`, the ticket toggle (when
   `station.narrow()`), the security button, and Lock. All four `data-testid`s
   stay. Cap at four badges.
7. **Remove `TokenSearch` from the bar** and mount it in the rail (§4.4).

Icon substitution: the shell uses the Unicode glyphs `▤ ◈ ⚙ ⇄` as icons. Replace
them with 1.5 px-stroke monoline SVG on `currentColor`. `DESIGN.md` §9 permits a
mono glyph only where the repo already uses one, and the shell chrome is not that
case — `▤` and `⇄` in particular are not legible as "rail" and "ticket" without
the tooltip. `MarketRail`'s `↻` and `‹` are inside the pattern the rule allows;
leave them.

### 4.4 `components/layout/MarketRail.tsx` (306 lines)

Vertical order becomes **Search → Network filter → list**, per `DESIGN.md` §5.2.

| Change | Detail |
|---|---|
| Mount `TokenSearch` | At the top of `.market-rail`, under `.market-rail__head`. It already owns its own combobox semantics (`role="combobox"`, `aria-controls`, `aria-activedescendant`, `role="listbox"`, `role="option"`) — **do not touch its query semantics** (300 ms debounce, blank queries never dispatched, the encrypted `search_token` op). Only move it and restyle. |
| Search results take over | While `station.query()` is non-empty, the Watchlist / Recent / Trending sections collapse and the results list is the rail. Add a `N results` section head. `DESIGN.md` §5.2 requires the swap to be *marked*, not silent. |
| Keep Watchlist and Recent | They are real surfaces (`station.watchlist()`, `station.recent()`) and the brief does not ask for them to go. They render below Trending when the query is empty and both are non-empty. |
| Row geometry | `.market-item` → 32 px tall, two columns: symbol (14/600 `--text-1`) over name (12 `--text-3`); price (13 mono `--text-1`, right-aligned) over 24h change. The address is **never** a column — it already lives in the `title` attribute, which is correct; keep it. |
| Row states | Keep `aria-pressed` on the row button. Selected = `--surface-3` fill + 2 px `--text-2` left marker (was `--accent`). Hover = `--surface-2`, text unchanged. |
| Chip selection goes neutral | `.chain-filter__chip[aria-pressed="true"]` becomes `--surface-3` + `--text-1` + a `--text-2` boundary. Chips go to 24 px tall with a `--control-border` default boundary. |
| Preserve | The honest-count filter and the fall-back-to-`All` behaviour. `DESIGN.md` §5.2 restates this rule and the code already implements it — do not regress it. |

### 4.5 `components/layout/TokenSearch.tsx` (177 lines)

Relocate and restyle only. Its combobox wiring, ids (`global-token-search`,
`token-search-listbox`, `token-option-N`), `data-testid`s
(`search-result-price|change|mcap|liquidity|volume`), and its 300 ms debounce all
stay. The popover becomes the search results list *inside* the rail rather than a
floating overlay, so `--elev-raised` is not needed there.

### 4.6 `components/layout/TradeTicket.tsx` (75 lines)

- `.trade-ticket__tabs` → 36 px, `--surface-2`, active tab takes a `--surface-1`
  fill plus a 2 px `--text-1` underline (was `--accent`).
- Apply the §3.1 keyboard hook to the tablist.
- Keep both panes mounted and keep `hidden` + `aria-hidden` in lockstep — the
  current code sets both, which is correct and must not be "simplified".
- Keep the `trade-ticket__empty` fallback (`EmptyBlock`) for no-target.
- Keep `data-testid="ticket-tab-market" | "ticket-tab-limit"` and
  `data-testid="trade-ticket"`.

### 4.7 `components/layout/BottomDock.tsx` (71 lines)

- Tab strip → 34 px on `--surface-2`, active tab `--surface-1` + 2 px `--text-1`.
- **The tab set becomes exactly five, and `trades` is removed** (V2 correction,
  owner-approved):

  ```ts
  export type DockTab = "positions" | "orders" | "activity" | "holders" | "about";
  ```

  Delete the `{ id: "trades", label: "Trades" }` entry from `DOCK_TABS` **and** the
  `<Show when={station.dockTab() === "trades"}>` block that renders its
  `CompactNote` — including its `capability="market.trades"` string. The brief is
  explicit: *do not preserve a dead placeholder merely because it exists today.*
  There is **no target requirement for a `market.trades` capability anywhere in
  the dock.**
- **`RealtimeChannel` in `realtime/types.ts` also has a `"trades"` member. Do not
  touch it.** That is a transport channel, not a dock tab, and it is a different
  namespace with a coincidentally identical word.
- Add `{ id: "about", label: "About" }` after `holders`, with **no count slot** —
  it has no natural count and a permanent `—` would read as a loading state.
- `holders` stops rendering its `CompactNote` and renders `HolderTradersPanel`
  instead (§12). `activity` stops rendering `ExecutionPanel` and renders
  `ActivityWorkspace` instead (§11.2), whose Mine subview is the **read-only**
  `OwnerExecutionActivityPanel` (§11.4). `ExecutionPanel` itself moves out of the
  dock entirely, to the trade ticket's Advanced execution area (§11.5).
- Add a count slot per remaining tab rendering `—`. Never `0`. The one real count
  is Holders' trader count, which is `—` when the read is unavailable.
- Apply the §3.1 keyboard hook, and keep the expand control a **sibling** of the
  tablist rather than a child.
- Keep `data-testid="bottom-dock"` and `dock-tab-${id}` for the surviving tabs.

### 4.8 `components/layout/SecurityDrawer.tsx` (69 lines)

Restyle only. It is already correct in every way that matters: `role="dialog"`,
`aria-modal`, `aria-label`, `tabindex="-1"`, Esc closes, focus moves in, and it is
outside the normal unlocked chrome. Do not move it into the top bar. The design
brief requires that security/auth chrome disappear from the outer workspace after
unlock and that Lock/Security stay compact inside the terminal — which is exactly
what the current structure does.

### 4.9 `chart/ChartPanel.tsx` (446 lines)

This is the largest structural change. Target: **two `--pane-bar-h: 36px` rows,
then the plot. Nothing overlays the plot or either scale.**

**Bar 1 — identity & readout.** Merge the current `.chart-panel__head`'s
`.chart-target` badges into `AppShell`'s `.chart-pane__bar`, and add the
**crosshair OHLC readout** on the right: `O · H · L · C · Δ · Vol` in mono 12 px.
It lives in the bar, not floating over the candles, so it can never cover a scale
or a wick — this is a hard requirement of `DESIGN.md` §5.3. Wire it to the Pro
chart's crosshair event (the panel already captures the chart instance via
`captureKlineChart`). Keep `data-testid="chart-target"` and its
`data-candles` attribute.

**Bar 2 — toolbar.** Drawing tools | divider | timeframe segmented control |
divider | indicator toggle + hint.

| Item | Change |
|---|---|
| Drawing tools | **`const drawingTools = DRAWING_TOOLS.filter((tool) => tool.id === "ruler")` (line 149) must lose the filter.** `DRAWING_TOOLS` already defines all seven the design requires — `ruler, trend, horizontal, vertical, ray, rectangle, fibonacci` — and only the ruler is rendered today. Rendering all seven is the single highest-value change in this file. Keep `data-testid={`draw-tool-${tool.id}`}` so `draw-tool-ruler` continues to satisfy the existing test. |
| Clear-all confirmation | Already implemented and already requires a second click (`draw-clear-all` → `draw-clear-confirm` / `draw-clear-cancel`). Keep the three `data-testid`s exactly. |
| Timeframe | Today a `<select id="chart-timeframe">`. The design wants a segmented control of `PRO_PERIODS` (`1m 5m 15m 1h 4h 1d`) with unserved windows rendered **disabled with a reason**, never hidden and never substituted. A `<select>` can do this via `<option disabled>`, so **[needs owner sign-off]** on which to build. Default: build the segmented control (a `role="group"` of `<button aria-pressed>`), because the design's whole point is that all served windows are visible at once — and keep `id="chart-timeframe"` and `aria-label="Chart timeframe"` on the group so nothing that queries it breaks. The gate stays `SERVED_TIMEFRAME_IDS` / `servedTimeframes`; do not widen it. |
| Indicator toggle | New: a 28 px `--control-sm` two-state toggle for MA7/MA25, `aria-pressed`, marked with a `--control-border` inset rule — deliberately quieter than the timeframe, because it is a switch, not a selection among alternatives. |
| Hint as the shrink point | The "wheel to zoom · drag to pan" hint is a bar element with `flex: 0 1 auto; min-width: 0; text-overflow: ellipsis`. It truncates before it can push a tool out. It is **never** an overlay. |
| Drawing colours | An armed tool and a selected drawing use `--text-1`, never `--accent`. |
| Keyboard | `.chart-panel` already has `onKeyDown`. Keep Escape-cancels and Delete-removes. |
| `pep-pro-chart-host` | Keep `role="group"` and the exact `aria-label` shape (`Price chart for ${symbol}, ${timeframe} timeframe`). The existing test asserts `getByRole("group", { name: /price chart/i })`. Extend the label to include the last close, per `DESIGN.md` §10, but keep the "Price chart" prefix. |
| `normalizePositiveTabindex` | Keep calling it — Pro 0.1.1 hardcodes `tabindex="1"` on its crosshair layer, which fails the axe `tabindex` rule. |

**Depth of book — an open decision this design does not silently resolve.**
`.depth-columns` is a real surface (bids/asks, `tabindex="0"`,
`aria-label="Depth of book"`, two `EmptyBlock`s reading "No depth") that the
design's layout spec never places, and two existing tests assert on it.

- **Default (recommended):** keep it in the chart pane, below the plot, constrained
  to `max-height: 96px` with internal scroll, on `--surface-1` behind a top
  hairline, as a compact two-column strip.
- **Consequence to accept:** the chart plot heights in `DESIGN.md` §4 become
  **652 / 484 / 344 px** at 1080 / 900 / 768 instead of 748 / 580 / 440. All three
  still clear the design's 320 px floor.
- **Alternative:** move depth into the dock as a sixth tab. That requires a new
  member on the `DockTab` union in `state/workstation.tsx` — a behavioural edit,
  so it is **out of scope for this pass** and listed in §9.

### 4.10 `features/trade/TradePanel.tsx` (1 296 lines)

**Restyle only. No logic change.** The panel's behaviour is already correct and is
the most safety-critical code in the product.

| Design element | Existing class | Change |
|---|---|---|
| Side control | `.ticket__side`, `.chip-button--buy`, `.chip-button--sell` | 34 px two-segment control. Active segment filled with `--buy-fill` / `--sell-fill`; inactive is a transparent ghost. **Never both filled.** Keep `role="group" aria-label="Side"` and `aria-pressed`. |
| Amount | `.ticket__amount-row`, `.input`, `.input.ticket__unit` | 44 px row, 16 px mono right-aligned input, `--surface-2` fill, `--control-border`. Keep `aria-label="Amount"` / `"Amount unit"`. |
| Presets | `.preset-row`, `.preset-chip` | One row of 28 px chips. Keep `data-testid="amount-preset-${preset}"`. The design's `MAX` chip is visually distinct by a heavier **boundary**, not by the accent. **Note:** the current presets are `25 / 50 / 100 / 250`; the design's prototype shows `25% 50% 75% MAX`. Do **not** change the preset values — they are product semantics. Restyle the existing four. |
| Receive | (rendered via `KeyValue` / economics rows) | `You receive (est.)` with a 16 px mono value; unknown ⇒ `—`. |
| Route | `.route-list`, `.route-list__item`, `preview-route-source` | Keep the auto-selected available route and keep `data-testid="preview-route-source"`. Never hide an unavailable route — list it disabled with its reason. |
| Advanced | `.ticket__advanced` (`<details>`) | Collapsed by default. `--text-2` collapsed → `--text-1` open; chevron rotates over `--motion-base`. Keep `data-testid="ticket-advanced"`. |
| Primary action | `.ticket__actions--primary`, `.btn--primary` | **Exactly one** primary-styled button in the ticket at a time. 44 px, full width, filled with the active side's colour. When trading is disabled it is disabled and a single 12 px inline reason sits directly above it — one place, one sentence. Keep `data-testid="execution-disabled"` and `"new-order-blocked"`. |
| Provenance | `.state-block__meta`, `FreshnessBadge`, `StaleRibbon` | Keep. The design adds a 12 px `--text-3` provenance line naming the quote source and its age, present whether or not the quote succeeded. |
| UNKNOWN guard | `.state-block--error` with `role="alert"` | Keep the `role="alert"` block and the out-of-band verification checkbox untouched. |

### 4.11 `features/limits/LimitsPanel.tsx` (816 lines)

Restyle only. It shares `.ticket__*`, `.chip-button*`, `.preset-*`, `.key-value`,
`.btn--primary` with `TradePanel`, so most of the work lands there. Keep every
`id` (`limit-net-price`, `limit-amount`, `limit-amount-type`, `limit-expiry`,
`limit-max-*`), every `aria-label`, every `data-testid`
(`limit-target`, `limit-advanced`, `limit-execution-disabled`, `limit-unknown`,
`order-filled`, `order-remaining`), and the `data-state` / `data-order-id`
attributes on `.order-card`. The order list gets the 32 px `--row-h` row rhythm.

### 4.12 `components/ui/primitives.tsx` (149 lines) and `states.tsx` (201 lines)

| Component | Change |
|---|---|
| `Badge` | Tint **8%**, not 12%. At 12% the danger badge's own 10 px text measures 4.47:1 against its tint over `--surface-2` — a fail that the artifact only escaped by placement. Keep the `Tone` union unchanged (six members). |
| `StatusDot` | Keep. Add the `--surface-3` halo so it reads on every surface. |
| `ActionButton` | Keep the three tones. `btn--primary` adopts the side colour in the ticket; it is **not** amber. |
| `Field` | Keep `field__label` (a real `<label for>`), `field__hint`, and `field__error` with `role="alert"`. Placeholder-as-label is forbidden by `DESIGN.md` §10 and the current code is already correct. |
| `KeyValue` | Restyle to the 32 px row rhythm; keep `data-key`. |
| `Panel` | Keep `aria-label={title}`. `panel__title` is an `h2` — keep the level. |
| `Metric` / `MetricGrid` | Keep. `MetricGrid`'s `data-columns` attribute is deliberate (the CSP blocks inline `style=`); do not "simplify" it to a style prop. |
| `CompactNote` | Becomes the design's **44 px compact unavailable row**: a muted `UNAVAILABLE` badge, the surface name, one sentence of product prose, and a `<details>` disclosure carrying the capability key. Keep `role="status"` and `compact-note__key`. The key never dominates the row. |
| `UnavailableBlock` / `EmptyBlock` | Keep the distinction. "Empty" and "unavailable" are different states and must keep saying so differently. |
| `ReasonNote`, `LoadingBlock`, `ErrorBlock`, `StaleRibbon`, `FreshnessBadge`, `AsyncSurface`, `DenialNote` | Restyle only. `AsyncSurface`'s `data-stale` attribute stays. |
| `AddressCopy` | Unchanged. Full-address copy, verbatim, no-op on a missing clipboard. |

---

## 5. Prototype class → repo class map

The prototype in `evercrest-terminal.html` uses shorter names than the app. Map
by role; **do not rename the app's classes.**

| Prototype | Repo | Role |
|---|---|---|
| `.terminal` | `.terminal.workspace` | viewport grid |
| `.topbar`, `.topbar__brand`, `.mark`, `.wordmark` | `.topbar`, `.topbar__lead`, `.topbar__mark`, `.topbar__title` | top bar |
| `.instrument`, `.instrument__symbol`, `.instrument__meta` | `.topbar__identity`, `.topbar__symbol`, `.topbar__ref` | instrument identity |
| `.addr` | `.address-copy` | address copy button |
| `.priceblock`, `.priceblock__rule`, `.priceblock__price`, `.priceblock__chg` | `.stat--price`, `.stat__label`, `.stat__value` | instrument price block |
| `.statstrip`, `.statstrip__item`, `.statstrip__value` | `.topbar__stats`, `.stat` (`.stat--optional`), `.stat__value` | stat strip |
| `.badge`, `.badge--*` | `.badge`, `.badge--*` | badges (tint 8%) |
| `.btn`, `.btn--sm` | `.btn`, `.btn--ghost\|primary\|danger` | buttons |
| `.iconbtn` | `.icon-button` | icon buttons (24 px) |
| `.input` | `.input` | inputs |
| `.rail` | `.market-rail` | left rail |
| `.rail__search`, `.rail__kbd` | `.token-search`, `.token-search__input` | search |
| `.chainfilter`, `.chip`, `.chip__count` | `.chain-filter`, `.chain-filter__chip`, `.chain-filter__count` | network filter |
| `.mrow`, `.mrow__id`, `.mrow__sym`, `.mrow__name`, `.mrow__val`, `.mrow__price`, `.mrow__chg` | `.market-item`, `.market-item__id`, `.market-item__symbol`, `.market-item__name`, `.market-item__value`, `.market-item__price`, `.market-item__sub--up\|down\|muted` | market row |
| `.chartpane`, `.chartpane__id`, `.chartpane__sym`, `.chartpane__legend` | `.chart-pane`, `.chart-pane__identity`, `.chart-pane__symbol`, *(new readout)* | chart bar 1 |
| `.panebar`, `.toolgroup`, `.seg`, `.seg__btn` | `.chart-panel__head`, `.chart-toolbar`, `.chart-draw-tools`, `.chart-tool`, *(new seg)* | chart bar 2 |
| `.chartpane__plot`, `#plot` | `.chart-frame`, `.pep-pro-chart-host` | the plot |
| `.tabs`, `.tab`, `.tabs__count` | `.trade-ticket__tabs`, `.trade-ticket__tab`, `.dock__tab` | tab strips |
| `.side`, `.side__btn` | `.ticket__side`, `.chip-button--buy\|sell` | side control |
| `.amountrow`, `.amountrow__input`, `.unitbtn` | `.ticket__amount-row`, `.input`, `.input.ticket__unit` | amount |
| `.presets`, `.preset` | `.preset-row`, `.preset-chip` | presets |
| `.receive`, `.receive__val` | *(economics rows / `KeyValue`)* | estimated receive |
| `.kv`, `.kv__row` | `.key-value`, `.key-value__row` | key/value rows |
| `.adv`, `.adv__body`, `.adv__chev` | `.ticket__advanced`, `.ticket__advanced-body` | advanced disclosure |
| `.cta`, `.cta__btn`, `.cta__reason` | `.ticket__actions--primary`, `.btn--primary`, `.reason-note` | primary action |
| `.prov` | `.state-block__meta` | provenance line |
| `.dock`, `.dock__tabs`, `.dock__body` | `.dock`, `.dock__tabs`, `.dock__body` | bottom dock |
| `.unavail` | `.compact-note` | compact unavailable row |
| `.statusbar`, `.statusbar__key`, `.statusbar__val` | *(new)* | status bar |

---

## 6. Test impact

| Test file | Expected impact |
|---|---|
| `components/layout/TokenSearch.test.tsx` | **None** if the combobox wiring, ids and `data-testid`s are preserved while moving the component. |
| `features/terminal/TerminalPanel.test.tsx` | Asserts `AWAITING FEED`, ≥2 "No depth", and `getByRole("group", { name: /price chart/i })`. All three survive if the `aria-label` keeps its "Price chart" prefix and the depth `EmptyBlock`s are kept (see §4.9's open decision — this is the test that makes "delete the depth pane" not an option). |
| `features/trade/TradePanel.test.tsx` (1 711 lines) | **None** — restyle only. Every `data-testid`, `aria-label` and `role` is preserved. Watch the preset testids: the values stay `25/50/100/250`. |
| `features/limits/LimitsPanel.test.tsx` (579 lines) | **None** — restyle only. Every `id` and `data-testid` is preserved. |
| `chart/chart-realtime-selection.test.tsx` | **None** — entity-key isolation is untouched. |
| `chart/drawings.test.ts`, `frames.test.ts`, `history.test.ts`, `pro/*` | **None** — no logic in those modules changes. |
| `chart/*` rendering assertions | **Watch.** Removing the `.filter(tool => tool.id === "ruler")` adds six buttons to the toolbar. Any snapshot or `getAllByRole("button")` count assertion in a chart test will change. This is the intended change, but it must be a deliberate test update, not a surprise. |

---

## 7. Recommended implementation order

1. **Tokens** (`style.css` `:root`) + the legacy aliases. Land alone; it is
   mechanical, verifiable, and immediately fixes the three measured contrast
   failures in §2.1.
2. **The accent audit.** Grep `var(--accent` across `style.css` and classify each
   hit. This is the change that makes the direction read as designed rather than
   as "the current app, tidier".
3. **`CompactNote` → 44 px row** and the `Badge` tint change. Small, isolated.
4. **The status bar** (§3.2) + the `.terminal` grid row.
5. **The tablist hook** (§3.1) on both tablists.
6. **`ChartPanel`**: remove the ruler filter, add the segmented timeframe and the
   indicator toggle, add the crosshair readout, add the depth constraint.
7. **`TerminalHeader` restructure** and the `TokenSearch` move.
8. **`MarketRail` rows and chips.**
9. **Ticket and dock restyle.**
10. **Verification** (§8).

---

## 8. Verification checklist for the implementer

Run these against the real app, not the prototype.

- [ ] `DESIGN.md` §2's `:root` block is byte-identical to `style.css`'s (76 tokens).
- [ ] Every one of the twelve legacy aliases still resolves; nothing falls back to
      a browser default.
- [ ] **Amber appears exactly twice on screen at rest**: the brand mark and the
      instrument price rule. Grep the rendered DOM for the accent colour and count.
- [ ] No `--line` on an interactive control boundary — every input, button, chip
      and select uses `--control-border`.
- [ ] `--sell` is used for text, `--sell-fill` for fills. The Sell button's white
      label measures ≥ 4.5:1.
- [ ] Every `:focus-visible` shows the ring; no `outline: none` without it.
- [ ] Both tablists respond to Left/Right/Home/End and keep one tab stop.
- [ ] The stat strip at 1366 px shows whole stats only — no value is clipped, and
      the strip never renders a partial number.
- [ ] No horizontal scroll at 1366, 1440, 1600, 1920, 1180, 980.
- [ ] All seven drawing tools render and each sets `aria-pressed`.
- [ ] An unserved timeframe is disabled with a reason and is never substituted.
- [ ] Every unknown value renders `—`; `grep -c '0'` on the unknown paths returns
      nothing suspicious.
- [ ] The dock shows all five tabs; counts are `—`.
- [ ] The status bar keys carry `letter-spacing: var(--tracking-label)`.
- [ ] `prefers-reduced-motion: reduce` zeroes the motion tokens and removes the
      press transform.
- [ ] `TokenSearch` still debounces at 300 ms and never dispatches a blank query.
- [ ] The full existing test suite passes, with only the intentional chart-toolbar
      count assertions updated.

---

## 9. Out of scope — explicitly not proposed here

- **Any backend, realtime, auth, crypto or execution change.** Not one line.
- **A sixth `DockTab` for depth of book.** Recommended in §4.9 only as a future
  option; it edits the `DockTab` union and is a behavioural change.
- **Replacing the numeric risk score with a level word.** Proposed in §4.2 with a
  default of "keep and restyle"; it changes how risk is communicated.
- **A `<select>` → segmented control conversion** for the timeframe if the owner
  prefers to keep the native control. Default is the segmented control.
- **Removing the `.offline-banner`.** Default is to keep it alongside the new
  status bar.
- **Renaming any existing class, `data-testid`, `id` or ARIA attribute.** The
  design maps onto the current names; it does not rename them.
- **The pre-unlock shell** (`web/workspace-shell/src/style.css`). The brief
  requires security/auth chrome to disappear from the outer workspace after
  unlock. That shell is a different surface and is not part of this design.
- **Keyboard *placement* of a drawing.** The chart viewport is keyboard-operable
  (`DESIGN.md` §5.3); drawing coordinates are not, and this document does not
  claim otherwise.

---

# Part 2 — FOMO token-intelligence revision

> Maps the §5A additions in `DESIGN.md` onto the existing codebase. Same hard
> scope limit as Part 1: **no application code is modified by this document.**
> Where a change needs a behavioural edit it is marked **[needs owner sign-off]**
> with a default.

## 10. The authoritative FOMO surface — read before designing anything

These are the real names and shapes in this repository. They are what the handoff
maps onto; they are **not** what the UI may display (§9 of `DESIGN.md`).

### 10.1 MCP adapter — `crates/mcp-adapters/src/fomo.rs`

Five tools, exact-name allowlisted, boundary-validated, **one transport call per
logical request with zero retries**, fail-closed with no payload leak:

| Tool | Arguments | Serves |
|---|---|---|
| `fomo_capabilities` | `{}` | availability |
| `fomo_search_tokens` | `{ query }` | exact-address token search: name, symbol, image, socials, launchpad, graduation, price, mcap, liquidity, volume, supply |
| `fomo_get_token` | `{ networkId, tokenAddress }` | token detail: holders, top-10 %, buy/sell counts + volumes for 5m/1h/4h/24h, unique buyers/sellers, warnings |
| `fomo_get_trending_tokens` | `{ list }` — `trendingTokens` \| `mostHeld` \| `graduatedTokens` \| `cryptoTokens` \| `verifiedTokens` | trending |
| `fomo_get_recent_events` | `{ since_minutes?, since?, until?, action?, user_handle?, user_id?, network_id?, token_address?, min_usd?, limit? }` | token activity |

Every response is a `FomoEnvelope`: `{ data, source?, freshness?, coverage?, warnings[] }`.

**Two consequences that shaped the design:**

1. `fomo_get_recent_events` **already validates `action`, `min_usd`, `limit`,
   `network_id` and `token_address`.** The activity feed's kind filter, minimum-USD
   filter and pagination are therefore not invented UI — they map one-to-one onto
   parameters the adapter already bounds. Build them as server-side filters, not
   client-side array work.
2. The envelope's `freshness` and `coverage` fields are the provider's own
   statements about staleness and completeness. Map them to the stale ribbon and
   the partial-data notes (§13.5) rather than recomputing either from timestamps.

### 10.2 Chain → network id — `apps/private-api/src/fomo_market.rs`

`fomo_network_id(chain_slug)` is the **only** permitted mapping and it refuses
anything unverified rather than guessing:

| chain slug | network id |
|---|---|
| `solana` | `1399811149` |
| `base` | `8453` |
| `ethereum` | `1` |
| `bnb_chain` (also `bsc`, `bnb`) | `56` |
| `robinhood` (also `robinhood_chain`) | `4663` |
| anything else | `None` → **refuse** |

`fomo_chain_slug(network_id)` is the inverse and also returns `None` for an
unknown id, so a read result on a network PEP cannot verify is **dropped rather
than mislabelled to another chain**. Reuse both; never re-derive the mapping.

### 10.3 The web command surface

`web_integration.rs` maps web intents to canonical commands. For this revision the
relevant ones are:

```
"search_token"                      → search
"get_token" | "get_intelligence"    → the SAME translation path
"get_chart"                         → chart, with trade fields
```

`get_intelligence` is already an accepted alias for the token-detail read. The
About pane's market-stats section is therefore servable **today** by an existing
command.

`token_detail_json` currently emits exactly:

```json
{ "token": { "chain", "address", "symbol?", "name?" },
  "stats": { "priceUsd", "priceChange24h", "marketCapUsd",
             "liquidityUsd", "volume24hUsd", "holders" },
  "risk": { "disableBuying?", "disableSelling?", "level?", "warnings": [] } | null,
  "evidence": [], "slot": null, "sourceAgeMs": 0, "source": "fomo-rest" }
```

which is already the `TokenDetail` shape in `contracts/market.ts`. **Do not invent
a parallel contract for the fields that already exist.**

### 10.4 What is plumbed, and what is genuinely new

This is the single most useful table in this document. Everything in the revision
falls into one of three buckets.

| Pane field | Authoritative source | Status |
|---|---|---|
| price, 24h change, market cap, liquidity, 24h volume, holders | `get_intelligence` → `TokenDetail.stats` | **Plumbed today** |
| risk level + warnings | `get_intelligence` → `TokenDetail.risk` | **Plumbed today** |
| `top10HoldersPercent` | `BridgeDetailMetrics.top10_holders_percent` exists in the bridge but `token_detail_json` does not emit it | **One field to add** to `token_detail_json` |
| `fdv` | `BridgeDetailMetrics.fdv` exists in the bridge, not emitted | **One field to add** |
| circulating supply, total supply | `fomo_search_tokens` / `fomo_get_token` | **New emitted field** |
| image, social links, launchpad, graduation % | `fomo_search_tokens` | **New emitted field** |
| buy/sell counts, buy/sell volumes, unique buyers/sellers × 5m/1h/4h/24h | `fomo_get_token` detail | **New emitted field** |
| holder traders — profile, followers, verified/clan, entry, hold, cost basis, realised/unrealised/total PnL, thesis, likes | holder payload | **New web-facing command** |
| token activity events | `fomo_get_recent_events` | **New web-facing command** |
| realtime prepend for new activity | — | **New stream topic**; see §15 |

Read the third column as the work estimate: the About pane's **market-stats and
risk sections ship against existing plumbing**, and everything else needs a new
web-facing read. That is why §5A.0 makes availability per-section: a partially
landed rollout must still show the sections that work.

## 11. Dock tab and dock sizing

### 11.1 `DockTab` — the V2 union

`state/workstation.tsx`:

```ts
export type DockTab = "positions" | "orders" | "activity" | "holders" | "about";
```

**`"trades"` is removed.** This is an owner-approved change, not an inference:
the tab was only ever a placeholder for a market-trades capability, and the
exact-token activity feed under *Activity → Token* supersedes it.

Delete, in `BottomDock.tsx`:
- the `{ id: "trades", label: "Trades" }` entry in `DOCK_TABS`;
- the `<Show when={station.dockTab() === "trades"}>` block and its `CompactNote`,
  including `capability="market.trades"`.

**Do not touch `RealtimeChannel`.** `realtime/types.ts` has its own `"trades"`
member; it is a transport channel, and the shared word is a coincidence. Also
leave `realtime/decoder.ts`'s `CHANNELS` list alone.

`DOCK_TABS` becomes, in order:

```ts
{ id: "positions", label: "Positions" }
{ id: "orders",    label: "Open Orders" }
{ id: "activity",  label: "Activity" }
{ id: "holders",   label: "Holders" }
{ id: "about",     label: "About" }
```

`Holders` keeps its label. The pane header reads **Holder traders**, which is what
the pane now shows — there is no separate Traders tab.

The About tab carries **no count slot**: it has no natural count, and a permanent
`—` would read as a loading state.

The expand control must be a **sibling** of the tablist, not a child — `role="tablist"`
may contain only `role="tab"` (or presentational) children, and a plain `<button>`
inside it is invalid ARIA. Structure it as
`.dock__tabs > (.dock__tablist[role="tablist"], .dock__expand)`. The ticket's tablist
already has no non-tab children and needs no change.

One further naming caution found while building this: the dock's **height** state
and the dock's **tab id** must not share an attribute name. The prototype uses
`data-dock-size` on `.terminal` for height and `data-dock` on `.tab[]` for the tab
id. Use two distinct names — a single `data-dock` for both is a collision waiting
to bite the next `[data-dock]` query.

### 11.2 `ActivityWorkspace` — one home for event streams

**New file:** `web/workspace-payload/src/features/intelligence/ActivityWorkspace.tsx`.

```tsx
export type ActivityScope = "token" | "mine";
export interface ActivityWorkspaceProps { readonly embedded?: boolean }
const ActivityWorkspace: Component<ActivityWorkspaceProps>
```

`BottomDock.tsx` renders it for the `activity` tab. **`ExecutionPanel` is not part
of this workspace at all** — see §11.4. The Mine subview is a separate read-only
component.

```tsx
<div hidden={station.dockTab() !== "activity"} aria-hidden={station.dockTab() !== "activity"}>
  <ActivityWorkspace embedded />
</div>
```

Scope resolution, in one memo:

```ts
// null = the operator has not chosen; the workspace decides.
const [chosen, setChosen] = createSignal<ActivityScope | null>(null);
const scope = () => chosen()
  ?? (tokenActivityState().kind === "ready" || tokenActivityState().kind === "stale" ? "token" : "mine");
```

- **Auto-scope**: Token when an exact token is selected *and* its activity is
  available, Mine otherwise. An explicit choice always wins and **survives an
  instrument switch** — re-choosing it on every token change would be its own
  small insult.
- The scope selector is a two-segment `role="group"` with `aria-pressed`, in the
  pane bar, so provenance is always visible next to the title.
- **The two scopes never share a row style and are never interleaved.** Do not
  render an owner execution row inside the market tape, and do not render a market
  row inside Mine to fill space.

`TokenActivity` (§13) is the Token subview. The Mine subview is
`OwnerExecutionActivityPanel` (§11.4) — **read-only**. There is no path from
Activity to a mutating execution control.

### 11.4 `OwnerExecutionActivityPanel` — read-only owner execution status

**New file:** `web/workspace-payload/src/features/intelligence/OwnerExecutionActivityPanel.tsx`.

```tsx
export interface OwnerExecutionActivityPanelProps { readonly embedded?: boolean }
const OwnerExecutionActivityPanel: Component<OwnerExecutionActivityPanelProps>
```

**This component must contain no form, no submit, no configuration control and no
button that changes server state.** Enforce it with a test (§17): assert the
rendered subtree contains zero `<button>` and zero `<input>`.

#### 11.4.1 It renders exactly one execution, and says so

The only execution read that exists is `get_execution_progress`
(`web_contract.rs`): with no `client_request_id` it returns the **current**
execution; with one it returns that execution. **There is no history-list
command.**

Therefore:

- render **one** current-status block;
- render a **permanent, honest** history-unavailable row beneath it —
  `No authoritative execution-history contract is composed. Only the current
  execution can be read, so no historical rows are shown.`;
- **never invent historical rows** to make the pane look complete. A truthful
  current-status surface is worth more than a fabricated tape.

#### 11.4.2 Reuse the existing read, and its existing denial

`ExecutionPanel.tsx` already has the read half wired correctly. Carry it across
verbatim rather than re-deriving it:

```ts
const progress = createCommandResource<ExecutionProgress>(ws.command, "get_execution_progress", {
  ttlMs: 5_000,
});
```

and the denial, whose comments record two decisions that must not be lost:

```ts
// `get_execution_progress` is an ungated owner-scoped reconciliation read (BR-9):
// the server serves it even when `twap` is not advertised, so the client must not
// hide it behind `twap` or an UNKNOWN execution could never be reconciled.
// Until the authenticated command channel is installed it must surface as
// "awaiting the channel" rather than an unqueried empty ("no execution running").
const progressDenial = (): CapabilityDenial | null =>
  ws.commandReady() ? null : { capability: "twap", reason: "Awaiting the authenticated command channel." };
```

`progressMetrics()` — `State / Chunks / Filled / Remaining / Realized vs estimate
/ Progress` — is the existing pure formatter for exactly this contract. **Move it
to a shared module** (e.g. `features/execution/progress-metrics.ts`) and import it
in both the read-only panel and the mutating panel, rather than duplicating it.

#### 11.4.3 Fields, and what each unknown becomes

Every field comes from `ExecutionProgress` and nothing else. `formatBps` and
`formatPercent` already return `—` for null; use them and never substitute `0`.

| Field | Source | Unknown ⇒ |
|---|---|---|
| State | `state` | `Unknown` — never "safe", never "idle" |
| Kind | `kind` | — |
| Chunks | `chunksDone` / `chunksTotal` | `—` |
| Progress | derived `done / total` | `—`, and the bar is omitted |
| Filled / Remaining | `filledAmount` / `remainingAmount` | `—` |
| Realised vs estimate | `realizedVsEstimateBps` | `—` |
| Halt reason | `haltReason` | the line is omitted entirely |
| Provenance | the read's source and age | — |

**Build the progress bar from the chunk ratio, never from the amount strings.**
`filledAmount` and `remainingAmount` are opaque provider strings; dividing them
would be inventing a number. The bar renders only when `chunksTotal > 0` — the same
no-ratio-without-a-denominator rule as the buy/sell bar.

#### 11.4.4 Three states that must not be conflated

| State | Condition | Rendering |
|---|---|---|
| **Active** | the read returned an execution | the status block with its lifecycle badge |
| **Idle** | the read succeeded and returned nothing | `No execution is running for this workspace.` — a normal state, not an error, and not an unavailable row |
| **Unavailable** | the read is not composed, or the channel is not up | the 44 px compact row, with the reason from §11.4.2 |

The third must never be rendered as the second: a stalled handoff that shows "no
execution running" forever is exactly the failure the repo's comment warns about.

### 11.5 Where the mutating execution controls move

**Placement rule — a move, not a rewrite.** `ExecutionPanel.tsx`'s Adaptive TWAP
form and RFQ / solver competition panel leave Activity and mount in the **trade
ticket → Advanced execution**:

- **Recommended:** a single entry point inside `TradePanel.tsx`'s existing
  `.ticket__advanced` disclosure (`data-testid="ticket-advanced"`, a `<details>`
  at `TradePanel.tsx:984`) that opens an **Advanced Execution drawer**.
- **Alternative:** inline inside `.ticket__advanced-body`.

The drawer is the recommended default because the two forms are large, and inlining
them would push the ticket's Advanced section past usability at 1366×768. Copy the
`SecurityDrawer` pattern: `role="dialog"`, `aria-modal="true"`, `aria-labelledby`,
`tabindex="-1"`, Escape closes, and focus returns to the invoking control.

**Every gate is retained, unchanged.** Moving a control must not weaken a guard:

- fail-closed defaults on every submission path;
- `createSubmissionKeyTracker("twap")` / `("rfq")` idempotency;
- the UNKNOWN-outcome guard, its two-step acknowledgement before release
  (`discardArmed` / `rfqDiscardArmed`), and the rule that an UNKNOWN is deliberately
  **not** cleared by switching source;
- `ws.tradingEnabled()` / `TRADING_ENABLED`;
- `ws.mutationDenial("twap")` / `ws.mutationDenial("rfq")` and their reasons;
- the rule that the browser never calls a provider directly (W13 / architecture
  lock L2).

Do **not** redesign the ticket around this. The ticket's own IA, layout and gates
are unchanged; only the mount point of one panel moves.

### 11.3 Dock sizing — state and the CSS clamp

Add to `WorkstationStore`, memory-only like every other pane signal:

```ts
readonly dockHeight: Accessor<number | null>;   // null = the tier's closed height
readonly dockExpanded: Accessor<boolean>;
setDockHeight(px: number | null): void;
toggleDockExpanded(): void;
```

The clamp itself stays in CSS (see `DESIGN.md` §5A.1) so no caller can breach the
chart floor:

```css
--dock-h-expanded: 400px;
--chart-min-h: 392px;          /* 2 pane bars + the 320px plot floor */
--dock-handle-h: 6px;
--dock-h-base: var(--dock-h);
--dock-h-max: calc(100vh - var(--topbar-h) - var(--statusbar-h) - var(--dock-handle-h) - var(--chart-min-h));

.workarea { grid-template-rows: minmax(0,1fr) var(--dock-handle-h)
                                clamp(96px, var(--dock-h-base), var(--dock-h-max)); }
.terminal[data-dock="expanded"] { --dock-h-base: var(--dock-h-expanded); }
```

The drag handler writes `--dock-h-base` through **CSSOM**
(`element.style.setProperty`), which is CSP-safe; `style=` attributes in markup are
not, because the payload policy is `style-src 'self'` with no `unsafe-inline`.

**The resize handle** is a `role="separator"` element above the dock:

```jsx
<div class="dockresize" role="separator" aria-orientation="horizontal"
     aria-label="Resize the data dock"
     aria-valuemin="96" aria-valuenow={dockNow()} aria-valuemax={dockMax()}
     tabindex="0" onPointerDown={beginDrag} onKeyDown={onSeparatorKey} />
```

`aria-valuenow` / `aria-valuemax` must be read from the live CSS custom properties,
not from a duplicated table, so they can never disagree with the layout.
ArrowUp/ArrowDown step 16 px (48 with Shift), Home toggles, End goes to the
ceiling. The handle's pointer target is extended to 24 px with an `::after` box so
it satisfies WCAG 2.5.8 outright.

**[needs owner sign-off] Depth-of-book when the dock expands.** In the application
the chart pane also carries `.depth-columns`. Recommendation, matching §5A.1:
depth yields to a summary row while the dock is expanded, keeping `--chart-min-h`
at 392 in both states. The alternative — moving depth into the dock as a seventh
`DockTab` — is a behavioural change and is out of scope here.

## 12. Holders — FOMO trader pane

**New file:** `web/workspace-payload/src/features/intelligence/HolderTradersPanel.tsx`.

```tsx
export interface HolderTradersPanelProps { readonly embedded?: boolean }
const HolderTradersPanel: Component<HolderTradersPanelProps>
```

`BottomDock.tsx` renders it in place of the current `CompactNote` for the
`holders` tab, using the same `embedded` convention `LimitsPanel` already uses:

```jsx
<div hidden={station.dockTab() !== "holders"} aria-hidden={station.dockTab() !== "holders"}>
  <HolderTradersPanel embedded />
</div>
```

### 12.1 Row anatomy → DOM

| Design tier | Element | Class |
|---|---|---|
| mark | `<MarkTile size="sm" />` | `.mark-tile.mark-tile--sm` |
| name + handle | `<span>` ×2 | `.trader__name`, `.trader__handle` |
| verified / clan / dev / followed | `<Badge>` ×n | `.badge.badge--positive\|muted\|info` |
| position value | mono `<span>` | `.trader__value` |
| total PnL | mono `<span>` | `.trader__pnl.up\|down` |
| thesis | `<span>` | `.trader__thesis` (one line, ellipsised) |
| entry · hold · followers | mono `<span>` | `.trader__sub` |
| expanded detail | `<dl>` | `.trader-detail`, `.trader-detail__grid` |

The row is a `<button aria-pressed aria-expanded>` inside an `<li>`; the list is a
`<ul>`. Never a `<div>` with a click handler.

**Reuse `Badge` from `components/ui/primitives.tsx`.** The four flags are four
`Tone` values that already exist; no new tones.

### 12.2 Scope and sorting

```ts
type HolderScope = "top" | "following";
type TraderSort  = "value" | "pnl" | "entry" | "hold";

const [holderScope, setHolderScope] = createSignal<HolderScope>("top");
const [traderSort, setTraderSort]   = createSignal<TraderSort | null>(null); // null = provider order
```

**Scope**
- `Top holders` is always available.
- **`Following` renders only when the provider actually returns followed rows** —
  derive it from the data (`rows.some(r => r.followed)`), never from a feature flag
  or a config value. A scope that can only ever render empty is a broken promise,
  not a feature.
- If the operator chose `Following` and then selects a token with no followed rows,
  fall back to `Top holders` **and let the pressed segment show the fallback**. This
  is the same principle the rail's network filter already follows when a network
  disappears: never present an empty list as if the provider had returned nothing.
  Keep the stored choice so returning to a token that has followed rows restores it.

**Sort**
- `null` is the **default and the documented contract**: the provider's own
  authoritative order, with no segment pressed.
- Pressing the active segment returns to `null`.
- Sort descending on the numeric key; **break ties by the provider's order** so the
  result is reproducible.
- The pane bar always states which order is in force (`FOMO order` / `sorted by …`).

Do both in a `createMemo` over the fetched rows. Do **not** sort or filter inside
the render pass.

### 12.3 Selection and the detail disclosure

`openTrader` is a memory-only `createSignal<string | null>(null)`. Selecting a row
expands `.trader-detail` **beneath that row** — full metric set, full thesis,
copyable address, total PnL.

**Do not navigate, and do not build the drawer yet.** The brief says the
in-terminal quick-view drawer comes later; this pass keeps the interaction inside
the pane. When the drawer is built, `features/security/SecurityDrawer.tsx` is the
pattern to copy: `role="dialog"`, `aria-modal`, `aria-label`, `tabindex="-1"`,
Escape closes, focus moves in and returns to the invoking row.

### 12.4 Wallet addresses

The address is **tertiary**: it appears only inside the expanded detail, rendered
through `AddressCopy` (`components/ui/AddressCopy.tsx`), which already copies
verbatim, writes only the public on-chain address, and degrades to a no-op without
a clipboard. Keep it exactly as it is.

**A provider-supplied address is real and may be shown.** A fixture or placeholder
address must be visibly not-an-address. `DESIGN.md` §9 forbids a plausible-looking
fabricated address outright.

## 13. About — token overview pane

**New file:** `web/workspace-payload/src/features/intelligence/TokenOverviewPanel.tsx`.
*(Renamed from `TokenIntelligencePanel` in the V2 correction: the pane is a token
overview, and the old name described a scope it no longer has.)*

```tsx
export interface TokenOverviewPanelProps { readonly embedded?: boolean }
const TokenOverviewPanel: Component<TokenOverviewPanelProps>
```

### 13.0 What is removed from About, and why it matters

**Remove the activity query, the pagination state, the kind filter and the
minimum-USD filter from this pane entirely.** The `TokenActivity` component and
every piece of state it needs — page index, kind, min-USD, the filters-disclosure
open flag — move to `ActivityWorkspace` (§11.2). They must not exist here in any
form, not even as an unused signal: an About pane that *can* page is an About pane
that will eventually page.

Delete from this pane, explicitly:
- the `activityState()` read and its `AsyncSurface`;
- `<TokenActivity />` and the feed row renderer;
- `page` / `kind` / `minUsd` / `filtersOpen` signals;
- the `Newer` / `Older` pager and the `1–12 of N` range.

The pane renders **five sections and no list**: identity & links, market snapshot,
ownership/supply, buy/sell flow, risk/warnings.

### 13.1 Per-section gating — the core structure

Five independent sections, each wrapped in its own `AsyncSurface` (from
`components/ui/states.tsx`), each with its own denial:

```tsx
<AsyncSurface state={profileState()} denial={ws.capabilityDenial("intelligence")}
              emptyTitle="No profile published" …>
  <TokenIdentity />
</AsyncSurface>
<AsyncSurface state={marketState()}  …><MarketSnapshot /></AsyncSurface>
<AsyncSurface state={supplyState()}  …><OwnershipSupply /></AsyncSurface>
<AsyncSurface state={flowState()}    …><BuySellFlow /></AsyncSurface>
<AsyncSurface state={riskState()}    …><RiskWarnings /></AsyncSurface>
```

`AsyncSurface` already renders the loading / stale / empty / unavailable matrix and
already sets `data-stale`. Reuse it rather than hand-rolling five state machines —
that component exists precisely to stop an unqueried empty from masquerading as
loaded data.

### 13.1b Risk / warnings — provider truth only

- **Level is the provider's word**: `clear` / `hard_risk`, and anything absent or
  unrecognised renders **Unknown**, never "safe". Render it as a `Badge`, not a
  number.
- **No invented numeric risk score.** `RiskAssessment.score` exists in the contract
  but must not be presented as a computed safety figure.
- **Buy and sell tax stay `—`** unless a verified provider supplies them, with the
  one-line reason stated. `formatBps` already returns an em dash for null — use it
  and do not substitute `0`.
- Warnings render as a short list. With none, say so: `No provider warnings
  reported.` — that is different from "unknown".

### 13.2 Layout

Two columns at **container** width, one below. Set `container-type: inline-size` on
the dock body and use `@container (min-width: 720px)`. A viewport media query is
wrong here: this pane's width depends on whether the rail and ticket are open.

Sections are separated by **hairlines and section headers**, never by bordered
rounded blocks — a dock pane already sits inside a pane (`DESIGN.md` §9).

### 13.3 Social links

```tsx
<Show when={socials().twitter}>
  <a class="extlink" href={socials().twitter!} target="_blank" rel="noopener noreferrer"
     title="X — opens in a new tab">X<ExternalGlyph /></a>
</Show>
```

- **Absent links are omitted, never disabled ghosts.** Wrap each in `Show`.
- Every link carries `target="_blank"` **and** `rel="noopener noreferrer"`, plus a
  visible outward-arrow glyph so the behaviour is legible before the click.
- Validate the scheme before rendering. Render a link only for `https:` URLs;
  anything else (including `javascript:` and `data:`) is dropped, not sanitised.
  The repo already has an XSS test — `security/xss.test.tsx` — and this is the
  surface it applies to.

### 13.4 Buy / sell flow

- Window switcher: `5m / 1h / 4h / 24h` — the exact windows the provider serves.
- Six values per window: buy count, sell count, buy volume, sell volume, unique
  buyers, unique sellers.
- **The ratio bar is not rendered when `buyCount + sellCount === 0`.** Omit the bar
  and render `No trades in this window`. An empty bar asserts a 0% the provider
  never stated (`DESIGN.md` §9).
- Fill widths go through CSSOM, never a `style=` attribute.

### 13.5 Stale, loading, error, partial

| State | Component | Rendering |
|---|---|---|
| loading | `LoadingBlock` | compact, in-section |
| stale | `StaleRibbon` + `FreshnessBadge` | a `Stale · 4m` ribbon **on the section that is stale**, driven by the envelope's `freshness` |
| unavailable | `CompactNote` | the 44 px row; capability key `intelligence` inside its `<details>` |
| empty | `EmptyBlock` | `No activity matches this filter.` — a *different* sentence from unavailable |
| partial | `—` per field | driven by the envelope's `coverage`; a trader with no thesis says so in its own row |
| error | `ErrorBlock` | retry only when `error.retryable` |

**Never** put a raw command name, a capability key outside a `<details>`, or a
provider error string on the face of the pane.

## 14. Lazy queries keyed by exact chain + address

**New file:** `web/workspace-payload/src/features/intelligence/queries.ts`.

```ts
/** The only permitted key. Symbol and name are never part of it. */
export interface IntelKey { readonly chain: string; readonly networkId: number; readonly address: string }

export function intelKeyFor(ref: InstrumentRef): IntelKey | null;  // null when fomo_network_id refuses
export function createIntelQueries(deps: IntelQueryDeps): IntelQueries;
```

Rules, each of which is an existing repo invariant restated for the new reads:

1. **Key on `(chain, networkId, address)`.** Never join by symbol or name — the
   brief and `chart-datafeed.ts` both require exact identity, and
   `fomo_chain_slug` exists precisely so an unverifiable network is dropped rather
   than mislabelled.
2. **Refuse rather than guess.** `fomo_network_id` returns `None` for an unverified
   chain; surface that as the unavailable state, never as a fallback to another
   network.
3. **Lazy.** Fetch when the tab is first opened for the current instrument, and on
   instrument change while the tab is open. Do not fetch on boot for a tab the
   operator has not opened.
4. **Cache by `IntelKey`, bounded.** Mirror `MarketEventRouter`'s
   `MAX_PRICE_ENTITIES` discipline; an unbounded per-token cache is a leak.
5. **Abort in flight on instrument change** (`AbortSignal`), so a slow response for
   token A can never paint into token B's pane.
6. **TTL 60 s** for the intelligence reads, matching the pane's stale ribbon.
7. **No persistence.** Nothing about these queries is written to storage, the URL,
   the title or history. `security/no-persistence.test.tsx` already asserts this
   class of rule; extend it.

## 15. Token activity — the feed, owned by Activity

This is the `TokenActivity` component that lives **inside `ActivityWorkspace`**
under Token scope. It has no home in About (§13.0).

```ts
interface ActivityQuery {
  readonly key: IntelKey;
  readonly kind: "all" | "buy" | "sell" | "transfers" | "thesis";
  readonly minUsd: number | null;
  readonly page: number;      // 0-based
  readonly pageSize: 12;
}
```

`"transfers"` is a **UI grouping, not a provider value**: it matches the
provider's `transfer` / `transfer_in` / `transfer_out` types. Map it to the
provider's own `action` filter values before the request rather than filtering
client-side — the adapter validates `action`, so push it down.

- **Page size 12, and the DOM is bounded by construction.** Do not append. The
  prototype's `Newer` / `Older` pager plus a `1–12 of 84` range is the model.
- **Push the filters down to the provider.** `fomo_get_recent_events` already
  validates `action`, `min_usd` and `limit`; a client-side filter over a
  server-paged set would produce wrong counts and empty-looking pages.
- **Pagination resets when the instrument changes.** Page 3 of token A's activity
  must never be presented as token B's. Reset the page index in the same place the
  instrument key changes, and keep the scope choice (that is the operator's).
- **Realtime prepend, exact identity only.** A pushed event may prepend a row only
  when its `chain + address` matches the currently selected instrument exactly —
  the same rule `chart-datafeed.ts` and `market-events.ts` already enforce for
  `ohlcv:<chain>:<address>` and `market:price:<chain>:<address>`. Anything else is
  dropped, not merged. A prepend must never cross a scope boundary either: a market
  event never lands in Mine.
- **REST reconciles.** A prepended row is provisional; the next REST read is
  authoritative and replaces the head of the list. State this in the UI (the
  prototype's pager says `REST reconciles the stream`) so the operator knows which
  lane they are reading.
- **Minimum USD sits behind a compact `Filters` disclosure**, not in the always-on
  filter row: the row stays scannable and the power-user control stays one click
  away. A `<details>` is enough; no popover, so nothing can be clipped by the
  scroll container. Remember the open state in a memory-only signal so the
  re-render the input itself triggers does not collapse it.

## 16. Mark tile

**New file:** `web/workspace-payload/src/components/ui/MarkTile.tsx`.

```tsx
export const MarkTile: Component<{
  symbol: string;
  src?: string | null;      // provider-supplied image URL
  size?: "md" | "sm";       // 32px | 20px
}>;
```

- Provider image present ⇒ `<img>` with `width`/`height`, `object-fit: cover`,
  `alt=""` (the symbol is already adjacent text).
- No image ⇒ the typographic monogram: mono 10 px/600, `--tracking-label`, uppercase,
  `--text-2`, on `--surface-3`.
- **Trader avatars always use the monogram** in this pass: a provider avatar is a
  third party's photograph and is never fabricated.
- Localized marks for the eleven snapshot instruments live in
  `assets/token-logos/` with per-address provenance in its `SOURCES.md`.

## 17. Test impact of the revision

| Test file | Expected impact |
|---|---|
| `components/layout/*` | `BottomDock` **loses** the `trades` tab and gains `about`. Any assertion on the tab count or the tab ids changes: the set becomes `positions / orders / activity / holders / about`. Delete any test asserting `dock-tab-trades` or the `market.trades` CompactNote. |
| `features/execution/ExecutionPanel.test.tsx` | **Structural move, not a rewrite.** `ExecutionPanel` leaves the dock entirely and mounts in the trade ticket's Advanced execution area (§11.5). Its own behaviour tests should survive untouched — if any of them rendered it *through* `BottomDock`, repoint them at the new mount point. **Add a test asserting the panel's guards still hold at the new location** (fail-closed, idempotency key, UNKNOWN two-step release, `TRADING_ENABLED`). |
| `features/intelligence/OwnerExecutionActivityPanel.test.tsx` | **New.** Assert the subtree contains **zero `<button>` and zero `<input>`** — the structural guarantee that Activity stays read-only. Plus: the three states (active / idle / unavailable) render distinctly, `haltReason` appears only when present, the progress bar is omitted when `chunksTotal` is null or 0, and the history row is permanently unavailable with no fabricated rows. |
| `features/trade/TradePanel.test.tsx` | **Extend** for the new Advanced-execution entry point: it opens, it is keyboard-reachable, Escape closes it, focus returns to the invoking control, and the ticket's existing gates are unaffected. |
| `features/terminal/TerminalPanel.test.tsx` | **None** — it does not open the dock. |
| `features/portfolio/PortfolioPanel.test.tsx` | **None** — unchanged panel. |
| `security/no-persistence.test.tsx` | **Extend** with `dockHeight`, `dockExpanded`, the activity scope/kind/page/min-USD signals, the filters-disclosure open flag, and the intelligence query cache. |
| `security/xss.test.tsx` | **Extend** with a hostile `socialLinks.twitter` value; the link must not render. |
| `state/workstation.test.ts` | **Extend** for the five-member `DockTab` union (asserting `"trades"` is no longer assignable, so the removal cannot silently regress) and the two new dock signals. |
| `realtime/*.test.ts` | **None** — `RealtimeChannel`'s `"trades"` member is untouched. Add an assertion that it still exists, so a future cleanup does not conflate the two namespaces. |
| New: `features/intelligence/*.test.tsx` | Activity scope resolution (auto + explicit + survives instrument change), the five About section states, the risk level never defaulting to safe, the holder scope falling back when Following is unprovable, the sort default, the zero-denominator ratio, the page bound, page reset on instrument change, and exact-identity keying. |
| New: `features/intelligence/About.test.tsx` | **A negative test:** assert that the About pane renders no element with `class="feed__row"`, no pager, and holds no activity signal — the structural guarantee that the feed has exactly one home. |

## 18. Verification checklist for the revision

- [ ] The dock has **exactly five** tabs: `positions / orders / activity / holders /
      about`. No `trades` tab, no `dock-tab-trades`, no `market.trades` string.
- [ ] `RealtimeChannel` still has its `"trades"` member.
- [ ] `fomo_network_id` is the only chain→network mapping in the new code, and an
      unverified chain renders unavailable rather than falling back.
- [ ] No intelligence query is keyed by symbol or name.
- [ ] Every About section gates independently; PEPE-like partial composition shows
      market/risk and gates holders/activity.
- [ ] **About renders no feed, no pager and no activity state.**
- [ ] **The token activity feed exists in exactly one place** — Activity → Token.
- [ ] Activity resolves scope automatically and honours an explicit choice across an
      instrument change.
- [ ] Token and Mine never interleave rows, and never share a row style.
- [ ] **Activity contains no form, no `<input>`, no submit, and no button that
      changes server state.** Assert zero `<button>` and zero `<input>` inside the
      Mine subtree.
- [ ] **Activity > Mine renders one current execution and no fabricated history.**
      The history row is permanently and honestly unavailable.
- [ ] Mine's **idle** state ("no execution is running") is never rendered as
      **unavailable**, and vice versa.
- [ ] The Mine progress bar is built from the chunk ratio, never from the opaque
      `filledAmount` / `remainingAmount` strings, and is omitted when `chunksTotal`
      is null or 0.
- [ ] The mutating Adaptive TWAP and RFQ controls live in the trade ticket's
      Advanced execution area, reachable by keyboard, with **every** guard intact:
      fail-closed, idempotency key, UNKNOWN two-step release, `TRADING_ENABLED`,
      `mutationDenial("twap" | "rfq")`.
- [ ] No path from the Activity tab reaches a mutating execution control.
- [ ] The holder sort defaults to the provider's order and returns to it.
- [ ] The `Following` holder scope is offered only when followed rows exist, and
      falls back visibly when they do not.
- [ ] The ratio bar is absent when the window has no trades.
- [ ] Activity is paginated; the DOM row count never exceeds one page, and the page
      resets when the instrument changes.
- [ ] Realtime prepend happens only on an exact `chain + address` match, and never
      across a scope boundary.
- [ ] `target="_blank"` and `rel="noopener noreferrer"` on every external link, and
      non-`https:` URLs never render.
- [ ] Absent social links are omitted, not disabled.
- [ ] Copy-address never shows a false "Copied".
- [ ] A holder's thesis appears in Holders and nowhere else.
- [ ] Risk level renders the provider's word, `unknown` never renders as safe, and
      buy/sell tax stays `—`.
- [ ] No command name, capability key (outside `<details>`), or provider error
      string appears on the face of a pane.
- [ ] No `style=` attribute anywhere; fill widths go through CSSOM.
- [ ] The dock separator is keyboard-operable and its `aria-valuenow` matches the
      live CSS value.
- [ ] At 1366×768, expanding the dock leaves the chart pane at ≥392 px.
- [ ] Opening a pane does not change the dock height.
- [ ] Nothing about dock height, scope, filters or query results is persisted.
