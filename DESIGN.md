# EverCrest / PEP Terminal — Design System

> **Status:** authoritative design contract for the PEP private desktop terminal.
> **Winning direction:** *Deep Vault* (see `design-directions.md` for the three
> explored directions, the scored self-critique, and why B and C were rejected).
> **Adversarial review:** `design-critique-deep-vault.md` re-derives every claim
> below from the built artifact and found eight defects, all fixed here and in
> `evercrest-terminal.html`. Where this document was wrong, the correction is
> recorded inline rather than quietly overwritten.
> **Revision:** the FOMO token-intelligence pass (§5A) adds the Holders trader
> pane and the About pane, plus dock expansion. It is additive — the direction,
> palette, type, pane geometry and every fail-closed invariant are unchanged.
> Source brief: `.design/FOMO_INTELLIGENCE_REVISION.md`.
> **Revision V2 — information-architecture correction (owner-approved):** the dock
> is exactly five tabs, `Trades` is removed, **Activity becomes the single home for
> event streams** with a Token | Mine scope, **Holders** combines holder position
> data with trader identity and thesis, and **About** is a calm token overview with
> no feed, no pagination and no activity state. See §5.5 and §5A.3–§5A.5.
> **Revision V3 — semantic correction (owner-approved):** **Activity > Mine is
> read-only.** It renders owner execution *status* from `get_execution_progress`
> and states honestly that no history contract exists; the mutating Adaptive TWAP
> and RFQ controls move to the trade ticket's Advanced execution area with every
> guard intact. See §5A.5a and §5A.5b.
> **Scope:** desktop trading workstation, dark-only, 1366×768 / 1440×900 / 1920×1080.
> **Implementation target:** the existing SolidJS components under
> `web/workspace-payload/src/**`. See `IMPLEMENTATION_HANDOFF.md`.
>
> Machine-readable tokens are the `:root` block in §2. Copy it verbatim — it is
> verified to hold exactly the same 76 tokens as the artifact's `:root`.

---

## 1. Design intent

EverCrest is an **instrument**, not a page. The trader's eye moves rail → chart →
ticket → dock dozens of times a minute, so the governing constraint is not beauty
but **pane re-acquisition speed**: how fast the eye can tell which region it is
looking at, and what the primary value in that region is.

Three rules follow, and every other decision in this document is downstream of them:

1. **Panes are regions, not cards.** Separation comes from an opaque surface ladder
   plus a three-weight hairline system. No floating cards, no shadows on panes, no
   rounded containers nested inside rounded containers.
2. **One number owns each region.** The instrument price owns the top bar; the
   candle close owns the chart; the market row's price owns the rail; the
   estimated receive owns the ticket. Everything else is deliberately quieter.
3. **The terminal never lies.** An unknown value renders `—`, never `0`. A risk
   level is the provider's word, never a computed score. A disabled action says
   why, once, in the place the action lives.

### The one decisive flourish

The **instrument price block** in the top bar: symbol at 12 px mono uppercase with
`+0.07em` tracking, price at **28 px** mono with `-0.02em` tracking and tabular
figures, introduced by a single **2 px amber rule**. It is the only place in the
terminal where type is allowed to be large. Nothing else exceeds 20 px.

---

## 2. Tokens — copy this `:root` block verbatim

```css
:root {
  color-scheme: dark;

  /* ─── Surface ladder (4 levels, opaque) ─────────────────────────────────
     Deeper = further back. The chart sits on the canvas; every pane is one
     step up; rows and controls are two; hover and wells are three. */
  --surface-0: #080c11;   /* canvas — viewport, chart plot background */
  --surface-1: #0d131a;   /* pane — top bar, rail, ticket, dock, pane bars */
  --surface-2: #121a23;   /* row / control — inputs, chips, table rows */
  --surface-3: #18222d;   /* hover / well — hovered rows, code wells, axes */

  /* ─── Hairlines (3 weights) ─────────────────────────────────────────────
     Pane edges are opaque so a pane boundary never shifts against the chart.
     --line-faint is used *inside* panes where a translucent rule is safe. */
  --line: #1e2a36;         /* pane edges, control chrome, section rules */
  --line-strong: #2c3d4d;  /* emphasised separators, table header rule */
  --line-faint: #151d26;   /* intra-pane row rules, chart gridlines */
  --control-border: #5b7288; /* interactive control boundaries — ≥3:1 on every
                                surface including --surface-3 (WCAG 1.4.11) */

  /* ─── Foreground ramp (4 levels) ────────────────────────────────────────
     Contrast measured against the worst-case surface each level may sit on. */
  --text-1: #e8eef2;  /* values, symbols, headings   — ≥13.7:1 on all surfaces */
  --text-2: #9fb0bd;  /* labels, secondary stats     — ≥7.2:1  on all surfaces */
  --text-3: #7a8d9b;  /* timestamps, axis, disabled  — ≥4.7:1  on all surfaces */

  /* ─── Accent — the instrument signal ────────────────────────────────────
     Budget: exactly TWO rendered uses per screen, and they are fixed: the brand
     mark and the 2 px instrument price rule. Amber is never a fill, never a
     link, never a focus ring and never a selection state, so it has no
     hover/active fill pair. --accent-soft is the single derivation, used for the
     text-selection wash. See §6 for the enforced budget. */
  --accent: #e9b44c;
  --accent-ink: #1a1204;   /* only if amber is ever a fill — today it is not */
  --accent-soft: color-mix(in oklab, var(--accent) 16%, transparent);

  /* ─── Directional data (semantic, never decorative) ─────────────────────
     Coral-red rather than pure red: the crypto-native convention, and it keeps
     red distinguishable from the amber accent at 11 px. */
  --buy: #2fbf8f;          /* up / bid / buy  — ≥7.5:1 on all surfaces */
  --buy-fill: #2fbf8f;     /* buy button fill; label is --buy-ink (8.1:1) */
  --buy-ink: #04140e;
  --buy-hover: color-mix(in oklab, var(--buy-fill), black 10%);
  --sell: #ea5a5f;         /* down / ask / sell — ≥4.7:1 on all surfaces */
  --sell-fill: #c9302f;    /* sell button fill; label is white (5.3:1) */
  --sell-ink: #ffffff;
  --sell-hover: color-mix(in oklab, var(--sell-fill), black 10%);

  /* ─── Status ──────────────────────────────────────────────────────────── */
  --warn: #e5b94a;
  --danger: #ea5a5f;
  --info: #5b9dff;
  --focus: #7fb2ff;        /* keyboard focus only — never selection */

  /* ─── Risk levels (provider truth only) ───────────────────────────────── */
  --risk-clear: var(--buy);
  --risk-warning: var(--warn);
  --risk-restricted: var(--danger);
  --risk-unknown: var(--text-3);

  /* ─── Typography ────────────────────────────────────────────────────────
     Two families, zero network dependency. The mono face carries the display
     role (instrument identity + every numeric); the UI sans carries labels and
     prose. No reference terminal in this category uses a display serif, and a
     mono display is what makes a terminal read as an instrument. */
  --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", "Roboto Mono", Menlo,
    Consolas, "Liberation Mono", monospace;
  --font-ui: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
    Arial, sans-serif;

  /* Scale — 7 steps. Nothing in the terminal exceeds --text-xl. */
  --text-2xs: 10px;   /* axis ticks, badge micro-copy */
  --text-xs: 11px;    /* ALL-CAPS labels, table headers */
  --text-sm: 12px;    /* secondary rows, hints, tabs */
  --text-md: 13px;    /* default UI text, values in tables */
  --text-base: 14px;  /* pane titles, rail symbols */
  --text-lg: 16px;    /* dock section titles, ticket amount */
  --text-xl: 28px;    /* instrument price — the only large type */

  --leading-tight: 1.15;   /* mono display + numeric runs */
  --leading-body: 1.45;    /* UI sans labels and prose */
  --tracking-display: -0.02em; /* mono display ≥20px only (Latin) */
  --tracking-label: 0.07em;    /* required on every ALL-CAPS run */
  --tracking-num: -0.01em;     /* tabular numeric runs at ≥14px */

  /* ─── Spacing — 4px base, 8-step ladder ───────────────────────────────── */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;

  /* ─── Radii — small on purpose. No pills on panes or controls. ────────── */
  --radius-xs: 2px;    /* chart selection, row marker */
  --radius-sm: 4px;    /* controls, chips, badges */
  --radius-md: 6px;    /* inputs, popovers, buttons */
  --radius-lg: 8px;    /* drawer, modal only */
  --radius-pill: 9999px; /* status dots and the network filter only */

  /* ─── Control geometry ────────────────────────────────────────────────── */
  --control-xs: 24px;  /* icon button in a pane bar — WCAG 2.5.8 AA floor */
  --control-sm: 28px;  /* dense control: chips, tabs, tool buttons */
  --control-md: 34px;  /* default: inputs, selects, segmented control */
  --control-lg: 44px;  /* primary action — meets WCAG 2.5.5 target size */
  --row-h: 32px;       /* market row, table row */
  --row-h-tall: 44px;  /* ticket input row, dock empty-state row */

  /* ─── Pane geometry ─────────────────────────────────────────────────────
     These are the BASE (widest, ≥1800px) values. Media queries step them down
     per §8; the base is the widest tier so that a viewport wider than any tier
     gets the roomiest layout rather than a clamped one. */
  --topbar-h: 56px;
  --pane-bar-h: 36px;
  --rail-w: 280px;
  --ticket-w: 352px;
  --dock-h: 216px;
  --statusbar-h: 24px;

  /* ─── Dock expansion (§5A.1) ────────────────────────────────────────────
     --dock-h is the CLOSED height and is unchanged, so the chart is unchanged
     while the dock is closed. --dock-h-base is the operator's DESIRED height
     (tier default, the expanded target, or a dragged value); --dock-h-max is the
     hard ceiling that keeps the chart pane above its floor. They are combined by
     a clamp() on the work-area grid track, so no script can breach the floor. */
  --dock-h-expanded: 400px;
  --chart-min-h: 392px;   /* 2 pane bars (72) + the 320px plot floor */
  --dock-handle-h: 6px;
  --dock-h-base: var(--dock-h);
  --dock-h-max: calc(100vh - var(--topbar-h) - var(--statusbar-h) - var(--dock-handle-h) - var(--chart-min-h));

  /* ─── Elevation — two levels. Panes are never elevated. ───────────────── */
  --elev-flat: none;
  --elev-ring: 0 0 0 1px var(--line);
  --elev-raised: 0 8px 24px color-mix(in oklab, #000 55%, transparent);
  --focus-ring: 0 0 0 2px var(--surface-1), 0 0 0 4px var(--focus);

  /* ─── Motion — short, and only where it confirms a state change ───────── */
  --motion-fast: 120ms;  /* hover, focus, press */
  --motion-base: 180ms;  /* tab change, disclosure, drawer */
  --motion-flash: 420ms; /* price-tick cell flash */
  --ease-standard: cubic-bezier(0.2, 0, 0, 1);

  font-family: var(--font-ui);
  font-size: var(--text-md);
  line-height: var(--leading-body);
  font-variant-numeric: tabular-nums;
  font-feature-settings: "tnum" 1, "zero" 1;
}
```

**Rules for the token block**
- No raw hex outside `:root`. Derive with `color-mix(in oklab, …)`.
- No new tokens. If a value is needed that is not here, the design is wrong.
- `--line` for pane edges, `--line-strong` for emphasised separators,
  `--line-faint` inside panes, `--control-border` for anything interactive.
- `--focus` is for keyboard focus only. Selection uses `--accent`. They must never
  be the same colour, so focus never reads as selection.

---

## 3. Typography

### Roles

| Role | Family | Size | Weight | Tracking | Case |
|---|---|---|---|---|---|
| Instrument symbol | `--font-mono` | 12px | 600 | `--tracking-label` | UPPER |
| Instrument price | `--font-mono` | 28px | 600 | `--tracking-display` | — |
| Instrument change | `--font-mono` | 14px | 600 | `--tracking-num` | — |
| Stat label | `--font-ui` | 10px | 600 | `--tracking-label` | UPPER |
| Stat value | `--font-mono` | 13px | 500 | `--tracking-num` | — |
| Pane title | `--font-ui` | 14px | 600 | `0` | Sentence |
| Chart pane symbol | `--font-ui` | 16px | 600 | `0` | — |
| Section header | `--font-ui` | 11px | 600 | `--tracking-label` | UPPER |
| Table header | `--font-ui` | 11px | 600 | `--tracking-label` | UPPER |
| Market row symbol | `--font-ui` | 14px | 600 | `0` | — |
| Market row price | `--font-mono` | 13px | 500 | `--tracking-num` | — |
| Body / label | `--font-ui` | 13px | 400 | `0` | Sentence |
| Hint / caption | `--font-ui` | 12px | 400 | `0` | Sentence |
| Chart axis tick | `--font-mono` | 10px | 500 | `0` | — |
| Tab label | `--font-ui` | 12px | 600 | `0.02em` | Sentence |
| Button / chip label | `--font-ui` | 11–14px | 600 | `0.02em` | Sentence |
| Status bar key | `--font-ui` | 11px | 400 | `--tracking-label` | UPPER |

### Rules
- **Weight ceiling is 600.** 700 is never used. Emphasis is carried by colour and
  by the mono/sans role switch, not by heavier type.
- **Every ALL-CAPS run carries `letter-spacing: var(--tracking-label)`.** No exceptions.
- **Every price, size, balance, percentage, timestamp and axis tick is
  `--font-mono` with `tabular-nums`.** Labels are never mono.
- Negative tracking applies only to mono display runs ≥20 px. It is never applied
  to the UI sans, and never to any CJK run.
- Numeric strings never reflow: tabular figures plus a fixed decimal count per
  field. A price that changes `104.39 → 99.11` must not change width.
- Line length for any prose block is capped at `62ch`.

---

## 4. Spacing, density and pane geometry

### Spacing contract
- Base unit **4 px**; the ladder is 4 / 8 / 12 / 16 / 20 / 24 / 32.
- **Pane content padding is 12–16 px.** `--space-3` (12px) is the default for
  dense panes (rail, dock, ticket); `--space-4` (16px) for the top bar and any
  pane with prose.
- **Row padding is 8 px vertical / 12 px horizontal** at `--row-h: 32px`.
- **Never pad a data row beyond 12 px horizontally.** Density is the product.
- Section rhythm inside a pane: `--space-4` above a section header,
  `--space-2` below it.
- A group of related controls uses `--space-2` (8px); unrelated groups use
  `--space-4` (16px) or a hairline. Never both.

### Pane geometry

| Region | Token | 1920 | 1440 | 1366 |
|---|---|---|---|---|
| Top instrument bar | `--topbar-h` | 56px | 56px | 56px |
| Left market rail | `--rail-w` | 280px | 264px | 248px |
| Centre work area | `1fr` | 1296px | 832px | 790px |
| Right trade ticket | `--ticket-w` | 352px | 344px | 328px |
| Bottom dock | `--dock-h` | 216px | 200px | 176px |
| Status bar | `--statusbar-h` | 24px | 24px | 24px |
| Chart plot height @1080/900/768 | derived | 748px | 580px | 440px |

Chart plot is split **price pane 72% / volume pane 28%**, with a 1 px
`--line-faint` divider and a 4 px drag handle. `minHeight` for either pane is
96 px, so the volume pane can never collapse below a readable height.

### Work-area grid

```
terminal  : grid-rows: var(--topbar-h) 1fr var(--statusbar-h)
body      : grid-columns: var(--rail-w) minmax(0,1fr) var(--ticket-w)
            grid-areas:   "rail work ticket"
workarea  : grid-rows: minmax(0,1fr) var(--dock-h)
```

Named grid areas are mandatory: the collapsed rail is `display:none`, and
auto-placement would otherwise slide the work area into the zero-width rail
column and collapse the chart. *(This is an existing, hard-won repo decision —
preserve it.)*

---

## 5. Component rules

### 5.1 Top instrument bar (`--topbar-h: 56px`)
Left → right, one row, `overflow: hidden` with a single shrink point:

1. **Brand** — a 6 × 18 px amber rule (the mark) + wordmark at 13 px/600 UI sans.
   The mark is one of the two permitted amber uses. It is a **vertical rule**, not
   a square, deliberately rhyming with the instrument price rule: amber appears in
   this product only as a vertical rule, and only twice.
2. **Divider** — 1 px `--line`, 20 px tall.
3. **Instrument identity** — symbol (mono 12px UPPER amber-tracked) over
   `chain · truncated-address` (12px `--text-2`). The address is the copy button.
4. **Instrument price block** — the flourish. 2 px amber rule, then label
   `PRICE` / 28 px price / 14 px change.
5. **Stat strip** — `24H · MCAP · LIQUIDITY · VOLUME`. Each stat is a 10 px
   UPPER label over a 13 px mono value, 8 px apart, separated by 20 px.
   Unknown ⇒ `—` in `--text-3`.
6. **Right cluster (pinned)** — source badge, connection badge, trading-gate
   badge, security icon button, Lock button.

Rules
- The bar is **56 px and single-row at every supported width**. It never wraps.
- The stat strip is the only thing that folds, and it folds **whole stats at
  breakpoints** rather than shrinking: `.statstrip` is `overflow: hidden`, so a
  squeezed strip would clip a numeric mid-value and `184.20 – 192.5` would read as
  a complete number. In a terminal whose contract is "never lie", a truncated
  figure is worse than an absent one. See §8 for the tier table.
  **A folded stat is never rendered as `0`.**
- Badges are 11 px UPPER, `--radius-sm`, 1 px border, tinted background at **8%**
  of their semantic colour. Four badges maximum in the right cluster. *(8%, not
  12%: at 12% the danger badge's own 10 px text measures 4.47:1 against its tint
  over `--surface-2`, just under the 4.5:1 floor. At 8% the worst case is 4.72:1.)*
- Trading-disabled is rendered as a **danger** badge, and the same fact is
  restated once — and only once — as an inline reason in the ticket (§5.4).

### 5.2 Left market rail (`--rail-w`)
Vertical order: **Search → Network filter → Trending list.**

- **Search** — a 28 px input pinned under the rail header, `--surface-2` fill,
  1 px `--control-border`, leading glyph, trailing `⌘K` kbd hint in `--text-3`.
  Matches on name, symbol and full address. Results replace the trending list
  while the query is non-empty; a `N results` header row marks the swap.
- **Network filter** — one horizontally wrapping row of 24 px pill chips:
  `All` + **only the networks actually present in the current rows**, each with
  its honest count. A filter whose network disappears falls back to `All` rather
  than rendering an empty list that looks like a provider failure.
  This is the **only** place `--radius-pill` is used besides status dots.
  *(24 px, not 22: that is the WCAG 2.5.8 AA target-size floor. A chip is a real
  click target and 2 px is cheaper than relying on the 2.5.8 spacing exception.)*
- **Market row** — 32 px tall, two columns:
  - left: `symbol` (14px/600 `--text-1`) over `name` (12px `--text-3`)
  - right: `price` (13px mono `--text-1`, right-aligned) over
    `24h change` (12px mono, `--buy`/`--sell`/`--text-3`)
  - **The address is never a column.** It lives in the row's `title` tooltip.
- Selected row: `--surface-3` fill + a 2 px `--text-2` marker at the left edge.
  Hover: `--surface-2` fill, text unchanged. A row has no room for a boundary
  rule, so a row's selection **is** its fill step — one level above hover.
- Row states are `aria-pressed`; the list is a `<ul>` of `<button>`s, never
  `<div>`s with click handlers.

### 5.3 Centre chart pane
Two `--pane-bar-h` rows above the plot. **Nothing overlays the plot or the scales.**

- **Row 1 — identity & readout.** Left: symbol, chain, address copy, risk badge.
  Right: the **crosshair OHLC readout** in mono 12 px —
  `O · H · L · C · Δ · Vol`. Because it lives in the bar rather than floating over
  the candles, it can never cover a scale or a wick.
- **Row 2 — toolbar.** Drawing tools | divider | timeframe segmented control |
  divider | indicator toggle. Every control is `--control-sm` (28 px) with a
  24 px icon hit area, `aria-pressed`, and a `title`. *(The `.seg` group is 28 px
  tall with 2 px inner padding, so its 22 px inner buttons satisfy WCAG 2.5.8 via
  the spacing exception; the icon buttons are `--control-xs` = 24 px outright.)*
- **Drawing tools (all six required, in this order):** ruler/measure, trend line,
  horizontal, vertical, ray, rectangle, Fibonacci retracement. Escape cancels;
  `Delete`/`Backspace` removes the selected drawing; "Clear all" requires a
  second confirming click. An armed tool and a selected drawing are marked with
  `--text-1`, never with the accent — the chart is data, and amber is the
  instrument signal.
- **Plot.** Canvas on `--surface-0`. Candles `--buy`/`--sell`; wick 1 px, body
  1 px minimum so a doji is never invisible. Gridlines `--line-faint`; axis text
  `--text-3` 10 px mono. Price axis **right**, volume axis **right**, time axis
  bottom, 22 px reserved. Crosshair `--text-2` dashed 1 px with a price pill on
  the right axis and a time pill on the bottom axis. MA7 `--info`, MA25 `--warn`
  — indicator lines reuse existing tokens and introduce no new hue.
- **Volume pane** is always visible and always shares the time axis. Volume bars
  are `color-mix(in oklab, var(--buy|--sell) 38%, transparent)`.
- **Keyboard contract for the plot.** The plot is the product's primary surface,
  so it is focusable (`tabindex="0"`, `--focus` ring) and operable from the
  keyboard: `←`/`→` pan, `↑`/`↓` (and `+`/`-`) zoom, `0`/`Home` reset. An
  `aria-describedby` paragraph states the whole contract. **Known limitation:**
  drawing *placement* is still pointer-only; a keyboard coordinate-entry design
  is out of scope for this pass and is not claimed as done.
- Chart data is explicitly non-authoritative. The pane bar carries a
  `LOCAL DATA` / `AWAITING FEED` badge; execution never depends on a chart level.

### 5.4 Right trade ticket (`--ticket-w`)
Top → bottom:

1. **Tabs** — `Market` / `Limit`, 36 px. The active tab takes a `--surface-1`
   fill (attaching it to the pane body below) plus a 2 px `--text-1` underline.
   Selection is neutral, by rule — see §6.
2. **Side control** — a 34 px two-segment control: `Buy` | `Sell`. This is a
   **mode toggle, not two CTAs**: the inactive segment is a transparent ghost, the
   active segment is filled with `--buy-fill` / `--sell-fill`. Never both filled.
3. **Amount** — a 44 px row: 16 px mono right-aligned input, `--surface-2` fill,
   `--control-border` 1 px, and a unit suffix that toggles `SOL ⇄ USD`.
4. **Presets** — one row of four 28 px chips: `25% 50% 75% MAX`. `MAX` is
   visually distinct (it is the only one that can commit the whole balance).
5. **Receive** — `You receive (est.)` label with a 16 px mono value. Unknown ⇒ `—`.
6. **Route row** — `Route` label, the auto-selected available route as a value,
   and a `--text-3` note that routing is auto. Only an *available* route is ever
   selected; an unavailable one is listed disabled with its reason, never hidden.
7. **Advanced** — a collapsed `<details>`; when open it reveals Slippage
   tolerance, Max price impact, Max total cost, and Router preference. Collapsed
   by default so the simple path stays simple.
8. **Primary action** — one button, 44 px, full width, filled with the active
   side's colour and labelled `Review order` / `Place limit order`.
   **When trading is disabled the button is disabled and a single 12 px inline
   reason sits directly above it** — one place, one sentence, no badge stack.
9. **Provenance line** — a 12 px `--text-3` line naming the quote source and its
   age. Present whether or not the quote succeeded.

Rules
- **Exactly one primary-styled button exists in the ticket at any time.**
- Both tab panes stay mounted (`hidden`, not unmounted) so a half-entered order
  survives a tab switch. *(Existing repo decision — preserve it.)*
- The route is never silently substituted. A fallback is a visible state change.
- `Advanced` is `--text-2` when collapsed and `--text-1` when open; the chevron
  rotates over `--motion-base`.

### 5.5 Bottom dock (`--dock-h`)
- Tab strip 34 px on `--surface-2`, **exactly five tabs**:
  **`Positions / Open Orders / Activity / Holders / About`** — the target
  `DockTab` union is
  `"positions" | "orders" | "activity" | "holders" | "about"`.
  Counts render as `—` when unknown — **never `0`**.
- **The former `Trades` tab is removed.** It was only ever a placeholder for a
  market-trades capability, and the exact-token activity feed under
  *Activity → Token* supersedes it. The owner explicitly approved changing the
  union, so the design does not preserve a dead placeholder merely because it
  exists today. *(Note that `RealtimeChannel` also has a `"trades"` member — that
  is a transport channel and is deliberately untouched.)*
  *(History: the first draft of this section listed `Balances`, which is not a dock
  tab, and the second listed `Trades`. Both corrections are recorded rather than
  quietly overwritten.)*
- Body on `--surface-1`, `--space-3` padding.
- **Unavailable capability ⇒ one compact 44 px row**, not a card and not a
  debug dump: a muted `UNAVAILABLE` badge, the surface name, one sentence of
  product prose, and a `<details>` disclosure carrying the raw capability key for
  an operator. The key never dominates the row. **Only surfaces whose capability
  key is real carry a key** — the two remaining placeholder surfaces
  (`positions`, `orders`) are composed from real panels in the application, so
  they state that instead of naming an invented key. **There is no target
  requirement for a `market.trades` capability anywhere in the dock.**
- Empty (capability present, no rows) is a *different* state from unavailable and
  says so: `No open orders.` vs `Open orders are not available on this deployment.`

#### The division of labour between Activity, Holders and About

Each answers exactly one question, and none answers another's:

| Tab | Question | Contains | Never contains |
|---|---|---|---|
| **Activity** | *What is happening?* | the event streams — **Token** scope (the exact token's market events) and **Mine** scope (owner/workspace execution activity) | stable token metadata; holder conviction |
| **Holders** | *Who owns this, and what is their conviction?* | holder position data combined with trader identity and the thesis that trader authored | a second transaction feed |
| **About** | *What is this token?* | identity and links, market snapshot, ownership/supply, flow stats, risk | **any feed, pagination, transaction row or social-feed behaviour** |

This is enforced structurally, not by convention: the token activity feed exists
in exactly one place in the product, and `About` carries **no activity query,
pagination or filter state at all**.

### 5.6 Status bar (`--statusbar-h: 24px`)
A single 24 px strip pinned to the bottom of the viewport, `--surface-1`, top
hairline. It carries provenance and environment truth that has no better home:
data source, snapshot age, and the execution gate. It replaces the current
build's practice of pushing environment prose into the top bar and the dock.

---

## 5A. Token intelligence — the Holders and About panes

*Added in the FOMO intelligence revision. This is an additive extension of Deep
Vault, not a new direction: same tokens, same pane chrome, same data-truth
contract. The dock gains one tab (`about`) and one pane stops being a placeholder
(`holders`).*

### 5A.0 The two rules this section exists to enforce

1. **Availability is per section, not per pane.** `About` draws on four
   independent reads — identity, market snapshot, ownership/supply, flow, risk —
   and `Activity` on two more; a deployment may compose some and not others. One
   pane-wide "unavailable" would hide data the operator actually has; one
   pane-wide "ready" would render fabricated blanks. So **each section gates
   itself.** This is the single most important structural decision in this
   revision, and it is why the PEPE case in the prototype shows a full market
   snapshot and risk section while its *holders* and *token activity* reads say
   they are unavailable.
2. **Derived, never transcribed.** Every figure that *can* be computed from
   another figure *is* computed. Market cap is `circulating × price`. Cost basis is
   `amount × entry`. Unrealised PnL is `amount × (price − entry)`. Total PnL is
   `realised + unrealised`. Nothing on screen can contradict anything else on
   screen, because nothing is written twice.

A third rule follows from the V2 information-architecture correction and is
enforced by the structure rather than by discipline:

3. **One question per tab, and one home per stream.** Activity is the only place a
   chronological event stream is rendered; Holders is the only place a holder's
   thesis appears; About renders no list at all. See §5.5.

### 5A.1 Dock sizing — the constraint that shapes both panes

The dock has a **closed** height and a **desired** height, and a hard ceiling
computed in CSS:

```css
--dock-h: 216px;          /* closed — unchanged, so the chart is unchanged when closed */
--dock-h-expanded: 400px; /* the operator's target when they expand */
--chart-min-h: 392px;     /* 2 pane bars (72) + the 320px plot floor */
--dock-handle-h: 6px;
--dock-h-base: var(--dock-h);
--dock-h-max: calc(100vh - var(--topbar-h) - var(--statusbar-h) - var(--dock-handle-h) - var(--chart-min-h));

.workarea { grid-template-rows: minmax(0,1fr) var(--dock-handle-h)
                                clamp(96px, var(--dock-h-base), var(--dock-h-max)); }
.terminal[data-dock="expanded"] { --dock-h-base: var(--dock-h-expanded); }
```

The clamp lives on the **grid track**, not in the script, so no drag, no toggle
and no future caller can push the chart pane below its floor. Measured result:

| Viewport | Closed | Expanded | Chart pane (expanded) | Plot (expanded) |
|---|---|---|---|---|
| 1920×1080 | 216 | 400 | 594 | 522 |
| 1440×900 | 200 | 400 | 414 | 342 |
| **1366×768** | **176** | **290** | **392** | **320** |
| 980×768 | 144 | 290 | 392 | 320 |

At the 1366×768 target the expanded dock resolves to 290 px — enough for a dense
two-column About pane — and the chart keeps its full 392 px pane and its 320 px
plot floor exactly. **Opening a pane never changes the dock height**; only the
operator's explicit expand or drag does. That is what "About must not reduce chart
height when its dock is closed" means in practice.

Two controls, both keyboard-operable, both memory-only:
- A **toggle** in the tab strip (`aria-expanded`, chevron flips).
- A **6 px resize handle** above the dock, `role="separator"`,
  `aria-orientation="horizontal"`, `aria-valuemin/now/max` kept in sync with the
  live CSS values. ArrowUp/ArrowDown step 16 px (48 with Shift), Home toggles, End
  goes to the ceiling. Its pointer target is 24 px via an `::after` extension, so
  it clears WCAG 2.5.8 outright rather than leaning on the spacing exception.

When depth-of-book is present in the chart pane (the application, not this
prototype), it **yields while the dock is expanded**: `--chart-min-h` then stays
392 in both states and depth collapses to a summary row. The operator's explicit
expansion wins over a secondary pane; that is a direct consequence of their
action, not a media query fighting a choice.

### 5A.2 Mark tile — one primitive, two content types

```
┌────┐   32px (--sm: 20px), --radius-sm (--sm: --radius-xs)
│ SOL│   1px --line border, --surface-3 fill, overflow hidden
└────┘   img: width/height 100%, object-fit: cover
         fallback: --font-mono 10px/600, --tracking-label, UPPER, --text-2
```

The **real token logo** when the provider supplies one; a **typographic monogram**
when it does not — and *always* for a trader, whose avatar is a third party's
photograph and is never fabricated.

`cover`, not `contain`. The real marks arrive with four different background
conventions — transparent (BNB, ETH), near-black (SOL, JUP, RAY, PYTH), saturated
full-bleed (BONK, PEPE) and light/photographic (WIF, AERO, VIRTUAL). `cover` gives
every one the same hard tile edge; `contain` leaves a visible ring of tile tone
around the light and transparent ones, which reads as a broken asset set rather
than a deliberate tile. Provenance and per-address verification for all eleven
marks: `assets/token-logos/SOURCES.md`.

### 5A.3 Holders — holders and traders are one concept

Holders answers *"who owns this token, and what is their conviction?"* Holder
position data and trader identity are **one pane**, never two tabs: the same
address that holds 42,800 tokens is the account that wrote the thesis, and
splitting them would force the operator to join two lists by eye.

Row anatomy, in the order the eye needs it:

```
[mark] Name  @handle  [Verified][Clan][Dev][Followed]        $48,210   +$6,140
       "thesis, one line, ellipsised"                        entry 60.5 · hold 12d · 48.2K followers
```

| Tier | Content | Treatment |
|---|---|---|
| 1 | identity + position value + total PnL | name 13/600 `--text-1`; value 16 px mono/600 `--text-1`; PnL 13 px mono/600 `--buy`/`--sell` |
| 2 | thesis | 12 px `--text-2`, **one line**, ellipsised; absent ⇒ `No thesis authored for this token` in `--text-3` |
| 3 | entry · hold · followers | 10 px mono `--text-3`, right-aligned |
| 4 | wallet address | **never in the row** — only inside the expanded detail, with copy |

Controls
- **Scope**: `Top holders` always; **`Following` only when the provider actually
  returns followed rows.** A scope that can only ever render empty is a broken
  promise, not a feature. If the operator chose Following and then selects a token
  with no followed rows, the pane falls back to `Top holders` and the pressed
  segment says so — the same principle the rail's network filter already follows
  when a network disappears.
- **Sorting**: `Value / PnL / Entry / Hold`, each descending, `aria-pressed`, plus a
  visible order label. **Default is the provider's own authoritative order** and no
  segment is pressed; pressing the active segment returns to it. Equal keys keep
  the provider's order (stable sort), so the default is reproducible. The label
  always states which order is in force.

Rules
- **Selecting a row expands an inline detail beneath it** — the full metric set
  (token amount, average entry, current price, cost basis, unrealised, realised,
  total PnL with percentage, average hold, followers, thesis likes), the full
  thesis, the copyable address, and the total. It does **not** navigate, and it
  does not open a drawer: the in-terminal quick-view drawer is the documented next
  step, not this pass.
- **A holder's thesis lives here and nowhere else.** It is never duplicated into
  About, and it is never repeated in the Activity feed except as the event that
  authored it.
- **Wallet addresses from a fixture are deliberately not plausible.** They render
  as `fixture:xxxxxxxx…xx`. A fabricated string that *looked* like a real on-chain
  address is the single most dangerous thing this prototype could print. A
  *provider-supplied* address is real and is shown normally.
- The tab label is **Holders** (the brief's and the provider's word); the pane
  header says **Holder traders**, which is what the pane actually shows. There is
  no separate Traders tab.

### 5A.4 About — token overview

About answers *"what is this token?"* and nothing else. It is deliberately the
**calm pane**: no feed, no pagination, no transaction rows, nothing that streams.
Every section is stable or aggregate, so the whole pane can be read at a glance
and then ignored.

```
┌── Token profile ──────────┬── Market snapshot ─────────────────────────────┐
│ [logo] Solana             │ Price  24h   MCap   Liquidity   24h Volume     │
│ SOL · Solana              ├── Buy / sell flow ─────────────────────────────┤
│ [progress] 100% graduated │ [5m|1h|4h|24h]                                 │
│ Contract  So111…1112 ⧉    │ Buys Sells BuyVol SellVol UniqB UniqS          │
│ X ↗  Website ↗            │ ▓▓▓▓▓▓▓░░░░░ 58% buy                           │
├── Ownership / supply ─────├── Risk / warnings ─────────────────────────────┤
│ Holders  Top 10 holders   │ [Clear]  Buying Enabled  Selling Enabled      │
│ Circulating  Total supply │ Buy tax —   Sell tax —                        │
│                           │ No provider warnings reported.                 │
└───────────────────────────┴───────────────────────────────────────────────┘
```

Sections, and only these five:

| Section | Content |
|---|---|
| Identity & links | image, name, symbol, chain, **full copyable contract**, launchpad, graduation, token age, X / Website / Telegram / Discord |
| Market snapshot | Price, 24h change, Market Cap, Liquidity, 24h Volume |
| Ownership / supply | holders, top-10 holder %, circulating supply, total supply |
| Buy / sell flow | 5m / 1h / 4h / 24h → buy count, sell count, buy volume, sell volume, unique buyers, unique sellers, and an honest ratio |
| Risk / warnings | the provider's level word, buying/selling availability, warnings, and tax left **unknown** |

Rules
- **Two columns at ≥720 px of *container* width** — a **container query**, not a
  viewport query, because this pane's width depends on whether the rail and ticket
  are open, not on the window. Falls back to one column where container queries are
  unsupported.
- **Sections are hairlines and headers, never cards.** A dock pane already sits
  inside a pane; a bordered, rounded block inside it would stack radii, which §9
  forbids.
- **Social links are omitted when absent, never rendered as disabled ghosts.** A
  note states how many of the four are unpublished, so a partial profile is legible
  as partial rather than as broken.
- **External links** open in a new tab with `rel="noopener noreferrer"`, and carry
  a small outward-arrow glyph so the behaviour is visible before the click.
- **The buy/sell ratio is not rendered when the denominator is zero.** With no
  trades in the window the bar is omitted entirely and the legend reads
  `No trades in this window`. An empty bar would assert a 0% the provider never
  stated.
- **Risk is the provider's word** — `clear` / `hard_risk` / `unknown`, never a
  computed score, and `unknown` is never rendered as safe. **Buy and sell tax stay
  `—`** unless a verified provider supplies them; the pane says why.
- **No activity query, no pagination, no filter state.** The pane cannot grow an
  infinite list because it has no list.
- Fill widths (the ratio bar, the graduation bar) are set through **CSSOM**, never
  an inline `style=` attribute: the payload CSP is `style-src 'self'` with no
  `unsafe-inline`.

### 5A.5 Activity — the single home for event streams

Activity answers *"what is happening?"*, and it is the **only** place in the
product that renders a chronological event stream. There is no second transaction
feed anywhere: not in About, not in a Trades tab, not in a widget.

```
Activity                    [Token | Mine]
──────────────────────────────────────────────────────────────
Token scope:
  [All|Buys|Sells|Transfers|Thesis]   [Filters ▾]
  ● @tape_reader   BUY   $18,400 @ 104.39  mcap $1.2B   22s
  ● @kamino_desk   THESIS  “…”                           1m
  [Newer] [Older]   1–12 of 14 · newest first · REST reconciles the stream

Mine scope:
  [Unavailable] Execution activity — no authoritative execution-history,
  TWAP or RFQ contract is composed for this deployment.        Details
```

**Scope selector — two ways, and the selector is what keeps provenance obvious.**

| Scope | Source | Contains |
|---|---|---|
| **Token** | the authoritative FOMO token activity read | Buy / Sell / Transfer In / Transfer Out / Thesis / other provider types, for the **exact** selected token |
| **Mine** | the owner-scoped `get_execution_progress` reconciliation read | **read-only** owner/workspace execution **status**: the current execution's lifecycle state, chunks, filled/remaining, realised-vs-estimate, halt reason, and its provenance |

**Activity is never a place to start anything.** No TWAP form, no RFQ request, no
execution configuration lives under a tab named *Activity*. Those are execution
**actions**, and their target location is the **trade ticket's Advanced execution
area** — or an explicit Advanced Execution drawer launched from it — behind the
same fail-closed, idempotency, UNKNOWN-outcome and `TRADING_ENABLED` gates as any
other order. See §5A.5b.

Rules
- **Default is automatic**: Token when an exact token is selected *and* its
  activity is available; Mine when it is not. An explicit operator choice always
  wins, and it survives an instrument switch — re-choosing it every time would be
  its own small insult.
- **The two scopes never share a row style and are never interleaved.** Scope is
  the provenance switch; mixing an owner execution row into a market tape would
  make the tape unreadable as a tape.
- **Token scope** carries the kind filter `All / Buys / Sells / Transfers / Thesis`
  and an optional **minimum USD** control behind a compact `Filters` disclosure —
  the filter row stays scannable and the power-user control stays one click away.
- **True pagination**, not an ever-growing list: `Newer` / `Older` plus a
  `1–12 of 84` range, page size 12, so the DOM is bounded by construction.
- **Newest first.** One row per event: mark · handle · kind badge · USD · execution
  price · market cap · age, with the thesis on a second line when the event carries
  one. Colour is never the only carrier — every row carries the word.
- **Pagination resets on instrument change.** Page 3 of token A's activity must
  never be shown as token B's, and stale events from a prior token are never mixed
  in.
- The pager states the reconciliation rule on the surface: *newest first · REST
  reconciles the stream*. A pushed frame may prepend a row **only** on an exact
  `chain + address` identity match; REST remains the reconciliation source.
- **Mine scope is read-only** and renders only what the backend can prove. See
  §5A.5a. It never borrows market rows to look busy, and it never renders a form.

### 5A.5a Mine scope — read-only owner execution activity

Mine answers *"what is my execution doing?"*, and it is a **status surface, not a
console**. It renders exactly one current execution and states plainly that
history is not available, because the only execution read that exists is
`get_execution_progress` — which returns the **current** execution, or one named by
a correlation id. There is no history-list command.

```
┌ Current execution ──────────────────────── [Running] [Adaptive TWAP] ┐
│ exec_7f3a91c4                                                        │
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░  67%                                        │
│ STATE Running   CHUNKS 4/6   PROGRESS 67%                            │
│ FILLED 12.40 SOL   REMAINING 5.60 SOL                                │
│ REALISED VS ESTIMATE −18 bps                                         │
│ Owner-scoped reconciliation read · updated 3s ago · this is a        │
│ current-status surface, not a history                                │
├ Execution history ────────────────────────────────────────────────────┤
│ [Unavailable] No authoritative execution-history contract is          │
│ composed. Only the current execution can be read, so no historical     │
│ rows are shown.                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**A truthful current-status surface is worth more than a fabricated tape.** The
history section is a permanent, honest unavailable row — never a list padded with
invented rows to look like a working feature.

Fields, all from `ExecutionProgress` and nothing else:

| Field | Source | Unknown ⇒ |
|---|---|---|
| State | `state` — `planning` / `running` / `halted` / `completed` / `failed` / `unknown` | `Unknown`, never "safe" |
| Kind | `kind` — `twap` / `rfq` | — |
| Chunks | `chunksDone` / `chunksTotal` | `—` |
| Progress | derived `done / total` | `—`, and the bar is omitted |
| Filled / Remaining | `filledAmount` / `remainingAmount` | `—` |
| Realised vs estimate | `realizedVsEstimateBps` | `—` |
| Halt reason | `haltReason` | the line is omitted |
| Provenance | the read's source and age | — |

Three states that must never be conflated:

| State | Condition | Rendering |
|---|---|---|
| **Running / halted / …** | the read returned an execution | the status block, with the lifecycle badge |
| **Idle** | the read succeeded and returned nothing | `No execution is running for this workspace.` — a *normal* state, not an error |
| **Unavailable** | the read is not composed, or the command channel is not up | the 44 px compact row. Per the repo's own note, this must surface as *awaiting the channel* rather than as an unqueried empty, or a stalled handoff would show "no execution running" forever |

Rules
- **Progress uses the chunk ratio, never a parsed amount.** `filledAmount` and
  `remainingAmount` are opaque strings; dividing them would be inventing a number.
  The bar appears only when `chunksTotal > 0`.
- **No ratio without a denominator**, the same rule as the buy/sell bar.
- **State colour is never the only carrier** — every state carries its word.

### 5A.5b Where the mutating execution controls live

Adaptive TWAP and RFQ / solver competition are **execution actions**. They are not
activity, and they must not be reachable from a tab named *Activity*.

**Placement rule (implementation, not a ticket redesign):** the mutating controls
move to the **trade ticket → Advanced execution** — either inside the ticket's
existing `.ticket__advanced` disclosure, or behind a single entry point in it that
opens an **Advanced Execution drawer**. The drawer is the recommended default: the
two forms are large, and inlining them would push the ticket's Advanced section past
usability at 1366×768. The `SecurityDrawer` pattern is the one to copy
(`role="dialog"`, `aria-modal`, `aria-labelledby`, `tabindex="-1"`, Escape closes,
focus returns to the invoking control).

**Every existing gate is retained, unchanged.** Moving a control must not weaken a
guard:

- fail-closed defaults on every submission path;
- the idempotency / submission-key tracking;
- the UNKNOWN-outcome guard, including its two-step acknowledgement before release
  and the rule that an UNKNOWN is deliberately **not** cleared by switching source;
- the `TRADING_ENABLED` gate;
- `mutationDenial("twap")` / `mutationDenial("rfq")` and the fail-closed reasons
  they carry;
- the rule that the browser never calls a provider directly.

This is a **move, not a rewrite**: the panel's logic, state machine and guards are
carried across intact, and only its mount point changes.

### 5A.6 Provenance and honest states

Every intelligence surface states where its data came from, in product language,
on itself — never a command name and never a backend error string.

| State | Rendering |
|---|---|
| Ready | the pane, plus a `FIXTURE` badge and one provenance sentence in this prototype |
| Stale | a compact `Stale · 4m` ribbon with a clock glyph, **on the section that is stale** (market snapshot), not a pane-wide alarm |
| Partial | the missing field is `—`; a trader without a thesis says so in its own row; a partly-published profile says how many links are missing |
| Unavailable | the 44 px compact row — badge, one product sentence, and a `<details>` carrying the **real** capability key |
| Empty | a *different* sentence from unavailable: `No activity matches this filter.` |

The capability key is **`intelligence`**, a real member of the application's
`CapabilityKey` union that already gates `IntelligencePanel` and `PortfolioPanel`.
No key is invented for this revision, and **no key is required for a
market-trades capability** — the surface that used to claim one is gone.

---

## 6. Accent discipline

`--accent` (amber) is the **instrument** signal, and nothing else. It has exactly
two rendered uses per screen, both of them persistent:

| The only two permitted uses | Not permitted |
|---|---|
| The brand mark (6 × 18 px amber rule) | **Selection of any kind** — tabs, chips, rows, tools, timeframes |
| The 2 px instrument price rule | Button fills, link colour, focus rings (`--focus` is its own token) |
| | Chart indicator lines (`--info`/`--warn`), chart drawings, price changes (`--buy`/`--sell`) |
| | Any icon, badge, border or hover state |

**Why the selection family is *not* amber — and this is a change from the first
draft of this document.** The earlier rule was "two *prominent* amber elements per
screen", with the active tab, the active filter chip and the selected row counted
as one "selection family" that shared the budget. That rule is unenforceable,
because the selection family is **persistent**, not transient: a row is always
selected, a tab is always active, a filter chip is always active. The built
prototype therefore rendered **five** amber elements at rest — brand mark, price
rule, tab underline, chip text+border+wash, and the row's left marker — against a
stated budget of two. The practical result was the exact failure the direction set
out to avoid: amber read as *the interactive colour*, which is what a generic
dashboard looks like, and the one deliberate flourish was drowned by four
competitors of equal chroma.

So the rule is now structural rather than a count:

> **Hover moves the fill. Selection is carried by a rule or a boundary. Neither
> ever spends the accent.**

In practice:

| Selection | How it is marked |
|---|---|
| Active tab | `--surface-1` fill (attached to the pane body) + 2 px `--text-1` underline |
| Active network filter chip | `--surface-3` fill + `--text-1` label + `--text-2` boundary |
| Selected market row | `--surface-3` fill + 2 px `--text-2` left marker |
| Active timeframe | `--surface-3` fill + 2 px `--text-1` inset rule |
| Armed drawing tool / selected drawing | `--text-1` |
| Indicator toggle (on/off, not a selection) | `--surface-3` fill + 2 px `--control-border` inset rule |

`--accent-soft` (16% amber) survives only as the text-selection wash
(`::selection`). It is not a hover or wash token any more, because there is no
amber control left to hover.

Directional colour (`--buy` / `--sell`) is **data**, not accent. It is confined to
price changes, side selection, depth bars, candles and order state — and it must
never be the *only* carrier of meaning: every buy/sell affordance pairs colour with
a text label. Amber is never used to mean "up".

### Why the Buy/Sell control is a filled segment and the CTA is also filled

This is deliberate and is not a violation of "one primary CTA". The Buy/Sell
control is a **parameter selector** — it chooses which side the order is on — not
an action. The action is `Review order`, and exactly one such button exists in the
ticket at a time. The two are separated by the whole form, differ by an order of
magnitude in size (28 px segment vs 44 px full-width button), and differ in
position (top of the form vs bottom). What the filled segment buys is legibility:
in the shipped deployment trading is disabled, so the CTA renders disabled and the
side control is the ticket's only colour anchor — remove it and Buy/Sell stops
being scannable. The rule the design actually enforces is stricter than "one filled
button": **never two filled controls adjacent to each other**, and never two
buttons that submit the same intent. Note that this is directional colour, not
accent — it does not touch the amber budget.

---

## 7. Interaction states

Every interactive element defines **all six** states. Foreground/background are
specified as a pair, and **contrast after a state change is never lower than the
default state.**

| State | Surface | Foreground | Border | Notes |
|---|---|---|---|---|
| Default (row) | `--surface-1` | `--text-1` / `--text-3` | none | |
| Hover (row) | `--surface-2` | unchanged | none | Fill moves, text does not |
| Selected (row) | `--surface-3` | `--text-1` | 2 px `--text-2` left | + `aria-pressed="true"` |
| Focus-visible | unchanged | unchanged | — | `box-shadow: var(--focus-ring)` |
| Active/pressed | `--surface-3` | unchanged | — | `transform: translateY(1px)` |
| Disabled | unchanged | `--text-3` | `--line` | The **only** state allowed to lose contrast |

| State | Control (button/input) |
|---|---|
| Default | bg `--surface-2`, fg `--text-1`, border 1px `--control-border` |
| Hover | bg `--surface-3`, fg `--text-1`, border 1px `--line-strong` |
| **Selected** | bg `--surface-3`, fg `--text-1`, border 1px `--text-2` |
| Focus-visible | unchanged bg/fg + `--focus-ring` |
| Active | bg `--surface-3`, `translateY(1px)` |
| Disabled | bg `--surface-1`, fg `--text-3`, border `--line`, `cursor: not-allowed` |

The **Selected (control)** row is the one that was missing from the first draft,
and its absence is what let the accent leak into tab, chip and toolbar states.
The rule it encodes: hover and selection may share a fill, so **selection must
carry a second, independent signal** — a boundary, a rule, or an inset marker.
`--text-2` and `--text-1` are the only two values used for that signal, because
they are the only ramp values that clear 3:1 against `--surface-3`
(`--text-2` 7.21:1, `--text-1` 13.74:1; `--control-border` is 3.22:1 and
`--line-strong` only 1.44:1, so neither can mark a selection).

| State | Primary action (side-coloured) |
|---|---|
| Buy default | bg `--buy-fill`, fg `--buy-ink` (8.1:1) |
| Buy hover | bg `--buy-hover`, fg `--buy-ink` |
| Sell default | bg `--sell-fill`, fg `--sell-ink` (5.3:1) |
| Sell hover | bg `--sell-hover`, fg `--sell-ink` |
| Disabled | bg `--surface-2`, fg `--text-3`, border `--line` |

Additional rules
- Hover moves the **background** by one surface step, never the text toward the
  background. Text that becomes lighter/more muted on hover is forbidden.
- **Recorded trade-off on row hover.** Because a row's hover lifts the fill from
  `--surface-1` to `--surface-2` while the foreground stays `--text-1`, the
  measured ratio moves from 15.95:1 to 14.98:1 — a 6% decrease, and the only
  place in the system where a state change lowers the number at all. This is
  deliberate and is the mechanism §7 prescribes ("fill moves, text does not").
  Any lighter hover fill in any dark UI produces it, both values are more than
  three times the 4.5:1 floor, and the rule the system actually enforces is the
  one that matters for legibility: **the foreground never moves toward the
  background.** Where a hover must not reduce the ratio at all, move the border
  or the position instead — as the control states above do.
- Focus ring is `0 0 0 2px var(--surface-1), 0 0 0 4px var(--focus)` — a 2 px
  surface-coloured spacer plus a 2 px visible ring, so the ring is legible on
  every surface and meets WCAG 2.4.13's 2 px perimeter.
- The ring is never removed. `outline: none` without a replacement is a defect.
- A price cell that receives a tick flashes its background toward
  `color-mix(in oklab, var(--buy|--sell) 18%, transparent)` over
  `--motion-flash`, then settles. The **value is retained until the new value is
  painted** so a fast market never produces a blank cell.
- `@media (prefers-reduced-motion: reduce)` sets `--motion-fast/base/flash` to
  `0ms` and removes the press transform. Opacity and colour transitions are kept.

---

## 8. Responsive behaviour

The terminal is desktop-first and **never scrolls horizontally**.

| Width | Rail | Ticket | Dock | Stat strip | Behaviour |
|---|---|---|---|---|---|
| ≥ 1800 | 280px | 352px | 216px (exp 400) | Mcap · Liquidity · Volume 24h · 24h range | Full |
| 1600–1799 | 280px | 344px | 200px (exp 400) | all four | Full |
| 1440–1599 | 264px | 344px | 200px (exp 400) | all four | Full |
| 1280–1439 | 248px | 328px | 176px (exp 400) | Mcap · 24h range | `data-fold="1"` folds (Liquidity, Volume 24h) |
| 1180–1279 | 0 (toggleable) | 320px | 160px (exp 322) | Mcap | `data-fold="2"` folds (24h range); rail auto-collapses |
| 980–1179 | 0 (toggleable) | overlay | 144px (exp 290) | Mcap | Ticket becomes a right overlay drawer |
| < 980 | 0 (overlay) | overlay | 128px (exp 290) | Mcap | Both rail and ticket are overlays; chart keeps the viewport |

The expanded column is the value after the CSS clamp, and it is what the dock
actually gets. At the 1366×768 target the clamp resolves to 290 px so the chart
keeps its full 392 px pane and 320 px plot. Full derivation in §5A.1.

The stat strip is the only element that folds, and it folds **whole stats**. At
1366 px — a named target resolution — the fixed top-bar chrome is ≈972 px, leaving
≈394 px; the full four-stat strip needs ≈374 px, which is inside the available
width by ~20 px and therefore a real clipping risk, and `.statstrip` is
`overflow: hidden`, so the failure mode would be a numeric truncated mid-value.
Folding `data-fold="1"` leaves ≈199 px of need against ≈394 px available — ~195 px
of slack. Measured slack by tier: **94 px at 1440, 109 px at 1280**, and 245 px
below that. *(An earlier draft of this table claimed 1366–1439 showed
Price · 24H · MCap only; neither the artifact nor this table now says that, and
the fold markers `data-fold="1"` / `data-fold="2"` are the single source of truth.)*

Rules
- The chart pane **never** drops below 480 px wide or 320 px tall. Below that the
  rail collapses first, then the dock, then the ticket becomes an overlay.
- Crossing a breakpoint collapses a pane but **never force-expands** one — an
  explicit operator choice is not fought by a media query.
- The top bar keeps its 56 px single-row contract at every width; content folds
  in the order stat-strip → instrument identity tooltip → badges.
- Touch/pointer targets: every control is ≥ 24×24 (WCAG 2.5.8 AA) and the primary
  action is ≥ 44×44 (WCAG 2.5.5 AAA, and the desktop pointer comfort floor).
  Where a dense control is smaller than 24 px in one axis — the `.seg` group's
  22 px inner buttons — it must satisfy the 2.5.8 **spacing exception**: its
  24 px exclusion circle must not intersect an adjacent target's. Anything that
  cannot satisfy the exception is 24 px or larger outright.

---

## 9. Anti-patterns — explicit prohibitions

**Layout**
- No floating cards inside panes; no shadow on any pane.
- No nested rounded containers. Radii do not stack.
- No pill shapes outside the network filter chips and status dots.
- No giant empty state. An unavailable surface is one 44 px row.
- No control, legend or toolbar overlapping the plot area or the price/time scales.
- No more than two levels of horizontal divider inside a single pane.

**Colour**
- No gradients on any background, pane, button or badge.
- No neon glow, no coloured box-shadow, no `filter: drop-shadow` as decoration.
- No amber as a CTA fill, link colour, focus ring, or **selection state of any
  kind**. If amber appears anywhere other than the brand mark and the instrument
  price rule, the design is wrong — see §6.
- No new hue. If it is not in §2, it does not ship.
- Green and red are never the sole carrier of meaning.
- No pure `#000` background and no pure `#fff` text.
- No badge tint above 8% of its semantic colour: the danger tone's own text stops
  clearing 4.5:1 against its tint at 12%.

**Layout**
- No stat or numeric value clipped mid-figure. `overflow: hidden` is a last-resort
  guard, never the mechanism: fold whole stats at breakpoints instead (§8). A
  truncated price is worse than an absent one, because it reads as a complete
  number.
- No card inside a pane. The intelligence panes divide themselves with hairlines
  and section headers; a bordered, rounded block inside a dock pane stacks radii
  and reads as a dashboard widget (§5A.4).
- No feed that grows without bound. Activity is paginated at a fixed page size, so
  the DOM has a ceiling the operator can reason about (§5A.5).
- No pane-wide unavailable state where per-section availability is possible. Gate
  the section that is missing, not the pane that contains it (§5A.0).
- No dock expansion that can breach the chart floor. The clamp belongs on the grid
  track, not in a script (§5A.1).

**Intelligence data — added in the FOMO revision**
- **No mutating control in a read-only surface.** Activity is a view. No submit, no
  configuration, no control that changes server state belongs in a tab named
  *Activity*. A **read-only filter** — the minimum-USD input under Token scope — is
  not a mutating control and is allowed; an execution form is not. Execution actions
  live in the trade ticket (§5A.5b). The testable form of this rule: the **Mine**
  subtree contains zero `<button>` and zero `<input>`.
- **No fabricated history.** When only a current-status read exists, the surface
  shows the current status and says history is unavailable. Padding a list with
  invented rows to look like a working feature is worse than an honest gap.
- **No ratio built from an opaque string.** `filledAmount` and `remainingAmount`
  are provider strings; dividing them invents a number. Ratios use numeric fields
  with a real denominator, or they are not rendered.
- **No conflating idle with unavailable.** "Nothing is running" and "the read is
  not composed" are different facts and get different sentences.
- **No second transaction feed.** The chronological event stream exists in exactly
  one place — Activity — and no other tab, pane or widget renders one. About
  renders no list at all (§5.5).
- **No mixing scopes.** An owner execution row never appears in a market tape and
  vice versa. The scope selector is the provenance switch, and provenance is not
  a styling detail.
- **No feed, pagination or filter state in About.** The pane cannot grow an
  infinite list because it has no list. If a section needs paging, it belongs in
  Activity.
- **No fabricated wallet address.** A fixture or placeholder address must be
  visibly not-a-real-address (`fixture:…`), never a plausible base58 or `0x`
  string. A convincing fake address is the single most dangerous thing this
  product could print.
- **No fabricated trader identity.** A trader avatar is a third party's
  photograph; when the provider supplies none, the mark is a typographic monogram.
  Never generate, draw or source a stand-in face.
- **No fabricated token brand mark.** Token logos are real third-party brand
  assets, keyed by **exact contract address** and never by symbol or name. If the
  correct mark cannot be acquired, the typographic monogram is the fallback.
- **No ratio without a denominator.** A buy/sell bar is not rendered when the
  window has no trades — an empty bar asserts a 0% the provider never stated.
- **No scope that can only render empty.** An internal control that filters to
  nothing is omitted, not shown disabled — a `Following` segment appears only when
  the provider actually returns followed rows.
- **No transcribing a figure that can be derived.** Market cap, cost basis,
  unrealised PnL and total PnL are computed from their inputs so they cannot
  contradict each other (§5A.0).
- **No raw provider field or tool name in a primary surface.** `fomo_get_token`,
  `averageHoldTimeSeconds`, `top10HoldersPercent` and their siblings live in the
  handoff document and inside a `<details>` disclosure, never on the face of the
  product.
- **No dead placeholder preserved for its own sake.** A tab that only ever renders
  "unavailable" and is superseded by a real surface is deleted, not kept green.

**Content**
- No invented numeric risk score. Risk is `clear` / `warning` / `restricted` /
  `unknown` — the provider's word.
- No invented buy/sell tax. `—` unless a verified provider supplies it.
- No `0` standing in for an unknown value, anywhere, ever.
- No lorem ipsum, no `Feature one`, no placeholder prose.
- No raw capability keys, stack traces or backend error text in a primary surface.
  They belong inside a `<details>` disclosure, one click away.
- No emoji as icons. Icons are 1.5 px-stroke monoline SVG on `currentColor`, or a
  mono glyph where the repo already uses one.

**Interaction**
- No hover state that lowers text contrast.
- No `outline: none` without a replacement ring.
- No `tabindex` greater than 0.
- No `<div role="button">` where a `<button>` will do.
- No animation on a state change that has not already happened (optimistic UI
  first, motion confirms it second).
- No animation longer than 500 ms on a non-navigation transition.
- No `scrollIntoView()` — it breaks the embedded preview. Use `scrollTo()`.

**Data**
- No chart level used as an execution input. Chart data is visual only.
- No silent route substitution.
- No silent timeframe substitution: an unserved window is refused, not coerced.

---

## 10. Accessibility contract

| Requirement | Target | How |
|---|---|---|
| Body text contrast | ≥ 4.5:1 | Measured: `--text-1` 13.7:1 worst case, `--text-2` 7.2:1, `--text-3` 4.7:1 |
| Large text / numeric display | ≥ 3:1 | `--text-1` 15.9:1 on `--surface-1` |
| Control boundary | ≥ 3:1 | `--control-border` `#5b7288` = 3.74:1 on `--surface-1`, 3.51:1 on `--surface-2`, **3.22:1 on `--surface-3`** (the worst case, and a real one: `.input:hover` and `.unitbtn:hover` both move to `--surface-3`) |
| Focus indicator | ≥ 3:1, ≥2 px perimeter | `--focus` `#7fb2ff` = 8.63:1 on `--surface-1` |
| Target size | ≥ 24×24 AA, 44×44 primary | `--control-xs` 24px, `--control-sm` 28px, `--control-lg` 44px; the `.seg` group's 22px inner buttons rely on the 2.5.8 spacing exception |
| Keyboard | Every control reachable and operable | Native `<button>`/`<input>`/`<select>`; `role="tablist"` + `aria-selected` **+ Left/Right/Home/End navigation with roving `tabindex`** (the roles promise it, so it must exist); the chart canvas is focusable with arrow-key pan, +/− zoom and 0 to reset |
| Form labels | Visible label, not placeholder-only | Every input has a `<label for>`; hints via `aria-describedby` |
| Live regions | Status changes announced | `role="status"` on connection/gate/copy feedback |
| Document language | `<html lang>` present | Required |
| Landmarks | `header` / `aside` / `main` / `footer` | Rail, ticket and dock are `aside`; chart is `main` |
| Heading order | One `h1`, no skipped levels | `h1` = instrument symbol; pane titles `h2` |
| Reduced motion | Honoured | `prefers-reduced-motion` zeroes motion tokens |
| Text alternatives | Every chart and icon | Chart host carries an `aria-label` with symbol + timeframe + last close; icon buttons carry `aria-label` |
| Resizable pane | A separator is operable, not just draggable | The dock handle is `role="separator"` + `aria-orientation` + live `aria-valuemin/now/max`, with Arrow/Home/End keys; its pointer target is extended to 24 px so it clears 2.5.8 outright |
| External links | Safe and announced | `target="_blank"` + `rel="noopener noreferrer"`, a visible outward-arrow glyph, and a `title` stating that it opens in a new tab |

Measured contrast (WCAG 2.x relative luminance; `--surface-3` is the worst case,
and tinted backgrounds are composited over it the way the browser composites them):

```
text-1 #e8eef2  13.74:1  on surface-3
text-2 #9fb0bd   7.21:1  on surface-3
text-3 #7a8d9b   4.68:1  on surface-3   ← the floor; nothing dimmer may carry text
buy    #2fbf8f   6.87:1  on surface-3
sell   #ea5a5f   4.69:1  on surface-3   ← a down-change can sit on a selected row
warn   #e5b94a   8.71:1  on surface-3
info   #5b9dff   5.91:1  on surface-3
focus  #7fb2ff   7.44:1  on surface-3
accent #e9b44c   8.50:1  on surface-3

control-border #5b7288   3.74 / 3.51 / 3.22  on surface-1 / 2 / 3
selected-control boundary: --text-2 on --surface-3  7.21:1
                           --text-1 on --surface-3 13.74:1

buy-ink  #04140e on buy-fill  #2fbf8f   8.07:1
sell-ink #ffffff on sell-fill #c9302f   5.32:1
accent-ink #1a1204 on accent  #e9b44c   9.80:1

tinted badges at 8% of their semantic colour:
  danger #ea5a5f  4.72:1 on the tint over surface-2   ← the binding constraint
  buy    #2fbf8f  6.61:1 on the tint over surface-1
  warn   #e5b94a  8.14:1 on the tint over surface-1
  info   #5b9dff  5.76:1 on the tint over surface-1
```

The badge tint is **8%**, not 12%. At 12% the danger badge's own 10 px text
measured **4.47:1** against its tint over `--surface-2` — a fail on the 4.5:1
floor for normal text, and one the artifact only escaped because the
`TRADING DISABLED` badge happens to sit on `--surface-1` rather than
`--surface-2`. Passing by placement is not passing. At 8% the worst case is
4.72:1 regardless of where the badge lands.

---

## 11. Implementation mapping — SolidJS components

Full file-by-file mapping is in `IMPLEMENTATION_HANDOFF.md`. Summary:

| Design region | Component | Key change |
|---|---|---|
| Viewport grid | `app/AppShell.tsx` | Add the status bar row; keep named grid areas |
| Top instrument bar | `components/layout/TerminalHeader.tsx` | Restructure to brand → identity → price block → stat strip → status cluster; remove `TokenSearch` from the bar |
| Market rail | `components/layout/MarketRail.tsx` | Move `TokenSearch` in; 32 px two-column rows; address → tooltip; add the honest-count network filter |
| Chart pane | `chart/ChartPanel.tsx` | Two pane bars; crosshair OHLC readout into bar 1; drawing toolbar into bar 2; all six drawing tools |
| Trade ticket | `components/layout/TradeTicket.tsx` + `features/trade/TradePanel.tsx` | Segmented side control; presets; route row; collapsed Advanced; one 44 px primary action |
| Bottom dock | `components/layout/BottomDock.tsx` | 34 px tab strip; **`DockTab` becomes `positions \| orders \| activity \| holders \| about`**; Trades removed; `—` counts; 44 px compact unavailable row with a real capability key only |
| Dock sizing | `components/layout/BottomDock.tsx` + `state/workstation.tsx` | 6 px `role="separator"` resize handle + expand toggle; `dockHeight` / `dockExpanded` memory-only state; the CSS clamp on the grid track keeps the chart floor |
| Activity | **new** `features/intelligence/ActivityWorkspace.tsx` | Owns the Token \| Mine scope; Token = the exact-token feed, Mine = the **read-only** owner execution status; auto-scope when the operator has not chosen |
| Token activity | **new** `features/intelligence/TokenActivity.tsx` | Kind filter (All / Buys / Sells / Transfers / Thesis), min-USD behind a `Filters` disclosure, true pagination, exact-identity prepend |
| Mine status | **new** `features/intelligence/OwnerExecutionActivityPanel.tsx` | **Read-only.** Current execution status from `get_execution_progress`, plus a permanent honest history-unavailable row. No form, no submit, no configuration |
| Mutating execution | `features/execution/ExecutionPanel.tsx` | **Moves out of Activity** to the trade ticket's Advanced execution area (recommended: an Advanced Execution drawer launched from `.ticket__advanced`). All fail-closed, idempotency, UNKNOWN and `TRADING_ENABLED` gates retained unchanged |
| Holders / traders | **new** `features/intelligence/HolderTradersPanel.tsx` | The sole Holders implementation: holder position data + trader identity + authored thesis; `Top holders` / `Following` (the latter only when provable); 4-way sort defaulting to provider order |
| About / token overview | **new** `features/intelligence/TokenOverviewPanel.tsx` | Five sections only — identity & links, market snapshot, ownership/supply, flow, risk. **No activity query, no pagination, no filter state** |
| Intelligence queries | **new** `features/intelligence/queries.ts` | Lazy reads keyed by exact `(chain, networkId, address)`; capability key `intelligence`; stale TTL 60 s; never joined by symbol or name |
| Mark tile | **new** `components/ui/MarkTile.tsx` | 32/20 px tile, real logo when the provider supplies one, typographic monogram fallback; `assets/token-logos/` holds the eleven verified marks |
| Tokens | `web/workspace-payload/src/style.css` | Replace the `:root` block with §2; keep the legacy aliases resolving |
| Formatters | `core/format.ts` | No change required — already em-dash-safe |

**Preserve, do not regress:** the named grid areas, the memory-only pane state,
the two-tab ticket that keeps both panes mounted, the `ohlcv:<chain>:<address>`
entity-key isolation, `SERVED_TIMEFRAME_IDS`, the `DataState` union, and every
fail-closed gate. This design changes appearance and information hierarchy only.
