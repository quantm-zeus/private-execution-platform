# EverCrest / PEP Terminal — Three Design Directions

> **Phase:** requirements clarification → direction exploration.
> **Scope:** visual treatment only. All three directions carry the **same information
> architecture** (top instrument bar → left market rail → centre chart → right trade
> ticket → bottom dock) and the **same data-integrity contract** (unknown ⇒ `—`,
> provider-truthful risk, fail-closed execution). Only the visual system differs.
> **Inputs inspected before designing:** `web/workspace-payload/src/style.css`
> (2 446 lines, the current Evergreen Terminal token set), `AppShell.tsx`,
> `TerminalHeader.tsx`, `MarketRail.tsx`, `TradeTicket.tsx`, `BottomDock.tsx`,
> `ChartPanel.tsx`, `components/ui/*`, `core/format.ts`, `contracts/market.ts`,
> `state/workstation.tsx`, `market/ohlcv.ts`, plus `docs/WEB_PRODUCT_ROADMAP.md`
> and `STATUS.md` for what is actually composed vs fail-closed.
>
> **Reference systems inspected as inspiration only** (never cloned):
> `design-systems/binance`, `design-systems/coinbase`, `design-systems/kraken`,
> `design-systems/linear-app`, `design-systems/trading-terminal`.

---

## 0. What the repo already establishes (constraints I must respect or deliberately supersede)

| Existing decision | Evidence | Verdict |
|---|---|---|
| Dark-only, `color-scheme: dark` | `style.css:12` | **Keep.** Dim-environment focus is correct for a trading desk. |
| Amber instrument accent `#e9b44c`, deliberately *not* acid-green-on-black | `style.css:27–31` comment | **Keep the thesis**, retune the value and ration its role. |
| 4 px spacing grid, dense control heights (28/34 px), `--row-h: 32px` | `style.css:52–77` | **Keep.** This is already exchange-grade. |
| Geometry tokens `--topbar-h: 52px`, `--rail-w: 264px`, `--ticket-w: 352px`, `--dock-h: 216px` | `style.css:79–83` | **Keep the names**, retune values per breakpoint. |
| Radii 4/6/8 px, borders-over-cards | `style.css:62–67` | **Keep.** Correct instinct; make the hairline system two-weight. |
| `system-ui` for both display and body, no distinct display face | `style.css:85–88` | **Supersede.** Hierarchy is flat at the identity level; a data-dense terminal still needs a display/instrument face. |
| Single border weight (`--line`) + one strong | `style.css:19–20` | **Supersede.** A 4-level surface ladder needs 3 border weights to read. |
| Accent used on tabs, focus, selection, chips, skip-link | `style.css:174–205, 899–902, 2411` | **Supersede.** Amber currently leaks; it must be rationed to ≤2 prominent uses per screen. |

**Cross-reference-system numbers that recur** (from the five reference systems):
dark canvases cluster at `#070b12 / #08090a / #0b1020 / #0d0d0d`; dark surfaces at
`#101826 / #121a33 / #141414 / #191a1b`; dark borders at `#263246 / #2a2a2a /
rgba(255,255,255,0.08)`; up/down pairs at `#0ecb81/#f6465d` (Binance),
`#00c853/#ff4d6d` (Kraken), `#22c55e/#ef4444` (generic), `#00d4aa/#ff4757`
(Bloomberg-style). Terminal radii cluster at **4–12 px**, never pill. Base body
size clusters at **12–15 px** for terminals, 16 px for consumer fintech. Every
trading system puts **numerics in a monospace with tabular figures**. No
reference system uses a display serif — the "display" role in this category is
carried by the numeric/mono face.

---

## Direction A — **Deep Vault**

*Opaque layered slate. Borders define panes. Amber is the instrument.*

### Thesis
A trading terminal is read under load, at speed, with three dense panes competing
for attention. **Pane legibility is the primary visual problem**, and it is solved
with an opaque surface ladder plus a two-weight hairline system — never with
floating cards, never with fills that shift under scroll. This is the direction
that extends the repo's own instinct and finishes it.

### Palette
| Role | Value | Notes |
|---|---|---|
| `--surface-0` canvas | `#080c11` | Cool near-black, blue undertone. Not `#000`. |
| `--surface-1` pane | `#0d131a` | Rail, ticket, dock, top bar. |
| `--surface-2` row/raised | `#121a23` | Table rows, chips, inputs. |
| `--surface-3` hover/inset | `#18222d` | Hover, active row, code wells. |
| `--line` | `#1e2a36` | Pane edges, row separators. |
| `--line-strong` | `#2c3d4d` | Control borders, focused inputs. |
| `--line-faint` | `#151d26` | Intra-pane row rules, grid. |
| `--text-1` | `#e8eef2` | Values, symbols, headings. |
| `--text-2` | `#9fb0bd` | Labels, secondary stats. |
| `--text-3` | `#6b7d8b` | Timestamps, disabled, axis. |
| `--accent` | `#e9b44c` | Instrument amber. Selection + one focal element. |
| `--buy` / `--sell` | `#2fbf8f` / `#e5484d` | Directional data only. |

### Typography
- **Instrument / display / numerics:** `ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace`
- **UI labels / body:** `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`
- Scale: 11 · 12 · 13 · 14 · 16 · 20 · 26 px. Display tracking `-0.02em`; ALL-CAPS labels `+0.07em`.
- Numerics: `font-variant-numeric: tabular-nums` globally on the terminal root.

### Layout
12-column-free; explicit pane grid `264px | 1fr | 352px` with `56px` top bar and
`216px` dock. Pane padding 12–16 px. Row height 32 px. Control height 28/34 px.

### Chrome & depth
Two elevation levels only: flat, and `--elev-raised: 0 2px 8px rgba(0,0,0,.45)`
reserved for the search popover and the security drawer. **No shadows on panes.**

### Why it might win
Highest pane legibility; cheapest implementation mapping (token names already
exist); matches trader expectations from OKX/Binance/Kraken without copying any.

### Why it might lose
Opaque ladders are the *safe* answer. With the amber left at its current value and
usage, it risks reading as "the current app, slightly tidier" rather than a step
change. Needs a decisive typographic move to avoid that.

---

## Direction B — **Graphite Hairline**

*Near-achromatic, zero-fill, translucent hairlines, one cool signal.*

### Thesis
Strip every fill. Panes are not boxes — they are regions delimited by
`rgba(255,255,255,0.06)` hairlines on a single `#08090a` canvas, and hierarchy is
carried almost entirely by **typography and luminance**, not by surface tone. The
most restrained, most "premium software" of the three.

### Palette
| Role | Value | Notes |
|---|---|---|
| `--surface-0` canvas | `#08090a` | One canvas for the whole viewport. |
| `--surface-1` | `rgba(255,255,255,0.02)` | Barely-there pane tint. |
| `--surface-2` | `rgba(255,255,255,0.04)` | Hover, inputs, chips. |
| `--line` | `rgba(255,255,255,0.06)` | Pane edges. |
| `--line-strong` | `rgba(255,255,255,0.11)` | Control borders. |
| `--text-1` | `#f2f4f6` | |
| `--text-2` | `#8b939c` | |
| `--text-3` | `#5d646c` | |
| `--accent` | `#7cc4ff` | Cool signal blue. |
| `--buy` / `--sell` | `#34d399` / `#f87171` | Softened for the achromatic field. |

### Typography
- **Display:** `"Inter Variable", Inter, system-ui, sans-serif` at weight 510, tracking `-0.022em`
- **Numerics:** `"Berkeley Mono", ui-monospace, "SF Mono", Menlo, monospace`
- Scale: 11 · 12 · 13 · 15 · 18 · 24 px.

### Layout
Same pane grid, but panes are separated by **24 px gutters of pure canvas** rather
than by adjacent edges — the "void as separator" model. Pane padding 16–20 px.
Row height 34 px. Control height 32 px.

### Chrome & depth
Ring elevation only: `0 0 0 1px rgba(255,255,255,0.06)`. No blur shadows anywhere.

### Why it might win
Highest perceived craft; the calmest surface under a 12-hour session; the
strongest "shipped by a top-tier product team" signal.

### Why it might lose
**Zero-fill fails at density.** With the rail, the dock and the ticket all
carrying 11–13 px numerals, hairline-only separation collapses: pane boundaries
disappear behind data, and the eye loses the chart/ticket/dock hierarchy that a
trader depends on. Translucent borders also resolve differently against the
canvas vs. a chart's own background, so the chart pane edge flickers visually.
Gutter separation costs ~48 px of horizontal budget — real money at 1366 px.

---

## Direction C — **Instrument Grid**

*Recessed wells, warm-neutral graphite, mono-dominant, safety-orange signal.*

### Thesis
Treat the terminal as a physical instrument panel: panes are **recessed wells**
cut into a warm-neutral chassis, controls are segmented and mechanical, and the
typography is monospace-dominant — labels included. The most overtly "terminal"
of the three.

### Palette
| Role | Value | Notes |
|---|---|---|
| `--surface-0` chassis | `#111110` | Warm neutral, not blue. |
| `--surface-1` well | `#0b0b0a` | *Darker* than the chassis — inset. |
| `--surface-2` | `#1a1a18` | Raised control beds. |
| `--line` | `#2a2a26` | |
| `--line-strong` | `#3d3d37` | |
| `--text-1` | `#f0efe9` | Bone-tinted. |
| `--text-2` | `#a3a29a` | |
| `--text-3` | `#6e6d66` | |
| `--accent` | `#ff6a2b` | Safety orange. |
| `--buy` / `--sell` | `#4ade80` / `#ff5470` | |

### Typography
- **Everything:** `"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace`
- Scale: 10 · 11 · 12 · 13 · 15 · 18 px. Aggressive `+0.08em` tracking on all labels.

### Layout
Same pane grid, 4 px radii, 2 px inset highlights on well edges
(`inset 0 1px 0 rgba(255,255,255,.04)`). Row height 30 px. Control height 26/32 px.

### Chrome & depth
Inset elevation: `inset 0 2px 6px rgba(0,0,0,.5)` on wells, plus a 1 px top
highlight on raised controls. Mechanical, physical, deliberate.

### Why it might win
Maximum density and maximum "this is a trading tool" signal. The warm-neutral
chassis is genuinely distinct from every blue-black exchange terminal.

### Why it might lose
**Monospace-dominant labels cost readability.** The brief explicitly requires
"UI labels highly readable" — 11 px mono at `+0.08em` for every field label is
measurably slower to scan than a UI sans, and the 10 px floor is below the
practical floor for a 1366 px laptop panel. Inset wells also consume vertical
budget (2 px highlight + 6 px shadow) in exactly the dimension that is scarcest
at 768 px tall.

---

## Self-critique

Scored 1–5 per axis. "Chart dominance" = does the centre pane visibly win the
viewport; "Order-entry clarity" = can a non-expert complete a swap without
misreading side, size, or cost.

| Axis | A — Deep Vault | B — Graphite Hairline | C — Instrument Grid |
|---|:--:|:--:|:--:|
| Hierarchy | **5** — surface ladder + 3 border weights give an unambiguous pane/row/label order | 3 — luminance-only hierarchy flattens once rows carry numerals | 4 — wells separate panes, but the chassis competes with them |
| Density | **5** — 32 px rows, 12–16 px pane padding, no wasted gutters | 3 — void gutters cost ~48 px of width and ~0 px of value | **5** — 30 px rows, tightest of the three |
| Usability | **5** — conventional, learnable, hover/focus trivially legible | 4 — beautiful but boundary-hunting costs a beat per glance | 3 — mono labels slow scanning; 10 px floor is below practical |
| Visual polish | 4 — needs the typographic move to stop reading as "tidy current app" | **5** — highest perceived craft | 4 — cohesive, but the inset treatment is one note held too long |
| Order-entry clarity | **5** — opaque ticket pane, amber-ruled sections, single submit | 4 — the ticket's collapsed Advanced is too quiet against the field | 4 — orange reads as warning next to the red Sell side |
| Chart dominance | **5** — chart sits on the darkest surface, panes are one step up | 3 — chart shares the canvas tone, so it does not dominate | 4 — the recessed well is good, but the highlight edge competes |
| Serious-terminal fit | **5** | 4 | 4 |
| **Total** | **34 / 35** | 27 / 35 | 28 / 35 |

### Specific findings

**A — Deep Vault.** Wins on the axis that matters most and is the only direction
that scores 5 on both hierarchy and chart dominance. Its weakness is real and
named: without a decisive move it is an incremental tidy-up. **The move is
typographic** — promote the numeric/mono face to a true *instrument display* role
(symbol identity and price at 26–30 px with `-0.02em` tracking) so the terminal
has a voice that no exchange reference has, and ration the amber so it appears at
most twice per screen. That converts "safe" into "confident".

**B — Graphite Hairline.** Genuinely the most beautiful of the three in isolation
and I want to be honest that it is the one I would enjoy looking at most. It loses
on evidence, not taste: a trading terminal is a *boundary-reading* task. The
trader's eye moves rail → chart → ticket → dock dozens of times a minute, and
hairline-only separation makes each of those moves cost a fraction of a second.
Compounding it, `rgba(255,255,255,0.06)` resolves to a different effective colour
against `#08090a` than against the chart's own plot background, so the chart pane
edge is not a stable line. **Rejected on usability, not on polish.**

**C — Instrument Grid.** The warm-neutral chassis is the single most original
colour decision across the three, and it is worth carrying forward as a rejected
alternative. It loses on two measured points: (1) the brief explicitly demands
"UI labels highly readable", and all-mono labels at 10–11 px with `+0.08em`
tracking is a readability regression against a UI sans; (2) safety orange sits
uncomfortably adjacent to `--sell` red in the ticket, creating a colour conflict
exactly where the highest-stakes decision is made. **Rejected on order-entry
clarity and label readability.**

---

## Selected direction — **A, Deep Vault, with two deliberate borrowings**

**Winner: Direction A — Deep Vault.**

**Why, in one paragraph.** A professional DEX terminal is not a page you read, it
is an instrument you glance at under load. That makes *pane legibility* — how fast
the eye can re-acquire which region it is looking at — the governing constraint,
and Direction A is the only one of the three that scores 5 on both hierarchy and
chart dominance while keeping labels in a face optimised for reading. It also
preserves the repo's existing and correct instincts (dark-only, amber-not-acid-green,
4 px grid, borders-over-cards, dense control heights) which means the design lands
as an evolution of a system the team already trusts rather than a rewrite — and the
implementation handoff maps onto tokens and class names that already exist.

**Two borrowings, and why each is safe:**
1. **From B — the two-weight translucent hairline discipline.** Applied *inside*
   panes only (row separators, chart gridlines, table rules) where a translucent
   line reads correctly against a known surface. Pane *edges* stay opaque, so B's
   instability failure mode is not imported.
2. **From C — the warm-neutral alternative is documented, not adopted.** C's chassis
   hue is recorded in this file as a rejected variant so a future brand pass can
   revisit it with evidence, rather than rediscovering it.

**The decisive flourish (one, not three).** The **instrument price block**: the
selected symbol and its live price rendered in the mono display face at 28 px with
tabular figures and `-0.02em` tracking, introduced by a single 2 px amber rule —
the only place in the terminal where type is allowed to be large, and the thing a
trader's eye lands on first, every time. Everything else in the terminal is 11–14 px
and quiet.

**Consequence for the accent budget — and it is a change from the current repo.**
Because the primary action adopts the *side* colour (green Buy / red Sell, the
exchange convention that makes the highest-stakes control unambiguous), amber is
freed from CTA duty entirely. It becomes purely the **selection / instrument**
signal: the brand mark, the instrument rule, the active tab underline, the active
network filter, and the selected market row marker. That is one coherent signal
rather than four unrelated amber accents, and it retires the current build's habit
of spending amber on tabs, chips, skip links and focus rings alike. Keyboard focus
moves to its own `--focus` token so it never competes with selection.

---

## Next

`DESIGN.md` locks this direction into tokens, type, spacing, pane geometry,
interaction states, component rules, anti-patterns and responsive behaviour, with
an explicit mapping onto the current SolidJS components.
`evercrest-terminal.html` is the high-fidelity prototype of the winning direction.
`IMPLEMENTATION_HANDOFF.md` maps the design onto existing files.
