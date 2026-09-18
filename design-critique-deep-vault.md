# Deep Vault — adversarial self-critique

> **Phase:** artifact design → refinement gate.
> **Subject:** the winning direction *Deep Vault* as locked in `DESIGN.md` and as
> built in `evercrest-terminal.html`.
> **Method:** re-derive every claim in the contract from the artifact, and every
> claim in the artifact from measured values. Contrast is computed with the WCAG
> 2.x relative-luminance formula; tinted backgrounds are composited the way the
> browser composites them (`color-mix(in oklab, C p%, transparent)` resolves to
> `C` at alpha `p`, then composites over the surface in sRGB). Widths are
> estimated from the declared type scale, and every estimate that decides a
> layout question is stated as a number rather than a feeling.
> **Stance:** this is a hostile read. The earlier critique in
> `design-directions.md` scored the three directions against each other *before*
> anything was built; this pass scores the built artifact against its own
> contract, and it is looking for the failures that only appear once the design
> is on screen.

---

## Verdict

Deep Vault survives as the right direction — its governing thesis (opaque surface
ladder + weighted hairlines → fast pane re-acquisition) is visible in the artifact
and is the reason the four panes stay distinguishable under data load. But the
artifact does **not** yet keep the contract it was built from. Two defects are
hard failures against the design system's own rules and the craft contract
(the accent budget, and a control border below the 3:1 non-text floor), one
contradicts the brief's data-integrity posture (a numeric that can be clipped
mid-value), and the dock's tab set was invented rather than read off the repo.
All of these are fixable without touching the direction. None of them is a reason
to reopen the direction choice.

---

## Part 1 — What actually holds up

These are not courtesies; each is a claim in `DESIGN.md` that the artifact earns.

**1. Pane separation survives data load.** Four surfaces (`#080c11` → `#0d131a` →
`#121a23` → `#18222d`) plus three hairline weights do the separation work with no
shadow on any pane and no nested rounded container. Measured, the ladder steps are
large enough to read at a glance and small enough to stay calm: surface-1 vs
surface-0 is a 1.6× luminance step, and the chart sits on the darkest surface, so
it wins the viewport without a border. The named grid areas
(`"rail work ticket"`) are present in the artifact, which is what stops the
collapsed rail from collapsing the chart.

**2. The unknown contract is genuinely honoured.** `fUsd`, `fPrice`, `fPct`,
`fAmt`, `fAge` and `truncAddr` all short-circuit to `—` on a non-finite input, and
`setStat` writes `data-unknown="true"` so the em dash is also *styled* as unknown.
There is no `|| 0` and no `?? 0` anywhere in the data path. The dock's four
unavailable surfaces are one compact row each, not a card and not a stack trace.
The provenance line under the ticket is present whether or not the quote
succeeded. This is the hardest part of the brief and it is done properly.

**3. Numerics do not reflow.** `font-variant-numeric: tabular-nums` is set on
`:root` and inherited by `button`/`input`/`select`; `.num` re-asserts it. A price
moving `104.39 → 99.11` keeps its width. The `.statstrip__value` and `.mrow__price`
rules carry `white-space: nowrap`, so a stat can be clipped but never wrapped
mid-number.

**4. The chart is not a picture of a chart.** 9 564 real bars decoded from a real
Binance snapshot, 120-bar default window, a real volume pane that shares the time
axis, real MA7/MA25 computed from the decoded series, six drawing tools plus the
ruler with a live Δ/percent/bar-count readout, and a crosshair whose readout lives
in the pane bar rather than floating over the candles. Nothing overlays the plot
or either scale — the toolbar's hint text is the designated shrink point and
truncates before it can push a control out. That is the §5.3 contract met
literally.

**5. Contrast is mostly measured, not asserted.** Re-derived independently:
`--text-1` 13.74:1, `--text-2` 7.21:1, `--text-3` 4.68:1 (worst case,
`--surface-3`); `--buy` 6.87:1, `--sell` 4.69:1, `--accent` 8.50:1 on the same
worst case; `--buy-ink` on `--buy-fill` 8.07:1, `--sell-ink` on `--sell-fill`
5.32:1, `--accent-ink` on `--accent` 9.80:1. Every one of these clears its AA
threshold, and the contract's own numbers for them are accurate.

---

## Part 2 — Defects

Severity is against this project's own bar, not a generic one. **P0** = the
artifact contradicts the design system or the charter. **P1** = it contradicts the
brief, or it breaks under a supported condition. **P2** = craft.

### D1 — P0 — The accent budget is breached fivefold

**Claim in the contract.** `DESIGN.md` §6: *"Budget: two prominent amber elements
per screen."* The charter is stricter still: one accent colour, **at most twice per
screen**.

**What the artifact does.** At boot, five amber elements are on screen
simultaneously:

| # | Element | Rule |
|---|---|---|
| 1 | Brand mark, 6×18 px | `.mark { background: var(--accent) }` |
| 2 | Instrument price rule, 2×30 px | `.priceblock__rule { background: var(--accent) }` |
| 3 | Active order-type tab underline | `.tab[aria-selected="true"] { border-bottom-color: var(--accent) }` |
| 4 | Active network filter chip (text **and** border **and** wash) | `.chip[aria-pressed="true"] { background: var(--accent-soft); color: var(--accent); border-color: var(--accent) }` |
| 5 | Selected market row's left marker | `.mrow[aria-pressed="true"] { border-left-color: var(--accent) }` |

Three more amber states exist off-screen at boot (armed drawing tool via
`.iconbtn[aria-pressed="true"]`, active timeframe via
`.seg__btn[aria-pressed="true"]`'s inset rule, armed-tool hint via
`.chartpane__hint[data-tool]`), plus `.preset[data-max]` and the selected-drawing
stroke on canvas.

**Why this is the most serious finding.** The direction's stated consequence was
that amber becomes *one coherent signal* rather than four unrelated accents —
`design-directions.md` says exactly that. But because the selection family is
**persistent** (a row is always selected, a tab is always active, a chip is always
active) rather than **transient**, "two per screen" is unenforceable as written.
The practical result is the failure mode the direction set out to avoid: amber
reads as *the interactive colour*, which is what a generic AI dashboard looks
like, and the one deliberate flourish — the amber-ruled instrument price — is
diluted by four competitors of equal chroma.

**Fix applied.** Amber is now spent on exactly the two persistent elements the
flourish needs — the brand mark and the instrument price rule — and the selection
family is carried by the surface ladder plus `--text-1`, which is what the ladder
was built for. Active tab and active timeframe take a `--text-1` rule plus a
content-attached `--surface-1` fill; the active chip takes `--surface-3` +
`--text-1` + `--line-strong`; the selected row keeps its `--surface-3` fill and
takes a `--text-2` marker; the armed tool, the armed hint and the selected drawing
take `--text-1`. Measured result: **two** amber elements at boot, and the price
block is now unambiguously the first thing the eye lands on.

### D2 — P0 — `--control-border` fails the 3:1 non-text floor on `--surface-3`

**Claim in the contract.** `DESIGN.md` §2 ships `--control-border: #556b7e` with
the comment *"interactive control boundaries — ≥3:1 (WCAG 1.4.11)"*, and §10
asserts *"`--control-border` `#556b7e` = 3.4:1 on `--surface-1`, 3.2:1 on
`--surface-2`"*.

**Measured.** `#556b7e` is **3.37:1** on `--surface-1`, **3.16:1** on
`--surface-2`, and **2.90:1** on `--surface-3`. The artifact puts that border on
`--surface-3` in two real states: `.input:hover { background: var(--surface-3) }`
and `.unitbtn:hover { background: var(--surface-3) }` — both keep
`--control-border` unchanged. So the amount input's and the denomination button's
boundary drops below 3:1 **on hover**, in the highest-stakes control on the screen.

**What the artifact already did.** The prototype silently ships
`--control-border: #5b7288` — a corrected value — while its own comment claims the
token block is *"DESIGN.md §2, copied verbatim"*. Measured: **3.74:1 / 3.51:1 /
3.22:1**, which clears 3:1 on all three surfaces. So the artifact was right and
the contract was wrong, and neither document flagged the divergence. That
divergence is itself the defect: a token block that claims to be verbatim and
isn't will be implemented verbatim by whoever reads `DESIGN.md` first.

**Fix applied.** `DESIGN.md` §2 and §10 are corrected to `#5b7288` with the
re-measured ratios. The artifact keeps its value.

### D3 — P1 — Danger badge text is 4.47:1 on its own tint over `--surface-2`

`.badge--danger` renders 10 px text in `--danger` on
`color-mix(in oklab, var(--danger) 12%, transparent)`. 10 px is normal text, so
the floor is 4.5:1. Composited over `--surface-2` the pair measures **4.47:1** —
a fail, by 0.03. Over `--surface-1` (where the top bar's `TRADING DISABLED` badge
actually sits today) it measures 4.79:1, so the artifact passes **by accident of
placement**, not by construction. `--buy` (6.12:1), `--warn` (7.54:1) and `--info`
(5.34:1) are unaffected.

**Fix applied.** The tint alpha for all four tinted badges drops from 12% to 8%,
which moves the worst case to **4.72:1** over `--surface-2` and 5.03:1 over
`--surface-1`, and keeps every other badge far above its floor. `DESIGN.md` §5.1
is corrected from "12% of their semantic colour" to 8%. A subtler tint is also the
better instrument-panel read.

### D4 — P1 — The stat strip can clip a numeric mid-value at 1366 px

**Claim in the contract.** `DESIGN.md` §8: at 1366–1439 the strip is
*"Price · 24H · MCap; Liquidity/Volume into tooltip"*.

**What the artifact does.** Its media queries hide `[data-optional]` (Liquidity)
only below 1280 and `[data-tertiary]` (Volume 24h, 24h range) only below 1024. At
1366 px — a **named target resolution in the brief** — all four stats render.

Sizing the fixed chrome from the declared type scale at 1366 px: top-bar padding
24, brand cluster ≈122, rule+gaps 25, instrument identity ≈124, price block ≈252
(worst case, a 10-character price at 28 px mono), status cluster ≈389, inter-item
gaps 60 → **≈996 px consumed**, leaving ≈370 px for the strip. The four stats need
≈314 px of text plus 3×20 px of gaps = **≈374 px**. The estimate is inside the
available width by roughly nothing, and `.statstrip { overflow: hidden }` means
the failure mode when the estimate is wrong is a **silently truncated number** —
`184.20 – 192.5` reading as a complete value. In a terminal whose entire posture is
"the terminal never lies", a clipped numeric is the worst possible defect: it is
not an em dash, it is a wrong number.

**Fix applied.** The fold order in the artifact is re-cut so the widest item (the
24h range, ≈117 px) and the two market-context stats fold before the strip can
reach its clipping point: at ≤1439 px Liquidity and Volume 24h fold, leaving
Mcap + 24h range (≈199 px needed against ≈370 px available at 1366 — 171 px of
slack); below 1280 px only Mcap remains. `DESIGN.md` §8's tier table is updated to
match, since the contract's stated tier was the one that could not fit.

### D5 — P1 — The dock's tab set was invented, and drops two real surfaces

**Claim in the contract.** `DESIGN.md` §5.5: *"tabs `Positions / Open Orders /
Activity / Balances`"*.

**What the repo actually has.** `state/workstation.tsx:44`:
`export type DockTab = "positions" | "orders" | "activity" | "trades" | "holders"`.
`BottomDock.tsx` renders exactly those five. **Balances is not a dock tab** — it is
part of `PortfolioPanel` under Positions. Trades and Holders are real, wired tabs
that render a truthful `CompactNote` with the capability keys `market.trades` and
`market.holders`.

So the design invented a tab that does not exist and silently deleted two that do.
This is the one finding where the design was less honest than the code it is
supposed to be describing — and it would have shipped as an instruction to delete
two product surfaces.

**Fix applied.** The artifact's dock now renders the repo's real five tabs, each
with a `—` count (never `0`). The two surfaces the repo itself declares
unavailable (`trades`, `holders`) carry their **real** capability keys in the
`<details>` disclosure; the three that the repo composes from real panels
(positions, orders, activity) state an honest reason without a fabricated
capability key, because inventing one would be exactly the kind of plausible
fiction the brief forbids. `DESIGN.md` §5.5 is corrected to the real tab set.

### D6 — P1 — §5.3's "22 px icon hit area" is below the floor §8 claims

`DESIGN.md` §2 ships `--control-xs: 22px`, §5.3 repeats *"a 22 px icon hit area"*,
and §8 claims *"every control is ≥ 24×24 (WCAG 2.5.8 AA)"*. 22 < 24, so the
contract contradicts itself, and the artifact had already resolved it by shipping
`--control-xs: 24px`.

**Fix applied.** `DESIGN.md` §2 and §5.3 are corrected to 24 px. The artifact keeps
its value.

### D7 — P2 — ALL-CAPS status-bar keys carry no tracking

`.statusbar__key` renders six hard-coded ALL-CAPS runs (`DATA`, `SNAPSHOT`, `FEED`,
`EXECUTION`) at 11 px with `color: var(--text-3)` and **no** `letter-spacing`.
`DESIGN.md` §3 says *"Every ALL-CAPS run carries `letter-spacing:
var(--tracking-label)`. No exceptions."*

**Fix applied.** `.statusbar__key` takes `letter-spacing: var(--tracking-label)`.
The same pass applies the craft rule's `0.02em` UI-label tracking to the button
family that was missing it (`.btn`, `.seg__btn`, `.side__btn`, `.cta__btn`,
`.preset`, `.chip`, `.unitbtn`) — `.tab` already had it, which is what makes the
omission look accidental rather than chosen.

### D8 — P2 — Negative tracking on a UI-sans uppercase run

`.chartpane__sym` is UI sans at 16 px carrying an uppercase ticker with
`letter-spacing: -0.01em`. `DESIGN.md` §3: *"Negative tracking applies only to mono
display runs ≥20 px. It is never applied to the UI sans."* The rule is stated and
then broken one pane to the left of where it is stated.

**Fix applied.** `.chartpane__sym` tracking goes to `0`.

### D9 — P1 — The chart canvas has no keyboard affordance

`DESIGN.md` §10 claims *"Keyboard: every control reachable and operable."* The
chart is the primary surface of the product, and pan, zoom and reset are
pointer-only (`pointerdown`/`pointermove`/`wheel`/`dblclick`). A keyboard-only
operator can select an instrument, switch timeframe, toggle MA, and arm a drawing
tool — and then cannot move the viewport of the chart at all.

**Fix applied.** The canvas takes `tabindex="0"`, a `--focus` ring, and
Left/Right to pan, Up/Down (and `+`/`-`) to zoom, `0`/`Home` to reset; its
`aria-describedby` points at a visually-hidden paragraph that states the whole
chart keyboard contract, including Escape-to-cancel and Delete-to-remove for
drawings. Drawing placement itself remains pointer-only and is stated as a known
limitation in the handoff rather than papered over.

### D10 — P2 — Tablists declare `role="tablist"` without arrow-key navigation

Both the ticket tabs and the dock tabs declare `role="tablist"` + `role="tab"`
+ `aria-selected` + `aria-controls`, and both panels are correctly `role="tabpanel"`.
What is missing is the rest of the ARIA APG tabs pattern: Left/Right (and
Home/End) move between tabs. Without it the roles promise a keyboard interaction
that does not exist, which is worse than not declaring the roles at all.

**Fix applied.** A single `wireTablist` helper gives both tablists Left/Right/Up/
Down/Home/End navigation with automatic activation and roving `tabindex`, so the
selected tab is the one Tab lands on and the arrow keys move within the set.

### D11 — P2 — `.receive` fits its narrowest tier by ~12 px

At the 320 px ticket tier the estimated width of
`You receive (est.)` + a 13-character value + padding is ≈292 px against ≈296 px
available. It fits, but with no margin, and `.receive` is
`justify-content: space-between` with no wrap — so an overrun would push the value
out of the pane rather than onto a second line.

**Fix applied.** `.receive` gains `flex-wrap: wrap` and `min-width: 0` on the
value, so the worst case degrades to a second right-aligned line instead of an
overflow. No change at any width where it already fits.

---

## Part 3 — Judgement on the direction itself

The critique in `design-directions.md` named Deep Vault's risk honestly: *"without a
decisive move it is an incremental tidy-up"*, and proposed the typographic move —
promote the mono face to a true instrument display role.

**Does the move land?** Partly, and the honest answer is that it lands *only now*
that D1 is fixed. The 28 px mono price with `-0.02em` tracking behind a 2 px amber
rule is a genuine focal point and it is the thing the eye finds first — but with
five amber elements competing, the rule was not doing the work the argument
claimed for it. With amber reduced to two, the price block is doing exactly what
the direction said it would. The move was correct; it was not yet *visible*.

**What remains genuinely distinctive.** Two things, and they are enough:
the **mono-as-display** role inversion (a terminal whose display face is its
numeric face — no reference system in the five inspected does this), and the
**three-weight opaque hairline system** where pane edges are opaque and only
intra-pane rules are translucent. That second one is the direct answer to
Direction B's failure mode and it is the reason the chart pane edge stays a stable
line against the plot.

**What is not distinctive, stated plainly.** The palette is a cool near-black
slate — the same family as every exchange terminal inspected. That is a
consequence of choosing legibility over novelty, and it is the right trade for
this product, but it means the terminal's identity lives entirely in its
typography, its density and its amber rationing, not in its colour. If a future
brand pass wants colour identity, Direction C's warm-neutral chassis is documented
in `design-directions.md` as the evidence-backed alternative.

**Would I re-open the direction choice?** No. B still loses on the same measured
ground it lost on before, and the artifact confirms it: the four panes carry
11–13 px numerics and the opaque ladder is doing real work. C still loses on label
readability. The direction holds; the execution needed the eight fixes above.

---

## Part 4 — Deliberately not changed

- **The direction, the palette hue, the type pairing, the pane geometry, the
  flourish.** No defect above is a reason to revisit any of them.
- **The repo's existing hard-won decisions**, all of which the artifact already
  preserves and which the handoff restates: named grid areas, both ticket panes
  staying mounted, `ohlcv:<chain>:<address>` entity-key isolation,
  `SERVED_TIMEFRAME_IDS`, the `DataState` union, every fail-closed gate.
- **The mono glyphs the repo already uses** (`↻`, `‹`) in `MarketRail`. The
  design's own rule permits a mono glyph where the repo already uses one; the
  shell's *chrome* glyphs (`▤ ◈ ⚙ ⇄`) are a separate question and are raised in
  `IMPLEMENTATION_HANDOFF.md` as a scoped substitution, not silently rewritten
  here.
- **`--text-3` at 4.68:1.** It is the floor and it is above 4.5:1. Raising it would
  flatten the ramp for no compliance gain; the rule is that nothing dimmer may
  carry text, and the contract says so.
- **The chart's drawing tools remaining pointer-only.** Keyboard *placement* of a
  drawing needs a coordinate-entry design that is out of scope for this pass; the
  viewport controls (D9) are the part that a keyboard operator is actually blocked
  on. Stated as a limitation rather than claimed as done.

---

# Part 5 — Critique of the FOMO intelligence revision

> **Subject:** the §5A additions — the Holders trader pane, the About token
> intelligence pane, and dock expansion — as built in `evercrest-terminal.html`.
> **Method:** the same hostile re-derivation as Part 2, plus two checks that only
> apply to this revision: every *derived* figure is re-computed from its inputs,
> and every *acquired* asset is re-verified against the referent it claims to be.
> **Stance:** the risk in an additive revision is not that the new panes look
> wrong; it is that they quietly break the invariants the approved design spent its
> whole budget establishing. So this pass hunts for regressions first and new
> defects second.

## Verdict

The revision holds. The panes are recognisably Deep Vault — same surface ladder,
same hairlines-not-cards discipline, same em-dash contract — and they add real
product depth rather than decoration. But the revision also surfaced **eight
defects**, and two of them are mine from the previous pass: a fabricated capability
key, and a dock geometry that would have broken the chart floor the moment anyone
expanded it. Both are fixed. Two limitations remain and are stated rather than
hidden.

## R1 — The dock expansion would have breached the chart floor

**This is the defect that shaped the whole revision.** The brief asks for a dock
that may expand while preserving usability at 1366×768, and separately requires
that About not reduce chart height while closed. A naive implementation — swap
`--dock-h` for a larger value on expand — breaks the design's own hard floor:

At 1366×768, the work area is `768 − 56 − 24 = 688 px`. The chart pane needs
`320 px plot + 72 px pane bars = 392 px`. A 400 px expanded dock would leave the
chart pane **288 px** — 104 px below its floor, and the plot at 216 px, which is
below the 320 px minimum `DESIGN.md` §8 declares non-negotiable.

**Fixed by putting the clamp on the grid track, not in the script:**

```css
--dock-h-max: calc(100vh - var(--topbar-h) - var(--statusbar-h) - var(--dock-handle-h) - var(--chart-min-h));
grid-template-rows: minmax(0,1fr) var(--dock-handle-h)
                    clamp(96px, var(--dock-h-base), var(--dock-h-max));
```

Verified at seven viewport tiers: the chart pane is **never** below 392 px and the
plot is never below 320 px, including 1366×768 (expanded dock resolves to 290 px)
and 980×768. Putting the ceiling in CSS rather than in the drag handler is the
point: a future caller cannot breach it even by mistake.

## R2 — A fabricated capability key, from the previous pass

Part 1 of this document criticised the *original* design for inventing capability
keys. Part 1's own fix then mapped `holders` to `market.holders` and called it "a
real capability key". It is not.

Measured against the repo:

- `web/workspace-payload/src/core/types.ts` defines the `CapabilityKey` union:
  `market · chart · realtime · quotes · preview · execute · limits · portfolio ·
  intelligence · twitter · gmgn · okx · twap · rfq · withdraw · wallet_limits`.
  **`market.holders` is not in it. Neither is `market.trades`.**
- `market.trades` and `market.holders` exist in the repo only as `CompactNote
  capability=` strings in `BottomDock.tsx` — a *contract* namespace, not the
  capability namespace.
- The key that actually gates this class of surface is **`intelligence`**, already
  a union member and already used by `IntelligencePanel` and `PortfolioPanel` via
  `capabilityDenial("intelligence")`.

**Fixed.** The trader and activity panes now gate on `intelligence`. The prototype
keeps `market.trades` for the Trades tab only, because that is the exact string
`BottomDock.tsx` itself passes. This is a good illustration of why the honesty rule
has to apply to the fix as well as to the original: the first correction introduced
its own small fiction.

## R3 — Token logos arrive with incompatible backgrounds

Discovered by measuring, not by looking. All eleven real marks were fetched and
their corner pixels and mean colours decoded:

| Background | Symbols | Corner pixel |
|---|---|---|
| Transparent | BNB, ETH | `alpha 0` |
| Near-black | SOL, JUP, RAY, PYTH | `(17,24,32)` … `(12,21,48)` |
| Saturated full-bleed | BONK, PEPE | `(239,150,1)`, `(0,158,30)` |
| **Light / photographic** | WIF, AERO, VIRTUAL | `(178,176,163)`, `(235,232,225)`, `(198,241,242)` |

Dropped raw onto a dark canvas, three of the eleven would have been bright squares,
two would have been invisible marks on the surface, and the set would have read as
broken rather than designed.

**Fixed with a normalising tile** — 32/20 px, `--radius-sm`, 1 px `--line`,
`--surface-3` fill, `object-fit: cover`. `contain` was tested and rejected: it
leaves a visible ring of tile tone around the light and transparent marks, which is
the same inconsistency with extra steps. `cover` gives every mark the same hard
edge regardless of what its own background does.

## R4 — A 6 px resize handle fails WCAG 2.5.8

The handle's visual track is 6 px. As a pointer target that is a quarter of the
24 px AA minimum, and the spacing exception does not rescue it: the chart canvas
above is itself focusable, so the exclusion circles would overlap.

**Fixed** with an `::after` box extending the hit area 9 px above and below —
`6 + 9 + 9 = 24 px` — without changing layout. The handle now clears 2.5.8 outright
rather than arguing for an exception.

## R5 — The ALL-CAPS monogram had no tracking

`.mark-tile__mono` sets `text-transform: uppercase` with `letter-spacing: 0.02em`.
`DESIGN.md` §3 requires ≥ 0.06em on every ALL-CAPS run, no exceptions — and the
OpenDesign linter caught it independently:

> `all-caps-no-tracking` (P1) — Selector `.mark-tile__mono` sets text-transform:
> uppercase without sufficient letter-spacing (≥0.06em).

**Fixed** to `0.06em`; the linter is clean. Worth noting that this is the *second*
time in two passes that the same rule has been violated in newly written CSS. It is
the single most reliable typographic slip in this codebase.

## R6 — A doubled divider between the chart and the dock

The dock carried `border-top: 1px solid var(--line)` and the new handle carried its
own `border-top`, producing a 2 px-looking rule where the design specifies one
hairline.

**Fixed** by removing the dock's border — the handle owns the single divider.

## R7 — The feed could have grown without bound

"Load more" is the obvious implementation and it is wrong here: it grows the DOM
monotonically for the lifetime of the pane, and the brief explicitly forbids
unbounded DOM growth.

**Fixed with true pagination** — `Newer` / `Older` plus a `1–12 of 84` range, page
size 12. The row count in the DOM is now bounded by construction, and the operator
can reason about which slice they are reading.

## R8 — The most dangerous thing this prototype could print

A fixture trader's wallet address. A plausible base58 or `0x` string, rendered in a
copyable control inside a trading terminal, is indistinguishable from a real
address and is exactly the kind of plausible fiction this project's whole data
contract exists to prevent.

**Fixed by making it visibly not-an-address:** `fixture:xxxxxxxx…xx`. Verified by
assertion that no 32–44 character base58 or 40-hex string appears anywhere in the
rendered panes. `DESIGN.md` §9 now forbids a plausible fabricated address outright.

## R9 — The fixture could have contradicted itself

Sixteen numbers per trader, hand-written, across nineteen rows, is sixteen chances
per row to print a cost basis that does not match the amount and entry price, or a
total PnL that is not the sum of its parts. In a terminal whose contract is "never
lie", an internally inconsistent row is a lie even when every number is labelled as
a fixture.

**Fixed by deriving rather than transcribing.** The fixture stores only
`amount`, `entryMultiple`, `realizedMultiple`, `holdSeconds`; entry is a multiple of
the token's **real** current price from the embedded snapshot, so:

```
cost = amount × price × entryMult
unrealised = amount × (price − cost/amount)      value = amount × price
realised = cost × realizedMult                   total = realised + unrealised
```

Verified by assertion over all 19 rows that `total === (value − cost) + realised`
to floating-point tolerance. The same discipline applies to the About stats:
`mcap = circulating × price`, `fdv = total × price`, `volume24` is the token's real
snapshot volume, and the flow volumes are the real 24h volume split by a fixture
buy share. **The About pane and the top instrument bar therefore cannot disagree
about price**, because there is only one price.

## R10 — Token logos are real brand marks, so they were acquired

Token marks are named real-world referents. The brief lists "token image" as a
profile field; the token addresses in the snapshot are real; and the charter is
explicit that a placeholder is not permission to skip acquisition. So the eleven
marks were fetched from an **address-keyed** source, which makes a wrong-token
look-alike structurally impossible, and verified two ways: the URL's address
segment was compared against `assets/market-snapshot.json`, and each decoded image's
dominant hue was compared against the token's known brand colour — BNB `yellow 84%`,
PEPE `green 82%`, BONK `orange 67% + yellow 23%`, WIF `orange/tan 56%` (a
photographic dog image), with JUP/RAY/PYTH dark-dominant as expected. Source,
licence (MIT) and the full per-address manifest are in
`assets/token-logos/SOURCES.md`.

**Trader avatars are deliberately monograms**, and this is not the same decision.
A trader avatar is a third party's photograph. Fabricating one, generating one, or
sourcing a stranger's face to stand in for an anonymous trader is a privacy failure,
not a sourcing shortcut. The provider-image path is specified and implemented in
CSS; the fallback is what this prototype renders, and it is a documented state the
design needs anyway.

## Honest limitations — stated, not hidden

**L1 — At 1366×768 the expanded dock shows about three trader rows.** The body is
`290 − 34 (tabs) − 30 (pane bar) − 24 (padding) ≈ 202 px`, against ~60 px rows. This
is a direct consequence of holding the chart floor, which is the right trade for a
trading terminal — but it is a real constraint, not a comfortable one. The resize
handle exists precisely so the operator can trade chart against data; at 1920×1080
the expanded body is ~306 px and shows five to six rows.

**L2 — At 1366×768 the About pane's left column scrolls.** Profile + market stats +
flow need roughly 384 px and get ~202 px in the expanded dock, so the left column
scrolls while the activity feed owns the right column's full height. That ordering
is deliberate — the live feed is the more perishable information — but it does mean
the market stats are not all visible at once at that tier.

**L3 — Keyboard placement of a drawing is still not supported**, unchanged from
Part 2. The chart viewport is keyboard-operable; drawing coordinates are not.

**L4 — The realtime prepend path is specified but not exercised.** There is no
stream in this prototype, so the exact-identity prepend rule is documented in
`DESIGN.md` §5A.5 and the handoff rather than demonstrated. It is the one part of
this revision that a reviewer cannot verify from the artifact.

## What was deliberately not done

- **The in-terminal trader quick-view drawer.** The brief says "later", and says
  do not navigate away. Selecting a row expands an inline detail instead. The
  drawer pattern to copy when it is built is `SecurityDrawer.tsx`.
- **A seventh `DockTab` for depth-of-book.** Recommended in the handoff as the
  follow-up that would relieve L1; it edits the `DockTab` union and is a
  behavioural change, so it is out of scope here.
- **Renaming the Holders tab.** The brief keeps the word; the pane header carries
  the clarification instead.
- **Any application, backend, realtime, auth, crypto or execution code.** Not one
  line, in either pass.

---

# Part 6 — Critique of the V2 information-architecture correction

> **Subject:** the owner-approved correction that reduces the dock to five tabs,
> removes Trades, makes Activity the single home for event streams with a
> Token | Mine scope, keeps Holders as one pane, and strips all activity from About.
> **Method:** the same hostile re-derivation, focused on the specific failure mode
> of an IA change — *content that is now in two places, or in none*.

## Verdict

The correction is right, and Part 5 should have caught it. The previous revision
left the token activity feed inside About, which meant About was simultaneously
answering "what is this token?" and "what is happening?" — two questions with
different lifetimes, different data sources and different reading rhythms, sharing
one scroll container. The correction separates them properly, and it does so by
making the *structure* enforce the rule rather than a convention.

## R11 — The dock was answering three questions in two places

Before the correction the dock had six tabs, and their responsibilities overlapped:

| Tab | Answered | Overlap |
|---|---|---|
| Trades | "what is happening?" — as a permanent `market.trades` placeholder | a second, permanently-empty answer to Activity's question |
| Activity | "what is my execution history?" — the `ExecutionPanel` | a *third* question, sharing a tab name with Trades' question |
| About | "what is this token?" **and** "what is happening?" | the feed |

So "what is happening?" had two homes (Trades, and About's feed) and "what is my
execution history?" had a tab labelled with a different word. Three questions, two
places, one of them empty by construction.

**Fixed by the correction.** Activity now owns the event streams with an explicit
Token | Mine scope; Trades is deleted; About owns only the token overview. The
table in `DESIGN.md` §5.5 states the division of labour, and §9 forbids a second
transaction feed.

## R12 — A dead placeholder was being preserved for its own sake

Part 5's own fix kept the Trades tab and gave it `capability="market.trades"`. That
was the wrong instinct twice over: the string is not a member of the application's
`CapabilityKey` union (Part 5 already documented that), and the tab could only ever
render "unavailable" while a richer, exact-identity feed for the same concept
existed one tab away.

**Fixed.** `DockTab` becomes
`"positions" | "orders" | "activity" | "holders" | "about"`, and the handoff now
says explicitly: delete the tab entry *and* its `CompactNote` *and* the
`market.trades` string, because the brief's instruction is to not preserve a dead
placeholder merely because it exists today.

**One thing the removal must not break, and this is the subtle part:** the
repository has a *different* `"trades"` in `realtime/types.ts` — a member of
`RealtimeChannel`, the transport channel union. Deleting the dock tab must not
touch it, and the handoff now says so twice and asks for a test that asserts it
still exists. Two namespaces, one word, and a correction that deletes one of them
is exactly where a careless sweep would take out both.

## R13 — A `data-dock` attribute collision, introduced by Part 5

Part 5 put the dock's **height** state on `.terminal` as `data-dock="expanded"` and
the dock's **tab id** on each tab as `data-dock="positions"`. Two meanings, one
attribute name.

It was harmless today only because every query happened to be scoped
(`.tab[data-dock]`). The first unscoped `[data-dock]` query — a test helper, a
scroll-into-view, a future stylesheet rule — would have matched the terminal as if
it were a tab.

**Found by the verification harness, not by reading the code:** the assertion
"exactly five dock tabs" returned six values, and the sixth was `expanded`. That is
precisely the value a real bug would have produced.

**Fixed** by renaming the height attribute to `data-dock-size`, and the handoff now
records the rule: two distinct names, always.

## R14 — A scope that could only render empty

The brief suggests a `Following / Friends` holder control "only when backend proves
such rows exist". Implemented naively as a permanent segment, it would be a control
whose only possible outcome is an empty list — the same class of defect as the
Trades tab.

**Fixed** by deriving availability from the data: the segment renders only when the
fetched rows actually contain followed entries. And when the operator has chosen
`Following` and then selects a token with no followed rows, the pane falls back to
`Top holders` **and the pressed segment shows the fallback**, rather than presenting
an empty list as if the provider had returned nothing. That is the same principle
the rail's network filter already follows when a network disappears — an existing,
documented repo decision, applied to a new control rather than reinvented.

## What the correction measurably improves

- **About is genuinely calm now.** Removing the feed removes the only list in the
  pane, which means About has no pagination, no page index, no filter state and no
  way to grow. The negative test the handoff asks for — *assert About renders no
  `feed__row` and no pager* — is the structural guarantee, not a style guideline.
- **About got shorter, which matters at 1366×768.** Part 5's limitation L2 was that
  the About pane's left column scrolled at that tier. With the feed gone the pane is
  a five-section overview grid, and the two columns now balance instead of one
  column carrying a full-height feed.
- **The scope selector makes provenance visible instead of implied.** Previously an
  owner execution row and a market row could in principle have appeared in the same
  dock region; now a single labelled switch governs which stream is on screen, and
  §9 forbids mixing them.

## Honest notes on the correction

**L5 — The Activity tab now carries two quite different panes.** Token is a live
market tape with filters and pagination; Mine is an execution workspace with TWAP
and RFQ panels. They share a tab because they share the question, but they do not
share a visual rhythm, and the scope switch is doing more work than a two-segment
control usually does. The mitigation is that the switch sits in the pane bar next
to the title, so the current scope is never ambiguous. If a third scope ever
appears, the correct move is a sub-navigation, not a third segment.

**L6 — `"transfers"` is a UI grouping, not a provider value.** The provider emits
transfer variants; the filter collapses them into one word for the operator. The
handoff requires that collapse to happen in the *request*, mapped onto the
provider's own `action` parameter, rather than as client-side array filtering over
a server-paged set — which would produce wrong counts and pages that look empty.

**L7 — Removing a tab is easy to do half-way.** The three-part deletion (tab entry,
`CompactNote`, capability string) plus the `RealtimeChannel` caution plus a test
asserting `"trades"` is no longer assignable to `DockTab` are all in the handoff
precisely because a partial removal leaves a tab that renders nothing, which is
worse than the placeholder it replaced.

## What was deliberately not done

- **No application code.** Not one line, in any of the three passes.
- **No `RealtimeChannel` change.** Its `"trades"` member is a transport channel and
  is unrelated to the deleted tab.
- **No change to the visual system, tokens, chart, order ticket, or any fail-closed
  invariant.** The correction is information architecture only.
- **No new feed anywhere.** The correction removes one and relocates another; it
  does not add a third.

---

# Part 7 — Critique of the V3 semantic correction

> **Subject:** the owner-approved correction that makes Activity > Mine read-only
> and relocates the mutating Adaptive TWAP / RFQ controls to the trade ticket.
> **Method:** the same hostile re-derivation, focused on the failure mode this
> correction is about — *a surface whose name promises one thing and whose contents
> do another*.

## Verdict

The flaw was real, and it was the kind that survives review precisely because it is
invisible in a screenshot. A tab named **Activity** contained a form that starts a
TWAP and requests an RFQ. Nothing about that pane looked wrong — the components were
well built, the gates were correct, the tests passed. It was wrong at the level of
*what the surface is for*, and Part 6 walked straight past it while carefully
checking that the feed had exactly one home.

## R15 — A mutating console was mounted under a tab named Activity

Measured against the code, not the description:

| In `ExecutionPanel.tsx` | Line | Kind |
|---|---|---|
| `createCommandResource(..., "submit_rfq", ...)` | 50 | **mutation** |
| `ws.command.send("start_twap", request, ...)` | 252 | **mutation** |
| `retryTwapUnknown`, `discardTwapUnknown` | 437, 453 | **mutation** |
| `requestRfq`, `discardRfq` | 507, 524, 542 | **mutation** |

Six mutation paths, inside a panel that V2's handoff instructed to become the Mine
subview of **Activity**. That is a category error: Activity answers *"what is
happening?"* and a TWAP form answers *"do this"*. An operator opening Activity to
read what is going on should not be one keystroke from committing an order.

**Fixed.** The mutating controls move to the trade ticket's Advanced execution area
(§5A.5b / handoff §11.5), and the Mine subview becomes a new read-only
`OwnerExecutionActivityPanel`. The handoff now carries an explicit, testable
prohibition: **the Mine subtree must contain zero `<button>` and zero `<input>`.**

## R16 — "Execution history" could only have been fabricated

The brief's caution — *do not fabricate historical rows if the backend only has
`get_execution_progress`* — is exactly right, and the code confirms it. From
`web_contract.rs`:

```
"get_execution_progress" => match request.payload.get("client_request_id") {
    None | Some(Value::Null) => self.web.current_execution_progress().await,
    Some(Value::String(id)) if !id.trim().is_empty() => self.web.execution_progress(id).await,
    Some(_) => Err(protocol("client_request_id must be a non-empty string.")),
}
```

Two reads: **the current execution**, or **one named execution**. There is no
history-list command anywhere in the surface.

So a Mine pane that rendered a chronological execution list would have had exactly
one possible source for its rows: invention. And because the pane is named
"activity", a reviewer would have read those rows as a tape.

**Fixed by designing the absence, not hiding it.** Mine renders **one** current
status block and a **permanent, honest** history-unavailable row. The prototype
demonstrates all three real states through normal navigation: SOL is *running*, WIF
is *halted* with its halt reason, BONK is *idle*, and JUP's read is *not composed*.

## R17 — `idle` and `unavailable` are one careless line apart

The repository already warns about this, in a comment that V2's handoff quoted and
then did not act on:

> `get_execution_progress` is an ungated owner-scoped reconciliation read (BR-9):
> the server serves it even when `twap` is not advertised, so the client must not
> hide it behind `twap` or an UNKNOWN execution could never be reconciled. … Until
> the authenticated command channel is installed it must surface as "awaiting the
> channel" rather than an unqueried empty ("no execution running"), which a stalled
> handoff would otherwise show forever.

Three facts that look alike and are not:

| Fact | Meaning | Rendering |
|---|---|---|
| the read returned an execution | something is running | the status block |
| the read succeeded, nothing running | **normal** | `No execution is running for this workspace.` |
| the read is not composed / channel down | **a gap** | the 44 px unavailable row |

Rendering the third as the second tells an operator their workspace is idle when in
truth the terminal cannot see. The prototype asserts the distinction in both
directions, and the handoff repeats the repo's own reasoning so the next
implementer cannot lose it a second time.

## R18 — A shadowed identifier, caught by the harness

The first build of `mineScope()` declared a local `let current` to hold the rendered
block — shadowing the module-level `current()` helper that resolves the selected
instrument. Every call to `mineScope()` threw a TDZ `ReferenceError`.

This is worth recording because of *how* it was found. Static review would not have
caught it: the code reads correctly, the names are individually reasonable, and the
prototype's own boot path never calls `mineScope()` (the dock opens on Positions).
The DOM-shim harness caught it on the first invocation, in the browser-equivalent
execution order, and the fix was a rename to `currentBlock`.

The lesson generalises: in a single-file prototype with a large shared scope, a
one-word local can silently take out a module-level helper, and only *running* the
code finds it.

## What the correction measurably improves

- **Activity is now safe to open.** A read-only surface cannot commit an order, so
  the tab is safe to land on, safe to leave open, and safe to hand to someone who
  only wants to look.
- **The execution forms are where execution already happens.** Placing them in the
  ticket's Advanced area puts them beside the order they belong to, behind the same
  gates — rather than in a different dock tab with a different mental model.
- **The read-only panel reuses the read the repo already got right.** `progressMetrics`,
  the 5 s TTL, and the `commandReady`-gated denial are carried across rather than
  re-derived, so the parts that were already correct stay correct.
- **The prototype no longer contains a single mutating execution op.** Verified:
  zero occurrences of `start_twap`, `submit_rfq` or `execute_market_order`.

## Honest notes on the correction

**L8 — The Mine scope is thin, and that is the point.** One status block and one
unavailable row is not much surface. It is, however, exactly what the backend can
prove, and the alternative — a plausible-looking history — is the one thing this
product's data contract exists to prevent. When an execution-history contract
arrives, this pane grows a real list; until then it stays honest and small.

**L9 — Moving `ExecutionPanel` is a behavioural move, not a styling one.** The
handoff marks it as such and lists every guard that must survive the move
(fail-closed, submission-key idempotency, the UNKNOWN two-step release, the
`TRADING_ENABLED` gate, the mutation denials, and the no-direct-provider rule). It
also asks for a test at the *new* location rather than assuming the existing tests
cover the relocation. This is the one part of the correction that cannot be verified
from the prototype, because the prototype has no execution channel at all.

**L10 — The drawer is a recommendation, not a measurement.** The handoff recommends
an Advanced Execution drawer over inlining the two forms into
`.ticket__advanced-body`, on the grounds that the forms are large and 1366×768 is
tight. That judgement is not measured against a rendered ticket; the alternative is
documented so an implementer who measures otherwise can choose it.

## What was deliberately not done

- **No application code.** Not one line, in any of the four passes.
- **No redesign of the trade ticket.** Only the mount point of one panel moves; the
  ticket's IA, layout and gates are untouched.
- **No new execution read.** The correction does not ask the backend for a history
  command; it designs honestly around the one read that exists.
- **No change to the visual system, tokens, chart, order-entry UX or any fail-closed
  invariant.**
