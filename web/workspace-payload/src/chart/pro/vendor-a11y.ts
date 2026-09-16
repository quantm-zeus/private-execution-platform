// Accessibility normalization for vendored KLineChart Pro DOM.
//
// Pro 0.1.1 hardcodes `tabindex="1"` on its crosshair layer (a plain `div`
// under `.klinecharts-pro-widget`), which fails the axe `tabindex` rule
// ("Element has a tabindex greater than 0"). A positive tabindex also moves
// the element ahead of the page's own focus order, so it is wrong even outside
// the gate. `0` keeps the layer keyboard-reachable in document order.
//
// The vendor can recreate the layer on symbol/period changes, so callers keep
// a MutationObserver on the host rather than patching once.

/** Rewrite every descendant `tabindex` greater than `0` to `0`. */
export function normalizePositiveTabindex(root: ParentNode): void {
  for (const element of root.querySelectorAll<HTMLElement>("[tabindex]")) {
    const raw = element.getAttribute("tabindex");
    if (raw === null) continue;
    const value = Number.parseInt(raw, 10);
    if (Number.isFinite(value) && value > 0) element.setAttribute("tabindex", "0");
  }
}
