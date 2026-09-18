// APG tablist keyboard navigation (DESIGN.md §10, IMPLEMENTATION_HANDOFF §3.1).
//
// TradeTicket and BottomDock both declare role="tablist" + role="tab" +
// aria-selected + aria-controls. Declaring those roles promises the rest of the
// ARIA APG tabs pattern, so this wires Left/Right/Home/End with roving tabindex.
//
// It deliberately calls `.click()` on the existing button rather than reaching
// into the store, so every existing handler runs unchanged.

export function wireTablist(root: HTMLElement, selector: string): () => void {
  const tabs = (): HTMLElement[] => Array.from(root.querySelectorAll<HTMLElement>(selector));

  const sync = (): void => {
    for (const tab of tabs()) {
      tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
    }
  };

  const go = (index: number): void => {
    const list = tabs();
    if (list.length === 0) return;
    const target = list[((index % list.length) + list.length) % list.length]!;
    target.focus();
    target.click();
    sync();
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    const list = tabs();
    const current = list.indexOf(event.target as HTMLElement);
    if (current < 0) return;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        event.preventDefault();
        go(current + 1);
        break;
      case "ArrowLeft":
      case "ArrowUp":
        event.preventDefault();
        go(current - 1);
        break;
      case "Home":
        event.preventDefault();
        go(0);
        break;
      case "End":
        event.preventDefault();
        go(list.length - 1);
        break;
      default:
        return;
    }
  };

  // Solid delegates `onClick` to the document, so this native listener can run
  // before the store has updated `aria-selected`. Sync on the next microtask so
  // the roving tabindex follows the newly selected tab.
  const onClick = (): void => queueMicrotask(sync);

  root.addEventListener("keydown", onKeyDown);
  root.addEventListener("click", onClick);
  sync();

  return () => {
    root.removeEventListener("keydown", onKeyDown);
    root.removeEventListener("click", onClick);
  };
}
