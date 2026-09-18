import { createEffect, createSignal, onCleanup, onMount, type Component } from "solid-js";
import { useWorkstation } from "../../state/workstation";

const MIN_H = 96;
const STEP = 16;
const STEP_LARGE = 48;

function readPx(element: HTMLElement | undefined, name: string, fallback: number): number {
  if (!element || typeof getComputedStyle !== "function") return fallback;
  try {
    const raw = getComputedStyle(element).getPropertyValue(name);
    const value = Number.parseFloat(raw);
    return Number.isFinite(value) ? Math.round(value) : fallback;
  } catch {
    // jsdom (and some embedded runtimes) cannot resolve a custom property here.
    return fallback;
  }
}

/**
 * The 6 px dock resize separator above the dock.
 *
 * It is keyboard-operable (`role="separator"`, aria-orientation, live
 * aria-valuemin/now/max, ArrowUp/Down step, Home toggles, End to the ceiling)
 * and its pointer target is extended to 24 px by the stylesheet's `::after`.
 *
 * The chosen height is memory-only. The hard ceiling is computed in CSS, so no
 * drag, toggle or future caller can push the chart below its floor.
 */
export const DockResize: Component = () => {
  const station = useWorkstation();
  const [active, setActive] = createSignal(false);
  const [tick, setTick] = createSignal(0);
  let element: HTMLDivElement | undefined;

  const dockMax = (): number => {
    // Derive the ceiling from the LIVE work-area height rather than parsing the
    // `--dock-h-max` calc() (which returns an unresolved token stream). This is
    // what keeps the chart floor correct even when the offline banner adds a row.
    const workarea = element?.parentElement;
    const handleH = readPx(element, "--dock-handle-h", 6);
    const chartMinH = readPx(element, "--chart-min-h", 392);
    const workareaH = workarea?.getBoundingClientRect().height ?? 0;
    if (workareaH > 0) {
      return Math.max(MIN_H, Math.round(workareaH - handleH - chartMinH));
    }
    return Math.max(MIN_H, readPx(element, "--dock-h-max", MIN_H));
  };
  const dockClosed = (): number => readPx(document.documentElement, "--dock-h", 176);
  const dockNow = (): number => {
    tick();
    const dragged = station.dockHeight();
    if (dragged !== null) return Math.min(dragged, dockMax());
    const dock = element?.parentElement?.querySelector<HTMLElement>(".dock");
    const height = dock?.getBoundingClientRect().height ?? 0;
    if (height > 0) return Math.min(Math.round(height), dockMax());
    return Math.min(readPx(element, "--dock-h-base", 216), dockMax());
  };

  const setDock = (px: number): void => {
    const clamped = Math.max(MIN_H, Math.min(dockMax(), Math.round(px)));
    station.setDockExpanded(clamped > dockClosed() + 24);
    station.setDockHeight(clamped);
    setTick((value) => value + 1);
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    const step = event.shiftKey ? STEP_LARGE : STEP;
    switch (event.key) {
      case "ArrowUp":
        event.preventDefault();
        setDock(dockNow() + step);
        break;
      case "ArrowDown":
        event.preventDefault();
        setDock(dockNow() - step);
        break;
      case "Home":
        event.preventDefault();
        station.setDockHeight(null);
        station.toggleDockExpanded();
        setTick((value) => value + 1);
        break;
      case "End":
        event.preventDefault();
        setDock(dockMax());
        break;
      default:
        break;
    }
  };

  const onPointerDown = (event: PointerEvent): void => {
    if (event.button !== 0 || !element) return;
    event.preventDefault();
    const target = element;
    target.setPointerCapture(event.pointerId);
    setActive(true);
    const startY = event.clientY;
    const startH = dockNow();
    const move = (moveEvent: PointerEvent): void => setDock(startH + (startY - moveEvent.clientY));
    const up = (upEvent: PointerEvent): void => {
      setActive(false);
      try {
        target.releasePointerCapture(upEvent.pointerId);
      } catch {
        // Pointer already released.
      }
      target.removeEventListener("pointermove", move);
      target.removeEventListener("pointerup", up);
    };
    target.addEventListener("pointermove", move);
    target.addEventListener("pointerup", up);
  };

  // Write the desired height through CSSOM (never an inline style attribute).
  createEffect(() => {
    const root = element?.closest(".terminal") as HTMLElement | null;
    const px = station.dockHeight();
    if (!root) return;
    if (px === null) root.style.removeProperty("--dock-h-base");
    else root.style.setProperty("--dock-h-base", `${px}px`);
  });

  onMount(() => {
    const onResize = (): void => {
      setTick((value) => value + 1);
    };
    window.addEventListener("resize", onResize);
    onCleanup(() => window.removeEventListener("resize", onResize));
  });

  return (
    <div
      class="dockresize"
      role="separator"
      aria-orientation="horizontal"
      aria-label="Resize the data dock"
      aria-valuemin={MIN_H}
      aria-valuenow={dockNow()}
      aria-valuemax={dockMax()}
      data-active={active() ? "true" : undefined}
      tabindex="0"
      title="Drag, or use the arrow keys, to resize the dock"
      ref={(value) => {
        element = value;
      }}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
    />
  );
};

export default DockResize;
