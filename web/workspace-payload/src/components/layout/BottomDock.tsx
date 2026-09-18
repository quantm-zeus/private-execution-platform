import { For, Show, onCleanup, type Component } from "solid-js";
import { useWorkstation, type DockTab } from "../../state/workstation";
import { wireTablist } from "../ui/tablist";
import PortfolioPanel from "../../features/portfolio/PortfolioPanel";
import LimitsPanel from "../../features/limits/LimitsPanel";
import ActivityWorkspace from "../../features/intelligence/ActivityWorkspace";
import HolderTradersPanel from "../../features/intelligence/HolderTradersPanel";
import TokenOverviewPanel from "../../features/intelligence/TokenOverviewPanel";

const DOCK_TABS: readonly { id: DockTab; label: string; count?: boolean }[] = [
  { id: "positions", label: "Positions", count: true },
  { id: "orders", label: "Open Orders", count: true },
  { id: "activity", label: "Activity", count: true },
  { id: "holders", label: "Holders", count: true },
  // About carries no count slot: it has no natural count, and a permanent `—`
  // would read as a loading state.
  { id: "about", label: "About" },
];

/**
 * Bottom dock: exactly five tabs — Positions / Open Orders / Activity /
 * Holders / About. The former Trades tab is removed (the exact-token activity
 * feed under Activity -> Token supersedes it); `RealtimeChannel`'s own "trades"
 * member is a transport channel and is untouched.
 *
 * Counts render `—` when unknown — never `0`.
 */
export const BottomDock: Component = () => {
  const station = useWorkstation();

  const holdersCount = (): string => {
    const state = station.holders.state();
    if (state.kind !== "ready" && state.kind !== "stale") return "—";
    return String(state.value.holders.length);
  };
  const countFor = (id: DockTab): string | null => {
    if (id === "holders") return holdersCount();
    return "—";
  };

  return (
    <div class="dock" data-testid="bottom-dock">
      <div class="dock__tabs">
        <div
          class="dock__tablist"
          role="tablist"
          aria-label="Workspace data"
          ref={(element) => onCleanup(wireTablist(element, ".dock__tab"))}
        >
          <For each={DOCK_TABS}>
            {(tab) => (
              <button
                type="button"
                role="tab"
                class="dock__tab"
                id={`dock-tab-${tab.id}`}
                data-testid={`dock-tab-${tab.id}`}
                aria-selected={station.dockTab() === tab.id}
                aria-controls="dock-body"
                onClick={() => station.setDockTab(tab.id)}
              >
                {tab.label}
                <Show when={tab.count}>
                  <span class="tabs__count">{countFor(tab.id)}</span>
                </Show>
              </button>
            )}
          </For>
        </div>
        <button
          type="button"
          class="icon-button dock__expand"
          data-testid="dock-expand"
          aria-expanded={station.dockExpanded()}
          aria-label={station.dockExpanded() ? "Collapse the data dock" : "Expand the data dock"}
          title={station.dockExpanded() ? "Collapse the data dock" : "Expand the data dock"}
          onClick={() => {
            station.setDockHeight(null);
            station.toggleDockExpanded();
          }}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d={station.dockExpanded() ? "M4 6l4 4 4-4" : "M4 10l4-4 4 4"} />
          </svg>
        </button>
      </div>
      <div
        class="dock__body"
        id="dock-body"
        role="tabpanel"
        aria-labelledby={`dock-tab-${station.dockTab()}`}
      >
        <div
          class="dock__pane"
          hidden={station.dockTab() !== "positions"}
          aria-hidden={station.dockTab() !== "positions"}
        >
          <PortfolioPanel />
        </div>
        <div
          class="dock__pane"
          hidden={station.dockTab() !== "orders"}
          aria-hidden={station.dockTab() !== "orders"}
        >
          <LimitsPanel section="orders" embedded />
        </div>
        <div
          class="dock__pane dock__pane--flush"
          hidden={station.dockTab() !== "activity"}
          aria-hidden={station.dockTab() !== "activity"}
        >
          <ActivityWorkspace embedded />
        </div>
        <div
          class="dock__pane dock__pane--flush"
          hidden={station.dockTab() !== "holders"}
          aria-hidden={station.dockTab() !== "holders"}
        >
          <HolderTradersPanel embedded />
        </div>
        <div
          class="dock__pane dock__pane--flush"
          hidden={station.dockTab() !== "about"}
          aria-hidden={station.dockTab() !== "about"}
        >
          <TokenOverviewPanel embedded />
        </div>
      </div>
    </div>
  );
};

export default BottomDock;
