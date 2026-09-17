import { For, Show, type Component } from "solid-js";
import { useWorkstation, type DockTab } from "../../state/workstation";
import { CompactNote } from "../ui/states";
import PortfolioPanel from "../../features/portfolio/PortfolioPanel";
import LimitsPanel from "../../features/limits/LimitsPanel";
import ExecutionPanel from "../../features/execution/ExecutionPanel";

const DOCK_TABS: readonly { id: DockTab; label: string }[] = [
  { id: "positions", label: "Positions" },
  { id: "orders", label: "Open Orders" },
  { id: "activity", label: "Activity" },
  { id: "trades", label: "Trades" },
  { id: "holders", label: "Holders" },
];

/**
 * Compact bottom dock. Peer datasets for the selected token/account context
 * use tabs here (and only here). Surfaces whose production source is not
 * composed render a compact, truthful note instead of a placeholder.
 */
export const BottomDock: Component = () => {
  const station = useWorkstation();

  return (
    <div class="dock" data-testid="bottom-dock">
      <div class="dock__tabs" role="tablist" aria-label="Workspace data">
        <For each={DOCK_TABS}>
          {(tab) => (
            <button
              type="button"
              role="tab"
              class="dock__tab"
              data-testid={`dock-tab-${tab.id}`}
              aria-selected={station.dockTab() === tab.id}
              onClick={() => station.setDockTab(tab.id)}
            >
              {tab.label}
            </button>
          )}
        </For>
      </div>
      <div class="dock__body">
        <div hidden={station.dockTab() !== "positions"} aria-hidden={station.dockTab() !== "positions"}>
          <PortfolioPanel />
        </div>
        <div hidden={station.dockTab() !== "orders"} aria-hidden={station.dockTab() !== "orders"}>
          <LimitsPanel section="orders" embedded />
        </div>
        <div hidden={station.dockTab() !== "activity"} aria-hidden={station.dockTab() !== "activity"}>
          <ExecutionPanel />
        </div>
        <Show when={station.dockTab() === "trades"}>
          <CompactNote
            label="Trades"
            reason="No authoritative trade-tape contract is composed for this deployment."
            capability="market.trades"
          />
        </Show>
        <Show when={station.dockTab() === "holders"}>
          <CompactNote
            label="Holders"
            reason="No authoritative holder-list contract is composed for this deployment."
            capability="market.holders"
          />
        </Show>
      </div>
    </div>
  );
};

export default BottomDock;
