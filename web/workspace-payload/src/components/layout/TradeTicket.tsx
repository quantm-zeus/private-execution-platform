import { Show, type Component } from "solid-js";
import { useWorkspace } from "../../state/session";
import { useWorkstation } from "../../state/workstation";
import { EmptyBlock } from "../ui/states";
import TradePanel from "../../features/trade/TradePanel";
import LimitsPanel from "../../features/limits/LimitsPanel";

/**
 * Persistent right trade ticket with exactly two primary tabs, Market and
 * Limit. Both panes stay mounted (hidden, not unmounted) so a half-entered
 * order, an UNKNOWN submission guard or a preview survives a tab switch, and
 * the shared selected instrument is never reset by switching tabs.
 */
export const TradeTicket: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const hasTarget = (): boolean => ws.selectedInstrument() !== null;

  return (
    <div class="trade-ticket" data-testid="trade-ticket">
      <div class="trade-ticket__tabs" role="tablist" aria-label="Trade ticket">
        <button
          type="button"
          role="tab"
          class="trade-ticket__tab"
          data-testid="ticket-tab-market"
          aria-selected={station.ticketTab() === "market"}
          onClick={() => station.setTicketTab("market")}
        >
          Market
        </button>
        <button
          type="button"
          role="tab"
          class="trade-ticket__tab"
          data-testid="ticket-tab-limit"
          aria-selected={station.ticketTab() === "limit"}
          onClick={() => station.setTicketTab("limit")}
        >
          Limit
        </button>
      </div>
      <div class="trade-ticket__body">
        <Show
          when={hasTarget()}
          fallback={
            <div class="trade-ticket__empty">
              <EmptyBlock
                title="No token selected"
                detail="Search or pick a token in the market rail to load its trade ticket."
              />
            </div>
          }
        >
          <div
            class="trade-ticket__pane"
            hidden={station.ticketTab() !== "market"}
            aria-hidden={station.ticketTab() !== "market"}
          >
            <TradePanel />
          </div>
          <div
            class="trade-ticket__pane"
            hidden={station.ticketTab() !== "limit"}
            aria-hidden={station.ticketTab() !== "limit"}
          >
            <LimitsPanel section="form" embedded />
          </div>
        </Show>
      </div>
    </div>
  );
};

export default TradeTicket;
