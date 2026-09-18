import { Show, createMemo, onMount, type Component } from "solid-js";
import ChartPanel from "../chart/ChartPanel";
import { BottomDock } from "../components/layout/BottomDock";
import { MarketRail } from "../components/layout/MarketRail";
import { SecurityDrawer } from "../components/layout/SecurityDrawer";
import { TerminalHeader } from "../components/layout/TerminalHeader";
import { TradeTicket } from "../components/layout/TradeTicket";
import { Badge } from "../components/ui/primitives";
import { useWorkspace } from "../state/session";
import { WorkstationProvider, useWorkstation } from "../state/workstation";
import { announceWorkspaceReady } from "../state/host";
import { useRealtimeFeed } from "../realtime/use-realtime";
import { RealtimeFeedProvider } from "../realtime/feed-context";
import { MarketRealtimeBridge } from "../realtime/market-bridge";
import { formatBps } from "../core/format";

/**
 * Compact selected-token risk context for the centre pane. Every value is
 * unknown-safe: a missing assessment renders an explicit dash, never a zero.
 */
const TokenRiskStrip: Component = () => {
  const station = useWorkstation();
  const risk = createMemo(() => station.visibleDetail()?.risk ?? null);
  return (
    <Show when={risk()}>
      {(value) => (
        <span class="chart-pane__stats" data-testid="token-risk">
          <span>
            risk {value().score === null ? "—" : value().score}
          </span>
          <span>buy tax {formatBps(value().buyTaxBps)}</span>
          <span>sell tax {formatBps(value().sellTaxBps)}</span>
          <Show when={value().sellRestricted === true}>
            <Badge tone="danger">SELL RESTRICTED</Badge>
          </Show>
        </span>
      )}
    </Show>
  );
};

const Terminal: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const offline = createMemo(() =>
    ["offline", "degraded", "reconnecting"].includes(ws.connection().phase),
  );

  return (
    <div
      class="terminal workspace"
      data-rail={station.railCollapsed() ? "collapsed" : "expanded"}
      data-ticket={station.ticketOpen() ? "open" : "closed"}
    >
      <a class="skip-link" href="#terminal-main">
        Skip to chart
      </a>
      <TerminalHeader />
      <Show when={offline()}>
        <div class="offline-banner" role="status" aria-live="polite">
          <Badge tone="warning">{ws.connection().phase.toUpperCase()}</Badge>
          <span>
            {ws.connection().reason ?? "Realtime stream is not connected."} Trading controls fail closed.
          </span>
        </div>
      </Show>
      <div class="terminal__body">
        <aside class="rail" aria-label="Market rail">
          <MarketRail />
        </aside>
        <main id="terminal-main" class="workarea" tabindex="-1" aria-label="Trading workstation">
          <section class="chart-pane" aria-label="Price chart">
            <div class="chart-pane__bar">
              <div class="chart-pane__identity">
                <span class="chart-pane__symbol">
                  {ws.selectedInstrument()?.symbol ?? "Price"}
                </span>
                <span class="muted">
                  {ws.selectedInstrument()?.chain ?? "Select a token to load its chart"}
                </span>
              </div>
              <TokenRiskStrip />
            </div>
            <ChartPanel />
          </section>
          <BottomDock />
        </main>
        <aside class="ticket-pane" aria-label="Trade ticket">
          <TradeTicket />
        </aside>
      </div>
      <SecurityDrawer />
    </div>
  );
};

export const AppShell: Component = () => {
  const ws = useWorkspace();
  const feed = useRealtimeFeed(ws);

  onMount(() => announceWorkspaceReady());

  return (
    <RealtimeFeedProvider feed={feed}>
      <WorkstationProvider ws={ws}>
        <MarketRealtimeBridge />
        <Terminal />
      </WorkstationProvider>
    </RealtimeFeedProvider>
  );
};

export default AppShell;
