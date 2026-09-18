import { Show, createMemo, createSignal, onCleanup, onMount, type Component } from "solid-js";
import ChartPanel from "../chart/ChartPanel";
import { BottomDock } from "../components/layout/BottomDock";
import { DockResize } from "../components/layout/DockResize";
import { MarketRail } from "../components/layout/MarketRail";
import { SecurityDrawer } from "../components/layout/SecurityDrawer";
import { TerminalHeader } from "../components/layout/TerminalHeader";
import { TradeTicket } from "../components/layout/TradeTicket";
import { Badge } from "../components/ui/primitives";
import { formatAge, formatClock } from "../core/format";
import { useWorkspace } from "../state/session";
import { WorkstationProvider, useWorkstation } from "../state/workstation";
import { announceWorkspaceReady } from "../state/host";
import { useRealtimeFeed } from "../realtime/use-realtime";
import { RealtimeFeedProvider } from "../realtime/feed-context";
import { MarketRealtimeBridge } from "../realtime/market-bridge";

/** A 1 s clock for the status bar. It reads the raw local clock, never state. */
const StatusClock: Component = () => {
  const ws = useWorkspace();
  const [now, setNow] = createSignal(ws.clockMs());
  onMount(() => {
    const timer = setInterval(() => setNow(ws.clockMs()), 1_000);
    onCleanup(() => clearInterval(timer));
  });
  return <span class="statusbar__val">{formatClock(now())}</span>;
};

const StatusBar: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const source = createMemo(() => {
    switch (station.marketSource()) {
      case "fomo-ws":
        return "live ws";
      case "fomo-polling":
        return "polling";
      default:
        return "—";
    }
  });
  const snapshotAge = createMemo<number | null>(() => {
    const state = station.trendingState();
    if (state.kind !== "ready" && state.kind !== "stale") return null;
    return Math.max(0, ws.nowMs() - state.freshness.receivedAtMs + state.freshness.sourceAgeMs);
  });
  return (
    <footer class="statusbar" aria-label="Terminal status">
      <span class="statusbar__item">
        <span class="statusbar__key">DATA</span>
        <span class="statusbar__val">{source()}</span>
      </span>
      <span class="statusbar__item">
        <span class="statusbar__key">SNAPSHOT</span>
        <span class="statusbar__val">
          {snapshotAge() === null ? "—" : `${formatAge(snapshotAge()!)} old`}
        </span>
      </span>
      <span class="statusbar__item">
        <span class="statusbar__key">FEED</span>
        <span class="statusbar__val">{ws.connection().phase}</span>
      </span>
      <span class="statusbar__item statusbar__item--grow">
        <span class="statusbar__key">EXECUTION</span>
        <span class="statusbar__val">
          {ws.tradingEnabled() ? "enabled" : "fail-closed"}
        </span>
      </span>
      <span class="statusbar__item statusbar__spacer">
        <StatusClock />
      </span>
    </footer>
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
      data-dock-size={station.dockExpanded() ? "expanded" : "default"}
      data-offline={offline() ? "true" : undefined}
    >
      <a class="skip-link" href="#terminal-main">
        Skip to chart
      </a>
      <TerminalHeader />
      <Show when={offline()}>
        <div class="offline-banner" role="status" aria-live="polite">
          <Badge tone="warning">{ws.connection().phase.toUpperCase()}</Badge>
          <span>
            {ws.connection().reason ?? "Realtime stream is not connected."} Trading controls fail
            closed.
          </span>
        </div>
      </Show>
      <div class="terminal__body">
        <aside class="rail" aria-label="Market rail">
          <MarketRail />
        </aside>
        <main id="terminal-main" class="workarea" tabindex="-1" aria-label="Trading workstation">
          <section class="chart-pane" aria-label="Price chart">
            <ChartPanel />
          </section>
          <DockResize />
          <BottomDock />
        </main>
        <aside class="ticket-pane" aria-label="Trade ticket">
          <TradeTicket />
        </aside>
      </div>
      <StatusBar />
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
