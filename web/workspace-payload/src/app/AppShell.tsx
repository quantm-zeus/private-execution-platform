import { Show, createMemo, createSignal, onMount, type Component } from "solid-js";
import { Dynamic } from "solid-js/web";
import type { ViewId } from "./views";
import { surfaceFor, viewMeta } from "../features/surfaces";
import { NavRail } from "../components/layout/NavRail";
import { StatusBar } from "../components/layout/StatusBar";
import { WorkspaceHeader } from "../components/layout/WorkspaceHeader";
import { Badge } from "../components/ui/primitives";
import { useWorkspace } from "../state/session";
import { announceWorkspaceReady, requestHostLock } from "../state/host";
import { useRealtimeFeed } from "../realtime/use-realtime";
import { RealtimeFeedProvider } from "../realtime/feed-context";

export const AppShell: Component = () => {
  const ws = useWorkspace();
  const feed = useRealtimeFeed(ws);
  const [active, setActive] = createSignal<ViewId>("overview");
  const meta = createMemo(() => viewMeta(active()));
  const panel = createMemo(() => surfaceFor(active()));
  const sessionFreshness = createMemo(() => {
    const state = ws.state();
    return state.kind === "ready" || state.kind === "stale" ? state.freshness : null;
  });
  const offline = createMemo(() =>
    ["offline", "degraded", "reconnecting"].includes(ws.connection().phase),
  );

  onMount(() => announceWorkspaceReady());

  return (
    <RealtimeFeedProvider feed={feed}>
      <div class="workspace" data-view={active()}>
      <a class="skip-link" href="#workspace-main">
        Skip to workspace content
      </a>
      <WorkspaceHeader
        connection={ws.connection()}
        killSwitch={ws.killSwitch()}
        tradingEnabled={ws.tradingEnabled()}
        nowMs={ws.nowMs()}
        onLock={() => {
          requestHostLock();
        }}
      />
      <Show when={offline()}>
        <div class="offline-banner" role="status" aria-live="polite">
          <Badge tone="warning">{ws.connection().phase.toUpperCase()}</Badge>
          <span>
            {ws.connection().reason ?? "Realtime stream is not connected."} Trading controls fail closed.
          </span>
        </div>
      </Show>
      <div class="workspace__body">
        <NavRail
          active={active()}
          onSelect={(id) => {
            setActive(id);
            queueMicrotask(() => document.getElementById("workspace-main")?.focus());
          }}
          capabilityOf={(view) => ws.capabilities()[view.capability] === true}
        />
        <main id="workspace-main" class="workspace__main" tabindex="-1" aria-labelledby="view-title">
          <header class="view-head">
            <div>
              <h2 class="view-head__title" id="view-title">
                {meta().label}
              </h2>
              <p class="view-head__desc">{meta().description}</p>
            </div>
            <Badge tone={ws.capabilities()[meta().capability] ? "positive" : "warning"}>
              {meta().capability}
            </Badge>
          </header>
          <Dynamic component={panel()} />
        </main>
      </div>
      <StatusBar
        connection={ws.connection()}
        capabilities={ws.capabilities()}
        nowMs={ws.nowMs()}
        sessionFreshness={sessionFreshness()}
        protocolVersion={ws.session()?.protocolVersion ?? null}
        workerHealthy={feed.started() ? feed.status().phase !== "offline" : null}
      />
      </div>
    </RealtimeFeedProvider>
  );
};
