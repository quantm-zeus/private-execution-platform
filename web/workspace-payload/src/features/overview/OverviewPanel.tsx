import { For, Show, type Component } from "solid-js";
import { formatClock } from "../../core/format";
import { CAPABILITY_KEYS, ageMs as computeAge } from "../../core/types";
import { useWorkspace } from "../../state/session";
import { Badge, Metric, MetricGrid, Panel } from "../../components/ui/primitives";
import { ErrorBlock, FreshnessBadge, LoadingBlock, StaleRibbon, UnavailableBlock } from "../../components/ui/states";
import { truncateAddress } from "../../core/format";

const OverviewPanel: Component = () => {
  const ws = useWorkspace();
  const state = () => ws.state();
  const session = () => ws.session();
  const freshness = () => {
    const s = state();
    return s.kind === "ready" || s.kind === "stale" ? s.freshness : null;
  };

  return (
    <div class="panel-stack">
      <Panel
        title="Workspace session"
        subtitle="Authenticated, memory-only, fail-closed"
        badge={
          <Show when={freshness()}>
            <FreshnessBadge freshness={freshness()!} nowMs={ws.nowMs()} />
          </Show>
        }
      >
        <Show when={state().kind === "loading" || state().kind === "idle"}>
          <LoadingBlock label="Resolving workspace session and capabilities…" />
        </Show>
        <Show when={state().kind === "unavailable"}>
          <UnavailableBlock
            denial={ws.capabilityDenial("market")}
            detail="POST /v1/bootstrap is not deployed. The workspace will populate once the private API contract is available."
          />
        </Show>
        <Show when={state().kind === "error"}>
          <ErrorBlock error={(state() as { error: import("../../core/types").WorkspaceErrorShape }).error} onRetry={() => ws.reload()} />
        </Show>
        <Show when={session()}>
          {(s) => (
            <div class="panel-stack">
              <Show when={state().kind === "stale"}>
                <StaleRibbon
                  ageMs={freshness() ? computeAge(freshness()!, ws.nowMs()) : undefined}
                  reason="Session snapshot exceeds its TTL."
                />
              </Show>
              <MetricGrid>
                <Metric label="Protocol" value={s().protocolVersion} />
                <Metric
                  label="Session expires"
                  value={formatClock(s().expiresAtMs)}
                  hint={`server anchor ${formatClock(s().serverTimeMs)}`}
                />
                <Metric label="Key id" value={<code>{truncateAddress(s().keyId, 6, 4)}</code>} />
                <Metric
                  label="Trading gate"
                  value={s().tradingEnabled ? "ENABLED" : "DISABLED"}
                  tone={s().tradingEnabled ? "positive" : "danger"}
                  hint={s().killSwitch.enabled ? (s().killSwitch.reason ?? "kill switch engaged") : "no halt"}
                />
              </MetricGrid>
            </div>
          )}
        </Show>
      </Panel>

      <Panel
        title="Capability matrix"
        subtitle="Authoritative backend capability discovery"
        badge={
          <Badge tone={session() ? "info" : "muted"}>
            {session() ? `${CAPABILITY_KEYS.filter((k) => s0(session()!, k)).length}/${CAPABILITY_KEYS.length}` : "unknown"}
          </Badge>
        }
      >
        <div class="capability-grid">
          <For each={CAPABILITY_KEYS}>
            {(key) => {
              const on = () => session()?.capabilities[key] === true;
              return (
                <div class="capability" data-on={on() ? "true" : "false"}>
                  <span class={`capability__dot ${on() ? "is-on" : "is-off"}`} aria-hidden="true" />
                  <span class="capability__key">{key}</span>
                  <span class="capability__state">{session() ? (on() ? "available" : "missing") : "unknown"}</span>
                </div>
              );
            }}
          </For>
        </div>
      </Panel>

      <Panel title="Chains" subtitle="Adapter-based, enabled per deployment">
        <Show
          when={session() && session()!.chains.length > 0}
          fallback={<p class="muted">No chain metadata was provided by bootstrap.</p>}
        >
          <ul class="chain-list">
            <For each={session()!.chains}>
              {(chain) => (
                <li class="chain-list__item">
                  <Badge tone={chain.enabled ? "positive" : "muted"}>{chain.enabled ? "ENABLED" : "DISABLED"}</Badge>
                  <span class="chain-list__name">{chain.display}</span>
                  <code class="chain-list__id">{chain.id}</code>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Panel>
    </div>
  );
};

function s0(session: { capabilities: Record<string, boolean> }, key: string): boolean {
  return session.capabilities[key] === true;
}

export default OverviewPanel;
