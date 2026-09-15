import { For, Show, createEffect, createMemo, type Component, type JSX } from "solid-js";
import type { ProviderHealth } from "../../contracts/market";
import { formatAge } from "../../core/format";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { Badge, Metric, MetricGrid, Panel, type Tone } from "../../components/ui/primitives";
import { AsyncSurface, UnavailableBlock } from "../../components/ui/states";

/** Provider telemetry older than this is rendered as STALE. */
const PROVIDER_TTL_MS = 30_000;

interface ProviderHealthPayload {
  readonly providers: readonly ProviderHealth[];
}

const STATE_TONE: Readonly<Record<ProviderHealth["state"], Tone>> = {
  healthy: "positive",
  degraded: "warning",
  cooldown: "warning",
  circuit_open: "danger",
  unavailable: "muted",
};

function isProviderStale(provider: ProviderHealth): boolean {
  return provider.ageMs !== null && provider.ageMs > PROVIDER_TTL_MS;
}

function providerAge(provider: ProviderHealth): string {
  return provider.ageMs === null ? "—" : formatAge(provider.ageMs);
}

const ProviderTable: Component<{ providers: readonly ProviderHealth[] }> = (props) => (
  <table class="provider-table">
    <caption class="provider-table__caption">
      Backend-authoritative provider health. Stale telemetry is never treated as live.
    </caption>
    <thead>
      <tr>
        <th scope="col">Provider</th>
        <th scope="col">State</th>
        <th scope="col">Reason</th>
        <th scope="col">Age</th>
      </tr>
    </thead>
    <tbody>
      <For each={props.providers}>
        {(provider) => (
          <tr data-stale={isProviderStale(provider) ? "true" : "false"}>
            <th scope="row" class="provider-table__provider">
              {provider.provider}
            </th>
            <td>
              <span class="provider-table__state">
                <Badge tone={STATE_TONE[provider.state]}>{provider.state}</Badge>
                <Show when={isProviderStale(provider)}>
                  <Badge tone="warning" title="Provider telemetry exceeds its freshness TTL">
                    STALE
                  </Badge>
                </Show>
              </span>
            </td>
            <td class="provider-table__reason">{provider.reason ?? "—"}</td>
            <td class="provider-table__age">{providerAge(provider)}</td>
          </tr>
        )}
      </For>
    </tbody>
  </table>
);

export default function IntelligencePanel(): JSX.Element {
  const ws = useWorkspace();
  const denial = createMemo(() => ws.capabilityDenial("intelligence"));

  const health = createCommandResource<ProviderHealthPayload>(ws.command, "get_provider_health", {
    capability: "intelligence",
    ttlMs: PROVIDER_TTL_MS,
    clock: () => ws.nowMs(),
  });

  let requested = false;
  createEffect(() => {
    // Wait until the authoritative session confirms the capability *and* the
    // encrypted command channel is installed, then load once.
    if (denial() === null && ws.commandReady() && !requested) {
      requested = true;
      void health.run();
    }
  });

  const healthyCount = (providers: readonly ProviderHealth[]): number =>
    providers.filter((provider) => provider.state === "healthy").length;

  return (
    <div class="panel-stack">
      <Panel
        title="Provider health"
        subtitle="Intelligence failure degrades evidence, never execution"
        badge={
          <Badge tone={denial() ? "warning" : "info"}>
            {denial() ? "NOT DEPLOYED" : "TELEMETRY"}
          </Badge>
        }
      >
        <Show
          when={denial() === null}
          fallback={
            <UnavailableBlock
              denial={denial()}
              detail="Requires /v1/command { get_provider_health } returning provider-broker state."
            />
          }
        >
          <AsyncSurface
            state={health.state()}
            nowMs={ws.nowMs()}
            onRetry={() => void health.run()}
            emptyTitle="No provider telemetry"
            emptyDetail="Provider health is backend-authoritative and currently empty."
            isEmpty={(payload) => payload.providers.length === 0}
          >
            {(payload) => (
              <div class="panel-stack">
                <MetricGrid>
                  <Metric label="Providers" value={String(payload.providers.length)} />
                  <Metric
                    label="Healthy"
                    value={`${healthyCount(payload.providers)}/${payload.providers.length}`}
                    tone={healthyCount(payload.providers) === payload.providers.length ? "positive" : "warning"}
                  />
                  <Metric
                    label="Stale"
                    value={String(payload.providers.filter(isProviderStale).length)}
                    tone={payload.providers.some(isProviderStale) ? "warning" : "positive"}
                  />
                </MetricGrid>
                <ProviderTable providers={payload.providers} />
              </div>
            )}
          </AsyncSurface>
        </Show>
      </Panel>
    </div>
  );
}
