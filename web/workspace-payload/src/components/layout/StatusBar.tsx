import { For, Show, type Component } from "solid-js";
import { formatClock } from "../../core/format";
import { CAPABILITY_KEYS, type CapabilitySet, type ConnectionStatus, type Freshness } from "../../core/types";

export const StatusBar: Component<{
  connection: ConnectionStatus;
  capabilities: CapabilitySet;
  nowMs: number;
  sessionFreshness: Freshness | null;
  protocolVersion: number | null;
  workerHealthy: boolean | null;
}> = (props) => {
  const available = () => CAPABILITY_KEYS.filter((key) => props.capabilities[key]);
  const missing = () => CAPABILITY_KEYS.filter((key) => !props.capabilities[key]);
  return (
    <footer class="status-bar" role="contentinfo">
      <span class="status-bar__item">
        <span class="status-bar__key">conn</span>
        {props.connection.phase}
        <Show when={props.connection.attempt > 0}>#{props.connection.attempt}</Show>
      </span>
      <span class="status-bar__item">
        <span class="status-bar__key">worker</span>
        {props.workerHealthy === null ? "n/a" : props.workerHealthy ? "ok" : "down"}
      </span>
      <span class="status-bar__item">
        <span class="status-bar__key">proto</span>
        {props.protocolVersion ?? "—"}
      </span>
      <span class="status-bar__item status-bar__item--grow">
        <span class="status-bar__key">capabilities</span>
        <For each={available()}>{(key) => <span class="chip chip--on">{key}</span>}</For>
        <For each={missing()}>{(key) => <span class="chip chip--off">{key}</span>}</For>
      </span>
      <Show when={props.sessionFreshness}>
        <span class="status-bar__item">
          <span class="status-bar__key">session</span>
          {formatClock(props.sessionFreshness!.receivedAtMs)}
        </span>
      </Show>
      <span class="status-bar__item">
        <span class="status-bar__key">utc</span>
        {formatClock(props.nowMs)}
      </span>
    </footer>
  );
};
