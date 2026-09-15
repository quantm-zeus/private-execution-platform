import { Show, type Component } from "solid-js";
import { formatAge, truncateAddress } from "../../core/format";
import type { ConnectionStatus, InstrumentRef, KillSwitchState } from "../../core/types";
import { ActionButton, Badge, type Tone } from "../ui/primitives";

function connectionTone(phase: ConnectionStatus["phase"]): Tone {
  switch (phase) {
    case "live":
      return "positive";
    case "connecting":
    case "reconnecting":
      return "warning";
    case "degraded":
      return "warning";
    case "offline":
      return "danger";
    default:
      return "muted";
  }
}

export const WorkspaceHeader: Component<{
  connection: ConnectionStatus;
  killSwitch: KillSwitchState;
  tradingEnabled: boolean;
  nowMs: number;
  /** Shared Discover target; `null` renders an explicit no-selection state. */
  instrument: InstrumentRef | null;
  onLock: () => void;
}> = (props) => {
  const lastFrameAge = () =>
    props.connection.lastFrameAtMs === null ? null : Math.max(0, props.nowMs - props.connection.lastFrameAtMs);
  return (
    <header class="ws-header">
      <div class="ws-header__brand">
        <span class="ws-header__mark" aria-hidden="true">
          ◈
        </span>
        <div>
          <h1 class="ws-header__title">Evergreen Private Workspace</h1>
          <p class="ws-header__subtitle">Memory-only session · no persistent private state</p>
        </div>
      </div>
      <span class="ws-header__target" data-testid="selected-instrument">
        <Show
          when={props.instrument}
          fallback={<span class="muted">No target selected</span>}
        >
          {(instrument) => (
            <>
              <Badge tone="info">{instrument().symbol}</Badge>
              <code title={instrument().address}>
                {truncateAddress(instrument().address, 6, 6)}
              </code>
              <span class="muted">{instrument().chain}</span>
            </>
          )}
        </Show>
      </span>
      <div class="ws-header__status">
        <Badge tone={connectionTone(props.connection.phase)} title={props.connection.reason ?? undefined}>
          {props.connection.phase.toUpperCase()}
        </Badge>
        <Show when={lastFrameAge() !== null}>
          <span class="ws-header__meta">last frame {formatAge(lastFrameAge()!)} ago</span>
        </Show>
        <Badge tone={props.tradingEnabled ? "info" : "danger"}>
          {props.tradingEnabled ? "TRADING ENABLED" : "TRADING DISABLED"}
        </Badge>
        <Show when={props.killSwitch.enabled}>
          <Badge tone="danger" title={props.killSwitch.reason ?? undefined}>
            KILL SWITCH
          </Badge>
        </Show>
        <ActionButton tone="ghost" onClick={props.onLock} title="Destroy session keys and lock the workspace">
          Lock
        </ActionButton>
      </div>
    </header>
  );
};
