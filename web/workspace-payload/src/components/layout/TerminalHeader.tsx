import { Show, createMemo, type Component } from "solid-js";
import { formatPercent, formatUsd, truncateAddress } from "../../core/format";
import type { ConnectionStatus, InstrumentRef } from "../../core/types";
import { useWorkspace } from "../../state/session";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { requestHostLock } from "../../state/host";
import { ActionButton, Badge, StatusDot, type Tone } from "../ui/primitives";
import { TokenSearch } from "./TokenSearch";

function connectionTone(phase: ConnectionStatus["phase"]): Tone {
  switch (phase) {
    case "live":
      return "positive";
    case "connecting":
    case "reconnecting":
    case "degraded":
      return "warning";
    case "offline":
      return "danger";
    default:
      return "muted";
  }
}

function changeTone(change: number | null | undefined): Tone {
  if (change === null || change === undefined || !Number.isFinite(change)) return "muted";
  return change >= 0 ? "positive" : "danger";
}

/**
 * Compact top bar. The selected token and its live market stats are the primary
 * content; security, kill-switch and trading-gate truth is collapsed into
 * compact status controls so fail-closed state stays visible without dominating
 * the product. It carries no navigation tabs and no session/auth chrome.
 */
export const TerminalHeader: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();

  const instrument = (): InstrumentRef | null => ws.selectedInstrument();
  const stats = createMemo(() => station.visibleDetail()?.stats ?? null);

  const offline = createMemo(() =>
    ["offline", "degraded", "reconnecting"].includes(ws.connection().phase),
  );
  const tradingDisabled = createMemo(() => !ws.tradingEnabled());

  return (
    <header class="topbar" data-testid="terminal-topbar">
      <div class="topbar__lead">
        <button
          type="button"
          class="icon-button"
          aria-label="Toggle market rail"
          aria-expanded={!station.railCollapsed()}
          title="Toggle market rail"
          onClick={() => station.toggleRail()}
        >
          ▤
        </button>
        <span class="topbar__mark" aria-hidden="true">
          ◈
        </span>
        <h1 class="topbar__title">Evergreen Private Workspace</h1>
      </div>

      <TokenSearch />

      <div class="topbar__market">
        <Show
          when={instrument()}
          fallback={
            <span class="muted topbar__no-target" data-testid="selected-instrument">
              No token selected
            </span>
          }
        >
          {(ref) => (
            <span class="topbar__identity" data-testid="selected-instrument">
              <span class="topbar__symbol">{tokenLabel(ref())}</span>
              <span class="topbar__ref">
                <span class="muted">{ref().chain}</span>
                <code title={ref().address}>{truncateAddress(ref().address, 6, 6)}</code>
              </span>
            </span>
          )}
        </Show>
        <Show when={stats()}>
          {(value) => (
            <span class="topbar__stats">
              <span class="stat stat--price">
                <span class="stat__label">Price</span>
                <span class="stat__value" data-testid="token-stat-price">
                  {formatUsd(value().priceUsd, 6)}
                </span>
              </span>
              <span class={`stat stat--${changeTone(value().priceChange24h)}`}>
                <span class="stat__label">24h</span>
                <span class="stat__value" data-testid="token-stat-change">
                  {formatPercent(value().priceChange24h)}
                </span>
              </span>
              <span class="stat">
                <span class="stat__label">MCap</span>
                <span class="stat__value" data-testid="token-stat-marketcap">
                  {formatUsd(value().marketCapUsd)}
                </span>
              </span>
              <span class="stat stat--optional">
                <span class="stat__label">Liquidity</span>
                <span class="stat__value" data-testid="token-stat-liquidity">
                  {formatUsd(value().liquidityUsd)}
                </span>
              </span>
              <span class="stat stat--optional">
                <span class="stat__label">Volume</span>
                <span class="stat__value" data-testid="token-stat-volume">
                  {formatUsd(value().volume24hUsd)}
                </span>
              </span>
            </span>
          )}
        </Show>
      </div>

      <div class="topbar__status">
        <Badge tone={connectionTone(ws.connection().phase)} title={ws.connection().reason ?? undefined}>
          <StatusDot tone={connectionTone(ws.connection().phase)} label="Connection state" />
          <span data-testid="connection-phase">{ws.connection().phase.toUpperCase()}</span>
        </Badge>
        <Badge
          tone={tradingDisabled() ? "danger" : "positive"}
          title={
            tradingDisabled()
              ? "Capital-committing actions fail closed until the operator enables trading."
              : "Trading is enabled for this deployment."
          }
          data-testid="trading-gate"
        >
          {tradingDisabled() ? "TRADING DISABLED" : "TRADING ENABLED"}
        </Badge>
        <Show when={ws.killSwitch().enabled}>
          <Badge tone="danger" title={ws.killSwitch().reason ?? undefined} data-testid="kill-switch">
            HALTED
          </Badge>
        </Show>
        <Show when={offline()}>
          <Badge tone="warning" data-testid="degraded" title={ws.connection().reason ?? undefined}>
            DEGRADED
          </Badge>
        </Show>
        <Show when={station.narrow()}>
          <button
            type="button"
            class="icon-button"
            aria-label="Toggle trade ticket"
            aria-expanded={station.ticketOpen()}
            title="Toggle trade ticket"
            onClick={() => station.setTicketOpen(!station.ticketOpen())}
          >
            ⇄
          </button>
        </Show>
        <button
          type="button"
          class="icon-button"
          aria-label="Security and settings"
          aria-expanded={station.securityOpen()}
          title="Security and settings"
          onClick={() => station.openSecurity()}
        >
          ⚙
        </button>
        <ActionButton
          tone="ghost"
          onClick={() => requestHostLock()}
          title="Destroy session keys and lock the workspace"
        >
          Lock
        </ActionButton>
      </div>
    </header>
  );
};

export default TerminalHeader;
