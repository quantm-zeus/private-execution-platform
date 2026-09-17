import { For, Show, createMemo, type Component } from "solid-js";
import { formatPercent, formatUsd, truncateAddress } from "../../core/format";
import type { ConnectionStatus, InstrumentRef } from "../../core/types";
import type { TokenRef } from "../../contracts/market";
import { useWorkspace } from "../../state/session";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { requestHostLock } from "../../state/host";
import { ActionButton, Badge, StatusDot, type Tone } from "../ui/primitives";

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
 * Compact top bar: global token search, selected-instrument identity and live
 * stats, connection/market health, the on-demand security drawer and the single
 * Lock action. It carries no navigation tabs and no session/auth chrome.
 */
export const TerminalHeader: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();

  const instrument = (): InstrumentRef | null => ws.selectedInstrument();
  const stats = createMemo(() => station.visibleDetail()?.stats ?? null);
  const results = createMemo<readonly TokenRef[]>(() => {
    const state = station.searchState();
    return state.kind === "ready" || state.kind === "stale" ? state.value.results : [];
  });

  const offline = createMemo(() =>
    ["offline", "degraded", "reconnecting"].includes(ws.connection().phase),
  );

  const submit = (event: Event): void => {
    event.preventDefault();
    station.runSearch(station.query());
  };

  return (
    <header class="topbar" data-testid="terminal-topbar">
      <div class="topbar__brand">
        <span class="topbar__mark" aria-hidden="true">
          ◈
        </span>
        <h1 class="topbar__title">Evergreen Private Workspace</h1>
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
      </div>

      <form class="topbar__search" role="search" onSubmit={submit}>
        <label class="sr-only" for="global-token-search">
          Search token
        </label>
        <input
          id="global-token-search"
          class="input"
          type="search"
          placeholder="Search token, symbol or address"
          aria-label="Search token"
          autocomplete="off"
          value={station.query()}
          onInput={(event) => station.setQuery(event.currentTarget.value)}
        />
        <Show when={results().length > 0}>
          <div class="search-popover" aria-label="Token search results">
            <For each={results()}>
              {(token) => (
                <button
                  type="button"
                  class="link-button"
                  onClick={() => station.selectInstrument(token)}
                >
                  <span class="search-results__symbol">{tokenLabel(token)}</span>
                  <code class="search-results__address">{truncateAddress(token.address, 6, 6)}</code>
                  <Badge tone="muted">{token.chain}</Badge>
                </button>
              )}
            </For>
          </div>
        </Show>
      </form>

      <div class="topbar__identity">
        <Show
          when={instrument()}
          fallback={
            <span class="muted" data-testid="selected-instrument">
              No token selected
            </span>
          }
        >
          {(ref) => (
            <span class="topbar__identity" data-testid="selected-instrument">
              <Badge tone="info">{ref().symbol}</Badge>
              <code title={ref().address}>{truncateAddress(ref().address, 6, 6)}</code>
              <span class="muted">{ref().chain}</span>
            </span>
          )}
        </Show>
        <Show when={stats()}>
          {(value) => (
            <span class="topbar__stats">
              <span class="stat">
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
              <span class="stat">
                <span class="stat__label">Liquidity</span>
                <span class="stat__value" data-testid="token-stat-liquidity">
                  {formatUsd(value().liquidityUsd)}
                </span>
              </span>
              <span class="stat">
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
        <Show when={ws.killSwitch().enabled}>
          <Badge tone="danger" title={ws.killSwitch().reason ?? undefined} data-testid="kill-switch">
            KILL SWITCH
          </Badge>
        </Show>
        <Show when={offline()}>
          <Badge tone="warning" data-testid="degraded">
            DEGRADED
          </Badge>
        </Show>
        <Badge tone={ws.tradingEnabled() ? "info" : "danger"} data-testid="trading-gate">
          {ws.tradingEnabled() ? "TRADING ENABLED" : "TRADING DISABLED"}
        </Badge>
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
