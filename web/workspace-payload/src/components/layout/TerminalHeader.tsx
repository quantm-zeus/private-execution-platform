import { Show, createMemo, type Component } from "solid-js";
import { formatPercent, formatUsd } from "../../core/format";
import type { ConnectionStatus, InstrumentRef } from "../../core/types";
import { useWorkspace } from "../../state/session";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { requestHostLock } from "../../state/host";
import { AddressCopy } from "../ui/AddressCopy";
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

function changeTone(change: number | null | undefined): string {
  if (change === null || change === undefined || !Number.isFinite(change)) return "flat";
  return change >= 0 ? "up" : "down";
}

/**
 * Top instrument bar. Left -> right: brand -> instrument identity -> the
 * instrument price block (the one decisive flourish) -> the stat strip -> the
 * pinned status cluster. Amber appears here exactly twice: the 6x18 brand rule
 * and the 2px price rule. The bar is 56px and single-row at every width.
 */
export const TerminalHeader: Component = () => {
  const ws = useWorkspace();
  const station = useWorkstation();

  const instrument = (): InstrumentRef | null => ws.selectedInstrument();
  const stats = createMemo(() => station.visibleDetail()?.stats ?? null);
  const live = createMemo(() => {
    const ref = instrument();
    return ref ? station.latestPrice(ref) : null;
  });
  const statView = createMemo(() => {
    const detail = stats();
    const tick = live();
    if (!detail && !tick) return null;
    return {
      priceUsd: tick?.priceUsd ?? detail?.priceUsd ?? null,
      priceChange24h: tick?.priceChange24h ?? detail?.priceChange24h ?? null,
      marketCapUsd: tick?.marketCapUsd ?? detail?.marketCapUsd ?? null,
      liquidityUsd: tick?.liquidityUsd ?? detail?.liquidityUsd ?? null,
      volume24hUsd: tick?.volume24hUsd ?? detail?.volume24hUsd ?? null,
    };
  });
  const sourceLabel = createMemo(() => {
    switch (station.marketSource()) {
      case "fomo-ws":
        return "LIVE WS";
      case "fomo-polling":
        return "POLLING";
      default:
        return null;
    }
  });

  const offline = createMemo(() =>
    ["offline", "degraded", "reconnecting"].includes(ws.connection().phase),
  );
  const tradingDisabled = createMemo(() => !ws.tradingEnabled());

  return (
    <header class="topbar" data-testid="terminal-topbar">
      <div class="topbar__brand">
        <span class="topbar__mark" aria-hidden="true" />
        <span class="topbar__title">EverCrest</span>
        <button
          type="button"
          class="icon-button"
          aria-label="Toggle market rail"
          aria-expanded={!station.railCollapsed()}
          title="Toggle market rail"
          onClick={() => station.toggleRail()}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M2 4h12M2 8h12M2 12h12" />
          </svg>
        </button>
      </div>

      <span class="vrule" aria-hidden="true" />

      {/* Search lives in the rail; when the rail is collapsed at the narrow
          tiers it falls back here so exact search stays reachable. */}
      <Show when={station.railCollapsed()}>
        <div class="topbar__search">
          <TokenSearch />
        </div>
      </Show>

      <Show
        when={instrument()}
        fallback={
          <span class="topbar__identity" data-testid="selected-instrument">
            <h1 class="topbar__symbol">—</h1>
            <span class="topbar__ref">
              <span class="muted">No token selected</span>
            </span>
          </span>
        }
      >
        {(ref) => (
          <span class="topbar__identity" data-testid="selected-instrument">
            <h1 class="topbar__symbol">{tokenLabel(ref())}</h1>
            <span class="topbar__ref">
              <span class="muted">{ref().chain}</span>
              <AddressCopy address={ref().address} chain={ref().chain} />
            </span>
          </span>
        )}
      </Show>

      <Show when={statView()}>
        {(value) => (
          <>
            <div class="priceblock">
              <span class="priceblock__rule" aria-hidden="true" />
              <div class="priceblock__col">
                <span class="lbl">Price</span>
                <span class="priceblock__price" data-testid="token-stat-price">
                  {formatUsd(value().priceUsd, 6)}
                </span>
              </div>
              <div class="priceblock__col">
                <span class="lbl">24h</span>
                <span
                  class={`priceblock__chg ${changeTone(value().priceChange24h)}`}
                  data-testid="token-stat-change"
                >
                  {formatPercent(value().priceChange24h)}
                </span>
              </div>
            </div>
            <dl class="statstrip" aria-label="Selected token stats">
              <div class="statstrip__item">
                <dt class="lbl">MCap</dt>
                <dd class="statstrip__value" data-testid="token-stat-marketcap">
                  {formatUsd(value().marketCapUsd)}
                </dd>
              </div>
              <div class="statstrip__item" data-fold="1">
                <dt class="lbl">Liquidity</dt>
                <dd class="statstrip__value" data-testid="token-stat-liquidity">
                  {formatUsd(value().liquidityUsd)}
                </dd>
              </div>
              <div class="statstrip__item" data-fold="1">
                <dt class="lbl">Volume 24h</dt>
                <dd class="statstrip__value" data-testid="token-stat-volume">
                  {formatUsd(value().volume24hUsd)}
                </dd>
              </div>
            </dl>
          </>
        )}
      </Show>

      <div class="topbar__status">
        <Show when={sourceLabel()}>
          <Badge
            tone={station.marketSource() === "fomo-ws" ? "positive" : "muted"}
            title="Provenance of the live market lane"
            data-testid="market-source"
          >
            {sourceLabel()}
          </Badge>
        </Show>
        <Badge
          tone={connectionTone(ws.connection().phase)}
          title={ws.connection().reason ?? undefined}
        >
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
        {/* At most four badges: the degraded state is folded into the halt slot
            rather than stacked beside it. */}
        <Show when={!ws.killSwitch().enabled && offline()}>
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
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
              <rect x="2.5" y="3" width="11" height="10" rx="1.5" />
              <path d="M6.5 3v10" />
            </svg>
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
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <circle cx="8" cy="8" r="2.2" />
            <path d="M8 1.5v1.8M8 12.7v1.8M14.5 8h-1.8M3.3 8H1.5M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3M12.6 12.6l-1.3-1.3M4.7 4.7L3.4 3.4" />
          </svg>
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
