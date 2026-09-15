import { For, Show, createEffect, createMemo, type JSX } from "solid-js";
import { formatAge, formatClock, formatUsd, truncateAddress } from "../../core/format";
import type { AlertView, PortfolioView } from "../../contracts/execution";
import { parsePortfolioView } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import {
  ActionButton,
  Badge,
  Metric,
  MetricGrid,
  Panel,
  type Tone,
} from "../../components/ui/primitives";
import {
  AsyncSurface,
  EmptyBlock,
  FreshnessBadge,
  StaleRibbon,
  UnavailableBlock,
} from "../../components/ui/states";

/** A balance older than this is rendered as stale, never as a confident value. */
const BALANCE_TTL_MS = 30_000;

const SEVERITY_TONES: Record<AlertView["severity"], Tone> = {
  info: "info",
  warning: "warning",
  critical: "danger",
};

interface AlertsResponse {
  readonly alerts: readonly AlertView[];
}

/**
 * Owner-scoped portfolio surface.
 *
 * Balance age is evaluated per row: a value past its TTL is explicitly marked
 * stale and never presented as fresh. Unknown USD values render as an em dash,
 * never as zero.
 */
export default function PortfolioPanel(): JSX.Element {
  const ws = useWorkspace();
  const command = ws.command;

  const portfolio = createCommandResource<PortfolioView>(command, "get_portfolio", {
    capability: "portfolio",
    ttlMs: BALANCE_TTL_MS,
    clock: () => ws.nowMs(),
    // Reject an unrenderable success document as a typed error instead of
    // marking it `ready` and throwing on `balances` (F3).
    validate: parsePortfolioView,
  });
  const alerts = createCommandResource<AlertsResponse>(command, "get_alerts", {
    capability: "intelligence",
    ttlMs: BALANCE_TTL_MS,
    clock: () => ws.nowMs(),
  });

  const portfolioDenial = createMemo(() => ws.capabilityDenial("portfolio"));
  const alertsDenial = createMemo(() => ws.capabilityDenial("intelligence"));

  // Load each surface once its capability is authoritatively confirmed and the
  // encrypted command channel is installed. A one-shot `onMount` check can
  // observe the pre-bootstrap (all-false) capability set and then never load;
  // firing before the BR-5 handoff installs the real client would latch the
  // fail-closed stub's `capability_missing` as a permanent `unavailable`.
  let portfolioRequested = false;
  let alertsRequested = false;
  createEffect(() => {
    if (!portfolioRequested && portfolioDenial() === null && ws.commandReady()) {
      portfolioRequested = true;
      void portfolio.run();
    }
    if (!alertsRequested && alertsDenial() === null && ws.commandReady()) {
      alertsRequested = true;
      void alerts.run();
    }
  });

  const portfolioFreshness = () => {
    const state = portfolio.state();
    return state.kind === "ready" || state.kind === "stale" ? state.freshness : null;
  };

  return (
    <Panel
      title="Portfolio"
      subtitle="Owner-scoped balances; unknown and stale values are never rendered as confident numbers"
      badge={
        <Badge tone={portfolioDenial() ? "warning" : "positive"}>
          {portfolioDenial() ? "NOT AVAILABLE" : "AVAILABLE"}
        </Badge>
      }
    >
      <Show
        when={portfolioDenial()}
        fallback={
          <div class="panel-stack">
            <section class="portfolio" aria-label="Balances">
              <AsyncSurface
                state={portfolio.state()}
                denial={portfolioDenial()}
                nowMs={ws.nowMs()}
                onRetry={() => void portfolio.run()}
                unavailableDetail="Requires command op get_portfolio with balances, equityUsd, slot and sourceAgeMs."
              >
                {(value) => (
                  <div class="panel-stack">
                    <Show when={value.sourceAgeMs > BALANCE_TTL_MS}>
                      <StaleRibbon
                        ageMs={value.sourceAgeMs}
                        reason="Portfolio source age exceeds the freshness TTL."
                      />
                    </Show>

                    <MetricGrid>
                      <Metric
                        label="Trading wallet"
                        value={<code>{truncateAddress(value.walletRef, 8, 6)}</code>}
                      />
                      <Metric
                        label="Equity (USD)"
                        value={formatUsd(value.equityUsd)}
                        hint={`source age ${formatAge(value.sourceAgeMs)}`}
                      />
                      <Metric
                        label="Freshness"
                        value={
                          <Show
                            when={portfolioFreshness()}
                            fallback={<Badge tone="muted">UNKNOWN</Badge>}
                          >
                            {(freshness) => (
                              <FreshnessBadge
                                freshness={{
                                  receivedAtMs: freshness().receivedAtMs,
                                  sourceAgeMs: value.sourceAgeMs,
                                  ttlMs: BALANCE_TTL_MS,
                                }}
                                nowMs={ws.nowMs()}
                              />
                            )}
                          </Show>
                        }
                      />
                      <Metric
                        label="Slot"
                        value={value.slot === null ? "—" : String(value.slot)}
                      />
                    </MetricGrid>

                    <Show
                      when={value.balances.length > 0}
                      fallback={
                        <EmptyBlock
                          title="No balances"
                          detail="The backend reported an empty owner-scoped balance set."
                        />
                      }
                    >
                      <table class="data-table" aria-label="Balances">
                        <thead>
                          <tr>
                            <th scope="col">Token</th>
                            <th scope="col">Symbol</th>
                            <th scope="col">Amount</th>
                            <th scope="col">USD value</th>
                            <th scope="col">Age</th>
                            <th scope="col">Freshness</th>
                          </tr>
                        </thead>
                        <tbody>
                          <For each={value.balances}>
                            {(balance) => {
                              const stale = balance.ageMs !== null && balance.ageMs > BALANCE_TTL_MS;
                              return (
                                <tr
                                  data-balance-token={balance.token}
                                  data-stale={stale ? "true" : "false"}
                                >
                                  <td>
                                    <code title={balance.token}>
                                      {truncateAddress(balance.token, 6, 4)}
                                    </code>
                                  </td>
                                  <td>{balance.symbol}</td>
                                  <td>{balance.amount}</td>
                                  <td
                                    class={stale ? "text--warning" : undefined}
                                    data-testid="balance-usd"
                                    title={stale ? "Stale balance value" : undefined}
                                  >
                                    {formatUsd(balance.usdValue)}
                                  </td>
                                  <td>{balance.ageMs === null ? "—" : formatAge(balance.ageMs)}</td>
                                  <td>
                                    <Show
                                      when={balance.ageMs !== null}
                                      fallback={<Badge tone="muted">AGE UNKNOWN</Badge>}
                                    >
                                      <Show
                                        when={stale}
                                        fallback={<Badge tone="positive">FRESH</Badge>}
                                      >
                                        <Badge tone="warning">STALE</Badge>
                                      </Show>
                                    </Show>
                                  </td>
                                </tr>
                              );
                            }}
                          </For>
                        </tbody>
                      </table>
                    </Show>
                  </div>
                )}
              </AsyncSurface>
            </section>

            <section class="alerts" aria-label="Alerts">
              <header class="alerts__head">
                <h3>Alerts</h3>
                <ActionButton disabled={alertsDenial() !== null} onClick={() => void alerts.run()}>
                  Refresh
                </ActionButton>
              </header>
              <AsyncSurface
                state={alerts.state()}
                denial={alertsDenial()}
                nowMs={ws.nowMs()}
                onRetry={() => void alerts.run()}
                emptyTitle="No alerts"
                emptyDetail="No candidate or position alerts were reported."
                isEmpty={(value) => value.alerts.length === 0}
              >
                {(value) => (
                  <ul class="alert-list">
                    <For each={value.alerts}>
                      {(alert) => (
                        <li class="alert-list__row" data-severity={alert.severity}>
                          <Badge tone={SEVERITY_TONES[alert.severity]}>
                            {alert.severity.toUpperCase()}
                          </Badge>
                          <span class="alert-list__summary">{alert.summary}</span>
                          <Show when={alert.stale}>
                            <Badge tone="warning">STALE</Badge>
                          </Show>
                          <span class="muted">{formatClock(alert.createdAtMs)}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                )}
              </AsyncSurface>
            </section>
          </div>
        }
      >
        <UnavailableBlock
          denial={portfolioDenial()}
          detail="Requires command op get_portfolio with balances, equityUsd, slot and sourceAgeMs."
        />
      </Show>
    </Panel>
  );
}
