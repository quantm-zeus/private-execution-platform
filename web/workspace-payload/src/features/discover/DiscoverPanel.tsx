import {
  For,
  Show,
  createMemo,
  createSignal,
  onCleanup,
  type Component,
  type JSX,
} from "solid-js";
import type { EvidenceItem, RiskFactor, TokenDetail, TokenRef } from "../../contracts/market";
import {
  formatAge,
  formatAmount,
  formatBps,
  formatPercent,
  formatUsd,
  truncateAddress,
} from "../../core/format";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import {
  ActionButton,
  Badge,
  Field,
  KeyValue,
  Metric,
  MetricGrid,
  Panel,
  type Tone,
} from "../../components/ui/primitives";
import { AsyncSurface, EmptyBlock, UnavailableBlock } from "../../components/ui/states";

/** Evidence older than this (or explicitly flagged) is rendered as STALE. */
const EVIDENCE_TTL_MS = 30_000;
const SEARCH_TTL_MS = 30_000;
const DETAIL_TTL_MS = 30_000;
/** Trailing debounce for search-as-you-type. */
const SEARCH_DEBOUNCE_MS = 300;

interface SearchPayload {
  readonly results: readonly TokenRef[];
}

const SEVERITY_TONE: Readonly<Record<RiskFactor["severity"], Tone>> = {
  info: "info",
  low: "muted",
  medium: "warning",
  high: "danger",
  critical: "danger",
};

function tokenLabel(token: TokenRef): string {
  if (token.symbol && token.symbol.length > 0) return token.symbol;
  if (token.name && token.name.length > 0) return token.name;
  return truncateAddress(token.address);
}

function isEvidenceStale(item: EvidenceItem): boolean {
  return item.stale === true || item.ageMs > EVIDENCE_TTL_MS;
}

function riskScoreTone(score: number | null): Tone {
  if (score === null || !Number.isFinite(score)) return "neutral";
  if (score >= 70) return "danger";
  if (score >= 40) return "warning";
  return "positive";
}

function changeTone(change: number | null): Tone {
  if (change === null || !Number.isFinite(change)) return "neutral";
  return change >= 0 ? "positive" : "danger";
}

const TokenDetailView: Component<{ detail: TokenDetail }> = (props) => {
  const stats = () => props.detail.stats;
  const risk = () => props.detail.risk;
  const evidence = () => props.detail.evidence;

  return (
    <div class="panel-stack">
      <div class="token-head">
        <Badge tone="info">{props.detail.token.chain}</Badge>
        <strong class="token-head__symbol">{tokenLabel(props.detail.token)}</strong>
        <code class="token-head__address" title={props.detail.token.address}>
          {truncateAddress(props.detail.token.address, 6, 6)}
        </code>
      </div>

      <KeyValue
        rows={[
          { key: "chain", label: "Chain", value: props.detail.token.chain },
          {
            key: "address",
            label: "Address",
            value: <code>{truncateAddress(props.detail.token.address, 8, 8)}</code>,
          },
          {
            key: "slot",
            label: "Slot",
            value: props.detail.slot === null ? "—" : String(props.detail.slot),
          },
          { key: "age", label: "Source age", value: formatAge(props.detail.sourceAgeMs) },
        ]}
      />

      <Show
        when={stats()}
        fallback={
          <EmptyBlock
            title="No market stats"
            detail="The provider returned no stats for this token."
          />
        }
      >
        {(value) => (
          <MetricGrid>
            <Metric label="Price" value={formatUsd(value().priceUsd, 6)} />
            <Metric
              label="24h change"
              value={formatPercent(value().priceChange24h)}
              tone={changeTone(value().priceChange24h)}
            />
            <Metric label="Market cap" value={formatUsd(value().marketCapUsd)} />
            <Metric label="Liquidity" value={formatUsd(value().liquidityUsd)} />
            <Metric label="Volume 24h" value={formatUsd(value().volume24hUsd)} />
            <Metric label="Holders" value={formatAmount(value().holders, 0)} />
          </MetricGrid>
        )}
      </Show>

      <Show
        when={risk()}
        fallback={
          <EmptyBlock
            title="No risk assessment"
            detail="The provider returned no safety data for this token."
          />
        }
      >
        {(value) => (
          <div class="panel-stack">
            <MetricGrid>
              <Metric
                label="Risk score"
                value={value().score === null ? "—" : String(value().score)}
                tone={riskScoreTone(value().score)}
              />
              <Metric label="Buy tax" value={formatBps(value().buyTaxBps)} />
              <Metric label="Sell tax" value={formatBps(value().sellTaxBps)} />
              <Metric label="Transfer fee" value={formatBps(value().transferFeeBps)} />
              <Metric
                label="Sell restricted"
                value={
                  value().sellRestricted === null
                    ? "—"
                    : value().sellRestricted
                      ? "YES"
                      : "No"
                }
                tone={
                  value().sellRestricted === null
                    ? "neutral"
                    : value().sellRestricted
                      ? "danger"
                      : "positive"
                }
              />
              <Metric label="Simulated" value={value().simulated ? "yes" : "no"} />
            </MetricGrid>
            <Show
              when={value().factors.length > 0}
              fallback={<p class="muted">No risk factors reported.</p>}
            >
              <ul class="risk-factors">
                <For each={value().factors}>
                  {(factor) => (
                    <li class="risk-factor">
                      <Badge tone={SEVERITY_TONE[factor.severity]}>{factor.severity}</Badge>
                      <strong class="risk-factor__label">{factor.label}</strong>
                      <span class="risk-factor__detail">{factor.detail}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </div>
        )}
      </Show>

      <Show
        when={evidence().length > 0}
        fallback={<EmptyBlock title="No evidence" detail="No provider evidence was returned." />}
      >
        <ul class="evidence-list">
          <For each={evidence()}>
            {(item) => (
              <li class="evidence-item" data-stale={isEvidenceStale(item) ? "true" : "false"}>
                <div class="evidence-item__head">
                  <Badge tone="info">{item.provider}</Badge>
                  <span class="evidence-item__kind">{item.kind}</span>
                  <Show when={isEvidenceStale(item)}>
                    <Badge tone="warning" title="Evidence exceeds its freshness TTL">
                      STALE
                    </Badge>
                  </Show>
                </div>
                <p class="evidence-item__summary">{item.summary}</p>
                <p class="evidence-item__meta">
                  age {formatAge(item.ageMs)} · confidence {formatPercent(item.confidence)}
                </p>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </div>
  );
};

export default function DiscoverPanel(): JSX.Element {
  const ws = useWorkspace();
  const denial = createMemo(() => ws.capabilityDenial("intelligence"));

  const [query, setQuery] = createSignal("");
  const [selected, setSelected] = createSignal<TokenRef | null>(null);

  const search = createCommandResource<SearchPayload>(ws.command, "search_token", {
    capability: "intelligence",
    ttlMs: SEARCH_TTL_MS,
    clock: () => ws.nowMs(),
  });
  const detail = createCommandResource<TokenDetail>(ws.command, "get_token", {
    capability: "intelligence",
    ttlMs: DETAIL_TTL_MS,
    clock: () => ws.nowMs(),
  });

  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  const clearDebounce = (): void => {
    if (debounceTimer !== undefined) {
      clearTimeout(debounceTimer);
      debounceTimer = undefined;
    }
  };
  onCleanup(clearDebounce);

  const runSearch = (raw: string): void => {
    const value = raw.trim();
    // An empty query must never reach the command channel.
    if (value.length === 0) return;
    void search.run({ query: value });
  };

  const handleInput = (value: string): void => {
    setQuery(value);
    clearDebounce();
    if (value.trim().length === 0) return;
    debounceTimer = setTimeout(() => {
      debounceTimer = undefined;
      runSearch(value);
    }, SEARCH_DEBOUNCE_MS);
  };

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    clearDebounce();
    runSearch(query());
  };

  const isSelected = (token: TokenRef): boolean => {
    const current = selected();
    return current !== null && current.chain === token.chain && current.address === token.address;
  };

  const selectToken = (token: TokenRef): void => {
    setSelected(token);
    void detail.run({ chain: token.chain, address: token.address });
  };

  const retryDetail = (): void => {
    const token = selected();
    if (!token) return;
    void detail.run({ chain: token.chain, address: token.address });
  };

  const searchStatus = (): string => {
    const state = search.state();
    switch (state.kind) {
      case "loading":
        return "Searching…";
      case "ready":
      case "stale":
        return `${state.value.results.length} result${state.value.results.length === 1 ? "" : "s"}.`;
      case "error":
        return "Search failed.";
      case "unavailable":
        return "Search is unavailable on this deployment.";
      default:
        return "";
    }
  };

  const detailStatus = (): string => {
    const state = detail.state();
    switch (state.kind) {
      case "loading":
        return "Loading token detail…";
      case "ready":
      case "stale":
        return "Token detail loaded.";
      case "error":
        return "Token detail failed to load.";
      case "unavailable":
        return "Token detail is unavailable on this deployment.";
      default:
        return "";
    }
  };

  return (
    <div class="panel-stack">
      <Panel
        title="Token discovery"
        subtitle="Search candidates, then inspect market, risk and evidence provenance"
        badge={
          <Badge tone={denial() ? "warning" : "positive"}>
            {denial() ? "NOT DEPLOYED" : "AVAILABLE"}
          </Badge>
        }
      >
        <Show
          when={denial() === null}
          fallback={
            <UnavailableBlock
              denial={denial()}
              detail="Requires /v1/command { search_token, get_token } with provider freshness metadata."
            />
          }
        >
          <form class="inline-form" onSubmit={handleSubmit}>
            <Field
              label="Search token"
              forId="discover-token-query"
              hint="Symbol, name or contract address."
            >
              <input
                id="discover-token-query"
                class="input"
                type="search"
                placeholder="Search token, symbol or address"
                aria-label="Search token"
                autocomplete="off"
                value={query()}
                onInput={(event) => handleInput(event.currentTarget.value)}
              />
            </Field>
            <ActionButton type="submit" disabled={search.state().kind === "loading"}>
              Search
            </ActionButton>
          </form>

          <p class="muted" role="status" aria-live="polite">
            {searchStatus()}
          </p>

          <AsyncSurface
            state={search.state()}
            nowMs={ws.nowMs()}
            onRetry={() => runSearch(query())}
            emptyTitle="No matches"
            emptyDetail="No token matched the current query."
            isEmpty={(payload) => payload.results.length === 0}
          >
            {(payload) => (
              <ul class="search-results">
                <For each={payload.results}>
                  {(token) => (
                    <li class="search-results__item">
                      <button
                        type="button"
                        class="link-button"
                        aria-pressed={isSelected(token)}
                        disabled={detail.state().kind === "loading"}
                        onClick={() => selectToken(token)}
                      >
                        <span class="search-results__symbol">{tokenLabel(token)}</span>
                        <code class="search-results__address">
                          {truncateAddress(token.address, 6, 6)}
                        </code>
                        <Badge tone="muted">{token.chain}</Badge>
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            )}
          </AsyncSurface>
        </Show>
      </Panel>

      <Panel
        title="Risk & intelligence evidence"
        subtitle="Provenance, freshness and confidence per claim"
        badge={
          <Show when={selected()}>
            {(token) => <Badge tone="info">{tokenLabel(token())}</Badge>}
          </Show>
        }
      >
        <Show
          when={denial() === null}
          fallback={
            <UnavailableBlock
              denial={denial()}
              detail="Requires /v1/command { get_token } returning stats, risk and evidence."
            />
          }
        >
          <Show
            when={selected()}
            fallback={
              <EmptyBlock
                title="No token selected"
                detail="Run a search and select a candidate to see tax/safety, holder and social evidence."
              />
            }
          >
            <p class="muted" role="status" aria-live="polite">
              {detailStatus()}
            </p>
            <AsyncSurface
              state={detail.state()}
              nowMs={ws.nowMs()}
              onRetry={retryDetail}
              emptyTitle="Token detail is idle"
              emptyDetail="Select a search result to load its detail."
            >
              {(value) => <TokenDetailView detail={value} />}
            </AsyncSurface>
          </Show>
        </Show>
      </Panel>
    </div>
  );
}
