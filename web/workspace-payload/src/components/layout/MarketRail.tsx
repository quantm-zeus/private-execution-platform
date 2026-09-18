import { For, Show, createMemo, createSignal, type Component } from "solid-js";
import { formatPercent, formatUsd } from "../../core/format";
import type { MarketListRow } from "../../contracts/market";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { Badge } from "../ui/primitives";
import { CompactNote } from "../ui/states";
import { TokenSearch } from "./TokenSearch";

/** Canonical display names for the networks the read path actually serves. */
const CHAIN_LABELS: Readonly<Record<string, string>> = {
  solana: "Solana",
  robinhood: "Robinhood",
  base: "Base",
  bnb_chain: "BNB",
  ethereum: "Ethereum",
  monad: "Monad",
};

/** Display order; unknown chains append after these. */
const CHAIN_ORDER: readonly string[] = [
  "solana",
  "robinhood",
  "base",
  "bnb_chain",
  "ethereum",
  "monad",
];

export function chainLabel(slug: string): string {
  return CHAIN_LABELS[slug] ?? slug;
}

function secondaryValue(row: MarketListRow): string | null {
  if (row.priceChange24h !== null) return formatPercent(row.priceChange24h);
  if (row.rank !== null) return `#${row.rank}`;
  return null;
}

function secondaryTone(row: MarketListRow): string {
  if (row.priceChange24h === null) return "market-item__sub--muted";
  return row.priceChange24h >= 0 ? "market-item__sub--up" : "market-item__sub--down";
}

/**
 * One trading-product market row: identity on the left, the price as the
 * primary right-side value, and the optional 24h change beneath it. A missing
 * price renders an explicit `—`; the contract address is context only (tooltip),
 * never the numeric column.
 */
const MarketItem: Component<{ row: MarketListRow }> = (props) => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const active = createMemo(() => {
    const selected = ws.selectedInstrument();
    return (
      selected !== null &&
      selected.chain === props.row.chain &&
      selected.address === props.row.address
    );
  });
  const sub = createMemo(() => secondaryValue(props.row));
  return (
    <li>
      <button
        type="button"
        class="market-item"
        aria-pressed={active()}
        title={`${tokenLabel(props.row)} · ${props.row.name ?? ""} · ${props.row.chain} · ${props.row.address}`}
        onClick={() => station.selectInstrument(props.row)}
      >
        <span class="market-item__id">
          <span class="market-item__symbol">{tokenLabel(props.row)}</span>
          <span class="market-item__name">
            {props.row.name && props.row.name !== tokenLabel(props.row)
              ? props.row.name
              : chainLabel(props.row.chain)}
          </span>
        </span>
        <span class="market-item__value">
          <span class="market-item__price" data-testid="market-row-price">
            {formatUsd(props.row.priceUsd, 6)}
          </span>
          <span class={`market-item__sub ${secondaryTone(props.row)}`}>{sub() ?? "—"}</span>
        </span>
      </button>
    </li>
  );
};

/**
 * Collapsible left market rail: search, the honest-count network filter and the
 * trending list, plus the memory-only watchlist and recent selections. Trending
 * rows are the reconciled command rows overlaid with pushed WS-observed values
 * (exact identity), and the local network filter narrows them without changing
 * ranks or identity.
 */
export const MarketRail: Component = () => {
  const station = useWorkstation();
  const [chainFilter, setChainFilter] = createSignal<string>("all");

  const results = createMemo<readonly MarketListRow[]>(() => {
    const state = station.searchState();
    return state.kind === "ready" || state.kind === "stale" ? state.value.results : [];
  });
  const trendingTokens = createMemo<readonly MarketListRow[]>(() => station.trendingRows());
  const trendingLoading = createMemo(() => {
    const kind = station.trendingState().kind;
    return kind === "idle" || kind === "loading";
  });
  const trendingError = createMemo(() => {
    const state = station.trendingState();
    return state.kind === "error" ? state.error.message : null;
  });
  const counts = createMemo(() => station.trendingChains());
  const visibleChains = createMemo<readonly string[]>(() => {
    const present = [...counts().keys()];
    const ordered = CHAIN_ORDER.filter((slug) => present.includes(slug));
    const extra = present.filter((slug) => !CHAIN_ORDER.includes(slug));
    return [...ordered, ...extra];
  });
  // A filter whose network disappeared falls back to All rather than showing an
  // empty list as if the provider had returned nothing.
  const effectiveFilter = createMemo(() =>
    chainFilter() === "all" || !visibleChains().includes(chainFilter()) ? "all" : chainFilter(),
  );
  const filtered = createMemo<readonly MarketListRow[]>(() => {
    const filter = effectiveFilter();
    const rows = trendingTokens();
    return filter === "all" ? rows : rows.filter((row) => row.chain === filter);
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

  return (
    <div class="market-rail" aria-label="Markets">
      <div class="market-rail__head">
        <span class="market-rail__title">Markets</span>
        <button
          type="button"
          class="icon-button"
          aria-label="Collapse market rail"
          title="Collapse market rail"
          onClick={() => station.setRailCollapsed(true)}
        >
          ‹
        </button>
      </div>

      <Show when={!station.railCollapsed()}>
        <div class="rail__search">
          <TokenSearch />
        </div>
      </Show>

      <Show when={station.searchDenial()}>
        {(denial) => (
          <div class="market-rail__note">
            <CompactNote
              label="Token search"
              reason={denial().reason}
              capability={denial().capability}
            />
          </div>
        )}
      </Show>

      <Show when={!station.trendingDenial() && visibleChains().length > 0}>
        <div class="chain-filter" role="group" aria-label="Filter trending by network">
          <button
            type="button"
            class="chain-filter__chip"
            data-testid="chain-filter-all"
            aria-pressed={effectiveFilter() === "all"}
            onClick={() => setChainFilter("all")}
          >
            All <span class="chain-filter__count">{trendingTokens().length}</span>
          </button>
          <For each={visibleChains()}>
            {(slug) => (
              <button
                type="button"
                class="chain-filter__chip"
                data-testid={`chain-filter-${slug}`}
                aria-pressed={effectiveFilter() === slug}
                onClick={() => setChainFilter(slug)}
              >
                {chainLabel(slug)}{" "}
                <span class="chain-filter__count">{counts().get(slug) ?? 0}</span>
              </button>
            )}
          </For>
        </div>
      </Show>

      <div class="market-rail__scroll" tabindex="0" aria-label="Tracked tokens">
        <Show when={results().length > 0}>
          <section class="market-rail__section" aria-label="Search results">
            <p class="market-rail__section-head">{results().length} results</p>
            <ul class="market-rail__list">
              <For each={results()}>{(row) => <MarketItem row={row} />}</For>
            </ul>
          </section>
        </Show>

        <section class="market-rail__section" aria-label="Watchlist">
          <p class="market-rail__section-head">Watchlist</p>
          <Show
            when={station.watchlist().length > 0}
            fallback={<p class="market-rail__section-head muted">No watched tokens yet.</p>}
          >
            <ul class="market-rail__list">
              <For each={station.watchlist()}>{(row) => <MarketItem row={row} />}</For>
            </ul>
          </Show>
        </section>

        <section class="market-rail__section" aria-label="Recent tokens">
          <p class="market-rail__section-head">Recent</p>
          <Show
            when={station.recent().length > 0}
            fallback={<p class="market-rail__section-head muted">No recent selections.</p>}
          >
            <ul class="market-rail__list">
              <For each={station.recent()}>{(row) => <MarketItem row={row} />}</For>
            </ul>
          </Show>
        </section>

        <section class="market-rail__section" aria-label="Trending">
          <p class="market-rail__section-head">
            <span>Trending</span>
            <span class="market-rail__head-tools">
              <Show when={sourceLabel()}>
                <Badge
                  tone={station.marketSource() === "fomo-ws" ? "positive" : "muted"}
                  data-testid="trending-source"
                >
                  {sourceLabel()}
                </Badge>
              </Show>
              <Show when={!station.trendingDenial()}>
                <button
                  type="button"
                  class="market-rail__refresh"
                  onClick={() => station.refreshTrending()}
                  aria-label="Refresh trending tokens"
                  title="Refresh trending"
                >
                  ↻
                </button>
              </Show>
            </span>
          </p>
          <Show
            when={!station.trendingDenial()}
            fallback={
              <div class="market-rail__note">
                <CompactNote
                  label="Trending"
                  reason={station.trendingDenial()?.reason ?? "Market data is unavailable."}
                  capability="market"
                />
              </div>
            }
          >
            <Show when={filtered().length > 0}>
              <ul class="market-rail__list" data-testid="trending-tokens">
                <For each={filtered()}>{(row) => <MarketItem row={row} />}</For>
              </ul>
            </Show>
            <Show when={filtered().length === 0 && trendingLoading()}>
              <p class="market-rail__empty" role="status">Loading trending…</p>
            </Show>
            <Show when={filtered().length === 0 && trendingError()}>
              <div class="market-rail__note" role="status">
                <span class="muted">Trending temporarily unavailable.</span>
              </div>
            </Show>
            <Show when={filtered().length === 0 && !trendingLoading() && !trendingError()}>
              <p class="market-rail__empty">
                {effectiveFilter() === "all"
                  ? "No trending tokens right now."
                  : `No ${chainLabel(effectiveFilter())} tokens in this list.`}
              </p>
            </Show>
          </Show>
        </section>
      </div>
    </div>
  );
};

export default MarketRail;
