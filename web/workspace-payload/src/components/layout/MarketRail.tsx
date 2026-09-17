import { For, Show, createMemo, type Component } from "solid-js";
import { formatPercent, formatUsd } from "../../core/format";
import type { MarketListRow } from "../../contracts/market";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { CompactNote } from "../ui/states";

/** Optional rank/change context on the right, never a fabricated zero. */
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
 * primary right-side value, and optional change/rank context beneath it. A
 * missing price renders an explicit `—`; the contract address is context only
 * (tooltip), never the numeric column.
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
              : props.row.chain}
          </span>
        </span>
        <span class="market-item__value">
          <span class="market-item__price" data-testid="market-row-price">
            {formatUsd(props.row.priceUsd, 6)}
          </span>
          <span class={`market-item__sub ${secondaryTone(props.row)}`}>
            {sub() ?? props.row.chain}
          </span>
        </span>
      </button>
    </li>
  );
};

/**
 * Collapsible left market rail: search results, the memory-only watchlist and
 * recent selections, and a truthful compact note where a trending feed is not
 * composed. It is not a second navigation system.
 */
export const MarketRail: Component = () => {
  const station = useWorkstation();
  const results = createMemo<readonly MarketListRow[]>(() => {
    const state = station.searchState();
    return state.kind === "ready" || state.kind === "stale" ? state.value.results : [];
  });
  const trendingTokens = createMemo<readonly MarketListRow[]>(() => {
    const state = station.trendingState();
    if (state.kind === "ready" || state.kind === "stale") return state.value.tokens;
    if ((state.kind === "loading" || state.kind === "error") && state.prior) return state.prior.tokens;
    return [];
  });
  const trendingLoading = createMemo(() => {
    const kind = station.trendingState().kind;
    return kind === "idle" || kind === "loading";
  });
  const trendingError = createMemo(() => {
    const state = station.trendingState();
    return state.kind === "error" ? state.error.message : null;
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
      <div class="market-rail__scroll" tabindex="0" aria-label="Tracked tokens">
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
        <Show when={results().length > 0}>
          <section class="market-rail__section" aria-label="Search results">
            <p class="market-rail__section-head">Search results</p>
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
            <Show when={trendingTokens().length > 0}>
              <ul class="market-rail__list" data-testid="trending-tokens">
                <For each={trendingTokens()}>{(row) => <MarketItem row={row} />}</For>
              </ul>
            </Show>
            <Show when={trendingTokens().length === 0 && trendingLoading()}>
              <p class="market-rail__empty" role="status">Loading trending…</p>
            </Show>
            <Show when={trendingTokens().length === 0 && trendingError()}>
              <div class="market-rail__note" role="status">
                <span class="muted">Trending temporarily unavailable.</span>
              </div>
            </Show>
            <Show
              when={
                trendingTokens().length === 0 &&
                !trendingLoading() &&
                !trendingError()
              }
            >
              <p class="market-rail__empty">No trending tokens right now.</p>
            </Show>
          </Show>
        </section>
      </div>
    </div>
  );
};

export default MarketRail;
