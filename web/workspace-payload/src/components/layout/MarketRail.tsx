import { For, Show, createMemo, type Component } from "solid-js";
import { truncateAddress } from "../../core/format";
import type { TokenRef } from "../../contracts/market";
import { tokenLabel, useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { CompactNote } from "../ui/states";

const MarketItem: Component<{ token: TokenRef }> = (props) => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const active = createMemo(() => {
    const selected = ws.selectedInstrument();
    return (
      selected !== null &&
      selected.chain === props.token.chain &&
      selected.address === props.token.address
    );
  });
  return (
    <li>
      <button
        type="button"
        class="market-item"
        aria-pressed={active()}
        title={`${tokenLabel(props.token)} · ${props.token.address}`}
        onClick={() => station.selectInstrument(props.token)}
      >
        <span class="market-item__symbol">{tokenLabel(props.token)}</span>
        <span class="market-item__meta">{truncateAddress(props.token.address, 4, 4)}</span>
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
  const results = createMemo<readonly TokenRef[]>(() => {
    const state = station.searchState();
    return state.kind === "ready" || state.kind === "stale" ? state.value.results : [];
  });
  const trendingTokens = createMemo<readonly TokenRef[]>(() => {
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
              <For each={results()}>{(token) => <MarketItem token={token} />}</For>
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
              <For each={station.watchlist()}>{(token) => <MarketItem token={token} />}</For>
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
              <For each={station.recent()}>{(token) => <MarketItem token={token} />}</For>
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
                <For each={trendingTokens()}>{(token) => <MarketItem token={token} />}</For>
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
