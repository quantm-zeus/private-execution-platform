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
      <div class="market-rail__scroll">
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
          <p class="market-rail__section-head">Trending</p>
          <div class="market-rail__note">
            <CompactNote
              label="Trending"
              reason="No composed trending feed is advertised by this deployment."
              capability="market.trending"
            />
          </div>
        </section>
      </div>
    </div>
  );
};

export default MarketRail;
