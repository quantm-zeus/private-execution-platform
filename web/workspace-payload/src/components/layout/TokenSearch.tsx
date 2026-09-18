import { For, Show, createEffect, createMemo, createSignal, type Component } from "solid-js";
import { formatPercent, formatUsd, truncateAddress } from "../../core/format";
import type { MarketListRow } from "../../contracts/market";
import { tokenLabel, useWorkstation } from "../../state/workstation";

/**
 * Global token search combobox.
 *
 * It keeps the existing query semantics exactly (300ms debounce, blank queries
 * never dispatched, the encrypted `search_token` op unchanged) and renders the
 * provider's symbol/name/chain/compact address plus any supplied price or
 * market cap. It is a native Solid ARIA combobox: the input owns focus, the
 * listbox is controlled through `aria-activedescendant`, and Arrow/Enter/Escape
 * are handled without a third-party primitive.
 */
export const TokenSearch: Component = () => {
  const station = useWorkstation();
  const [open, setOpen] = createSignal(false);
  const [activeIndex, setActiveIndex] = createSignal(0);

  const results = createMemo<readonly MarketListRow[]>(() => {
    const state = station.searchState();
    return state.kind === "ready" || state.kind === "stale" ? state.value.results : [];
  });
  const searching = createMemo(() => station.searchState().kind === "loading");
  const listVisible = createMemo(() => open() && results().length > 0);

  // A new result set resets the active option; the old index may no longer exist.
  createEffect(() => {
    results();
    setActiveIndex(0);
  });

  const choose = (row: MarketListRow): void => {
    station.selectInstrument(row);
    setOpen(false);
  };

  const move = (delta: number): void => {
    const count = results().length;
    if (count === 0) return;
    setActiveIndex((index) => (index + delta + count) % count);
    const id = `token-option-${activeIndex()}`;
    // `scrollIntoView` is absent in jsdom and some embedded runtimes; the
    // active-descendant state is the source of truth either way.
    queueMicrotask(() => document.getElementById(id)?.scrollIntoView?.({ block: "nearest" }));
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!open()) setOpen(true);
      else move(1);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
      return;
    }
    if (event.key === "Enter") {
      if (listVisible()) {
        const row = results()[activeIndex()];
        if (row) {
          event.preventDefault();
          choose(row);
        }
      }
      return;
    }
    if (event.key === "Escape") {
      if (listVisible()) {
        event.preventDefault();
        setOpen(false);
      }
    }
  };

  return (
    <div class="token-search">
      <span class="token-search__icon" aria-hidden="true">
        <svg viewBox="0 0 16 16" width="14" height="14">
          <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.5" />
          <line x1="10.4" y1="10.4" x2="14" y2="14" stroke="currentColor" stroke-width="1.5" />
        </svg>
      </span>
      <input
        id="global-token-search"
        class="input token-search__input"
        type="text"
        role="combobox"
        placeholder="Search symbol, name or address"
        aria-label="Search token"
        aria-autocomplete="list"
        aria-expanded={listVisible()}
        aria-controls="token-search-listbox"
        aria-activedescendant={listVisible() ? `token-option-${activeIndex()}` : undefined}
        autocomplete="off"
        spellcheck={false}
        value={station.query()}
        onInput={(event) => {
          setOpen(true);
          station.setQuery(event.currentTarget.value);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={onKeyDown}
      />
      <ul
        class="search-popover"
        id="token-search-listbox"
        role="listbox"
        aria-label="Token search results"
        hidden={!listVisible()}
        // Keep the input focused so a click selects rather than blurs first.
        onMouseDown={(event) => event.preventDefault()}
      >
        <For each={results()}>
          {(row, index) => (
            <li
              id={`token-option-${index()}`}
              role="option"
              class="search-result"
              aria-selected={index() === activeIndex()}
              onMouseEnter={() => setActiveIndex(index())}
              onClick={() => choose(row)}
            >
              <span class="search-result__identity">
                <span class="search-results__symbol">{tokenLabel(row)}</span>
                <span class="search-result__name">
                  {row.name && row.name !== tokenLabel(row) ? row.name : "—"}
                </span>
              </span>
              <span class="search-result__chain">{row.chain}</span>
              <code class="search-results__address" title={row.address}>
                {truncateAddress(row.address, 4, 4)}
              </code>
              <span class="search-result__market">
                <span class="search-result__price" data-testid="search-result-price">
                  {formatUsd(row.priceUsd, 6)}
                </span>
                <span
                  class={`search-result__change ${
                    row.priceChange24h === null
                      ? ""
                      : row.priceChange24h >= 0
                        ? "text--positive"
                        : "text--danger"
                  }`}
                  data-testid="search-result-change"
                >
                  {formatPercent(row.priceChange24h)}
                </span>
                <span class="search-result__stat" data-testid="search-result-mcap">
                  MC {formatUsd(row.marketCapUsd)}
                </span>
                <span class="search-result__stat" data-testid="search-result-liquidity">
                  Liq {formatUsd(row.liquidityUsd)}
                </span>
                <span class="search-result__stat" data-testid="search-result-volume">
                  Vol {formatUsd(row.volume24hUsd)}
                </span>
              </span>
            </li>
          )}
        </For>
      </ul>
      <Show when={open() && searching() && results().length === 0}>
        <p class="token-search__status" role="status">
          Searching…
        </p>
      </Show>
    </div>
  );
};

export default TokenSearch;
