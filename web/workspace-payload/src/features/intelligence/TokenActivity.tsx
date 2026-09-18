import { For, Show, createEffect, createMemo, createSignal, type Component, type JSX } from "solid-js";
import type { TokenActivityEvent } from "../../contracts/token-intelligence";
import { formatAge, formatUsd } from "../../core/format";
import { useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { MarkTile } from "../../components/ui/MarkTile";
import { Badge, type Tone } from "../../components/ui/primitives";
import { CompactNote, ErrorBlock, LoadingBlock } from "../../components/ui/states";
import { freshnessView } from "./queries";

type ActivityKind = "all" | "buy" | "sell" | "transfers" | "thesis";

const KINDS: readonly { id: ActivityKind; label: string }[] = [
  { id: "all", label: "All" },
  { id: "buy", label: "Buys" },
  { id: "sell", label: "Sells" },
  { id: "transfers", label: "Transfers" },
  { id: "thesis", label: "Thesis" },
];

const PAGE_SIZE = 12;

function eventTone(event: TokenActivityEvent): { tone: Tone; label: string } {
  switch (event.type) {
    case "buy":
      return { tone: "positive", label: "Buy" };
    case "sell":
      return { tone: "danger", label: "Sell" };
    case "transfer":
      return { tone: "muted", label: event.direction === "out" ? "Transfer out" : "Transfer in" };
    case "thesis":
      return { tone: "info", label: "Thesis" };
    default:
      return { tone: "muted", label: event.rawType ?? "Event" };
  }
}

function matchesKind(event: TokenActivityEvent, kind: ActivityKind): boolean {
  if (kind === "all") return true;
  if (kind === "transfers") return event.type === "transfer";
  return event.type === kind;
}

function handleFor(event: TokenActivityEvent): string {
  return event.user.handle ?? event.user.displayName ?? "—";
}

function monogramFor(event: TokenActivityEvent): string {
  const raw = (event.user.displayName ?? event.user.handle ?? "?")
    .replace(/^@/, "")
    .replace(/[^A-Za-z0-9 ]/g, "");
  return raw
    .split(/[\s_]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase() || "?";
}

/**
 * Activity > Token — the exact selected token's FOMO event stream. It is the
 * only chronological feed in the product, paginated at a fixed page size so the
 * DOM is bounded by construction, and it is identity-bound: the store aborts and
 * rejects a response that does not echo the requested chain+address.
 *
 * NOTE: the integrated `get_token_activity` command accepts only `cursor` and
 * `limit`; the kind and minimum-USD controls therefore filter the fetched page
 * client-side rather than being pushed to the provider. The pager states the
 * reconciliation rule on the surface.
 */
export const TokenActivity: Component<{ embedded?: boolean }> = (props) => {
  const station = useWorkstation();
  const ws = useWorkspace();
  const [kind, setKind] = createSignal<ActivityKind>("all");
  const [minUsd, setMinUsd] = createSignal("");
  const [filtersOpen, setFiltersOpen] = createSignal(false);
  const [cursorStack, setCursorStack] = createSignal<(string | null)[]>([null]);
  const [pageIndex, setPageIndex] = createSignal(0);

  // Reset pagination and filters when the exact identity changes, then load the
  // first page. Page 3 of token A must never be shown as token B's.
  createEffect(() => {
    if (props.embedded && station.dockTab() !== "activity") return;
    const key = station.intelKey();
    if (!key || station.intelDenial()) return;
    if (station.activity.state().kind !== "idle") return;
    setCursorStack([null]);
    setPageIndex(0);
    setKind("all");
    setMinUsd("");
    station.runIntel("activity", { limit: PAGE_SIZE, cursor: null });
  });

  const page = createMemo(() => {
    const state = station.activity.state();
    if (state.kind === "ready" || state.kind === "stale") return state.value;
    return null;
  });

  const threshold = createMemo<number | null>(() => {
    const parsed = Number.parseFloat(minUsd());
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  });

  const visible = createMemo<readonly TokenActivityEvent[]>(() => {
    const value = page();
    if (!value) return [];
    const min = threshold();
    return value.events.filter((event) => {
      if (!matchesKind(event, kind())) return false;
      if (min !== null && !(event.usdAmount !== null && event.usdAmount >= min)) return false;
      return true;
    });
  });

  const canOlder = createMemo(() => {
    const value = page();
    // A cursor is required; `hasNextPage === false` is the provider's explicit
    // "no more pages" and is respected, while `null` (unstated) does not block.
    return value !== null && value.nextCursor !== null && value.hasNextPage !== false;
  });
  const canNewer = createMemo(() => pageIndex() > 0);

  const staleAgeMs = createMemo<number | null>(() => {
    const view = freshnessView(station.activity.state(), ws.nowMs());
    return view !== null && view.stale ? view.ageMs : null;
  });

  // The cursor page range is derived from the loaded page (the provider gives no
  // total), and the filtered match count is stated separately so a client-side
  // filter is never presented as an authoritative range.
  const pageEvents = createMemo(() => page()?.events.length ?? 0);
  const rangeStart = createMemo(() => (pageEvents() === 0 ? 0 : pageIndex() * PAGE_SIZE + 1));
  const rangeEnd = createMemo(() => pageIndex() * PAGE_SIZE + pageEvents());

  const goOlder = (): void => {
    const value = page();
    if (!value || value.nextCursor === null) return;
    const next = pageIndex() + 1;
    setCursorStack((stack) => {
      const copy = stack.slice(0, next);
      copy[next] = value.nextCursor;
      return copy;
    });
    setPageIndex(next);
    station.runIntel("activity", { limit: PAGE_SIZE, cursor: value.nextCursor });
  };
  const goNewer = (): void => {
    if (pageIndex() <= 0) return;
    const next = pageIndex() - 1;
    setPageIndex(next);
    station.runIntel("activity", { limit: PAGE_SIZE, cursor: cursorStack()[next] ?? null });
  };

  const unavailableView = createMemo<JSX.Element | null>(() => {
    const state = station.activity.state();
    return state.kind === "unavailable" ? (
      <CompactNote label="Token activity" reason={state.reason} capability={state.capability} />
    ) : null;
  });
  const errorView = createMemo<JSX.Element | null>(() => {
    const state = station.activity.state();
    return state.kind === "error" ? (
      <ErrorBlock
        error={state.error}
        onRetry={() =>
          station.runIntel("activity", {
            limit: PAGE_SIZE,
            cursor: cursorStack()[pageIndex()] ?? null,
          })
        }
      />
    ) : null;
  });

  return (
    <div class="pane__scroll">
      <Show when={station.intelDenial()}>
        {(denial) => (
          <CompactNote
            label="Token activity"
            reason={denial().reason}
            capability={denial().capability}
          />
        )}
      </Show>

      <Show when={!station.intelDenial()}>
        {unavailableView()}
        {errorView()}
        <Show when={station.activity.state().kind === "loading" && page() === null}>
          <LoadingBlock label="Loading token activity…" />
        </Show>

        <Show when={page()}>
          <div class="subbar" data-testid="activity-filters">
            <div class="seg" role="group" aria-label="Filter token activity">
              <For each={KINDS}>
                {(entry) => (
                  <button
                    type="button"
                    class="seg__btn"
                    data-testid={`activity-kind-${entry.id}`}
                    aria-pressed={kind() === entry.id}
                    onClick={() => setKind(entry.id)}
                  >
                    {entry.label}
                  </button>
                )}
              </For>
            </div>
            <details
              class="filters"
              open={filtersOpen()}
              on:toggle={(event) => setFiltersOpen(event.currentTarget.open)}
            >
              <summary>
                Filters{threshold() !== null ? ` · ≥ $${minUsd()}` : ""}
              </summary>
              <div class="filters__body">
                <label class="lbl" for="feed-min">
                  Minimum USD
                </label>
                <input
                  id="feed-min"
                  class="input input--xs"
                  inputmode="decimal"
                  autocomplete="off"
                  placeholder="0"
                  aria-label="Minimum USD amount"
                  value={minUsd()}
                  onInput={(event) => setMinUsd(event.currentTarget.value.replace(/[^0-9.]/g, ""))}
                />
                <Show when={threshold() !== null}>
                  <button
                    type="button"
                    class="btn btn--sm"
                    onClick={() => {
                      setMinUsd("");
                      setFiltersOpen(false);
                    }}
                  >
                    Clear
                  </button>
                </Show>
              </div>
            </details>
            <Show when={staleAgeMs() !== null}>
              <span class="stale">Stale · {formatAge(staleAgeMs() ?? 0)}</span>
            </Show>
          </div>

          <Show
            when={visible().length > 0}
            fallback={<p class="prov">No activity matches this filter.</p>}
          >
            <ul class="feed" data-testid="activity-feed">
              <For each={visible()}>
                {(event) => <ActivityRow event={event} />}
              </For>
            </ul>
          </Show>

          <div class="pager">
            <button
              type="button"
              class="btn btn--sm"
              data-testid="activity-newer"
              disabled={!canNewer()}
              onClick={goNewer}
            >
              Newer
            </button>
            <button
              type="button"
              class="btn btn--sm"
              data-testid="activity-older"
              disabled={!canOlder()}
              onClick={goOlder}
            >
              Older
            </button>
            <span class="pager__range">
              {rangeStart()}–{rangeEnd()} · newest first · REST reconciles the stream
              {visible().length !== pageEvents() ? ` · ${visible().length} match this filter` : ""}
            </span>
          </div>
        </Show>
      </Show>
    </div>
  );
};

const ActivityRow: Component<{ event: TokenActivityEvent }> = (props) => {
  const view = createMemo(() => eventTone(props.event));
  const age = createMemo(() =>
    props.event.createdAtMs === null ? "—" : formatAge(Math.max(0, Date.now() - props.event.createdAtMs)),
  );
  return (
    <li class="feed__row">
      <span class="feed__mark">
        <MarkTile symbol={handleFor(props.event)} monogram={monogramFor(props.event)} size="sm" />
      </span>
      <span class="feed__who">
        <span class="feed__handle">{handleFor(props.event)}</span>
        <Badge tone={view().tone}>{view().label}</Badge>
      </span>
      <span class="feed__nums">
        <Show when={props.event.type !== "thesis"} fallback={<span class="feed__age">{age()}</span>}>
          <span class="feed__usd">{formatUsd(props.event.usdAmount)}</span>
          <span class="feed__price">
            @ {props.event.priceUsd === null ? "—" : formatUsd(props.event.priceUsd, 4)}
          </span>
          <span class="feed__mcap">mcap {formatUsd(props.event.marketCapUsd)}</span>
          <span class="feed__age">{age()}</span>
        </Show>
      </span>
      <Show when={props.event.thesis}>
        {(thesis) => <span class="feed__thesis">“{thesis()}”</span>}
      </Show>
    </li>
  );
};

export default TokenActivity;
