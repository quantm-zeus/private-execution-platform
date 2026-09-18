import { For, Show, createEffect, createMemo, createSignal, type Component, type JSX } from "solid-js";
import type { HolderThesis, TokenHolder } from "../../contracts/token-intelligence";
import {
  formatAge,
  formatCount,
  formatDurationSeconds,
  formatSignedPercent,
  formatSignedUsd,
  formatUsd,
} from "../../core/format";
import { useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { AddressCopy } from "../../components/ui/AddressCopy";
import { MarkTile } from "../../components/ui/MarkTile";
import { Badge, type Tone } from "../../components/ui/primitives";
import { CompactNote, EmptyBlock, ErrorBlock, LoadingBlock } from "../../components/ui/states";
import { freshnessView } from "./queries";

type HolderScope = "top" | "following";
type TraderSort = "value" | "pnl" | "entry" | "hold";

interface TraderRow {
  readonly holder: TokenHolder;
  readonly entry: number | null;
  readonly value: number | null;
  readonly cost: number | null;
  readonly unrealized: number | null;
  readonly realized: number | null;
  readonly total: number | null;
  readonly pnlPct: number | null;
  readonly hold: number | null;
  readonly thesis: HolderThesis | null;
}

function deriveRow(holder: TokenHolder): TraderRow {
  const amount = holder.amount;
  const current = holder.currentPriceUsd;
  const entry = holder.averageEntryPriceUsd;
  const value =
    holder.valueUsd ?? (amount !== null && current !== null ? amount * current : null);
  const cost = holder.costBasisUsd ?? (amount !== null && entry !== null ? amount * entry : null);
  const unrealized =
    holder.unrealizedPnlUsd ??
    (amount !== null && current !== null && entry !== null ? amount * (current - entry) : null);
  const realized = holder.realizedPnlUsd;
  const total =
    holder.totalPnlUsd ??
    (realized !== null && unrealized !== null ? realized + unrealized : null);
  return {
    holder,
    entry,
    value,
    cost,
    unrealized,
    realized,
    total,
    pnlPct: cost !== null && cost > 0 && total !== null ? total / cost : null,
    hold: holder.averageHoldTimeSeconds,
    thesis: holder.thesis,
  };
}

function traderName(holder: TokenHolder): string {
  const { displayName, handle } = holder.user;
  if (displayName) return displayName;
  if (handle) return handle;
  if (holder.wallet) return holder.wallet;
  return "—";
}

function traderMonogram(holder: TokenHolder): string {
  const raw = (holder.user.displayName ?? holder.user.handle ?? holder.wallet ?? "?")
    .replace(/^@/, "")
    .replace(/[^A-Za-z0-9 ]/g, "");
  const initials = raw
    .split(/[\s_]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase();
  return initials || "?";
}

function toneForPnl(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "flat";
  return value >= 0 ? "up" : "down";
}

/** Holders and traders are ONE concept: position data + identity + authored thesis. */
export const HolderTradersPanel: Component<{ embedded?: boolean }> = (props) => {
  const station = useWorkstation();
  const ws = useWorkspace();
  const [holderScope, setHolderScope] = createSignal<HolderScope>("top");
  const [traderSort, setTraderSort] = createSignal<TraderSort | null>(null);
  const [openTrader, setOpenTrader] = createSignal<string | null>(null);

  // Lazy: fetch when the pane opens for the current instrument, and again after
  // an instrument change resets the resource to idle.
  createEffect(() => {
    if (props.embedded && station.dockTab() !== "holders") return;
    if (!station.intelKey() || station.intelDenial()) return;
    if (station.holders.state().kind === "idle") station.runIntel("holders");
  });

  const rows = createMemo<readonly TraderRow[]>(() => {
    const state = station.holders.state();
    if (state.kind !== "ready" && state.kind !== "stale") return [];
    return state.value.holders.map(deriveRow);
  });

  const staleAgeMs = createMemo<number | null>(() => {
    const view = freshnessView(station.holders.state(), ws.nowMs());
    return view !== null && view.stale ? view.ageMs : null;
  });

  const hasFollowing = createMemo(() => rows().some((row) => row.holder.user.followed === true));
  // A Following scope that can only ever render empty is a broken promise: fall
  // back visibly to Top holders, but keep the stored choice so a token that does
  // have followed rows restores it.
  const effectiveScope = createMemo<HolderScope>(() =>
    holderScope() === "following" && hasFollowing() ? "following" : "top",
  );
  const visible = createMemo<readonly TraderRow[]>(() =>
    effectiveScope() === "following"
      ? rows().filter((row) => row.holder.user.followed === true)
      : rows(),
  );
  const sorted = createMemo<readonly TraderRow[]>(() => {
    const key = traderSort();
    if (key === null) return visible();
    const value = (row: TraderRow): number | null => {
      switch (key) {
        case "value":
          return row.value;
        case "pnl":
          return row.total;
        case "entry":
          return row.entry;
        case "hold":
          return row.hold;
      }
    };
    // Stable: equal keys (and unknown keys) keep the provider's authoritative order.
    return visible()
      .slice()
      .sort((a, b) => {
        const av = value(a);
        const bv = value(b);
        if (av === null && bv === null) return 0;
        if (av === null) return 1;
        if (bv === null) return -1;
        return bv - av;
      });
  });

  const orderLabel = createMemo(() =>
    traderSort() === null ? "FOMO order" : `sorted by ${traderSort()}`,
  );
  const meta = createMemo(() => {
    const symbol = station.intelKey()?.chain ? ws.selectedInstrument()?.symbol ?? "—" : "—";
    const scope = effectiveScope() === "following" ? "followed " : "";
    return `${symbol} · ${sorted().length} ${scope}traders · ${orderLabel()}`;
  });

  const setScope = (scope: HolderScope): void => {
    setHolderScope(scope);
    setOpenTrader(null);
  };
  const setSort = (sort: TraderSort): void => {
    // Pressing the active segment returns to the provider's authoritative order.
    setTraderSort((current) => (current === sort ? null : sort));
  };

  const unavailableView = createMemo<JSX.Element | null>(() => {
    const state = station.holders.state();
    return state.kind === "unavailable" ? (
      <div class="pane__scroll">
        <CompactNote label="Holder traders" reason={state.reason} capability={state.capability} />
      </div>
    ) : null;
  });
  const errorView = createMemo<JSX.Element | null>(() => {
    const state = station.holders.state();
    return state.kind === "error" ? (
      <div class="pane__scroll">
        <ErrorBlock error={state.error} onRetry={() => station.runIntel("holders")} />
      </div>
    ) : null;
  });

  return (
    <section class="pane" data-testid="holders-pane">
      <div class="pane__bar">
        <Show when={ws.selectedInstrument()}>
          {(ref) => <MarkTile symbol={ref().symbol} size="sm" />}
        </Show>
        <h3 class="pane__title">Holder traders</h3>
        <span class="pane__meta">{meta()}</span>
        <span class="pane__tools">
          <Show when={staleAgeMs() !== null}>
            <span class="stale">Stale · {formatAge(staleAgeMs() ?? 0)}</span>
          </Show>
          <div class="seg" role="group" aria-label="Holder scope">
            <button
              type="button"
              class="seg__btn"
              data-testid="holder-scope-top"
              aria-pressed={effectiveScope() === "top"}
              title="All top holders"
              onClick={() => setScope("top")}
            >
              Top holders
            </button>
            <Show when={hasFollowing()}>
              <button
                type="button"
                class="seg__btn"
                data-testid="holder-scope-following"
                aria-pressed={effectiveScope() === "following"}
                title="Only holders you follow"
                onClick={() => setScope("following")}
              >
                Following
              </button>
            </Show>
          </div>
          <div class="seg" role="group" aria-label="Sort holder traders">
            <For each={["value", "pnl", "entry", "hold"] as const}>
              {(id) => (
                <button
                  type="button"
                  class="seg__btn"
                  data-testid={`holder-sort-${id}`}
                  aria-pressed={traderSort() === id}
                  title={`Sort by ${id}`}
                  onClick={() => setSort(id)}
                >
                  {id === "pnl" ? "PnL" : id.charAt(0).toUpperCase() + id.slice(1)}
                </button>
              )}
            </For>
          </div>
        </span>
      </div>

      <Show when={station.intelDenial()}>
        {(denial) => (
          <div class="pane__scroll">
            <CompactNote
              label="Holder traders"
              reason={denial().reason}
              capability={denial().capability}
            />
          </div>
        )}
      </Show>

      <Show when={!station.intelDenial()}>
        <Show when={station.holders.state().kind === "loading" && rows().length === 0}>
          <div class="pane__scroll">
            <LoadingBlock label="Loading holder traders…" />
          </div>
        </Show>
        {unavailableView()}
        {errorView()}
        <Show when={station.holders.state().kind === "ready" || station.holders.state().kind === "stale"}>
          <div class="pane__scroll">
            <Show
              when={sorted().length > 0}
              fallback={
                <EmptyBlock
                  title={
                    effectiveScope() === "following"
                      ? "No holders you follow are in this token's top holders."
                      : "No holder traders returned for this token."
                  }
                />
              }
            >
              <ul class="traders" data-testid="trader-list">
                <For each={sorted()}>
                  {(row, index) => (
                    <TraderRowView
                      row={row}
                      open={openTrader() === traderKey(row, index())}
                      onToggle={() =>
                        setOpenTrader((current) =>
                          current === traderKey(row, index()) ? null : traderKey(row, index()),
                        )
                      }
                    />
                  )}
                </For>
              </ul>
            </Show>
          </div>
        </Show>
      </Show>
    </section>
  );
};

function traderKey(row: TraderRow, index: number): string {
  return (
    row.holder.user.handle ??
    row.holder.user.displayName ??
    row.holder.wallet ??
    `holder-${index}`
  );
}

const TraderRowView: Component<{ row: TraderRow; open: boolean; onToggle: () => void }> = (props) => {
  const badges = createMemo<JSX.Element[]>(() => {
    const user = props.row.holder.user;
    const items: JSX.Element[] = [];
    if (user.dev === true) items.push(<Badge tone="info">Dev</Badge>);
    if (user.verified === true) items.push(<Badge tone="positive">Verified</Badge>);
    if (user.clan) items.push(<Badge tone="muted">{user.clan}</Badge>);
    if (user.followed === true) items.push(<Badge tone="muted">Followed</Badge>);
    return items;
  });
  return (
    <li class="trader-row">
      <button
        type="button"
        class="trader"
        data-testid="trader-row"
        aria-pressed={props.open}
        aria-expanded={props.open}
        title={`${traderName(props.row.holder)} ${props.row.holder.user.handle ?? ""}`.trim()}
        onClick={props.onToggle}
      >
        <span class="trader__mark">
          <MarkTile
            symbol={traderName(props.row.holder)}
            monogram={traderMonogram(props.row.holder)}
            size="sm"
          />
        </span>
        <span class="trader__id">
          <span class="trader__name">{traderName(props.row.holder)}</span>
          <Show when={props.row.holder.user.handle}>
            {(handle) => <span class="trader__handle">{handle()}</span>}
          </Show>
          <span class="trader__badges">
            <For each={badges()}>{(badge) => badge}</For>
          </span>
        </span>
        <span class="trader__nums">
          <span class="trader__value">{formatUsd(props.row.value)}</span>
          <span class={`trader__pnl ${toneForPnl(props.row.total)}`}>
            {formatSignedUsd(props.row.total)}
          </span>
        </span>
        <span
          class={`trader__thesis${props.row.thesis?.text ? "" : " trader__thesis--none"}`}
        >
          {props.row.thesis?.text
            ? `“${props.row.thesis.text}”`
            : "No thesis authored for this token"}
        </span>
        <span class="trader__sub">
          entry {props.row.entry === null ? "—" : formatUsd(props.row.entry, 4)} · hold{" "}
          {formatDurationSeconds(props.row.hold)} · {formatCount(props.row.holder.user.followers)}{" "}
          followers
        </span>
      </button>
      <Show when={props.open}>
        <TraderDetail row={props.row} />
      </Show>
    </li>
  );
};

const TraderDetail: Component<{ row: TraderRow }> = (props) => {
  const cells = createMemo<readonly [string, string][]>(() => [
    ["Token amount", formatCount(props.row.holder.amount)],
    ["Average entry", props.row.entry === null ? "—" : formatUsd(props.row.entry, 4)],
    [
      "Current price",
      props.row.holder.currentPriceUsd === null ? "—" : formatUsd(props.row.holder.currentPriceUsd, 4),
    ],
    ["Cost basis", formatUsd(props.row.cost)],
    ["Unrealised PnL", formatSignedUsd(props.row.unrealized)],
    ["Realised PnL", formatSignedUsd(props.row.realized)],
    [
      "Total PnL",
      props.row.total === null
        ? "—"
        : `${formatSignedUsd(props.row.total)}${
            props.row.pnlPct === null ? "" : ` · ${formatSignedPercent(props.row.pnlPct)}`
          }`,
    ],
    ["Average hold", formatDurationSeconds(props.row.hold)],
    ["Followers", formatCount(props.row.holder.user.followers)],
    ["Thesis likes", formatCount(props.row.thesis?.likes)],
  ]);
  return (
    <div class="trader-detail" data-testid="trader-detail">
      <p class="trader-detail__thesis">
        {props.row.thesis?.text ? (
          `“${props.row.thesis.text}”`
        ) : (
          <span class="dim">
            This trader has not authored a thesis for this token. Position data is unaffected.
          </span>
        )}
      </p>
      <dl class="trader-detail__grid">
        <For each={cells()}>
          {([label, value]) => (
            <div class="statgrid__cell">
              <dt>{label}</dt>
              <dd data-unknown={value === "—" ? "true" : undefined}>{value}</dd>
            </div>
          )}
        </For>
      </dl>
      <div class="trader-detail__foot">
        <Show
          when={props.row.holder.wallet}
          fallback={<span class="dim">Wallet address not provided.</span>}
        >
          {(wallet) => <AddressCopy address={wallet()} />}
        </Show>
        <Show when={props.row.thesis?.createdAtMs}>
          {(created) => <span class="dim">thesis {formatAge(Date.now() - created())} old</span>}
        </Show>
        <span class={`trader__pnl ${toneForPnl(props.row.total)}`}>
          total {formatSignedUsd(props.row.total)}
        </span>
      </div>
    </div>
  );
};

export default HolderTradersPanel;
