import {
  createContext,
  createEffect,
  createMemo,
  createSignal,
  getOwner,
  onCleanup,
  onMount,
  untrack,
  useContext,
  type Accessor,
  type JSX,
} from "solid-js";
import type { MarketListRow, TokenDetail, TokenRef } from "../contracts/market";
import type { CapabilityDenial, DataState } from "../core/types";
import { isServedTimeframe } from "../market/ohlcv";
import {
  createRealtimeTargetCoordinator,
  type RealtimeTargetState,
} from "../realtime/target-coordinator";
import { createCommandResource, type CommandResource } from "./command-state";
import { useWorkspace, type WorkspaceStore } from "./session";

export type TicketTab = "market" | "limit";
export type DockTab = "positions" | "orders" | "activity" | "trades" | "holders";

interface SearchPayload {
  readonly results: readonly MarketListRow[];
}

export interface TrendingPayload {
  readonly category: string;
  readonly tokens: readonly MarketListRow[];
}

const SEARCH_TTL_MS = 30_000;
const DETAIL_TTL_MS = 30_000;
const TRENDING_TTL_MS = 30_000;
const TRENDING_REFRESH_MS = 30_000;
const RECENT_LIMIT = 8;
const WATCHLIST_LIMIT = 50;

/**
 * Default chart window. It is owned by the workstation store so the chart and
 * the encrypted realtime-target coordinator always agree on one authoritative
 * timeframe for the selected token.
 */
export const DEFAULT_TIMEFRAME = "1m";

export interface WorkstationStore {
  /* Pane / drawer state — memory-only for the session, never persisted. */
  readonly railCollapsed: Accessor<boolean>;
  readonly securityOpen: Accessor<boolean>;
  readonly ticketOpen: Accessor<boolean>;
  setRailCollapsed(value: boolean): void;
  toggleRail(): void;
  openSecurity(): void;
  closeSecurity(): void;
  setTicketOpen(value: boolean): void;
  /** `pending` keeps the caller's aria-expanded state in sync with the pane. */
  readonly narrow: Accessor<boolean>;

  /* Primary ticket / dock tab selection. The ticket tab survives an instrument
     switch: switching token must never bounce the user back to Market. */
  readonly ticketTab: Accessor<TicketTab>;
  setTicketTab(tab: TicketTab): void;
  readonly dockTab: Accessor<DockTab>;
  setDockTab(tab: DockTab): void;

  /* Token search (header) and the shared, memory-only market rail lists. */
  readonly query: Accessor<string>;
  setQuery(value: string): void;
  runSearch(raw: string): void;
  readonly search: CommandResource<SearchPayload>;
  readonly searchState: Accessor<DataState<SearchPayload>>;
  readonly searchDenial: Accessor<CapabilityDenial | null>;
  readonly trending: CommandResource<TrendingPayload>;
  readonly trendingState: Accessor<DataState<TrendingPayload>>;
  readonly trendingDenial: Accessor<CapabilityDenial | null>;
  refreshTrending(): void;

  /* Selected token detail for the header stats and centre identity strip. */
  /** Detail value is visible only when it belongs to the currently selected token. */
  readonly visibleDetail: Accessor<TokenDetail | null>;

  readonly recent: Accessor<readonly MarketListRow[]>;
  readonly watchlist: Accessor<readonly MarketListRow[]>;
  isWatched(ref: TokenRef): boolean;
  toggleWatch(row: MarketListRow): void;
  selectInstrument(row: MarketListRow): void;

  /**
   * One authoritative chart timeframe for the selected token. The chart reads
   * and writes this; the realtime-target coordinator reads it too, so a token or
   * timeframe change produces exactly one encrypted `set_realtime_target`.
   */
  readonly timeframe: Accessor<string>;
  setTimeframe(value: string): void;
  /** Observable state of the encrypted per-session realtime target binding. */
  readonly realtimeTarget: Accessor<RealtimeTargetState>;
}

const WorkspaceContext = createContext<WorkstationStore>();

/** Symbol-first label; never invents a value when the provider omits one. */
export function tokenLabel(token: TokenRef): string {
  if (token.symbol && token.symbol.length > 0) return token.symbol;
  if (token.name && token.name.length > 0) return token.name;
  return token.address.length > 13
    ? `${token.address.slice(0, 6)}…${token.address.slice(-4)}`
    : token.address;
}

function sameInstrument(a: { chain: string; address: string }, b: { chain: string; address: string }): boolean {
  return a.chain === b.chain && a.address === b.address;
}

/**
 * A finite, non-negative provider number, or `null`. Anything else (absent,
 * `NaN`, `Infinity`, a string, a negative) stays unknown so the renderer shows
 * an explicit `—` and never invents a zero.
 */
function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** A finite signed number (a 24h change may legitimately be negative), or `null`. */
function signedFiniteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** A positive integer rank, or `null`. */
function rankOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

function parseTokenRef(entry: unknown): TokenRef | null {
  if (typeof entry !== "object" || entry === null) return null;
  const token = entry as Record<string, unknown>;
  // Normalize the identity once, so the chart entity key, the coordinator's
  // exact target and the backend's trimmed identity all agree.
  const chain = typeof token.chain === "string" ? token.chain.trim() : "";
  const address = typeof token.address === "string" ? token.address.trim() : "";
  if (chain.length === 0 || address.length === 0) return null;
  const ref: {
    chain: string;
    address: string;
    symbol?: string;
    name?: string;
    decimals?: number;
  } = { chain, address };
  if (typeof token.symbol === "string" && token.symbol.length > 0) ref.symbol = token.symbol;
  if (typeof token.name === "string" && token.name.length > 0) ref.name = token.name;
  if (typeof token.decimals === "number" && Number.isInteger(token.decimals)) {
    ref.decimals = token.decimals;
  }
  return ref;
}

/**
 * Parse one market-list row, preserving the validated optional financial fields
 * the provider supplied. This is the typed row the market rail and search
 * combobox render; it never fabricates a price, market cap or rank.
 */
export function parseMarketRow(entry: unknown): MarketListRow | null {
  const token = parseTokenRef(entry);
  if (!token) return null;
  const record = entry as Record<string, unknown>;
  return {
    ...token,
    priceUsd: finiteOrNull(record.priceUsd),
    // A 24h change is signed: a down token must keep its negative value.
    priceChange24h: signedFiniteOrNull(record.priceChange24h),
    marketCapUsd: finiteOrNull(record.marketCapUsd),
    rank: rankOrNull(record.rank),
  };
}

/** Upper bound on rows parsed from one provider page. */
export const MAX_MARKET_ROWS = 200;

/** Parse a bounded list of market rows, dropping entries without an identity. */
export function parseMarketRows(value: unknown): readonly MarketListRow[] {
  if (!Array.isArray(value)) return [];
  const rows: MarketListRow[] = [];
  for (const entry of value) {
    if (rows.length >= MAX_MARKET_ROWS) break;
    const row = parseMarketRow(entry);
    if (row) rows.push(row);
  }
  return rows;
}

function asTokenResults(value: unknown): SearchPayload {
  if (typeof value !== "object" || value === null) return { results: [] };
  return { results: parseMarketRows((value as { results?: unknown }).results) };
}

function asTrendingPayload(value: unknown): TrendingPayload {
  if (typeof value !== "object" || value === null) {
    return { category: "trending", tokens: [] };
  }
  const raw = value as { category?: unknown; tokens?: unknown };
  return {
    category: typeof raw.category === "string" && raw.category.length > 0 ? raw.category : "trending",
    tokens: parseMarketRows(raw.tokens),
  };
}

export function createWorkstationStore(ws: WorkspaceStore): WorkstationStore {
  const [railCollapsed, setRailCollapsed] = createSignal(false);
  const [securityOpen, setSecurityOpen] = createSignal(false);
  const [ticketOpen, setTicketOpen] = createSignal(false);
  const [ticketTab, setTicketTab] = createSignal<TicketTab>("market");
  const [dockTab, setDockTab] = createSignal<DockTab>("positions");
  const [query, setQueryValue] = createSignal("");
  const [recent, setRecent] = createSignal<readonly MarketListRow[]>([]);
  const [watchlist, setWatchlist] = createSignal<readonly MarketListRow[]>([]);
  const [timeframe, setTimeframeValue] = createSignal<string>(DEFAULT_TIMEFRAME);

  const [narrow, setNarrow] = createSignal(false);

  const searchDenial = () => ws.capabilityDenial("market");
  const search = createCommandResource<SearchPayload>(ws.command, "search_token", {
    capability: "market",
    ttlMs: SEARCH_TTL_MS,
    clock: () => ws.nowMs(),
    validate: asTokenResults,
  });
  const detail = createCommandResource<TokenDetail>(ws.command, "get_token", {
    capability: "market",
    ttlMs: DETAIL_TTL_MS,
    clock: () => ws.nowMs(),
  });
  const trendingDenial = () => ws.capabilityDenial("market");
  const trending = createCommandResource<TrendingPayload>(ws.command, "get_trending", {
    capability: "market",
    ttlMs: TRENDING_TTL_MS,
    clock: () => ws.nowMs(),
    validate: asTrendingPayload,
  });
  const refreshTrending = (): void => {
    if (!ws.commandReady() || trendingDenial()) return;
    void trending.run({ category: "trending", limit: 30 });
  };
  const visibleDetail = createMemo<TokenDetail | null>(() => {
    const selected = ws.selectedInstrument();
    if (!selected) return null;
    const state = detail.state();
    const candidate =
      state.kind === "ready" || state.kind === "stale"
        ? state.value
        : state.kind === "loading" || state.kind === "error"
          ? state.prior
          : undefined;
    return candidate && sameInstrument(candidate.token, selected) ? candidate : null;
  });

  // Encrypted per-session realtime target binding. It is driven by one effect so
  // a token/timeframe change produces exactly one deduplicated command once both
  // the command channel and the realtime capability are ready.
  const targetCoordinator = createRealtimeTargetCoordinator({
    command: ws.command,
    canSend: () => ws.commandReady() && ws.capabilities().realtime,
  });
  createEffect(() => {
    const selected = ws.selectedInstrument();
    const window = timeframe();
    const ready = ws.commandReady() && ws.capabilities().realtime;
    if (!ready || selected === null) {
      targetCoordinator.setDesired(null);
      return;
    }
    targetCoordinator.setDesired({
      chain: selected.chain,
      address: selected.address,
      timeframe: window,
    });
  });
  onCleanup(() => targetCoordinator.reset());

  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  const clearDebounce = (): void => {
    if (debounceTimer !== undefined) {
      clearTimeout(debounceTimer);
      debounceTimer = undefined;
    }
  };
  onCleanup(clearDebounce);

  const runSearch = (raw: string): void => {
    clearDebounce();
    const value = raw.trim();
    // A blank query never reaches the encrypted command channel.
    if (value.length === 0) return;
    void search.run({ query: value });
  };

  const setQueryAndSearch = (value: string): void => {
    setQueryValue(value);
    clearDebounce();
    if (value.trim().length === 0) return;
    debounceTimer = setTimeout(() => {
      debounceTimer = undefined;
      runSearch(value);
    }, 300);
  };

  const selectInstrument = (row: MarketListRow): void => {
    ws.setSelectedInstrument({
      chain: row.chain,
      address: row.address,
      symbol: tokenLabel(row),
    });
    setRecent((prev) => [row, ...prev.filter((entry) => !sameInstrument(entry, row))].slice(0, RECENT_LIMIT));
    // Reflecting the label is not a new query: do not dispatch a search here.
    clearDebounce();
    setQueryValue(tokenLabel(row));
    void detail.run({ chain: row.chain, address: row.address });
  };

  const toggleWatch = (row: MarketListRow): void => {
    setWatchlist((prev) =>
      prev.some((entry) => sameInstrument(entry, row))
        ? prev.filter((entry) => !sameInstrument(entry, row))
        : [row, ...prev].slice(0, WATCHLIST_LIMIT),
    );
  };

  const isWatched = (token: TokenRef): boolean =>
    watchlist().some((entry) => sameInstrument(entry, token));

  const setTimeframe = (value: string): void => {
    // An unserved id (unknown or a local-only seconds window) is refused rather
    // than silently rendering a different window: the chart, the backend
    // realtime target and the Pro period set must all agree exactly.
    if (!isServedTimeframe(value)) return;
    setTimeframeValue(value);
  };

  let trendingTimer: ReturnType<typeof setInterval> | undefined;
  createEffect(() => {
    const canReadTrending = ws.commandReady() && !trendingDenial();
    if (trendingTimer !== undefined) {
      clearInterval(trendingTimer);
      trendingTimer = undefined;
    }
    if (!canReadTrending) {
      trending.reset();
      return;
    }
    untrack(refreshTrending);
    trendingTimer = setInterval(refreshTrending, TRENDING_REFRESH_MS);
  });
  onCleanup(() => {
    if (trendingTimer !== undefined) clearInterval(trendingTimer);
  });

  // Responsive collapse: the rail is the first thing to fold at <=1180px. A
  // user can still reopen it; crossing the breakpoint collapses but never
  // force-expands, so an explicit choice is not fought by the media query.
  onMount(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const railQuery = window.matchMedia("(max-width: 1180px)");
    const narrowQuery = window.matchMedia("(max-width: 980px)");
    const apply = (): void => {
      if (railQuery.matches) setRailCollapsed(true);
      setNarrow(narrowQuery.matches);
      if (!narrowQuery.matches) setTicketOpen(false);
    };
    apply();
    railQuery.addEventListener("change", apply);
    narrowQuery.addEventListener("change", apply);
    onCleanup(() => {
      railQuery.removeEventListener("change", apply);
      narrowQuery.removeEventListener("change", apply);
    });
  });

  if (getOwner()) onCleanup(() => search.reset());
  if (getOwner()) onCleanup(() => detail.reset());
  if (getOwner()) onCleanup(() => trending.reset());

  return {
    railCollapsed,
    securityOpen,
    ticketOpen,
    setRailCollapsed,
    toggleRail: () => setRailCollapsed((value) => !value),
    openSecurity: () => setSecurityOpen(true),
    closeSecurity: () => setSecurityOpen(false),
    setTicketOpen,
    narrow,
    ticketTab,
    setTicketTab,
    dockTab,
    setDockTab,
    query,
    setQuery: setQueryAndSearch,
    runSearch,
    search,
    searchState: search.state,
    searchDenial,
    trending,
    trendingState: trending.state,
    trendingDenial,
    refreshTrending,
    visibleDetail,
    recent,
    watchlist,
    isWatched,
    toggleWatch,
    selectInstrument,
    timeframe,
    setTimeframe,
    realtimeTarget: targetCoordinator.state,
  };
}

export function WorkstationProvider(props: {
  ws: WorkspaceStore;
  children: JSX.Element;
}): JSX.Element {
  const store = createWorkstationStore(props.ws);
  return <WorkspaceContext.Provider value={store}>{props.children}</WorkspaceContext.Provider>;
}

export function useWorkstation(): WorkstationStore {
  const store = useContext(WorkspaceContext);
  if (!store) throw new Error("useWorkstation must be used within a WorkstationProvider");
  return store;
}
