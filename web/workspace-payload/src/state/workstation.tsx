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
import type {
  TokenAboutPayload,
  TokenActivityPage,
  TokenHoldersPayload,
} from "../contracts/token-intelligence";
import type { CapabilityDenial, DataState } from "../core/types";
import { stateValue } from "../core/types";
import { intelKeyFor, intelKeyId, type IntelKey } from "../features/intelligence/queries";
import { createTokenIntelligenceResources } from "./token-intelligence";
import { isServedTimeframe } from "../market/ohlcv";
import {
  createRealtimeTargetCoordinator,
  type RealtimeTargetState,
} from "../realtime/target-coordinator";
import {
  MarketEventRouter,
  isPriceFresh,
  marketPriceEntityKey,
  mergeTrendingRows,
  trendingChainCounts,
  type MarketSource,
  type PricePush,
  type TrendingPush,
} from "../realtime/market-events";
import type { DecodedFrame } from "../realtime/types";
import { createCommandResource, type CommandResource } from "./command-state";
import { parseMarketRows } from "./market-row";
import { createTrendingPoller, type TrendingPoller } from "./trending-poller";
import { useWorkspace, type WorkspaceStore } from "./session";

// Re-exported so existing consumers/tests keep importing the shared parser from
// the workstation module while the implementation lives in `./market-row`
// (which the realtime router can import without a cycle).
export { MAX_MARKET_ROWS, parseMarketRow, parseMarketRows } from "./market-row";

export type TicketTab = "market" | "limit";
/**
 * The V2 dock union (owner-approved): `trades` is removed — it was only ever a
 * placeholder for a market-trades capability, and the exact-token activity feed
 * under Activity -> Token supersedes it. `RealtimeChannel` also has a `trades`
 * member; that is a transport channel and is deliberately untouched.
 */
export type DockTab = "positions" | "orders" | "activity" | "holders" | "about";

/** Token-intelligence subviews the dock panes may request lazily. */
export type IntelKind = "holders" | "about" | "activity";

export interface IntelRunOptions {
  readonly limit?: number;
  readonly cursor?: string | null;
}

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

  /* Bottom-dock sizing — memory-only, like every other pane signal. The clamp
     itself lives in CSS so no caller can breach the chart floor. */
  readonly dockHeight: Accessor<number | null>;
  readonly dockExpanded: Accessor<boolean>;
  setDockHeight(px: number | null): void;
  setDockExpanded(value: boolean): void;
  toggleDockExpanded(): void;

  /* Token intelligence — lazy reads keyed by the exact (chain, networkId,
     address) identity. A response for token A is never rendered under token B. */
  readonly intelKey: Accessor<IntelKey | null>;
  readonly intelDenial: Accessor<CapabilityDenial | null>;
  readonly holders: CommandResource<TokenHoldersPayload>;
  readonly about: CommandResource<TokenAboutPayload>;
  readonly activity: CommandResource<TokenActivityPage>;
  /** Run one exact-identity read; an identity change resets all three first. */
  runIntel(kind: IntelKind, options?: IntelRunOptions): void;

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
  /** Rows = reconciled command rows overlaid with pushed WS-observed values. */
  readonly trendingRows: Accessor<readonly MarketListRow[]>;
  /** Honest per-chain counts of the current trending rows. */
  readonly trendingChains: Accessor<ReadonlyMap<string, number>>;
  /** Latest pushed trending batch, or `null` when none has been observed. */
  readonly pushedTrending: Accessor<TrendingPush | null>;
  /** Provenance of the realtime market lane: ws, polling fallback, or none. */
  readonly marketSource: Accessor<MarketSource>;
  /** Latest pushed price for an exact instrument, or `null` when none/other. */
  latestPrice(ref: TokenRef): PricePush | null;
  /** Apply decrypted `market` frames; returns true when anything was accepted. */
  applyMarketFrames(frames: readonly DecodedFrame[]): void;

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
  const [dockHeight, setDockHeight] = createSignal<number | null>(null);
  const [dockExpanded, setDockExpanded] = createSignal(false);
  const toggleDockExpanded = (): void => {
    setDockExpanded((value) => !value);
  };

  // Lazy token-intelligence reads. The resources are keyed by the exact identity
  // the request carries; `createCommandResource` aborts the previous request and
  // the validator rejects a success whose echo does not match the request, so a
  // slow A document can never paint into B's pane.
  const intelResources = createTokenIntelligenceResources({
    command: ws.command,
    nowMs: () => ws.nowMs(),
  });
  const intelDenial = (): CapabilityDenial | null =>
    ws.capabilityDenial("token_intelligence");
  const intelKey = createMemo<IntelKey | null>(() => intelKeyFor(ws.selectedInstrument()));
  let lastIntelId = "";
  createEffect(() => {
    const id = intelKeyId(intelKey());
    if (id === lastIntelId) return;
    lastIntelId = id;
    // A new instrument invalidates every in-flight and cached intelligence read.
    intelResources.holders.reset();
    intelResources.about.reset();
    intelResources.activity.reset();
  });
  const runIntel = (kind: IntelKind, options: IntelRunOptions = {}): void => {
    const key = intelKey();
    if (key === null || intelDenial() !== null) return;
    const payload: Record<string, unknown> = { chain: key.chain, address: key.address };
    if (kind === "holders") {
      payload.limit = options.limit ?? 200;
      void intelResources.holders.run(payload);
      return;
    }
    if (kind === "about") {
      void intelResources.about.run(payload);
      return;
    }
    payload.limit = options.limit ?? 12;
    if (options.cursor) payload.cursor = options.cursor;
    void intelResources.activity.run(payload);
  };

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

  // Pushed `market` frames from the encrypted realtime feed. The router is a
  // plain class; one generation signal makes its immutable state reactive.
  const marketRouter = new MarketEventRouter();
  const [marketGeneration, setMarketGeneration] = createSignal(0);
  const applyMarketFrames = (frames: readonly DecodedFrame[]): void => {
    if (marketRouter.apply(frames)) setMarketGeneration((value) => value + 1);
  };
  const pushedTrending = createMemo<TrendingPush | null>(() => {
    marketGeneration();
    return marketRouter.state.trending;
  });
  const marketSource = createMemo<MarketSource>(() => {
    marketGeneration();
    return marketRouter.state.source;
  });
  const latestPrice = (ref: TokenRef): PricePush | null => {
    marketGeneration();
    const push =
      marketRouter.state.prices.get(marketPriceEntityKey(ref.chain, ref.address)) ?? null;
    if (!push) return null;
    // The lane retains a cached price per entity; never surface one older than
    // the absolute freshness window as the current price.
    return isPriceFresh(push, ws.serverNowMs()) ? push : null;
  };
  const trendingRows = createMemo<readonly MarketListRow[]>(() => {
    const base = stateValue(trending.state())?.tokens ?? [];
    return mergeTrendingRows(base, pushedTrending());
  });
  const trendingChains = createMemo<ReadonlyMap<string, number>>(() =>
    trendingChainCounts(trendingRows()),
  );

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

  // Trending reconciliation. Pushed WS frames keep the visible rows fresh; this
  // poller is the bounded fallback (2s active, deferred when hidden, backed off
  // when the connection is degraded) and never overlaps a request.
  const trendingPoller: TrendingPoller = createTrendingPoller({
    refresh: refreshTrending,
    isReady: () => ws.commandReady() && !trendingDenial(),
    isHidden: () => typeof document !== "undefined" && document.hidden === true,
    isDegraded: () => {
      const phase = ws.connection().phase;
      return phase === "offline" || phase === "reconnecting" || phase === "degraded";
    },
    subscribeVisibility: (cb) => {
      if (typeof document === "undefined") return () => {};
      document.addEventListener("visibilitychange", cb);
      return () => document.removeEventListener("visibilitychange", cb);
    },
  });
  createEffect(() => {
    const canReadTrending = ws.commandReady() && !trendingDenial();
    if (!canReadTrending) {
      trendingPoller.stop();
      trending.reset();
      return;
    }
    // One immediate reconciliation when the channel becomes ready, then the
    // poller keeps the visible list fresh at the bounded cadence.
    untrack(refreshTrending);
    trendingPoller.start();
  });
  onCleanup(() => trendingPoller.dispose());

  // Responsive collapse: the rail is the first thing to fold at <=1180px. A
  // user can still reopen it; crossing the breakpoint collapses but never
  // force-expands, so an explicit choice is not fought by the media query.
  onMount(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    // DESIGN.md §8: the rail collapses at 1279 and below; the ticket becomes a
    // right overlay at 980 and below.
    const railQuery = window.matchMedia("(max-width: 1279px)");
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
  if (getOwner()) onCleanup(() => intelResources.holders.reset());
  if (getOwner()) onCleanup(() => intelResources.about.reset());
  if (getOwner()) onCleanup(() => intelResources.activity.reset());

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
    dockHeight,
    dockExpanded,
    setDockHeight,
    setDockExpanded,
    toggleDockExpanded,
    intelKey,
    intelDenial,
    holders: intelResources.holders,
    about: intelResources.about,
    activity: intelResources.activity,
    runIntel,
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
    trendingRows,
    trendingChains,
    pushedTrending,
    marketSource,
    latestPrice,
    applyMarketFrames,
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
