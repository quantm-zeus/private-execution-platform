import {
  createContext,
  createMemo,
  createSignal,
  getOwner,
  onCleanup,
  onMount,
  useContext,
  type Accessor,
  type JSX,
} from "solid-js";
import type { TokenDetail, TokenRef } from "../contracts/market";
import type { CapabilityDenial, DataState } from "../core/types";
import { createCommandResource, type CommandResource } from "./command-state";
import { useWorkspace, type WorkspaceStore } from "./session";

export type TicketTab = "market" | "limit";
export type DockTab = "positions" | "orders" | "activity" | "trades" | "holders";

interface SearchPayload {
  readonly results: readonly TokenRef[];
}

const SEARCH_TTL_MS = 30_000;
const DETAIL_TTL_MS = 30_000;
const RECENT_LIMIT = 8;
const WATCHLIST_LIMIT = 50;

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

  /* Selected token detail for the header stats and centre identity strip. */
  /** Detail value is visible only when it belongs to the currently selected token. */
  readonly visibleDetail: Accessor<TokenDetail | null>;

  readonly recent: Accessor<readonly TokenRef[]>;
  readonly watchlist: Accessor<readonly TokenRef[]>;
  isWatched(ref: TokenRef): boolean;
  toggleWatch(ref: TokenRef): void;
  selectInstrument(ref: TokenRef): void;
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
  const results = (value as { results?: unknown }).results;
  if (!Array.isArray(results)) return { results: [] };
  const parsed = results.filter((entry): entry is TokenRef => {
    if (typeof entry !== "object" || entry === null) return false;
    const token = entry as Record<string, unknown>;
    return (
      typeof token.chain === "string" &&
      token.chain.length > 0 &&
      typeof token.address === "string" &&
      token.address.length > 0
    );
  });
  return { results: parsed };
}

export function createWorkstationStore(ws: WorkspaceStore): WorkstationStore {
  const [railCollapsed, setRailCollapsed] = createSignal(false);
  const [securityOpen, setSecurityOpen] = createSignal(false);
  const [ticketOpen, setTicketOpen] = createSignal(false);
  const [ticketTab, setTicketTab] = createSignal<TicketTab>("market");
  const [dockTab, setDockTab] = createSignal<DockTab>("positions");
  const [query, setQueryValue] = createSignal("");
  const [recent, setRecent] = createSignal<readonly TokenRef[]>([]);
  const [watchlist, setWatchlist] = createSignal<readonly TokenRef[]>([]);

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

  const selectInstrument = (token: TokenRef): void => {
    ws.setSelectedInstrument({
      chain: token.chain,
      address: token.address,
      symbol: tokenLabel(token),
    });
    setRecent((prev) => [token, ...prev.filter((entry) => !sameInstrument(entry, token))].slice(0, RECENT_LIMIT));
    // Reflecting the label is not a new query: do not dispatch a search here.
    clearDebounce();
    setQueryValue(tokenLabel(token));
    void detail.run({ chain: token.chain, address: token.address });
  };

  const toggleWatch = (token: TokenRef): void => {
    setWatchlist((prev) =>
      prev.some((entry) => sameInstrument(entry, token))
        ? prev.filter((entry) => !sameInstrument(entry, token))
        : [token, ...prev].slice(0, WATCHLIST_LIMIT),
    );
  };

  const isWatched = (token: TokenRef): boolean =>
    watchlist().some((entry) => sameInstrument(entry, token));

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
    visibleDetail,
    recent,
    watchlist,
    isWatched,
    toggleWatch,
    selectInstrument,
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
