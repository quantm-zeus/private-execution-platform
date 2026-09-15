import type { CapabilityKey } from "../core/types";

/**
 * Workspace navigation is intentionally in-memory only. No view id, token,
 * order or amount is ever written to the URL, document title or history.
 */
export type ViewId =
  | "overview"
  | "discover"
  | "terminal"
  | "trade"
  | "limits"
  | "execution"
  | "portfolio"
  | "intelligence"
  | "security";

export interface ViewDef {
  readonly id: ViewId;
  readonly label: string;
  readonly description: string;
  readonly group: "Market" | "Execute" | "Account";
  /** Primary backend capability this view needs to show live data. */
  readonly capability: CapabilityKey;
}

export const VIEWS: readonly ViewDef[] = [
  {
    id: "overview",
    label: "Overview",
    description: "Workspace, session and execution-gate status.",
    group: "Market",
    capability: "market",
  },
  {
    id: "discover",
    label: "Discover",
    description: "Token search, market stats and risk/intelligence evidence.",
    group: "Market",
    // Matches the server's operation map: `search_token`/`get_token` are gated
    // on the authoritative `market` capability (`opaque.rs`), not `intelligence`.
    capability: "market",
  },
  {
    id: "terminal",
    label: "Terminal",
    description: "Local realtime chart, OHLCV and depth.",
    group: "Market",
    capability: "realtime",
  },
  {
    id: "trade",
    label: "Trade",
    description: "Quote, market preview and full net-economics ticket.",
    group: "Execute",
    capability: "preview",
  },
  {
    id: "limits",
    label: "Limits",
    description: "Net-price limit orders, partial fills and lifecycle.",
    group: "Execute",
    capability: "limits",
  },
  {
    id: "execution",
    label: "Execution",
    description: "Adaptive TWAP, RFQ/solver competition and progress.",
    group: "Execute",
    capability: "twap",
  },
  {
    id: "portfolio",
    label: "Portfolio",
    description: "Balances, open orders, history and alerts.",
    group: "Account",
    capability: "portfolio",
  },
  {
    id: "intelligence",
    label: "Intelligence",
    description: "Provider health, freshness and evidence provenance.",
    group: "Account",
    capability: "intelligence",
  },
  {
    id: "security",
    label: "Security",
    description: "Session, limits and the web-only withdrawal surface.",
    group: "Account",
    capability: "withdraw",
  },
];

export const VIEW_GROUPS: readonly ViewDef["group"][] = ["Market", "Execute", "Account"];

export function viewById(id: ViewId): ViewDef {
  const found = VIEWS.find((view) => view.id === id);
  if (!found) throw new Error(`unknown view: ${id}`);
  return found;
}
