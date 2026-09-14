import { type Component } from "solid-js";
import { viewById, type ViewId } from "../app/views";
import DiscoverPanel from "./discover/DiscoverPanel";
import ExecutionPanel from "./execution/ExecutionPanel";
import IntelligencePanel from "./intelligence/IntelligencePanel";
import LimitsPanel from "./limits/LimitsPanel";
import OverviewPanel from "./overview/OverviewPanel";
import PortfolioPanel from "./portfolio/PortfolioPanel";
import SecurityPanel from "./security/SecurityPanel";
import TerminalPanel from "./terminal/TerminalPanel";
import TradePanel from "./trade/TradePanel";

/**
 * View registry. Navigation is in-memory only; panel components own their own
 * capability gating and DataState rendering so no private semantics leak into
 * routes or titles.
 */
export const SURFACES: Record<Exclude<ViewId, "overview">, Component> = {
  discover: DiscoverPanel,
  terminal: TerminalPanel,
  trade: TradePanel,
  limits: LimitsPanel,
  execution: ExecutionPanel,
  portfolio: PortfolioPanel,
  intelligence: IntelligencePanel,
  security: SecurityPanel,
};

export function surfaceFor(view: ViewId): Component {
  if (view === "overview") return OverviewPanel;
  return SURFACES[view];
}

export function viewMeta(view: ViewId) {
  return viewById(view);
}
