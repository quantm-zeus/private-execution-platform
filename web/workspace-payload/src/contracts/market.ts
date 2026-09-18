// Web-side view of the canonical market/evidence contracts. These mirror the
// backend `market-types` projections the private API is expected to serve (see
// .dsh/web-product/BACKEND_REQUESTS.md BR-1/BR-2/BR-3). The web app never
// invents values: every field is optional-but-typed and rendered with explicit
// unknown handling.

export interface TokenRef {
  readonly chain: string;
  readonly address: string;
  readonly symbol?: string;
  readonly name?: string;
  readonly decimals?: number;
}

/**
 * A typed market-list row: a `TokenRef` plus the optional financial fields a
 * market provider may return for list surfaces (search / trending / watchlist).
 *
 * The backend already returns `priceUsd` / `marketCapUsd` / `rank` on trending
 * rows. They are optional by contract: an absent or non-finite value stays
 * `null` so the renderer shows an explicit `—` and never invents a zero. The
 * row is a superset of `TokenRef`, so existing selection/detail consumers keep
 * accepting it unchanged.
 */
export interface MarketListRow extends TokenRef {
  readonly priceUsd: number | null;
  readonly priceChange24h: number | null;
  readonly marketCapUsd: number | null;
  readonly liquidityUsd: number | null;
  readonly volume24hUsd: number | null;
  readonly rank: number | null;
}

export interface TokenStats {
  readonly priceUsd: number | null;
  readonly priceChange24h: number | null;
  readonly marketCapUsd: number | null;
  readonly liquidityUsd: number | null;
  readonly volume24hUsd: number | null;
  readonly holders: number | null;
}

export interface Candle {
  /** Bucket start time in epoch ms. */
  readonly timeMs: number;
  readonly open: number;
  readonly high: number;
  readonly low: number;
  readonly close: number;
  readonly volume: number;
}

export interface TradeTick {
  readonly timeMs: number;
  readonly price: number;
  readonly size: number;
  readonly side: "buy" | "sell";
}

export interface DepthLevel {
  readonly price: number;
  readonly size: number;
}

export interface DepthBook {
  readonly bids: readonly DepthLevel[];
  readonly asks: readonly DepthLevel[];
  readonly slot: number | null;
}

export interface RiskFactor {
  readonly id: string;
  readonly label: string;
  readonly severity: "info" | "low" | "medium" | "high" | "critical";
  readonly detail: string;
}

export interface RiskAssessment {
  readonly score: number | null;
  readonly factors: readonly RiskFactor[];
  readonly buyTaxBps: number | null;
  readonly sellTaxBps: number | null;
  readonly transferFeeBps: number | null;
  readonly sellRestricted: boolean | null;
  readonly simulated: boolean;
  /**
   * Optional provider risk state (e.g. FOMO `clear` / `hard_risk`). `null` or
   * absent means the provider stated no level — the renderer then derives a
   * state from the provider's own factors and never invents a score.
   */
  readonly level?: string | null;
}

export type EvidenceProvider = "fomo" | "gmgn" | "twitter" | "okx" | "onchain" | "local";

export interface EvidenceItem {
  readonly provider: EvidenceProvider;
  readonly kind: string;
  readonly summary: string;
  /** Local age of this evidence; consumers must mark stale evidence. */
  readonly ageMs: number;
  readonly confidence: number | null;
  readonly stale: boolean;
}

export interface ProviderHealth {
  readonly provider: EvidenceProvider;
  readonly state: "healthy" | "degraded" | "cooldown" | "circuit_open" | "unavailable";
  readonly reason: string | null;
  readonly ageMs: number | null;
}

export interface TokenDetail {
  readonly token: TokenRef;
  readonly stats: TokenStats | null;
  readonly risk: RiskAssessment | null;
  readonly evidence: readonly EvidenceItem[];
  readonly slot: number | null;
  readonly sourceAgeMs: number;
}
