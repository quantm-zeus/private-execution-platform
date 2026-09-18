// Web-side view of the FOMO token-intelligence contracts served by the private
// API over the encrypted `/v1/command` boundary (ops `get_token_holders`,
// `get_token_about`, `get_token_activity`).
//
// These mirror the Rust `fomo_intelligence` projection. The web app never
// invents a value: an absent or non-finite provider field is `null` and is
// rendered explicitly as unknown. External links are normalized to http/https
// only; a missing link is omitted (never a ghost button).

import type { RiskAssessment } from "./market";

/** A trader/user identity. Every field is optional-by-contract; `null` is unknown. */
export interface TokenIntelUser {
  readonly handle: string | null;
  readonly displayName: string | null;
  readonly avatarUrl: string | null;
  /** Only ever `true`/`false` when the provider proved it; otherwise `null`. */
  readonly verified: boolean | null;
  readonly clan: string | null;
  readonly followed: boolean | null;
  readonly dev: boolean | null;
  readonly followers: number | null;
}

/** The optional thesis/comment a holder authored for the token. */
export interface HolderThesis {
  readonly text: string | null;
  readonly createdAtMs: number | null;
  readonly likes: number | null;
  readonly tradeId: string | null;
}

/** One FOMO trader holding the selected token. */
export interface TokenHolder {
  readonly user: TokenIntelUser;
  /** Secondary identity only; the UI keeps the handle primary. */
  readonly wallet: string | null;
  readonly amount: number | null;
  readonly valueUsd: number | null;
  readonly costBasisUsd: number | null;
  readonly averageEntryPriceUsd: number | null;
  readonly currentPriceUsd: number | null;
  readonly realizedPnlUsd: number | null;
  readonly unrealizedPnlUsd: number | null;
  readonly totalPnlUsd: number | null;
  readonly averageHoldTimeSeconds: number | null;
  readonly thesis: HolderThesis | null;
}

export interface TokenHoldersPayload {
  readonly chain: string;
  readonly address: string;
  readonly holders: readonly TokenHolder[];
  readonly count: number;
  /** Provider provenance label; `null` when the provider did not state one. */
  readonly source: string | null;
  /** Age of the provider document; `null` when the provider did not state one. */
  readonly sourceAgeMs: number | null;
}

/** Normalized external links; an absent key is omitted and parsed as `null`. */
export interface TokenSocialLinks {
  readonly twitter: string | null;
  readonly website: string | null;
  readonly telegram: string | null;
  readonly discord: string | null;
}

export interface TokenAboutProfile {
  readonly launchpad: string | null;
  readonly graduationPercent: number | null;
  readonly createdAtMs: number | null;
  readonly circulatingSupply: number | null;
  readonly totalSupply: number | null;
}

export interface TokenAboutStats {
  readonly priceUsd: number | null;
  readonly priceChange24h: number | null;
  readonly marketCapUsd: number | null;
  readonly fdvUsd: number | null;
  readonly liquidityUsd: number | null;
  readonly volume24hUsd: number | null;
  readonly holders: number | null;
  readonly top10HoldersPercent: number | null;
}

/** Buy/sell statistics for one closed timeframe. */
export interface TradingWindow {
  readonly buyCount: number | null;
  readonly sellCount: number | null;
  readonly buyVolumeUsd: number | null;
  readonly sellVolumeUsd: number | null;
  readonly uniqueBuyers: number | null;
  readonly uniqueSellers: number | null;
}

export interface TokenAboutTrading {
  readonly "5m": TradingWindow | null;
  readonly "1h": TradingWindow | null;
  readonly "4h": TradingWindow | null;
  readonly "24h": TradingWindow | null;
}

export interface TokenAboutPayload {
  readonly token: {
    readonly chain: string;
    readonly address: string;
    readonly symbol: string | null;
    readonly name: string | null;
    readonly imageUrl: string | null;
    readonly socialLinks: TokenSocialLinks;
  };
  readonly profile: TokenAboutProfile;
  readonly stats: TokenAboutStats;
  readonly trading: TokenAboutTrading;
  readonly warnings: readonly string[];
  readonly risk: RiskAssessment | null;
  /** Provider provenance label; `null` when the provider did not state one. */
  readonly source: string | null;
  /** Age of the provider document; `null` when the provider did not state one. */
  readonly sourceAgeMs: number | null;
}

/** The closed PEP activity kinds; the provider's own type is kept in `rawType`. */
export type TokenActivityKind = "buy" | "sell" | "transfer" | "thesis" | "other";

export interface TokenActivityEvent {
  readonly id: string | null;
  readonly type: TokenActivityKind;
  readonly rawType: string | null;
  readonly direction: "in" | "out" | null;
  readonly user: TokenIntelUser;
  readonly usdAmount: number | null;
  readonly priceUsd: number | null;
  readonly marketCapUsd: number | null;
  readonly fdvUsd: number | null;
  readonly createdAtMs: number | null;
  readonly thesis: string | null;
}

export interface TokenActivityPage {
  readonly chain: string;
  readonly address: string;
  readonly events: readonly TokenActivityEvent[];
  readonly count: number;
  readonly nextCursor: string | null;
  readonly hasNextPage: boolean | null;
  /** Provider provenance label; `null` when the provider did not state one. */
  readonly source: string | null;
  /** Age of the provider document; `null` when the provider did not state one. */
  readonly sourceAgeMs: number | null;
}
