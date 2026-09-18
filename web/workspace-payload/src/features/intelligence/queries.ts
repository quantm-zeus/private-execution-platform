// Lazy, exact-identity token-intelligence queries.
//
// Every read is keyed by the exact `(chain, networkId, address)` triple. Symbol
// and name are never part of the key: a response for token A must never paint
// into token B's pane, and `fomoNetworkId` refuses an unverified chain rather
// than falling back to another network.

import type { InstrumentRef } from "../../core/types";
import { ageMs, isFresh, type DataState } from "../../core/types";

/** The only permitted query key. Symbol and name are never part of it. */
export interface IntelKey {
  readonly chain: string;
  readonly networkId: number;
  readonly address: string;
}

/**
 * The single chain-slug -> FOMO network-id mapping. It mirrors
 * `apps/private-api/src/fomo_market.rs::fomo_network_id` and returns `null` for
 * anything unverified, so an unknown chain renders unavailable rather than being
 * mislabelled to another network.
 */
const FOMO_NETWORKS: Readonly<Record<string, number>> = {
  solana: 1399811149,
  base: 8453,
  ethereum: 1,
  bnb_chain: 56,
  bsc: 56,
  bnb: 56,
  robinhood: 4663,
  robinhood_chain: 4663,
};

export function fomoNetworkId(chain: string): number | null {
  const slug = chain.trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(FOMO_NETWORKS, slug)) return null;
  return FOMO_NETWORKS[slug]!;
}

/** The only permitted key derivation. `null` when the chain is unverified. */
export function intelKeyFor(ref: InstrumentRef | null): IntelKey | null {
  if (!ref) return null;
  const networkId = fomoNetworkId(ref.chain);
  if (networkId === null) return null;
  const address = ref.address.trim();
  if (address.length === 0) return null;
  return { chain: ref.chain.trim(), networkId, address };
}

/** Stable display/serialisation key for an exact identity. */
export function intelKeyId(key: IntelKey | null): string {
  return key === null ? "" : `${key.chain.toLowerCase()}:${key.address}`;
}

export interface FreshnessView {
  readonly stale: boolean;
  readonly ageMs: number;
}

/**
 * Whether a settled read is stale against its own TTL. `createCommandResource`
 * never sets the `stale` kind itself (it keeps `ready` + freshness), so the
 * panes must derive staleness exactly as `AsyncSurface` does.
 */
export function freshnessView(
  state: DataState<unknown>,
  nowMs: number,
): FreshnessView | null {
  if (state.kind !== "ready" && state.kind !== "stale") return null;
  const freshness = { ...state.freshness, slot: null };
  return { stale: !isFresh(freshness, nowMs), ageMs: ageMs(freshness, nowMs) };
}
