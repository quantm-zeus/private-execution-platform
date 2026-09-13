//! Bounded, deterministic candidate enumeration over caller-supplied pool state.
//!
//! Enumeration is limited to a direct path (`token_in -> token_out`) and exactly
//! one bridge asset (`token_in -> B -> token_out`), at most two pools per path.
//! The token graph is never brute-force traversed: bridges are drawn only from
//! the distinct counter-assets of `token_in` edges, capped at
//! [`crate::MAX_BRIDGE_ASSETS`], and the final candidate list is capped at
//! [`crate::MAX_ROUTE_CANDIDATES`]. Every emitted order is sorted, so hash-map
//! iteration never influences output.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use chain_types::AssetId;
use domain::TradeIntent;
use market_types::{
    BinPoolState, Bps, ClmmPoolState, CpmmPoolState, LiquidityBin, PoolKindState, PoolStateEnvelope,
};
use serde::{Deserialize, Serialize};

use crate::error::RoutingError;
use crate::label::{PoolRefLabel, VenueLabel};
use crate::{MAX_BRIDGE_ASSETS, MAX_POOLS_SCANNED, MAX_ROUTE_CANDIDATES, MAX_ROUTE_HOPS};

/// Adapter-neutral pool offered to the single-path router.
///
/// `venue` maps to `RouteLeg.venue` (the normalized router id used by the policy
/// venue allowlist); `leg_pool_ref` maps to `RouteLeg.pool_ref` (EVM pool account
/// or Solana program id, because the locked contract overloads that field).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolDescriptor {
    /// Canonical local pool state and deterministic freshness metadata.
    pub envelope: PoolStateEnvelope,
    /// Router/venue identifier for `RouteLeg.venue`.
    pub venue: VenueLabel,
    /// Pool account or program id for `RouteLeg.pool_ref`.
    pub leg_pool_ref: PoolRefLabel,
    /// Exact CLMM/Bin price-impact override in basis points, when known.
    pub impact_override_bps: Option<Bps>,
}

/// One pool hop inside a candidate path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateLeg {
    /// Index of the source descriptor in the caller-supplied slice.
    pub descriptor_index: usize,
    /// Directed input asset for this hop.
    pub token_in: AssetId,
    /// Directed output asset for this hop.
    pub token_out: AssetId,
}

/// A loop-free candidate path of one or two hops.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidatePath {
    /// Ordered hops (`1..=MAX_ROUTE_HOPS`).
    pub legs: Vec<CandidateLeg>,
}

/// Result of bounded enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSet {
    /// Deterministically ordered candidate paths.
    pub paths: Vec<CandidatePath>,
    /// `true` when a bridge-asset or route-candidate cap clipped the result.
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgeDir {
    ZeroForOne,
    OneForZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Edge {
    desc_idx: usize,
    dir: EdgeDir,
}

fn desc_token_in(desc: &PoolDescriptor, dir: EdgeDir) -> &AssetId {
    match dir {
        EdgeDir::ZeroForOne => desc.envelope.state.token_0(),
        EdgeDir::OneForZero => desc.envelope.state.token_1(),
    }
}

fn desc_token_out(desc: &PoolDescriptor, dir: EdgeDir) -> &AssetId {
    match dir {
        EdgeDir::ZeroForOne => desc.envelope.state.token_1(),
        EdgeDir::OneForZero => desc.envelope.state.token_0(),
    }
}

type EdgeKey<'a> = (&'a str, &'a str, &'a str, &'a str);

fn edge_sort_key<'a>(descriptors: &'a [PoolDescriptor], edge: Edge) -> EdgeKey<'a> {
    let desc = &descriptors[edge.desc_idx];
    (
        desc_token_in(desc, edge.dir).address.as_str(),
        desc_token_out(desc, edge.dir).address.as_str(),
        desc.venue.as_str(),
        desc.leg_pool_ref.as_str(),
    )
}

fn descriptor_index(desc: &PoolDescriptor) -> String {
    desc.envelope.pool_id.address.clone()
}

fn dir_code(dir: EdgeDir) -> u8 {
    match dir {
        EdgeDir::ZeroForOne => 0,
        EdgeDir::OneForZero => 1,
    }
}

fn asset_cmp(left: &AssetId, right: &AssetId) -> Ordering {
    // Enumeration already rejects cross-chain descriptors, so the chain is equal
    // and the address alone gives a deterministic order.
    left.address.cmp(&right.address)
}

fn cmp_slices_by<T>(
    left: &[T],
    right: &[T],
    mut compare: impl FnMut(&T, &T) -> Ordering,
) -> Ordering {
    let common = left.len().min(right.len());
    for index in 0..common {
        let ordering = compare(&left[index], &right[index]);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn cpmm_cmp(left: &CpmmPoolState, right: &CpmmPoolState) -> Ordering {
    asset_cmp(&left.token_0, &right.token_0)
        .then_with(|| asset_cmp(&left.token_1, &right.token_1))
        .then_with(|| left.decimals_0.cmp(&right.decimals_0))
        .then_with(|| left.decimals_1.cmp(&right.decimals_1))
        .then_with(|| left.reserve_0.cmp(&right.reserve_0))
        .then_with(|| left.reserve_1.cmp(&right.reserve_1))
        .then_with(|| left.total_lp_supply.cmp(&right.total_lp_supply))
        .then_with(|| left.fee_bps.cmp(&right.fee_bps))
}

fn clmm_cmp(left: &ClmmPoolState, right: &ClmmPoolState) -> Ordering {
    asset_cmp(&left.token_0, &right.token_0)
        .then_with(|| asset_cmp(&left.token_1, &right.token_1))
        .then_with(|| left.decimals_0.cmp(&right.decimals_0))
        .then_with(|| left.decimals_1.cmp(&right.decimals_1))
        .then_with(|| left.tick_spacing.cmp(&right.tick_spacing))
        .then_with(|| left.current_tick.cmp(&right.current_tick))
        .then_with(|| left.sqrt_price_x64.cmp(&right.sqrt_price_x64))
        .then_with(|| left.liquidity.cmp(&right.liquidity))
        .then_with(|| left.fee_bps.cmp(&right.fee_bps))
        .then_with(|| {
            cmp_slices_by(&left.ticks, &right.ticks, |a, b| {
                a.index
                    .cmp(&b.index)
                    .then_with(|| a.liquidity_gross.cmp(&b.liquidity_gross))
                    .then_with(|| a.liquidity_net.cmp(&b.liquidity_net))
            })
        })
}

fn bin_cmp(left: &BinPoolState, right: &BinPoolState) -> Ordering {
    asset_cmp(&left.token_0, &right.token_0)
        .then_with(|| asset_cmp(&left.token_1, &right.token_1))
        .then_with(|| left.decimals_0.cmp(&right.decimals_0))
        .then_with(|| left.decimals_1.cmp(&right.decimals_1))
        .then_with(|| left.active_bin_id.cmp(&right.active_bin_id))
        .then_with(|| left.bin_step.cmp(&right.bin_step))
        .then_with(|| left.fee_bps.cmp(&right.fee_bps))
        .then_with(|| {
            cmp_slices_by(
                &left.bins,
                &right.bins,
                |a: &LiquidityBin, b: &LiquidityBin| {
                    a.id.cmp(&b.id)
                        .then_with(|| a.reserve_0.cmp(&b.reserve_0))
                        .then_with(|| a.reserve_1.cmp(&b.reserve_1))
                },
            )
        })
}

fn state_rank(state: &PoolKindState) -> u8 {
    match state {
        PoolKindState::Cpmm(_) => 0,
        PoolKindState::Clmm(_) => 1,
        PoolKindState::Bin(_) => 2,
    }
}

fn state_cmp(left: &PoolKindState, right: &PoolKindState) -> Ordering {
    match (left, right) {
        (PoolKindState::Cpmm(a), PoolKindState::Cpmm(b)) => cpmm_cmp(a, b),
        (PoolKindState::Clmm(a), PoolKindState::Clmm(b)) => clmm_cmp(a, b),
        (PoolKindState::Bin(a), PoolKindState::Bin(b)) => bin_cmp(a, b),
        _ => state_rank(left).cmp(&state_rank(right)),
    }
}

/// Canonical order over two descriptors that share a `(pool_id, direction)`.
///
/// The comparison never consults descriptor slice position, so the retained
/// representative is independent of the caller's ordering even when duplicate
/// descriptors carry conflicting state.
fn descriptor_cmp(left: &PoolDescriptor, right: &PoolDescriptor) -> Ordering {
    left.venue
        .as_str()
        .cmp(right.venue.as_str())
        .then_with(|| left.leg_pool_ref.as_str().cmp(right.leg_pool_ref.as_str()))
        .then_with(|| {
            left.envelope
                .observed_at_ms
                .cmp(&right.envelope.observed_at_ms)
        })
        .then_with(|| {
            left.envelope
                .sequence
                .get()
                .cmp(&right.envelope.sequence.get())
        })
        .then_with(|| left.impact_override_bps.cmp(&right.impact_override_bps))
        .then_with(|| state_cmp(&left.envelope.state, &right.envelope.state))
}

/// Deduplicates directed edges by `(pool_id, direction)`.
///
/// For each directed pool edge the canonically smallest descriptor (per
/// [`descriptor_cmp`]) is retained, and the surviving edges keep their incoming
/// deterministic order. Duplicate descriptors can therefore never emit an
/// identical second bridge candidate, consume the route cap, or make the winner
/// order-dependent under conflicting duplicate state.
fn dedupe_edges(edges: Vec<Edge>, descriptors: &[PoolDescriptor]) -> Vec<Edge> {
    let mut deduped: Vec<Edge> = Vec::with_capacity(edges.len());
    let mut seen: HashMap<(String, u8), usize> = HashMap::new();
    for edge in edges {
        let key = (
            descriptor_index(&descriptors[edge.desc_idx]),
            dir_code(edge.dir),
        );
        match seen.get(&key).copied() {
            Some(existing) => {
                let current = deduped[existing];
                if descriptor_cmp(&descriptors[edge.desc_idx], &descriptors[current.desc_idx])
                    == Ordering::Less
                {
                    deduped[existing] = edge;
                }
            }
            None => {
                seen.insert(key, deduped.len());
                deduped.push(edge);
            }
        }
    }
    deduped
}

fn candidate_leg(desc: &PoolDescriptor, dir: EdgeDir, descriptor_index: usize) -> CandidateLeg {
    CandidateLeg {
        descriptor_index,
        token_in: desc_token_in(desc, dir).clone(),
        token_out: desc_token_out(desc, dir).clone(),
    }
}

type PathKey = (usize, Vec<(String, String, String, String)>);

fn path_key(descriptors: &[PoolDescriptor], path: &CandidatePath) -> PathKey {
    let legs: Vec<(String, String, String, String)> = path
        .legs
        .iter()
        .map(|leg| {
            let desc = &descriptors[leg.descriptor_index];
            (
                desc.venue.as_str().to_string(),
                desc.leg_pool_ref.as_str().to_string(),
                leg.token_in.address.clone(),
                leg.token_out.address.clone(),
            )
        })
        .collect();
    (path.legs.len(), legs)
}

/// Enumerates the bounded direct and one-bridge candidate set.
///
/// Fails closed on an empty descriptor set, a descriptor count above
/// [`MAX_POOLS_SCANNED`], an invalid or cross-chain pool state, or an unsupported
/// hop count. Caps that clip rather than fail set [`CandidateSet::truncated`].
pub fn enumerate_candidates(
    intent: &TradeIntent,
    max_hops: usize,
    descriptors: &[PoolDescriptor],
) -> Result<CandidateSet, RoutingError> {
    if max_hops == 0 || max_hops > MAX_ROUTE_HOPS {
        return Err(RoutingError::UnsupportedHopCount);
    }
    if descriptors.is_empty() {
        return Err(RoutingError::EmptyPoolSet);
    }
    if descriptors.len() > MAX_POOLS_SCANNED {
        return Err(RoutingError::PoolSetTooLarge);
    }
    if intent.token_in == intent.token_out {
        return Err(RoutingError::SameAssetPair);
    }

    let mut edges: Vec<Edge> = Vec::with_capacity(descriptors.len().saturating_mul(2));
    for (desc_idx, desc) in descriptors.iter().enumerate() {
        desc.envelope
            .validate()
            .map_err(|_| RoutingError::PoolStateInvalid)?;
        if desc.envelope.pool_id.chain != intent.chain
            || desc.envelope.state.token_0().chain != intent.chain
            || desc.envelope.state.token_1().chain != intent.chain
        {
            return Err(RoutingError::PoolChainMismatch);
        }
        edges.push(Edge {
            desc_idx,
            dir: EdgeDir::ZeroForOne,
        });
        edges.push(Edge {
            desc_idx,
            dir: EdgeDir::OneForZero,
        });
    }

    edges.sort_by(|left, right| {
        edge_sort_key(descriptors, *left).cmp(&edge_sort_key(descriptors, *right))
    });

    // Duplicate descriptors collapse to one directed edge each, so they cannot
    // flood the candidate cap with identical bridge candidates or trade places
    // under caller reordering.
    let edges = dedupe_edges(edges, descriptors);

    // Lookup-only map: iteration order never drives emitted output.
    let mut by_input: HashMap<AssetId, Vec<usize>> = HashMap::new();
    for (edge_index, edge) in edges.iter().enumerate() {
        let token_in = desc_token_in(&descriptors[edge.desc_idx], edge.dir).clone();
        by_input.entry(token_in).or_default().push(edge_index);
    }

    let mut paths: Vec<CandidatePath> = Vec::new();
    let mut truncated = false;

    // Direct: `token_in -> token_out`, deduped by pool id.
    let mut seen_direct_pools: HashSet<String> = HashSet::new();
    if let Some(edge_indices) = by_input.get(&intent.token_in) {
        for &edge_index in edge_indices {
            let edge = edges[edge_index];
            let desc = &descriptors[edge.desc_idx];
            if desc_token_out(desc, edge.dir) != &intent.token_out {
                continue;
            }
            let pool = descriptor_index(desc);
            if !seen_direct_pools.insert(pool) {
                continue;
            }
            paths.push(CandidatePath {
                legs: vec![candidate_leg(desc, edge.dir, edge.desc_idx)],
            });
        }
    }

    if max_hops >= 2 {
        // Distinct bridge assets reachable from `token_in`, deterministically ordered.
        let mut bridge_assets: Vec<&AssetId> = Vec::new();
        if let Some(edge_indices) = by_input.get(&intent.token_in) {
            for &edge_index in edge_indices {
                let edge = edges[edge_index];
                let out = desc_token_out(&descriptors[edge.desc_idx], edge.dir);
                if out == &intent.token_out || out == &intent.token_in {
                    continue;
                }
                if !bridge_assets.contains(&out) {
                    bridge_assets.push(out);
                }
            }
        }
        bridge_assets.sort_by(|left, right| left.address.cmp(&right.address));
        if bridge_assets.len() > MAX_BRIDGE_ASSETS {
            bridge_assets.truncate(MAX_BRIDGE_ASSETS);
            truncated = true;
        }

        if let Some(first_edges) = by_input.get(&intent.token_in) {
            for bridge in &bridge_assets {
                let second_edges = match by_input.get(*bridge) {
                    Some(indices) => indices,
                    None => continue,
                };
                for &first_index in first_edges {
                    let first_edge = edges[first_index];
                    let first_desc = &descriptors[first_edge.desc_idx];
                    if desc_token_out(first_desc, first_edge.dir) != *bridge {
                        continue;
                    }
                    let first_pool = descriptor_index(first_desc);
                    for &second_index in second_edges {
                        let second_edge = edges[second_index];
                        let second_desc = &descriptors[second_edge.desc_idx];
                        if desc_token_out(second_desc, second_edge.dir) != &intent.token_out {
                            continue;
                        }
                        // Loop-free: never reuse the same pool on both hops.
                        if descriptor_index(second_desc) == first_pool {
                            continue;
                        }
                        paths.push(CandidatePath {
                            legs: vec![
                                candidate_leg(first_desc, first_edge.dir, first_edge.desc_idx),
                                candidate_leg(second_desc, second_edge.dir, second_edge.desc_idx),
                            ],
                        });
                    }
                }
            }
        }
    }

    let mut keyed: Vec<(PathKey, CandidatePath)> = paths
        .into_iter()
        .map(|path| (path_key(descriptors, &path), path))
        .collect();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut paths: Vec<CandidatePath> = keyed.into_iter().map(|(_, path)| path).collect();
    if paths.len() > MAX_ROUTE_CANDIDATES {
        paths.truncate(MAX_ROUTE_CANDIDATES);
        truncated = true;
    }

    Ok(CandidateSet { paths, truncated })
}
