//! Phase 4 S1: exact, deterministic direct-route planner.
//!
//! Plans a single-hop direct route across injected local pool candidates. The
//! planner is pure: all pool state, tax assessment, freshness policy, and the
//! reference timestamp are supplied by the caller. There is no RPC, network,
//! wall clock, floating point, or randomness.
//!
//! Ranking is by exact simulated **net** output (never gross), and the winning
//! path is converted into a validated [`domain::RoutePlan`].
//!
//! Explicit non-goals for this slice: multi-hop/bridge search, split
//! optimization, CLMM/Bin depth targets, gas modelling, provider benchmark, and
//! DEX adapters. Splits are deferred until `domain::RoutePlan` can represent and
//! the signing digest can commit them.

#![forbid(unsafe_code)]

pub mod error;
pub mod leg;
pub mod plan;
pub mod types;

pub use error::RoutingError;
pub use leg::{simulate_leg, swap_dir};
pub use plan::{plan_direct_route, select_best_path, to_route_plan};
pub use types::{
    EvaluatedLeg, EvaluatedPath, PoolCandidate, RouteDecision, RoutingConfig, RoutingInput, SwapDir,
};
