//! Pure, deterministic CPMM local quote and simulation kernel.
//!
//! Part of Phase-3 exact simulation. Operates directly over canonical
//! [`market_types::CpmmPoolState`] without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

pub mod cpmm;
pub mod error;

pub use cpmm::{
    cmp_u128_products, div_u256_by_u128_floor, mul_u128_wide, simulate_cpmm_exact_input,
    simulate_cpmm_swap, simulate_cpmm_swap_directed, CpmmExactInputRequest, CpmmQuote,
    CpmmSimulationKernel, CpmmSimulationQuote,
};
pub use error::SimulationError;
