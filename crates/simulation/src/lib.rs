//! Pure, deterministic CPMM local quote and simulation kernel.
//!
//! Part of Phase-3 exact simulation. Operates directly over canonical
//! [`market_types::CpmmPoolState`] without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

pub mod buy_tax;
pub mod cpmm;
pub mod error;

pub use buy_tax::{
    simulate_cpmm_exact_input_buy_tax, simulate_tax_aware_cpmm_buy,
    simulate_tax_aware_cpmm_buy_directed, simulate_tax_aware_cpmm_buy_exact_input,
    simulate_tax_aware_cpmm_buy_swap, TaxAwareCpmmBuyQuote, TaxAwareCpmmBuyResult,
    TaxAwareCpmmSimulationQuote,
};
pub use cpmm::{
    cmp_u128_products, div_u256_by_u128_floor, mul_u128_wide, simulate_cpmm_exact_input,
    simulate_cpmm_swap, simulate_cpmm_swap_directed, CpmmExactInputRequest, CpmmQuote,
    CpmmSimulationKernel, CpmmSimulationQuote,
};
pub use error::{
    CpmmErrorClass, CpmmSimulationErrorClass, SimulationError, TaxAwareCpmmBuyError,
    TaxAwareCpmmError, TaxAwareSimulationError,
};
