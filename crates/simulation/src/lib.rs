//! Pure, deterministic CPMM local quote and simulation kernel.
//!
//! Part of Phase-3 exact simulation. Operates directly over canonical
//! [`market_types::CpmmPoolState`] without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

pub mod bin;
pub mod buy_tax;
pub mod clmm;
pub mod clmm_buy_tax;
pub mod clmm_roundtrip_tax;
pub mod clmm_sell_tax;
pub mod cpmm;
pub mod error;
pub mod roundtrip_tax;
pub mod sell_tax;

pub use bin::{
    simulate_bin_exact_input, BinExactInputRequest, BinSimulationQuote, MAX_BIN_CROSSES,
};
pub use buy_tax::{
    simulate_cpmm_exact_input_buy_tax, simulate_tax_aware_cpmm_buy,
    simulate_tax_aware_cpmm_buy_directed, simulate_tax_aware_cpmm_buy_exact_input,
    simulate_tax_aware_cpmm_buy_swap, TaxAwareCpmmBuyQuote, TaxAwareCpmmBuyResult,
    TaxAwareCpmmSimulationQuote,
};
pub use clmm::{
    simulate_clmm_exact_input, ClmmExactInputRequest, ClmmSimulationQuote, MAX_CLMM_TICK_CROSSES,
};
pub use clmm_buy_tax::{simulate_tax_aware_clmm_buy_exact_input, TaxAwareClmmBuyQuote};
pub use clmm_roundtrip_tax::{
    simulate_tax_aware_clmm_roundtrip_exact_input, TaxAwareClmmRoundtripQuote,
};
pub use clmm_sell_tax::{simulate_tax_aware_clmm_sell_exact_input, TaxAwareClmmSellQuote};
pub use cpmm::{
    cmp_u128_products, div_u256_by_u128_ceil, div_u256_by_u128_floor, mul_u128_wide,
    simulate_cpmm_exact_input, simulate_cpmm_exact_output, simulate_cpmm_swap,
    simulate_cpmm_swap_directed, CpmmExactInputRequest, CpmmExactOutputQuote,
    CpmmExactOutputRequest, CpmmQuote, CpmmSimulationKernel, CpmmSimulationQuote,
};
pub use error::{
    BinSimulationError, ClmmSimulationError, CpmmErrorClass, CpmmSimulationErrorClass,
    SimulationError, TaxAwareClmmSimulationError, TaxAwareCpmmBuyError, TaxAwareCpmmError,
    TaxAwareSimulationError,
};
pub use roundtrip_tax::{
    simulate_tax_aware_cpmm_roundtrip_exact_input, TaxAwareCpmmRoundtripQuote,
};
pub use sell_tax::{simulate_tax_aware_cpmm_sell_exact_input, TaxAwareCpmmSellQuote};
