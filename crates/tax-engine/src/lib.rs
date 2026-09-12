//! Pure, deterministic tax and safety assessment contracts.
//!
//! Part of Phase-3 tax/safety evaluation. Validates direct trade intents against
//! optional observed tax and sellability snapshots. Operates without floating-point
//! arithmetic, wall-clock time, external RPCs, credentials, or side-effects.

pub mod assessment;
pub mod buy_output;
pub mod error;
pub mod sell_input;

pub use assessment::{
    assess_tax_safety, assessed_asset_for_intent, evaluate_tax_safety, TaxAssessment,
    TaxSafetyEngine,
};
pub use buy_output::{
    apply_buy_tax, apply_buy_tax_to_output, calculate_buy_tax_output, BuyOutputTax, BuyTaxOutput,
};
pub use error::TaxSafetyError;
pub use sell_input::{
    apply_sell_tax, apply_sell_tax_to_input, calculate_sell_tax_input, SellInputTax, SellTaxInput,
};
