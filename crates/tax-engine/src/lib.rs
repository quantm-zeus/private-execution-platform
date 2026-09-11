//! Pure, deterministic tax and safety assessment contracts.
//!
//! Part of Phase-3 tax/safety evaluation. Validates direct trade intents against
//! optional observed tax and sellability snapshots. Operates without floating-point
//! arithmetic, wall-clock time, external RPCs, credentials, or side-effects.

pub mod assessment;
pub mod error;

pub use assessment::{
    assess_tax_safety, assessed_asset_for_intent, evaluate_tax_safety, TaxAssessment,
    TaxSafetyEngine,
};
pub use error::TaxSafetyError;
