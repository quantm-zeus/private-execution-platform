//! Redacted, payload-free limit-engine errors.
//!
//! Every variant is a unit value with a static message, so neither
//! [`Display`](std::fmt::Display) nor [`Debug`](std::fmt::Debug) can leak
//! amounts, assets, prices, order/owner/wallet references, endpoints, or
//! digests. [`LimitEngineError::ALL`] is the roster the redaction test walks.

use thiserror::Error;

/// Fail-closed limit-engine error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LimitEngineError {
    /// `from -> to` is not permitted by the authoritative order state machine.
    #[error("order status transition is not allowed")]
    InvalidTransition,
    /// The stored order violates the fill-ledger conservation invariant.
    #[error("stored order violates ledger invariants")]
    InvalidOrder,
    /// The order deadline has passed for a non-terminal target state.
    #[error("order is expired")]
    Expired,
    /// The net executable price does not satisfy the limit price.
    #[error("net executable price violates the limit")]
    LimitPriceViolated,
    /// No fill amount satisfies the limit price within the allowed range.
    #[error("no safe fill satisfies the limit")]
    NoSafeFill,
    /// The candidate fill is below the order's minimum fill.
    #[error("fill amount is below the minimum fill")]
    AmountBelowMinFill,
    /// The order forbids partial fills.
    #[error("partial fill is not allowed")]
    PartialFillNotAllowed,
    /// The fill exceeds the order's remaining input.
    #[error("fill exceeds remaining input")]
    RemainingUnderflow,
    /// The fill delta disagrees with the resulting remaining input.
    #[error("fill delta does not match remaining input")]
    FillMismatch,
    /// The local market state is stale.
    #[error("local market state is stale")]
    StaleState,
    /// The local market state requires a resynchronization.
    #[error("local market state requires resync")]
    ResyncRequired,
    /// No quote is available for the order.
    #[error("quote is unavailable")]
    QuoteUnavailable,
    /// The store rejected the append because the expected version is stale.
    #[error("persistence version conflict")]
    PersistenceConflict,
    /// The store is unavailable.
    #[error("persistence is unavailable")]
    PersistenceUnavailable,
    /// The idempotency key is already bound to a different order.
    #[error("idempotency key conflict")]
    IdempotencyConflict,
    /// Recovery could not complete.
    #[error("recovery failed")]
    RecoveryFailed,
    /// Recovery replay produced a state inconsistent with the stored log.
    #[error("recovery replay is inconsistent")]
    RecoveryInconsistent,
    /// Checked amount or sequence arithmetic overflowed.
    #[error("amount arithmetic overflow")]
    ArithmeticOverflow,
    /// The store holds an internally inconsistent order record.
    #[error("order store state is invalid")]
    StoreInvalid,
}

impl LimitEngineError {
    /// Every error variant, for the redaction roster test.
    pub const ALL: [Self; 19] = [
        Self::InvalidTransition,
        Self::InvalidOrder,
        Self::Expired,
        Self::LimitPriceViolated,
        Self::NoSafeFill,
        Self::AmountBelowMinFill,
        Self::PartialFillNotAllowed,
        Self::RemainingUnderflow,
        Self::FillMismatch,
        Self::StaleState,
        Self::ResyncRequired,
        Self::QuoteUnavailable,
        Self::PersistenceConflict,
        Self::PersistenceUnavailable,
        Self::IdempotencyConflict,
        Self::RecoveryFailed,
        Self::RecoveryInconsistent,
        Self::ArithmeticOverflow,
        Self::StoreInvalid,
    ];
}

#[cfg(test)]
mod tests {
    use super::LimitEngineError;

    /// Exhaustive match: adding a variant without naming it here fails to
    /// compile, which forces the author to look at (and extend) `ALL`.
    fn variant_name(error: &LimitEngineError) -> &'static str {
        match error {
            LimitEngineError::InvalidTransition => "InvalidTransition",
            LimitEngineError::InvalidOrder => "InvalidOrder",
            LimitEngineError::Expired => "Expired",
            LimitEngineError::LimitPriceViolated => "LimitPriceViolated",
            LimitEngineError::NoSafeFill => "NoSafeFill",
            LimitEngineError::AmountBelowMinFill => "AmountBelowMinFill",
            LimitEngineError::PartialFillNotAllowed => "PartialFillNotAllowed",
            LimitEngineError::RemainingUnderflow => "RemainingUnderflow",
            LimitEngineError::FillMismatch => "FillMismatch",
            LimitEngineError::StaleState => "StaleState",
            LimitEngineError::ResyncRequired => "ResyncRequired",
            LimitEngineError::QuoteUnavailable => "QuoteUnavailable",
            LimitEngineError::PersistenceConflict => "PersistenceConflict",
            LimitEngineError::PersistenceUnavailable => "PersistenceUnavailable",
            LimitEngineError::IdempotencyConflict => "IdempotencyConflict",
            LimitEngineError::RecoveryFailed => "RecoveryFailed",
            LimitEngineError::RecoveryInconsistent => "RecoveryInconsistent",
            LimitEngineError::ArithmeticOverflow => "ArithmeticOverflow",
            LimitEngineError::StoreInvalid => "StoreInvalid",
        }
    }

    #[test]
    fn roster_names_every_variant_once() {
        let mut names: Vec<&'static str> = LimitEngineError::ALL.iter().map(variant_name).collect();
        assert_eq!(names.len(), 19);
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 19, "ALL duplicates a variant");
    }
}
