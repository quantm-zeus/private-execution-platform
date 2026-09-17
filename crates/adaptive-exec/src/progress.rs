//! Durable progress models for adaptive TWAP and RFQ execution.
//!
//! The pure engines in [`crate::plan`]/[`crate::engine`] and [`crate::rfq`] decide
//! *what to do next*; these types are what a durable store persists between
//! steps so a restart can resume safely. Each carries a monotonically increasing
//! `version`, the last applied idempotency key, and a validated status
//! transition table, so a replayed slice/decision is a no-op rather than a
//! double execution.
//!
//! No signing, submission, clock, or I/O is named here: these are data contracts
//! a scheduler composes with the isolated [`crate::AdaptiveTwap`] and
//! [`crate::SolverCompetition`] cores and the durable attempt store.

use market_types::AtomicAmount;
use thiserror::Error;

use crate::plan::{TwapPlan, TwapState};
use crate::rfq::{CompetitionOutcome, RfqRequest};

/// Lifecycle of a durable TWAP plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwapStatus {
    /// Created but not started.
    Pending,
    /// Executing slices.
    Running,
    /// Fully consumed.
    Complete,
    /// Halted (for example by the hard slippage cap).
    Halted,
    /// Cancelled by the owner.
    Cancelled,
}

impl TwapStatus {
    /// Whether no further transition is allowed.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Halted | Self::Cancelled)
    }

    /// The allowed transition table.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use TwapStatus::*;
        matches!(
            (self, next),
            (Pending, Running)
                | (Pending, Cancelled)
                | (Running, Running)
                | (Running, Complete)
                | (Running, Halted)
                | (Running, Cancelled)
        )
    }
}

/// Durable progress of one TWAP plan.
#[derive(Clone, PartialEq, Eq)]
pub struct TwapProgress {
    /// Server-generated plan identity.
    pub plan_id: String,
    /// The immutable plan.
    pub plan: TwapPlan,
    /// Current mutable state.
    pub state: TwapState,
    /// Lifecycle status.
    pub status: TwapStatus,
    /// Monotonic version, starting at 1.
    pub version: u64,
    /// When the last transition was applied.
    pub updated_at_ms: i64,
    /// Every `(idempotency_key, chunk)` applied so far.
    pub applied: Vec<(String, AtomicAmount)>,
}

impl std::fmt::Debug for TwapProgress {
    /// Redacted: amounts, assets, and plan ids are payload semantics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TwapProgress")
            .field("status", &self.status)
            .field("slices_done", &self.state.slices_done)
            .field("applied", &self.applied.len())
            .finish_non_exhaustive()
    }
}

/// Bound on the in-memory applied-key ledger a progress record retains.
///
/// A durable store enforces uniqueness in the database; the pure model fails
/// closed rather than growing without bound.
pub const MAX_APPLIED_PROGRESS_KEYS: usize = 4096;

/// Progress-model failure taxonomy. Redacted: no ids or amounts are rendered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProgressError {
    /// The plan/request id was empty.
    #[error("progress id is required")]
    EmptyId,
    /// A mutating call had no idempotency key.
    #[error("progress mutation requires an idempotency key")]
    MissingIdempotencyKey,
    /// The chunk was zero or exceeded the remaining input.
    #[error("invalid execution chunk")]
    InvalidChunk,
    /// The status transition is not permitted.
    #[error("invalid progress transition")]
    InvalidTransition,
    /// The same idempotency key was reused for a different payload.
    #[error("progress idempotency conflict")]
    IdempotencyConflict,
    /// The applied-key ledger is full.
    #[error("progress idempotency ledger is full")]
    IdempotencyLedgerFull,
    /// The version counter overflowed.
    #[error("progress version overflow")]
    Saturated,
}

impl TwapProgress {
    /// Creates a `Pending` plan.
    pub fn new(plan_id: &str, plan: TwapPlan) -> Result<Self, ProgressError> {
        if plan_id.trim().is_empty() {
            return Err(ProgressError::EmptyId);
        }
        Ok(Self {
            plan_id: plan_id.to_string(),
            plan,
            state: TwapState::new(plan.total_input),
            status: TwapStatus::Pending,
            version: 1,
            updated_at_ms: 0,
            applied: Vec::new(),
        })
    }

    /// Starts the plan (`Pending -> Running`).
    pub fn start(&self, at_ms: i64) -> Result<Self, ProgressError> {
        self.transition(TwapStatus::Running, at_ms, |_| {})
    }

    /// Applies one executed slice.
    ///
    /// A replay of **any** previously applied `idempotency_key` returns the record
    /// unchanged; reusing an applied key with a *different* chunk is an
    /// [`ProgressError::IdempotencyConflict`]. A zero chunk or a chunk larger than
    /// the remaining input is rejected, and a plan that is not `Running` refuses
    /// the slice.
    pub fn record_slice(
        &self,
        chunk: AtomicAmount,
        at_ms: i64,
        idempotency_key: &str,
    ) -> Result<Self, ProgressError> {
        if idempotency_key.trim().is_empty() {
            return Err(ProgressError::MissingIdempotencyKey);
        }
        if let Some((_, applied_chunk)) = self
            .applied
            .iter()
            .find(|(key, _)| key == idempotency_key)
        {
            return if *applied_chunk == chunk {
                Ok(self.clone())
            } else {
                Err(ProgressError::IdempotencyConflict)
            };
        }
        if self.status != TwapStatus::Running {
            return Err(ProgressError::InvalidTransition);
        }
        if chunk.is_zero() || chunk.get() > self.state.remaining_input.get() {
            return Err(ProgressError::InvalidChunk);
        }
        let version = self
            .version
            .checked_add(1)
            .ok_or(ProgressError::Saturated)?;
        let state = self.state.record(chunk, at_ms);
        let status = if state.remaining_input.is_zero() {
            TwapStatus::Complete
        } else {
            TwapStatus::Running
        };
        if self.applied.len() >= MAX_APPLIED_PROGRESS_KEYS {
            return Err(ProgressError::IdempotencyLedgerFull);
        }
        let mut applied = self.applied.clone();
        applied.push((idempotency_key.to_string(), chunk));
        Ok(Self {
            plan_id: self.plan_id.clone(),
            plan: self.plan,
            state,
            status,
            version,
            updated_at_ms: at_ms,
            applied,
        })
    }

    /// Halts a running plan (`Running -> Halted`).
    pub fn halt(&self, at_ms: i64) -> Result<Self, ProgressError> {
        self.transition(TwapStatus::Halted, at_ms, |_| {})
    }

    /// Cancels a pending or running plan.
    pub fn cancel(&self, at_ms: i64) -> Result<Self, ProgressError> {
        self.transition(TwapStatus::Cancelled, at_ms, |_| {})
    }

    fn transition(
        &self,
        next: TwapStatus,
        at_ms: i64,
        apply: impl FnOnce(&mut Self),
    ) -> Result<Self, ProgressError> {
        if !self.status.can_transition_to(next) {
            return Err(ProgressError::InvalidTransition);
        }
        let version = self
            .version
            .checked_add(1)
            .ok_or(ProgressError::Saturated)?;
        let mut updated = self.clone();
        updated.status = next;
        updated.version = version;
        updated.updated_at_ms = at_ms;
        apply(&mut updated);
        Ok(updated)
    }
}

/// Lifecycle of a durable RFQ request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfqStatus {
    /// Raised, no quotes collected yet.
    Requested,
    /// At least one usable quote was collected.
    Quoted,
    /// An external solver won; the caller executes it.
    Won,
    /// No external solver beat the local baseline.
    NoWinner,
    /// Cancelled by the owner.
    Cancelled,
    /// Definitively failed.
    FailedFinal,
}

impl RfqStatus {
    /// Whether no further transition is allowed.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Won | Self::NoWinner | Self::Cancelled | Self::FailedFinal
        )
    }

    /// The allowed transition table.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use RfqStatus::*;
        matches!(
            (self, next),
            (Requested, Quoted)
                | (Requested, Cancelled)
                | (Requested, FailedFinal)
                | (Quoted, Won)
                | (Quoted, NoWinner)
                | (Quoted, Cancelled)
                | (Quoted, FailedFinal)
        )
    }
}

/// Durable progress of one RFQ request.
#[derive(Clone, PartialEq, Eq)]
pub struct RfqProgress {
    /// Server-generated request id.
    pub request_id: String,
    /// The immutable request.
    pub request: RfqRequest,
    /// Lifecycle status.
    pub status: RfqStatus,
    /// Winning solver id, when one won.
    pub winner: Option<String>,
    /// Realized improvement over the local baseline in bps.
    pub improvement_bps: Option<u16>,
    /// Monotonic version, starting at 1.
    pub version: u64,
    /// When the last transition was applied.
    pub updated_at_ms: i64,
    /// Idempotency keys already applied, in order.
    pub applied: Vec<String>,
}

impl std::fmt::Debug for RfqProgress {
    /// Redacted: assets, amounts, and request ids are payload semantics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RfqProgress")
            .field("status", &self.status)
            .field("applied", &self.applied.len())
            .finish_non_exhaustive()
    }
}

impl RfqProgress {
    /// Creates a `Requested` RFQ.
    pub fn new(request_id: &str, request: RfqRequest) -> Result<Self, ProgressError> {
        if request_id.trim().is_empty() {
            return Err(ProgressError::EmptyId);
        }
        Ok(Self {
            request_id: request_id.to_string(),
            request,
            status: RfqStatus::Requested,
            winner: None,
            improvement_bps: None,
            version: 1,
            updated_at_ms: 0,
            applied: Vec::new(),
        })
    }

    /// Records that usable quotes were collected.
    pub fn record_quoted(
        &self,
        at_ms: i64,
        idempotency_key: &str,
    ) -> Result<Self, ProgressError> {
        self.transition(RfqStatus::Quoted, at_ms, idempotency_key, |_| {})
    }

    /// Records the competition decision.
    pub fn record_decision(
        &self,
        outcome: &CompetitionOutcome,
        at_ms: i64,
        idempotency_key: &str,
    ) -> Result<Self, ProgressError> {
        match outcome {
            CompetitionOutcome::Winner {
                winner,
                improvement_bps,
                ..
            } => {
                let winner_id = winner.solver_id.clone();
                let improvement = *improvement_bps;
                self.transition(
                    RfqStatus::Won,
                    at_ms,
                    idempotency_key,
                    move |updated| {
                        updated.winner = Some(winner_id);
                        updated.improvement_bps = Some(improvement);
                    },
                )
            }
            CompetitionOutcome::NoWinner {
                improvement_bps, ..
            } => {
                let improvement = *improvement_bps;
                self.transition(
                    RfqStatus::NoWinner,
                    at_ms,
                    idempotency_key,
                    move |updated| {
                        updated.improvement_bps = improvement;
                    },
                )
            }
        }
    }

    /// Cancels the request.
    pub fn cancel(&self, at_ms: i64, idempotency_key: &str) -> Result<Self, ProgressError> {
        self.transition(RfqStatus::Cancelled, at_ms, idempotency_key, |_| {})
    }

    /// Fails the request definitively.
    pub fn fail_final(&self, at_ms: i64, idempotency_key: &str) -> Result<Self, ProgressError> {
        self.transition(RfqStatus::FailedFinal, at_ms, idempotency_key, |_| {})
    }

    fn transition(
        &self,
        next: RfqStatus,
        at_ms: i64,
        idempotency_key: &str,
        apply: impl FnOnce(&mut Self),
    ) -> Result<Self, ProgressError> {
        if idempotency_key.trim().is_empty() {
            return Err(ProgressError::MissingIdempotencyKey);
        }
        if self.applied.iter().any(|key| key == idempotency_key) {
            return Ok(self.clone());
        }
        if !self.status.can_transition_to(next) {
            return Err(ProgressError::InvalidTransition);
        }
        if self.applied.len() >= MAX_APPLIED_PROGRESS_KEYS {
            return Err(ProgressError::IdempotencyLedgerFull);
        }
        let version = self
            .version
            .checked_add(1)
            .ok_or(ProgressError::Saturated)?;
        let mut updated = self.clone();
        updated.status = next;
        updated.version = version;
        updated.updated_at_ms = at_ms;
        updated.applied.push(idempotency_key.to_string());
        apply(&mut updated);
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfq::{NoWinnerReason, RfqSide, SolverQuote};
    use chain_types::{AssetId, ChainId};
    use market_types::{AssetAmount, AtomicAmount};

    fn plan() -> TwapPlan {
        TwapPlan::new(
            AtomicAmount::new(300),
            3,
            AtomicAmount::new(50),
            AtomicAmount::new(150),
            60_000,
            5_000,
            200,
        )
    }

    #[test]
    fn twap_progress_completes_and_replays_idempotently() {
        let progress = TwapProgress::new("plan-1", plan()).expect("new");
        assert_eq!(progress.status, TwapStatus::Pending);
        let running = progress.start(1).expect("start");

        let first = running
            .record_slice(AtomicAmount::new(100), 2, "slice-1")
            .expect("slice");
        assert_eq!(first.status, TwapStatus::Running);
        assert_eq!(first.state.remaining_input, AtomicAmount::new(200));
        assert_eq!(first.version, 3);

        // Replaying the same key is a no-op.
        let replay = first
            .record_slice(AtomicAmount::new(100), 3, "slice-1")
            .expect("replay");
        assert_eq!(replay, first);

        let second = first
            .record_slice(AtomicAmount::new(100), 4, "slice-2")
            .expect("slice");
        // Replaying an OLDER key is still a no-op (not just the last one).
        let out_of_order_replay = second
            .record_slice(AtomicAmount::new(100), 5, "slice-1")
            .expect("older replay");
        assert_eq!(out_of_order_replay, second);
        // The same key with a different chunk is a conflict.
        assert_eq!(
            second.record_slice(AtomicAmount::new(50), 6, "slice-1"),
            Err(ProgressError::IdempotencyConflict)
        );

        let third = second
            .record_slice(AtomicAmount::new(100), 5, "slice-3")
            .expect("slice");
        assert_eq!(third.status, TwapStatus::Complete);
        assert_eq!(third.state.remaining_input, AtomicAmount::new(0));
        // A completed plan refuses another slice.
        assert_eq!(
            third.record_slice(AtomicAmount::new(1), 6, "slice-4"),
            Err(ProgressError::InvalidTransition)
        );
        assert!(!format!("{third:?}").contains("300"));
    }

    #[test]
    fn twap_progress_rejects_invalid_chunks_and_keys() {
        let running = TwapProgress::new("plan-1", plan())
            .expect("new")
            .start(1)
            .expect("start");
        assert_eq!(
            running.record_slice(AtomicAmount::new(0), 2, "k"),
            Err(ProgressError::InvalidChunk)
        );
        assert_eq!(
            running.record_slice(AtomicAmount::new(301), 2, "k"),
            Err(ProgressError::InvalidChunk)
        );
        assert_eq!(
            running.record_slice(AtomicAmount::new(100), 2, "  "),
            Err(ProgressError::MissingIdempotencyKey)
        );
        assert_eq!(
            TwapProgress::new("  ", plan()).err(),
            Some(ProgressError::EmptyId)
        );
    }

    #[test]
    fn twap_progress_halt_and_cancel_are_terminal() {
        let running = TwapProgress::new("plan-1", plan())
            .expect("new")
            .start(1)
            .expect("start");
        let halted = running.halt(2).expect("halt");
        assert!(halted.status.is_terminal());
        assert_eq!(halted.cancel(3), Err(ProgressError::InvalidTransition));

        let cancelled = TwapProgress::new("plan-2", plan())
            .expect("new")
            .cancel(1)
            .expect("cancel");
        assert!(cancelled.status.is_terminal());
        assert_eq!(cancelled.start(2), Err(ProgressError::InvalidTransition));
    }

    fn rfq_request() -> RfqRequest {
        RfqRequest {
            chain: ChainId::Base,
            token_in: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            token_out: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
            side: RfqSide::Buy,
            input_amount: AtomicAmount::new(1_000),
            deadline_ms: 10_000,
            min_improvement_bps: 25,
        }
    }

    #[test]
    fn rfq_progress_records_a_winner() {
        let progress = RfqProgress::new("rfq-1", rfq_request()).expect("new");
        let quoted = progress.record_quoted(1, "q1").expect("quoted");
        // Replaying q1 is a no-op.
        assert_eq!(quoted.record_quoted(2, "q1").expect("replay"), quoted);
        let decision = CompetitionOutcome::Winner {
            winner: SolverQuote {
                solver_id: "solver-a".to_string(),
                settled_output: AssetAmount {
                    asset: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
                    amount: AtomicAmount::new(2_400),
                },
                valid_until_ms: 9_000,
            },
            runner_up: None,
            improvement_bps: 40,
        };
        let won = quoted
            .record_decision(&decision, 2, "d1")
            .expect("won");
        assert_eq!(won.status, RfqStatus::Won);
        assert_eq!(won.winner.as_deref(), Some("solver-a"));
        assert_eq!(won.improvement_bps, Some(40));
        assert!(won.status.is_terminal());
        assert_eq!(
            won.record_quoted(3, "q2"),
            Err(ProgressError::InvalidTransition)
        );
        assert!(!format!("{won:?}").contains("solver-a"));
    }

    #[test]
    fn rfq_progress_records_no_winner_and_cancel() {
        let quoted = RfqProgress::new("rfq-1", rfq_request())
            .expect("new")
            .record_quoted(1, "q1")
            .expect("quoted");
        let decision = CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::BelowBaseline,
            best_quote: None,
            improvement_bps: Some(10),
        };
        let no_winner = quoted
            .record_decision(&decision, 2, "d1")
            .expect("decision");
        assert_eq!(no_winner.status, RfqStatus::NoWinner);
        assert_eq!(no_winner.improvement_bps, Some(10));

        let cancelled = RfqProgress::new("rfq-2", rfq_request())
            .expect("new")
            .cancel(1, "c1")
            .expect("cancel");
        assert_eq!(cancelled.status, RfqStatus::Cancelled);
        assert_eq!(
            RfqProgress::new("rfq-3", rfq_request())
                .expect("new")
                .record_quoted(1, "q1")
                .expect("quoted")
                .fail_final(2, "f1")
                .expect("failed")
                .status,
            RfqStatus::FailedFinal
        );
        // A missing idempotency key fails closed.
        assert_eq!(
            RfqProgress::new("rfq-4", rfq_request())
                .expect("new")
                .record_quoted(1, "  "),
            Err(ProgressError::MissingIdempotencyKey)
        );
    }
}
