//! Solver competition / RFQ: rank independent solver quotes against the local
//! route and pick a winner only when it beats the route by a required margin.
//!
//! The core is deterministic and pure apart from awaiting the injected
//! [`Solver`]s; it never signs, submits, or performs I/O. A caller may wrap each
//! solver with a timeout or drive them concurrently, but scoring and selection
//! are centralized here so every caller applies the same best-execution rule.

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use market_types::{AssetAmount, AtomicAmount};

/// Direction of an RFQ request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfqSide {
    /// Spend `token_in` to receive `token_out`.
    Buy,
    /// Spend `token_in` (the held token) to receive `token_out` (the quote asset).
    Sell,
}

/// One RFQ request for a bounded input amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqRequest {
    /// Chain the request is bound to.
    pub chain: ChainId,
    /// Asset spent.
    pub token_in: AssetId,
    /// Asset received.
    pub token_out: AssetId,
    /// Direction.
    pub side: RfqSide,
    /// Input amount.
    pub input_amount: AtomicAmount,
    /// Request deadline; solvers must quote before it.
    pub deadline_ms: i64,
    /// Minimum improvement over the local baseline, in bps, required to accept
    /// an external solver.
    pub min_improvement_bps: u16,
}

impl RfqRequest {
    /// The asset the user receives.
    pub fn output_asset(&self) -> AssetId {
        match self.side {
            RfqSide::Buy => self.token_out.clone(),
            RfqSide::Sell => self.token_in.clone(),
        }
    }

    /// Whether the request is still open at `now_ms` (inclusive).
    pub fn is_open(&self, now_ms: i64) -> bool {
        now_ms <= self.deadline_ms
    }
}

/// A redacted solver failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SolverError {
    /// The solver is unavailable.
    #[error("solver unavailable")]
    Unavailable,
    /// The solver refused the request.
    #[error("solver rejected the request")]
    Rejected,
    /// The solver returned an unusable response.
    #[error("solver returned a malformed response")]
    Malformed,
}

/// The payload a solver returns; the competition stamps the solver id itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverQuoteResult {
    /// Net output the solver guarantees (already net of the solver's costs).
    pub settled_output: AssetAmount,
    /// The quote expires at this time.
    pub valid_until_ms: i64,
}

/// Injected RFQ solver / private market maker.
///
/// A production implementation talks to an external solver behind a bounded
/// transport; this crate ships none.
#[async_trait]
pub trait Solver: Send + Sync {
    /// Stable solver identity, used only for the deterministic tie-break.
    fn id(&self) -> &str;

    /// Returns a quote for `request`, or a redacted failure.
    async fn quote(&self, request: &RfqRequest) -> Result<SolverQuoteResult, SolverError>;
}

/// A validated, ranked solver quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverQuote {
    /// Solver identity (stamped by the competition).
    pub solver_id: String,
    /// Net output the solver guarantees.
    pub settled_output: AssetAmount,
    /// Expiry.
    pub valid_until_ms: i64,
}

/// Why no external solver was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoWinnerReason {
    /// The request deadline had already passed.
    RequestExpired,
    /// No solver returned a usable quote.
    NoQuotes,
    /// Quotes were returned but every one had expired.
    AllExpired,
    /// The local baseline's asset did not match the request's output asset.
    InvalidBaseline,
    /// The best quote did not beat the baseline by the required margin.
    BelowBaseline,
    /// Exact-arithmetic overflow while comparing (treated as no improvement).
    Arithmetic,
}

/// Result of one competition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompetitionOutcome {
    /// A solver beat the baseline by the required margin.
    Winner {
        /// The winning quote.
        winner: SolverQuote,
        /// The next-best valid quote, if any.
        runner_up: Option<SolverQuote>,
        /// Realized improvement over the baseline, in bps (floored, saturated).
        improvement_bps: u16,
    },
    /// No solver was accepted; the caller should use the local route.
    NoWinner {
        /// Why no winner was chosen.
        reason: NoWinnerReason,
        /// The best valid quote, when one existed (for observability).
        best_quote: Option<SolverQuote>,
        /// Improvement of the best quote over the baseline, when computable.
        improvement_bps: Option<u16>,
    },
}

/// Deterministic solver competition over the injected solvers.
pub struct SolverCompetition<'a> {
    solvers: &'a [&'a dyn Solver],
}

impl<'a> SolverCompetition<'a> {
    /// Builds a competition over `solvers`.
    pub fn new(solvers: &'a [&'a dyn Solver]) -> Self {
        Self { solvers }
    }

    /// Queries every solver, validates and ranks the quotes, and accepts the
    /// best quote only when it beats `baseline` by
    /// [`RfqRequest::min_improvement_bps`].
    pub async fn run(
        &self,
        request: &RfqRequest,
        baseline: &AssetAmount,
        now_ms: i64,
    ) -> CompetitionOutcome {
        if !request.is_open(now_ms) {
            return CompetitionOutcome::NoWinner {
                reason: NoWinnerReason::RequestExpired,
                best_quote: None,
                improvement_bps: None,
            };
        }
        let output_asset = request.output_asset();
        if baseline.asset != output_asset {
            return CompetitionOutcome::NoWinner {
                reason: NoWinnerReason::InvalidBaseline,
                best_quote: None,
                improvement_bps: None,
            };
        }

        let mut valid: Vec<SolverQuote> = Vec::new();
        let mut saw_expired = false;
        for solver in self.solvers {
            let Ok(result) = solver.quote(request).await else {
                continue;
            };
            // Contract checks: right asset and positive size. A contract
            // violation is not a usable quote.
            if result.settled_output.asset != output_asset
                || result.settled_output.amount.get() == 0
            {
                continue;
            }
            if result.valid_until_ms < now_ms {
                saw_expired = true;
                continue;
            }
            valid.push(SolverQuote {
                solver_id: solver.id().to_string(),
                settled_output: result.settled_output,
                valid_until_ms: result.valid_until_ms,
            });
        }

        if valid.is_empty() {
            return CompetitionOutcome::NoWinner {
                reason: if saw_expired {
                    NoWinnerReason::AllExpired
                } else {
                    NoWinnerReason::NoQuotes
                },
                best_quote: None,
                improvement_bps: None,
            };
        }

        // Highest net output wins; an exact tie breaks deterministically on the
        // solver id so the result does not depend on query order.
        valid.sort_by(|left, right| {
            right
                .settled_output
                .amount
                .get()
                .cmp(&left.settled_output.amount.get())
                .then_with(|| left.solver_id.cmp(&right.solver_id))
        });
        let best = valid[0].clone();
        let runner_up = valid.get(1).cloned();
        let best_amount = best.settled_output.amount.get();
        let baseline_amount = baseline.amount.get();

        let improvement_bps = improvement_bps(best_amount, baseline_amount);

        // Exact best-execution rule: best * 10_000 >= baseline * (10_000 + min_bps).
        let required = 10_000u128.saturating_add(request.min_improvement_bps as u128);
        let accepted = match (
            best_amount.checked_mul(10_000),
            baseline_amount.checked_mul(required),
        ) {
            (Some(left), Some(right)) => left >= right,
            _ => {
                return CompetitionOutcome::NoWinner {
                    reason: NoWinnerReason::Arithmetic,
                    best_quote: Some(best),
                    improvement_bps: Some(improvement_bps),
                }
            }
        };

        if accepted {
            CompetitionOutcome::Winner {
                winner: best,
                runner_up,
                improvement_bps,
            }
        } else {
            CompetitionOutcome::NoWinner {
                reason: NoWinnerReason::BelowBaseline,
                best_quote: Some(best),
                improvement_bps: Some(improvement_bps),
            }
        }
    }
}

/// Floored improvement of `winner` over `baseline` in bps, saturated at `u16`.
fn improvement_bps(winner: u128, baseline: u128) -> u16 {
    if winner <= baseline {
        return 0;
    }
    if baseline == 0 {
        return u16::MAX;
    }
    let delta = winner - baseline;
    let bps = delta.saturating_mul(10_000) / baseline;
    bps.min(u16::MAX as u128) as u16
}
