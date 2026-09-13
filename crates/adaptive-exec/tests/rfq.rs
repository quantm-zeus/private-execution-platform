//! P62: RFQ solver competition — validation, ranking, best-execution gating.

use adaptive_exec::{
    CompetitionOutcome, NoWinnerReason, RfqRequest, RfqSide, Solver, SolverCompetition,
    SolverError, SolverQuoteResult,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use market_types::{AssetAmount, AtomicAmount};

struct FakeSolver {
    id: String,
    result: Result<SolverQuoteResult, SolverError>,
}

#[async_trait]
impl Solver for FakeSolver {
    fn id(&self) -> &str {
        &self.id
    }

    async fn quote(&self, _request: &RfqRequest) -> Result<SolverQuoteResult, SolverError> {
        self.result.clone()
    }
}

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn request(side: RfqSide, min_improvement_bps: u16) -> RfqRequest {
    RfqRequest {
        chain: ChainId::Base,
        token_in: asset("USDC"),
        token_out: asset("TOKEN"),
        side,
        input_amount: AtomicAmount::new(1_000),
        deadline_ms: 10_000,
        min_improvement_bps,
    }
}

fn baseline(asset_name: &str, amount: u128) -> AssetAmount {
    AssetAmount {
        asset: asset(asset_name),
        amount: AtomicAmount::new(amount),
    }
}

fn quote(asset_name: &str, amount: u128, valid_until_ms: i64) -> SolverQuoteResult {
    SolverQuoteResult {
        settled_output: AssetAmount {
            asset: asset(asset_name),
            amount: AtomicAmount::new(amount),
        },
        valid_until_ms,
    }
}

fn ok(id: &str, asset_name: &str, amount: u128, valid_until_ms: i64) -> Box<dyn Solver> {
    Box::new(FakeSolver {
        id: id.to_string(),
        result: Ok(quote(asset_name, amount, valid_until_ms)),
    })
}

fn failing(id: &str) -> Box<dyn Solver> {
    Box::new(FakeSolver {
        id: id.to_string(),
        result: Err(SolverError::Unavailable),
    })
}

async fn run(
    solvers: &[Box<dyn Solver>],
    request: &RfqRequest,
    baseline: &AssetAmount,
    now_ms: i64,
) -> CompetitionOutcome {
    let refs: Vec<&dyn Solver> = solvers.iter().map(|solver| solver.as_ref()).collect();
    SolverCompetition::new(&refs)
        .run(request, baseline, now_ms)
        .await
}

#[tokio::test]
async fn the_highest_valid_quote_wins_with_a_runner_up() {
    let solvers = vec![
        ok("alpha", "TOKEN", 100, 10_000),
        ok("beta", "TOKEN", 250, 10_000),
        ok("gamma", "TOKEN", 200, 10_000),
    ];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::Winner {
            winner,
            runner_up,
            improvement_bps,
        } => {
            assert_eq!(winner.solver_id, "beta");
            assert_eq!(winner.settled_output.amount.get(), 250);
            assert_eq!(runner_up.expect("runner up").solver_id, "gamma");
            // (250 - 200) / 200 = 2500 bps.
            assert_eq!(improvement_bps, 2_500);
        }
        other => panic!("expected a winner, got {other:?}"),
    }
}

#[tokio::test]
async fn expired_and_failing_solvers_are_skipped() {
    let solvers = vec![
        ok("expired", "TOKEN", 10_000, 5),
        failing("broken"),
        ok("valid", "TOKEN", 150, 10_000),
    ];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 100),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::Winner { winner, .. } => assert_eq!(winner.solver_id, "valid"),
        other => panic!("expected a winner, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_asset_or_zero_quotes_are_not_usable() {
    let solvers = vec![
        ok("wrong", "OTHER", 900, 10_000),
        ok("zero", "TOKEN", 0, 10_000),
    ];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 100),
        1_000,
    )
    .await;
    assert_eq!(
        outcome,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::NoQuotes,
            best_quote: None,
            improvement_bps: None,
        }
    );
}

#[tokio::test]
async fn an_all_expired_field_reports_expiry() {
    let solvers = vec![ok("a", "TOKEN", 900, 0), ok("b", "TOKEN", 950, 0)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 100),
        1_000,
    )
    .await;
    assert_eq!(
        outcome,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::AllExpired,
            best_quote: None,
            improvement_bps: None,
        }
    );
}

#[tokio::test]
async fn a_quote_below_the_required_margin_is_rejected() {
    let solvers = vec![ok("a", "TOKEN", 201, 10_000)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 100),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::NoWinner {
            reason,
            best_quote,
            improvement_bps,
        } => {
            assert_eq!(reason, NoWinnerReason::BelowBaseline);
            assert_eq!(best_quote.expect("best quote").solver_id, "a");
            assert_eq!(improvement_bps, Some(50));
        }
        other => panic!("expected no winner, got {other:?}"),
    }
}

#[tokio::test]
async fn exactly_at_the_required_margin_is_accepted() {
    let solvers = vec![ok("a", "TOKEN", 201, 10_000)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 50),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::Winner {
            winner,
            improvement_bps,
            ..
        } => {
            assert_eq!(winner.solver_id, "a");
            assert_eq!(improvement_bps, 50);
        }
        other => panic!("expected a winner, got {other:?}"),
    }
}

#[tokio::test]
async fn an_exact_tie_breaks_deterministically_by_solver_id() {
    let solvers = vec![
        ok("beta", "TOKEN", 250, 10_000),
        ok("alpha", "TOKEN", 250, 10_000),
    ];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::Winner {
            winner, runner_up, ..
        } => {
            assert_eq!(winner.solver_id, "alpha");
            assert_eq!(runner_up.expect("runner up").solver_id, "beta");
        }
        other => panic!("expected a winner, got {other:?}"),
    }
}

#[tokio::test]
async fn an_expired_request_and_a_mismatched_baseline_are_rejected() {
    let solvers = vec![ok("a", "TOKEN", 250, 10_000)];
    let expired = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 200),
        10_001,
    )
    .await;
    assert_eq!(
        expired,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::RequestExpired,
            best_quote: None,
            improvement_bps: None,
        }
    );

    let invalid = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("USDC", 200),
        1_000,
    )
    .await;
    assert_eq!(
        invalid,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::InvalidBaseline,
            best_quote: None,
            improvement_bps: None,
        }
    );
}

#[tokio::test]
async fn the_settled_output_is_token_out_for_both_sides() {
    // `token_in` is always the spent asset, so a quote in token_in (USDC) is
    // invalid for both a Buy and a Sell.
    for side in [RfqSide::Buy, RfqSide::Sell] {
        let solvers = vec![
            ok("wrong", "USDC", 900, 10_000),
            ok("right", "TOKEN", 120, 10_000),
        ];
        let outcome = run(&solvers, &request(side, 0), &baseline("TOKEN", 100), 1_000).await;
        match outcome {
            CompetitionOutcome::Winner { winner, .. } => {
                assert_eq!(winner.solver_id, "right");
                assert_eq!(winner.settled_output.asset, asset("TOKEN"));
            }
            other => panic!("expected a winner for {side:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_validity_and_deadline_boundaries_are_inclusive() {
    // valid_until_ms == now_ms is accepted; deadline == now_ms is open.
    let solvers = vec![ok("a", "TOKEN", 250, 1_000)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    assert!(matches!(outcome, CompetitionOutcome::Winner { .. }));

    // One millisecond later the request has closed.
    let expired = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 200),
        10_001,
    )
    .await;
    assert_eq!(
        expired,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::RequestExpired,
            best_quote: None,
            improvement_bps: None,
        }
    );
}

#[tokio::test]
async fn improvement_saturates_and_a_margin_above_10000_is_honored() {
    // A nonzero baseline with an enormous winner saturates the reported
    // improvement without panicking; the exact cross-multiply overflows, so the
    // result is fail-closed `Arithmetic` (the improvement is still reported).
    let solvers = vec![ok("a", "TOKEN", u128::MAX, 10_000)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 1),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::NoWinner {
            reason,
            improvement_bps,
            ..
        } => {
            assert_eq!(reason, NoWinnerReason::Arithmetic);
            assert_eq!(improvement_bps, Some(u16::MAX));
        }
        other => panic!("expected arithmetic no-winner, got {other:?}"),
    }

    // A margin above 100% requires a quote that more than doubles the baseline.
    let below_solvers = vec![ok("a", "TOKEN", 250, 10_000)];
    let below = run(
        &below_solvers,
        &request(RfqSide::Buy, 20_000),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    assert!(matches!(
        below,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::BelowBaseline,
            ..
        }
    ));
    let above_solvers = vec![ok("a", "TOKEN", 700, 10_000)];
    let above = run(
        &above_solvers,
        &request(RfqSide::Buy, 20_000),
        &baseline("TOKEN", 200),
        1_000,
    )
    .await;
    assert!(matches!(above, CompetitionOutcome::Winner { .. }));
}

#[tokio::test]
async fn a_zero_baseline_accepts_any_positive_quote() {
    let solvers = vec![ok("a", "TOKEN", 1, 10_000)];
    let outcome = run(
        &solvers,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", 0),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::Winner {
            improvement_bps, ..
        } => assert_eq!(improvement_bps, u16::MAX),
        other => panic!("expected a winner, got {other:?}"),
    }
}

#[tokio::test]
async fn no_solvers_and_overflow_are_handled() {
    let none: Vec<Box<dyn Solver>> = Vec::new();
    assert_eq!(
        run(
            &none,
            &request(RfqSide::Buy, 0),
            &baseline("TOKEN", 100),
            1_000
        )
        .await,
        CompetitionOutcome::NoWinner {
            reason: NoWinnerReason::NoQuotes,
            best_quote: None,
            improvement_bps: None,
        }
    );

    let huge = vec![ok("a", "TOKEN", u128::MAX, 10_000)];
    let outcome = run(
        &huge,
        &request(RfqSide::Buy, 0),
        &baseline("TOKEN", u128::MAX),
        1_000,
    )
    .await;
    match outcome {
        CompetitionOutcome::NoWinner { reason, .. } => {
            assert_eq!(reason, NoWinnerReason::Arithmetic)
        }
        other => panic!("expected arithmetic no-winner, got {other:?}"),
    }
}
