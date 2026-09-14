//! P78 composition-root integration tests over in-memory fakes.
//!
//! These exercise the real durable read model, the real (P76) reconcile identity
//! rebuild, the recording registry, the fail-closed relay-backed default port,
//! and the strict `TRADING_ENABLED` gate. Every mutation-sensitive assertion is
//! backed by an explicit call counter or a panicking/counting port.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use agent_backend::{FixedClock, MarketExecutionError, MarketExecutionOutcome};
use execution_relay::ChainHealthBreaker;
use limit_engine::RecoveryReport;
use mcp_server::{AgentBackend, BackendOutcome, McpServer};
use serde_json::json;
use trading_core::composition::{
    build_fail_closed_market_port, MarketReconcileLoop, ReconcilePassReport, ReconcileSchedule,
    RecordingAgentBackend, TradingCore, TradingCoreSeams, UnavailableOpaqueStore,
};

use support::{
    attempt, config, disabled_policy, enabled_policy, lock, market_arguments, parse, result,
    tools_call, CountingAgentBackend, CountingMarketPort, FixedOrderKeys, InMemoryOpaqueStore,
    RecordingReservationStore, ScriptedAgentBackend, StubLimitRecovery, NOW,
};

#[tokio::test]
async fn reads_are_served_while_disabled_over_the_real_store() {
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    let server = McpServer::new(
        RecordingAgentBackend::new(core.backend(), core.registry()),
        core.capabilities(),
    );
    let response = server.handle(&tools_call(1, "get_orders", json!({}))).await;
    assert_eq!(result(&parse(&response))["isError"], false);

    // Contrast: the identical read against the fail-closed store is unavailable,
    // so the success above really came from the wired durable store.
    let unavailable = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(UnavailableOpaqueStore),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    let server = McpServer::new(
        RecordingAgentBackend::new(unavailable.backend(), unavailable.registry()),
        unavailable.capabilities(),
    );
    let response = server.handle(&tools_call(2, "get_orders", json!({}))).await;
    assert_eq!(result(&parse(&response))["isError"], true);
}

#[tokio::test]
async fn disabled_denies_mutations_before_backend_or_port() {
    let port = Arc::new(CountingMarketPort::new(Vec::new()));
    let execute_calls = port.execute_calls();
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            market_execution: Some(port),
            ..TradingCoreSeams::default()
        },
    );
    let counting = Arc::new(CountingAgentBackend::new(core.backend()));
    let backend_calls = counting.execute_calls();
    let server = McpServer::new(
        RecordingAgentBackend::new(counting, core.registry()),
        core.capabilities(),
    );

    let response = server
        .handle(&tools_call(10, "execute_market_order", market_arguments()))
        .await;
    let value = parse(&response);
    assert_eq!(result(&value)["isError"], true);
    assert_eq!(result(&value)["content"][0]["text"], "TradingDisabled");
    assert_eq!(
        backend_calls.load(Ordering::SeqCst),
        0,
        "a denied mutation must never reach the backend"
    );
    assert!(core.registry().is_empty(), "no attempt may be recorded");
    assert_eq!(
        execute_calls.load(Ordering::SeqCst),
        0,
        "the market port must never execute while disabled"
    );

    // Non-vacuous: the same disabled dispatcher serves reads, so the zero counts
    // above are the denial, not a disconnected backend.
    let response = server
        .handle(&tools_call(11, "get_orders", json!({})))
        .await;
    assert_eq!(result(&parse(&response))["isError"], false);
    assert_eq!(backend_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn default_fail_closed_port_never_reserves() {
    let store = RecordingReservationStore::new();
    let reserves = store.reserve_calls();
    let port =
        build_fail_closed_market_port(enabled_policy(), store, ChainHealthBreaker::new(3, 30_000));
    let outcome = port.execute(support::dummy_request()).await;
    assert_eq!(outcome, Err(MarketExecutionError::Unavailable));
    assert_eq!(
        reserves.load(Ordering::SeqCst),
        0,
        "the fail-closed port must never claim a reservation"
    );
}

#[tokio::test]
async fn reconcile_loop_is_read_only_and_idempotent_over_real_backend() {
    let port = Arc::new(CountingMarketPort::new(vec![
        Ok(MarketExecutionOutcome::Filled {
            net_input: 10,
            net_output: 20,
        }),
        Ok(MarketExecutionOutcome::Failed),
        Ok(MarketExecutionOutcome::Unknown),
        Err(MarketExecutionError::Denied),
        Err(MarketExecutionError::Unavailable),
        // Second pass: only the two retained attempts are re-queried.
        Ok(MarketExecutionOutcome::Unknown),
        Err(MarketExecutionError::Unavailable),
    ]));
    let execute_calls = port.execute_calls();
    let reconcile_calls = port.reconcile_calls();
    let core = TradingCore::new(
        config(),
        enabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            market_execution: Some(port),
            ..TradingCoreSeams::default()
        },
    );
    let registry = core.registry();
    for amount in [1u128, 2, 3, 4, 5] {
        assert!(registry.record(attempt(amount)));
    }
    let loop_ = MarketReconcileLoop::new(
        core.backend(),
        registry.clone(),
        ReconcileSchedule::default(),
    );

    let report = loop_.reconcile_pass(NOW).await;
    assert_eq!(
        report,
        ReconcilePassReport {
            examined: 5,
            filled: 1,
            failed: 2,
            in_flight: 1,
            unavailable: 1,
        }
    );
    assert_eq!(
        execute_calls.load(Ordering::SeqCst),
        0,
        "reconcile must never call execute"
    );
    assert_eq!(reconcile_calls.load(Ordering::SeqCst), 5);
    assert_eq!(registry.len(), 2);

    let report = loop_.reconcile_pass(NOW).await;
    assert_eq!(
        report,
        ReconcilePassReport {
            examined: 2,
            filled: 0,
            failed: 0,
            in_flight: 1,
            unavailable: 1,
        }
    );
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reconcile_calls.load(Ordering::SeqCst), 7);
    assert_eq!(registry.len(), 2);
}

#[tokio::test]
async fn reconcile_identity_is_deterministic_and_amount_bound() {
    let port = Arc::new(CountingMarketPort::new(vec![
        Ok(MarketExecutionOutcome::Unknown),
        Ok(MarketExecutionOutcome::Unknown),
    ]));
    let keys = port.captured_keys();
    let core = TradingCore::new(
        config(),
        enabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            market_execution: Some(port),
            ..TradingCoreSeams::default()
        },
    );
    let registry = core.registry();
    registry.record(attempt(1));
    registry.record(attempt(2));
    let loop_ = MarketReconcileLoop::new(core.backend(), registry, ReconcileSchedule::default());

    loop_.reconcile_pass(NOW).await;
    loop_.reconcile_pass(NOW).await;

    let captured = lock(&keys).clone();
    assert_eq!(captured.len(), 4);
    assert_eq!(captured[0], captured[2], "same params -> same P76 identity");
    assert_eq!(captured[1], captured[3]);
    assert_ne!(
        captured[0], captured[1],
        "a different amount must derive a different identity"
    );
}

#[tokio::test]
async fn startup_recovery_is_gated_on_the_startup_trading_gate() {
    let recovery = Arc::new(StubLimitRecovery::new());
    let calls = recovery.calls();
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            limit_recovery: Some(recovery),
            ..TradingCoreSeams::default()
        },
    );
    assert!(core.startup_recovery(NOW).await.is_none());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "disabled path must not recover"
    );

    let core = TradingCore::new(
        config(),
        enabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    assert!(core.startup_recovery(NOW).await.is_none());

    let recovery = Arc::new(StubLimitRecovery::new());
    let calls = recovery.calls();
    let core = TradingCore::new(
        config(),
        enabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            limit_recovery: Some(recovery),
            ..TradingCoreSeams::default()
        },
    );
    let report = core
        .startup_recovery(NOW)
        .await
        .expect("recovery requested")
        .expect("recovery ok");
    assert_eq!(
        report,
        RecoveryReport {
            open: 0,
            in_flight: 0,
            reconciled: 0,
            fills_applied: 0,
            finalized: 0,
            retryable: 0,
            quarantined: 0,
            truncated: false,
            kill_switch_deferred: false,
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn composition_debug_output_is_redacted() {
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    let rendered = format!("{core:?}");
    assert!(!rendered.contains("u1"));
    assert!(!rendered.contains("w1"));

    let report = ReconcilePassReport {
        examined: 1,
        filled: 1,
        failed: 0,
        in_flight: 0,
        unavailable: 0,
    };
    assert!(format!("{report:?}").contains("examined"));
    assert_eq!(format!("{:?}", attempt(1)), "PendingMarketAttempt { .. }");
}

#[tokio::test]
async fn recording_backend_records_only_market_executes_and_forwards_valuation() {
    use agent_commands::{
        AgentChannel, AgentCommand, AmountSpec, AssetRef, ReadCommand, TradeCommand,
    };
    use chain_types::ChainId;
    use domain::TradeSide;
    use trading_core::composition::{MarketAttemptRegistry, PendingMarketAttempt};

    let inner = Arc::new(ScriptedAgentBackend::new(Some(4_242)));
    let registry = Arc::new(MarketAttemptRegistry::new());
    let recorder = RecordingAgentBackend::new(inner.clone(), registry.clone());

    let token_in = AssetRef::new(ChainId::Base, "USDC").expect("asset");
    let token_out = AssetRef::new(ChainId::Base, "TOKEN").expect("asset");
    let trade = AgentCommand::Trade(TradeCommand::ExecuteMarketOrder {
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(1_000),
        max_slippage_bps: Some(100),
        max_price_impact_bps: Some(200),
    });
    let outcome = recorder.execute(AgentChannel::Mcp, trade.clone()).await;
    assert!(matches!(outcome, BackendOutcome::Unavailable));
    assert_eq!(inner.execute_calls(), 1);
    assert_eq!(registry.len(), 1);
    assert_eq!(
        registry.pending()[0],
        PendingMarketAttempt::new(
            AgentChannel::Mcp,
            token_in,
            token_out,
            TradeSide::Buy,
            AmountSpec::TokenAtomic(1_000),
            Some(100),
            Some(200),
        )
    );
    // The trusted valuation is forwarded verbatim; dropping it would deny
    // otherwise-valid mutations.
    assert_eq!(recorder.valuation_usd_micros(&trade).await, Some(4_242));

    // A read is forwarded but never recorded.
    let read = AgentCommand::Read(ReadCommand::GetPortfolio);
    let _ = recorder.execute(AgentChannel::Telegram, read).await;
    assert_eq!(inner.execute_calls(), 2);
    assert_eq!(registry.len(), 1, "reads must not be recorded");
}
