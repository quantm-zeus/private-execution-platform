//! Additive handoff-factory tests: readiness derivation, the injected portfolio
//! seam, restart-recovery delegation, and the strict source-bound composition.
//!
//! Everything is injected and in-memory; no network, signer, or real funds.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{
    BalanceEntry, FixedClock, MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort,
    MarketExecutionRequest, PortfolioReadModel, PortfolioSummary,
};
use agent_commands::{AgentChannel, AgentCommand, ReadCommand, RouterSource};
use async_trait::async_trait;
use mcp_server::BackendOutcome;
use storage::{ComponentHealth, HealthProbe};
use support::{
    config, disabled_policy, dummy_request, enabled_policy, FixedOrderKeys, InMemoryOpaqueStore,
};
use trading_core::capability::CapabilityReadiness;
use trading_core::composition::{
    build_trading_core, compose_source_bound_market_execution, TradingCoreSeams,
    TradingReadinessProbes,
};

fn probe(component: &'static str) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Healthy,
        observed_at_ms: 1_000,
    }
}

fn unhealthy(component: &'static str) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Unavailable,
        observed_at_ms: 1_000,
    }
}

/// Fully healthy probes for every dependency.
fn all_healthy() -> TradingReadinessProbes {
    TradingReadinessProbes::none()
        .with_market(probe("market"))
        .with_limit(probe("limit"))
        .with_realtime(probe("realtime"))
        .with_durable_store(probe("store"))
        .with_chain(probe("chain"))
        .with_signer(probe("signer"))
}

/// Injected portfolio projection with one fixed balance.
struct FakePortfolio {
    calls: AtomicUsize,
}

#[async_trait]
impl PortfolioReadModel for FakePortfolio {
    async fn portfolio(&self) -> Result<PortfolioSummary, agent_backend::BackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PortfolioSummary {
            balances: vec![BalanceEntry {
                asset: support::asset_id("USDC"),
                amount: market_types::AtomicAmount::new(42),
            }],
            open_orders: 1,
            filled_orders: 2,
            total_orders: 3,
        })
    }
}

/// Port that counts calls and answers `execute` with a fixed outcome.
struct ScriptedPort {
    executes: AtomicUsize,
    outcome: MarketExecutionOutcome,
}

impl ScriptedPort {
    fn new(outcome: MarketExecutionOutcome) -> Arc<Self> {
        Arc::new(Self {
            executes: AtomicUsize::new(0),
            outcome,
        })
    }

    fn executes(&self) -> usize {
        self.executes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MarketExecutionPort for ScriptedPort {
    async fn execute(
        &self,
        _request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.executes.fetch_add(1, Ordering::SeqCst);
        Ok(self.outcome)
    }
}

fn store() -> Arc<InMemoryOpaqueStore> {
    Arc::new(InMemoryOpaqueStore::new())
}

fn keys() -> Arc<FixedOrderKeys> {
    Arc::new(FixedOrderKeys)
}

fn clock() -> Arc<FixedClock> {
    Arc::new(FixedClock(support::NOW))
}

#[test]
fn readiness_requires_every_probe_and_the_live_gate() {
    assert!(all_healthy().readiness(true).execute());
    assert!(!all_healthy().readiness(false).execute());
    // Any single unhealthy execution dependency removes execution capability.
    for (label, probes) in [
        (
            "store",
            all_healthy().with_durable_store(unhealthy("store")),
        ),
        ("chain", all_healthy().with_chain(unhealthy("chain"))),
        ("signer", all_healthy().with_signer(unhealthy("signer"))),
        (
            "missing-store",
            TradingReadinessProbes::none()
                .with_market(probe("market"))
                .with_limit(probe("limit"))
                .with_realtime(probe("realtime"))
                .with_chain(probe("chain"))
                .with_signer(probe("signer")),
        ),
        (
            "missing-chain",
            TradingReadinessProbes::none()
                .with_market(probe("market"))
                .with_limit(probe("limit"))
                .with_realtime(probe("realtime"))
                .with_durable_store(probe("store"))
                .with_signer(probe("signer")),
        ),
    ] {
        assert!(!probes.readiness(true).execute(), "{label}");
    }
    // Read capabilities follow their own probes independently.
    let partial = all_healthy()
        .with_market(unhealthy("market"))
        .with_limit(unhealthy("limit"))
        .with_realtime(unhealthy("realtime"));
    let readiness = partial.readiness(true);
    assert!(!readiness.market());
    assert!(!readiness.limits());
    assert!(!readiness.realtime());
    assert!(readiness.execute());
    assert_eq!(
        TradingReadinessProbes::none().readiness(true),
        CapabilityReadiness::deny_all()
    );
}

#[test]
fn handoff_bundles_backend_capabilities_and_readiness() {
    let handoff = build_trading_core(
        config(),
        enabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams::default(),
        all_healthy(),
    );
    assert!(handoff.capabilities().trading_enabled);
    assert!(handoff.readiness().execute());
    assert!(handoff.trading_enabled_at_startup());
    assert!(!format!("{handoff:?}").contains("owner"));
}

#[tokio::test]
async fn default_composition_serves_no_portfolio() {
    let handoff = build_trading_core(
        config(),
        enabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams::default(),
        all_healthy(),
    );
    let outcome = handoff
        .agent_backend()
        .execute(
            AgentChannel::Web,
            AgentCommand::Read(ReadCommand::GetPortfolio),
        )
        .await;
    assert_eq!(outcome, BackendOutcome::Unavailable);
}

#[tokio::test]
async fn injected_portfolio_is_served_by_the_composed_backend() {
    let portfolio = Arc::new(FakePortfolio {
        calls: AtomicUsize::new(0),
    });
    let handoff = build_trading_core(
        config(),
        enabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams {
            portfolio: Some(portfolio.clone()),
            ..TradingCoreSeams::default()
        },
        all_healthy(),
    );
    let outcome = handoff
        .agent_backend()
        .execute(
            AgentChannel::Web,
            AgentCommand::Read(ReadCommand::GetPortfolio),
        )
        .await;
    match outcome {
        BackendOutcome::Value(value) => {
            assert_eq!(value["portfolio"]["open_orders"], 1);
            assert_eq!(value["portfolio"]["filled_orders"], 2);
            assert_eq!(value["portfolio"]["total_orders"], 3);
        }
        other => panic!("expected a portfolio value, got {other:?}"),
    }
    assert_eq!(portfolio.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disabled_gate_is_reflected_in_capabilities_and_readiness_but_reads_still_work() {
    let portfolio = Arc::new(FakePortfolio {
        calls: AtomicUsize::new(0),
    });
    let handoff = build_trading_core(
        config(),
        disabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams {
            portfolio: Some(portfolio),
            ..TradingCoreSeams::default()
        },
        all_healthy(),
    );
    assert!(!handoff.capabilities().trading_enabled);
    assert!(!handoff.readiness().execute());
    assert!(!handoff.trading_enabled_at_startup());

    // Reads remain available while mutations are gated off.
    let outcome = handoff
        .agent_backend()
        .execute(
            AgentChannel::Web,
            AgentCommand::Read(ReadCommand::GetPortfolio),
        )
        .await;
    assert!(matches!(outcome, BackendOutcome::Value(_)));
}

#[tokio::test]
async fn source_bound_composition_never_falls_back_to_local() {
    let local = ScriptedPort::new(MarketExecutionOutcome::Submitted);

    // No provider: OKX is a final denial and the local port is untouched.
    let no_provider = compose_source_bound_market_execution(local.clone(), None);
    let mut okx_request = dummy_request();
    okx_request.router_source = RouterSource::Okx;
    assert_eq!(
        no_provider.execute(okx_request).await,
        Err(MarketExecutionError::Denied)
    );
    assert_eq!(local.executes(), 0);

    // With a provider: OKX reaches only the provider.
    let okx = ScriptedPort::new(MarketExecutionOutcome::Filled {
        net_input: 1,
        net_output: 2,
    });
    let bound = compose_source_bound_market_execution(local.clone(), Some(okx.clone()));
    let mut okx_request = dummy_request();
    okx_request.router_source = RouterSource::Okx;
    assert_eq!(
        bound.execute(okx_request).await,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1,
            net_output: 2,
        })
    );
    assert_eq!(okx.executes(), 1);
    assert_eq!(local.executes(), 0);

    // Local still reaches only the local port.
    assert_eq!(
        bound.execute(dummy_request()).await,
        Ok(MarketExecutionOutcome::Submitted)
    );
    assert_eq!(local.executes(), 1);
}

#[tokio::test]
async fn startup_recovery_is_delegated_and_gated_on_the_startup_gate() {
    let recovery = Arc::new(support::StubLimitRecovery::default());
    let enabled = build_trading_core(
        config(),
        enabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams {
            limit_recovery: Some(recovery.clone()),
            ..TradingCoreSeams::default()
        },
        all_healthy(),
    );
    assert!(enabled.startup_recovery(support::NOW).await.is_some());

    let disabled = build_trading_core(
        config(),
        disabled_policy(),
        store(),
        keys(),
        clock(),
        TradingCoreSeams {
            limit_recovery: Some(recovery),
            ..TradingCoreSeams::default()
        },
        all_healthy(),
    );
    assert!(disabled.startup_recovery(support::NOW).await.is_none());
}
