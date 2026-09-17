//! P84D tests for the strictly source-bound market-execution facade.
//!
//! Pure and deterministic: two scripted ports, no network, signer, chain, or
//! real funds. The tests pin the two invariants the Market tab depends on:
//!
//! 1. A request reaches exactly the port for its declared `RouterSource`; an OKX
//!    request with no configured OKX port is a final denial and never falls back
//!    to the local router.
//! 2. Reconciliation is read-only and returns the most definitive observation
//!    across configured sources.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
};
use agent_commands::RouterSource;
use async_trait::async_trait;
use execution_relay::AttemptBinding;
use market_execution::SourceBoundMarketExecutionPort;
use support::{intent, request_with};

/// Port that counts execute calls and replays a fixed outcome for each verb.
struct ScriptedPort {
    executes: AtomicUsize,
    reconciles: AtomicUsize,
    execute_outcome: Result<MarketExecutionOutcome, MarketExecutionError>,
    reconcile_outcome: Result<MarketExecutionOutcome, MarketExecutionError>,
}

impl ScriptedPort {
    fn executing(outcome: MarketExecutionOutcome) -> Arc<Self> {
        Arc::new(Self {
            executes: AtomicUsize::new(0),
            reconciles: AtomicUsize::new(0),
            execute_outcome: Ok(outcome),
            reconcile_outcome: Ok(MarketExecutionOutcome::Unknown),
        })
    }

    fn reconciling(outcome: Result<MarketExecutionOutcome, MarketExecutionError>) -> Arc<Self> {
        Arc::new(Self {
            executes: AtomicUsize::new(0),
            reconciles: AtomicUsize::new(0),
            execute_outcome: Ok(MarketExecutionOutcome::Unknown),
            reconcile_outcome: outcome,
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
        self.execute_outcome
    }

    async fn reconcile(
        &self,
        _binding: &AttemptBinding,
        _now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        self.reconcile_outcome
    }
}

fn request(router_source: RouterSource) -> MarketExecutionRequest {
    let mut request = request_with(240, 240, 100);
    request.router_source = router_source;
    request
}

fn binding() -> AttemptBinding {
    AttemptBinding::from_intent(&intent())
}

#[tokio::test]
async fn local_request_reaches_only_the_local_port() {
    let local = ScriptedPort::executing(MarketExecutionOutcome::Submitted);
    let okx = ScriptedPort::executing(MarketExecutionOutcome::Filled {
        net_input: 1,
        net_output: 2,
    });
    let port = SourceBoundMarketExecutionPort::new(local.clone()).with_okx(okx.clone());

    assert_eq!(
        port.execute(request(RouterSource::Local)).await,
        Ok(MarketExecutionOutcome::Submitted)
    );
    assert_eq!(local.executes(), 1);
    assert_eq!(okx.executes(), 0, "OKX port must not see a Local request");
}

#[tokio::test]
async fn okx_request_reaches_only_the_okx_port() {
    let local = ScriptedPort::executing(MarketExecutionOutcome::Submitted);
    let okx = ScriptedPort::executing(MarketExecutionOutcome::Filled {
        net_input: 1,
        net_output: 2,
    });
    let port = SourceBoundMarketExecutionPort::new(local.clone()).with_okx(okx.clone());

    assert_eq!(
        port.execute(request(RouterSource::Okx)).await,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1,
            net_output: 2,
        })
    );
    assert_eq!(okx.executes(), 1);
    assert_eq!(
        local.executes(),
        0,
        "local port must not see an OKX request"
    );
}

#[tokio::test]
async fn okx_without_a_configured_source_is_a_final_denial() {
    let local = ScriptedPort::executing(MarketExecutionOutcome::Submitted);
    let port = SourceBoundMarketExecutionPort::new(local.clone());
    assert!(!port.okx_configured());
    assert_eq!(
        port.execute(request(RouterSource::Okx)).await,
        Err(MarketExecutionError::Denied)
    );
    assert_eq!(
        local.executes(),
        0,
        "no silent fallback to the local router"
    );
}

#[tokio::test]
async fn reconcile_returns_the_most_definitive_observation() {
    let local = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Unknown));
    let okx = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Filled {
        net_input: 3,
        net_output: 4,
    }));
    let port = SourceBoundMarketExecutionPort::new(local).with_okx(okx);
    assert_eq!(
        port.reconcile(&binding(), 1).await,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 3,
            net_output: 4,
        })
    );

    // A definitive local failure outranks an OKX in-flight submission.
    let local = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Failed));
    let okx = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Submitted));
    let port = SourceBoundMarketExecutionPort::new(local).with_okx(okx);
    assert_eq!(
        port.reconcile(&binding(), 1).await,
        Ok(MarketExecutionOutcome::Failed)
    );
}

#[tokio::test]
async fn reconcile_tolerates_a_single_source_outage_when_another_observes() {
    let local = ScriptedPort::reconciling(Err(MarketExecutionError::Unavailable));
    let okx = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Submitted));
    let port = SourceBoundMarketExecutionPort::new(local).with_okx(okx);
    assert_eq!(
        port.reconcile(&binding(), 1).await,
        Ok(MarketExecutionOutcome::Submitted)
    );
}

#[tokio::test]
async fn reconcile_surfaces_the_first_error_only_when_no_source_observes() {
    let local = ScriptedPort::reconciling(Err(MarketExecutionError::Unavailable));
    let port = SourceBoundMarketExecutionPort::new(local);
    assert_eq!(
        port.reconcile(&binding(), 1).await,
        Err(MarketExecutionError::Unavailable)
    );
}

#[tokio::test]
async fn reconcile_for_queries_only_the_owning_source() {
    // The local port reports Failed; the OKX port reports Submitted. An OKX
    // binding must never see the local (misleading) failure.
    let local = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Failed));
    let okx = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Submitted));
    let port = SourceBoundMarketExecutionPort::new(local.clone()).with_okx(okx.clone());

    assert_eq!(
        port.reconcile_for(RouterSource::Okx, &binding(), 1).await,
        Ok(MarketExecutionOutcome::Submitted)
    );
    assert_eq!(okx.reconciles.load(Ordering::SeqCst), 1);
    assert_eq!(
        local.reconciles.load(Ordering::SeqCst),
        0,
        "the local source must not be consulted for an OKX binding"
    );

    assert_eq!(
        port.reconcile_for(RouterSource::Local, &binding(), 1).await,
        Ok(MarketExecutionOutcome::Failed)
    );
    assert_eq!(local.reconciles.load(Ordering::SeqCst), 1);
    assert_eq!(okx.reconciles.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconcile_for_an_okx_binding_without_a_provider_stays_unknown() {
    let local = ScriptedPort::reconciling(Ok(MarketExecutionOutcome::Failed));
    let port = SourceBoundMarketExecutionPort::new(local.clone());
    assert_eq!(
        port.reconcile_for(RouterSource::Okx, &binding(), 1).await,
        Ok(MarketExecutionOutcome::Unknown)
    );
    assert_eq!(
        local.reconciles.load(Ordering::SeqCst),
        0,
        "an OKX binding must not fall through to the local source"
    );
}

#[test]
fn debug_reports_only_the_source_configuration() {
    let local = ScriptedPort::executing(MarketExecutionOutcome::Unknown);
    let with_okx = SourceBoundMarketExecutionPort::new(local.clone())
        .with_okx(ScriptedPort::executing(MarketExecutionOutcome::Unknown));
    assert_eq!(
        format!("{with_okx:?}"),
        "SourceBoundMarketExecutionPort { okx_configured: true, .. }"
    );
    let local_only = SourceBoundMarketExecutionPort::new(local);
    assert_eq!(
        format!("{local_only:?}"),
        "SourceBoundMarketExecutionPort { okx_configured: false, .. }"
    );
}
