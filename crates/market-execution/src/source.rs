//! Strict, source-bound market-execution facade.
//!
//! The Market tab has exactly two routing sources: the local router
//! (`RouterSource::Local`) and the OKX provider (`RouterSource::Okx`, the
//! default). Each concrete [`MarketExecutionPort`] implementation serves exactly
//! one source and denies the other:
//!
//! - [`crate::RelayMarketExecutionPort`] serves `Local` and denies `Okx`.
//! - [`crate::VerifiedProviderExecutionPort`] serves `Okx` and denies `Local`.
//!
//! This module composes the two into one [`MarketExecutionPort`] so a composition
//! root can install a single port. The dispatch is a strict `match` on the
//! request's `router_source`:
//!
//! - `Local` always reaches the local port (it is mandatory).
//! - `Okx` reaches the verified provider port **only when one was explicitly
//!   installed**; otherwise it is a final [`MarketExecutionError::Denied`].
//!
//! There is deliberately **no fallback arm**: an OKX request can never be served
//! by the local router, a Local request can never be served by the provider, and a
//! missing/denied source is a final denial rather than a silent re-route. This is
//! the composition-level counterpart of the per-port source checks and is what
//! makes "OKX default when configured, Local explicit alternate, never silent
//! fallback" true for the executed path.
//!
//! Reconciliation is read-only and source-agnostic: [`MarketExecutionPort::reconcile`]
//! carries only the durable attempt binding (which does not name the source), so
//! the facade queries every configured port and returns the most definitive
//! observation (`Filled` > `Failed` > `Submitted` > `Unknown`). It never signs,
//! submits, or advances a reservation.

use std::fmt;
use std::sync::Arc;

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
    RouterSource,
};
use async_trait::async_trait;
use execution_relay::AttemptBinding;

/// Composes the local and OKX execution ports behind one strictly source-bound
/// port.
///
/// `Debug` is redacted: whether each source is configured is reported, never the
/// underlying ports or any payload-derived value.
pub struct SourceBoundMarketExecutionPort {
    local: Arc<dyn MarketExecutionPort>,
    okx: Option<Arc<dyn MarketExecutionPort>>,
}

impl SourceBoundMarketExecutionPort {
    /// Wires the mandatory local port. Until [`Self::with_okx`] installs one, an
    /// OKX request is a final denial.
    pub fn new(local: Arc<dyn MarketExecutionPort>) -> Self {
        Self { local, okx: None }
    }

    /// Installs the verified OKX provider port.
    ///
    /// The port is expected to be a [`crate::VerifiedProviderExecutionPort`];
    /// installed or not, it only ever receives `RouterSource::Okx` requests.
    pub fn with_okx(mut self, okx: Arc<dyn MarketExecutionPort>) -> Self {
        self.okx = Some(okx);
        self
    }

    /// Whether a verified OKX provider port is configured.
    pub fn okx_configured(&self) -> bool {
        self.okx.is_some()
    }
}

impl fmt::Debug for SourceBoundMarketExecutionPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceBoundMarketExecutionPort")
            .field("okx_configured", &self.okx.is_some())
            .finish_non_exhaustive()
    }
}

/// Ranks outcomes by definitiveness for source-agnostic reconciliation.
///
/// Higher is more definitive. `Unknown` is the absence of an observation, so any
/// concrete observation outranks it.
fn rank(outcome: MarketExecutionOutcome) -> u8 {
    match outcome {
        MarketExecutionOutcome::Unknown => 0,
        MarketExecutionOutcome::Submitted => 1,
        MarketExecutionOutcome::Failed => 2,
        MarketExecutionOutcome::Filled { .. } => 3,
    }
}

#[async_trait]
impl MarketExecutionPort for SourceBoundMarketExecutionPort {
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        match request.router_source {
            // The local router is a mandatory dependency installed at
            // construction. The relay port re-checks the source itself.
            RouterSource::Local => self.local.execute(request).await,
            // No fallback: an unconfigured OKX source is a final denial, and a
            // configured one must be the verified provider port.
            RouterSource::Okx => match self.okx.as_ref() {
                Some(okx) => okx.execute(request).await,
                None => Err(MarketExecutionError::Denied),
            },
        }
    }

    /// Reconciles the attempt against every configured source and returns the
    /// most definitive observation.
    ///
    /// This source-agnostic form is read-only: it never signs or submits. It is a
    /// fallback for callers that do not know the owning source; the composition
    /// uses [`Self::reconcile_for`] instead, which cannot consult a source that
    /// never owned the binding.
    async fn reconcile(
        &self,
        binding: &AttemptBinding,
        now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        let mut first_error: Option<MarketExecutionError> = None;
        let mut best: Option<MarketExecutionOutcome> = None;

        match self.local.reconcile(binding, now_ms).await {
            Ok(outcome) => best = Some(outcome),
            Err(error) => first_error = Some(error),
        }

        if let Some(okx) = self.okx.as_ref() {
            match okx.reconcile(binding, now_ms).await {
                Ok(outcome) => {
                    best = Some(match best {
                        Some(current) if rank(current) >= rank(outcome) => current,
                        _ => outcome,
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        match best {
            Some(outcome) => Ok(outcome),
            None => Err(first_error.unwrap_or(MarketExecutionError::Unavailable)),
        }
    }

    /// Reconciles the binding **only** at the source that owns it.
    ///
    /// A `Local` binding is never queried at the OKX port, and an `Okx` binding
    /// is never queried at the local port, so an outage in one source cannot be
    /// misreported as a terminal failure of an attempt owned by the other. An
    /// OKX binding with no configured provider is `Unknown` (still in flight,
    /// never fabricated and never dropped).
    async fn reconcile_for(
        &self,
        router_source: RouterSource,
        binding: &AttemptBinding,
        now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        match router_source {
            RouterSource::Local => {
                self.local
                    .reconcile_for(RouterSource::Local, binding, now_ms)
                    .await
            }
            RouterSource::Okx => match self.okx.as_ref() {
                Some(okx) => okx.reconcile_for(RouterSource::Okx, binding, now_ms).await,
                None => Ok(MarketExecutionOutcome::Unknown),
            },
        }
    }
}
