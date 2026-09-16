//! Typed capability readiness proofs (remediation F6 / D6).
//!
//! Capability is derived from **healthy backing dependencies**, never from a
//! boolean or the mere presence of a seam. A `FailClosedDispatcher` is not
//! evidence of execute capability, and wiring a trait object is not evidence
//! that the backing service works.
//!
//! Integration status: this is the typed surface the private-api bootstrap
//! reads instead of `WiredCapabilities` booleans. `apps/private-api::trading`
//! turns the injected durable/chain/signer/market/limit/realtime probes into a
//! [`CapabilityReadiness`], and `production::build_opaque` gates the advertised
//! document on those proofs. A wired trait object with no healthy proof can no
//! longer advertise the capability.
//!
//! Each proof type has no public constructor: it can only be produced by
//! [`MarketCapability::prove`] / [`ExecutionCapability::prove`] / etc., which
//! consume a [`HealthProbe`] and fail closed unless the probe is
//! [`ComponentHealth::Healthy`]. Downstream code (the eventual private-api
//! bootstrap document) must read these proofs rather than bare booleans.

use storage::{ComponentHealth, HealthProbe};

/// Evidence that one backing dependency was observed healthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyProof {
    component: &'static str,
    observed_at_ms: i64,
}

impl DependencyProof {
    fn from_probe(probe: &HealthProbe) -> Option<Self> {
        if probe.status != ComponentHealth::Healthy {
            return None;
        }
        Some(Self {
            component: probe.component,
            observed_at_ms: probe.observed_at_ms,
        })
    }

    /// The component name that was observed.
    pub fn component(&self) -> &'static str {
        self.component
    }

    /// When the observation was taken.
    pub fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }
}

macro_rules! capability {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            proof: DependencyProof,
        }

        impl $name {
            /// Builds the proof only from a healthy probe.
            pub fn prove(probe: &HealthProbe) -> Option<Self> {
                DependencyProof::from_probe(probe).map(|proof| Self { proof })
            }

            /// The dependency proof backing this capability.
            pub fn proof(&self) -> &DependencyProof {
                &self.proof
            }
        }
    };
}

capability!(
    MarketCapability,
    "Proof that authoritative market state is healthy."
);
capability!(
    LimitCapability,
    "Proof that the limit/order engine store is healthy."
);
capability!(
    RealtimeCapability,
    "Proof that the realtime stream source is healthy."
);

/// Proof that a live execution path has every backing dependency healthy.
///
/// It requires **all** of: a durable attempt store, a chain adapter, and a
/// signing transport, each observed healthy, with the trading gate enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionCapability {
    durable_store: DependencyProof,
    chain: DependencyProof,
    signer: DependencyProof,
}

impl ExecutionCapability {
    /// Proves execution capability from three healthy dependency probes and the
    /// live trading gate.
    ///
    /// Returns `None` when the gate is off or any dependency is not healthy: a
    /// single missing dependency removes the capability entirely.
    pub fn prove(
        trading_enabled: bool,
        durable_store: &HealthProbe,
        chain: &HealthProbe,
        signer: &HealthProbe,
    ) -> Option<Self> {
        if !trading_enabled {
            return None;
        }
        Some(Self {
            durable_store: DependencyProof::from_probe(durable_store)?,
            chain: DependencyProof::from_probe(chain)?,
            signer: DependencyProof::from_probe(signer)?,
        })
    }

    /// The durable attempt-store proof.
    pub fn durable_store(&self) -> &DependencyProof {
        &self.durable_store
    }

    /// The chain adapter proof.
    pub fn chain(&self) -> &DependencyProof {
        &self.chain
    }

    /// The signer transport proof.
    pub fn signer(&self) -> &DependencyProof {
        &self.signer
    }
}

/// The complete typed readiness surface of a composition.
///
/// Every field is `None` unless its backing dependency was observed healthy; a
/// bootstrap document must derive advertised capabilities from these proofs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityReadiness {
    market: Option<MarketCapability>,
    execution: Option<ExecutionCapability>,
    limit: Option<LimitCapability>,
    realtime: Option<RealtimeCapability>,
}

impl CapabilityReadiness {
    /// The fully denied readiness surface: no dependency is proven.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Records a market-state proof.
    pub fn with_market(mut self, capability: MarketCapability) -> Self {
        self.market = Some(capability);
        self
    }

    /// Records an execution proof.
    pub fn with_execution(mut self, capability: ExecutionCapability) -> Self {
        self.execution = Some(capability);
        self
    }

    /// Records a limit-engine proof.
    pub fn with_limit(mut self, capability: LimitCapability) -> Self {
        self.limit = Some(capability);
        self
    }

    /// Records a realtime proof.
    pub fn with_realtime(mut self, capability: RealtimeCapability) -> Self {
        self.realtime = Some(capability);
        self
    }

    /// Whether authoritative market state is proven.
    pub fn market(&self) -> bool {
        self.market.is_some()
    }

    /// Whether a live execution path is proven.
    pub fn execute(&self) -> bool {
        self.execution.is_some()
    }

    /// Whether the limit engine is proven.
    pub fn limits(&self) -> bool {
        self.limit.is_some()
    }

    /// Whether a realtime stream is proven.
    pub fn realtime(&self) -> bool {
        self.realtime.is_some()
    }

    /// The execution proof, when present.
    pub fn execution(&self) -> Option<&ExecutionCapability> {
        self.execution.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(component: &'static str, status: ComponentHealth) -> HealthProbe {
        HealthProbe {
            component,
            status,
            observed_at_ms: 42,
        }
    }

    #[test]
    fn unhealthy_probe_yields_no_capability() {
        assert!(MarketCapability::prove(&probe("market", ComponentHealth::Healthy)).is_some());
        assert!(MarketCapability::prove(&probe("market", ComponentHealth::Degraded)).is_none());
        assert!(MarketCapability::prove(&probe("market", ComponentHealth::Unavailable)).is_none());
    }

    #[test]
    fn execution_requires_gate_and_all_three_dependencies() {
        let healthy = probe("dep", ComponentHealth::Healthy);
        assert!(ExecutionCapability::prove(true, &healthy, &healthy, &healthy).is_some());
        // Kill switch off removes execution capability even with healthy deps.
        assert!(ExecutionCapability::prove(false, &healthy, &healthy, &healthy).is_none());
        // Any single unavailable dependency removes it.
        let down = probe("dep", ComponentHealth::Unavailable);
        assert!(ExecutionCapability::prove(true, &down, &healthy, &healthy).is_none());
        assert!(ExecutionCapability::prove(true, &healthy, &down, &healthy).is_none());
        assert!(ExecutionCapability::prove(true, &healthy, &healthy, &down).is_none());
    }

    #[test]
    fn readiness_defaults_to_denied() {
        let readiness = CapabilityReadiness::deny_all();
        assert!(!readiness.market());
        assert!(!readiness.execute());
        assert!(!readiness.limits());
        assert!(!readiness.realtime());
        assert_eq!(CapabilityReadiness::default(), readiness);
    }

    #[test]
    fn readiness_reflects_only_proven_dependencies() {
        let market = MarketCapability::prove(&probe("market", ComponentHealth::Healthy)).unwrap();
        let execution = ExecutionCapability::prove(
            true,
            &probe("store", ComponentHealth::Healthy),
            &probe("chain", ComponentHealth::Healthy),
            &probe("signer", ComponentHealth::Healthy),
        )
        .unwrap();
        let readiness = CapabilityReadiness::deny_all()
            .with_market(market)
            .with_execution(execution);
        assert!(readiness.market());
        assert!(readiness.execute());
        assert!(!readiness.limits());
        assert!(!readiness.realtime());
        assert_eq!(
            readiness
                .execution()
                .expect("execution")
                .signer()
                .component(),
            "signer"
        );
    }
}
