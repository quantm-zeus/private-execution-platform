//! Per-chain execution readiness and the additive adapter factory handoff.
//!
//! A chain is advertised as execution-capable only when its transport, signed
//! payload binding, submit path, and receipt/reconciliation path are all
//! verified. Base, Ethereum, BNB Chain and Solana have verified typed paths in
//! this crate; `RobinhoodAssociated` does **not**, so it is reported as a hard
//! blocker with explicit evidence and the factory refuses to build an execution
//! adapter for it.
//!
//! The [`ChainAdapterRegistry`] is the composition seam for the private-api
//! integrator: register the injected (redacted, credential-owning) transports
//! once, then request a boxed [`ChainSubmissionAdapter`] by
//! [`ChainId`]. No real endpoint, credential, or broadcast is used here.

use std::collections::HashMap;
use std::sync::Arc;

use chain_types::ChainId;
use execution_relay::ChainSubmissionAdapter;

use crate::{
    ChainAdapterError, EvmChain, EvmChainSubmissionAdapter, EvmChainTransport,
    SolanaChainSubmissionAdapter, SolanaChainTransport, SolanaCluster,
};

/// Whether a chain's execution path is verified end to end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionVerdict {
    /// Transport, signing payload binding, submit, and receipt reconciliation
    /// are implemented and covered by deterministic tests.
    Verified,
    /// At least one execution layer is unverified; execution must not be
    /// advertised.
    Blocked,
}

/// A concrete, evidence-backed reason an execution layer is unverified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionBlocker {
    /// The chain has no verified transport binding in the domain model.
    TransportUnverified,
    /// The signed payload cannot be bound to a verified provider/payload path.
    SigningPayloadUnverified,
    /// Submission has no verified end-to-end path.
    SubmitUnverified,
    /// Receipt/reconciliation semantics are unverified for the chain.
    ReceiptReconciliationUnverified,
    /// No provider quote/swap proposal path supports the chain.
    ProviderProposalUnsupported,
}

impl ExecutionBlocker {
    /// Stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::TransportUnverified => "transport_unverified",
            Self::SigningPayloadUnverified => "signing_payload_unverified",
            Self::SubmitUnverified => "submit_unverified",
            Self::ReceiptReconciliationUnverified => "receipt_reconciliation_unverified",
            Self::ProviderProposalUnsupported => "provider_proposal_unsupported",
        }
    }

    /// Concrete evidence for the blocker, citing repository and/or public
    /// sources. Public sources are external, untrusted data used only as
    /// evidence to *refuse* support.
    pub const fn evidence(self) -> &'static str {
        match self {
            Self::TransportUnverified => {
                "No verified transport binding: ChainId::RobinhoodAssociated carries no canonical \
                 chain id in the domain, and no injected/verified transport exists. Public docs \
                 (docs.robinhood.com/chain/connecting) describe an Arbitrum Orbit EVM L2 with chain \
                 id 4663, but the repository has not bound that identity or proven a transport."
            }
            Self::SigningPayloadUnverified => {
                "privy::canonical_chain_tag maps RobinhoodAssociated=4, but that tag is an internal \
                 request-digest encoding, not proof that Privy can sign a chain-id-4663 payload; no \
                 verified payload builder exists (crates/privy/src/signing.rs:100-104)."
            }
            Self::SubmitUnverified => {
                "No end-to-end submit proof: there is no operator endpoint, no chain-id binding, and \
                 no test that a Robinhood-bound payload is accepted and observed on chain."
            }
            Self::ReceiptReconciliationUnverified => {
                "No receipt/reconciliation proof exists against chain id 4663; EVM receipt semantics \
                 are assumed, not verified, for this chain."
            }
            Self::ProviderProposalUnsupported => {
                "crates/okx-client/src/quote.rs maps ChainId::RobinhoodAssociated to \
                 OkxClientError::UnsupportedChain, so no provider quote/swap proposal path exists."
            }
        }
    }
}

/// Execution readiness for one chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainExecutionSupport {
    /// The domain chain identifier.
    pub chain: ChainId,
    /// Chain family label (`"evm"`, `"solana"`, or `"unknown"`).
    pub family: &'static str,
    /// Verified or blocked.
    pub verdict: ExecutionVerdict,
    /// Evidence-backed blockers when [`Self::verdict`] is
    /// [`ExecutionVerdict::Blocked`].
    pub blockers: &'static [ExecutionBlocker],
}

impl ChainExecutionSupport {
    /// Whether execution may be advertised for this chain.
    pub fn execution_verified(&self) -> bool {
        self.verdict == ExecutionVerdict::Verified
    }
}

/// Every execution blocker recorded for `RobinhoodAssociated`.
pub const ROBINHOOD_BLOCKERS: &[ExecutionBlocker] = &[
    ExecutionBlocker::TransportUnverified,
    ExecutionBlocker::SigningPayloadUnverified,
    ExecutionBlocker::SubmitUnverified,
    ExecutionBlocker::ReceiptReconciliationUnverified,
    ExecutionBlocker::ProviderProposalUnsupported,
];

/// Blocker recorded for an operator-defined (`Other`) chain.
pub const CUSTOM_CHAIN_BLOCKERS: &[ExecutionBlocker] = &[ExecutionBlocker::TransportUnverified];

/// The chains whose execution path this crate verifies end to end.
pub const VERIFIED_EXECUTION_CHAINS: &[ChainId] = &[
    ChainId::Base,
    ChainId::Ethereum,
    ChainId::BnbChain,
    ChainId::Solana,
];

/// The EVM chains verified for execution.
pub const VERIFIED_EVM_CHAINS: &[EvmChain] =
    &[EvmChain::Base, EvmChain::Ethereum, EvmChain::BnbChain];

/// Returns the execution readiness for `chain`.
///
/// Only the verified EVM chains and Solana return
/// [`ExecutionVerdict::Verified`]. `RobinhoodAssociated` and operator-defined
/// chains are [`ExecutionVerdict::Blocked`] with evidence.
pub fn execution_support(chain: &ChainId) -> ChainExecutionSupport {
    match chain {
        ChainId::Base | ChainId::Ethereum | ChainId::BnbChain => ChainExecutionSupport {
            chain: chain.clone(),
            family: "evm",
            verdict: ExecutionVerdict::Verified,
            blockers: &[],
        },
        ChainId::Solana => ChainExecutionSupport {
            chain: chain.clone(),
            family: "solana",
            verdict: ExecutionVerdict::Verified,
            blockers: &[],
        },
        ChainId::RobinhoodAssociated => ChainExecutionSupport {
            chain: chain.clone(),
            family: "unknown",
            verdict: ExecutionVerdict::Blocked,
            blockers: ROBINHOOD_BLOCKERS,
        },
        ChainId::Other(_) => ChainExecutionSupport {
            chain: chain.clone(),
            family: "unknown",
            verdict: ExecutionVerdict::Blocked,
            blockers: CUSTOM_CHAIN_BLOCKERS,
        },
    }
}

/// Registry of injected chain transports used to build relay adapters.
///
/// It holds only operator-supplied transports (which own any endpoint and
/// credential internally and render redacted `Debug`), never credentials
/// itself. Registering a chain does not prove execution readiness: the factory
/// still refuses chains whose [`execution_support`] is blocked.
#[derive(Default)]
pub struct ChainAdapterRegistry {
    evm: HashMap<EvmChain, Arc<dyn EvmChainTransport>>,
    solana: Option<(SolanaCluster, Arc<dyn SolanaChainTransport>)>,
}

impl ChainAdapterRegistry {
    /// Builds an empty registry (every chain unproven).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an injected EVM transport for one verified EVM chain.
    ///
    /// A later registration for the same chain replaces the earlier one.
    pub fn register_evm(&mut self, chain: EvmChain, transport: Arc<dyn EvmChainTransport>) {
        self.evm.insert(chain, transport);
    }

    /// Registers the injected Solana transport and its expected cluster.
    pub fn register_solana(
        &mut self,
        cluster: SolanaCluster,
        transport: Arc<dyn SolanaChainTransport>,
    ) {
        self.solana = Some((cluster, transport));
    }

    /// Whether a transport is registered for `chain`.
    pub fn is_registered(&self, chain: &ChainId) -> bool {
        match chain {
            ChainId::Solana => self.solana.is_some(),
            other => EvmChain::from_chain_id(other)
                .map(|evm| self.evm.contains_key(&evm))
                .unwrap_or(false),
        }
    }

    /// Builds a relay-facing submission adapter for `chain`, or fails closed.
    ///
    /// A blocked chain ([`ChainId::RobinhoodAssociated`] or an operator-defined
    /// chain) is always [`ChainAdapterError::UnsupportedChain`]; a verified
    /// chain with no registered transport is
    /// [`ChainAdapterError::TransportUnavailable`]. The returned adapter's
    /// cached health still starts `Unavailable`; call
    /// [`Self::ready_submission_adapter`] to also prove identity.
    pub fn submission_adapter(
        &self,
        chain: &ChainId,
    ) -> Result<Arc<dyn ChainSubmissionAdapter>, ChainAdapterError> {
        if !execution_support(chain).execution_verified() {
            return Err(ChainAdapterError::UnsupportedChain);
        }
        match chain {
            ChainId::Solana => {
                let (cluster, transport) = self
                    .solana
                    .as_ref()
                    .ok_or(ChainAdapterError::TransportUnavailable)?;
                Ok(Arc::new(SolanaChainSubmissionAdapter::new(
                    transport.clone(),
                    *cluster,
                )))
            }
            other => {
                let evm =
                    EvmChain::from_chain_id(other).ok_or(ChainAdapterError::UnsupportedChain)?;
                let transport = self
                    .evm
                    .get(&evm)
                    .ok_or(ChainAdapterError::TransportUnavailable)?
                    .clone();
                Ok(Arc::new(EvmChainSubmissionAdapter::for_chain(
                    transport, evm,
                )))
            }
        }
    }

    /// Builds a submission adapter **and** proves its chain identity.
    ///
    /// Returns [`ChainAdapterError::WrongChain`] when the endpoint answers a
    /// different chain, and [`ChainAdapterError::TransportUnavailable`] when the
    /// identity read fails.
    pub async fn ready_submission_adapter(
        &self,
        chain: &ChainId,
    ) -> Result<Arc<dyn ChainSubmissionAdapter>, ChainAdapterError> {
        match chain {
            ChainId::Solana => {
                let (cluster, transport) = self
                    .solana
                    .as_ref()
                    .ok_or(ChainAdapterError::TransportUnavailable)?;
                let adapter = SolanaChainSubmissionAdapter::new(transport.clone(), *cluster);
                adapter.refresh_health().await;
                adapter.verify_cluster_identity().await?;
                Ok(Arc::new(adapter))
            }
            other => {
                if !execution_support(other).execution_verified() {
                    return Err(ChainAdapterError::UnsupportedChain);
                }
                let evm =
                    EvmChain::from_chain_id(other).ok_or(ChainAdapterError::UnsupportedChain)?;
                let transport = self
                    .evm
                    .get(&evm)
                    .ok_or(ChainAdapterError::TransportUnavailable)?
                    .clone();
                let adapter = EvmChainSubmissionAdapter::for_chain(transport, evm);
                adapter.refresh_health().await;
                adapter.verify_chain_identity().await?;
                Ok(Arc::new(adapter))
            }
        }
    }
}

impl std::fmt::Debug for ChainAdapterRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChainAdapterRegistry")
            .field("evm_chains", &self.evm.len())
            .field("solana", &self.solana.is_some())
            .finish()
    }
}

/// Free-function adapter factory over a registry (private-api handoff).
pub fn submission_adapter_for_chain(
    chain: &ChainId,
    registry: &ChainAdapterRegistry,
) -> Result<Arc<dyn ChainSubmissionAdapter>, ChainAdapterError> {
    registry.submission_adapter(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::{ReceiptObservation, TokenMetadata};

    /// Deterministic EVM transport double bound to a configurable chain id.
    #[derive(Default)]
    struct MockEvm {
        chain_id: AtomicU64,
    }

    #[async_trait]
    impl EvmChainTransport for MockEvm {
        async fn chain_id(&self) -> Result<u64, ChainAdapterError> {
            Ok(self.chain_id.load(Ordering::SeqCst))
        }

        async fn block_number(&self) -> Result<u64, ChainAdapterError> {
            Ok(1)
        }

        async fn call(&self, _to: &str, _data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
            Ok(Vec::new())
        }

        async fn erc20_balance(
            &self,
            _token: &str,
            _owner: &str,
        ) -> Result<u128, ChainAdapterError> {
            Ok(0)
        }

        async fn erc20_metadata(&self, _token: &str) -> Result<TokenMetadata, ChainAdapterError> {
            Ok(TokenMetadata {
                symbol: "MOCK".to_string(),
                decimals: 18,
            })
        }

        async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
            Ok("0xhash".to_string())
        }

        async fn transaction_receipt(
            &self,
            _reference: &str,
        ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
            Ok(None)
        }
    }

    #[test]
    fn verified_chains_are_advertised_and_robinhood_is_not() {
        for chain in [
            ChainId::Base,
            ChainId::Ethereum,
            ChainId::BnbChain,
            ChainId::Solana,
        ] {
            let support = execution_support(&chain);
            assert!(support.execution_verified(), "{chain:?}");
            assert!(support.blockers.is_empty(), "{chain:?}");
        }

        let robinhood = execution_support(&ChainId::RobinhoodAssociated);
        assert_eq!(robinhood.verdict, ExecutionVerdict::Blocked);
        assert!(!robinhood.execution_verified());
        assert_eq!(robinhood.blockers, ROBINHOOD_BLOCKERS);
        // Every execution layer is explicitly unverified.
        for blocker in ROBINHOOD_BLOCKERS {
            assert!(!blocker.code().is_empty());
            assert!(!blocker.evidence().is_empty());
        }

        let custom = execution_support(&ChainId::Other("hypercore".to_string()));
        assert!(!custom.execution_verified());
    }

    #[test]
    fn factory_refuses_robinhood_even_with_registered_evm_transport() {
        let mut registry = ChainAdapterRegistry::new();
        registry.register_evm(
            EvmChain::Base,
            Arc::new(MockEvm {
                chain_id: AtomicU64::new(8453),
            }),
        );
        assert_eq!(
            registry
                .submission_adapter(&ChainId::RobinhoodAssociated)
                .err(),
            Some(ChainAdapterError::UnsupportedChain)
        );
    }

    #[test]
    fn factory_reports_absent_transport_for_a_verified_chain() {
        let registry = ChainAdapterRegistry::new();
        assert_eq!(
            registry.submission_adapter(&ChainId::Base).err(),
            Some(ChainAdapterError::TransportUnavailable)
        );
        assert_eq!(
            registry.submission_adapter(&ChainId::Solana).err(),
            Some(ChainAdapterError::TransportUnavailable)
        );
    }

    #[test]
    fn factory_builds_adapters_for_each_registered_verified_chain() {
        let mut registry = ChainAdapterRegistry::new();
        for evm in VERIFIED_EVM_CHAINS {
            registry.register_evm(
                *evm,
                Arc::new(MockEvm {
                    chain_id: AtomicU64::new(evm.expected_chain_id()),
                }),
            );
            assert!(registry.is_registered(&evm.chain()));
            let adapter = registry.submission_adapter(&evm.chain()).expect("adapter");
            // Health starts unavailable until the integrator proves identity.
            assert_eq!(adapter.health(0), execution_relay::ChainHealth::Unavailable);
        }
        assert!(!registry.is_registered(&ChainId::RobinhoodAssociated));
    }
}
