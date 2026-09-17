//! Multi-chain factory handoff: public-API integration tests.
//!
//! These drive the additive [`ChainAdapterRegistry`] seam the private-api
//! integrator uses, over deterministic mock transports. No endpoint is
//! contacted, no credential exists, and nothing signs or broadcasts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chain_adapters::{
    execution_support, validate_solana_transaction, ChainAdapterError, ChainAdapterRegistry,
    EvmChain, EvmChainTransport, ExecutionVerdict, ReceiptObservation, SolanaChainTransport,
    SolanaCluster, SolanaCommitment, SolanaSignatureStatus, TokenMetadata,
};
use chain_types::ChainId;
use execution_relay::ChainHealth;

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
        Ok(7)
    }

    async fn call(&self, _to: &str, _data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
        Ok(Vec::new())
    }

    async fn erc20_balance(&self, _token: &str, _owner: &str) -> Result<u128, ChainAdapterError> {
        Ok(0)
    }

    async fn erc20_metadata(&self, _token: &str) -> Result<TokenMetadata, ChainAdapterError> {
        Ok(TokenMetadata {
            symbol: "MOCK".to_string(),
            decimals: 18,
        })
    }

    async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
        Ok("0xsubmitted".to_string())
    }

    async fn transaction_receipt(
        &self,
        _reference: &str,
    ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
        Ok(None)
    }
}

/// Deterministic Solana transport double for a single cluster.
struct MockSolana {
    genesis: String,
}

#[async_trait]
impl SolanaChainTransport for MockSolana {
    async fn cluster_genesis_hash(&self) -> Result<String, ChainAdapterError> {
        Ok(self.genesis.clone())
    }

    async fn latest_blockhash(
        &self,
        _commitment: SolanaCommitment,
    ) -> Result<String, ChainAdapterError> {
        Ok("blockhash".to_string())
    }

    async fn lamport_balance(&self, _address: &str) -> Result<u128, ChainAdapterError> {
        Ok(0)
    }

    async fn send_raw_transaction(&self, _raw: &[u8]) -> Result<String, ChainAdapterError> {
        Err(ChainAdapterError::TransportUnavailable)
    }

    async fn signature_status(
        &self,
        _signature: &str,
    ) -> Result<Option<SolanaSignatureStatus>, ChainAdapterError> {
        Ok(None)
    }
}

/// A syntactically valid one-signature legacy Solana transaction.
fn legacy_transaction() -> Vec<u8> {
    let mut bytes = vec![0x01];
    bytes.extend_from_slice(&[0u8; 64]);
    bytes.extend_from_slice(&[1, 0, 0]);
    bytes.push(0x01);
    bytes.extend_from_slice(&[7u8; 32]);
    bytes.extend_from_slice(&[9u8; 32]);
    bytes.push(0x01);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes
}

#[tokio::test]
async fn factory_ready_paths_every_verified_chain_and_refuses_robinhood() {
    let mut registry = ChainAdapterRegistry::new();
    for evm in [EvmChain::Base, EvmChain::Ethereum, EvmChain::BnbChain] {
        registry.register_evm(
            evm,
            Arc::new(MockEvm {
                chain_id: AtomicU64::new(evm.expected_chain_id()),
            }),
        );
        let adapter = registry
            .ready_submission_adapter(&evm.chain())
            .await
            .expect("evm ready");
        assert_eq!(adapter.health(0), ChainHealth::Healthy);
    }
    registry.register_solana(
        SolanaCluster::MainnetBeta,
        Arc::new(MockSolana {
            genesis: SolanaCluster::MainnetBeta.genesis_hash().to_string(),
        }),
    );
    let adapter = registry
        .ready_submission_adapter(&ChainId::Solana)
        .await
        .expect("solana ready");
    assert_eq!(adapter.health(0), ChainHealth::Healthy);

    // Robinhood-associated execution is a hard blocker, never a guess.
    let robinhood = execution_support(&ChainId::RobinhoodAssociated);
    assert_eq!(robinhood.verdict, ExecutionVerdict::Blocked);
    assert!(!robinhood.blockers.is_empty());
    assert_eq!(
        registry
            .ready_submission_adapter(&ChainId::RobinhoodAssociated)
            .await
            .err(),
        Some(ChainAdapterError::UnsupportedChain)
    );
}

#[tokio::test]
async fn factory_reports_wrong_chain_identity() {
    let mut registry = ChainAdapterRegistry::new();
    // An Ethereum endpoint bound to Base must fail closed.
    registry.register_evm(
        EvmChain::Base,
        Arc::new(MockEvm {
            chain_id: AtomicU64::new(EvmChain::Ethereum.expected_chain_id()),
        }),
    );
    assert_eq!(
        registry
            .ready_submission_adapter(&ChainId::Base)
            .await
            .err(),
        Some(ChainAdapterError::WrongChain)
    );

    // A devnet endpoint bound to mainnet-beta must fail closed too.
    registry.register_solana(
        SolanaCluster::MainnetBeta,
        Arc::new(MockSolana {
            genesis: SolanaCluster::Devnet.genesis_hash().to_string(),
        }),
    );
    assert_eq!(
        registry
            .ready_submission_adapter(&ChainId::Solana)
            .await
            .err(),
        Some(ChainAdapterError::WrongChain)
    );
}

#[test]
fn solana_payload_validation_never_accepts_evm_payloads() {
    assert!(validate_solana_transaction(&legacy_transaction()).is_ok());
    // Legacy EVM RLP list.
    assert_eq!(
        validate_solana_transaction(&[0xc0, 0x01, 0x02]),
        Err(ChainAdapterError::InvalidPayload)
    );
    // EIP-1559-shaped typed envelope.
    assert_eq!(
        validate_solana_transaction(&[0x02, 0xc0, 0x01, 0x02, 0x03]),
        Err(ChainAdapterError::InvalidPayload)
    );
    // Empty.
    assert_eq!(
        validate_solana_transaction(&[]),
        Err(ChainAdapterError::InvalidPayload)
    );
}

#[test]
fn evm_family_mapping_excludes_solana_and_robinhood() {
    assert_eq!(
        EvmChain::from_chain_id(&ChainId::Base),
        Some(EvmChain::Base)
    );
    assert_eq!(
        EvmChain::from_chain_id(&ChainId::Ethereum),
        Some(EvmChain::Ethereum)
    );
    assert_eq!(
        EvmChain::from_chain_id(&ChainId::BnbChain),
        Some(EvmChain::BnbChain)
    );
    assert_eq!(EvmChain::from_chain_id(&ChainId::Solana), None);
    assert_eq!(EvmChain::from_chain_id(&ChainId::RobinhoodAssociated), None);
}
