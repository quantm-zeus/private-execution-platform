//! P84C verified OKX provider execution seam.
//!
//! The local relay port (see [`crate::RelayMarketExecutionPort`]) refuses a
//! non-Local `router_source`, because an OKX-sourced quote must be verified
//! before anything is signed. This module provides that verified path:
//!
//! 1. fetch the untrusted provider swap proposal through an injected
//!    [`ProviderProposalSource`] (production default fails closed);
//! 2. derive the trusted tax basis and minimum output from the same seams the
//!    local relay uses ([`crate::MarketExecutionTrustSource`] + the approved
//!    quote);
//! 3. run the pure [`provider_verification::verify_provider_proposal`] binding,
//!    allowlist, spend, digest, and freshness checks; and
//! 4. hand only the resulting [`ApprovedProviderPayload`] to an injected
//!    [`ApprovedProviderSink`].
//!
//! No signing or submission capability is implemented here. The default sink is
//! fail-closed, so production live submission stays unavailable until a
//! separately reviewed chain/signing adapter installs a real sink. A tampered or
//! mismatched proposal is denied and never reaches the sink.

use std::fmt;

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
    RouterSource,
};
use async_trait::async_trait;
use market_types::Bps;
use okx_client::{OkxClient, OkxClientError, OkxSwapProposal, OkxSwapRequest, OkxTransport};
use provider_verification::{
    verify_provider_proposal, ApprovedProviderPayload, ProviderSwapProposal,
    ProviderVerificationPolicy,
};
use tax_engine::evaluate_tax_safety;

use crate::{market_min_out, MarketExecutionTrust, MarketExecutionTrustSource};

/// Redacted provider-proposal source failure taxonomy.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderProposalError {
    /// The provider transport/proposal source is not reachable.
    #[error("provider proposal source unavailable")]
    Unavailable,
    /// The provider request or response was structurally rejected.
    #[error("provider proposal source rejected")]
    Rejected,
}

impl fmt::Debug for ProviderProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProviderProposalError({self})")
    }
}

/// Injected, read-only source of one untrusted provider swap proposal.
#[async_trait]
pub trait ProviderProposalSource: Send + Sync {
    /// Fetches an untrusted OKX swap proposal at `now_ms`.
    async fn fetch_swap(
        &self,
        request: &OkxSwapRequest,
        now_ms: i64,
    ) -> Result<OkxSwapProposal, ProviderProposalError>;
}

/// Fail-closed default: no provider proposal source is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableProviderProposalSource;

#[async_trait]
impl ProviderProposalSource for UnavailableProviderProposalSource {
    async fn fetch_swap(
        &self,
        _request: &OkxSwapRequest,
        _now_ms: i64,
    ) -> Result<OkxSwapProposal, ProviderProposalError> {
        Err(ProviderProposalError::Unavailable)
    }
}

#[async_trait]
impl<T: OkxTransport + 'static> ProviderProposalSource for OkxClient<T> {
    async fn fetch_swap(
        &self,
        request: &OkxSwapRequest,
        now_ms: i64,
    ) -> Result<OkxSwapProposal, ProviderProposalError> {
        OkxClient::swap(self, request, now_ms)
            .await
            .map_err(|error| match error {
                OkxClientError::TransportUnavailable | OkxClientError::TransportFailure => {
                    ProviderProposalError::Unavailable
                }
                _ => ProviderProposalError::Rejected,
            })
    }
}

/// Injected boundary that receives ONLY an approved provider payload.
///
/// Implementations own any signing/submission; the shipped default fails closed
/// so no live action can occur without a separately reviewed adapter.
#[async_trait]
pub trait ApprovedProviderSink: Send + Sync {
    /// Consumes one verified payload. Must never fabricate a `Filled` outcome.
    async fn submit(
        &self,
        payload: ApprovedProviderPayload,
        request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError>;
}

/// Fail-closed default: no signing/submission boundary is installed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableApprovedProviderSink;

#[async_trait]
impl ApprovedProviderSink for UnavailableApprovedProviderSink {
    async fn submit(
        &self,
        _payload: ApprovedProviderPayload,
        _request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        Err(MarketExecutionError::Unavailable)
    }
}

/// Pre-sign revalidation gate for the verified provider path.
///
/// A [`VerifiedProviderExecutionPort`] calls this immediately before handing an
/// approved payload to the sink. Implementations MUST run the same authoritative
/// gates the local relay path runs: policy authorization
/// (`policy::PolicyEngine::authorize_trade`, i.e. the kill switch, limits,
/// turnover, and allowed venue) and the locked
/// `execution_preview::revalidate_pre_sign` gate (route/recipient binding, wallet
/// balance, allowance + spender, tax freshness/caps, and the net-delta/min-out
/// binding). The shipped default fails closed, so an approved payload can never
/// reach a signing sink until a real gate is installed.
#[async_trait]
pub trait ProviderRevalidationGate: Send + Sync {
    /// Revalidates the request, trusted state, and minimum output before signing.
    async fn revalidate(
        &self,
        request: &MarketExecutionRequest,
        trust: &MarketExecutionTrust,
        min_out: &market_types::AssetAmount,
    ) -> Result<(), MarketExecutionError>;
}

/// Fail-closed default: no revalidation gate is installed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableProviderRevalidationGate;

#[async_trait]
impl ProviderRevalidationGate for UnavailableProviderRevalidationGate {
    async fn revalidate(
        &self,
        _request: &MarketExecutionRequest,
        _trust: &MarketExecutionTrust,
        _min_out: &market_types::AssetAmount,
    ) -> Result<(), MarketExecutionError> {
        Err(MarketExecutionError::Unavailable)
    }
}

/// Trusted configuration for the verified provider port.
pub struct OkxExecutionConfig {
    /// Trusted verification policy (allowlists, recipient, caps, freshness).
    pub policy: ProviderVerificationPolicy,
    /// Trusted owner wallet the proposal must spend from.
    pub user_wallet: String,
    /// Optional slippage tolerance forwarded to the provider.
    pub slippage_bps: Option<Bps>,
}

impl fmt::Debug for OkxExecutionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OkxExecutionConfig")
            .field("policy", &self.policy)
            .field("has_slippage", &self.slippage_bps.is_some())
            .finish_non_exhaustive()
    }
}

/// Verified OKX provider execution port.
///
/// `Debug` is redacted: the source, sink, config, and every payload-derived value
/// are never rendered.
pub struct VerifiedProviderExecutionPort<S, K, T, G> {
    source: S,
    sink: K,
    trust: T,
    gate: G,
    config: OkxExecutionConfig,
}

impl<S, K, T, G> VerifiedProviderExecutionPort<S, K, T, G> {
    /// Wires the port from its injected seams.
    pub fn new(source: S, sink: K, trust: T, gate: G, config: OkxExecutionConfig) -> Self {
        Self {
            source,
            sink,
            trust,
            gate,
            config,
        }
    }
}

impl<S, K, T, G> fmt::Debug for VerifiedProviderExecutionPort<S, K, T, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderExecutionPort")
            .finish_non_exhaustive()
    }
}

fn project(proposal: &OkxSwapProposal) -> ProviderSwapProposal {
    ProviderSwapProposal {
        chain: proposal.chain().clone(),
        wallet: proposal.wallet().to_string(),
        receiver: proposal.receiver().to_string(),
        router: proposal.router().to_string(),
        spender: proposal.spender().map(str::to_string),
        token_in: proposal.token_in().clone(),
        token_out: proposal.token_out().clone(),
        amount_in: proposal.amount_in(),
        amount_out: proposal.amount_out(),
        min_receive_amount: proposal.min_receive_amount(),
        value: proposal.value(),
        // The OKX swap contract does not surface an approval amount; the
        // spender allowlist still applies, and a hidden approval cannot exceed
        // the cap the sink enforces (the default sink does nothing).
        approval_amount: None,
        calldata: proposal.calldata().to_vec(),
        calldata_digest: proposal.calldata_digest(),
        observed_at_ms: proposal.observed_at_ms(),
    }
}

#[async_trait]
impl<S, K, T, G> MarketExecutionPort for VerifiedProviderExecutionPort<S, K, T, G>
where
    S: ProviderProposalSource,
    K: ApprovedProviderSink,
    T: MarketExecutionTrustSource,
    G: ProviderRevalidationGate,
{
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        // This port only serves the OKX source; a Local request must use the
        // local relay port. A mismatch is a final denial before any work.
        if request.router_source != RouterSource::Okx {
            return Err(MarketExecutionError::Denied);
        }

        let leg = request
            .quote
            .plan
            .legs
            .first()
            .ok_or(MarketExecutionError::Denied)?;
        let trust = self.trust.trust(&request)?;
        let min_out = market_min_out(&request.intent, &request.quote.plan)?;
        let basis = evaluate_tax_safety(
            &request.intent,
            Some(&trust.tax_observation),
            request.now_ms,
            &trust.freshness_policy,
        )
        .map_err(|_| MarketExecutionError::Denied)?;

        let swap_request = OkxSwapRequest::new(
            request.intent.chain.clone(),
            request.intent.token_in.clone(),
            request.intent.token_out.clone(),
            leg.amount_in,
            self.config.slippage_bps,
            self.config.user_wallet.clone(),
        )
        .map_err(|_| MarketExecutionError::Denied)?;

        let proposal = self
            .source
            .fetch_swap(&swap_request, request.now_ms)
            .await
            .map_err(|error| match error {
                ProviderProposalError::Unavailable => MarketExecutionError::Unavailable,
                ProviderProposalError::Rejected => MarketExecutionError::Denied,
            })?;

        let mut policy = self.config.policy.clone();
        policy.min_receive = min_out.amount.get();

        let approved = verify_provider_proposal(
            &request.intent,
            &request.quote.plan,
            &request.quote.net_delta,
            &basis,
            &project(&proposal),
            &policy,
            request.now_ms,
        )
        .map_err(|_| MarketExecutionError::Denied)?;

        // The authoritative pre-sign gate must pass before any signing boundary
        // may act. The default gate fails closed, so an approved payload cannot
        // reach a sink without policy authorization and P39 revalidation.
        self.gate.revalidate(&request, &trust, &min_out).await?;

        // Only the approved, bound payload crosses this boundary.
        self.sink.submit(approved, &request).await
    }
}
