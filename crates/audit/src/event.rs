//! Versioned, self-contained execution audit event.
//!
//! The event is sealed whole into the ciphertext of an
//! [`storage::OpaqueEventRecord`]; the outer record never sees these fields. The
//! event is deliberately self-contained (it repeats intent/route/preview
//! bindings) so a replay can be validated without reaching into live state.
//!
//! The model carries **no wall clock**: only the caller-supplied
//! [`storage::CreatedBucket`] is persisted outside the ciphertext, and the
//! policy approval timestamps are evidence copied from an earlier approval
//! decision, not a new observation.

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionId, ExecutionPreview, IdempotencyKey, IntentId, LimitPrice, OrderType,
    RiskConstraints, RoutePlan, TradeSide, TradeSource, UserId, WalletRef,
};
use market_types::AtomicAmount;
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// Audit payload schema version understood by this build.
pub const AUDIT_SCHEMA_VERSION: u16 = 1;

/// Opaque reference produced by the signing boundary.
///
/// The audit crate defines its own newtype so it never depends on `privy`. It is
/// never rendered by `Debug`; the serialized form is the opaque string itself,
/// which only ever lives inside the ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SigningReference(String);

impl SigningReference {
    /// Wraps a non-empty opaque reference.
    pub fn new(reference: impl Into<String>) -> Result<Self, AuditError> {
        Self::try_from(reference.into())
    }

    /// Borrows the opaque reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SigningReference {
    type Error = AuditError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.trim().is_empty() {
            return Err(AuditError::EventValidationFailed("empty signing reference"));
        }
        Ok(Self(value))
    }
}

impl std::fmt::Debug for SigningReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningReference([REDACTED])")
    }
}

/// Audit-owned classification of the relay outcome, independent of
/// `execution-relay`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayOutcomeClass {
    /// The submission adapter acknowledged the attempt; on-chain state unknown.
    Submitted,
    /// The attempt's chain state could not be determined.
    Unknown,
    /// The chain confirmed the submission.
    Confirmed,
    /// The chain definitively rejected the submission.
    Rejected,
    /// The attempt failed before any chain submission.
    FailedBeforeSubmit,
}

impl RelayOutcomeClass {
    /// Whether this outcome can only exist after a signing reference was issued.
    pub const fn requires_signing(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Unknown | Self::Confirmed | Self::Rejected
        )
    }
}

/// Audit-owned classification of the pre-sign revalidation outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevalidationOutcomeClass {
    /// The preview is still valid.
    Valid,
    /// A requote is required before signing.
    Requote,
    /// The attempt is final and must not be signed.
    Final,
}

/// Revalidation evidence attached to a lifecycle event.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevalidationSummary {
    /// Classification of the revalidation decision.
    pub outcome: RevalidationOutcomeClass,
    /// Stable reason code chosen by the revalidation layer.
    pub reason_code: u16,
}

/// Signing evidence attached to a lifecycle event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningSummary {
    /// Canonical request digest bound by the signing boundary.
    pub request_digest: [u8; 32],
    /// Digest of the unsigned payload.
    pub payload_digest: [u8; 32],
    /// Signing request nonce.
    pub nonce: u64,
    /// Opaque signing reference, present only after a successful signature.
    pub reference: Option<SigningReference>,
}

/// Relay evidence attached to a lifecycle event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySummary {
    /// Outcome classification.
    pub outcome: RelayOutcomeClass,
    /// Opaque chain reference, present once an attempt reached the adapter.
    pub reference: Option<String>,
    /// Coarse attempt bucket; never an exact timestamp.
    pub attempt_bucket: u32,
}

/// Policy approval evidence copied from the approval decision.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApprovalSummary {
    /// Approval decision time in milliseconds.
    pub approved_at_ms: i64,
    /// Approved trade notional in USD micros.
    pub approved_trade_usd: u64,
    /// Approval expiry in milliseconds, when the policy set one.
    pub expires_at_ms: Option<i64>,
}

/// Full lifecycle audit event, schema version 1.
///
/// `Debug` reveals only the schema version and sequence; the payload carries
/// plaintext trading semantics and is never formatted into logs by accident.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionAuditEvent {
    /// Payload schema version; must equal [`AUDIT_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Monotonic sequence within the event's intent stream. Must equal the outer
    /// record's sequence on replay.
    pub sequence: u64,
    /// Chain-scoped intent identifier.
    pub intent_id: IntentId,
    /// Idempotency key bound to the intent.
    pub idempotency_key: IdempotencyKey,
    /// Owning user.
    pub user_id: UserId,
    /// Opaque wallet reference.
    pub wallet_ref: WalletRef,
    /// Chain of the trade.
    pub chain: ChainId,
    /// Originating surface.
    pub source: TradeSource,
    /// Input asset.
    pub token_in: AssetId,
    /// Output asset.
    pub token_out: AssetId,
    /// Trade side.
    pub side: TradeSide,
    /// Unit of `amount`.
    pub amount_type: AmountType,
    /// Requested amount in `amount_type` units.
    pub amount: AtomicAmount,
    /// Order type.
    pub order_type: OrderType,
    /// Limit price for limit orders.
    pub limit_price: Option<LimitPrice>,
    /// Risk caps applied to the intent.
    pub risk: RiskConstraints,
    /// Planned route.
    pub route: RoutePlan,
    /// Simulated execution preview.
    pub preview: ExecutionPreview,
    /// Pre-sign revalidation evidence, when one was performed.
    pub revalidation: Option<RevalidationSummary>,
    /// Signing evidence.
    pub signing: SigningSummary,
    /// Relay evidence.
    pub relay: RelaySummary,
    /// Policy approval evidence.
    pub policy: PolicyApprovalSummary,
    /// Execution identity for relayed attempts, when one was assigned.
    pub execution_id: Option<ExecutionId>,
}

impl std::fmt::Debug for ExecutionAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionAuditEvent")
            .field("schema_version", &self.schema_version)
            .field("sequence", &self.sequence)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl ExecutionAuditEvent {
    /// Validates the event's internal consistency and lifecycle ordering.
    ///
    /// Every failure maps to [`AuditError::EventValidationFailed`] with a
    /// redaction-safe static reason.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != AUDIT_SCHEMA_VERSION {
            return Err(AuditError::EventValidationFailed(
                "unsupported schema version",
            ));
        }
        if self.sequence == 0 {
            return Err(AuditError::EventValidationFailed(
                "sequence must be positive",
            ));
        }
        self.intent_id
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("intent identifier invalid"))?;
        self.idempotency_key
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("idempotency key invalid"))?;
        self.user_id
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("user identifier invalid"))?;
        self.wallet_ref
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("wallet reference invalid"))?;
        self.chain
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("chain invalid"))?;
        self.token_in
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("input asset invalid"))?;
        self.token_out
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("output asset invalid"))?;
        if let Some(execution_id) = &self.execution_id {
            execution_id
                .validate()
                .map_err(|_| AuditError::EventValidationFailed("execution identifier invalid"))?;
        }
        if self.token_in == self.token_out {
            return Err(AuditError::EventValidationFailed(
                "trade pair must be distinct",
            ));
        }
        if self.token_in.chain != self.chain || self.token_out.chain != self.chain {
            return Err(AuditError::EventValidationFailed("asset chain mismatch"));
        }
        if self.amount.is_zero() {
            return Err(AuditError::EventValidationFailed("amount must be positive"));
        }
        match (self.order_type, &self.limit_price) {
            (OrderType::Market, None) | (OrderType::Limit, Some(_)) => {}
            (OrderType::Market, Some(_)) | (OrderType::Limit, None) => {
                return Err(AuditError::EventValidationFailed(
                    "order type and limit price disagree",
                ));
            }
        }
        self.risk
            .validate(&self.token_in)
            .map_err(|_| AuditError::EventValidationFailed("risk constraints invalid"))?;
        self.route
            .validate()
            .map_err(|_| AuditError::EventValidationFailed("route plan invalid"))?;
        self.preview
            .validate_internal()
            .map_err(|_| AuditError::EventValidationFailed("preview invalid"))?;
        self.validate_bindings()?;
        if self.signing.nonce == 0 {
            return Err(AuditError::EventValidationFailed(
                "signing nonce must be positive",
            ));
        }
        let has_reference = self.signing.reference.is_some();
        if has_reference
            && (self.signing.request_digest == [0u8; 32]
                || self.signing.payload_digest == [0u8; 32])
        {
            return Err(AuditError::EventValidationFailed("signing digests missing"));
        }
        if let Some(reference) = &self.relay.reference {
            if reference.trim().is_empty() {
                return Err(AuditError::EventValidationFailed("relay reference invalid"));
            }
        }
        if self.relay.outcome.requires_signing() && !has_reference {
            return Err(AuditError::EventValidationFailed(
                "relay outcome before signing",
            ));
        }
        if self.relay.reference.is_some() && !has_reference {
            return Err(AuditError::EventValidationFailed(
                "relay outcome before signing",
            ));
        }
        Ok(())
    }

    /// Binds the preview and route to the flattened intent fields.
    fn validate_bindings(&self) -> Result<(), AuditError> {
        if self.preview.intent_id != self.intent_id {
            return Err(AuditError::EventValidationFailed("preview intent mismatch"));
        }
        if self.preview.chain != self.chain {
            return Err(AuditError::EventValidationFailed("preview chain mismatch"));
        }
        if self.preview.token_in != self.token_in || self.preview.token_out != self.token_out {
            return Err(AuditError::EventValidationFailed("preview asset mismatch"));
        }
        if self.preview.side != self.side {
            return Err(AuditError::EventValidationFailed("preview side mismatch"));
        }
        let first_leg = self
            .route
            .legs
            .first()
            .ok_or(AuditError::EventValidationFailed("route plan invalid"))?;
        let last_leg = self
            .route
            .legs
            .last()
            .ok_or(AuditError::EventValidationFailed("route plan invalid"))?;
        if first_leg.token_in != self.token_in {
            return Err(AuditError::EventValidationFailed("route token mismatch"));
        }
        if last_leg.token_out != self.token_out {
            return Err(AuditError::EventValidationFailed("route output mismatch"));
        }
        if self.route.expected_net_output != self.preview.simulated_net_output {
            return Err(AuditError::EventValidationFailed(
                "route output amount mismatch",
            ));
        }
        Ok(())
    }
}
