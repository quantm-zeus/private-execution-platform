//! Opaque persistence and internal eventing contracts.
//!
//! This crate deliberately does not own encryption keys. Trusted callers encrypt payloads
//! before they cross this boundary and provide only blind-index-ready lookup bytes.
//! Trusted callers likewise supply quantized creation-time buckets: opaque records never
//! carry exact wall-clock timestamps, and this crate never computes time.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const STORAGE_SCHEMA_VERSION: u16 = 1;

/// Quantized creation-time bucket supplied by the trusted caller.
///
/// Physical persistence must not observe exact wall-clock time, so opaque records carry a
/// coarse bucket (for example a day boundary) instead of a millisecond timestamp. Storage
/// never derives this value itself. Matching the SQL schema, bucket 0 is valid and negative
/// buckets are invalid. Deserialization is validated, so negative values cannot enter even
/// by bypassing [`CreatedBucket::new`]; record validation rejects them as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64")]
pub struct CreatedBucket(i64);

impl TryFrom<i64> for CreatedBucket {
    type Error = StorageValidationError;

    fn try_from(bucket: i64) -> Result<Self, Self::Error> {
        if bucket < 0 {
            return Err(StorageValidationError::InvalidCreatedBucket);
        }
        Ok(Self(bucket))
    }
}

impl CreatedBucket {
    pub fn new(bucket: i64) -> Option<Self> {
        Self::try_from(bucket).ok()
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueObject {
    pub id: String,
    pub owner_blind_index: Vec<u8>,
    pub class_blind_index: Vec<u8>,
    pub version: u64,
    pub ciphertext: Vec<u8>,
    pub created_bucket: CreatedBucket,
}

impl OpaqueObject {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.id.trim().is_empty() {
            return Err(StorageValidationError::EmptyId);
        }
        if self.owner_blind_index.is_empty() {
            return Err(StorageValidationError::EmptyOwnerIndex);
        }
        if self.class_blind_index.is_empty() {
            return Err(StorageValidationError::EmptyClassIndex);
        }
        if self.version == 0 {
            return Err(StorageValidationError::ZeroVersion);
        }
        if self.ciphertext.is_empty() {
            return Err(StorageValidationError::EmptyCiphertext);
        }
        if self.created_bucket.get() < 0 {
            return Err(StorageValidationError::InvalidCreatedBucket);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueEventRecord {
    pub stream_blind_index: Vec<u8>,
    pub sequence: u64,
    pub schema_version: u16,
    pub ciphertext: Vec<u8>,
    pub created_bucket: CreatedBucket,
}

impl OpaqueEventRecord {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.stream_blind_index.is_empty() {
            return Err(StorageValidationError::EmptyStreamIndex);
        }
        if self.sequence == 0 {
            return Err(StorageValidationError::ZeroSequence);
        }
        if self.schema_version == 0 {
            return Err(StorageValidationError::ZeroSchemaVersion);
        }
        if self.ciphertext.is_empty() {
            return Err(StorageValidationError::EmptyCiphertext);
        }
        if self.created_bucket.get() < 0 {
            return Err(StorageValidationError::InvalidCreatedBucket);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueSnapshot {
    pub stream_blind_index: Vec<u8>,
    pub sequence: u64,
    pub version: u64,
    pub ciphertext: Vec<u8>,
    pub created_bucket: CreatedBucket,
}

impl OpaqueSnapshot {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.stream_blind_index.is_empty() {
            return Err(StorageValidationError::EmptyStreamIndex);
        }
        if self.sequence == 0 {
            return Err(StorageValidationError::ZeroSequence);
        }
        if self.version == 0 {
            return Err(StorageValidationError::ZeroVersion);
        }
        if self.ciphertext.is_empty() {
            return Err(StorageValidationError::EmptyCiphertext);
        }
        if self.created_bucket.get() < 0 {
            return Err(StorageValidationError::InvalidCreatedBucket);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSubject {
    MarketPoolUpdated,
    MarketAssetUpdated,
    IntelFomoUpdated,
    IntelGmgnUpdated,
    IntelSocialUpdated,
    OrderCreated,
    OrderTriggered,
    OrderPartiallyFilled,
    OrderFilled,
    OrderCancelled,
    ExecutionStarted,
    ExecutionSigned,
    ExecutionSubmitted,
    ExecutionConfirmed,
    ExecutionFailed,
}

impl EventSubject {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MarketPoolUpdated => "market.pool.updated",
            Self::MarketAssetUpdated => "market.asset.updated",
            Self::IntelFomoUpdated => "intel.fomo.updated",
            Self::IntelGmgnUpdated => "intel.gmgn.updated",
            Self::IntelSocialUpdated => "intel.social.updated",
            Self::OrderCreated => "order.created",
            Self::OrderTriggered => "order.triggered",
            Self::OrderPartiallyFilled => "order.partially_filled",
            Self::OrderFilled => "order.filled",
            Self::OrderCancelled => "order.cancelled",
            Self::ExecutionStarted => "execution.started",
            Self::ExecutionSigned => "execution.signed",
            Self::ExecutionSubmitted => "execution.submitted",
            Self::ExecutionConfirmed => "execution.confirmed",
            Self::ExecutionFailed => "execution.failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalEventEnvelope {
    pub event_id: String,
    pub subject: EventSubject,
    pub schema_version: u16,
    pub occurred_at_ms: i64,
    pub payload: Vec<u8>,
}

impl InternalEventEnvelope {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.event_id.trim().is_empty() {
            return Err(StorageValidationError::EmptyId);
        }
        if self.schema_version == 0 {
            return Err(StorageValidationError::ZeroSchemaVersion);
        }
        if self.payload.is_empty() {
            return Err(StorageValidationError::EmptyPayload);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthProbe {
    pub component: &'static str,
    pub status: ComponentHealth,
    pub observed_at_ms: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageValidationError {
    #[error("identifier must not be empty")]
    EmptyId,
    #[error("owner blind index must not be empty")]
    EmptyOwnerIndex,
    #[error("class blind index must not be empty")]
    EmptyClassIndex,
    #[error("stream blind index must not be empty")]
    EmptyStreamIndex,
    #[error("sequence must be greater than zero")]
    ZeroSequence,
    #[error("version must be greater than zero")]
    ZeroVersion,
    #[error("schema version must be greater than zero")]
    ZeroSchemaVersion,
    #[error("ciphertext must not be empty")]
    EmptyCiphertext,
    #[error("event payload must not be empty")]
    EmptyPayload,
    #[error("created bucket must not be negative")]
    InvalidCreatedBucket,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("storage unavailable")]
    Unavailable,
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("invalid record: {0}")]
    Invalid(#[from] StorageValidationError),
    #[error("backend error")]
    Backend,
}

#[async_trait]
pub trait OpaqueStore: Send + Sync {
    async fn put_object(&self, object: OpaqueObject) -> Result<(), StorageError>;
    async fn get_object(&self, id: &str) -> Result<Option<OpaqueObject>, StorageError>;
    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError>;
    async fn latest_snapshot(
        &self,
        stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError>;
    async fn health(&self) -> HealthProbe;
}

#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, event: InternalEventEnvelope) -> Result<(), StorageError>;
    async fn health(&self) -> HealthProbe;
}

pub mod nats;
pub mod pg;

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> OpaqueObject {
        OpaqueObject {
            id: "o1".into(),
            owner_blind_index: vec![1],
            class_blind_index: vec![2],
            version: 1,
            ciphertext: vec![3, 4],
            created_bucket: CreatedBucket::new(86_400_000).unwrap(),
        }
    }

    #[test]
    fn opaque_object_round_trips_without_semantic_fields() {
        let value = object();
        value.validate().unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("wallet"));
        assert!(!json.contains("token"));
        assert!(!json.contains("order"));
        assert!(!json.contains("created_at_ms"));
        assert!(!json.contains("occurred_at_ms"));
        let decoded: OpaqueObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn invalid_opaque_object_is_rejected() {
        let mut value = object();
        value.ciphertext.clear();
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::EmptyCiphertext)
        );
    }

    #[test]
    fn opaque_object_rejects_negative_created_bucket() {
        let mut value = object();
        value.created_bucket = CreatedBucket(-1);
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::InvalidCreatedBucket)
        );

        let mut value = object();
        value.created_bucket = CreatedBucket(-86_400_000);
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::InvalidCreatedBucket)
        );
    }

    #[test]
    fn opaque_object_accepts_zero_created_bucket() {
        let mut value = object();
        value.created_bucket = CreatedBucket::new(0).unwrap();
        value.validate().unwrap();
    }

    #[test]
    fn created_bucket_constructor_accepts_zero_and_rejects_negative() {
        assert_eq!(CreatedBucket::new(0).unwrap().get(), 0);
        assert!(CreatedBucket::new(-1).is_none());
        assert_eq!(CreatedBucket::new(86_400_000).unwrap().get(), 86_400_000);
    }

    #[test]
    fn created_bucket_deserialization_is_validated() {
        let negative: Result<CreatedBucket, _> = serde_json::from_str("-1");
        assert!(negative.is_err());

        let zero: CreatedBucket = serde_json::from_str("0").unwrap();
        assert_eq!(zero.get(), 0);

        let positive: CreatedBucket = serde_json::from_str("86400000").unwrap();
        assert_eq!(positive.get(), 86_400_000);
    }

    fn event_record() -> OpaqueEventRecord {
        OpaqueEventRecord {
            stream_blind_index: vec![7],
            sequence: 1,
            schema_version: STORAGE_SCHEMA_VERSION,
            ciphertext: vec![5, 6],
            created_bucket: CreatedBucket::new(86_400_000).unwrap(),
        }
    }

    fn snapshot() -> OpaqueSnapshot {
        OpaqueSnapshot {
            stream_blind_index: vec![8],
            sequence: 2,
            version: 1,
            ciphertext: vec![9, 10],
            created_bucket: CreatedBucket::new(86_400_000).unwrap(),
        }
    }

    #[test]
    fn valid_event_record_passes_validation() {
        event_record().validate().unwrap();
    }

    #[test]
    fn valid_snapshot_passes_validation() {
        snapshot().validate().unwrap();
    }

    #[test]
    fn event_record_rejects_empty_stream_index() {
        let mut value = event_record();
        value.stream_blind_index.clear();
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::EmptyStreamIndex)
        );
    }

    #[test]
    fn event_record_rejects_zero_sequence() {
        let mut value = event_record();
        value.sequence = 0;
        assert_eq!(value.validate(), Err(StorageValidationError::ZeroSequence));
    }

    #[test]
    fn event_record_rejects_zero_schema_version() {
        let mut value = event_record();
        value.schema_version = 0;
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::ZeroSchemaVersion)
        );
    }

    #[test]
    fn event_record_rejects_empty_ciphertext() {
        let mut value = event_record();
        value.ciphertext.clear();
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::EmptyCiphertext)
        );
    }

    #[test]
    fn event_record_rejects_negative_created_bucket() {
        let mut value = event_record();
        value.created_bucket = CreatedBucket(-86_400_000);
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::InvalidCreatedBucket)
        );
    }

    #[test]
    fn snapshot_rejects_empty_stream_index() {
        let mut value = snapshot();
        value.stream_blind_index.clear();
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::EmptyStreamIndex)
        );
    }

    #[test]
    fn snapshot_rejects_zero_sequence_and_version() {
        let mut value = snapshot();
        value.sequence = 0;
        assert_eq!(value.validate(), Err(StorageValidationError::ZeroSequence));

        let mut value = snapshot();
        value.version = 0;
        assert_eq!(value.validate(), Err(StorageValidationError::ZeroVersion));
    }

    #[test]
    fn snapshot_rejects_empty_ciphertext() {
        let mut value = snapshot();
        value.ciphertext.clear();
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::EmptyCiphertext)
        );
    }

    #[test]
    fn snapshot_rejects_negative_created_bucket() {
        let mut value = snapshot();
        value.created_bucket = CreatedBucket(-86_400_000);
        assert_eq!(
            value.validate(),
            Err(StorageValidationError::InvalidCreatedBucket)
        );
    }

    #[test]
    fn internal_subjects_are_stable() {
        assert_eq!(
            EventSubject::OrderPartiallyFilled.as_str(),
            "order.partially_filled"
        );
        assert_eq!(
            EventSubject::ExecutionConfirmed.as_str(),
            "execution.confirmed"
        );
    }

    #[test]
    fn event_serialization_is_versioned() {
        let event = InternalEventEnvelope {
            event_id: "e1".into(),
            subject: EventSubject::MarketPoolUpdated,
            schema_version: STORAGE_SCHEMA_VERSION,
            occurred_at_ms: 1,
            payload: vec![9],
        };
        event.validate().unwrap();
        let json = serde_json::to_string(&event).unwrap();
        let decoded: InternalEventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn opaque_object_round_trip_does_not_expose_exact_timestamp() {
        let value = object();
        let json = serde_json::to_string(&value).unwrap();
        let decoded: OpaqueObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.created_bucket.get(), 86_400_000);
    }
}
