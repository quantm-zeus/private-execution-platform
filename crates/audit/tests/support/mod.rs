//! Shared fixtures and deterministic doubles for the audit integration tests.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use audit::{
    AuditKeyMaterial, AuditKeyProvider, BlindIndexKey, ExecutionAuditEvent, PolicyApprovalSummary,
    RelayOutcomeClass, RelaySummary, RevalidationOutcomeClass, RevalidationSummary,
    SigningReference, SigningSummary, AUDIT_SCHEMA_VERSION,
};
use chain_types::{AssetId, ChainId};
use crypto_envelope::SealKey;
use domain::{
    AmountType, ExecutionCostComponents, ExecutionId, ExecutionPreview, IdempotencyKey, IntentId,
    OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeSide, TradeSource, UserId, WalletRef,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessStatus, Sequence};
use storage::{
    ComponentHealth, CreatedBucket, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    OpaqueStore, StorageError, StorageValidationError,
};

pub const KID_A: [u8; 16] = [0x2Au8; 16];
pub const KID_B: [u8; 16] = [0x2Fu8; 16];
pub const SEAL_A: [u8; 32] = [0x11u8; 32];
pub const SEAL_B: [u8; 32] = [0x22u8; 32];
pub const BLIND_A: [u8; 32] = [0x33u8; 32];
pub const BLIND_B: [u8; 32] = [0x44u8; 32];

pub const AMOUNT_IN: u128 = 1_000_000_000;
pub const GROSS_OUT: u128 = 2_500_000_000;
pub const NET_OUT: u128 = 2_250_000_000;
pub const DEX_FEE: u128 = 5_000_000;
pub const TAX_COST: u128 = 250_000_000;

pub const INTENT: &str = "intent-alpha";
pub const IDEMPOTENCY: &str = "idem-alpha";
pub const USER: &str = "user-alpha";
pub const WALLET: &str = "wallet-alpha";
pub const VENUE: &str = "venue-alpha";
pub const POOL: &str = "pool-alpha";
pub const SIGNING_REF: &str = "ref-alpha";
pub const RELAY_REF: &str = "relay-ref-alpha";
pub const EXECUTION: &str = "exec-alpha";

pub fn base() -> ChainId {
    ChainId::Base
}

pub fn bucket() -> CreatedBucket {
    CreatedBucket::new(1).expect("bucket")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// In-memory `OpaqueStore` with call counters and injectable failure.
#[derive(Default)]
pub struct CountingStore {
    events: Mutex<Vec<OpaqueEventRecord>>,
    append_calls: AtomicUsize,
    read_calls: AtomicUsize,
    fail_next: Mutex<Option<StorageError>>,
}

impl CountingStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_calls(&self) -> usize {
        self.append_calls.load(Ordering::SeqCst)
    }

    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    pub fn fail_next_append(&self, error: StorageError) {
        *lock(&self.fail_next) = Some(error);
    }

    pub fn seed(&self, records: Vec<OpaqueEventRecord>) {
        *lock(&self.events) = records;
    }

    pub fn records(&self) -> Vec<OpaqueEventRecord> {
        lock(&self.events).clone()
    }
}

#[async_trait]
impl OpaqueStore for CountingStore {
    async fn put_object(&self, _object: OpaqueObject) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn get_object(&self, _id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        Ok(None)
    }

    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError> {
        self.append_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = lock(&self.fail_next).take() {
            return Err(error);
        }
        event.validate()?;
        let mut events = lock(&self.events);
        let expected = events
            .iter()
            .filter(|stored| stored.stream_blind_index == event.stream_blind_index)
            .map(|stored| stored.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        if event.sequence != expected {
            return Err(StorageError::Conflict);
        }
        events.push(event);
        Ok(())
    }

    async fn read_events(
        &self,
        stream_blind_index: &[u8],
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        if stream_blind_index.is_empty() {
            return Err(StorageError::Invalid(
                StorageValidationError::EmptyStreamIndex,
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let events = lock(&self.events);
        let mut records: Vec<OpaqueEventRecord> = events
            .iter()
            .filter(|stored| {
                stored.stream_blind_index == stream_blind_index && stored.sequence >= from_sequence
            })
            .cloned()
            .collect();
        records.sort_by_key(|record| record.sequence);
        records.truncate(limit);
        Ok(records)
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Ok(None)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "audit.test.store",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct KeyEntry {
    kid: [u8; 16],
    seal: [u8; 32],
    blind_index: [u8; 32],
}

impl KeyEntry {
    fn material(self) -> AuditKeyMaterial {
        AuditKeyMaterial {
            kid: self.kid,
            seal: SealKey::from_bytes(self.seal),
            blind_index: BlindIndexKey::from_bytes(self.blind_index),
        }
    }
}

/// Deterministic key provider: a current key plus optional alternates.
pub struct FixedProvider {
    current: KeyEntry,
    alternates: Vec<KeyEntry>,
    unavailable: bool,
}

impl FixedProvider {
    fn entry(kid: [u8; 16], seal: [u8; 32], blind_index: [u8; 32]) -> KeyEntry {
        KeyEntry {
            kid,
            seal,
            blind_index,
        }
    }

    pub fn single() -> Self {
        Self {
            current: Self::entry(KID_A, SEAL_A, BLIND_A),
            alternates: Vec::new(),
            unavailable: false,
        }
    }

    /// Current key plus a rotated key so kid tamper can be authenticated away.
    pub fn rotatable() -> Self {
        Self {
            current: Self::entry(KID_A, SEAL_A, BLIND_A),
            alternates: vec![Self::entry(KID_B, SEAL_B, BLIND_B)],
            unavailable: false,
        }
    }

    /// Same kid and blind key as [`FixedProvider::single`], wrong seal key.
    pub fn wrong_key() -> Self {
        Self {
            current: Self::entry(KID_A, SEAL_B, BLIND_A),
            alternates: Vec::new(),
            unavailable: false,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            current: Self::entry(KID_A, SEAL_A, BLIND_A),
            alternates: Vec::new(),
            unavailable: true,
        }
    }
}

impl AuditKeyProvider for FixedProvider {
    fn current(&self) -> Result<AuditKeyMaterial, audit::AuditError> {
        if self.unavailable {
            return Err(audit::AuditError::KeyUnavailable);
        }
        Ok(self.current.material())
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<AuditKeyMaterial, audit::AuditError> {
        if self.unavailable {
            return Err(audit::AuditError::KeyUnavailable);
        }
        if kid == &self.current.kid {
            return Ok(self.current.material());
        }
        self.alternates
            .iter()
            .find(|entry| &entry.kid == kid)
            .map(|entry| entry.material())
            .ok_or(audit::AuditError::UnknownKeyId)
    }
}

pub fn intent_id(value: &str) -> IntentId {
    IntentId::new(value).expect("intent id")
}

pub fn idempotency_key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).expect("idempotency key")
}

pub fn user_id(value: &str) -> UserId {
    UserId::new(value).expect("user id")
}

pub fn wallet_ref(value: &str) -> WalletRef {
    WalletRef::new(value).expect("wallet ref")
}

pub fn execution_id(value: &str) -> ExecutionId {
    ExecutionId::new(value).expect("execution id")
}

pub fn asset(address: &str) -> AssetId {
    AssetId::new(base(), address).expect("asset")
}

fn amount(asset: AssetId, value: u128) -> AssetAmount {
    AssetAmount {
        asset,
        amount: AtomicAmount::new(value),
    }
}

/// Full lifecycle event that validates.
pub fn lifecycle_event(sequence: u64) -> ExecutionAuditEvent {
    let token_in = asset("USDCADDRESS");
    let token_out = asset("TOKENADDRESS");
    let route = RoutePlan {
        legs: vec![RouteLeg {
            venue: VENUE.to_string(),
            pool_ref: POOL.to_string(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(AMOUNT_IN),
            expected_amount_out: AtomicAmount::new(GROSS_OUT),
        }],
        expected_net_output: amount(token_out.clone(), NET_OUT),
        state: Freshness {
            observed_at_ms: 1,
            chain_height: 1,
            sequence: Sequence::new(1),
        },
    };
    let preview = ExecutionPreview {
        intent_id: intent_id(INTENT),
        chain: base(),
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        simulated_net_input: amount(token_in.clone(), AMOUNT_IN),
        simulated_net_output: amount(token_out.clone(), NET_OUT),
        gross_output: amount(token_out.clone(), GROSS_OUT),
        cost_components: ExecutionCostComponents {
            gas_cost: None,
            dex_fee: Some(amount(token_in.clone(), DEX_FEE)),
            provider_fee: None,
            tax_cost: Some(amount(token_out.clone(), TAX_COST)),
        },
        local_state_freshness: FreshnessStatus::Fresh,
    };
    ExecutionAuditEvent {
        schema_version: AUDIT_SCHEMA_VERSION,
        sequence,
        intent_id: intent_id(INTENT),
        idempotency_key: idempotency_key(IDEMPOTENCY),
        user_id: user_id(USER),
        wallet_ref: wallet_ref(WALLET),
        chain: base(),
        source: TradeSource::Web,
        token_in,
        token_out,
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(AMOUNT_IN),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(100).expect("bps"),
            max_slippage: Bps::new(50).expect("bps"),
            max_total_cost: None,
        },
        route,
        preview,
        revalidation: Some(RevalidationSummary {
            outcome: RevalidationOutcomeClass::Valid,
            reason_code: 0,
        }),
        signing: SigningSummary {
            request_digest: [0xABu8; 32],
            payload_digest: [0xCDu8; 32],
            nonce: 7,
            reference: Some(SigningReference::new(SIGNING_REF).expect("signing reference")),
        },
        relay: RelaySummary {
            outcome: RelayOutcomeClass::Confirmed,
            reference: Some(RELAY_REF.to_string()),
            attempt_bucket: 3,
        },
        policy: PolicyApprovalSummary {
            approved_at_ms: 900,
            approved_trade_usd: 1_000_000,
            expires_at_ms: Some(2_000),
        },
        execution_id: Some(execution_id(EXECUTION)),
    }
}

/// Event that reaches a relay outcome without any signing evidence.
pub fn event_without_signing(sequence: u64) -> ExecutionAuditEvent {
    let mut event = lifecycle_event(sequence);
    event.signing.reference = None;
    event.signing.request_digest = [0u8; 32];
    event.signing.payload_digest = [0u8; 32];
    event.relay.outcome = RelayOutcomeClass::Confirmed;
    event
}

/// Stream index for an arbitrary intent under the provider's current key.
pub fn stream_for(provider: &FixedProvider, intent: &str) -> Vec<u8> {
    let material = provider.current().expect("current");
    audit::stream_blind_index(&material.blind_index, &base(), &intent_id(intent))
        .expect("stream index")
        .to_vec()
}

/// Stream index for the fixture intent under the given provider's current key.
pub fn fixture_stream(provider: &FixedProvider) -> Vec<u8> {
    stream_for(provider, INTENT)
}
