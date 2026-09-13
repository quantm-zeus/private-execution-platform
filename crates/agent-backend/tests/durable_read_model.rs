//! P58 integration: the real [`DurableOrderReadModel`] path over an
//! `OpaqueStore` (seal -> list -> decrypt -> project), and its fail-closed
//! mapping when the store cannot list.

use std::sync::{Arc, Mutex};

use agent_backend::{BackendError, DurableOrderReadModel, OrderReadModel};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use crypto_envelope::at_rest::SealKey;
use domain::{
    IdempotencyKey, IntentId, LimitOrder, LimitPrice, OrderStatus, RiskConstraints, TradeSide,
    UserId, WalletRef,
};
use limit_engine::{
    order_id_for_creation, BlindIndexKey, DurableLimitOrderStore, LimitEngineError,
    LimitOrderStore, OrderKeyMaterial, OrderKeyProvider, StoredLimitOrder, DEFAULT_SCHEMA_VERSION,
};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};
use storage::{
    ClassListCursor, ComponentHealth, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    OpaqueStore, StorageError,
};

const KID: [u8; 16] = [3; 16];
const SEAL: [u8; 32] = [4; 32];
const BLIND: [u8; 32] = [5; 32];

fn material() -> OrderKeyMaterial {
    OrderKeyMaterial {
        kid: KID,
        seal: SealKey::from_bytes(SEAL),
        blind_index: BlindIndexKey::from_bytes(BLIND),
    }
}

struct TestKeys;

impl OrderKeyProvider for TestKeys {
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError> {
        Ok(material())
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError> {
        if kid == &KID {
            Ok(material())
        } else {
            Err(LimitEngineError::UnknownKeyId)
        }
    }
}

#[derive(Default)]
struct MemStore {
    objects: Mutex<Vec<OpaqueObject>>,
    fail_listing: Mutex<bool>,
}

impl MemStore {
    fn failing_listing() -> Self {
        Self {
            objects: Mutex::new(Vec::new()),
            fail_listing: Mutex::new(true),
        }
    }
}

#[async_trait]
impl OpaqueStore for MemStore {
    async fn put_object(&self, object: OpaqueObject) -> Result<(), StorageError> {
        object.validate().map_err(StorageError::Invalid)?;
        self.objects
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .push(object);
        Ok(())
    }

    async fn get_object(&self, id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        let objects = self.objects.lock().map_err(|_| StorageError::Unavailable)?;
        Ok(objects
            .iter()
            .filter(|object| object.id == id)
            .max_by_key(|object| object.version)
            .cloned())
    }

    async fn list_objects_by_class_page(
        &self,
        class_blind_index: &[u8],
        cursor: Option<&ClassListCursor>,
        limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        if *self
            .fail_listing
            .lock()
            .map_err(|_| StorageError::Unavailable)?
        {
            return Err(StorageError::Unavailable);
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let objects = self.objects.lock().map_err(|_| StorageError::Unavailable)?;
        let mut newest: Vec<OpaqueObject> = Vec::new();
        for object in objects
            .iter()
            .filter(|object| object.class_blind_index == class_blind_index)
        {
            match newest.iter_mut().find(|stored| stored.id == object.id) {
                Some(stored) if object.version > stored.version => *stored = object.clone(),
                Some(_) => {}
                None => newest.push(object.clone()),
            }
        }
        newest.sort_by(|left, right| {
            right
                .created_bucket
                .get()
                .cmp(&left.created_bucket.get())
                .then_with(|| left.id.cmp(&right.id))
        });
        if let Some(cursor) = cursor {
            newest.retain(|object| {
                object.created_bucket.get() < cursor.created_bucket.get()
                    || (object.created_bucket.get() == cursor.created_bucket.get()
                        && object.id > cursor.id)
            });
        }
        newest.truncate(limit);
        Ok(newest)
    }

    async fn append_event(&self, _event: OpaqueEventRecord) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn read_events(
        &self,
        _stream_blind_index: &[u8],
        _from_sequence: u64,
        _limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Ok(None)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "test.mem",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn stored(
    creation: &str,
    owner: &UserId,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
) -> StoredLimitOrder {
    let creation_key = IdempotencyKey::new(creation).expect("creation key");
    let order_id = order_id_for_creation(&BlindIndexKey::from_bytes(BLIND), &creation_key)
        .expect("derived order id");
    StoredLimitOrder {
        schema_version: DEFAULT_SCHEMA_VERSION,
        version: 1,
        order: LimitOrder {
            id: order_id,
            owner: owner.clone(),
            wallet_ref: WalletRef::new("w1").expect("wallet"),
            chain: ChainId::Base,
            token_in: asset("USDC"),
            token_out: asset("TOKEN"),
            side: TradeSide::Buy,
            max_input: AssetAmount {
                asset: asset("USDC"),
                amount: AtomicAmount::new(max),
            },
            remaining_input: AtomicAmount::new(remaining),
            limit_price: LimitPrice {
                numerator_asset: asset("USDC"),
                denominator_asset: asset("TOKEN"),
                ratio: PriceRatio::new(100, 25).expect("ratio"),
            },
            risk: RiskConstraints {
                max_buy_tax: Bps::new(500).expect("bps"),
                max_sell_tax: Bps::new(500).expect("bps"),
                max_price_impact: Bps::new(300).expect("bps"),
                max_slippage: Bps::new(200).expect("bps"),
                max_total_cost: None,
            },
            allow_partial_fill: true,
            min_fill: AtomicAmount::new(1),
            expires_at_ms: 1_000_000,
            status,
        },
        order_intent_id: IntentId::new("i1").expect("intent"),
        order_idempotency_key: creation_key,
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(filled),
        last_transition_seq: 0,
        published_seq: 0,
        next_eligible_at_ms: None,
    }
}

fn open_durable(store: Arc<MemStore>) -> Arc<DurableLimitOrderStore<MemStore>> {
    Arc::new(DurableLimitOrderStore::new(
        store,
        Arc::new(TestKeys),
        ChainId::Base,
    ))
}

#[tokio::test]
async fn real_read_model_lists_only_the_owner_and_maps_faults() {
    let durable = open_durable(Arc::new(MemStore::default()));
    let owner = UserId::new("u1").expect("owner");
    let other = UserId::new("u2").expect("owner");

    durable
        .create(stored("a", &owner, OrderStatus::Active, 100, 100, 0))
        .await
        .expect("create a");
    durable
        .create(stored("b", &owner, OrderStatus::Filled, 50, 0, 50))
        .await
        .expect("create b");
    durable
        .create(stored("c", &other, OrderStatus::Active, 10, 10, 0))
        .await
        .expect("create c");

    let model = DurableOrderReadModel::new(durable.clone(), owner);
    let all = model.list_orders(None).await.expect("list");
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|order| order.wallet_ref == "w1"));
    assert!(all
        .iter()
        .all(|order| order.status == OrderStatus::Active || order.status == OrderStatus::Filled));

    let active = model
        .list_orders(Some(OrderStatus::Active))
        .await
        .expect("list active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].status, OrderStatus::Active);
    assert_eq!(active[0].remaining_input, AtomicAmount::new(100));

    // A store that cannot list fails closed rather than returning partial data.
    let broken = DurableOrderReadModel::new(
        open_durable(Arc::new(MemStore::failing_listing())),
        UserId::new("u1").expect("owner"),
    );
    assert_eq!(
        broken.list_orders(None).await,
        Err(BackendError::Unavailable)
    );
}
