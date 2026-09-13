//! Persistence contract for limit orders plus an in-memory fake.
//!
//! The trait is deliberately small and side-effect-free from the engine's point
//! of view: `create` is idempotent by key, `append_transition` is a
//! compare-and-swap on `version` that reports an already-applied sequence
//! without re-applying it, and `replay_from` rebuilds state from the log.
//!
//! This slice depends on no storage crate; `InMemoryLimitOrderStore` is the
//! executable reference for the contract.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use domain::{IdempotencyKey, OrderId};

use crate::error::LimitEngineError;
use crate::fsm::{apply_transition, is_terminal};
use crate::order::{OrderTransition, StoredLimitOrder};

/// Result of creating an order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    /// The order was inserted.
    Created(StoredLimitOrder),
    /// The idempotency key already mapped to this (or an equal) order.
    Existing(StoredLimitOrder),
}

/// Result of appending a transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The transition was validated and recorded.
    Applied(StoredLimitOrder),
    /// The transition sequence was already present; nothing was re-applied.
    AlreadyApplied(StoredLimitOrder),
}

/// Idempotent, compare-and-swap persistence for limit orders.
#[async_trait]
pub trait LimitOrderStore: Send + Sync {
    /// Creates `order`, or returns the existing order for the same
    /// idempotency key.
    async fn create(&self, order: StoredLimitOrder) -> Result<CreateOutcome, LimitEngineError>;

    /// Loads the current record, if present.
    async fn load(&self, order_id: &OrderId) -> Result<Option<StoredLimitOrder>, LimitEngineError>;

    /// Appends `transition` when `expected_version` matches the stored version.
    ///
    /// `next` must be exactly the result of applying `transition` to the stored
    /// record. A repeated sequence returns
    /// [`AppendOutcome::AlreadyApplied`]; a stale version returns
    /// [`LimitEngineError::PersistenceConflict`].
    async fn append_transition(
        &self,
        expected_version: u64,
        transition: &OrderTransition,
        next: &StoredLimitOrder,
    ) -> Result<AppendOutcome, LimitEngineError>;

    /// Replays the transition log from `from_seq` (inclusive) and returns the
    /// resulting record, verifying it against the stored per-transition states.
    async fn replay_from(
        &self,
        order_id: &OrderId,
        from_seq: u64,
    ) -> Result<StoredLimitOrder, LimitEngineError>;

    /// Lists all non-terminal records, deterministically ordered by order id.
    async fn list_open(&self) -> Result<Vec<StoredLimitOrder>, LimitEngineError>;
}

#[derive(Default)]
struct Inner {
    /// Current state per order.
    orders: HashMap<OrderId, StoredLimitOrder>,
    /// State as created, the replay baseline.
    baseline: HashMap<OrderId, StoredLimitOrder>,
    /// Idempotency key -> order id.
    by_idempotency: HashMap<IdempotencyKey, OrderId>,
    /// Append-only validated transition log per order.
    transitions: HashMap<OrderId, Vec<(OrderTransition, StoredLimitOrder)>>,
}

/// Deterministic in-memory [`LimitOrderStore`].
#[derive(Default)]
pub struct InMemoryLimitOrderStore {
    inner: Mutex<Inner>,
}

impl InMemoryLimitOrderStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, LimitEngineError> {
        self.inner
            .lock()
            .map_err(|_| LimitEngineError::PersistenceUnavailable)
    }
}

#[async_trait]
impl LimitOrderStore for InMemoryLimitOrderStore {
    async fn create(&self, order: StoredLimitOrder) -> Result<CreateOutcome, LimitEngineError> {
        let mut inner = self.lock()?;
        if let Some(existing_id) = inner.by_idempotency.get(&order.order_idempotency_key) {
            let existing = inner
                .orders
                .get(existing_id)
                .cloned()
                .ok_or(LimitEngineError::StoreInvalid)?;
            return Ok(CreateOutcome::Existing(existing));
        }
        if inner.orders.contains_key(&order.order.id) {
            return Err(LimitEngineError::IdempotencyConflict);
        }
        inner.baseline.insert(order.order.id.clone(), order.clone());
        inner
            .by_idempotency
            .insert(order.order_idempotency_key.clone(), order.order.id.clone());
        inner.orders.insert(order.order.id.clone(), order.clone());
        Ok(CreateOutcome::Created(order))
    }

    async fn load(&self, order_id: &OrderId) -> Result<Option<StoredLimitOrder>, LimitEngineError> {
        let inner = self.lock()?;
        Ok(inner.orders.get(order_id).cloned())
    }

    async fn append_transition(
        &self,
        expected_version: u64,
        transition: &OrderTransition,
        next: &StoredLimitOrder,
    ) -> Result<AppendOutcome, LimitEngineError> {
        let mut inner = self.lock()?;
        let current = inner
            .orders
            .get(&transition.order_id)
            .cloned()
            .ok_or(LimitEngineError::StoreInvalid)?;

        // Idempotency first: a sequence at or below the stored one is a replay.
        if transition.transition_seq <= current.last_transition_seq {
            return Ok(AppendOutcome::AlreadyApplied(current));
        }

        if expected_version != current.version {
            return Err(LimitEngineError::PersistenceConflict);
        }
        if next.order.id != transition.order_id {
            return Err(LimitEngineError::StoreInvalid);
        }
        if transition.from != current.order.status {
            return Err(LimitEngineError::StoreInvalid);
        }

        let derived = apply_transition(
            &current,
            transition.to,
            transition.fill.as_ref(),
            transition.at_ms,
        )
        .map_err(|_| LimitEngineError::StoreInvalid)?;
        if derived != *next {
            return Err(LimitEngineError::StoreInvalid);
        }

        inner
            .transitions
            .entry(transition.order_id.clone())
            .or_default()
            .push((transition.clone(), next.clone()));
        inner
            .orders
            .insert(transition.order_id.clone(), next.clone());
        Ok(AppendOutcome::Applied(next.clone()))
    }

    async fn replay_from(
        &self,
        order_id: &OrderId,
        from_seq: u64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        let inner = self.lock()?;
        let baseline = inner
            .baseline
            .get(order_id)
            .ok_or(LimitEngineError::StoreInvalid)?;
        let log = match inner.transitions.get(order_id) {
            Some(log) => log.as_slice(),
            None => &[],
        };

        // State just before `from_seq`: either the creation baseline or the
        // stored state after the preceding transition.
        let mut state = if from_seq == 0 {
            baseline.clone()
        } else {
            match log
                .iter()
                .find(|(transition, _)| transition.transition_seq.saturating_add(1) == from_seq)
            {
                Some((_, next)) => next.clone(),
                None => {
                    let first_seq = log.first().map(|(transition, _)| transition.transition_seq);
                    if first_seq.is_none_or(|seq| from_seq <= seq) {
                        baseline.clone()
                    } else {
                        return Err(LimitEngineError::RecoveryInconsistent);
                    }
                }
            }
        };

        for (transition, expected) in log
            .iter()
            .filter(|(transition, _)| transition.transition_seq >= from_seq)
        {
            state = apply_transition(
                &state,
                transition.to,
                transition.fill.as_ref(),
                transition.at_ms,
            )?;
            if state != *expected {
                return Err(LimitEngineError::RecoveryInconsistent);
            }
        }
        Ok(state)
    }

    async fn list_open(&self) -> Result<Vec<StoredLimitOrder>, LimitEngineError> {
        let inner = self.lock()?;
        let mut open: Vec<StoredLimitOrder> = inner
            .orders
            .values()
            .filter(|order| !is_terminal(order.order.status))
            .cloned()
            .collect();
        open.sort_by(|left, right| left.order.id.as_str().cmp(right.order.id.as_str()));
        Ok(open)
    }
}
