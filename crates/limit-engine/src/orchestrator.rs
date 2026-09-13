//! P51 — Phase 5 L3: deterministic limit-order orchestrator tick.
//!
//! This module is the durable, deterministic join point of the landed Phase-5
//! pieces. One [`Orchestrator::tick`] call:
//!
//! 1. loads the authoritative order from the P46 durable store,
//! 2. fails closed on a terminal order or a disabled trading gate,
//! 3. structurally refuses to re-touch an `Executing` order (its `Bound` WAL is
//!    already durable and re-signing is forbidden),
//! 4. normalizes a crash-left `Created`/`Quoting`/`Simulating` order to `Active`,
//! 5. evaluates the P45 trigger against the P44/P45 pure economics,
//! 6. re-quotes the exact chunk and runs the P50 preparation core,
//! 7. persists the `TriggerCandidate -> Quoting -> Simulating -> Executing`
//!    chain *before* any side effect,
//! 8. appends the durable `Bound` attempt (reserve-before-sign),
//! 9. delegates signing/submission to an injected [`AttemptExecutor`], and
//! 10. applies the realized fill / remainder through the P44 FSM + fill ledger.
//!
//! Nothing here signs, submits, reads a clock, uses an RNG, or performs network
//! I/O: every instant is the explicit `now_ms`, and the only capability that can
//! reach a chain is the injected seam. Event/outbox publication (P51b) and the
//! concrete relay adapter are out of scope.
//!
//! # Adaptations forced by the real APIs
//! The spec sketch is authoritative for the semantics; the landed APIs force
//! these shape changes:
//!
//! 1. [`evaluate_trigger`] returns the *post-state* of its internal transitions.
//!    A `NotExecutable` revert to `Active` is a two-step
//!    (`Active -> TriggerCandidate -> Active`) result, which cannot be persisted
//!    as one transition: [`Orchestrator::persist_trigger`] replays the same
//!    `apply_transition` chain the trigger used, one persisted step at a time,
//!    because the durable store re-derives and compares every transition
//!    byte-for-byte. `TriggerCandidate`/`Expired` outcomes are single-step.
//! 2. The kill-switch gate runs immediately after the terminal check and before
//!    any execution-path write, so a disabled gate leaves a `Created`/`Quoting`
//!    order untouched (no transition persisted) and never calls the provider.
//! 3. The locked FSM has no `TriggerCandidate -> FailedFinal` edge, so a final
//!    preparation abort parks the order back in `Active` with no side effect.
//! 4. The executor receives the live [`PreparedAttempt`] in addition to the
//!    durable [`BoundAttempt`]: `policy::ApprovedExecution` is opaque and cannot
//!    be reconstructed from the durable [`ApprovalSnapshot`], so a concrete
//!    adapter needs the same-process value.

use async_trait::async_trait;
use domain::{IdempotencyKey, OrderId, OrderStatus, TradeIntent, TradeSource};
use execution_preview::RevalidationReason;
use market_types::AtomicAmount;
use policy::PolicyEngine;
use storage::OpaqueStore;

use crate::attempt::{ApprovalSnapshot, AttemptPhase, BoundAttempt, OrderAttemptEvent};
use crate::error::LimitEngineError;
use crate::fill::FillDelta;
use crate::fsm::{apply_transition, is_terminal};
use crate::journal::{AttemptAppendOutcome, DurableLimitOrderStore};
use crate::order::{OrderTransition, StoredLimitOrder};
use crate::prepare::{
    prepare_attempt, AttemptTrust, PrepareAttemptInput, PreparedAttempt, PreparedAttemptOutcome,
};
use crate::store::{AppendOutcome, LimitOrderStore};
use crate::trigger::{evaluate_trigger, QuoteOutcome, QuoteProvider, TriggerDecision};

/// Realized net fill reported by the execution seam.
///
/// `Debug` is redacted: it never renders either amount.
#[derive(Clone, PartialEq, Eq)]
pub struct RealizedFill {
    /// Net input actually consumed on chain.
    pub net_input: AtomicAmount,
    /// Net output actually received on chain.
    pub net_output: AtomicAmount,
}

impl std::fmt::Debug for RealizedFill {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RealizedFill { .. }")
    }
}

/// Resolution of one attempt by the execution seam.
///
/// `Debug` is redacted: `Filled` never renders its amounts.
#[derive(Clone, PartialEq, Eq)]
pub enum AttemptResolution {
    /// Chain confirmed a realized fill.
    Filled(RealizedFill),
    /// Submission state unknown: reconcile, never retry.
    Unknown,
    /// Definitive pre-send failure: retryable under the attempt limit.
    FailedBeforeSubmit,
    /// Chain definitively rejected: final.
    Rejected,
}

impl std::fmt::Debug for AttemptResolution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filled(_) => formatter.write_str("Filled { .. }"),
            Self::Unknown => formatter.write_str("Unknown"),
            Self::FailedBeforeSubmit => formatter.write_str("FailedBeforeSubmit"),
            Self::Rejected => formatter.write_str("Rejected"),
        }
    }
}

/// Injected execution seam: binds the payload, signs exactly once, submits at
/// most once. No implementation in this crate signs; it is injected.
#[async_trait]
pub trait AttemptExecutor: Send + Sync {
    /// Deterministic payload digest that `execute` will bind into the signing
    /// request for `intent`. Must be stable for the same intent.
    async fn payload_digest(&self, intent: &TradeIntent) -> Result<[u8; 32], LimitEngineError>;

    /// Signs and submits `attempt` at most once. Must not re-sign or re-submit
    /// an attempt whose `(attempt_key, payload_digest)` is already reserved;
    /// returning `Unknown` forces reconciliation.
    ///
    /// `prepared` is the live same-process preparation value (carrying the
    /// opaque `policy::ApprovedExecution`); `attempt` is the durable binding.
    async fn execute(
        &self,
        prepared: &PreparedAttempt,
        attempt: &BoundAttempt,
        now_ms: i64,
    ) -> AttemptResolution;
}

/// Attempt-level retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptLimits {
    /// Maximum number of attempts an order may reserve before the next
    /// pre-send failure is final. A value of `0` makes every attempt final.
    pub max_attempts_per_order: u32,
}

/// One tick's explicit inputs. All trusted facts arrive here.
pub struct TickInput<'a> {
    /// Order to advance.
    pub order_id: &'a OrderId,
    /// Market signal (chart/threshold candidate). The trigger still decides
    /// exclusively from exact net economics.
    pub signal: bool,
    /// Trade source for the attempt intent.
    pub source: TradeSource,
    /// Trusted backend facts for preparation.
    pub trust: &'a AttemptTrust,
    /// Explicit caller-supplied time in milliseconds.
    pub now_ms: i64,
}

/// Redacted `Debug`; never renders amounts, remaining input, or assets.
pub enum TickOutcome {
    /// Order is terminal (or was moved to `Expired`).
    Terminal {
        /// Terminal status the order holds.
        status: OrderStatus,
    },
    /// No market signal.
    NoSignal,
    /// A signal exists but no safe, limit-satisfying fill is available.
    NotExecutable,
    /// Preparation asked for a requote; order returned to `Active`.
    Requote(RevalidationReason),
    /// Preparation aborted; order returned to `Active`; nothing was signed.
    Abort(RevalidationReason),
    /// Policy refused the attempt (e.g. kill switch off); order returned to
    /// `Active` (or left untouched when the gate was disabled before a write).
    PolicyRejected,
    /// A confirmed fill completed the order.
    Filled {
        /// Attempt that filled the order.
        attempt_seq: u64,
        /// Realized net fill.
        realized: RealizedFill,
    },
    /// A confirmed fill left a viable remainder; order is `PartiallyFilled`.
    PartiallyFilled {
        /// Attempt that produced the partial fill.
        attempt_seq: u64,
        /// Realized net fill.
        realized: RealizedFill,
        /// Remaining input after the fill.
        remaining: AtomicAmount,
    },
    /// Attempt is possibly in flight; reconcile only, never re-execute.
    InFlight {
        /// Attempt that may be in flight.
        attempt_seq: u64,
    },
    /// Definitive pre-send failure; `retryable` is false once the attempt cap
    /// is reached.
    FailedBeforeSubmit {
        /// Attempt that failed before submission.
        attempt_seq: u64,
        /// Whether a later attempt is permitted.
        retryable: bool,
    },
    /// Chain rejected the attempt; order is `FailedFinal`.
    Rejected {
        /// Attempt the chain rejected.
        attempt_seq: u64,
    },
    /// A confirmed fill violated the order's net limit/`min_out`; order is
    /// `FailedFinal` and no non-compliant fill was applied.
    Violation {
        /// Attempt whose fill violated the order's net limit.
        attempt_seq: u64,
    },
}

impl std::fmt::Debug for TickOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render realized amounts, remaining input, attempt sequences, or
        // assets. `status`/`reason` are payload-free enums.
        match self {
            Self::Terminal { status } => formatter
                .debug_struct("Terminal")
                .field("status", status)
                .finish(),
            Self::Requote(reason) => formatter.debug_tuple("Requote").field(reason).finish(),
            Self::Abort(reason) => formatter.debug_tuple("Abort").field(reason).finish(),
            Self::NoSignal => formatter.write_str("NoSignal"),
            Self::NotExecutable => formatter.write_str("NotExecutable"),
            Self::PolicyRejected => formatter.write_str("PolicyRejected"),
            Self::Filled { .. } => formatter.write_str("Filled { .. }"),
            Self::PartiallyFilled { .. } => formatter.write_str("PartiallyFilled { .. }"),
            Self::InFlight { .. } => formatter.write_str("InFlight { .. }"),
            Self::FailedBeforeSubmit { .. } => formatter.write_str("FailedBeforeSubmit { .. }"),
            Self::Rejected { .. } => formatter.write_str("Rejected { .. }"),
            Self::Violation { .. } => formatter.write_str("Violation { .. }"),
        }
    }
}

/// Deterministic limit-order orchestrator over the durable store.
pub struct Orchestrator<S: OpaqueStore, Q: QuoteProvider, E: AttemptExecutor> {
    store: DurableLimitOrderStore<S>,
    provider: Q,
    executor: E,
    policy: PolicyEngine,
    limits: AttemptLimits,
}

impl<S: OpaqueStore, Q: QuoteProvider, E: AttemptExecutor> Orchestrator<S, Q, E> {
    /// Builds an orchestrator from its durable store, pure quote provider,
    /// injected execution seam, policy engine, and attempt limits.
    pub fn new(
        store: DurableLimitOrderStore<S>,
        provider: Q,
        executor: E,
        policy: PolicyEngine,
        limits: AttemptLimits,
    ) -> Self {
        Self {
            store,
            provider,
            executor,
            policy,
            limits,
        }
    }

    /// Runs exactly one deterministic orchestrator tick.
    ///
    /// The returned [`TickOutcome`] is the only channel for the result; the
    /// durable store and attempt journal are the only side effects.
    pub async fn tick(&self, input: TickInput<'_>) -> Result<TickOutcome, LimitEngineError> {
        // 1. Load the authoritative order.
        let Some(mut order) = self.store.load(input.order_id).await? else {
            return Err(LimitEngineError::StoreInvalid);
        };

        // 2. Terminal orders are absorbing.
        if is_terminal(order.order.status) {
            return Ok(TickOutcome::Terminal {
                status: order.order.status,
            });
        }

        // 2b. Kill-switch gate: fail closed before any execution-path write or
        // provider call. `prepare_attempt` re-checks policy as the second layer.
        if !self.policy.is_trading_enabled() {
            return Ok(TickOutcome::PolicyRejected);
        }

        // 3. An `Executing` order already has a durable `Bound` WAL; a tick must
        // never re-sign or re-submit it. Reporting in-flight is the structural
        // crash-safety answer.
        if order.order.status == OrderStatus::Executing {
            let attempt_seq = self
                .store
                .latest_attempt(input.order_id)
                .await?
                .map(|event| event.attempt_seq)
                .unwrap_or(0);
            return Ok(TickOutcome::InFlight { attempt_seq });
        }

        // 4. Normalize a crash-left pre-sign state without any execution side
        // effect: nothing before `Executing` could have signed. A crash-left
        // order already past its deadline must terminate rather than wedge:
        // `apply_transition` rejects every non-terminal target at/after expiry,
        // so `-> Active` would fail the tick forever. `Created`/`Quoting`/
        // `Simulating -> Expired` are all legal domain edges.
        order = match order.order.status {
            OrderStatus::Created | OrderStatus::Quoting | OrderStatus::Simulating => {
                let target = if input.now_ms >= order.order.expires_at_ms {
                    OrderStatus::Expired
                } else {
                    OrderStatus::Active
                };
                let advanced = self.advance(&order, target, input.now_ms).await?;
                if target == OrderStatus::Expired {
                    return Ok(TickOutcome::Terminal {
                        status: OrderStatus::Expired,
                    });
                }
                advanced
            }
            _ => order,
        };

        // 5. Trigger: the decision is made exclusively from exact net economics.
        let trigger = evaluate_trigger(
            &order,
            input.signal,
            &self.provider,
            input.now_ms,
            &input.trust.freshness_policy,
        )?;
        if trigger.order.version != order.version {
            order = self
                .persist_trigger(&order, &trigger.order, input.now_ms)
                .await?;
        }
        if order.order.status == OrderStatus::Expired {
            return Ok(TickOutcome::Terminal {
                status: OrderStatus::Expired,
            });
        }
        let chunk = match trigger.decision {
            TriggerDecision::NoSignal => return Ok(TickOutcome::NoSignal),
            TriggerDecision::NotExecutable => return Ok(TickOutcome::NotExecutable),
            TriggerDecision::Fill(chunk) => chunk,
        };

        // 6. Re-quote the exact chunk. The provider is pure by contract, so the
        // re-quote must reproduce the trigger's probe.
        let quoted = match self.provider.quote(&order, chunk, input.now_ms) {
            QuoteOutcome::Unavailable => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Ok(TickOutcome::NotExecutable);
            }
            QuoteOutcome::Quoted(quoted) => quoted,
        };

        // 7. Deterministic per-attempt identity from the authoritative journal.
        let identity = self.store.next_attempt_identity(input.order_id).await?;

        // 8. Pure preparation: policy -> exact net economics -> locked
        // revalidation. Nothing is persisted on any failure path.
        let prepared = match prepare_attempt(
            &PrepareAttemptInput {
                order: &order,
                source: input.source,
                attempt_seq: identity.attempt_seq,
                attempt_intent_id: identity.intent_id.clone(),
                attempt_key: identity.idempotency_key.clone(),
                chunk,
                quoted: &quoted,
                trust: input.trust,
                now_ms: input.now_ms,
            },
            &self.policy,
        ) {
            Ok(PreparedAttemptOutcome::Ready(prepared)) => prepared,
            Ok(PreparedAttemptOutcome::Requote(reason)) => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Ok(TickOutcome::Requote(reason));
            }
            Ok(PreparedAttemptOutcome::Abort(reason)) => {
                // The locked FSM has no `TriggerCandidate -> FailedFinal` edge, so
                // a final abort parks the order in `Active` with no side effect.
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Ok(TickOutcome::Abort(reason));
            }
            Err(LimitEngineError::PolicyRejected) => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Ok(TickOutcome::PolicyRejected);
            }
            Err(error) => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Err(error);
            }
        };

        // 9. Persist the FSM chain before any side effect. Each step is the
        // exact `apply_transition` output; the store re-derives and compares it.
        order = self
            .advance(&order, OrderStatus::Quoting, input.now_ms)
            .await?;
        order = self
            .advance(&order, OrderStatus::Simulating, input.now_ms)
            .await?;
        order = self
            .advance(&order, OrderStatus::Executing, input.now_ms)
            .await?;

        // 10. Build the durable binding.
        let approval = &prepared.approval;
        let bound = BoundAttempt {
            intent: prepared.intent.clone(),
            route: prepared.route.clone(),
            preview: prepared.preview.preview().clone(),
            approval: ApprovalSnapshot {
                intent_id: approval.intent_id().clone(),
                wallet_ref: approval.wallet_ref().clone(),
                chain: approval.chain().clone(),
                idempotency_key: approval.idempotency_key().clone(),
                expires_at_ms: approval.expires_at_ms(),
                approved_trade_usd: approval.approved_trade_usd().get(),
                approved_at_ms: approval.approved_at_ms(),
            },
            prepared_reference: identity.prepared_reference.clone(),
            payload_digest: self.executor.payload_digest(&prepared.intent).await?,
            attempt_key: prepared.intent.idempotency_key.clone(),
            attempt_seq: identity.attempt_seq,
            nonce: prepared.intent.nonce,
        };
        if bound.payload_digest == [0u8; 32] {
            return Err(LimitEngineError::RecordMalformed);
        }

        // 11. Reserve before sign: the `Bound` event is durable before the
        // executor is ever contacted. A fresh attempt may only be `Applied`.
        let bound_event =
            OrderAttemptEvent::bound(bound.clone(), input.order_id.clone(), input.now_ms);
        match self.store.append_attempt(&bound_event).await? {
            AttemptAppendOutcome::Applied(_) => {}
            AttemptAppendOutcome::AlreadyApplied(_) => {
                return Err(LimitEngineError::PersistenceConflict);
            }
        }

        // 12. Delegate signing/submission to the injected seam at most once.
        let resolution = self.executor.execute(&prepared, &bound, input.now_ms).await;

        // 13. Record the matching attempt phase, then apply the order effect.
        let attempt_seq = identity.attempt_seq;
        let attempt_key = bound.attempt_key.clone();
        match resolution {
            AttemptResolution::Filled(fill) => {
                self.append_phase(
                    input.order_id,
                    attempt_seq,
                    &attempt_key,
                    AttemptPhase::Confirmed,
                    input.now_ms,
                )
                .await?;
                self.resolve_fill(&order, &prepared, &fill, attempt_seq, input.now_ms)
                    .await
            }
            AttemptResolution::Unknown => {
                self.append_phase(
                    input.order_id,
                    attempt_seq,
                    &attempt_key,
                    AttemptPhase::Unknown,
                    input.now_ms,
                )
                .await?;
                // The order stays `Executing`: the next tick reports in-flight and
                // never re-executes (OR-3).
                Ok(TickOutcome::InFlight { attempt_seq })
            }
            AttemptResolution::FailedBeforeSubmit => {
                self.append_phase(
                    input.order_id,
                    attempt_seq,
                    &attempt_key,
                    AttemptPhase::FailedBeforeSubmit,
                    input.now_ms,
                )
                .await?;
                let retryable = attempt_seq < u64::from(self.limits.max_attempts_per_order);
                let target = if retryable {
                    OrderStatus::FailedRetryable
                } else {
                    OrderStatus::FailedFinal
                };
                self.advance(&order, target, input.now_ms).await?;
                Ok(TickOutcome::FailedBeforeSubmit {
                    attempt_seq,
                    retryable,
                })
            }
            AttemptResolution::Rejected => {
                self.append_phase(
                    input.order_id,
                    attempt_seq,
                    &attempt_key,
                    AttemptPhase::Rejected,
                    input.now_ms,
                )
                .await?;
                self.advance(&order, OrderStatus::FailedFinal, input.now_ms)
                    .await?;
                Ok(TickOutcome::Rejected { attempt_seq })
            }
        }
    }

    /// Applies a confirmed fill only when it satisfies the order's net limit and
    /// matches the bound chunk; otherwise the order fails final with no ledger
    /// mutation (OR-4).
    async fn resolve_fill(
        &self,
        order: &StoredLimitOrder,
        prepared: &PreparedAttempt,
        fill: &RealizedFill,
        attempt_seq: u64,
        at_ms: i64,
    ) -> Result<TickOutcome, LimitEngineError> {
        if fill.net_input != prepared.intent.amount || fill.net_output < prepared.min_out.amount {
            self.advance(order, OrderStatus::FailedFinal, at_ms).await?;
            return Ok(TickOutcome::Violation { attempt_seq });
        }

        let remaining_after = order
            .order
            .remaining_input
            .get()
            .checked_sub(fill.net_input.get())
            .ok_or(LimitEngineError::RemainingUnderflow)?;
        let remaining_after = AtomicAmount::new(remaining_after);
        let delta = FillDelta {
            simulated_net_input: fill.net_input,
            simulated_net_output: fill.net_output,
            remaining_after,
        };
        let target = if remaining_after.is_zero() {
            OrderStatus::Filled
        } else {
            OrderStatus::PartiallyFilled
        };
        let next = apply_transition(order, target, Some(&delta), at_ms)?;
        let applied = self
            .persist_transition(order, &next, target, Some(delta), at_ms)
            .await?;

        // `apply_transition` may coerce `PartiallyFilled` to `Expired` past the
        // deadline (recording the fill) and `Expired` with zero remaining to
        // `Filled`; report the effective post-state.
        match applied.order.status {
            OrderStatus::Filled => Ok(TickOutcome::Filled {
                attempt_seq,
                realized: fill.clone(),
            }),
            OrderStatus::PartiallyFilled => Ok(TickOutcome::PartiallyFilled {
                attempt_seq,
                realized: fill.clone(),
                remaining: applied.order.remaining_input,
            }),
            status => Ok(TickOutcome::Terminal { status }),
        }
    }

    /// Persists exactly one transition, accepting both the applied and the
    /// idempotent already-applied outcomes as success.
    async fn persist_transition(
        &self,
        current: &StoredLimitOrder,
        next: &StoredLimitOrder,
        to: OrderStatus,
        fill: Option<FillDelta>,
        at_ms: i64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        let transition = OrderTransition {
            order_id: current.order.id.clone(),
            from: current.order.status,
            to,
            transition_seq: current
                .last_transition_seq
                .checked_add(1)
                .ok_or(LimitEngineError::ArithmeticOverflow)?,
            fill,
            at_ms,
        };
        match self
            .store
            .append_transition(current.version, &transition, next)
            .await?
        {
            AppendOutcome::Applied(applied) => Ok(applied),
            AppendOutcome::AlreadyApplied(authoritative) => Ok(authoritative),
        }
    }

    /// Persists a single `apply_transition` step, computing `next` itself.
    async fn advance(
        &self,
        current: &StoredLimitOrder,
        to: OrderStatus,
        at_ms: i64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        let next = apply_transition(current, to, None, at_ms)?;
        self.persist_transition(current, &next, to, None, at_ms)
            .await
    }

    /// Persists the state change an [`evaluate_trigger`] outcome represents.
    ///
    /// `TriggerCandidate` and `Expired` are single transitions. A revert to
    /// `Active` may be two transitions (`Active -> TriggerCandidate -> Active`,
    /// or `PartiallyFilled`/`FailedRetryable -> TriggerCandidate -> Active`), or
    /// one when the order was already a `TriggerCandidate`; the exact
    /// `apply_transition` chain is replayed so every durable record is the
    /// store's own re-derived output.
    async fn persist_trigger(
        &self,
        current: &StoredLimitOrder,
        target: &StoredLimitOrder,
        at_ms: i64,
    ) -> Result<StoredLimitOrder, LimitEngineError> {
        if target.version == current.version {
            return Ok(current.clone());
        }
        match target.order.status {
            OrderStatus::TriggerCandidate | OrderStatus::Expired => {
                let next = apply_transition(current, target.order.status, None, at_ms)?;
                self.persist_transition(current, &next, target.order.status, None, at_ms)
                    .await
            }
            OrderStatus::Active => {
                let candidate = if current.order.status == OrderStatus::TriggerCandidate {
                    current.clone()
                } else {
                    let next =
                        apply_transition(current, OrderStatus::TriggerCandidate, None, at_ms)?;
                    self.persist_transition(
                        current,
                        &next,
                        OrderStatus::TriggerCandidate,
                        None,
                        at_ms,
                    )
                    .await?
                };
                let reverted = apply_transition(&candidate, OrderStatus::Active, None, at_ms)?;
                self.persist_transition(&candidate, &reverted, OrderStatus::Active, None, at_ms)
                    .await
            }
            // `evaluate_trigger` can only produce the outcomes above for a
            // non-terminal input; anything else is a store/engine inconsistency.
            _ => Err(LimitEngineError::StoreInvalid),
        }
    }

    /// Appends one attempt-phase event, treating the idempotent already-applied
    /// outcome as success.
    async fn append_phase(
        &self,
        order_id: &OrderId,
        attempt_seq: u64,
        attempt_key: &IdempotencyKey,
        phase: AttemptPhase,
        at_ms: i64,
    ) -> Result<(), LimitEngineError> {
        let event = OrderAttemptEvent::phase(
            order_id.clone(),
            attempt_seq,
            attempt_key.clone(),
            phase,
            None,
            at_ms,
        );
        match self.store.append_attempt(&event).await? {
            AttemptAppendOutcome::Applied(_) | AttemptAppendOutcome::AlreadyApplied(_) => Ok(()),
        }
    }
}
