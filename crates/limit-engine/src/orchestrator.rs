//! P51 — Phase 5 L3: deterministic limit-order orchestrator tick.
//!
//! This module is the durable, deterministic join point of the landed Phase-5
//! pieces. One [`Orchestrator::tick`] call:
//!
//! 1. loads the authoritative order from the P46 durable store,
//! 2. fails closed on a terminal order,
//! 3. structurally refuses to re-touch an `Executing` order (its `Bound` WAL is
//!    already durable and re-signing is forbidden),
//! 4. fails closed on a disabled trading gate,
//! 5. normalizes a crash-left `Created`/`Quoting`/`Simulating` order to `Active`,
//! 6. evaluates the P45 trigger against the P44/P45 pure economics,
//! 7. re-quotes the exact chunk and runs the P50 preparation core,
//! 8. validates the executor's payload digest, then persists the
//!    `TriggerCandidate -> Quoting -> Simulating -> Executing` chain *before* any
//!    side effect,
//! 9. appends the durable `Bound` attempt (reserve-before-sign),
//! 10. delegates signing/submission to an injected [`AttemptExecutor`], and
//! 11. applies the realized fill / remainder through the P44 FSM + fill ledger.
//!
//! Nothing here signs, submits, reads a clock, uses an RNG, or performs network
//! I/O: every instant is the explicit `now_ms`, and the only capability that can
//! reach a chain is the injected seam. P54 adds best-effort order-event outbox
//! publication: when an optional [`storage::EventBus`] is injected, `tick` and
//! `recover` publish the sealed transition events durably produced by that call
//! after the call's durable writes complete. Publication never fails or rolls
//! back the state machine; the concrete relay adapter is still out of scope.
//!
//! # P54 publication shape
//! The orchestrator stays transport-free: [`Orchestrator::new`] takes no bus and
//! publication is opt-in through [`Orchestrator::with_event_bus`], or callers may
//! publish explicitly with [`Orchestrator::publish_events`]. When a bus is
//! injected, `tick`/`recover` publish once after their durable writes rather than
//! after each individual `apply_transition` step: the watermark write advances
//! the object version, so publishing mid-call would invalidate the in-memory
//! record the remaining steps derive from. The whole call's transitions are
//! already durable before publication runs, so OE-1 still holds.
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
//! 2. The kill-switch gate runs after the terminal *and* `Executing` checks but
//!    before any execution-path write, so a disabled gate still reports
//!    `InFlight` for an already-reserved attempt while leaving a
//!    `Created`/`Quoting` order untouched (no transition persisted) and never
//!    calling the provider.
//! 3. The locked FSM has no `TriggerCandidate -> FailedFinal` edge, so a final
//!    preparation abort parks the order back in `Active` with no side effect.
//! 4. The executor receives the live [`PreparedAttempt`] in addition to the
//!    durable [`BoundAttempt`]: `policy::ApprovedExecution` is opaque and cannot
//!    be reconstructed from the durable [`ApprovalSnapshot`], so a concrete
//!    adapter needs the same-process value.

use std::sync::Arc;

use async_trait::async_trait;
use domain::{IdempotencyKey, OrderId, OrderStatus, TradeIntent, TradeSource};
use execution_preview::RevalidationReason;
use market_types::AtomicAmount;
use policy::PolicyEngine;
use storage::{EventBus, OpaqueStore};

use crate::attempt::{
    ApprovalSnapshot, AttemptPhase, BoundAttempt, OrderAttemptEvent, RealizedFill,
};
use crate::error::LimitEngineError;
use crate::fill::FillDelta;
use crate::fsm::{apply_transition, is_terminal};
use crate::journal::{AttemptAppendOutcome, DurableLimitOrderStore};
use crate::order::{OrderTransition, StoredLimitOrder};
use crate::prepare::{
    min_out_for, prepare_attempt, AttemptTrust, PrepareAttemptInput, PreparedAttempt,
    PreparedAttemptOutcome,
};
use crate::store::{AppendOutcome, LimitOrderStore};
use crate::trigger::{evaluate_trigger, QuoteOutcome, QuoteProvider, TriggerDecision};

/// Transition events published per best-effort outbox pump.
pub const DEFAULT_PUBLISH_BATCH: usize = 32;

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

    /// Queries authoritative chain state for an already-reserved attempt. MUST
    /// NOT sign or submit. Returns `Unknown` when the state cannot be
    /// determined.
    async fn reconcile(&self, attempt: &BoundAttempt, now_ms: i64) -> AttemptResolution;
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

/// Redacted recovery summary; counts only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Non-terminal orders enumerated by the read pass.
    pub open: u32,
    /// Open orders whose latest attempt is non-terminal.
    pub in_flight: u32,
    /// Possibly-sent attempts reconciled through the injected seam.
    pub reconciled: u32,
    /// Confirmed fills applied during this pass.
    pub fills_applied: u32,
    /// Orders closed terminal (`Filled`/`Expired`/`FailedFinal`).
    pub finalized: u32,
    /// Orders advanced to `FailedRetryable`.
    pub retryable: u32,
    /// Orders skipped as untrustworthy by the read pass.
    pub quarantined: u32,
    /// Whether order enumeration hit the hard object cap.
    pub truncated: bool,
    /// Whether the trading gate was disabled, deferring all recovery work.
    pub kill_switch_deferred: bool,
}

/// Effect of applying one attempt resolution to an `Executing` order.
///
/// Internal to the orchestrator: it is the shared vocabulary between
/// [`Orchestrator::tick`] and [`Orchestrator::recover`].
enum AppliedResolution {
    /// A compliant fill was applied; `status` is the effective post-state.
    Filled {
        realized: RealizedFill,
        remaining: AtomicAmount,
        status: OrderStatus,
    },
    /// The attempt may still be in flight; the order stays `Executing`.
    InFlight,
    /// Definitive pre-send failure; `retryable` mirrors the target choice.
    FailedBeforeSubmit { retryable: bool },
    /// The chain rejected the attempt; the order is `FailedFinal`.
    Rejected,
    /// The confirmed fill violated the net limit; the order is `FailedFinal`.
    Violation,
}

/// Folds one applied resolution into the recovery counts.
///
/// `fills_applied` counts successful fills (including a fill that the FSM
/// coerces to `Expired` past the deadline); `finalized` counts orders closed
/// terminal *without* a successful fill, matching the spec's per-case
/// increments.
fn record_applied(applied: AppliedResolution, report: &mut RecoveryReport) {
    match applied {
        AppliedResolution::Filled { .. } => report.fills_applied += 1,
        AppliedResolution::InFlight => {}
        AppliedResolution::FailedBeforeSubmit { retryable: true } => report.retryable += 1,
        AppliedResolution::FailedBeforeSubmit { retryable: false } => report.finalized += 1,
        AppliedResolution::Rejected | AppliedResolution::Violation => report.finalized += 1,
    }
}

/// Sum of the net input of every `Confirmed` event's sealed fill.
///
/// `filled_input` equals the sum of every confirmed fill already applied to the
/// order, so this total tells recovery whether the `Confirmed` event at the head
/// of the stream is already reflected in the ledger. `None` signals an
/// unrecoverable record: checked-arithmetic overflow, or *any* `Confirmed` event
/// without a sealed fill. A legacy P51 `Confirmed` (written before the fill was
/// persisted) makes the applied total unknowable, so recovery must fail closed
/// rather than under-count and mistake an outstanding head fill for one that was
/// already applied.
fn confirmed_input_total(events: &[OrderAttemptEvent]) -> Option<u128> {
    events
        .iter()
        .try_fold(0u128, |total, event| match event.phase {
            AttemptPhase::Confirmed => {
                let fill = event.realized_fill.as_ref()?;
                total.checked_add(fill.net_input.get())
            }
            _ => Some(total),
        })
}

/// Deterministic limit-order orchestrator over the durable store.
pub struct Orchestrator<S: OpaqueStore, Q: QuoteProvider, E: AttemptExecutor> {
    store: DurableLimitOrderStore<S>,
    provider: Q,
    executor: E,
    policy: PolicyEngine,
    limits: AttemptLimits,
    bus: Option<Arc<dyn EventBus>>,
}

impl<S: OpaqueStore, Q: QuoteProvider, E: AttemptExecutor> Orchestrator<S, Q, E> {
    /// Builds an orchestrator from its durable store, pure quote provider,
    /// injected execution seam, policy engine, and attempt limits.
    ///
    /// No event bus is attached, so `tick`/`recover` publish nothing. Opt in with
    /// [`Orchestrator::with_event_bus`], or publish explicitly with
    /// [`Orchestrator::publish_events`].
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
            bus: None,
        }
    }

    /// Attaches (or clears) the outbox event bus used by `tick`/`recover`.
    ///
    /// Publication is always best-effort: a bus or watermark failure is left for
    /// the next `tick`/`recover` to retry and never fails or rolls back the order
    /// state machine (OE-2).
    pub fn with_event_bus(mut self, bus: Option<Arc<dyn EventBus>>) -> Self {
        self.bus = bus;
        self
    }

    /// Publishes up to `max_events` durable pending events for `order_id` on an
    /// explicit `bus`.
    ///
    /// This is the transport-free publication seam: the orchestrator stores no
    /// transport, and callers that do not inject a bus can drive the outbox
    /// directly. It never fails the caller for a bus or watermark error; the
    /// returned count is the number of envelopes the bus accepted.
    pub async fn publish_events(
        &self,
        order_id: &OrderId,
        bus: &dyn EventBus,
        max_events: usize,
    ) -> Result<u32, LimitEngineError> {
        self.store.publish_pending(order_id, bus, max_events).await
    }

    /// Best-effort publication of this order's durable pending events on the
    /// injected bus. Swallows every failure (OE-2); a no-op when no bus is
    /// attached.
    async fn publish_best_effort(&self, order_id: &OrderId) {
        let Some(bus) = &self.bus else {
            return;
        };
        let _ = self
            .store
            .publish_pending(order_id, bus.as_ref(), DEFAULT_PUBLISH_BATCH)
            .await;
    }

    /// Runs exactly one deterministic orchestrator tick.
    ///
    /// The returned [`TickOutcome`] is the only channel for the result; the
    /// durable store and attempt journal are the only side effects. When an
    /// event bus is injected, every transition this tick made durable is
    /// published best-effort before the outcome returns.
    pub async fn tick(&self, input: TickInput<'_>) -> Result<TickOutcome, LimitEngineError> {
        let order_id = input.order_id;
        let result = self.tick_inner(input).await;
        self.publish_best_effort(order_id).await;
        result
    }

    /// The body of [`Orchestrator::tick`], split out so publication runs after
    /// both the success and the failure paths.
    async fn tick_inner(&self, input: TickInput<'_>) -> Result<TickOutcome, LimitEngineError> {
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

        // 3. An `Executing` order already has a durable `Bound` WAL; a tick must
        // never re-sign or re-submit it. Reporting in-flight is the structural
        // crash-safety answer. This must run before the kill-switch gate so a
        // disabled gate cannot mask an in-flight attempt that still needs
        // reconciliation.
        if order.order.status == OrderStatus::Executing {
            let attempt_seq = self
                .store
                .latest_attempt(input.order_id)
                .await?
                .map(|event| event.attempt_seq)
                .unwrap_or(0);
            return Ok(TickOutcome::InFlight { attempt_seq });
        }

        // 3b. Kill-switch gate: fail closed before any execution-path write or
        // provider call, but after the in-flight check so it cannot mask an
        // `Executing` order. `prepare_attempt` re-checks policy as the second
        // layer.
        if !self.policy.is_trading_enabled() {
            return Ok(TickOutcome::PolicyRejected);
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

        // 9. Resolve the executor's payload digest *before* persisting any part
        // of the execution chain. A digest error or a zero digest must not leave
        // the order durably `Executing` with no `Bound` attempt, which would
        // wedge it forever. The revert below restores the `Active` state that
        // `prepare_attempt` saw, so a later tick can retry from scratch.
        let payload_digest = match self.executor.payload_digest(&prepared.intent).await {
            Ok(digest) if digest != [0u8; 32] => digest,
            Ok(_) => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Err(LimitEngineError::RecordMalformed);
            }
            Err(error) => {
                self.advance(&order, OrderStatus::Active, input.now_ms)
                    .await?;
                return Err(error);
            }
        };

        // 10. Persist the FSM chain before any side effect. Each step is the
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

        // 11. Build the durable binding.
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
            payload_digest,
            attempt_key: prepared.intent.idempotency_key.clone(),
            attempt_seq: identity.attempt_seq,
            nonce: prepared.intent.nonce,
        };

        // 12. Reserve before sign: the `Bound` event is durable before the
        // executor is ever contacted. A fresh attempt may only be `Applied`.
        let bound_event =
            OrderAttemptEvent::bound(bound.clone(), input.order_id.clone(), input.now_ms);
        match self.store.append_attempt(&bound_event).await? {
            AttemptAppendOutcome::Applied(_) => {}
            AttemptAppendOutcome::AlreadyApplied(_) => {
                return Err(LimitEngineError::PersistenceConflict);
            }
        }

        // 13. Delegate signing/submission to the injected seam at most once.
        let resolution = self.executor.execute(&prepared, &bound, input.now_ms).await;

        // 14. Record the matching attempt phase, then apply the order effect.
        // The exact mapping is the same one `recover` replays, so a live tick
        // and a restart reconciliation cannot drift.
        let attempt_seq = identity.attempt_seq;
        let attempt_key = bound.attempt_key.clone();
        let applied = self
            .apply_resolution(
                &order,
                prepared.intent.amount,
                prepared.min_out.amount.get(),
                attempt_seq,
                &attempt_key,
                Some(AttemptPhase::Bound),
                resolution,
                input.now_ms,
            )
            .await?;
        Ok(match applied {
            AppliedResolution::Filled {
                realized,
                remaining,
                status,
            } => match status {
                OrderStatus::Filled => TickOutcome::Filled {
                    attempt_seq,
                    realized,
                },
                OrderStatus::PartiallyFilled => TickOutcome::PartiallyFilled {
                    attempt_seq,
                    realized,
                    remaining,
                },
                status => TickOutcome::Terminal { status },
            },
            AppliedResolution::InFlight => TickOutcome::InFlight { attempt_seq },
            AppliedResolution::FailedBeforeSubmit { retryable } => {
                TickOutcome::FailedBeforeSubmit {
                    attempt_seq,
                    retryable,
                }
            }
            AppliedResolution::Rejected => TickOutcome::Rejected { attempt_seq },
            AppliedResolution::Violation => TickOutcome::Violation { attempt_seq },
        })
    }

    /// One idempotent startup recovery pass. Never signs or submits.
    ///
    /// Enumerates durable open orders; for every `Executing` order it reads the
    /// authenticated attempt journal and either closes the P51
    /// `Executing`-without-`Bound` window, reconciles a possibly-sent attempt
    /// through the injected seam, or replays a crash-after-`Confirmed`-before-fill
    /// window. The resolution mapping is the same
    /// [`Orchestrator::apply_resolution`] that [`Orchestrator::tick`] uses, so a
    /// live tick and a restart cannot drift.
    ///
    /// When an event bus is injected, every open order's durable pending events
    /// are published best-effort after all recovery writes complete, and the
    /// whole order class is drained once more so a terminal order whose final
    /// event never published is retried too. A publication failure never fails
    /// or rolls back recovery.
    pub async fn recover(&self, now_ms: i64) -> Result<RecoveryReport, LimitEngineError> {
        let outcome = self.store.recover().await?;
        let mut report = RecoveryReport {
            open: outcome.open.len() as u32,
            in_flight: outcome.in_flight.len() as u32,
            reconciled: 0,
            fills_applied: 0,
            finalized: 0,
            retryable: 0,
            quarantined: outcome.quarantined.len() as u32,
            truncated: outcome.truncated,
            kill_switch_deferred: false,
        };

        // Kill switch off: report the classification and defer every write and
        // every executor call. No order is reconciled.
        if !self.policy.is_trading_enabled() {
            report.kill_switch_deferred = true;
            return Ok(report);
        }

        for order in &outcome.open {
            if order.order.status != OrderStatus::Executing {
                continue;
            }
            let events = self.store.read_attempts(&order.order.id).await?;
            self.recover_executing(order, &events, now_ms, &mut report)
                .await?;
        }

        // Best-effort outbox pump for every open order, after all recovery
        // writes complete so a watermark bump cannot perturb an in-flight
        // reconciliation. A failure is retried by the next recover/tick.
        for order in &outcome.open {
            self.publish_best_effort(&order.order.id).await;
        }

        // Terminal orders are absent from `outcome.open`, so a terminal order
        // whose final `Filled`/`FailedFinal` event failed to publish would be
        // unreachable on restart. Drain the whole class once, terminal orders
        // included. This is still best-effort: a bus failure is swallowed and a
        // per-order record fault is skipped, so it can never fail or roll back
        // the recovery above (OE-2).
        if let Some(bus) = &self.bus {
            let _ = self
                .store
                .drain_all_pending(bus.as_ref(), DEFAULT_PUBLISH_BATCH)
                .await;
        }
        Ok(report)
    }

    /// Recovers exactly one `Executing` order from its authenticated attempt
    /// stream.
    async fn recover_executing(
        &self,
        order: &StoredLimitOrder,
        events: &[OrderAttemptEvent],
        now_ms: i64,
        report: &mut RecoveryReport,
    ) -> Result<(), LimitEngineError> {
        // P51 crash window: `Executing` persisted with no attempt event. No
        // executor call ever ran, so this is a definitive pre-send failure: close
        // it retryable / final / expired. Zero attempts were reserved (the crash
        // predates the first `Bound`), so this window does not consume the
        // attempt budget. No attempt event exists to append.
        let Some(latest) = events.last() else {
            return self.close_without_attempt(order, 0, now_ms, report).await;
        };

        // Every later-phase event continues a `Bound` attempt that must still be
        // durable; without it the record is inconsistent and cannot be
        // reconciled safely.
        let bound = events
            .iter()
            .find(|event| {
                event.attempt_seq == latest.attempt_seq && event.phase == AttemptPhase::Bound
            })
            .and_then(|event| event.bound.clone());
        let Some(bound) = bound else {
            self.advance(order, OrderStatus::FailedFinal, now_ms)
                .await?;
            report.finalized += 1;
            return Ok(());
        };

        match latest.phase {
            AttemptPhase::Bound
            | AttemptPhase::Signed
            | AttemptPhase::Submitted
            | AttemptPhase::Unknown => {
                // Possibly sent: reconcile, never re-sign or re-submit.
                let resolution = self.executor.reconcile(&bound, now_ms).await;
                report.reconciled += 1;
                let min_out = min_out_for(&bound.intent, &bound.route)?.amount.get();
                let applied = self
                    .apply_resolution(
                        order,
                        bound.intent.amount,
                        min_out,
                        latest.attempt_seq,
                        &latest.attempt_key,
                        Some(latest.phase),
                        resolution,
                        now_ms,
                    )
                    .await?;
                record_applied(applied, report);
            }
            AttemptPhase::Confirmed => {
                let Some(fill) = latest.realized_fill.clone() else {
                    // Unrecoverable legacy/corrupt record: fail closed with no
                    // ledger mutation.
                    self.advance(order, OrderStatus::FailedFinal, now_ms)
                        .await?;
                    report.finalized += 1;
                    return Ok(());
                };
                // A terminal `Confirmed` at the head of the stream may belong to a
                // *previous* attempt: an order that partially filled can re-enter
                // `Executing` for a new attempt and crash before its `Bound`. The
                // ledger is the discriminator: `filled_input` equals the sum of
                // every confirmed fill already applied, so when it already covers
                // this fill the current window reserved no attempt and must close
                // pre-send instead of replaying a fill (RC-3). When exactly this
                // fill is outstanding, it is the crash-after-Confirmed-before-fill
                // window and is applied once.
                let Some(confirmed_total) = confirmed_input_total(events) else {
                    self.advance(order, OrderStatus::FailedFinal, now_ms)
                        .await?;
                    report.finalized += 1;
                    return Ok(());
                };
                let applied_input = order.filled_input.get();
                if applied_input >= confirmed_total {
                    // The stale head belongs to a prior *reserved* attempt; the
                    // crashed window reserved nothing, so the number of attempts
                    // already reserved is `latest.attempt_seq` (not `+ 1`).
                    return self
                        .close_without_attempt(order, latest.attempt_seq, now_ms, report)
                        .await;
                }
                if confirmed_total - applied_input != fill.net_input.get() {
                    // An outstanding confirmed total that is not exactly this
                    // fill is an inconsistent record; never apply a partial
                    // amount.
                    self.advance(order, OrderStatus::FailedFinal, now_ms)
                        .await?;
                    report.finalized += 1;
                    return Ok(());
                }
                // Crash-after-Confirmed-before-fill: apply the sealed fill
                // exactly once. The phase already exists, so it is not
                // re-appended.
                let min_out = min_out_for(&bound.intent, &bound.route)?.amount.get();
                let applied = self
                    .apply_resolution(
                        order,
                        bound.intent.amount,
                        min_out,
                        latest.attempt_seq,
                        &latest.attempt_key,
                        Some(AttemptPhase::Confirmed),
                        AttemptResolution::Filled(fill),
                        now_ms,
                    )
                    .await?;
                record_applied(applied, report);
            }
            AttemptPhase::FailedBeforeSubmit => {
                let applied = self
                    .apply_resolution(
                        order,
                        bound.intent.amount,
                        bound.intent.amount.get(),
                        latest.attempt_seq,
                        &latest.attempt_key,
                        Some(AttemptPhase::FailedBeforeSubmit),
                        AttemptResolution::FailedBeforeSubmit,
                        now_ms,
                    )
                    .await?;
                record_applied(applied, report);
            }
            AttemptPhase::Rejected => {
                let applied = self
                    .apply_resolution(
                        order,
                        bound.intent.amount,
                        bound.intent.amount.get(),
                        latest.attempt_seq,
                        &latest.attempt_key,
                        Some(AttemptPhase::Rejected),
                        AttemptResolution::Rejected,
                        now_ms,
                    )
                    .await?;
                record_applied(applied, report);
            }
        }
        Ok(())
    }

    /// Closes an `Executing` order whose current window reserved no signable
    /// attempt (`Bound`), as a definitive pre-send failure.
    ///
    /// `attempt_seq` is the number of attempts already reserved: `0` when the
    /// stream is empty (the crash predates the first `Bound`) or
    /// `latest.attempt_seq` when the head is a previous attempt's terminal
    /// event. The failed window reserved nothing, so it is not counted. No
    /// attempt event is appended.
    async fn close_without_attempt(
        &self,
        order: &StoredLimitOrder,
        attempt_seq: u64,
        now_ms: i64,
        report: &mut RecoveryReport,
    ) -> Result<(), LimitEngineError> {
        let target = self.pre_send_target(attempt_seq, now_ms, order.order.expires_at_ms);
        self.advance(order, target, now_ms).await?;
        if target == OrderStatus::FailedRetryable {
            report.retryable += 1;
        } else {
            report.finalized += 1;
        }
        Ok(())
    }

    /// Records one attempt resolution and applies its order effect.
    ///
    /// Single mapping shared by [`Orchestrator::tick`] and
    /// [`Orchestrator::recover`]. `expected_input`/`min_out` are the bound chunk
    /// and net floor; `prior_phase` is the phase already durably recorded for the
    /// attempt. The phase append is skipped when it already matches, which makes
    /// re-running recovery idempotent even for a repeated `Unknown`.
    #[allow(clippy::too_many_arguments)]
    async fn apply_resolution(
        &self,
        order: &StoredLimitOrder,
        expected_input: AtomicAmount,
        min_out: u128,
        attempt_seq: u64,
        attempt_key: &IdempotencyKey,
        prior_phase: Option<AttemptPhase>,
        resolution: AttemptResolution,
        at_ms: i64,
    ) -> Result<AppliedResolution, LimitEngineError> {
        match resolution {
            AttemptResolution::Filled(fill) => {
                if prior_phase != Some(AttemptPhase::Confirmed) {
                    self.append_confirmed(&order.order.id, attempt_seq, attempt_key, &fill, at_ms)
                        .await?;
                }
                self.resolve_fill(order, expected_input, min_out, &fill, at_ms)
                    .await
            }
            AttemptResolution::Unknown => {
                if prior_phase != Some(AttemptPhase::Unknown) {
                    self.append_phase(
                        &order.order.id,
                        attempt_seq,
                        attempt_key,
                        AttemptPhase::Unknown,
                        at_ms,
                    )
                    .await?;
                }
                // The order stays `Executing`: a later tick/recovery reconciles
                // again and never re-executes (OR-3).
                Ok(AppliedResolution::InFlight)
            }
            AttemptResolution::FailedBeforeSubmit => {
                if prior_phase != Some(AttemptPhase::FailedBeforeSubmit) {
                    self.append_phase(
                        &order.order.id,
                        attempt_seq,
                        attempt_key,
                        AttemptPhase::FailedBeforeSubmit,
                        at_ms,
                    )
                    .await?;
                }
                let target = self.pre_send_target(attempt_seq, at_ms, order.order.expires_at_ms);
                self.advance(order, target, at_ms).await?;
                Ok(AppliedResolution::FailedBeforeSubmit {
                    retryable: target == OrderStatus::FailedRetryable,
                })
            }
            AttemptResolution::Rejected => {
                if prior_phase != Some(AttemptPhase::Rejected) {
                    self.append_phase(
                        &order.order.id,
                        attempt_seq,
                        attempt_key,
                        AttemptPhase::Rejected,
                        at_ms,
                    )
                    .await?;
                }
                self.advance(order, OrderStatus::FailedFinal, at_ms).await?;
                Ok(AppliedResolution::Rejected)
            }
        }
    }

    /// Chooses the retryable/terminal target for a definitive pre-send failure.
    ///
    /// `attempt_seq` is the number of attempts already reserved: a new attempt is
    /// allowed iff `attempt_seq < max_attempts_per_order`. The count excludes the
    /// window that just failed, so a crashed window that never reserved a `Bound`
    /// passes the number of prior reservations (or `0` when the stream is empty).
    ///
    /// A retryable failure in an open window becomes `FailedRetryable`; one with
    /// no attempts left is final; a retryable failure past the deadline is
    /// `Expired`, because `apply_transition` expiry-gates every non-terminal
    /// target.
    fn pre_send_target(&self, attempt_seq: u64, now_ms: i64, expires_at_ms: i64) -> OrderStatus {
        let retryable = attempt_seq < u64::from(self.limits.max_attempts_per_order);
        if retryable && now_ms < expires_at_ms {
            OrderStatus::FailedRetryable
        } else if !retryable {
            OrderStatus::FailedFinal
        } else {
            OrderStatus::Expired
        }
    }

    /// Applies a confirmed fill only when it satisfies the order's net limit and
    /// matches the bound chunk; otherwise the order fails final with no ledger
    /// mutation (OR-4).
    async fn resolve_fill(
        &self,
        order: &StoredLimitOrder,
        expected_input: AtomicAmount,
        min_out: u128,
        fill: &RealizedFill,
        at_ms: i64,
    ) -> Result<AppliedResolution, LimitEngineError> {
        if fill.net_input != expected_input || fill.net_output.get() < min_out {
            self.advance(order, OrderStatus::FailedFinal, at_ms).await?;
            return Ok(AppliedResolution::Violation);
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
        Ok(AppliedResolution::Filled {
            realized: fill.clone(),
            remaining: applied.order.remaining_input,
            status: applied.order.status,
        })
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

    /// Appends a `Confirmed` event carrying the realized fill, treating the
    /// idempotent already-applied outcome as success. Recovery can replay the
    /// exact fill from this sealed record after a crash.
    async fn append_confirmed(
        &self,
        order_id: &OrderId,
        attempt_seq: u64,
        attempt_key: &IdempotencyKey,
        fill: &RealizedFill,
        at_ms: i64,
    ) -> Result<(), LimitEngineError> {
        let event = OrderAttemptEvent::confirmed(
            order_id.clone(),
            attempt_seq,
            attempt_key.clone(),
            fill.clone(),
            at_ms,
        );
        match self.store.append_attempt(&event).await? {
            AttemptAppendOutcome::Applied(_) | AttemptAppendOutcome::AlreadyApplied(_) => Ok(()),
        }
    }
}
