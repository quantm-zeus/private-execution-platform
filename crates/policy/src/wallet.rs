//! Durable, per-wallet trading limits and the strong-confirmation rule for
//! relaxing them.
//!
//! `PolicyLimits` is the process-global engine shape; this module is the
//! *persisted, per-wallet* policy record the wallet-limits backend reads and
//! writes. It owns three things the PRD requires:
//!
//! 1. A validated [`WalletLimits`] record (bounds, allowed chains/venues).
//! 2. A change classifier that distinguishes a **tightening** (safe, applied
//!    immediately) from a **relaxation** (raising a cap or adding a chain/venue),
//!    which requires [`Confirmation::WebStrong`], i.e. the owner's fresh
//!    re-authentication on the private web channel.
//! 3. A [`WalletPolicyStore`] contract with a version CAS and idempotent retry,
//!    plus an in-memory implementation. A durable Postgres adapter can implement
//!    the same trait (not included in this crate); the contract and the
//!    confirmation rule are what this crate proves.
//!
//! No generic signing or transfer capability is named here. Wallet-policy writes
//! are a control-plane mutation, not a capital movement.
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use chain_types::ChainId;
use domain::WalletRef;
use market_types::Bps;
use thiserror::Error;

use crate::{PolicyLimits, UsdMicros};

/// Durable, owner-scoped wallet trading limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletLimits {
    /// Wallet these limits apply to.
    pub wallet_ref: WalletRef,
    /// Maximum notional per trade, in USD micros.
    pub max_trade_usd: UsdMicros,
    /// Maximum rolling-hour turnover, in USD micros.
    pub max_hourly_turnover_usd: UsdMicros,
    /// Maximum rolling-day turnover, in USD micros.
    pub max_daily_turnover_usd: UsdMicros,
    /// Maximum buy tax.
    pub max_buy_tax: Bps,
    /// Maximum sell tax.
    pub max_sell_tax: Bps,
    /// Maximum price impact.
    pub max_price_impact: Bps,
    /// Maximum slippage.
    pub max_slippage: Bps,
    /// Chains this wallet may trade.
    pub allowed_chains: HashSet<ChainId>,
    /// Venues this wallet may trade on.
    pub allowed_venues: HashSet<String>,
}

impl WalletLimits {
    /// Validates structural invariants, mirroring [`PolicyLimits::validate`].
    pub fn validate(&self) -> Result<(), WalletPolicyError> {
        if self.max_trade_usd.get() == 0
            || self.max_hourly_turnover_usd < self.max_trade_usd
            || self.max_daily_turnover_usd < self.max_trade_usd
            || self.max_hourly_turnover_usd > self.max_daily_turnover_usd
        {
            return Err(WalletPolicyError::InvalidLimits);
        }
        if self.allowed_chains.is_empty() {
            return Err(WalletPolicyError::InvalidLimits);
        }
        if self
            .allowed_venues
            .iter()
            .any(|venue| venue.trim().is_empty())
        {
            return Err(WalletPolicyError::InvalidLimits);
        }
        Ok(())
    }

    /// Projects the record onto the process-global engine shape.
    pub fn to_policy_limits(&self) -> PolicyLimits {
        PolicyLimits {
            max_trade_usd: self.max_trade_usd,
            max_hourly_turnover_usd: self.max_hourly_turnover_usd,
            max_daily_turnover_usd: self.max_daily_turnover_usd,
            max_buy_tax: self.max_buy_tax,
            max_sell_tax: self.max_sell_tax,
            max_price_impact: self.max_price_impact,
            max_slippage: self.max_slippage,
            allowed_chains: self.allowed_chains.clone(),
            allowed_venues: self.allowed_venues.clone(),
        }
    }
}

/// How a proposed change relates to the current limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsChange {
    /// No effective change.
    Unchanged,
    /// Every changed dimension is strictly safer.
    Tightening,
    /// At least one dimension is looser and none is tighter.
    Relaxation,
    /// At least one looser and at least one tighter dimension.
    Mixed,
}

impl LimitsChange {
    /// Whether applying this change needs a fresh web re-authentication.
    ///
    /// A [`LimitsChange::Relaxation`] or [`LimitsChange::Mixed`] change may
    /// loosen a cap, so both require strong confirmation; a pure tightening (and
    /// a no-op) does not.
    pub fn requires_strong_confirmation(self) -> bool {
        matches!(self, Self::Relaxation | Self::Mixed)
    }
}

/// Evidence of the owner's fresh re-authentication on the web channel.
///
/// This is a data contract, not a cryptographic primitive: the trusted web
/// handler mints it after its own re-authentication ceremony succeeds. No
/// agent/MCP/Telegram path can reach it, because `agent-commands` has no policy
/// dependency and exposes no way to construct one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebStrongConfirmation {
    verified_at_ms: i64,
}

impl WebStrongConfirmation {
    /// Mints a confirmation stamped by the trusted web re-authentication handler.
    pub fn from_web_reauthentication(verified_at_ms: i64) -> Self {
        Self { verified_at_ms }
    }

    /// When the re-authentication was verified.
    pub fn verified_at_ms(&self) -> i64 {
        self.verified_at_ms
    }
}

/// Confirmation supplied with a wallet-policy write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Confirmation {
    /// No strong confirmation was performed.
    #[default]
    None,
    /// The owner re-authenticated on the web channel.
    WebStrong(WebStrongConfirmation),
}

impl Confirmation {
    /// Whether a strong confirmation is present.
    pub fn is_strong(&self) -> bool {
        matches!(self, Self::WebStrong(_))
    }
}

/// One versioned wallet-policy record as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletPolicyRecord {
    /// The stored limits.
    pub limits: WalletLimits,
    /// Monotonic version, starting at 1 for the first applied change.
    pub version: u64,
}

/// A proposed, version-guarded wallet-policy write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletLimitsChange {
    /// The wallet being changed; must match `next.wallet_ref`.
    pub wallet_ref: WalletRef,
    /// The desired limits.
    pub next: WalletLimits,
    /// The version the caller observed. `0` means "no record yet".
    pub expected_version: u64,
    /// Caller-supplied idempotency key for a retried write.
    pub idempotency_key: String,
}

/// Wallet-policy failure taxonomy. Redacted: no values are rendered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletPolicyError {
    /// The limits violate a structural invariant.
    #[error("invalid wallet limits")]
    InvalidLimits,
    /// The change did not name the same wallet as its record.
    #[error("wallet policy change does not match its wallet")]
    WalletMismatch,
    /// The observed version is stale (a concurrent write landed first).
    #[error("wallet policy version conflict")]
    VersionConflict,
    /// Relaxing limits requires a fresh web strong confirmation.
    #[error("relaxing wallet limits requires strong confirmation")]
    StrongConfirmationRequired,
    /// The change carries an empty idempotency key.
    #[error("wallet policy change requires an idempotency key")]
    MissingIdempotencyKey,
    /// Trading is disabled, so no policy mutation is admitted.
    #[error("trading disabled")]
    TradingDisabled,
    /// The store is unavailable.
    #[error("wallet policy store unavailable")]
    Unavailable,
}

/// Classifies a proposed change against the current record.
///
/// A **missing** current record is classified [`LimitsChange::Relaxation`]: with
/// no stored baseline there is nothing to tighten against, so the first write
/// (including one that enables trading for the wallet) requires strong
/// confirmation rather than being applied implicitly.
pub fn classify_limits_change(current: Option<&WalletLimits>, next: &WalletLimits) -> LimitsChange {
    let Some(current) = current else {
        return LimitsChange::Relaxation;
    };
    let mut looser = false;
    let mut tighter = false;

    macro_rules! compare_cap {
        ($field:ident) => {{
            let old = current.$field.get();
            let new = next.$field.get();
            if new > old {
                looser = true;
            } else if new < old {
                tighter = true;
            }
        }};
    }
    compare_cap!(max_trade_usd);
    compare_cap!(max_hourly_turnover_usd);
    compare_cap!(max_daily_turnover_usd);
    compare_cap!(max_buy_tax);
    compare_cap!(max_sell_tax);
    compare_cap!(max_price_impact);
    compare_cap!(max_slippage);

    // Adding an allowed chain/venue is looser; removing one is tighter.
    if !next.allowed_chains.is_subset(&current.allowed_chains) {
        looser = true;
    }
    if !current.allowed_chains.is_subset(&next.allowed_chains) {
        tighter = true;
    }
    if !next.allowed_venues.is_subset(&current.allowed_venues) {
        looser = true;
    }
    if !current.allowed_venues.is_subset(&next.allowed_venues) {
        tighter = true;
    }

    match (looser, tighter) {
        (false, false) => LimitsChange::Unchanged,
        (false, true) => LimitsChange::Tightening,
        (true, false) => LimitsChange::Relaxation,
        (true, true) => LimitsChange::Mixed,
    }
}

/// Durable wallet-policy store contract.
pub trait WalletPolicyStore: Send + Sync {
    /// Reads the wallet's current record, or `None` when unset.
    fn record(
        &self,
        wallet_ref: &WalletRef,
    ) -> Result<Option<WalletPolicyRecord>, WalletPolicyError>;

    /// Applies a version-guarded change, enforcing the strong-confirmation rule.
    ///
    /// A retried write with the same idempotency key and identical target limits
    /// is idempotent: it returns the exact record the original write applied,
    /// instead of a version conflict or the current (later) record. A stale
    /// `expected_version` with *different* limits is
    /// [`WalletPolicyError::VersionConflict`].
    ///
    /// `trading_enabled` is the live `TRADING_ENABLED` gate: a policy write is a
    /// mutation and is refused with [`WalletPolicyError::TradingDisabled`] while
    /// the gate is off, so a disabled deployment cannot widen its own limits.
    fn apply(
        &self,
        change: &WalletLimitsChange,
        confirmation: Confirmation,
        trading_enabled: bool,
    ) -> Result<WalletPolicyRecord, WalletPolicyError>;
}

/// Bound on the in-memory idempotency ledger.
///
/// A production adapter enforces uniqueness in the database; this in-memory
/// store fails closed (unavailable) rather than growing without bound.
pub const MAX_APPLIED_POLICY_KEYS: usize = 4096;

/// In-memory [`WalletPolicyStore`] with a version CAS.
///
/// This is a real, deterministic implementation of the contract (used by the
/// disabled-path and unit tests); a production deployment substitutes a durable
/// Postgres adapter that enforces the same rules transactionally.
#[derive(Default)]
pub struct InMemoryWalletPolicyStore {
    records: Mutex<HashMap<String, (WalletLimits, u64)>>,
    applied: Mutex<HashMap<String, WalletPolicyRecord>>,
}

impl std::fmt::Debug for InMemoryWalletPolicyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryWalletPolicyStore")
            .finish_non_exhaustive()
    }
}

impl InMemoryWalletPolicyStore {
    /// Builds an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl WalletPolicyStore for InMemoryWalletPolicyStore {
    fn record(
        &self,
        wallet_ref: &WalletRef,
    ) -> Result<Option<WalletPolicyRecord>, WalletPolicyError> {
        let records = Self::lock(&self.records);
        Ok(records
            .get(wallet_ref.as_str())
            .map(|(limits, version)| WalletPolicyRecord {
                limits: limits.clone(),
                version: *version,
            }))
    }

    fn apply(
        &self,
        change: &WalletLimitsChange,
        confirmation: Confirmation,
        trading_enabled: bool,
    ) -> Result<WalletPolicyRecord, WalletPolicyError> {
        if !trading_enabled {
            return Err(WalletPolicyError::TradingDisabled);
        }
        if change.idempotency_key.trim().is_empty() {
            return Err(WalletPolicyError::MissingIdempotencyKey);
        }
        if change.wallet_ref != change.next.wallet_ref {
            return Err(WalletPolicyError::WalletMismatch);
        }
        change.next.validate()?;

        let mut records = Self::lock(&self.records);
        let current = records.get(change.wallet_ref.as_str()).cloned();

        // Idempotency is scoped to the wallet, so the same key used by two
        // different wallets cannot collide.
        let scoped_key = format!("{}:{}", change.wallet_ref.as_str(), change.idempotency_key);

        // Idempotent retry: the same key returns the exact record the original
        // write applied, even after an intervening write advanced the version.
        // The same key with a different target is a conflict.
        {
            let applied = Self::lock(&self.applied);
            if let Some(applied_record) = applied.get(&scoped_key) {
                if applied_record.limits == change.next {
                    return Ok(applied_record.clone());
                }
                return Err(WalletPolicyError::VersionConflict);
            }
        }

        let current_limits = current.as_ref().map(|(limits, _)| limits);
        let observed_version = current.as_ref().map(|(_, version)| *version).unwrap_or(0);
        if observed_version != change.expected_version {
            return Err(WalletPolicyError::VersionConflict);
        }

        let classification = classify_limits_change(current_limits, &change.next);
        if classification.requires_strong_confirmation() && !confirmation.is_strong() {
            return Err(WalletPolicyError::StrongConfirmationRequired);
        }

        let version = observed_version
            .checked_add(1)
            .ok_or(WalletPolicyError::Unavailable)?;
        records.insert(
            change.wallet_ref.as_str().to_string(),
            (change.next.clone(), version),
        );
        let applied_record = WalletPolicyRecord {
            limits: change.next.clone(),
            version,
        };
        {
            let mut applied = Self::lock(&self.applied);
            if applied.len() >= MAX_APPLIED_POLICY_KEYS {
                return Err(WalletPolicyError::Unavailable);
            }
            applied.insert(scoped_key, applied_record.clone());
        }
        Ok(applied_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use market_types::Bps;

    fn wallet() -> WalletRef {
        WalletRef::new("wallet-1").expect("wallet")
    }

    fn limits(max_trade_usd: u64) -> WalletLimits {
        WalletLimits {
            wallet_ref: wallet(),
            max_trade_usd: UsdMicros::new(max_trade_usd),
            max_hourly_turnover_usd: UsdMicros::new(max_trade_usd * 5),
            max_daily_turnover_usd: UsdMicros::new(max_trade_usd * 20),
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            allowed_chains: [ChainId::Base].into_iter().collect(),
            allowed_venues: ["uniswap".to_string()].into_iter().collect(),
        }
    }

    fn change(next: WalletLimits, expected_version: u64, key: &str) -> WalletLimitsChange {
        WalletLimitsChange {
            wallet_ref: wallet(),
            next,
            expected_version,
            idempotency_key: key.to_string(),
        }
    }

    fn confirmed() -> Confirmation {
        Confirmation::WebStrong(WebStrongConfirmation::from_web_reauthentication(42))
    }

    #[test]
    fn classification_distinguishes_tightening_from_relaxation() {
        let base = limits(1_000_000);
        assert_eq!(
            classify_limits_change(Some(&base), &limits(1_000_000)),
            LimitsChange::Unchanged
        );
        assert_eq!(
            classify_limits_change(Some(&base), &limits(500_000)),
            LimitsChange::Tightening
        );
        assert_eq!(
            classify_limits_change(Some(&base), &limits(2_000_000)),
            LimitsChange::Relaxation
        );

        // Adding a chain is a relaxation; removing one is a tightening.
        let mut wider = limits(1_000_000);
        wider.allowed_chains.insert(ChainId::Ethereum);
        assert_eq!(
            classify_limits_change(Some(&base), &wider),
            LimitsChange::Relaxation
        );
        let mut narrower = limits(1_000_000);
        narrower.allowed_venues.clear();
        narrower.allowed_venues.insert("local".to_string());
        assert_eq!(
            classify_limits_change(Some(&base), &narrower),
            LimitsChange::Mixed
        );

        // A missing baseline cannot be tightened against, so the first write is a
        // relaxation and requires confirmation.
        assert_eq!(
            classify_limits_change(None, &base),
            LimitsChange::Relaxation
        );
    }

    #[test]
    fn first_write_and_relaxation_require_confirmation_but_tightening_does_not() {
        let store = InMemoryWalletPolicyStore::new();
        // The first write needs strong confirmation.
        assert_eq!(
            store.apply(
                &change(limits(1_000_000), 0, "k1"),
                Confirmation::None,
                true
            ),
            Err(WalletPolicyError::StrongConfirmationRequired)
        );
        let first = store
            .apply(&change(limits(1_000_000), 0, "k1"), confirmed(), true)
            .expect("initial write");
        assert_eq!(first.version, 1);

        // Tightening applies without confirmation.
        let tightened = store
            .apply(&change(limits(500_000), 1, "k2"), Confirmation::None, true)
            .expect("tightening");
        assert_eq!(tightened.version, 2);

        // Relaxation without confirmation fails closed.
        assert_eq!(
            store.apply(
                &change(limits(2_000_000), 2, "k3"),
                Confirmation::None,
                true
            ),
            Err(WalletPolicyError::StrongConfirmationRequired)
        );
        // The rejected write did not advance the version.
        assert_eq!(
            store
                .record(&wallet())
                .expect("record")
                .expect("some")
                .version,
            2
        );

        let relaxed = store
            .apply(&change(limits(2_000_000), 2, "k3"), confirmed(), true)
            .expect("relaxation");
        assert_eq!(relaxed.version, 3);
        assert_eq!(relaxed.limits.max_trade_usd, UsdMicros::new(2_000_000));
    }

    #[test]
    fn disabled_gate_denies_every_policy_write() {
        let store = InMemoryWalletPolicyStore::new();
        assert_eq!(
            store.apply(&change(limits(1_000_000), 0, "k1"), confirmed(), false),
            Err(WalletPolicyError::TradingDisabled)
        );
        assert!(store.record(&wallet()).expect("record").is_none());
    }

    #[test]
    fn stale_version_conflicts_and_retry_returns_the_applied_record() {
        let store = InMemoryWalletPolicyStore::new();
        store
            .apply(&change(limits(1_000_000), 0, "k1"), confirmed(), true)
            .expect("first");
        // Stale version with different limits conflicts.
        assert_eq!(
            store.apply(&change(limits(900_000), 0, "k2"), Confirmation::None, true),
            Err(WalletPolicyError::VersionConflict)
        );
        // Same key and target retried after success is idempotent, even with a
        // refreshed expected_version.
        let retried = store
            .apply(
                &change(limits(1_000_000), 1, "k1"),
                Confirmation::None,
                true,
            )
            .expect("idempotent retry");
        assert_eq!(retried.version, 1);

        // An intervening tightening, then replaying k1 returns k1's applied
        // record, never the intervening one.
        store
            .apply(&change(limits(500_000), 1, "k2"), Confirmation::None, true)
            .expect("tightening");
        let replay = store
            .apply(
                &change(limits(1_000_000), 0, "k1"),
                Confirmation::None,
                true,
            )
            .expect("replay");
        assert_eq!(replay.version, 1);
        assert_eq!(replay.limits.max_trade_usd, UsdMicros::new(1_000_000));
        // The same key with a different target is a conflict.
        assert_eq!(
            store.apply(&change(limits(3_000_000), 2, "k1"), confirmed(), true),
            Err(WalletPolicyError::VersionConflict)
        );
    }

    #[test]
    fn idempotency_keys_are_scoped_per_wallet() {
        let store = InMemoryWalletPolicyStore::new();
        store
            .apply(&change(limits(1_000_000), 0, "shared"), confirmed(), true)
            .expect("wallet-1");
        let mut other = limits(1_000_000);
        other.wallet_ref = WalletRef::new("wallet-2").expect("wallet");
        let record = store
            .apply(
                &WalletLimitsChange {
                    wallet_ref: other.wallet_ref.clone(),
                    next: other,
                    expected_version: 0,
                    idempotency_key: "shared".to_string(),
                },
                confirmed(),
                true,
            )
            .expect("wallet-2 with the same key is independent");
        assert_eq!(record.version, 1);
        assert_eq!(record.limits.wallet_ref.as_str(), "wallet-2");
    }

    #[test]
    fn invalid_and_mismatched_changes_fail_closed() {
        let store = InMemoryWalletPolicyStore::new();
        assert_eq!(
            store.apply(&change(limits(1_000_000), 0, ""), Confirmation::None, true),
            Err(WalletPolicyError::MissingIdempotencyKey)
        );

        let mut other = limits(1_000_000);
        other.wallet_ref = WalletRef::new("wallet-2").expect("wallet");
        assert_eq!(
            store.apply(
                &WalletLimitsChange {
                    wallet_ref: wallet(),
                    next: other,
                    expected_version: 0,
                    idempotency_key: "k".to_string(),
                },
                Confirmation::None,
                true,
            ),
            Err(WalletPolicyError::WalletMismatch)
        );

        let mut zero = limits(1_000_000);
        zero.max_trade_usd = UsdMicros::new(0);
        assert_eq!(
            store.apply(&change(zero, 0, "k"), Confirmation::None, true),
            Err(WalletPolicyError::InvalidLimits)
        );

        // An inconsistent hourly/daily ordering is rejected too.
        let mut inconsistent = limits(1_000_000);
        inconsistent.max_hourly_turnover_usd = UsdMicros::new(500_000_000);
        inconsistent.max_daily_turnover_usd = UsdMicros::new(50_000_000);
        assert_eq!(
            store.apply(&change(inconsistent, 0, "k"), Confirmation::None, true),
            Err(WalletPolicyError::InvalidLimits)
        );
    }

    #[test]
    fn projected_engine_limits_match_the_record() {
        let record = limits(1_000_000);
        let engine = record.to_policy_limits();
        assert_eq!(engine.max_trade_usd, record.max_trade_usd);
        assert_eq!(engine.allowed_chains, record.allowed_chains);
        assert_eq!(record.validate(), Ok(()));
    }
}
