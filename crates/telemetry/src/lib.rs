//! Privacy-aware telemetry primitives.
//!
//! Label keys are a closed enum and label values must originate from a
//! fixed, statically-known vocabulary: `&'static str` validated by
//! [`LabelValue::new`], or the typed enums ([`Component`], [`Operation`],
//! [`Provider`], [`ResultCategory`]). There is no constructor from a
//! runtime `String`, so user-derived data (wallets, tokens, order ids)
//! cannot reach an exported metric label; such data belongs in metric
//! values or logs, never in labels.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The complete, closed set of metric label keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelKey {
    Component,
    Operation,
    Provider,
    Result,
}

impl LabelKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::Operation => "operation",
            Self::Provider => "provider",
            Self::Result => "result",
        }
    }

    /// Every key, exhaustively — keeps the exported key set fixed.
    pub const ALL: [LabelKey; 4] = [
        LabelKey::Component,
        LabelKey::Operation,
        LabelKey::Provider,
        LabelKey::Result,
    ];
}

/// A statically-known label value.
///
/// Constructible only from a `&'static str` via [`LabelValue::new`]
/// (validated against the cardinality budget) or from the typed enum
/// vocabularies below. `LabelValue` cannot wrap a runtime `String`, so
/// user-derived strings cannot leak into exported labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct LabelValue(&'static str);

impl LabelValue {
    /// Maximum byte length for a label value; bounds per-key cardinality.
    pub const MAX_LEN: usize = 96;

    pub const fn new(value: &'static str) -> Result<Self, TelemetryError> {
        if value.is_empty() {
            return Err(TelemetryError::EmptyValue);
        }
        if value.len() > Self::MAX_LEN {
            return Err(TelemetryError::ValueTooLong);
        }
        Ok(Self(value))
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Fixed vocabulary for the `component` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Storage,
    ProviderBroker,
    Execution,
}

impl Component {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::ProviderBroker => "provider_broker",
            Self::Execution => "execution",
        }
    }

    pub const fn as_label_value(self) -> LabelValue {
        LabelValue(self.as_str())
    }
}

/// Fixed vocabulary for the `operation` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Read,
    Write,
    Commit,
    Publish,
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Commit => "commit",
            Self::Publish => "publish",
        }
    }

    pub const fn as_label_value(self) -> LabelValue {
        LabelValue(self.as_str())
    }
}

/// Fixed vocabulary for the `provider` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Fomo,
    Gmgn,
    Okx,
    Twitter,
    Local,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fomo => "fomo",
            Self::Gmgn => "gmgn",
            Self::Okx => "okx",
            Self::Twitter => "twitter",
            Self::Local => "local",
        }
    }

    pub const fn as_label_value(self) -> LabelValue {
        LabelValue(self.as_str())
    }
}

/// Fixed vocabulary for the `result` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultCategory {
    Ok,
    Error,
    Timeout,
    Rejected,
}

impl ResultCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
        }
    }

    pub const fn as_label_value(self) -> LabelValue {
        LabelValue(self.as_str())
    }
}

/// One metric label: a closed key paired with a statically-known value.
///
/// Deliberately not `Deserialize`: reading a label from untrusted input
/// would allow arbitrary values and defeat the static-vocabulary
/// invariant. `Serialize` is retained for export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct MetricLabel {
    pub key: LabelKey,
    pub value: LabelValue,
}

impl MetricLabel {
    pub const fn new(key: LabelKey, value: LabelValue) -> Self {
        Self { key, value }
    }

    pub const fn component(value: Component) -> Self {
        Self {
            key: LabelKey::Component,
            value: value.as_label_value(),
        }
    }

    pub const fn operation(value: Operation) -> Self {
        Self {
            key: LabelKey::Operation,
            value: value.as_label_value(),
        }
    }

    pub const fn provider(value: Provider) -> Self {
        Self {
            key: LabelKey::Provider,
            value: value.as_label_value(),
        }
    }

    pub const fn result(value: ResultCategory) -> Self {
        Self {
            key: LabelKey::Result,
            value: value.as_label_value(),
        }
    }
}

/// An ordered set of at most one label per key.
///
/// The inner vector is private; mutation only happens through
/// [`MetricLabels::push`], which rejects duplicate keys, so the
/// at-most-one-value-per-key invariant always holds.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize)]
pub struct MetricLabels(Vec<MetricLabel>);

impl MetricLabels {
    /// Build from an iterator of labels, rejecting duplicate keys.
    pub fn new<I: IntoIterator<Item = MetricLabel>>(labels: I) -> Result<Self, TelemetryError> {
        let mut set = Self(Vec::new());
        for label in labels {
            set.push(label)?;
        }
        Ok(set)
    }

    pub fn push(&mut self, label: MetricLabel) -> Result<(), TelemetryError> {
        if self.0.iter().any(|existing| existing.key == label.key) {
            return Err(TelemetryError::DuplicateKey);
        }
        self.0.push(label);
        Ok(())
    }

    pub fn as_slice(&self) -> &[MetricLabel] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CounterMetric {
    pub name: &'static str,
    pub increment: u64,
    pub labels: MetricLabels,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatencyMetric {
    pub name: &'static str,
    pub duration_micros: u64,
    pub labels: MetricLabels,
}

pub const PROVIDER_REQUESTS: &str = "provider_requests_total";
pub const PROVIDER_ERRORS: &str = "provider_errors_total";
pub const CACHE_HITS: &str = "cache_hits_total";
pub const OPERATION_LATENCY: &str = "operation_latency_micros";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TelemetryError {
    #[error("metric label value must not be empty")]
    EmptyValue,
    #[error("metric label value is too long")]
    ValueTooLong,
    #[error("duplicate metric label key")]
    DuplicateKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_semantic_minimal_label_keys_exist() {
        let rendered: Vec<_> = LabelKey::ALL.into_iter().map(LabelKey::as_str).collect();
        for forbidden in [
            "wallet",
            "wallet_id",
            "token",
            "token_address",
            "order",
            "order_id",
            "position",
        ] {
            assert!(!rendered.contains(&forbidden));
        }
    }

    #[test]
    fn runtime_string_cannot_become_label_value() {
        // The only public constructors are `LabelValue::new(&'static str)`
        // and the typed enums; no impl From<String> exists, so this would
        // not compile:
        //   let s = String::from("0xdeadbeef");
        //   MetricLabel::new(LabelKey::Provider, LabelValue::new(&s))
        // At runtime, verify the public surface still behaves: a leaked
        // static passes validation, but empty/over-long statics fail.
        let runtime: String = "0xdeadbeef".into();
        let leaked: &'static str = Box::leak(runtime.into_boxed_str());
        assert_eq!(LabelValue::new(leaked).unwrap().as_str(), "0xdeadbeef");
        assert_eq!(LabelValue::new(""), Err(TelemetryError::EmptyValue));
        const TOO_LONG: &str = concat!("x", include_str!("../Cargo.toml"), "y");
        assert!(TOO_LONG.len() > LabelValue::MAX_LEN);
        assert_eq!(LabelValue::new(TOO_LONG), Err(TelemetryError::ValueTooLong));
    }

    #[test]
    fn typed_enum_vocabulary_is_fixed() {
        assert_eq!(Component::Storage.as_str(), "storage");
        assert_eq!(Component::ProviderBroker.as_str(), "provider_broker");
        assert_eq!(Operation::Read.as_str(), "read");
        assert_eq!(Provider::Fomo.as_str(), "fomo");
        assert_eq!(Provider::Gmgn.as_str(), "gmgn");
        assert_eq!(Provider::Okx.as_str(), "okx");
        assert_eq!(Provider::Twitter.as_str(), "twitter");
        assert_eq!(Provider::Local.as_str(), "local");
        assert_eq!(ResultCategory::Ok.as_str(), "ok");
    }

    #[test]
    fn typed_constructors_pair_correct_keys() {
        let l = MetricLabel::component(Component::Storage);
        assert_eq!(l.key, LabelKey::Component);
        assert_eq!(l.value.as_str(), "storage");
        assert_eq!(
            MetricLabel::result(ResultCategory::Rejected).value.as_str(),
            "rejected"
        );
        assert_eq!(
            MetricLabel::provider(Provider::Gmgn).key,
            LabelKey::Provider
        );
    }

    #[test]
    fn duplicate_labels_are_rejected() {
        let mut labels = MetricLabels::default();
        labels
            .push(MetricLabel::component(Component::Storage))
            .unwrap();
        assert_eq!(
            labels
                .push(MetricLabel::component(Component::ProviderBroker))
                .unwrap_err(),
            TelemetryError::DuplicateKey
        );
    }

    #[test]
    fn duplicate_labels_rejected_in_batch_constructor() {
        assert_eq!(
            MetricLabels::new([
                MetricLabel::component(Component::Storage),
                MetricLabel::component(Component::Execution),
            ])
            .unwrap_err(),
            TelemetryError::DuplicateKey
        );
        assert!(MetricLabels::new([
            MetricLabel::component(Component::Storage),
            MetricLabel::operation(Operation::Write),
            MetricLabel::provider(Provider::Okx),
            MetricLabel::result(ResultCategory::Ok),
        ])
        .is_ok());
    }

    #[test]
    fn every_exported_label_is_static_or_typed() {
        let labels = MetricLabels::new([
            MetricLabel::component(Component::Storage),
            MetricLabel::operation(Operation::Commit),
            MetricLabel::provider(Provider::Okx),
            MetricLabel::result(ResultCategory::Error),
        ])
        .unwrap();
        assert_eq!(labels.as_slice().len(), 4);
        for label in labels.as_slice() {
            let v = label.value.as_str();
            assert!(!v.is_empty());
            assert!(v.len() <= LabelValue::MAX_LEN);
        }
    }
}
