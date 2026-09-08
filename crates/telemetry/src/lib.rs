//! Privacy-aware telemetry primitives.
//!
//! Label keys, label values, and metric names are all closed enums with
//! private representations. There is no public constructor that accepts
//! caller-supplied strings: a runtime `String` (including one that has
//! been `Box::leak`ed into a `&'static str`) cannot reach an exported
//! metric label or metric name. User-derived data belongs in metric
//! values or logs, never in telemetry labels or names.

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
/// The field is private and there is no public string constructor, so
/// `LabelValue` can only originate from the fixed enum vocabularies
/// below. This closes the `Box::leak` escape: caller-controlled
/// `String` data cannot become a label value, even if leaked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct LabelValue(&'static str);

impl LabelValue {
    /// Maximum byte length for a label value; bounds per-key cardinality.
    pub const MAX_LEN: usize = 96;

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

/// One metric label: a closed key paired with a closed-vocabulary value.
///
/// The fields are private and generic construction is private; external
/// callers can only create a label through the typed key constructors.
/// Deliberately not `Deserialize`: reading a label from untrusted input
/// would allow arbitrary values and defeat the static-vocabulary
/// invariant. `Serialize` is retained for export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct MetricLabel {
    key: LabelKey,
    value: LabelValue,
}

impl MetricLabel {
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

    pub const fn key(&self) -> LabelKey {
        self.key
    }

    pub const fn value(&self) -> LabelValue {
        self.value
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

/// The complete, closed set of exported metric names.
///
/// The inner string is private and there is no public constructor from
/// caller-supplied data, closing the same `Box::leak` escape that a
/// public `&'static str` name field would expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum MetricName {
    ProviderRequests,
    ProviderErrors,
    CacheHits,
    OperationLatency,
}

impl MetricName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderRequests => "provider_requests_total",
            Self::ProviderErrors => "provider_errors_total",
            Self::CacheHits => "cache_hits_total",
            Self::OperationLatency => "operation_latency_micros",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CounterMetric {
    name: MetricName,
    increment: u64,
    labels: MetricLabels,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatencyMetric {
    name: MetricName,
    duration_micros: u64,
    labels: MetricLabels,
}

impl CounterMetric {
    pub const fn new(name: MetricName, increment: u64, labels: MetricLabels) -> Self {
        Self {
            name,
            increment,
            labels,
        }
    }

    pub const fn name(&self) -> MetricName {
        self.name
    }

    pub const fn increment(&self) -> u64 {
        self.increment
    }

    pub const fn labels(&self) -> &MetricLabels {
        &self.labels
    }
}

impl LatencyMetric {
    pub const fn new(name: MetricName, duration_micros: u64, labels: MetricLabels) -> Self {
        Self {
            name,
            duration_micros,
            labels,
        }
    }

    pub const fn name(&self) -> MetricName {
        self.name
    }

    pub const fn duration_micros(&self) -> u64 {
        self.duration_micros
    }

    pub const fn labels(&self) -> &MetricLabels {
        &self.labels
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TelemetryError {
    #[error("duplicate metric label key")]
    DuplicateKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A privacy attacker takes runtime input and forces it into a
    /// `&'static str` via `Box::leak`. The public API offers no method
    /// accepting `&'static str`, so this attack cannot create a label
    /// value, label, or metric name. These calls intentionally exercise
    /// only the public surface; if a string-accepting constructor is
    /// ever added, a leaked runtime string must not be able to reach it.
    #[test]
    fn leaked_runtime_string_has_no_public_route_into_telemetry() {
        let runtime: String = "0xdeadbeef".into();
        let leaked: &'static str = Box::leak(runtime.into_boxed_str());

        // Every public construction path requires a closed enum. The
        // following lines show the actual surface and therefore compile;
        // none of them accepts `leaked`.
        let labels = MetricLabels::new([
            MetricLabel::component(Component::Storage),
            MetricLabel::operation(Operation::Commit),
            MetricLabel::provider(Provider::Okx),
            MetricLabel::result(ResultCategory::Error),
        ])
        .unwrap();
        let counter = CounterMetric::new(MetricName::ProviderRequests, 1, MetricLabels::default());
        let latency = LatencyMetric::new(MetricName::OperationLatency, 123, labels.clone());

        assert!(!counter.name().as_str().contains(leaked));
        assert!(!latency.labels().as_slice().is_empty());
        assert!(labels
            .as_slice()
            .iter()
            .all(|label| !label.value().as_str().contains(leaked)));
    }

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
    fn metric_names_are_the_fixed_closed_vocabulary() {
        let names = [
            MetricName::ProviderRequests.as_str(),
            MetricName::ProviderErrors.as_str(),
            MetricName::CacheHits.as_str(),
            MetricName::OperationLatency.as_str(),
        ];
        assert_eq!(
            names,
            [
                "provider_requests_total",
                "provider_errors_total",
                "cache_hits_total",
                "operation_latency_micros",
            ]
        );
        assert!(names.iter().all(|name| !name.is_empty()));
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
        assert_eq!(l.key(), LabelKey::Component);
        assert_eq!(l.value().as_str(), "storage");
        assert_eq!(
            MetricLabel::result(ResultCategory::Rejected)
                .value()
                .as_str(),
            "rejected"
        );
        assert_eq!(
            MetricLabel::provider(Provider::Gmgn).key(),
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
            let v = label.value().as_str();
            assert!(!v.is_empty());
            assert!(v.len() <= LabelValue::MAX_LEN);
        }
    }

    #[test]
    fn metrics_expose_read_only_closed_names() {
        let counter = CounterMetric::new(MetricName::CacheHits, 3, MetricLabels::default());
        assert_eq!(counter.name(), MetricName::CacheHits);
        assert_eq!(counter.name().as_str(), "cache_hits_total");
        assert_eq!(counter.increment(), 3);
        let latency = LatencyMetric::new(MetricName::OperationLatency, 42, MetricLabels::default());
        assert_eq!(latency.name(), MetricName::OperationLatency);
        assert_eq!(latency.duration_micros(), 42);
    }
}
