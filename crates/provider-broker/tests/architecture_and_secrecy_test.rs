use mcp_adapters::{McpAdapterError, McpServiceId};
use provider_broker::{
    BrokerError, CacheState, CandidateContext, LogicalRequestKey, PositionContext, ProviderHealth,
    ProviderHealthState, ProviderId, RequestContext, ResponseMeta, TRADING_ENABLED,
};

#[test]
fn test_no_direct_upstream_or_network_dependencies() {
    let cargo_toml = include_str!("../Cargo.toml");

    let prohibited_crates = [
        "reqwest",
        "hyper",
        "curl",
        "tungstenite",
        "tokio-tungstenite",
        "ureq",
        "surf",
        "tonic/transport",
        "axum",
        "warp",
        "actix",
        "websocket",
    ];

    for prohibited in prohibited_crates {
        assert!(
            !cargo_toml.contains(&format!("name = \"{prohibited}\""))
                && !cargo_toml.contains(&format!("{prohibited} ="))
                && !cargo_toml.contains(&format!("{prohibited}.")),
            "Violation: broker dependencies must not contain network library '{prohibited}'"
        );
    }
}

#[test]
fn test_no_hardcoded_upstream_endpoints_in_source() {
    let prohibited_endpoints = [
        "api.fomo.family",
        "fomo.family",
        "gmgn.ai",
        "https://",
        "http://",
        "wss://",
        "ws://",
    ];

    let source_files = [
        include_str!("../src/lib.rs"),
        include_str!("../src/broker.rs"),
        include_str!("../src/budget.rs"),
        include_str!("../src/cache.rs"),
        include_str!("../src/circuit.rs"),
        include_str!("../src/clock.rs"),
        include_str!("../src/error.rs"),
        include_str!("../src/key.rs"),
        include_str!("../src/meta.rs"),
        include_str!("../src/policy.rs"),
        include_str!("../src/provider.rs"),
    ];

    for code in source_files {
        for endpoint in prohibited_endpoints {
            assert!(
                !code.contains(endpoint),
                "Violation: broker source must not hardcode upstream endpoint '{endpoint}'"
            );
        }
    }
}

#[test]
fn test_trading_disabled_invariants() {
    const { assert!(!TRADING_ENABLED) };
    const { assert!(!mcp_adapters::TRADING_ENABLED) };
}

#[test]
fn test_error_log_debug_forms_expose_no_secrets_endpoints_or_payloads() {
    let secret = "secret_bearer_token_xyz_98765";
    let endpoint = "https://upstream.provider.internal/v1/stream";
    let raw_payload = r#"{"private_key": "0xdeadbeef1234"}"#;

    let meta = ResponseMeta {
        provider: ProviderId::Gmgn,
        cache_state: CacheState::Miss,
        freshness_ms: None,
        degraded_reason: None,
        health_state: ProviderHealthState::Healthy,
        consecutive_failures: 0,
        request_cost: 2,
    };

    let errors = [
        BrokerError::BudgetExhausted {
            provider: ProviderId::Gmgn,
            meta: meta.clone(),
        },
        BrokerError::CircuitOpen {
            provider: ProviderId::Fomo,
            meta: meta.clone(),
        },
        BrokerError::CooldownActive {
            provider: ProviderId::Fomo,
            meta: meta.clone(),
        },
        BrokerError::PriorityShed {
            provider: ProviderId::Gmgn,
            meta: meta.clone(),
        },
        BrokerError::CandidateNotEligible {
            candidate_id: "candidate-1".into(),
            meta: meta.clone(),
        },
        BrokerError::NegativeCached {
            provider: ProviderId::Gmgn,
            kind: provider_broker::OpaqueFailureKind::ServiceUnavailable,
            meta: meta.clone(),
        },
        BrokerError::Adapter {
            error: McpAdapterError::TransportFailure {
                service: McpServiceId::Gmgn,
            },
            meta: meta.clone(),
        },
    ];

    for err in &errors {
        let display_str = format!("{err}");
        let debug_str = format!("{err:?}");

        for sensitive in [secret, endpoint, raw_payload] {
            assert!(!display_str.contains(sensitive));
            assert!(!debug_str.contains(sensitive));
        }
    }

    // Key Debug formatting test
    let ctx = RequestContext::default()
        .with_candidate(CandidateContext::new("cand_safe", 10, 20))
        .with_position(PositionContext::new("pos_safe"));

    let key = LogicalRequestKey::new(
        ProviderId::Fomo,
        "search_tokens",
        format!("raw_payload={raw_payload}&secret={secret}"),
        &ctx,
    );

    let key_debug = format!("{key:?}");
    assert!(
        !key_debug.contains(secret),
        "key debug must not leak secrets"
    );
    assert!(
        !key_debug.contains(raw_payload),
        "key debug must not leak raw payloads"
    );
    assert!(
        !key_debug.contains(endpoint),
        "key debug must not leak endpoints"
    );

    // ProviderHealth Display and Debug test
    let health = ProviderHealth {
        provider: ProviderId::Fomo,
        state: ProviderHealthState::Healthy,
        consecutive_failures: 0,
        total_requests: 100,
        total_failures: 0,
        circuit_trips: 0,
        available_budget: 100,
    };
    let health_display = format!("{health}");
    let health_debug = format!("{health:?}");
    for sensitive in [secret, endpoint, raw_payload] {
        assert!(!health_display.contains(sensitive));
        assert!(!health_debug.contains(sensitive));
    }
}
