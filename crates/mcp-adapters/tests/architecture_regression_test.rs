//! Architectural regression test.
//!
//! Asserts that:
//! 1. No direct upstream path exists through this crate.
//! 2. No network, HTTP, WebSocket, or RPC upstream client dependencies are included.
//! 3. All service calls are mediated exclusively through the injected [`mcp_adapters::McpTransport`].
//! 4. Trading capabilities are strictly disabled (`TRADING_ENABLED == false`).

#[test]
fn test_no_direct_upstream_or_network_dependencies() {
    let cargo_toml = include_str!("../Cargo.toml");

    // Prohibited network and upstream client libraries
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
            "Violation: crate dependencies must not contain network library '{prohibited}'"
        );
    }
}

#[test]
fn test_no_hardcoded_upstream_endpoints_in_source() {
    // Upstream domain hosts must never appear as direct endpoints in adapter source code
    let fomo_rs = include_str!("../src/fomo.rs");
    let gmgn_rs = include_str!("../src/gmgn.rs");
    let lib_rs = include_str!("../src/lib.rs");
    let transport_rs = include_str!("../src/transport.rs");

    let prohibited_endpoints = [
        "api.fomo.family",
        "fomo.family",
        "gmgn.ai",
        "https://",
        "http://",
        "wss://",
        "ws://",
    ];

    for code in [fomo_rs, gmgn_rs, lib_rs, transport_rs] {
        for endpoint in prohibited_endpoints {
            assert!(
                !code.contains(endpoint),
                "Violation: adapter source must not hardcode upstream endpoint '{endpoint}'"
            );
        }
    }
}

#[test]
fn test_fail_closed_trading_disabled_invariant() {
    // Fail-closed global trading invariant
    assert!(
        !mcp_adapters::TRADING_ENABLED,
        "TRADING_ENABLED must be false"
    );
}

#[test]
fn test_no_generic_string_tool_call_api() {
    // Assert that McpToolCall fields are private and no arbitrary string constructor exists
    let transport_rs = include_str!("../src/transport.rs");
    assert!(
        !transport_rs.contains("pub tool_name: String"),
        "McpToolCall must not expose a public mutable/forged tool_name: String"
    );
    assert!(
        !transport_rs.contains("pub service: McpServiceId"),
        "McpToolCall must not expose public mutable fields"
    );
    assert!(
        !transport_rs.contains("pub arguments: Value"),
        "McpToolCall must not expose public mutable fields"
    );
}
