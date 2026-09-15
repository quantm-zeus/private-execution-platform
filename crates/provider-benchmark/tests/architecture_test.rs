//! Architecture pins for the benchmark service crate.

/// The service must stay a pure analytics consumer: no execution, signing,
/// relay, or network dependency may enter its graph. (`routing` transitively
/// links `execution-preview`, but only the pure benchmark comparator is used.)
#[test]
fn no_execution_or_network_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    for forbidden in [
        "market-execution",
        "execution-relay",
        "provider-verification",
        "agent-backend",
        "okx-client",
        "reqwest",
        "hyper",
        "tokio-tungstenite",
        "axum",
        "tonic",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency in provider-benchmark: {forbidden}"
        );
    }
    const { assert!(!provider_benchmark::TRADING_ENABLED) };
}
