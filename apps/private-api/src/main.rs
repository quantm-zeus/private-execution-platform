use std::net::SocketAddr;
use std::sync::Arc;

use private_api::opaque::{self, OpaqueServiceState};
use private_api::relay;
use private_api::{router, OpaqueSystemClock, PrivateApiConfig, PrivateApiState};
use service_identity::ServiceIdentityConfig;

fn parse_bind_addr(value: &str) -> Result<SocketAddr, std::io::Error> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| std::io::Error::other("invalid bind address"))?;
    if !address.ip().is_loopback() {
        return Err(std::io::Error::other(
            "private api must bind to loopback in Phase 0",
        ));
    }
    Ok(address)
}

/// Optional internal mTLS relay identity. All four values must be present to
/// enable the encrypted relay; otherwise the private API serves only its
/// HTTP auth/artifact boundary and the edge stays fail-closed.
fn optional_relay_identity() -> Option<ServiceIdentityConfig> {
    let cert_chain_path = std::env::var("PRIVATE_API_TLS_CERT").ok()?;
    let private_key_path = std::env::var("PRIVATE_API_TLS_KEY").ok()?;
    let ca_path = std::env::var("PRIVATE_API_TLS_CA").ok()?;
    let expected_peer_dns = std::env::var("PRIVATE_API_EDGE_DNS").ok()?;
    if cert_chain_path.is_empty()
        || private_key_path.is_empty()
        || ca_path.is_empty()
        || expected_peer_dns.is_empty()
    {
        return None;
    }
    Some(ServiceIdentityConfig {
        cert_chain_path: cert_chain_path.into(),
        private_key_path: private_key_path.into(),
        ca_path: ca_path.into(),
        expected_peer_dns,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rp_id = std::env::var("PRIVATE_RP_ID")?;
    let origin = std::env::var("PRIVATE_ORIGIN")?;
    let config = PrivateApiConfig {
        rp_id,
        origin,
        challenge_ttl_ms: 60_000,
        session_ttl_ms: 15 * 60_000,
        artifact_grant_ttl_ms: 60_000,
    };
    let session_ttl_ms = config.session_ttl_ms;
    let state = PrivateApiState::production(config)
        .map_err(|_| std::io::Error::other("private api configuration invalid"))?;

    // TRADING_ENABLED=false remains fail-closed: the encrypted command surface
    // is built with no backend and an all-false capability document until the
    // operator wires the Trading Core composition. Reads/previews stay denied.
    let opaque_state = OpaqueServiceState::fail_closed(
        state.sessions(),
        Arc::new(OpaqueSystemClock),
        session_ttl_ms,
    )
    .map_err(|_| std::io::Error::other("opaque service configuration invalid"))?;

    let relay_bind = std::env::var("PRIVATE_API_RELAY_BIND_ADDR").unwrap_or_default();
    if !relay_bind.is_empty() {
        if let Some(identity) = optional_relay_identity() {
            let relay_address = parse_bind_addr(&relay_bind)?;
            let tls = relay::server_tls_config(&identity)
                .map_err(|_| std::io::Error::other("relay identity invalid"))?;
            let relay_router = opaque::relay_tls_router_with(opaque_state, tls)
                .map_err(|_| std::io::Error::other("relay TLS configuration invalid"))?;
            tokio::spawn(async move {
                // A failed relay listener must not take down the HTTP boundary;
                // the edge already fails closed when the relay is unreachable.
                let _ = relay_router.serve(relay_address).await;
            });
        }
    }

    let bind =
        std::env::var("PRIVATE_API_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let address = parse_bind_addr(&bind)?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase0_bind_must_be_loopback() {
        assert!(parse_bind_addr("127.0.0.1:8081").is_ok());
        assert!(parse_bind_addr("[::1]:8081").is_ok());
        assert!(parse_bind_addr("0.0.0.0:8081").is_err());
        assert!(parse_bind_addr("192.0.2.1:8081").is_err());
    }
}
