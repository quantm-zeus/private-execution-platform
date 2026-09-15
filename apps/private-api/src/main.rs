use std::net::SocketAddr;
use std::sync::Arc;

use auth::passkey::PasskeyCredentialStore;
use private_api::opaque::{self};
use private_api::relay;
use private_api::{
    router, FilePasskeyCredentialStore, OpaqueSystemClock, PrivateApiConfig, PrivateApiState,
};
use service_identity::ServiceIdentityConfig;
use zeroize::Zeroizing;

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

/// Strict boolean environment parse (`true`/`false`; unset uses `default`).
/// Anything else refuses startup so a typo cannot flip a security default.
fn strict_bool_env(name: &str, default: bool) -> Result<bool, std::io::Error> {
    match std::env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => Err(std::io::Error::other(format!(
            "{name} must be true or false"
        ))),
        Err(_) => Ok(default),
    }
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

/// Optional durable passkey credential store. When `PRIVATE_PASSKEY_STORE_PATH`
/// is configured, production passkey authentication is enabled against that
/// file; without it the private API keeps its fail-closed
/// `authenticator: None` default (every auth route answers `503`).
fn optional_passkey_store() -> Result<Option<Arc<dyn PasskeyCredentialStore>>, std::io::Error> {
    let path = match std::env::var("PRIVATE_PASSKEY_STORE_PATH") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let store = FilePasskeyCredentialStore::open(path)
        .map_err(|_| std::io::Error::other("passkey credential store invalid"))?;
    Ok(Some(Arc::new(store)))
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

    // Production passkey composition. The operator bootstrap secret is only
    // meaningful together with a durable store (otherwise an enrolled credential
    // could not survive a restart), so a secret without a store refuses startup
    // rather than silently presenting a dead enrollment surface.
    let passkey_store = optional_passkey_store()?;
    let enrollment_secret = std::env::var("PRIVATE_PASSKEY_ENROLL_SECRET")
        .ok()
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    let allow_additional_credentials = strict_bool_env("PRIVATE_PASSKEY_ALLOW_ADDITIONAL", false)?;
    if passkey_store.is_none() && (enrollment_secret.is_some() || allow_additional_credentials) {
        return Err(std::io::Error::other(
            "passkey enrollment configuration requires PRIVATE_PASSKEY_STORE_PATH",
        )
        .into());
    }
    let state = match passkey_store {
        Some(store) => PrivateApiState::production_with_passkeys(
            config,
            store,
            enrollment_secret,
            allow_additional_credentials,
        )
        .map_err(|_| std::io::Error::other("private api passkey configuration invalid"))?,
        None => PrivateApiState::production(config)
            .map_err(|_| std::io::Error::other("private api configuration invalid"))?,
    };

    // TRADING_ENABLED is parsed strictly (`"true"`/`"false"`; unset disables) so
    // a typo can never silently enable execution. The authoritative Trading Core
    // backend, capabilities, instrument registry, web-contract backend and
    // realtime stream source are operator-injected seams; with none wired the
    // advertised document advertises no capability and the kill switch stays
    // engaged, so every mutation is an authenticated `capability_missing`
    // denial — never a fabricated success.
    let gate = private_api::production::TradingGate::from_env()
        .map_err(|_| std::io::Error::other("TRADING_ENABLED must be true or false"))?;
    let production =
        private_api::production::build_opaque(private_api::production::OpaqueComposition {
            sessions: state.sessions(),
            clock: Arc::new(OpaqueSystemClock),
            session_ttl_ms,
            gate,
            dispatcher: None,
            wired: private_api::production::WiredCapabilities::default(),
            stream_source: None,
            chains: Vec::new(),
        })
        .map_err(|_| std::io::Error::other("opaque service configuration invalid"))?;
    let opaque_state = production.state;

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

    #[test]
    fn strict_bool_env_defaults_and_rejects_typos() {
        let name = "PRIVATE_PASSKEY_TEST_BOOL";
        std::env::remove_var(name);
        assert!(!strict_bool_env(name, false).unwrap());
        std::env::set_var(name, "true");
        assert!(strict_bool_env(name, false).unwrap());
        std::env::set_var(name, "false");
        assert!(!strict_bool_env(name, true).unwrap());
        std::env::set_var(name, "1");
        assert!(strict_bool_env(name, false).is_err());
        std::env::remove_var(name);
    }
}
