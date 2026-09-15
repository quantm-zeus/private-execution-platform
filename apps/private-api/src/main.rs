use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Strict all-or-none relay configuration.
///
/// The relay is optional: with none of the five variables supplied it stays
/// disabled and the HTTP boundary serves alone. But once an operator supplies
/// *any* of the relay bind address or the four identity values, the whole set
/// must be present and non-empty, otherwise startup refuses. A partial set can
/// no longer silently degrade a deployment into a process that looks healthy
/// while its opaque transport never listens.
fn resolve_relay_config(
    bind: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    ca: Option<String>,
    dns: Option<String>,
) -> Result<Option<(String, ServiceIdentityConfig)>, std::io::Error> {
    let present = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
    let bind_present = present(&bind);
    let identity = [
        cert.as_deref(),
        key.as_deref(),
        ca.as_deref(),
        dns.as_deref(),
    ];
    let any_identity = identity
        .iter()
        .any(|value| value.is_some_and(|v| !v.trim().is_empty()));
    if !bind_present && !any_identity {
        return Ok(None);
    }
    let all_identity = identity
        .iter()
        .all(|value| value.is_some_and(|v| !v.trim().is_empty()));
    if !bind_present || !all_identity {
        return Err(std::io::Error::other(
            "private relay configuration must supply PRIVATE_API_RELAY_BIND_ADDR, \
             PRIVATE_API_TLS_CERT, PRIVATE_API_TLS_KEY, PRIVATE_API_TLS_CA and \
             PRIVATE_API_EDGE_DNS together",
        ));
    }
    let bind = bind.expect("checked present");
    let cert = cert.expect("checked present");
    let key = key.expect("checked present");
    let ca = ca.expect("checked present");
    let dns = dns.expect("checked present");
    Ok(Some((
        bind,
        ServiceIdentityConfig {
            cert_chain_path: cert.into(),
            private_key_path: key.into(),
            ca_path: ca.into(),
            expected_peer_dns: dns,
        },
    )))
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

    let relay_identity = resolve_relay_config(
        std::env::var("PRIVATE_API_RELAY_BIND_ADDR").ok(),
        std::env::var("PRIVATE_API_TLS_CERT").ok(),
        std::env::var("PRIVATE_API_TLS_KEY").ok(),
        std::env::var("PRIVATE_API_TLS_CA").ok(),
        std::env::var("PRIVATE_API_EDGE_DNS").ok(),
    )?;
    let relay_required = relay_identity.is_some();
    let relay_ready = Arc::new(AtomicBool::new(false));
    if let Some((relay_bind, identity)) = relay_identity {
        let relay_address = parse_bind_addr(&relay_bind)?;
        let tls = relay::server_tls_config(&identity)
            .map_err(|_| std::io::Error::other("relay identity invalid"))?;
        let relay_router = opaque::relay_tls_router_with(opaque_state, tls)
            .map_err(|_| std::io::Error::other("relay TLS configuration invalid"))?;
        // Bind before spawning so a bad address or taken port is a startup
        // error rather than a hidden degraded process. Readiness flips true only
        // once the listener exists, and back to false if serving dies.
        let listener = tokio::net::TcpListener::bind(relay_address).await?;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let ready_flag = relay_ready.clone();
        tokio::spawn(async move {
            ready_flag.store(true, Ordering::SeqCst);
            if relay_router.serve_with_incoming(incoming).await.is_err() {
                ready_flag.store(false, Ordering::SeqCst);
            }
        });
    }
    let state = state.with_relay_readiness(relay_required, relay_ready);

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
    fn relay_configuration_is_strict_all_or_none() {
        // Nothing supplied: the relay stays disabled and the HTTP boundary serves.
        assert_eq!(
            resolve_relay_config(None, None, None, None, None).unwrap(),
            None
        );
        // A complete set resolves.
        let (bind, identity) = resolve_relay_config(
            Some("127.0.0.1:8443".into()),
            Some("cert.pem".into()),
            Some("key.pem".into()),
            Some("ca.pem".into()),
            Some("edge.internal".into()),
        )
        .unwrap()
        .expect("complete relay config");
        assert_eq!(bind, "127.0.0.1:8443");
        assert_eq!(identity.expected_peer_dns, "edge.internal");
        // A supplied bind with incomplete identity must refuse startup.
        assert!(resolve_relay_config(
            Some("127.0.0.1:8443".into()),
            Some("cert.pem".into()),
            None,
            None,
            None,
        )
        .is_err());
        // An identity without a bind address must refuse startup.
        assert!(resolve_relay_config(
            None,
            Some("cert.pem".into()),
            Some("key.pem".into()),
            Some("ca.pem".into()),
            Some("edge.internal".into()),
        )
        .is_err());
        // Present-but-blank values count as supplied and therefore incomplete.
        assert!(resolve_relay_config(
            Some("127.0.0.1:8443".into()),
            Some("   ".into()),
            Some("key.pem".into()),
            Some("ca.pem".into()),
            Some("edge.internal".into()),
        )
        .is_err());
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
