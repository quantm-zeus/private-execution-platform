use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

/// Read an optional environment variable. A present-but-non-Unicode value is a
/// misconfiguration that refuses startup instead of silently collapsing to
/// "unset" (which could disable a required dependency behind a healthy probe).
fn read_env(name: &str) -> Result<Option<String>, std::io::Error> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(std::io::Error::other(format!("{name} must be valid UTF-8")))
        }
    }
}

/// Strict boolean environment parse (`true`/`false`; unset uses `default`).
/// Anything else refuses startup so a typo cannot flip a security default.
fn strict_bool_env(name: &str, default: bool) -> Result<bool, std::io::Error> {
    match read_env(name)? {
        Some(value) if value == "true" => Ok(true),
        Some(value) if value == "false" => Ok(false),
        Some(_) => Err(std::io::Error::other(format!(
            "{name} must be true or false"
        ))),
        None => Ok(default),
    }
}

/// Enforce the immutable release manifest as the normal production mode.
///
/// `WORKSPACE_RELEASE_MANIFEST` binds the artifact to the trusted recipient
/// public-key fingerprint; without it the compatibility preflight enforces only
/// version/KID. That weaker mode is now an explicit, opt-in fallback: an absent
/// manifest refuses startup unless `WORKSPACE_ALLOW_NO_MANIFEST=true`. A
/// present-but-blank path is always a misconfiguration, never an opt-out.
fn release_manifest_policy(
    manifest: Option<&str>,
    allow_no_manifest: bool,
) -> Result<(), &'static str> {
    match manifest {
        Some(value) if !value.trim().is_empty() => Ok(()),
        Some(_) => Err("WORKSPACE_RELEASE_MANIFEST must not be blank"),
        None if allow_no_manifest => Ok(()),
        None => Err(
            "WORKSPACE_RELEASE_MANIFEST is required; set WORKSPACE_ALLOW_NO_MANIFEST=true \
             to explicitly accept the weaker version/KID-only preflight",
        ),
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
    // "Supplied" is `is_some()`: a present-but-blank key is an attempted
    // configuration (typically a typo), not an absent one, so it must take part
    // in the all-or-none decision. A whitespace-only bind with no identity must
    // therefore refuse startup rather than silently disabling the relay.
    let any_supplied =
        bind.is_some() || cert.is_some() || key.is_some() || ca.is_some() || dns.is_some();
    if !any_supplied {
        return Ok(None);
    }
    // The required identity *values* must additionally be non-blank to be
    // usable; a supplied key with a blank value is still a misconfiguration.
    let identity = [
        cert.as_deref(),
        key.as_deref(),
        ca.as_deref(),
        dns.as_deref(),
    ];
    let all_identity = identity
        .iter()
        .all(|value| value.is_some_and(|v| !v.trim().is_empty()));
    let bind_usable = bind.as_deref().is_some_and(|v| !v.trim().is_empty());
    if !bind_usable || !all_identity {
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
    let path = match read_env("PRIVATE_PASSKEY_STORE_PATH")? {
        Some(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let store = FilePasskeyCredentialStore::open(path)
        .map_err(|_| std::io::Error::other("passkey credential store invalid"))?;
    Ok(Some(Arc::new(store)))
}

/// Optional durable passkey-bound recovery wrapper store. When
/// `PRIVATE_RECOVERY_WRAPPER_STORE_PATH` is configured, the passkey recovery
/// surface is enabled; without it every recovery route answers `503` and the
/// shell keeps the offline recovery code as the only credential.
fn optional_recovery_store(
) -> Result<Option<Arc<dyn private_api::recovery::RecoveryWrapperStore>>, std::io::Error> {
    let path = match read_env("PRIVATE_RECOVERY_WRAPPER_STORE_PATH")? {
        Some(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let store = private_api::recovery::FileRecoveryWrapperStore::open(path)
        .map_err(|_| std::io::Error::other("recovery wrapper store invalid"))?;
    Ok(Some(Arc::new(store)))
}

/// Parse a bounded milliseconds env var (`min..=max`), defaulting when unset.
fn parse_millis_env(
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<Duration, std::io::Error> {
    let value = match read_env(name)? {
        None => default,
        Some(raw) if raw.trim().is_empty() => default,
        Some(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| std::io::Error::other(format!("{name} must be an integer")))?,
    };
    if value < min || value > max {
        return Err(std::io::Error::other(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(Duration::from_millis(value))
}

/// Parse a bounded `u32` env var (`min..=max`), defaulting when unset.
fn parse_u32_env(name: &str, default: u32, min: u32, max: u32) -> Result<u32, std::io::Error> {
    let value = match read_env(name)? {
        None => default,
        Some(raw) if raw.trim().is_empty() => default,
        Some(raw) => raw
            .trim()
            .parse::<u32>()
            .map_err(|_| std::io::Error::other(format!("{name} must be an integer")))?,
    };
    if value < min || value > max {
        return Err(std::io::Error::other(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(value)
}

/// Parse `chain:address:timeframe` for the single configured realtime target.
fn parse_stream_target(value: &str) -> Result<(String, String, String), std::io::Error> {
    let mut parts = value.split(':');
    let chain = parts.next().unwrap_or("");
    let address = parts.next().unwrap_or("");
    let timeframe = parts.next().unwrap_or("");
    if parts.next().is_some() || chain.is_empty() || address.is_empty() || timeframe.is_empty() {
        return Err(std::io::Error::other(
            "PRIVATE_FOMO_STREAM_TARGET must be chain:address:timeframe",
        ));
    }
    if private_api::fomo_market::fomo_symbol(chain, address).is_none() {
        return Err(std::io::Error::other(
            "PRIVATE_FOMO_STREAM_TARGET chain/address is not supported",
        ));
    }
    if private_api::fomo_market::fomo_resolution(timeframe).is_none() {
        return Err(std::io::Error::other(
            "PRIVATE_FOMO_STREAM_TARGET timeframe is not supported",
        ));
    }
    Ok((
        chain.to_string(),
        address.to_string(),
        timeframe.to_string(),
    ))
}

/// Resolve the optional FOMO market bridge configuration.
///
/// All-or-none: any FOMO market variable requires `PRIVATE_FOMO_MARKET_URL` and
/// `PRIVATE_FOMO_MARKET_API_KEY_FILE`. With none set the chart stays on its
/// bounded local buffer and neither `market` nor `realtime` is advertised.
fn optional_fomo_market_config(
) -> Result<Option<(private_api::FomoMarketConfig, Zeroizing<String>)>, std::io::Error> {
    let base = read_env("PRIVATE_FOMO_MARKET_URL")?.filter(|value| !value.trim().is_empty());
    let key_file =
        read_env("PRIVATE_FOMO_MARKET_API_KEY_FILE")?.filter(|value| !value.trim().is_empty());
    let stream_target =
        read_env("PRIVATE_FOMO_STREAM_TARGET")?.filter(|value| !value.trim().is_empty());
    // Any FOMO variable counts as a supplied (partial) configuration, so a lone
    // timeout/poll/count refuses startup instead of being silently ignored.
    let timeout =
        read_env("PRIVATE_FOMO_MARKET_TIMEOUT_MS")?.filter(|value| !value.trim().is_empty());
    let poll = read_env("PRIVATE_FOMO_STREAM_POLL_MS")?.filter(|value| !value.trim().is_empty());
    let count =
        read_env("PRIVATE_FOMO_STREAM_COUNT_BACK")?.filter(|value| !value.trim().is_empty());
    if base.is_none()
        && key_file.is_none()
        && stream_target.is_none()
        && timeout.is_none()
        && poll.is_none()
        && count.is_none()
    {
        return Ok(None);
    }
    let base = base.ok_or_else(|| {
        std::io::Error::other(
            "PRIVATE_FOMO_MARKET_URL is required when any FOMO market variable is set",
        )
    })?;
    let key_file = key_file.ok_or_else(|| {
        std::io::Error::other(
            "PRIVATE_FOMO_MARKET_API_KEY_FILE is required with PRIVATE_FOMO_MARKET_URL",
        )
    })?;
    // The bearer key is read through the hardened, owner-only path and never
    // logged; the buffer zeroizes on drop.
    let api_key = private_api::read_operator_secret_file(std::path::Path::new(&key_file))?;
    let request_timeout = parse_millis_env(
        "PRIVATE_FOMO_MARKET_TIMEOUT_MS",
        private_api::fomo_market::DEFAULT_REQUEST_TIMEOUT.as_millis() as u64,
        100,
        30_000,
    )?;
    let stream_poll = parse_millis_env("PRIVATE_FOMO_STREAM_POLL_MS", 5_000, 5_000, 60_000)?;
    let stream_count_back = parse_u32_env("PRIVATE_FOMO_STREAM_COUNT_BACK", 300, 1, 1_500)?;
    let target = match stream_target {
        Some(value) => Some(parse_stream_target(&value)?),
        None => None,
    };
    Ok(Some((
        private_api::FomoMarketConfig {
            base_url: base,
            api_key_file: std::path::PathBuf::from(key_file),
            request_timeout,
            stream_target: target,
            stream_poll,
            stream_count_back,
        },
        api_key,
    )))
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

    // The immutable release manifest is the normal production mode; the weaker
    // version/KID-only preflight is an explicit opt-in.
    release_manifest_policy(
        read_env(private_api::release::RELEASE_MANIFEST_ENV)?.as_deref(),
        strict_bool_env("WORKSPACE_ALLOW_NO_MANIFEST", false)?,
    )
    .map_err(std::io::Error::other)?;

    // Production passkey composition. The operator bootstrap secret is only
    // meaningful together with a durable store (otherwise an enrolled credential
    // could not survive a restart), so a secret without a store refuses startup
    // rather than silently presenting a dead enrollment surface.
    let passkey_store = optional_passkey_store()?;
    let enrollment_secret = read_env("PRIVATE_PASSKEY_ENROLL_SECRET")?
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
    let state = match optional_recovery_store()? {
        Some(store) => state.with_recovery_store(store),
        None => state,
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
    // Live trading wiring is presence-only and explicitly opt-in; it never reads
    // a credential value. A partial configuration (opted in but missing an
    // endpoint) refuses startup regardless of the trading gate, so a
    // half-configured live path is a determinate operator error rather than a
    // silently inert one.
    let live_opted_in =
        private_api::trading::parse_live_opt_in(read_env("TRADING_CORE_LIVE")?.as_deref())
            .map_err(|_| std::io::Error::other("TRADING_CORE_LIVE must be 1 or 0"))?;
    let live_wiring = private_api::trading::LiveWiring::from_presence(
        live_opted_in,
        read_env("EXECUTION_DATABASE_DSN")?.as_deref(),
        read_env("BASE_RPC_ENDPOINT")?.as_deref(),
        read_env("PRIVY_HTTP_ENDPOINT")?.as_deref(),
    );
    if live_wiring.partial() {
        return Err(std::io::Error::other(
            "live trading wiring requires TRADING_CORE_LIVE=1 together with \
             EXECUTION_DATABASE_DSN, BASE_RPC_ENDPOINT and PRIVY_HTTP_ENDPOINT",
        )
        .into());
    }
    // Typed capability readiness. Every seam defaults absent, so the default
    // composition proves nothing and the bootstrap advertises no trading
    // capability. Connecting the durable store is gated behind the explicit
    // live opt-in, so the disabled deployment performs no trading I/O.
    let mut trading_seams = private_api::trading::TradingSeams::new();
    if gate.is_enabled() && live_wiring.durable_store_configured() {
        let dsn = read_env("EXECUTION_DATABASE_DSN")?.expect("checked present");
        match private_api::trading::connect_durable_attempt_store(&dsn).await {
            Ok((store, probe)) => {
                trading_seams = trading_seams.with_durable_store(store, probe);
            }
            Err(_) => {
                // A configured live path without its durable store is a
                // determinate refusal, never a process that claims readiness.
                return Err(std::io::Error::other("execution database unavailable").into());
            }
        }
    }
    // Optional read-only FOMO market bridge. With no configuration the chart
    // stays on its bounded local buffer and no capability is advertised; the
    // chart dispatcher wraps the fail-closed default for every non-chart op.
    let fomo = optional_fomo_market_config()?;
    // Observational health flag shared with the realtime stream source and
    // `/ready`; it starts false and is only set true by an observed successful
    // bridge read, so a configured-but-unreachable provider is never reported
    // healthy.
    let stream_health = Arc::new(AtomicBool::new(false));
    let (fomo_dispatcher, fomo_stream, fomo_wired) = match fomo {
        Some((config, api_key)) => {
            let provider: Arc<dyn private_api::BarsProvider> = Arc::new(
                private_api::FomoBarsClient::new(&config.base_url, api_key, config.request_timeout)
                    .map_err(|_| std::io::Error::other("FOMO market configuration invalid"))?,
            );
            let probe_provider = provider.clone();
            let wiring = private_api::build_fomo_market_wiring_with_health(
                &config,
                provider,
                Arc::new(private_api::FailClosedDispatcher),
                Some(stream_health.clone()),
            )
            .map_err(|_| std::io::Error::other("FOMO market wiring invalid"))?;
            // Observe the configured realtime source once at startup. A
            // reachable bridge proves the realtime capability; an unavailable
            // one leaves it unadvertised (fail closed) rather than claiming a
            // stream that was never reached. The shared flag keeps `/ready`
            // honest for later poll failures too.
            if wiring.stream_source.is_some() {
                let reachable = private_api::probe_realtime(probe_provider.as_ref(), &config).await;
                stream_health.store(reachable, Ordering::SeqCst);
                if reachable {
                    trading_seams = trading_seams.with_realtime_probe(
                        private_api::trading::healthy(private_api::trading::COMPONENT_REALTIME),
                    );
                }
            }
            let wired = private_api::production::WiredCapabilities {
                // Chart history only: `search_token`/`get_token` stay denied
                // because FOMO does not back them (capability truth, audit F6).
                chart: true,
                realtime: wiring.stream_source.is_some(),
                ..private_api::production::WiredCapabilities::default()
            };
            (Some(wiring.dispatcher), wiring.stream_source, wired)
        }
        None => (
            None,
            None,
            private_api::production::WiredCapabilities::default(),
        ),
    };
    let fomo_stream_present = fomo_stream.is_some();
    let readiness = trading_seams.readiness(gate.is_enabled());
    // The stream is a required readiness dependency only when the composition
    // both advertises realtime and proved it reachable at startup.
    let stream_required = fomo_stream_present && readiness.realtime();
    let production =
        private_api::production::build_opaque(private_api::production::OpaqueComposition {
            sessions: state.sessions(),
            clock: Arc::new(OpaqueSystemClock),
            session_ttl_ms,
            gate,
            dispatcher: fomo_dispatcher,
            wired: fomo_wired,
            stream_source: fomo_stream,
            chains: Vec::new(),
            readiness,
        })
        .map_err(|_| std::io::Error::other("opaque service configuration invalid"))?;
    let opaque_state = production.state;

    let relay_identity = resolve_relay_config(
        read_env("PRIVATE_API_RELAY_BIND_ADDR")?,
        read_env("PRIVATE_API_TLS_CERT")?,
        read_env("PRIVATE_API_TLS_KEY")?,
        read_env("PRIVATE_API_TLS_CA")?,
        read_env("PRIVATE_API_EDGE_DNS")?,
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
            // Clear the flag however the task ends: after `serve` returns (Ok or
            // Err) and while unwinding if it panics, so a process whose relay has
            // stopped can never keep reporting readiness.
            struct ReadinessGuard(Arc<AtomicBool>);
            impl Drop for ReadinessGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::SeqCst);
                }
            }
            let _guard = ReadinessGuard(ready_flag.clone());
            ready_flag.store(true, Ordering::SeqCst);
            let _ = relay_router.serve_with_incoming(incoming).await;
        });
    }
    // The opaque dispatcher is always wired (the fail-closed default is a real
    // dispatcher), so it is ready by construction. The realtime stream is a
    // required dependency only when a reachable source was composed; the shared
    // flag flips false if the source later exhausts its bounded failure budget.
    let dispatcher_ready = Arc::new(AtomicBool::new(true));
    let state = state
        .with_relay_readiness(relay_required, relay_ready)
        .with_dispatcher_readiness(dispatcher_ready)
        .with_stream_readiness(stream_required, stream_health);

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
        // A whitespace-only bind address with no identity is a supplied (but
        // unusable) relay configuration, not "unset": it must refuse startup
        // rather than silently disabling the relay.
        assert!(resolve_relay_config(Some("   ".into()), None, None, None, None).is_err());
        assert!(resolve_relay_config(Some(String::new()), None, None, None, None).is_err());
        // A whitespace-only identity value alone is supplied and incomplete too.
        assert!(resolve_relay_config(None, Some("   ".into()), None, None, None).is_err());
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

    #[test]
    fn release_manifest_is_required_unless_explicitly_opted_out() {
        // A configured manifest is the normal mode.
        assert_eq!(
            release_manifest_policy(Some("/srv/pep/manifest.json"), false),
            Ok(())
        );
        // No manifest refuses unless the operator explicitly accepts the weaker
        // version/KID-only preflight.
        assert!(release_manifest_policy(None, false).is_err());
        assert_eq!(release_manifest_policy(None, true), Ok(()));
        // A present-but-blank path is always a misconfiguration, never an opt-out.
        assert!(release_manifest_policy(Some("   "), true).is_err());
        assert!(release_manifest_policy(Some(""), true).is_err());
        assert!(release_manifest_policy(Some("   "), false).is_err());
    }

    #[test]
    fn fomo_stream_target_is_strictly_validated() {
        assert_eq!(
            parse_stream_target("base:0xabc:1m").unwrap(),
            ("base".to_string(), "0xabc".to_string(), "1m".to_string())
        );
        // Unknown chain, unknown window, missing field and extra field refuse.
        assert!(parse_stream_target("unknown:0xabc:1m").is_err());
        assert!(parse_stream_target("base:0xabc:1s").is_err());
        assert!(parse_stream_target("base:0xabc").is_err());
        assert!(parse_stream_target("base:0xabc:1m:extra").is_err());
        assert!(parse_stream_target("").is_err());
    }

    #[test]
    fn bounded_millis_env_uses_default_and_rejects_out_of_range() {
        let name = "PRIVATE_FOMO_TEST_MILLIS";
        std::env::remove_var(name);
        assert_eq!(
            parse_millis_env(name, 5_000, 100, 30_000).unwrap(),
            Duration::from_millis(5_000)
        );
        std::env::set_var(name, "42");
        assert!(parse_millis_env(name, 5_000, 100, 30_000).is_err());
        std::env::set_var(name, "notanumber");
        assert!(parse_millis_env(name, 5_000, 100, 30_000).is_err());
        std::env::remove_var(name);
    }
}
