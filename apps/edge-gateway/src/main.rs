use std::net::SocketAddr;

/// Strict boolean environment parse (`true`/`false`; unset uses `default`).
///
/// A present-but-non-Unicode value is a misconfiguration that refuses startup,
/// matching `private-api`'s `read_env`: collapsing it to the default could
/// silently flip a security-relevant flag.
fn strict_bool_env(name: &str, default: bool) -> Result<bool, std::io::Error> {
    match std::env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => Err(std::io::Error::other(format!(
            "{name} must be true or false"
        ))),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(std::io::Error::other(format!("{name} must be valid UTF-8")))
        }
    }
}

/// Resolve `EDGE_BIND_ADDR` with a fail-closed public-interface guard.
///
/// The edge authorizes `/v1/*` with a perimeter-injected assertion header, not a
/// cryptographic check, so the listener must not be reachable except through the
/// perimeter. Until Cloudflare Access JWT validation (issuer/audience/signature/
/// expiry) is actually implemented and wired, a non-loopback bind is refused:
/// with `EDGE_ACCESS_JWT_VALIDATION` unset *and* with it set, because enabling
/// the flag cannot enable validation that does not exist. The deployment
/// mitigation (every PEP listener on loopback) therefore cannot be silently
/// widened by an environment change.
fn resolve_edge_bind(
    value: &str,
    jwt_validation_enabled: bool,
) -> Result<SocketAddr, std::io::Error> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| std::io::Error::other("invalid EDGE_BIND_ADDR"))?;
    if address.ip().is_loopback() {
        return Ok(address);
    }
    if !jwt_validation_enabled {
        return Err(std::io::Error::other(
            "EDGE_BIND_ADDR must be loopback unless cryptographic Access-JWT validation is enabled",
        ));
    }
    Err(std::io::Error::other(
        "cryptographic Access-JWT validation is not implemented in this build; refusing a public edge bind",
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("EDGE_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let address = resolve_edge_bind(&bind, strict_bool_env("EDGE_ACCESS_JWT_VALIDATION", false)?)?;
    // BR-7 production composition: the edge forwards ciphertext only, over the
    // pinned internal mTLS boundary, when the operator supplies a relay
    // identity. With no identity the edge keeps its fail-closed default (every
    // /v1/* request is a 503) rather than silently serving a cleartext path.
    // A partial/invalid identity is a configuration error and refuses to start.
    let router = edge_gateway::production::router_from_env()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_bind_refuses_public_and_non_address_forms() {
        assert!(resolve_edge_bind("127.0.0.1:8080", false).is_ok());
        assert!(resolve_edge_bind("[::1]:8080", false).is_ok());
        // Public bind without JWT validation is refused.
        assert!(resolve_edge_bind("0.0.0.0:8080", false).is_err());
        assert!(resolve_edge_bind("[::]:8080", false).is_err());
        assert!(resolve_edge_bind("192.0.2.10:8080", false).is_err());
        // An IPv4-mapped IPv6 loopback is not `is_loopback` and must be refused.
        assert!(resolve_edge_bind("[::ffff:127.0.0.1]:8080", false).is_err());
        // The flag cannot enable unimplemented cryptographic validation, so a
        // public bind is refused even when set.
        assert!(resolve_edge_bind("0.0.0.0:8080", true).is_err());
        assert!(resolve_edge_bind("[::ffff:127.0.0.1]:8080", true).is_err());
        // A DNS name, a whitespace-padded value, a missing port and an empty
        // value are configuration errors, not a silent public bind.
        for bad in [
            "internal.example:8080",
            " 127.0.0.1:8080 ",
            "127.0.0.1",
            "",
            "localhost:8080",
        ] {
            assert!(
                resolve_edge_bind(bad, false).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn strict_bool_env_rejects_typos() {
        let name = "EDGE_ACCESS_JWT_VALIDATION_TEST";
        std::env::remove_var(name);
        assert!(!strict_bool_env(name, false).unwrap());
        std::env::set_var(name, "true");
        assert!(strict_bool_env(name, false).unwrap());
        std::env::set_var(name, "1");
        assert!(strict_bool_env(name, false).is_err());
        std::env::remove_var(name);
    }

    #[cfg(unix)]
    #[test]
    fn strict_bool_env_refuses_non_unicode_instead_of_defaulting() {
        use std::os::unix::ffi::OsStrExt;

        let name = "EDGE_ACCESS_JWT_VALIDATION_NON_UNICODE_TEST";
        std::env::remove_var(name);
        std::env::set_var(name, std::ffi::OsStr::from_bytes(b"\xff\xfe"));
        assert!(strict_bool_env(name, true).is_err());
        assert!(strict_bool_env(name, false).is_err());
        std::env::remove_var(name);
    }
}
