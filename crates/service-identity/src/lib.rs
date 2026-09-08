//! Fail-closed internal mTLS service identity boundary.

use std::{
    fmt,
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};
use zeroize::Zeroizing;

pub const MAX_IDENTITY_FILE_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct ServiceIdentityConfig {
    pub cert_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub ca_path: PathBuf,
    pub expected_peer_dns: String,
}

impl fmt::Debug for ServiceIdentityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceIdentityConfig")
            .field("cert_chain_path", &"[REDACTED]")
            .field("private_key_path", &"[REDACTED]")
            .field("ca_path", &"[REDACTED]")
            .field("expected_peer_dns", &self.expected_peer_dns)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFileRole {
    Certificate,
    PrivateKey,
    Ca,
}

impl fmt::Display for IdentityFileRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Certificate => "certificate",
            Self::PrivateKey => "private key",
            Self::Ca => "CA",
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceIdentityError {
    #[error("{0} file unavailable")]
    FileUnavailable(IdentityFileRole),
    #[error("{0} file is empty")]
    FileEmpty(IdentityFileRole),
    #[error("{0} file exceeds size limit")]
    FileTooLarge(IdentityFileRole),
    #[error("{0} file has invalid PEM type")]
    InvalidPem(IdentityFileRole),
    #[error("expected peer DNS name is invalid")]
    InvalidPeerDns,
    #[error("client TLS configuration failed")]
    ClientTlsConfigurationFailed,
}

impl ServiceIdentityConfig {
    pub fn validate(&self) -> Result<(), ServiceIdentityError> {
        validate_dns_name(&self.expected_peer_dns)
    }
}

pub fn load_server_tls_config(
    config: &ServiceIdentityConfig,
) -> Result<ServerTlsConfig, ServiceIdentityError> {
    config.validate()?;
    let cert = read_certificate(&config.cert_chain_path, IdentityFileRole::Certificate)?;
    let key = read_private_key(&config.private_key_path)?;
    let ca = read_certificate(&config.ca_path, IdentityFileRole::Ca)?;

    // Identity::from_pem copies the key into tonic/rustls-owned state. Our
    // temporary key buffer remains Zeroizing and is cleared when this function returns.
    let identity = Identity::from_pem(&cert, key.as_slice());
    let client_ca = Certificate::from_pem(&ca);
    Ok(ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca))
}

/// Applies mTLS to a tonic client endpoint without exposing `ClientTlsConfig`.
///
/// Tonic 0.14.5's `ClientTlsConfig`/`Identity` Debug implementations can expose
/// the copied private-key bytes. The raw TLS config therefore remains local to
/// this function and is consumed immediately by `Endpoint::tls_config`.
pub fn configure_client_endpoint(
    endpoint: Endpoint,
    config: &ServiceIdentityConfig,
) -> Result<Endpoint, ServiceIdentityError> {
    config.validate()?;
    let cert = read_certificate(&config.cert_chain_path, IdentityFileRole::Certificate)?;
    let key = read_private_key(&config.private_key_path)?;
    let ca = read_certificate(&config.ca_path, IdentityFileRole::Ca)?;

    let identity = Identity::from_pem(&cert, key.as_slice());
    let server_ca = Certificate::from_pem(&ca);
    let tls = ClientTlsConfig::new()
        .identity(identity)
        .ca_certificate(server_ca)
        .domain_name(config.expected_peer_dns.clone());
    endpoint
        .tls_config(tls)
        .map_err(|_| ServiceIdentityError::ClientTlsConfigurationFailed)
}

fn validate_dns_name(value: &str) -> Result<(), ServiceIdentityError> {
    if value.is_empty()
        || value.len() > 253
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
        || value.contains([':', '/', '@', '?', '#'])
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(ServiceIdentityError::InvalidPeerDns);
    }
    let valid = value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if valid {
        Ok(())
    } else {
        Err(ServiceIdentityError::InvalidPeerDns)
    }
}

fn read_certificate(path: &Path, role: IdentityFileRole) -> Result<Vec<u8>, ServiceIdentityError> {
    let bytes = read_bounded(path, role)?;
    if !has_pem_pair(
        &bytes,
        b"-----BEGIN CERTIFICATE-----",
        b"-----END CERTIFICATE-----",
    ) {
        return Err(ServiceIdentityError::InvalidPem(role));
    }
    Ok(bytes)
}

fn read_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, ServiceIdentityError> {
    let role = IdentityFileRole::PrivateKey;
    let bytes = read_bounded_secret(path, role)?;
    let valid = [
        (
            b"-----BEGIN PRIVATE KEY-----".as_slice(),
            b"-----END PRIVATE KEY-----".as_slice(),
        ),
        (
            b"-----BEGIN RSA PRIVATE KEY-----".as_slice(),
            b"-----END RSA PRIVATE KEY-----".as_slice(),
        ),
        (
            b"-----BEGIN EC PRIVATE KEY-----".as_slice(),
            b"-----END EC PRIVATE KEY-----".as_slice(),
        ),
    ]
    .into_iter()
    .any(|(begin, end)| has_pem_pair(&bytes, begin, end));
    if !valid {
        return Err(ServiceIdentityError::InvalidPem(role));
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, role: IdentityFileRole) -> Result<Vec<u8>, ServiceIdentityError> {
    let file = File::open(path).map_err(|_| ServiceIdentityError::FileUnavailable(role))?;
    let mut bytes = Vec::new();
    file.take((MAX_IDENTITY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceIdentityError::FileUnavailable(role))?;
    validate_file_size(&bytes, role)?;
    Ok(bytes)
}

fn read_bounded_secret(
    path: &Path,
    role: IdentityFileRole,
) -> Result<Zeroizing<Vec<u8>>, ServiceIdentityError> {
    let file = File::open(path).map_err(|_| ServiceIdentityError::FileUnavailable(role))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_IDENTITY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceIdentityError::FileUnavailable(role))?;
    validate_file_size(&bytes, role)?;
    Ok(bytes)
}

fn validate_file_size(bytes: &[u8], role: IdentityFileRole) -> Result<(), ServiceIdentityError> {
    if bytes.is_empty() {
        return Err(ServiceIdentityError::FileEmpty(role));
    }
    if bytes.len() > MAX_IDENTITY_FILE_BYTES {
        return Err(ServiceIdentityError::FileTooLarge(role));
    }
    Ok(())
}

fn has_pem_pair(bytes: &[u8], begin: &[u8], end: &[u8]) -> bool {
    let Some(begin_at) = find_subslice(bytes, begin) else {
        return false;
    };
    find_subslice(&bytes[begin_at + begin.len()..], end).is_some()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::fs;
    use tempfile::TempDir;

    const CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n";

    fn fixture() -> (TempDir, ServiceIdentityConfig) {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("service-cert.pem");
        let key = dir.path().join("service-key.pem");
        let ca = dir.path().join("ca.pem");
        let CertifiedKey {
            cert: generated_cert,
            signing_key,
        } = generate_simple_self_signed(vec!["core.internal.example".to_string()]).unwrap();
        let cert_pem = generated_cert.pem();
        let key_pem = signing_key.serialize_pem();
        fs::write(&cert, cert_pem.as_bytes()).unwrap();
        fs::write(&key, key_pem.as_bytes()).unwrap();
        fs::write(&ca, cert_pem.as_bytes()).unwrap();
        let config = ServiceIdentityConfig {
            cert_chain_path: cert,
            private_key_path: key,
            ca_path: ca,
            expected_peer_dns: "core.internal.example".to_string(),
        };
        (dir, config)
    }

    #[test]
    fn tls_configs_construct_from_bounded_pem_shaped_inputs() {
        let (_dir, config) = fixture();
        let server = load_server_tls_config(&config).expect("server TLS config");
        let server_debug = format!("{server:?}");
        assert!(!server_debug.contains("ZmFrZQ"));
        assert!(!server_debug.contains("PRIVATE KEY"));

        let endpoint = Endpoint::from_static("https://core.internal.example");
        let configured = configure_client_endpoint(endpoint, &config).expect("client TLS endpoint");
        assert_eq!(format!("{configured:?}"), "Endpoint");
    }

    #[test]
    fn invalid_peer_dns_is_rejected() {
        let invalid = [
            "",
            " example.com",
            "example.com ",
            "https://example.com",
            "example.com:443",
            "user@example.com",
            "example.com/path",
            "example.com?x=1",
            "example.com#x",
            "-bad.example",
            "bad-.example",
            "bad..example",
            "127.0.0.1",
            "::1",
        ];
        for value in invalid {
            assert_eq!(
                validate_dns_name(value),
                Err(ServiceIdentityError::InvalidPeerDns),
                "{value}"
            );
        }
        assert_eq!(
            validate_dns_name(&format!("{}.example", "a".repeat(64))),
            Err(ServiceIdentityError::InvalidPeerDns)
        );
        assert!(validate_dns_name("service-1.internal.example").is_ok());
    }

    #[test]
    fn missing_empty_and_oversize_files_fail_closed() {
        let (dir, mut config) = fixture();
        config.cert_chain_path = dir.path().join("missing-secret-name.pem");
        let err = load_server_tls_config(&config).unwrap_err();
        assert_eq!(
            err,
            ServiceIdentityError::FileUnavailable(IdentityFileRole::Certificate)
        );
        assert!(!err.to_string().contains("missing-secret-name"));

        let empty = dir.path().join("empty.pem");
        fs::write(&empty, b"").unwrap();
        config.cert_chain_path = empty;
        assert_eq!(
            load_server_tls_config(&config).unwrap_err(),
            ServiceIdentityError::FileEmpty(IdentityFileRole::Certificate)
        );

        let huge = dir.path().join("huge.pem");
        fs::write(&huge, vec![b'x'; MAX_IDENTITY_FILE_BYTES + 1]).unwrap();
        config.cert_chain_path = huge;
        assert_eq!(
            load_server_tls_config(&config).unwrap_err(),
            ServiceIdentityError::FileTooLarge(IdentityFileRole::Certificate)
        );
    }

    #[test]
    fn wrong_pem_roles_are_rejected() {
        let (dir, mut config) = fixture();
        fs::write(&config.cert_chain_path, KEY).unwrap();
        assert_eq!(
            load_server_tls_config(&config).unwrap_err(),
            ServiceIdentityError::InvalidPem(IdentityFileRole::Certificate)
        );
        fs::write(&config.cert_chain_path, CERT).unwrap();
        fs::write(&config.private_key_path, CERT).unwrap();
        assert_eq!(
            load_server_tls_config(&config).unwrap_err(),
            ServiceIdentityError::InvalidPem(IdentityFileRole::PrivateKey)
        );
        fs::write(&config.private_key_path, KEY).unwrap();
        let wrong_ca = dir.path().join("wrong-ca.pem");
        fs::write(&wrong_ca, KEY).unwrap();
        config.ca_path = wrong_ca;
        assert_eq!(
            configure_client_endpoint(
                Endpoint::from_static("https://core.internal.example"),
                &config
            )
            .unwrap_err(),
            ServiceIdentityError::InvalidPem(IdentityFileRole::Ca)
        );
    }

    #[test]
    fn private_key_reader_rejects_missing_empty_and_oversize() {
        let (dir, config) = fixture();
        let original_key = config.private_key_path.clone();

        let missing = dir.path().join("missing-secret-name.pem");
        assert_eq!(
            read_private_key(&missing).unwrap_err(),
            ServiceIdentityError::FileUnavailable(IdentityFileRole::PrivateKey)
        );

        let empty = dir.path().join("empty-secret.pem");
        fs::write(&empty, b"").unwrap();
        assert_eq!(
            read_private_key(&empty).unwrap_err(),
            ServiceIdentityError::FileEmpty(IdentityFileRole::PrivateKey)
        );

        let huge = dir.path().join("huge-secret.pem");
        fs::write(&huge, vec![b'x'; MAX_IDENTITY_FILE_BYTES + 1]).unwrap();
        assert_eq!(
            read_private_key(&huge).unwrap_err(),
            ServiceIdentityError::FileTooLarge(IdentityFileRole::PrivateKey)
        );

        let errors = [
            read_private_key(&missing).unwrap_err().to_string(),
            read_private_key(&empty).unwrap_err().to_string(),
            read_private_key(&huge).unwrap_err().to_string(),
        ];
        assert_eq!(
            errors,
            [
                "private key file unavailable".to_string(),
                "private key file is empty".to_string(),
                "private key file exceeds size limit".to_string(),
            ]
        );
        let leaked = [original_key.to_string_lossy(), dir.path().to_string_lossy()];
        for path in leaked {
            for error in &errors {
                assert!(!error.contains(&*path));
            }
        }
        assert!(!errors[2].contains("PRIVATE KEY"));
    }

    #[test]
    fn ca_reader_rejects_oversize() {
        let (dir, mut config) = fixture();
        let huge_ca = dir.path().join("huge-ca.pem");
        let pem = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
        fs::write(
            &huge_ca,
            pem.repeat((MAX_IDENTITY_FILE_BYTES / pem.len()) + 1),
        )
        .unwrap();
        config.ca_path = huge_ca;
        assert_eq!(
            load_server_tls_config(&config).unwrap_err(),
            ServiceIdentityError::FileTooLarge(IdentityFileRole::Ca)
        );
    }

    #[test]
    fn debug_and_errors_do_not_expose_paths_or_key_material() {
        let (_dir, config) = fixture();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("service-key.pem"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let missing = ServiceIdentityConfig {
            private_key_path: PathBuf::from("/tmp/SUPER_SECRET_KEY_LOCATION.pem"),
            ..config
        };
        let error = configure_client_endpoint(
            Endpoint::from_static("https://core.internal.example"),
            &missing,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("SUPER_SECRET"));
        assert!(!error.contains("BEGIN PRIVATE KEY"));
        assert_eq!(error, "private key file unavailable");
    }
}
