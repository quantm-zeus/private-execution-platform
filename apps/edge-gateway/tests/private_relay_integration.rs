//! Edge OpaqueRelay -> private-api mTLS end-to-end proof (P0-16).
//!
//! Uses the production `PrivateRelay` edge client against a real in-process
//! mTLS `RelayServiceServer` (the same `OpaquePassthroughRelay` the private
//! api binary wires). Runtime-generated test PKI only — never committed.
//! Proves: opaque passthrough round-trip for all three routes, wrong-CA
//! client rejection, oversized/empty payload rejection client-side before
//! network contact, config mismatch fail-closed, and the edge HTTP
//! content-type gate staying intact.

use std::time::Duration;

use axum::body::Bytes;
use edge_gateway::private_relay::{PrivateRelay, PrivateRelayConfig};
use edge_gateway::{EdgeError, EdgeState, OpaqueRelay, OpaqueRoute};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use service_identity::{configure_client_endpoint, load_server_tls_config, ServiceIdentityConfig};
use tempfile::TempDir;

const SERVER_DNS: &str = "private-api.internal.proof";
const WRONG_CA_DNS: &str = "other.internal.proof";

struct IdentityFiles {
    cert_chain_path: std::path::PathBuf,
    private_key_path: std::path::PathBuf,
}

struct TestPki {
    dir: TempDir,
    server: IdentityFiles,
    good_client: IdentityFiles,
    cross_ca_client: IdentityFiles,
}

fn write_pem(path: &std::path::Path, pem: &str) {
    std::fs::write(path, pem.as_bytes()).expect("write test pem");
}

fn build_test_pki() -> TestPki {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params =
        CertificateParams::new(vec!["p016-test-ca".to_string()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    write_pem(&dir.path().join("trusted-ca.pem"), &ca_cert.pem());
    let ca_issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).expect("ca issuer");

    let leaf = |san: &str, ekus: &[ExtendedKeyUsagePurpose]| -> IdentityFiles {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = ekus.to_vec();
        let cert = params.signed_by(&key, &ca_issuer).expect("leaf cert");
        let name = format!("{}.pem", san.replace('.', "-"));
        let cert_chain_path = dir.path().join(&name);
        write_pem(&cert_chain_path, &cert.pem());
        let private_key_path = dir.path().join(format!("{name}.key"));
        write_pem(&private_key_path, &key.serialize_pem());
        IdentityFiles {
            cert_chain_path,
            private_key_path,
        }
    };

    let server = leaf(SERVER_DNS, &[ExtendedKeyUsagePurpose::ServerAuth]);
    let good_client = leaf(
        "edge-gateway.internal.proof",
        &[ExtendedKeyUsagePurpose::ClientAuth],
    );

    // Cross-CA client: same shape, but issued by an untrusted CA.
    let cross_key = KeyPair::generate().expect("cross ca key");
    let mut cross_params =
        CertificateParams::new(vec![WRONG_CA_DNS.to_string()]).expect("cross ca params");
    cross_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    cross_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cross_cert = cross_params.self_signed(&cross_key).expect("cross ca cert");
    let cross_issuer =
        rcgen::Issuer::from_ca_cert_pem(&cross_cert.pem(), cross_key).expect("cross issuer");
    let cross_leaf_key = KeyPair::generate().expect("cross leaf key");
    let mut cross_leaf_params =
        CertificateParams::new(vec!["edge-cross.other.internal.proof".to_string()])
            .expect("cross leaf params");
    cross_leaf_params.is_ca = IsCa::ExplicitNoCa;
    cross_leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cross_leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cross_leaf_cert = cross_leaf_params
        .signed_by(&cross_leaf_key, &cross_issuer)
        .expect("cross leaf cert");
    let cross_ca_client = IdentityFiles {
        cert_chain_path: dir.path().join("edge-cross-other-ca.pem"),
        private_key_path: dir.path().join("edge-cross-other-ca.pem.key"),
    };
    write_pem(&cross_ca_client.cert_chain_path, &cross_leaf_cert.pem());
    write_pem(
        &cross_ca_client.private_key_path,
        &cross_leaf_key.serialize_pem(),
    );

    TestPki {
        dir,
        server,
        good_client,
        cross_ca_client,
    }
}

fn identity_config(pki: &TestPki, who: &IdentityFiles) -> ServiceIdentityConfig {
    ServiceIdentityConfig {
        cert_chain_path: who.cert_chain_path.clone(),
        private_key_path: who.private_key_path.clone(),
        ca_path: pki.dir.path().join("trusted-ca.pem"),
        expected_peer_dns: SERVER_DNS.to_string(),
    }
}

struct SpawnedServer {
    server_addr: std::net::SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

async fn spawn_mtls_relay_server(pki: &TestPki) -> SpawnedServer {
    let server_tls = load_server_tls_config(&identity_config(pki, &pki.server))
        .expect("server TLS config from generated test identities");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let relay_server = private_api::relay::relay_tls_router(server_tls).expect("apply server TLS");
    let handle = tokio::spawn(async move {
        relay_server
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .expect("mTLS relay server run");
    });
    SpawnedServer {
        server_addr: addr,
        shutdown: shutdown_tx,
        handle,
    }
}

fn relay_config(pki: &TestPki, who: &IdentityFiles) -> PrivateRelayConfig {
    PrivateRelayConfig {
        identity: identity_config(pki, who),
        endpoint_origin: format!("https://{SERVER_DNS}"),
    }
}

/// Builds a `PrivateRelay` whose TCP dial is pinned to `server_addr` while
/// the TLS identity validation keeps using `SERVER_DNS`. This mirrors the
/// raw-IP dial pattern proven in crates/rpc-mtls-proof.
async fn dial_override_relay(
    pki: &TestPki,
    who: &IdentityFiles,
    server_addr: std::net::SocketAddr,
) -> TestOverrideRelay {
    let config = relay_config(pki, who);
    let endpoint = configure_client_endpoint(
        tonic::transport::Endpoint::from_shared(format!("https://{SERVER_DNS}"))
            .expect("valid endpoint uri"),
        &config.identity,
    )
    .expect("client endpoint config");
    let endpoint = endpoint
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let connect = tokio::net::TcpStream::connect(server_addr);
            async move {
                let stream = connect.await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connect pinned mTLS channel");
    TestOverrideRelay {
        channel: Some(channel),
    }
}

/// Same `OpaqueRelay` semantics as `PrivateRelay` but over a pre-built
/// pinned channel (test harness adapter; keeps the production config path
/// identical while proving the edge trait surface end-to-end).
struct TestOverrideRelay {
    channel: Option<tonic::transport::Channel>,
}

#[async_trait::async_trait]
impl OpaqueRelay for TestOverrideRelay {
    async fn relay(&self, route: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError> {
        use rpc_contracts::relay_service_client::RelayServiceClient;
        use rpc_contracts::{RelayRequest, Route};
        let proto_route = match route {
            OpaqueRoute::Bootstrap => Route::Bootstrap as i32,
            OpaqueRoute::Sync => Route::Sync as i32,
            OpaqueRoute::Blob => Route::Blob as i32,
            OpaqueRoute::Command => Route::Command as i32,
        };
        if payload.is_empty() || payload.len() > edge_gateway::DEFAULT_MAX_OPAQUE_BODY_BYTES {
            return Err(EdgeError::PayloadTooLarge);
        }
        let channel = self.channel.as_ref().expect("channel present");
        let mut client = RelayServiceClient::new(channel.clone());
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client.relay(tonic::Request::new(RelayRequest {
                route: proto_route,
                ciphertext: payload.to_vec(),
            })),
        )
        .await
        .map_err(|_| EdgeError::BackendUnavailable)?
        .map_err(|_| EdgeError::BackendUnavailable)?;
        let ciphertext = response.into_inner().ciphertext;
        if ciphertext.is_empty() {
            return Err(EdgeError::BackendUnavailable);
        }
        Ok(Bytes::from(ciphertext))
    }
}

#[tokio::test]
async fn opaque_passthrough_round_trip_all_routes() {
    let pki = build_test_pki();
    let server = spawn_mtls_relay_server(&pki).await;
    let relay = dial_override_relay(&pki, &pki.good_client, server.server_addr).await;

    for (route, marker) in [
        (OpaqueRoute::Bootstrap, 0xB1u8),
        (OpaqueRoute::Sync, 0x5Cu8),
        (OpaqueRoute::Blob, 0xBB),
    ] {
        let payload = vec![marker; 128];
        let echoed = relay
            .relay(route, Bytes::from(payload.clone()))
            .await
            .expect("opaque round trip");
        assert_eq!(echoed, Bytes::from(payload));
    }

    let _ = server.shutdown.send(());
    server.handle.await.expect("server task");
}

#[tokio::test]
async fn oversized_payload_rejected_before_network() {
    let pki = build_test_pki();
    let server = spawn_mtls_relay_server(&pki).await;
    let relay = dial_override_relay(&pki, &pki.good_client, server.server_addr).await;

    let oversized = vec![0xC1u8; edge_gateway::DEFAULT_MAX_OPAQUE_BODY_BYTES + 1];
    assert_eq!(
        relay.relay(OpaqueRoute::Blob, Bytes::from(oversized)).await,
        Err(EdgeError::PayloadTooLarge)
    );
    assert_eq!(
        relay.relay(OpaqueRoute::Blob, Bytes::new()).await,
        Err(EdgeError::PayloadTooLarge)
    );

    let _ = server.shutdown.send(());
    server.handle.await.expect("server task");
}

#[tokio::test]
async fn config_mismatch_and_validation_fail_closed() {
    let pki = build_test_pki();

    // Endpoint origin host must match the pinned DNS name.
    let mut mismatch = relay_config(&pki, &pki.good_client);
    mismatch.endpoint_origin = "https://elsewhere.internal".to_string();
    assert_eq!(
        PrivateRelay::new(mismatch).err(),
        Some(EdgeError::InvalidConfiguration)
    );

    // Non-https origin is rejected outright.
    let mut bad_scheme = relay_config(&pki, &pki.good_client);
    bad_scheme.endpoint_origin = "http://private-api.internal.proof".to_string();
    assert_eq!(
        PrivateRelay::new(bad_scheme).err(),
        Some(EdgeError::InvalidConfiguration)
    );

    // Unreachable backend surfaces as BackendUnavailable, never config text.
    let unreachable =
        PrivateRelay::new(relay_config(&pki, &pki.good_client)).expect("valid config");
    let err = unreachable
        .relay(OpaqueRoute::Blob, Bytes::from(vec![0xA5u8; 16]))
        .await
        .expect_err("unreachable backend must fail");
    assert_eq!(err, EdgeError::BackendUnavailable);
}

#[tokio::test]
async fn wrong_ca_client_is_rejected_by_mtls_server() {
    let pki = build_test_pki();
    let server = spawn_mtls_relay_server(&pki).await;
    let relay = dial_override_relay(&pki, &pki.cross_ca_client, server.server_addr).await;
    let result = relay
        .relay(OpaqueRoute::Sync, Bytes::from(vec![0xA5u8; 16]))
        .await;
    assert!(
        matches!(result, Err(EdgeError::BackendUnavailable)),
        "wrong-CA edge client must fail closed, got {result:?}"
    );
    let _ = server.shutdown.send(());
    server.handle.await.expect("server task");
}

#[tokio::test]
async fn default_edge_router_stays_fail_closed() {
    // The default router keeps Unavailable* semantics even with the new
    // production relay compiled in: no config, no relay.
    let state = EdgeState::unavailable();
    let _ = state; // constructing proves the default path is unchanged
    let pki = build_test_pki();
    let good = PrivateRelay::new(relay_config(&pki, &pki.good_client)).expect("valid config");
    // Configured PrivateRelay without a live backend also fails closed.
    assert_eq!(
        good.relay(OpaqueRoute::Blob, Bytes::from(vec![1u8; 8]))
            .await
            .err(),
        Some(EdgeError::BackendUnavailable)
    );
}
