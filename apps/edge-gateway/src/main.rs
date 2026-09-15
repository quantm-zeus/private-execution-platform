use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = std::env::var("EDGE_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
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
