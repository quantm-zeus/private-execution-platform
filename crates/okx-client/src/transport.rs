//! Injected OKX HTTP transport boundary.
//!
//! The client never opens a socket itself. A caller injects an [`OkxTransport`]
//! implementation; production wiring is expected to be a narrow HTTP client that
//! attaches exactly the [`OkxAuthHeaders`] it is given and performs at most one
//! physical request per call (no automatic retry). The default
//! [`UnavailableOkxTransport`] fails closed.

use std::fmt;

use async_trait::async_trait;

use crate::auth::OkxAuthHeaders;
use crate::error::OkxClientError;

/// Default maximum accepted provider response body size (256 KiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Hard ceiling for a caller-configured response bound (8 MiB).
pub const MAX_RESPONSE_BYTES_CEILING: usize = 8 * 1024 * 1024;

/// Maximum accepted number of query parameters on one request.
pub const MAX_QUERY_PAIRS: usize = 32;

/// Maximum accepted non-GET request body size (64 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// HTTP method subset used by the OKX client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkxHttpMethod {
    /// `GET` (quote reads).
    Get,
    /// `POST` (version-dependent writes).
    Post,
}

impl OkxHttpMethod {
    /// The exact uppercase wire method.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A validated, redacted OKX request handed to the transport.
///
/// Query values are economy-bearing (token addresses and amounts), so `Debug`
/// renders only the method, path, and cardinalities. `signed_path` is the exact
/// `path?query` string that was signed and must be the same path the transport
/// sends.
pub struct OkxRequest {
    method: OkxHttpMethod,
    path: String,
    query: Vec<(String, String)>,
    body: Vec<u8>,
}

impl OkxRequest {
    /// Builds a validated `GET` request.
    pub fn get(
        path: impl Into<String>,
        query: Vec<(String, String)>,
    ) -> Result<Self, OkxClientError> {
        Self::build(OkxHttpMethod::Get, path.into(), query, Vec::new())
    }

    /// Builds a validated `POST` request with a bounded body.
    pub fn post(path: impl Into<String>, body: Vec<u8>) -> Result<Self, OkxClientError> {
        Self::build(OkxHttpMethod::Post, path.into(), Vec::new(), body)
    }

    fn build(
        method: OkxHttpMethod,
        path: String,
        query: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Self, OkxClientError> {
        if query.len() > MAX_QUERY_PAIRS || body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(OkxClientError::InvalidRequest);
        }
        for (key, value) in &query {
            if !is_valid_component(key) || !is_valid_component(value) {
                return Err(OkxClientError::InvalidRequest);
            }
        }
        if !is_valid_path(&path) {
            return Err(OkxClientError::InvalidRequest);
        }
        let request = Self {
            method,
            path,
            query,
            body,
        };
        if request.signed_path().len() > crate::auth::MAX_REQUEST_PATH_BYTES {
            return Err(OkxClientError::InvalidRequest);
        }
        Ok(request)
    }

    /// The request method.
    pub fn method(&self) -> OkxHttpMethod {
        self.method
    }

    /// The request path (no query string).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The ordered query parameters.
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// The request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The exact percent-encoded `path?query` string that is signed.
    pub fn signed_path(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let encoded = self
            .query
            .iter()
            .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{}", self.path, encoded)
    }
}

impl fmt::Debug for OkxRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OkxRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query_pairs", &self.query.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// A bounded provider HTTP response.
pub struct OkxHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl OkxHttpResponse {
    /// Constructs a response from a status code and raw body.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The raw response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for OkxHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OkxHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Transport-level failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkxTransportError {
    /// No route to the provider is configured.
    Unavailable,
    /// The provider call failed.
    Failed,
    /// The provider call timed out.
    Timeout,
}

impl OkxTransportError {
    /// Maps a transport failure onto the redacted client taxonomy.
    pub fn into_client_error(self) -> OkxClientError {
        match self {
            Self::Unavailable => OkxClientError::TransportUnavailable,
            Self::Failed | Self::Timeout => OkxClientError::TransportFailure,
        }
    }
}

impl fmt::Display for OkxTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("okx transport unavailable"),
            Self::Failed => formatter.write_str("okx transport failed"),
            Self::Timeout => formatter.write_str("okx transport timed out"),
        }
    }
}

/// Injected, mockable OKX transport.
///
/// Implementations must execute at most one physical request per invocation with
/// no automatic retry, attach exactly the supplied [`OkxAuthHeaders`], and never
/// log or persist credentials.
#[async_trait]
pub trait OkxTransport: Send + Sync {
    /// Sends one physical request and returns a bounded response.
    async fn send(
        &self,
        request: OkxRequest,
        auth: &OkxAuthHeaders,
    ) -> Result<OkxHttpResponse, OkxTransportError>;
}

/// Fail-closed default transport: no network route is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableOkxTransport;

#[async_trait]
impl OkxTransport for UnavailableOkxTransport {
    async fn send(
        &self,
        _request: OkxRequest,
        _auth: &OkxAuthHeaders,
    ) -> Result<OkxHttpResponse, OkxTransportError> {
        Err(OkxTransportError::Unavailable)
    }
}

/// Percent-encodes one query component (RFC 3986 unreserved set preserved).
pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{byte:02X}"));
            }
        }
    }
    encoded
}

fn is_valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= crate::auth::MAX_REQUEST_PATH_BYTES
        && path.starts_with('/')
        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn is_valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builds_and_redacts() {
        let request = OkxRequest::get(
            "/api/v5/dex/aggregator/quote",
            vec![
                ("chainIndex".to_string(), "8453".to_string()),
                ("fromTokenAddress".to_string(), "0xsecret".to_string()),
            ],
        )
        .expect("valid");
        assert_eq!(request.method(), OkxHttpMethod::Get);
        assert_eq!(request.query().len(), 2);
        assert_eq!(
            request.signed_path(),
            "/api/v5/dex/aggregator/quote?chainIndex=8453&fromTokenAddress=0xsecret"
        );
        assert!(request.signed_path().len() <= crate::auth::MAX_REQUEST_PATH_BYTES);
        let debug = format!("{request:?}");
        assert!(!debug.contains("0xsecret"));
        assert!(debug.contains("query_pairs"));

        // The total signed path is bounded, not just each component.
        let long = "a".repeat(1_024);
        let oversized: Vec<(String, String)> = (0..3)
            .map(|index| (format!("k{index}"), long.clone()))
            .collect();
        assert!(OkxRequest::get("/q", oversized).is_err());
    }

    #[test]
    fn invalid_paths_and_components_fail_closed() {
        assert!(OkxRequest::get("quote", Vec::new()).is_err());
        assert!(OkxRequest::get("/q", vec![("k".to_string(), String::new())]).is_err());
        assert!(OkxRequest::get("/q", vec![(String::new(), "v".to_string())]).is_err());
        assert!(OkxRequest::get("/q", vec![("k\n".to_string(), "v".to_string())]).is_err());
        assert!(OkxRequest::get("/q", vec![("k".to_string(), "v w".to_string())]).is_err());
        let too_many = (0..=MAX_QUERY_PAIRS)
            .map(|index| (format!("k{index}"), "v".to_string()))
            .collect();
        assert!(OkxRequest::get("/q", too_many).is_err());
    }

    #[test]
    fn percent_encoding_is_strict() {
        assert_eq!(percent_encode("aZ0-_.~"), "aZ0-_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("/"), "%2F");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn unavailable_transport_fails_closed() {
        let transport = UnavailableOkxTransport;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let credentials = crate::credentials::OkxCredentials::new("k", "s", "p").expect("valid");
        let auth = crate::auth::sign_request(&credentials, "GET", "/q", &[], 0).expect("signed");
        let result = runtime
            .block_on(transport.send(OkxRequest::get("/q", Vec::new()).expect("valid"), &auth));
        assert_eq!(result.err(), Some(OkxTransportError::Unavailable));
    }
}
