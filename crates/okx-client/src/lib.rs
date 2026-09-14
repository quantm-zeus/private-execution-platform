//! # OKX Swap client boundary (P84A)
//!
//! A narrow, read-only Rust client for the OKX DEX aggregator (Classic Swap)
//! quote API, used as an additional PEP routing source alongside the local
//! router. This slice contains **contracts, authentication, an injected
//! transport, and quote normalization only**: it never signs, submits, or holds
//! wallet key material, and it does not change any Trading Core behavior.
//!
//! ## Boundaries
//! - **Injected transport.** No socket is opened here. A caller supplies an
//!   [`OkxTransport`]; the fail-closed default is [`UnavailableOkxTransport`].
//! - **Server-side credentials.** [`OkxCredentials`] validates and zeroizes the
//!   API key, signing secret, and passphrase. They are redacted from every
//!   `Debug`/error surface and never serialized.
//! - **Untrusted responses.** Provider JSON is bounded and structurally
//!   validated before normalization; a response that does not match the
//!   requested chain/pair/amount fails closed.
//! - **PEP-native output.** [`OkxNormalizedQuote`] projects onto
//!   [`routing::ProviderQuote`] for the P80 provider-route benchmark comparator.
//! - No signing, transfer, relay, or execution surface; `#![forbid(unsafe_code)]`.
//!
//! ## Global posture
//! Live trading remains disabled and no real-funds action is performed by this
//! crate. Verification of an OKX transaction proposal before signing is a later
//! bounded slice (P84C).

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod credentials;
pub mod error;
pub mod quote;
pub mod transport;

pub use auth::{
    sign_request, OkxAuthHeaders, MAX_REQUEST_PATH_BYTES, OK_ACCESS_KEY, OK_ACCESS_PASSPHRASE,
    OK_ACCESS_SIGN, OK_ACCESS_TIMESTAMP,
};
pub use client::OkxClient;
pub use credentials::{OkxCredentials, MAX_CREDENTIAL_BYTES};
pub use error::OkxClientError;
pub use quote::{
    okx_chain_index, OkxApiConfig, OkxNormalizedQuote, OkxQuoteRequest, DEFAULT_API_PREFIX,
    MAX_API_PREFIX_BYTES, MAX_QUOTE_REFERENCE_BYTES, OKX_CHAIN_BASE, OKX_CHAIN_BNB,
    OKX_CHAIN_ETHEREUM, OKX_CHAIN_SOLANA,
};
pub use transport::{
    OkxHttpMethod, OkxHttpResponse, OkxRequest, OkxTransport, OkxTransportError,
    UnavailableOkxTransport, DEFAULT_MAX_RESPONSE_BYTES, MAX_QUERY_PAIRS, MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES_CEILING,
};

/// This crate is a read-only quoting boundary and possesses no trading capability.
pub const TRADING_ENABLED: bool = false;
