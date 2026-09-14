//! Typed OKX quote request/response contracts and PEP normalization.
//!
//! The wire types here are untrusted external input. They are parsed from a
//! bounded byte buffer, structurally validated, and only then projected onto a
//! redacted PEP-facing [`OkxNormalizedQuote`], which can in turn produce a
//! [`routing::ProviderQuote`] for the P80 provider-route benchmark comparator.
//!
//! Version/configurability: the API path prefix (including the v5 version
//! segment) is caller-configurable through [`OkxApiConfig`]; the default is
//! [`DEFAULT_API_PREFIX`].
//!
//! Redaction: [`OkxNormalizedQuote`] and [`OkxQuoteRequest`] carry execution
//! economics (assets, amounts) and therefore render payload-free `Debug`. The
//! opaque provider reference is never rendered.

use std::fmt;

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps};
use routing::{BenchmarkSource, ProviderQuote};
use serde::Deserialize;

use crate::error::OkxClientError;
use crate::transport::OkxRequest;

/// Default OKX DEX aggregator API prefix (v5).
pub const DEFAULT_API_PREFIX: &str = "/api/v5/dex/aggregator";

/// Maximum accepted API path-prefix length in bytes.
pub const MAX_API_PREFIX_BYTES: usize = 128;

/// Maximum accepted opaque provider-reference length in bytes.
pub const MAX_QUOTE_REFERENCE_BYTES: usize = 256;

/// OKX chain index for Solana.
pub const OKX_CHAIN_SOLANA: u64 = 501;
/// OKX chain index for Ethereum mainnet.
pub const OKX_CHAIN_ETHEREUM: u64 = 1;
/// OKX chain index for Base.
pub const OKX_CHAIN_BASE: u64 = 8_453;
/// OKX chain index for BNB Smart Chain.
pub const OKX_CHAIN_BNB: u64 = 56;

/// Version/configurable OKX API endpoint settings.
#[derive(Clone, PartialEq, Eq)]
pub struct OkxApiConfig {
    prefix: String,
    max_response_bytes: usize,
}

impl Default for OkxApiConfig {
    fn default() -> Self {
        Self {
            prefix: DEFAULT_API_PREFIX.to_string(),
            max_response_bytes: crate::transport::DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

impl OkxApiConfig {
    /// Validates and constructs a configuration for `prefix`.
    ///
    /// `prefix` must start with `/`, contain only printable non-space ASCII, and
    /// must not end with `/`.
    pub fn new(prefix: impl Into<String>) -> Result<Self, OkxClientError> {
        let prefix = prefix.into();
        if !is_valid_prefix(&prefix) {
            return Err(OkxClientError::InvalidRequest);
        }
        Ok(Self {
            prefix,
            max_response_bytes: crate::transport::DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Overrides the accepted response-body bound.
    ///
    /// `0` and values above the hard ceiling are rejected.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self, OkxClientError> {
        if bytes == 0 || bytes > crate::transport::MAX_RESPONSE_BYTES_CEILING {
            return Err(OkxClientError::InvalidRequest);
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }

    /// The configured path prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The configured response-body bound.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

impl fmt::Debug for OkxApiConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OkxApiConfig")
            .field("prefix", &self.prefix)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// A validated exact-input OKX quote request.
#[derive(Clone, PartialEq, Eq)]
pub struct OkxQuoteRequest {
    chain: ChainId,
    token_in: AssetId,
    token_out: AssetId,
    amount_in: AtomicAmount,
    slippage_bps: Option<Bps>,
}

impl OkxQuoteRequest {
    /// Validates and constructs a quote request bound to one chain and pair.
    ///
    /// The chain must have a configured OKX index, both assets must be valid and
    /// live on that chain, the amount must be non-zero, and the assets must be
    /// distinct.
    pub fn new(
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: AtomicAmount,
        slippage_bps: Option<Bps>,
    ) -> Result<Self, OkxClientError> {
        chain
            .validate()
            .map_err(|_| OkxClientError::InvalidRequest)?;
        token_in
            .validate()
            .map_err(|_| OkxClientError::InvalidRequest)?;
        token_out
            .validate()
            .map_err(|_| OkxClientError::InvalidRequest)?;
        if token_in.chain != chain || token_out.chain != chain {
            return Err(OkxClientError::InvalidRequest);
        }
        if token_in == token_out {
            return Err(OkxClientError::InvalidRequest);
        }
        if amount_in.is_zero() {
            return Err(OkxClientError::InvalidRequest);
        }
        okx_chain_index(&chain)?;
        Ok(Self {
            chain,
            token_in,
            token_out,
            amount_in,
            slippage_bps,
        })
    }

    /// The bound chain.
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// The input asset.
    pub fn token_in(&self) -> &AssetId {
        &self.token_in
    }

    /// The output asset.
    pub fn token_out(&self) -> &AssetId {
        &self.token_out
    }

    /// The exact input amount in `token_in` atomic units.
    pub fn amount_in(&self) -> AtomicAmount {
        self.amount_in
    }

    /// The optional slippage tolerance.
    pub fn slippage_bps(&self) -> Option<Bps> {
        self.slippage_bps
    }

    /// Builds the exact HTTP request this quote is fetched with.
    pub(crate) fn to_http(&self, config: &OkxApiConfig) -> Result<OkxRequest, OkxClientError> {
        let chain_index = okx_chain_index(&self.chain)?;
        let mut query = vec![
            ("chainIndex".to_string(), chain_index.to_string()),
            (
                "fromTokenAddress".to_string(),
                self.token_in.address.clone(),
            ),
            ("toTokenAddress".to_string(), self.token_out.address.clone()),
            ("amount".to_string(), self.amount_in.get().to_string()),
        ];
        if let Some(slippage) = self.slippage_bps {
            query.push((
                "slippage".to_string(),
                format_bps_as_percent(slippage.get()),
            ));
        }
        OkxRequest::get(format!("{}/quote", config.prefix()), query)
    }
}

impl fmt::Debug for OkxQuoteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Assets and amounts are execution economics; render cardinalities only.
        formatter
            .debug_struct("OkxQuoteRequest")
            .field("has_slippage", &self.slippage_bps.is_some())
            .finish_non_exhaustive()
    }
}

/// Normalized, redacted OKX quote economics.
#[derive(Clone, PartialEq, Eq)]
pub struct OkxNormalizedQuote {
    chain: ChainId,
    token_in: AssetId,
    token_out: AssetId,
    amount_in: u128,
    amount_out: u128,
    reference: String,
    observed_at_ms: i64,
}

impl OkxNormalizedQuote {
    /// The quote's chain.
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// The input asset.
    pub fn token_in(&self) -> &AssetId {
        &self.token_in
    }

    /// The output asset.
    pub fn token_out(&self) -> &AssetId {
        &self.token_out
    }

    /// Net input in `token_in` atomic units.
    pub fn amount_in(&self) -> u128 {
        self.amount_in
    }

    /// Net output in `token_out` atomic units.
    pub fn amount_out(&self) -> u128 {
        self.amount_out
    }

    /// The opaque, non-secret provider reference (never rendered by `Debug`).
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// The caller reference instant the quote was observed at, in milliseconds.
    pub fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    /// Projects this quote into the P80 provider-route benchmark model,
    /// preserving the observed instant so freshness gating is exact.
    pub fn to_provider_quote(
        &self,
        source: BenchmarkSource,
    ) -> Result<ProviderQuote, OkxClientError> {
        ProviderQuote::new(
            source,
            self.chain.clone(),
            self.token_in.clone(),
            self.token_out.clone(),
            self.amount_in,
            self.amount_out,
            self.observed_at_ms,
            self.reference.clone(),
        )
        .map_err(|_| OkxClientError::NormalizationFailed)
    }
}

impl fmt::Debug for OkxNormalizedQuote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Amounts, assets, chain, and reference are private execution economics.
        formatter
            .debug_struct("OkxNormalizedQuote")
            .finish_non_exhaustive()
    }
}

/// Maps a PEP [`ChainId`] to its OKX chain index, failing closed if unknown.
pub fn okx_chain_index(chain: &ChainId) -> Result<u64, OkxClientError> {
    match chain {
        ChainId::Solana => Ok(OKX_CHAIN_SOLANA),
        ChainId::Ethereum => Ok(OKX_CHAIN_ETHEREUM),
        ChainId::Base => Ok(OKX_CHAIN_BASE),
        ChainId::BnbChain => Ok(OKX_CHAIN_BNB),
        ChainId::RobinhoodAssociated => Err(OkxClientError::UnsupportedChain),
        ChainId::Other(value) => canonical_chain_index(value),
    }
}

/// Parses a numeric [`ChainId::Other`] value canonically.
///
/// The value must be non-empty, all ASCII digits, and must not carry a leading
/// zero unless it is exactly `"0"`. This rejects non-canonical spellings such as
/// `"01"` or `"+1"` that would otherwise parse to an ambiguous index.
fn canonical_chain_index(value: &str) -> Result<u64, OkxClientError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OkxClientError::UnsupportedChain);
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(OkxClientError::UnsupportedChain);
    }
    value
        .parse::<u64>()
        .map_err(|_| OkxClientError::UnsupportedChain)
}

/// Renders basis points as the OKX percentage string (for example `50` -> `0.5`).
pub(crate) fn format_bps_as_percent(bps: u16) -> String {
    let whole = bps / 100;
    let fraction = bps % 100;
    if fraction == 0 {
        whole.to_string()
    } else if fraction % 10 == 0 {
        format!("{whole}.{}", fraction / 10)
    } else {
        format!("{whole}.{fraction:02}")
    }
}

fn is_valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= MAX_API_PREFIX_BYTES
        && prefix.starts_with('/')
        && !prefix.ends_with('/')
        && prefix.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~')
        })
}

/// Untrusted OKX quote envelope (wire shape).
#[derive(Deserialize)]
pub(crate) struct OkxQuoteEnvelope {
    code: String,
    #[serde(default)]
    #[allow(dead_code)]
    msg: Option<String>,
    #[serde(default)]
    data: Vec<OkxQuoteDataWire>,
}

/// Untrusted OKX quote row. Amounts are expected as decimal integer strings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OkxQuoteDataWire {
    #[serde(default)]
    chain_index: Option<String>,
    #[serde(default)]
    from_token_amount: Option<String>,
    #[serde(default)]
    to_token_amount: Option<String>,
    #[serde(default)]
    from_token_address: Option<String>,
    #[serde(default)]
    to_token_address: Option<String>,
    #[serde(default)]
    from_token: Option<OkxTokenWire>,
    #[serde(default)]
    to_token: Option<OkxTokenWire>,
    #[serde(default)]
    quote_id: Option<String>,
}

/// Untrusted nested token descriptor.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OkxTokenWire {
    #[serde(default)]
    token_contract_address: Option<String>,
}

/// Validates an untrusted envelope against `request` and normalizes it.
pub(crate) fn normalize_quote(
    request: &OkxQuoteRequest,
    envelope: OkxQuoteEnvelope,
    observed_at_ms: i64,
) -> Result<OkxNormalizedQuote, OkxClientError> {
    if envelope.code != "0" {
        return Err(OkxClientError::ProviderError);
    }
    if envelope.data.len() != 1 {
        return Err(OkxClientError::MalformedResponse);
    }
    let data = &envelope.data[0];

    // The response chain index is mandatory: an absent binding is malformed,
    // never silently trusted as "probably the requested chain".
    let chain_index = data
        .chain_index
        .as_deref()
        .ok_or(OkxClientError::MalformedResponse)?;
    let expected = okx_chain_index(request.chain())?;
    if chain_index != expected.to_string() {
        return Err(OkxClientError::QuoteMismatch);
    }

    let from_address =
        resolve_address(data.from_token_address.as_deref(), data.from_token.as_ref())?;
    let to_address = resolve_address(data.to_token_address.as_deref(), data.to_token.as_ref())?;
    if from_address != request.token_in().address || to_address != request.token_out().address {
        return Err(OkxClientError::QuoteMismatch);
    }

    let from_amount = parse_atomic_decimal(data.from_token_amount.as_deref(), false)?;
    let to_amount = parse_atomic_decimal(data.to_token_amount.as_deref(), true)?;
    if from_amount != request.amount_in().get() {
        return Err(OkxClientError::QuoteMismatch);
    }

    let reference = data
        .quote_id
        .as_deref()
        .filter(|value| is_valid_reference(value))
        .unwrap_or("okx")
        .to_string();

    Ok(OkxNormalizedQuote {
        chain: request.chain().clone(),
        token_in: request.token_in().clone(),
        token_out: request.token_out().clone(),
        amount_in: from_amount,
        amount_out: to_amount,
        reference,
        observed_at_ms,
    })
}

fn resolve_address<'a>(
    top_level: Option<&'a str>,
    nested: Option<&'a OkxTokenWire>,
) -> Result<&'a str, OkxClientError> {
    let top_level = top_level.filter(|address| !address.is_empty());
    let nested = nested
        .and_then(|token| token.token_contract_address.as_deref())
        .filter(|address| !address.is_empty());
    match (top_level, nested) {
        // Both spellings are present: they must agree, or the row is ambiguous.
        (Some(top_level), Some(nested)) => {
            if top_level == nested {
                Ok(top_level)
            } else {
                Err(OkxClientError::MalformedResponse)
            }
        }
        (Some(address), None) | (None, Some(address)) => Ok(address),
        (None, None) => Err(OkxClientError::MalformedResponse),
    }
}

/// Parses a strict non-negative decimal integer atomic amount.
///
/// `require_nonzero` additionally rejects a zero output.
fn parse_atomic_decimal(
    value: Option<&str>,
    require_nonzero: bool,
) -> Result<u128, OkxClientError> {
    let value = value.ok_or(OkxClientError::MalformedResponse)?;
    if value.is_empty() || value.len() > 39 {
        return Err(OkxClientError::MalformedResponse);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OkxClientError::MalformedResponse);
    }
    // Canonical decimal: only `"0"` may begin with `0`.
    if value.len() > 1 && value.starts_with('0') {
        return Err(OkxClientError::MalformedResponse);
    }
    let parsed = value
        .parse::<u128>()
        .map_err(|_| OkxClientError::MalformedResponse)?;
    if require_nonzero && parsed == 0 {
        return Err(OkxClientError::QuoteMismatch);
    }
    Ok(parsed)
}

fn is_valid_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_QUOTE_REFERENCE_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> OkxQuoteRequest {
        OkxQuoteRequest::new(
            ChainId::Base,
            AssetId::new(ChainId::Base, "0xaaaa").expect("asset"),
            AssetId::new(ChainId::Base, "0xbbbb").expect("asset"),
            AtomicAmount::new(1_000),
            None,
        )
        .expect("request")
    }

    #[test]
    fn chain_indices_are_pinned() {
        assert_eq!(okx_chain_index(&ChainId::Solana), Ok(501));
        assert_eq!(okx_chain_index(&ChainId::Ethereum), Ok(1));
        assert_eq!(okx_chain_index(&ChainId::Base), Ok(8_453));
        assert_eq!(okx_chain_index(&ChainId::BnbChain), Ok(56));
        assert_eq!(
            okx_chain_index(&ChainId::RobinhoodAssociated),
            Err(OkxClientError::UnsupportedChain)
        );
        assert_eq!(
            okx_chain_index(&ChainId::Other("hypercore".to_string())),
            Err(OkxClientError::UnsupportedChain)
        );
        assert_eq!(okx_chain_index(&ChainId::Other("137".to_string())), Ok(137));
    }

    #[test]
    fn chain_index_parsing_is_canonical() {
        assert_eq!(okx_chain_index(&ChainId::Other("137".to_string())), Ok(137));
        assert_eq!(okx_chain_index(&ChainId::Other("1".to_string())), Ok(1));
        assert_eq!(okx_chain_index(&ChainId::Other("0".to_string())), Ok(0));
        for non_canonical in ["01", "+1", "-1", " 1", "1 ", "00", "1_0", ""] {
            assert_eq!(
                okx_chain_index(&ChainId::Other(non_canonical.to_string())),
                Err(OkxClientError::UnsupportedChain),
                "non-canonical value {non_canonical:?} must be rejected"
            );
        }
    }

    #[test]
    fn ambiguous_address_spellings_fail_closed() {
        let nested = |address: &str| OkxTokenWire {
            token_contract_address: Some(address.to_string()),
        };

        // (a) both present and equal -> accepted.
        assert_eq!(
            resolve_address(Some("0xaaaa"), Some(&nested("0xaaaa"))),
            Ok("0xaaaa")
        );
        // (b) both present and different -> ambiguous.
        assert_eq!(
            resolve_address(Some("0xaaaa"), Some(&nested("0xdddd"))),
            Err(OkxClientError::MalformedResponse)
        );
        // (c) only nested -> accepted.
        assert_eq!(resolve_address(None, Some(&nested("0xaaaa"))), Ok("0xaaaa"));
        // (d) only top-level -> accepted.
        assert_eq!(resolve_address(Some("0xaaaa"), None), Ok("0xaaaa"));
        // Empty spellings are treated as absent.
        assert_eq!(
            resolve_address(Some(""), Some(&nested("0xaaaa"))),
            Ok("0xaaaa")
        );
        assert_eq!(
            resolve_address(Some("0xaaaa"), Some(&nested(""))),
            Ok("0xaaaa")
        );
        // Neither present -> malformed.
        assert_eq!(
            resolve_address(None, None),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            resolve_address(Some(""), Some(&nested(""))),
            Err(OkxClientError::MalformedResponse)
        );
    }

    #[test]
    fn bps_percent_formatting_is_exact() {
        assert_eq!(format_bps_as_percent(0), "0");
        assert_eq!(format_bps_as_percent(1), "0.01");
        assert_eq!(format_bps_as_percent(10), "0.1");
        assert_eq!(format_bps_as_percent(50), "0.5");
        assert_eq!(format_bps_as_percent(99), "0.99");
        assert_eq!(format_bps_as_percent(100), "1");
        assert_eq!(format_bps_as_percent(10_000), "100");
    }

    #[test]
    fn request_validation_fails_closed() {
        let base = AssetId::new(ChainId::Base, "0xaaaa").expect("asset");
        let sol = AssetId::new(ChainId::Solana, "So111").expect("asset");
        assert!(OkxQuoteRequest::new(
            ChainId::Base,
            base.clone(),
            base.clone(),
            AtomicAmount::new(1),
            None
        )
        .is_err());
        assert!(OkxQuoteRequest::new(
            ChainId::Base,
            base.clone(),
            sol.clone(),
            AtomicAmount::new(1),
            None
        )
        .is_err());
        assert!(OkxQuoteRequest::new(
            ChainId::Base,
            base.clone(),
            AssetId::new(ChainId::Base, "0xbbbb").expect("asset"),
            AtomicAmount::ZERO,
            None
        )
        .is_err());
        assert!(OkxQuoteRequest::new(
            ChainId::RobinhoodAssociated,
            AssetId::new(ChainId::RobinhoodAssociated, "0xaaaa").expect("asset"),
            AssetId::new(ChainId::RobinhoodAssociated, "0xbbbb").expect("asset"),
            AtomicAmount::new(1),
            None
        )
        .is_err());
    }

    #[test]
    fn request_http_shape_is_exact() {
        let request = base_request();
        let http = request
            .to_http(&OkxApiConfig::default())
            .expect("http request");
        assert_eq!(
            http.signed_path(),
            "/api/v5/dex/aggregator/quote?chainIndex=8453&fromTokenAddress=0xaaaa&toTokenAddress=0xbbbb&amount=1000"
        );
    }

    #[test]
    fn request_http_includes_optional_slippage() {
        let request = OkxQuoteRequest::new(
            ChainId::Base,
            AssetId::new(ChainId::Base, "0xaaaa").expect("asset"),
            AssetId::new(ChainId::Base, "0xbbbb").expect("asset"),
            AtomicAmount::new(1_000),
            Some(Bps::new(50).expect("bps")),
        )
        .expect("request");
        let http = request
            .to_http(&OkxApiConfig::default())
            .expect("http request");
        assert!(http.signed_path().ends_with("&slippage=0.5"));
    }

    #[test]
    fn api_config_validation() {
        assert!(OkxApiConfig::new("/api/v5/dex/aggregator").is_ok());
        assert!(OkxApiConfig::new("api/v5").is_err());
        assert!(OkxApiConfig::new("/api/v5/").is_err());
        assert!(OkxApiConfig::new("/api/v5 dex").is_err());
        assert!(OkxApiConfig::new("/api?v=5").is_err());
        assert!(OkxApiConfig::default().with_max_response_bytes(0).is_err());
        assert!(OkxApiConfig::default()
            .with_max_response_bytes(MAX_API_PREFIX_BYTES)
            .is_ok());
        assert!(OkxApiConfig::default()
            .with_max_response_bytes(crate::transport::MAX_RESPONSE_BYTES_CEILING + 1)
            .is_err());
    }

    #[test]
    fn parse_atomic_decimal_is_strict() {
        assert_eq!(parse_atomic_decimal(Some("0"), false), Ok(0));
        assert_eq!(parse_atomic_decimal(Some("1000"), false), Ok(1_000));
        assert_eq!(
            parse_atomic_decimal(Some("0"), true),
            Err(OkxClientError::QuoteMismatch)
        );
        assert_eq!(
            parse_atomic_decimal(Some("+1"), false),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            parse_atomic_decimal(Some("1.0"), false),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            parse_atomic_decimal(Some(""), false),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            parse_atomic_decimal(None, false),
            Err(OkxClientError::MalformedResponse)
        );
        let overflow = "9".repeat(39);
        assert_eq!(
            parse_atomic_decimal(Some(&overflow), false),
            Err(OkxClientError::MalformedResponse)
        );
        // Canonical decimal only: `"0"` is valid, leading zeros are not.
        assert_eq!(parse_atomic_decimal(Some("0"), false), Ok(0));
        assert_eq!(
            parse_atomic_decimal(Some("0"), true),
            Err(OkxClientError::QuoteMismatch)
        );
        for leading_zero in ["00", "01", "01000"] {
            assert_eq!(
                parse_atomic_decimal(Some(leading_zero), false),
                Err(OkxClientError::MalformedResponse),
                "leading-zero value {leading_zero:?} must be rejected"
            );
        }
    }

    #[test]
    fn response_row_without_chain_index_is_rejected() {
        let request = base_request();
        // This row was accepted before chain binding became mandatory.
        let payload = r#"{
            "code":"0",
            "msg":"",
            "data":[{
                "fromTokenAddress":"0xaaaa",
                "toTokenAddress":"0xbbbb",
                "fromTokenAmount":"1000",
                "toTokenAmount":"2500"
            }]
        }"#;
        let envelope: OkxQuoteEnvelope = serde_json::from_str(payload).expect("fixture");
        assert_eq!(
            normalize_quote(&request, envelope, 123),
            Err(OkxClientError::MalformedResponse)
        );
    }

    #[test]
    fn response_row_with_mismatched_chain_index_is_rejected() {
        let request = base_request();
        let payload = r#"{
            "code":"0",
            "msg":"",
            "data":[{
                "chainIndex":"1",
                "fromTokenAddress":"0xaaaa",
                "toTokenAddress":"0xbbbb",
                "fromTokenAmount":"1000",
                "toTokenAmount":"2500"
            }]
        }"#;
        let envelope: OkxQuoteEnvelope = serde_json::from_str(payload).expect("fixture");
        assert_eq!(
            normalize_quote(&request, envelope, 123),
            Err(OkxClientError::QuoteMismatch)
        );
    }

    #[test]
    fn ambiguous_response_address_fields_are_rejected() {
        let request = base_request();
        let from_side = r#"{
            "code":"0",
            "msg":"",
            "data":[{
                "chainIndex":"8453",
                "fromTokenAddress":"0xaaaa",
                "fromToken":{"tokenContractAddress":"0xdddd"},
                "toTokenAddress":"0xbbbb",
                "fromTokenAmount":"1000",
                "toTokenAmount":"2500"
            }]
        }"#;
        let to_side = r#"{
            "code":"0",
            "msg":"",
            "data":[{
                "chainIndex":"8453",
                "fromTokenAddress":"0xaaaa",
                "toTokenAddress":"0xbbbb",
                "toToken":{"tokenContractAddress":"0xdddd"},
                "fromTokenAmount":"1000",
                "toTokenAmount":"2500"
            }]
        }"#;
        for payload in [from_side, to_side] {
            let envelope: OkxQuoteEnvelope = serde_json::from_str(payload).expect("fixture");
            assert_eq!(
                normalize_quote(&request, envelope, 123),
                Err(OkxClientError::MalformedResponse)
            );
        }
    }

    #[test]
    fn normalized_quote_redacts_and_projects() {
        let request = base_request();
        let payload = r#"{
            "code":"0",
            "msg":"",
            "data":[{
                "chainIndex":"8453",
                "fromTokenAddress":"0xaaaa",
                "toTokenAddress":"0xbbbb",
                "fromTokenAmount":"1000",
                "toTokenAmount":"2500",
                "quoteId":"q-1"
            }]
        }"#;
        let envelope: OkxQuoteEnvelope = serde_json::from_str(payload).expect("fixture");
        let normalized = normalize_quote(&request, envelope, 123).expect("normalized");
        assert_eq!(normalized.amount_in(), 1_000);
        assert_eq!(normalized.amount_out(), 2_500);
        assert_eq!(normalized.reference(), "q-1");
        assert_eq!(normalized.observed_at_ms(), 123);

        let debug = format!("{normalized:?}");
        assert!(!debug.contains("2500"));
        assert!(!debug.contains("0xaaaa"));

        let source = BenchmarkSource::new("okx").expect("source");
        let provider = normalized
            .to_provider_quote(source)
            .expect("provider quote");
        assert_eq!(provider.amount_in, 1_000);
        assert_eq!(provider.amount_out, 2_500);
        assert_eq!(provider.reference(), "q-1");
        assert_eq!(provider.observed_at_ms, 123);
    }
}
