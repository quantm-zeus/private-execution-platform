//! Typed, untrusted OKX DEX aggregator swap-proposal contract.
//!
//! This module fetches and strictly parses the OKX aggregator `/swap` response
//! into an [`OkxSwapProposal`]. It is deliberately inert: it does **not** sign,
//! submit, relay, or verify anything, and it holds no key material. Every field
//! of a proposal is untrusted external input; the type merely guarantees a
//! bounded, structurally valid, request-bound shape for a downstream verifier
//! (the separate provider-verification slice) to accept or reject.
//!
//! Fail-closed posture (mirroring [`crate::quote`]):
//! - the wire shape is parsed from a bounded byte buffer;
//! - `chainIndex` is mandatory and must match the request;
//! - the token pair and DEX input amount returned by the provider must match the
//!   validated request;
//! - amounts are strict canonical decimal integer strings (no floats, signs,
//!   leading zeros, or numeric JSON tokens);
//! - token address spellings may appear top-level or nested, but two different
//!   spellings for one side are ambiguous and rejected;
//! - `tx.data` must be a bounded, non-empty, even-length `0x`-prefixed hex
//!   string, and [`OkxSwapProposal::calldata_digest`] is the SHA-256 of the
//!   decoded bytes;
//! - wallet, router, receiver, spender, and `minReceiveAmount` are structurally
//!   validated and bounded.
//!
//! Redaction: [`OkxSwapRequest`] and [`OkxSwapProposal`] carry execution
//! economics (addresses, amounts, calldata, digest), so both render a
//! payload-free `Debug`. Neither implements `Serialize`/`Deserialize`.

use std::fmt;

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::OkxClientError;
use crate::quote::{
    format_bps_as_percent, okx_chain_index, parse_atomic_decimal, resolve_address, OkxApiConfig,
    OkxTokenWire,
};
use crate::transport::OkxRequest;

/// Maximum accepted decoded calldata length in bytes (32 KiB).
pub const MAX_CALLDATA_BYTES: usize = 32 * 1024;

/// Maximum accepted address/label length in bytes.
pub const MAX_ADDRESS_BYTES: usize = 128;

/// A validated exact-input OKX swap request.
#[derive(Clone, PartialEq, Eq)]
pub struct OkxSwapRequest {
    chain: ChainId,
    token_in: AssetId,
    token_out: AssetId,
    amount_in: AtomicAmount,
    slippage_bps: Option<Bps>,
    user_wallet_address: String,
}

impl OkxSwapRequest {
    /// Validates and constructs a swap request bound to one chain, pair, and
    /// user wallet.
    ///
    /// The chain must have a configured OKX index, both assets must be valid and
    /// live on that chain, the amount must be non-zero, the assets must be
    /// distinct, and the wallet must be a bounded, printable non-space ASCII
    /// label.
    pub fn new(
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: AtomicAmount,
        slippage_bps: Option<Bps>,
        user_wallet_address: impl Into<String>,
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
        let user_wallet_address = user_wallet_address.into();
        if !is_valid_address(&user_wallet_address) {
            return Err(OkxClientError::InvalidRequest);
        }
        Ok(Self {
            chain,
            token_in,
            token_out,
            amount_in,
            slippage_bps,
            user_wallet_address,
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

    /// The user wallet address the swap is requested for.
    pub fn user_wallet_address(&self) -> &str {
        &self.user_wallet_address
    }

    /// Builds the exact HTTP request this swap proposal is fetched with.
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
        query.push((
            "userWalletAddress".to_string(),
            self.user_wallet_address.clone(),
        ));
        OkxRequest::get(format!("{}/swap", config.prefix()), query)
    }
}

impl fmt::Debug for OkxSwapRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Assets, amounts, and the wallet address are execution economics.
        formatter
            .debug_struct("OkxSwapRequest")
            .field("has_slippage", &self.slippage_bps.is_some())
            .finish_non_exhaustive()
    }
}

/// Untrusted, bounded OKX swap transaction proposal.
///
/// Every accessor exposes raw provider data. Nothing here is verified or
/// trusted; a proposal must be handed to a verifier before it can influence a
/// signature or a funds movement.
#[derive(Clone, PartialEq, Eq)]
pub struct OkxSwapProposal {
    chain: ChainId,
    wallet: String,
    receiver: String,
    router: String,
    spender: Option<String>,
    token_in: AssetId,
    token_out: AssetId,
    amount_in: u128,
    amount_out: u128,
    min_receive_amount: Option<u128>,
    value: u128,
    calldata: Vec<u8>,
    calldata_digest: [u8; 32],
    observed_at_ms: i64,
}

impl OkxSwapProposal {
    /// The chain the proposal executes on.
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// The owner wallet (`tx.from`).
    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    /// The output recipient, falling back to [`Self::wallet`] when the provider
    /// did not report one.
    pub fn receiver(&self) -> &str {
        &self.receiver
    }

    /// The router contract the transaction calls (`tx.to`).
    pub fn router(&self) -> &str {
        &self.router
    }

    /// The approval spender, when the response includes one.
    pub fn spender(&self) -> Option<&str> {
        self.spender.as_deref()
    }

    /// The requested input asset.
    pub fn token_in(&self) -> &AssetId {
        &self.token_in
    }

    /// The requested output asset.
    pub fn token_out(&self) -> &AssetId {
        &self.token_out
    }

    /// The DEX input amount (`fromTokenAmount`) in `token_in` atomic units.
    pub fn amount_in(&self) -> u128 {
        self.amount_in
    }

    /// The quoted output amount (`toTokenAmount`) in `token_out` atomic units.
    pub fn amount_out(&self) -> u128 {
        self.amount_out
    }

    /// The transaction-enforced minimum output, when provided.
    pub fn min_receive_amount(&self) -> Option<u128> {
        self.min_receive_amount
    }

    /// The native value attached to the transaction.
    pub fn value(&self) -> u128 {
        self.value
    }

    /// The raw transaction calldata bytes.
    pub fn calldata(&self) -> &[u8] {
        &self.calldata
    }

    /// `SHA-256(calldata bytes)`.
    pub fn calldata_digest(&self) -> [u8; 32] {
        self.calldata_digest
    }

    /// The caller reference instant the proposal was observed at, in
    /// milliseconds.
    pub fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }
}

impl fmt::Debug for OkxSwapProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Addresses, amounts, calldata, and the digest are execution economics.
        formatter
            .debug_struct("OkxSwapProposal")
            .finish_non_exhaustive()
    }
}

/// Untrusted OKX swap envelope (wire shape).
#[derive(Deserialize)]
pub(crate) struct OkxSwapEnvelope {
    code: String,
    #[serde(default)]
    #[allow(dead_code)]
    msg: Option<String>,
    #[serde(default)]
    data: Vec<OkxSwapDataWire>,
}

/// Untrusted OKX swap row. Amounts are expected as canonical decimal strings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OkxSwapDataWire {
    #[serde(default)]
    chain_index: Option<String>,
    #[serde(default)]
    from_token_amount: Option<String>,
    #[serde(default)]
    to_token_amount: Option<String>,
    #[serde(default)]
    min_receive_amount: Option<String>,
    #[serde(default)]
    from_token_address: Option<String>,
    #[serde(default)]
    to_token_address: Option<String>,
    #[serde(default)]
    from_token: Option<OkxTokenWire>,
    #[serde(default)]
    to_token: Option<OkxTokenWire>,
    #[serde(default)]
    receiver: Option<String>,
    #[serde(default)]
    spender: Option<String>,
    #[serde(default)]
    approve_target: Option<String>,
    #[serde(default)]
    approval: Option<OkxSwapApprovalWire>,
    #[serde(default)]
    tx: Option<OkxSwapTxWire>,
}

/// Untrusted nested approval descriptor.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OkxSwapApprovalWire {
    #[serde(default)]
    spender: Option<String>,
    #[serde(default)]
    approve_target: Option<String>,
}

/// Untrusted nested transaction descriptor.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OkxSwapTxWire {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    min_receive_amount: Option<String>,
    #[serde(default)]
    spender: Option<String>,
    #[serde(default)]
    approve_target: Option<String>,
}

/// Validates an untrusted swap envelope against `request` and normalizes it.
pub(crate) fn normalize_swap(
    request: &OkxSwapRequest,
    envelope: OkxSwapEnvelope,
    observed_at_ms: i64,
) -> Result<OkxSwapProposal, OkxClientError> {
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
    if from_amount != request.amount_in().get() {
        return Err(OkxClientError::QuoteMismatch);
    }
    // A zero quoted output is not a usable proposal.
    let to_amount = parse_atomic_decimal(data.to_token_amount.as_deref(), true)?;

    let tx = data.tx.as_ref().ok_or(OkxClientError::MalformedResponse)?;
    let wallet = require_address(tx.from.as_deref())?;
    let router = require_address(tx.to.as_deref())?;

    let value = parse_atomic_decimal(tx.value.as_deref(), false)?;
    let calldata = decode_calldata(tx.data.as_deref())?;
    let calldata_digest: [u8; 32] = Sha256::digest(&calldata).into();

    let min_receive_amount = resolve_optional_decimal([
        data.min_receive_amount.as_deref(),
        tx.min_receive_amount.as_deref(),
    ])?;

    let spender = resolve_optional_address(&[
        data.spender.as_deref(),
        data.approve_target.as_deref(),
        data.approval
            .as_ref()
            .and_then(|approval| approval.spender.as_deref()),
        data.approval
            .as_ref()
            .and_then(|approval| approval.approve_target.as_deref()),
        tx.spender.as_deref(),
        tx.approve_target.as_deref(),
    ])?;

    let receiver = resolve_optional_address(&[
        data.receiver.as_deref(),
        data.from_token
            .as_ref()
            .and_then(|token| token.receiver.as_deref()),
        data.to_token
            .as_ref()
            .and_then(|token| token.receiver.as_deref()),
    ])?
    .unwrap_or_else(|| wallet.clone());

    Ok(OkxSwapProposal {
        chain: request.chain().clone(),
        wallet,
        receiver,
        router,
        spender,
        token_in: request.token_in().clone(),
        token_out: request.token_out().clone(),
        amount_in: from_amount,
        amount_out: to_amount,
        min_receive_amount,
        value,
        calldata,
        calldata_digest,
        observed_at_ms,
    })
}

/// Validates a bounded, printable non-space ASCII address/label.
fn is_valid_address(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ADDRESS_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Requires a mandatory, structurally valid address/label.
fn require_address(value: Option<&str>) -> Result<String, OkxClientError> {
    let value = value.ok_or(OkxClientError::MalformedResponse)?;
    if !is_valid_address(value) {
        return Err(OkxClientError::MalformedResponse);
    }
    Ok(value.to_string())
}

/// Resolves zero or more optional address spellings, requiring every present,
/// non-empty spelling to agree. Empty spellings are treated as absent.
fn resolve_optional_address(candidates: &[Option<&str>]) -> Result<Option<String>, OkxClientError> {
    let mut resolved: Option<&str> = None;
    for candidate in candidates.iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        if !is_valid_address(candidate) {
            return Err(OkxClientError::MalformedResponse);
        }
        match resolved {
            Some(existing) if existing != *candidate => {
                return Err(OkxClientError::MalformedResponse)
            }
            _ => resolved = Some(candidate),
        }
    }
    Ok(resolved.map(str::to_string))
}

/// Resolves zero or more optional canonical decimal amounts, requiring every
/// present, non-empty spelling to agree.
fn resolve_optional_decimal(candidates: [Option<&str>; 2]) -> Result<Option<u128>, OkxClientError> {
    let mut resolved: Option<u128> = None;
    for candidate in candidates.into_iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        let parsed = parse_atomic_decimal(Some(candidate), false)?;
        match resolved {
            Some(existing) if existing != parsed => return Err(OkxClientError::MalformedResponse),
            _ => resolved = Some(parsed),
        }
    }
    Ok(resolved)
}

/// Decodes a bounded, non-empty, even-length `0x`-prefixed hex calldata string.
fn decode_calldata(value: Option<&str>) -> Result<Vec<u8>, OkxClientError> {
    let value = value.ok_or(OkxClientError::MalformedResponse)?;
    let body = value
        .strip_prefix("0x")
        .ok_or(OkxClientError::MalformedResponse)?;
    // Reject empty output and odd nibble counts before allocating.
    if body.is_empty() || body.len() % 2 != 0 || body.len() > MAX_CALLDATA_BYTES * 2 {
        return Err(OkxClientError::MalformedResponse);
    }
    let mut decoded = Vec::with_capacity(body.len() / 2);
    for pair in body.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

/// Decodes one ASCII hex nibble.
fn hex_nibble(byte: u8) -> Result<u8, OkxClientError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OkxClientError::MalformedResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoding_is_strict_and_canonical() {
        assert_eq!(
            decode_calldata(Some("0xdeadbeef")),
            Ok(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            decode_calldata(Some("0xDEADBEEF")),
            Ok(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(decode_calldata(Some("0x00")), Ok(vec![0x00]));
        for malformed in [
            "", "0x", "deadbeef", "0x0", "0xabc", "0xgg", "0x12 34", "0X12", "0x+1",
        ] {
            assert_eq!(
                decode_calldata(Some(malformed)),
                Err(OkxClientError::MalformedResponse),
                "malformed calldata {malformed:?} must fail closed"
            );
        }
        assert_eq!(
            decode_calldata(None),
            Err(OkxClientError::MalformedResponse)
        );
    }

    #[test]
    fn oversized_calldata_is_rejected_before_decoding() {
        let too_long = format!("0x{}", "ab".repeat(MAX_CALLDATA_BYTES + 1));
        assert_eq!(
            decode_calldata(Some(&too_long)),
            Err(OkxClientError::MalformedResponse)
        );
        // Exactly the bound is accepted.
        let at_bound = format!("0x{}", "ab".repeat(MAX_CALLDATA_BYTES));
        assert_eq!(
            decode_calldata(Some(&at_bound)).map(|bytes| bytes.len()),
            Ok(MAX_CALLDATA_BYTES)
        );
    }

    #[test]
    fn optional_address_resolution_requires_agreement() {
        assert_eq!(resolve_optional_address(&[None, None]), Ok(None));
        assert_eq!(
            resolve_optional_address(&[Some("0xaaaa"), None]),
            Ok(Some("0xaaaa".to_string()))
        );
        assert_eq!(
            resolve_optional_address(&[Some(""), Some("0xaaaa")]),
            Ok(Some("0xaaaa".to_string()))
        );
        assert_eq!(
            resolve_optional_address(&[Some("0xaaaa"), Some("0xbbbb")]),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            resolve_optional_address(&[Some("has space")]),
            Err(OkxClientError::MalformedResponse)
        );
    }

    #[test]
    fn optional_decimal_resolution_requires_agreement() {
        assert_eq!(resolve_optional_decimal([None, None]), Ok(None));
        assert_eq!(
            resolve_optional_decimal([Some("2400"), Some("2400")]),
            Ok(Some(2_400))
        );
        assert_eq!(
            resolve_optional_decimal([Some("2400"), Some("2401")]),
            Err(OkxClientError::MalformedResponse)
        );
        assert_eq!(
            resolve_optional_decimal([Some("01"), None]),
            Err(OkxClientError::MalformedResponse)
        );
    }

    #[test]
    fn address_validation_is_bounded_and_printable() {
        assert!(is_valid_address("0x1111"));
        assert!(!is_valid_address(""));
        assert!(!is_valid_address("has space"));
        assert!(!is_valid_address(&"a".repeat(MAX_ADDRESS_BYTES + 1)));
        assert!(is_valid_address(&"a".repeat(MAX_ADDRESS_BYTES)));
    }
}
