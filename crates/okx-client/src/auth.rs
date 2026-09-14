//! OKX API v5 request authentication.
//!
//! The signature is `base64(HMAC-SHA256(timestamp + method + requestPath + body,
//! secret))` exactly as the OKX v5 specification defines it, where
//! `timestamp` is the same RFC 3339 (millisecond, UTC) string sent in the
//! `OK-ACCESS-TIMESTAMP` header and `requestPath` includes the query string.
//!
//! No clock is read here: the caller supplies the epoch-millisecond instant. No
//! OS timezone is consulted; the formatter is pure integer civil-calendar math.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::credentials::OkxCredentials;
use crate::error::OkxClientError;

type HmacSha256 = Hmac<Sha256>;

/// OKX API-key header name.
pub const OK_ACCESS_KEY: &str = "OK-ACCESS-KEY";
/// OKX request-signature header name.
pub const OK_ACCESS_SIGN: &str = "OK-ACCESS-SIGN";
/// OKX request-timestamp header name.
pub const OK_ACCESS_TIMESTAMP: &str = "OK-ACCESS-TIMESTAMP";
/// OKX API-passphrase header name.
pub const OK_ACCESS_PASSPHRASE: &str = "OK-ACCESS-PASSPHRASE";

/// Maximum accepted signed request-path length in bytes.
pub const MAX_REQUEST_PATH_BYTES: usize = 2048;

/// Redacted per-request authentication headers.
///
/// The values are secret material: this type deliberately does not implement
/// `Serialize`, `Clone`, `Display`, or a payload-bearing `Debug`. The only
/// escape hatch is [`OkxAuthHeaders::pairs`], which a transport implementation
/// uses to attach the headers to exactly one physical call.
pub struct OkxAuthHeaders {
    api_key: Zeroizing<String>,
    signature: Zeroizing<String>,
    timestamp: Zeroizing<String>,
    passphrase: Zeroizing<String>,
}

impl OkxAuthHeaders {
    /// The four OKX authentication header name/value pairs.
    pub fn pairs(&self) -> [(&'static str, &str); 4] {
        [
            (OK_ACCESS_KEY, self.api_key.as_str()),
            (OK_ACCESS_SIGN, self.signature.as_str()),
            (OK_ACCESS_TIMESTAMP, self.timestamp.as_str()),
            (OK_ACCESS_PASSPHRASE, self.passphrase.as_str()),
        ]
    }

    /// The RFC 3339 timestamp string signed into the request.
    pub fn timestamp(&self) -> &str {
        self.timestamp.as_str()
    }
}

impl fmt::Debug for OkxAuthHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OkxAuthHeaders { .. }")
    }
}

/// Builds the redacted authentication headers for one physical request.
///
/// `method` must be `"GET"` or `"POST"`, and `request_path` must start with `/`
/// and contain only printable non-space ASCII (which excludes CR/LF and other
/// header-injection bytes). `timestamp_ms` must be non-negative.
pub fn sign_request(
    credentials: &OkxCredentials,
    method: &str,
    request_path: &str,
    body: &[u8],
    timestamp_ms: i64,
) -> Result<OkxAuthHeaders, OkxClientError> {
    if method != "GET" && method != "POST" {
        return Err(OkxClientError::InvalidRequest);
    }
    if !is_valid_request_path(request_path) {
        return Err(OkxClientError::InvalidRequest);
    }
    let timestamp = format_rfc3339_millis(timestamp_ms)?;

    let mut mac = HmacSha256::new_from_slice(credentials.secret_key().as_bytes())
        .map_err(|_| OkxClientError::InvalidCredentials)?;
    mac.update(timestamp.as_bytes());
    mac.update(method.as_bytes());
    mac.update(request_path.as_bytes());
    mac.update(body);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    let signature = STANDARD.encode(tag);

    Ok(OkxAuthHeaders {
        api_key: Zeroizing::new(credentials.api_key().to_string()),
        signature: Zeroizing::new(signature),
        timestamp: Zeroizing::new(timestamp),
        passphrase: Zeroizing::new(credentials.passphrase().to_string()),
    })
}

fn is_valid_request_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_REQUEST_PATH_BYTES {
        return false;
    }
    if !path.starts_with('/') {
        return false;
    }
    path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Formats a non-negative epoch-millisecond instant as
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Pure integer arithmetic (Howard Hinnant's `civil_from_days`); no clock,
/// timezone database, or floating point is involved.
pub(crate) fn format_rfc3339_millis(epoch_ms: i64) -> Result<String, OkxClientError> {
    if epoch_ms < 0 {
        return Err(OkxClientError::InvalidRequest);
    }
    let millis_total = epoch_ms as u64;
    let seconds = millis_total / 1_000;
    let millis = millis_total % 1_000;
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

/// Converts days since 1970-01-01 to a `(year, month, day)` civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_formats_exactly() {
        assert_eq!(
            format_rfc3339_millis(0).expect("epoch"),
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn known_okx_timestamp_formats_exactly() {
        // 2020-12-08T09:08:57.715Z per the OKX v5 signature example.
        assert_eq!(
            format_rfc3339_millis(1_607_418_537_715).expect("known"),
            "2020-12-08T09:08:57.715Z"
        );
    }

    #[test]
    fn leap_day_and_boundary_dates_format() {
        assert_eq!(
            format_rfc3339_millis(951_782_400_000).expect("leap"),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(
            format_rfc3339_millis(1_735_689_599_999).expect("end"),
            "2024-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn negative_timestamp_fails_closed() {
        assert_eq!(
            format_rfc3339_millis(-1),
            Err(OkxClientError::InvalidRequest)
        );
    }

    #[test]
    fn signature_is_deterministic_and_redacted() {
        let credentials = OkxCredentials::new("key", "secret", "pass").expect("valid");
        let first = sign_request(
            &credentials,
            "GET",
            "/api/v5/dex/aggregator/quote?a=1",
            &[],
            0,
        )
        .expect("signed");
        let second = sign_request(
            &credentials,
            "GET",
            "/api/v5/dex/aggregator/quote?a=1",
            &[],
            0,
        )
        .expect("signed");
        assert_eq!(first.pairs(), second.pairs());

        let pairs = first.pairs();
        assert_eq!(pairs[0], (OK_ACCESS_KEY, "key"));
        assert_eq!(pairs[2], (OK_ACCESS_TIMESTAMP, "1970-01-01T00:00:00.000Z"));
        assert_eq!(pairs[3], (OK_ACCESS_PASSPHRASE, "pass"));
        // The signature is a 32-byte base64 tag (44 chars with one `=`).
        assert_eq!(pairs[1].1.len(), 44);
        assert!(pairs[1].1.ends_with('='));

        let debug = format!("{first:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains(pairs[1].1));
    }

    #[test]
    fn signature_changes_with_path_and_method() {
        let credentials = OkxCredentials::new("key", "secret", "pass").expect("valid");
        let base = sign_request(&credentials, "GET", "/api/v5/dex/aggregator/quote", &[], 5)
            .expect("signed")
            .pairs()[1]
            .1
            .to_string();
        let other_path = sign_request(&credentials, "GET", "/api/v5/dex/aggregator/swap", &[], 5)
            .expect("signed")
            .pairs()[1]
            .1
            .to_string();
        let other_method =
            sign_request(&credentials, "POST", "/api/v5/dex/aggregator/quote", &[], 5)
                .expect("signed")
                .pairs()[1]
                .1
                .to_string();
        let other_ts = sign_request(&credentials, "GET", "/api/v5/dex/aggregator/quote", &[], 6)
            .expect("signed")
            .pairs()[1]
            .1
            .to_string();
        assert_ne!(base, other_path);
        assert_ne!(base, other_method);
        assert_ne!(base, other_ts);
    }

    #[test]
    fn signature_matches_independently_computed_vector() {
        // Independently computed with Python's `hmac`/`hashlib`/`base64`:
        // base64(HMAC-SHA256("secret", ts + "GET" + path + body)).
        let credentials = OkxCredentials::new("key", "secret", "pass").expect("valid");
        let headers = sign_request(
            &credentials,
            "GET",
            "/api/v5/dex/aggregator/quote?a=1",
            &[],
            0,
        )
        .expect("signed");
        assert_eq!(
            headers.pairs()[1],
            (
                OK_ACCESS_SIGN,
                "2ghnc2SURrOV2Eh0QIiqnbNSITEyJlMUkZnITI1At2c="
            )
        );
    }

    #[test]
    fn malformed_path_or_method_fails_closed() {
        let credentials = OkxCredentials::new("key", "secret", "pass").expect("valid");
        assert_eq!(
            sign_request(&credentials, "PATCH", "/x", &[], 0).err(),
            Some(OkxClientError::InvalidRequest)
        );
        assert_eq!(
            sign_request(&credentials, "GET", "x", &[], 0).err(),
            Some(OkxClientError::InvalidRequest)
        );
        assert_eq!(
            sign_request(&credentials, "GET", "/x y", &[], 0).err(),
            Some(OkxClientError::InvalidRequest)
        );
        assert_eq!(
            sign_request(&credentials, "GET", "/x\r\nInjected: 1", &[], 0).err(),
            Some(OkxClientError::InvalidRequest)
        );
    }
}
