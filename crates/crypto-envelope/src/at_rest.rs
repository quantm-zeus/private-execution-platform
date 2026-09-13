//! Deterministic at-rest sealing for durable opaque records.
//!
//! This module is additive to the existing session/artifact envelopes and does
//! not change their behavior. It provides a single-record AEAD primitive used
//! by the encrypted audit trail:
//!
//! - 32-byte [`SealKey`], zeroized on drop, never rendered.
//! - XChaCha20-Poly1305 with a 24-byte nonce derived deterministically from the
//!   seal key, the stream blind index, the record sequence, the schema version,
//!   and the key id. No random source is used, so sealing is reproducible for
//!   identical inputs and a caller can never accidentally reuse a nonce across
//!   distinct `(stream, sequence, kid)` tuples.
//! - Wire form `version(1) || kid(16) || nonce(24) || ciphertext+tag`.
//! - AAD binds the domain tag, wire version, kid, sequence, schema version, and
//!   stream blind index, so swapping or splicing records fails authentication.
//!
//! Failure is always closed: [`seal_at_rest`] returns an empty vector if
//! sealing cannot complete (the minimum wire length is
//! [`AT_REST_MIN_LEN`], so an empty result is unambiguous), and
//! [`open_at_rest`] refuses malformed, truncated, mis-versioned, or
//! unauthenticated input with a typed [`CryptoError`] that carries no payload.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// Domain separation tag for the at-rest construction.
pub const AT_REST_DOMAIN: &[u8] = b"crypto.envelope.at_rest.v1";

/// Wire format version byte.
pub const AT_REST_VERSION: u8 = 1;

/// Key identifier length in the wire header.
pub const AT_REST_KID_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length.
pub const AT_REST_NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length.
pub const AT_REST_TAG_LEN: usize = 16;

/// Bytes before the ciphertext: version + kid + nonce.
pub const AT_REST_HEADER_LEN: usize = 1 + AT_REST_KID_LEN + AT_REST_NONCE_LEN;

/// Minimum well-formed wire length: header + authentication tag.
pub const AT_REST_MIN_LEN: usize = AT_REST_HEADER_LEN + AT_REST_TAG_LEN;

/// 32-byte at-rest seal key.
///
/// Zeroized on drop and never revealed by `Debug`. The key is intentionally not
/// `Clone`; move it into the operation that needs it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealKey([u8; 32]);

impl SealKey {
    /// Wraps exactly 32 bytes of caller-supplied key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey([REDACTED])")
    }
}

/// Derives the 24-byte nonce for `(stream, sequence, schema_version, kid)`.
///
/// HKDF-SHA256 with `ikm = seal`, `salt = stream_blind_index`, and
/// `info = tag || kid || sequence || schema_version`; expanded to 24 bytes. The
/// expansion length is fixed and far below the HKDF limit, so the only possible
/// error is an internal invariant failure, surfaced as
/// [`CryptoError::DerivationFailed`].
fn derive_nonce(
    seal: &SealKey,
    kid: &[u8; AT_REST_KID_LEN],
    sequence: u64,
    schema_version: u16,
    stream_blind_index: &[u8],
) -> Result<[u8; AT_REST_NONCE_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(stream_blind_index), &seal.0);
    let mut info = Vec::with_capacity(AT_REST_DOMAIN.len() + AT_REST_KID_LEN + 8 + 2);
    info.extend_from_slice(AT_REST_DOMAIN);
    info.extend_from_slice(kid);
    info.extend_from_slice(&sequence.to_be_bytes());
    info.extend_from_slice(&schema_version.to_be_bytes());
    let mut okm = [0u8; AT_REST_NONCE_LEN];
    hkdf.expand(&info, &mut okm)
        .map_err(|_| CryptoError::DerivationFailed)?;
    Ok(okm)
}

/// Builds the AEAD additional authenticated data for a record.
fn build_aad(
    version: u8,
    kid: &[u8; AT_REST_KID_LEN],
    sequence: u64,
    schema_version: u16,
    stream_blind_index: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        AT_REST_DOMAIN.len() + 1 + AT_REST_KID_LEN + 8 + 2 + stream_blind_index.len(),
    );
    aad.extend_from_slice(AT_REST_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(kid);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&schema_version.to_be_bytes());
    aad.extend_from_slice(stream_blind_index);
    aad
}

/// Seals `plaintext` into the at-rest wire form.
///
/// Returns an empty vector when sealing cannot complete; callers must treat any
/// result shorter than [`AT_REST_MIN_LEN`] as a fail-closed seal failure.
pub fn seal_at_rest(
    seal: &SealKey,
    kid: &[u8; AT_REST_KID_LEN],
    sequence: u64,
    schema_version: u16,
    stream_blind_index: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let Ok(nonce) = derive_nonce(seal, kid, sequence, schema_version, stream_blind_index) else {
        return Vec::new();
    };
    let aad = build_aad(
        AT_REST_VERSION,
        kid,
        sequence,
        schema_version,
        stream_blind_index,
    );
    let cipher = XChaCha20Poly1305::new((&seal.0).into());
    let Ok(ciphertext) = cipher.encrypt(
        (&nonce).into(),
        chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &aad,
        },
    ) else {
        return Vec::new();
    };
    let mut wire = Vec::with_capacity(AT_REST_HEADER_LEN + ciphertext.len());
    wire.push(AT_REST_VERSION);
    wire.extend_from_slice(kid);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ciphertext);
    wire
}

/// Opens an at-rest wire value, returning the authenticated plaintext.
///
/// `kid`, `sequence`, `schema_version`, and `stream_blind_index` are the values
/// the caller expects the record to carry; every one of them is bound into the
/// AAD, so a mismatch fails authentication. The nonce is validated against the
/// internally derived value before decryption.
pub fn open_at_rest(
    seal: &SealKey,
    kid: &[u8; AT_REST_KID_LEN],
    sequence: u64,
    schema_version: u16,
    stream_blind_index: &[u8],
    wire: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if wire.len() < AT_REST_MIN_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    let version = wire[0];
    if version != AT_REST_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut wire_kid = [0u8; AT_REST_KID_LEN];
    wire_kid.copy_from_slice(&wire[1..1 + AT_REST_KID_LEN]);
    if &wire_kid != kid {
        return Err(CryptoError::KeyIdMismatch);
    }
    let mut wire_nonce = [0u8; AT_REST_NONCE_LEN];
    wire_nonce.copy_from_slice(&wire[1 + AT_REST_KID_LEN..AT_REST_HEADER_LEN]);
    let expected_nonce = derive_nonce(seal, kid, sequence, schema_version, stream_blind_index)?;
    if wire_nonce != expected_nonce {
        return Err(CryptoError::DecryptFailed);
    }
    let aad = build_aad(version, kid, sequence, schema_version, stream_blind_index);
    let cipher = XChaCha20Poly1305::new((&seal.0).into());
    cipher
        .decrypt(
            (&wire_nonce).into(),
            chacha20poly1305::aead::Payload {
                msg: &wire[AT_REST_HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Reads the key id from an at-rest wire header without authenticating it.
///
/// Callers use this to select key material by id before opening; the id is
/// still authenticated as part of the AAD during [`open_at_rest`], so an
/// attacker who rewrites it cannot redirect decryption to a different key
/// without failing the tag check.
pub fn wire_kid(wire: &[u8]) -> Result<[u8; AT_REST_KID_LEN], CryptoError> {
    if wire.len() < AT_REST_HEADER_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    if wire[0] != AT_REST_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut kid = [0u8; AT_REST_KID_LEN];
    kid.copy_from_slice(&wire[1..1 + AT_REST_KID_LEN]);
    Ok(kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID_A: [u8; AT_REST_KID_LEN] = [0x11u8; AT_REST_KID_LEN];
    const KID_B: [u8; AT_REST_KID_LEN] = [0x22u8; AT_REST_KID_LEN];
    const STREAM: &[u8] = b"stream-index-bytes";

    fn seal_key(fill: u8) -> SealKey {
        SealKey::from_bytes([fill; 32])
    }

    #[test]
    fn round_trip_returns_plaintext() {
        let seal = seal_key(7);
        let wire = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"payload");
        assert!(wire.len() >= AT_REST_MIN_LEN);
        let opened = open_at_rest(&seal, &KID_A, 1, 1, STREAM, &wire).expect("open");
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn wire_layout_is_version_kid_nonce_ciphertext() {
        let seal = seal_key(7);
        let wire = seal_at_rest(&seal, &KID_A, 9, 3, STREAM, b"x");
        assert_eq!(wire[0], AT_REST_VERSION);
        assert_eq!(&wire[1..1 + AT_REST_KID_LEN], &KID_A);
        assert_eq!(wire_kid(&wire).expect("kid"), KID_A);
        // The derived nonce must be identical for the same bound inputs.
        let second = seal_at_rest(&seal, &KID_A, 9, 3, STREAM, b"x");
        assert_eq!(wire, second);
    }

    #[test]
    fn deterministic_but_sequence_separated() {
        let seal = seal_key(7);
        let first = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"same");
        let second = seal_at_rest(&seal, &KID_A, 2, 1, STREAM, b"same");
        assert_ne!(
            first[1 + AT_REST_KID_LEN..AT_REST_HEADER_LEN],
            second[1 + AT_REST_KID_LEN..AT_REST_HEADER_LEN],
            "distinct sequences must derive distinct nonces"
        );
        assert_ne!(first, second);
    }

    #[test]
    fn short_wire_is_rejected() {
        let seal = seal_key(7);
        let wire = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"payload");
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &wire[..AT_REST_MIN_LEN - 1]),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn cross_field_swaps_fail_authentication() {
        let seal = seal_key(7);
        let wire = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"payload");
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 2, 1, STREAM, &wire),
            Err(CryptoError::DecryptFailed)
        ));
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 2, STREAM, &wire),
            Err(CryptoError::DecryptFailed)
        ));
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, b"other-stream", &wire),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn nonce_version_kid_and_ciphertext_tamper_fail_closed() {
        let seal = seal_key(7);
        let wire = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"payload");

        let mut version = wire.clone();
        version[0] ^= 0x01;
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &version),
            Err(CryptoError::UnsupportedVersion)
        ));

        let mut kid = wire.clone();
        kid[1] ^= 0xFF;
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &kid),
            Err(CryptoError::KeyIdMismatch)
        ));

        let mut nonce = wire.clone();
        nonce[1 + AT_REST_KID_LEN] ^= 0xFF;
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &nonce),
            Err(CryptoError::DecryptFailed)
        ));

        let mut body = wire.clone();
        body[AT_REST_HEADER_LEN] ^= 0xFF;
        assert!(matches!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &body),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let wire = seal_at_rest(&seal_key(7), &KID_A, 1, 1, STREAM, b"payload");
        assert!(matches!(
            open_at_rest(&seal_key(8), &KID_A, 1, 1, STREAM, &wire),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn different_kid_derives_different_nonce_and_key_selection_matters() {
        let seal = seal_key(7);
        let a = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"payload");
        let b = seal_at_rest(&seal, &KID_B, 1, 1, STREAM, b"payload");
        assert_ne!(
            a[1 + AT_REST_KID_LEN..AT_REST_HEADER_LEN],
            b[1 + AT_REST_KID_LEN..AT_REST_HEADER_LEN]
        );
        assert!(matches!(
            open_at_rest(&seal, &KID_B, 1, 1, STREAM, &a),
            Err(CryptoError::KeyIdMismatch)
        ));
        assert_eq!(wire_kid(&a).expect("kid"), KID_A);
    }

    #[test]
    fn seal_key_debug_is_redacted() {
        let seal = seal_key(0xAB);
        let debug = format!("{seal:?}");
        assert_eq!(debug, "SealKey([REDACTED])");
        assert!(!debug.contains("171"));
    }

    #[test]
    fn wire_kid_rejects_short_and_bad_version() {
        assert!(matches!(
            wire_kid(&[0u8; 3]),
            Err(CryptoError::CiphertextTooShort)
        ));
        let mut header = vec![0u8; AT_REST_HEADER_LEN];
        header[0] = 9;
        assert!(matches!(
            wire_kid(&header),
            Err(CryptoError::UnsupportedVersion)
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let seal = seal_key(1);
        let wire = seal_at_rest(&seal, &KID_A, 1, 1, STREAM, b"");
        assert_eq!(wire.len(), AT_REST_MIN_LEN);
        assert_eq!(
            open_at_rest(&seal, &KID_A, 1, 1, STREAM, &wire).expect("open"),
            Vec::<u8>::new()
        );
    }
}
