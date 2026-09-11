//! Compact, versioned, bounded opaque market-stream frame codec.
//!
//! Encodes and decodes stream frames strictly inside authenticated ciphertext.
//! External `Envelope` metadata remains completely generic, carrying only session
//! `kid`, nonce, sequence, and authenticated ciphertext. All frame semantics
//! (kind, version, inner sequence, and opaque payload) are encapsulated and
//! protected by AEAD encryption.
//!
//! Enforces strict fail-closed validation:
//! - Frame sequence is cryptographically and logically bound to envelope sequence.
//! - Nonzero sequence numbers strictly enforced.
//! - Unsupported versions and kinds fail closed.
//! - Explicit bounded payload and frame size limits enforced before allocation/serialization
//!   and after decryption.
//! - All arithmetic uses checked operations.
//! - Rejected, tampered, replayed, or malformed frames never advance session or replay state,
//!   and never produce partial frame state.
//! - Content-free errors and redacted debug formats prevent leakage of plaintext,
//!   ciphertext, credentials, endpoints, keys, nonces, or targets.

use std::fmt;

use thiserror::Error;

use crate::{CryptoError, Envelope, ReceiveSession, SendSession, AEAD_TAG_LEN, KID_LEN};

/// Current wire protocol version for opaque stream frames.
pub const FRAME_VERSION: u8 = 1;

/// Fixed length in bytes of the stream frame wire header:
/// version (1) + kind (1) + sequence (8) + payload_len (4) = 14 bytes.
pub const FRAME_HEADER_LEN: usize = 1 + 1 + 8 + 4;

/// Hard upper bound for a single stream frame payload (1 MiB).
pub const MAX_FRAME_PAYLOAD_LEN: usize = 1024 * 1024;

/// Minimum valid frame plaintext length (header only, zero-length payload).
pub const MIN_FRAME_LEN: usize = FRAME_HEADER_LEN;

/// Maximum valid frame plaintext length: header + 1 MiB payload.
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD_LEN;

/// Minimum valid ciphertext length: header + AEAD tag (14 + 16 = 30 bytes).
pub const MIN_CIPHERTEXT_LEN: usize = MIN_FRAME_LEN + AEAD_TAG_LEN;

/// Maximum valid ciphertext length: header + 1 MiB payload + AEAD tag (1,048,606 bytes).
pub const MAX_CIPHERTEXT_LEN: usize = MAX_FRAME_LEN + AEAD_TAG_LEN;

// =========================================================================
// Frame Kind
// =========================================================================

/// Discriminator for opaque market-stream frames.
///
/// Encoded exclusively within authenticated ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamFrameKind {
    /// Canonical market depth baseline snapshot.
    Snapshot = 1,
    /// Incremental order book depth delta update.
    Delta = 2,
    /// Aggregated OHLCV candle window.
    Candle = 3,
    /// Stream liveness and sync probe.
    Heartbeat = 4,
    /// Resynchronization / state reset marker.
    Resync = 5,
    /// Consumer batch of sequenced items.
    Batch = 6,
}

pub type FrameKind = StreamFrameKind;

impl StreamFrameKind {
    /// Returns the wire byte representation of this frame kind.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a frame kind from a wire byte, failing closed on unsupported kinds.
    pub const fn from_u8(val: u8) -> Result<Self, StreamFrameError> {
        match val {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Delta),
            3 => Ok(Self::Candle),
            4 => Ok(Self::Heartbeat),
            5 => Ok(Self::Resync),
            6 => Ok(Self::Batch),
            _ => Err(StreamFrameError::UnsupportedKind),
        }
    }
}

impl TryFrom<u8> for StreamFrameKind {
    type Error = StreamFrameError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        Self::from_u8(val)
    }
}

impl From<StreamFrameKind> for u8 {
    fn from(kind: StreamFrameKind) -> Self {
        kind.as_u8()
    }
}

impl fmt::Display for StreamFrameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot => f.write_str("snapshot"),
            Self::Delta => f.write_str("delta"),
            Self::Candle => f.write_str("candle"),
            Self::Heartbeat => f.write_str("heartbeat"),
            Self::Resync => f.write_str("resync"),
            Self::Batch => f.write_str("batch"),
        }
    }
}

// =========================================================================
// Structured Content-Free Errors
// =========================================================================

/// Structured, content-free errors for stream frame operations.
///
/// Intentionally omits plaintext, ciphertext, endpoints, key IDs, nonces,
/// targets, or credentials to prevent leakage across logging or boundary surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StreamFrameError {
    #[error("frame sequence number must be nonzero")]
    ZeroSequence,

    #[error("frame sequence does not match envelope sequence")]
    SequenceMismatch,

    #[error("sequence must be strictly increasing")]
    SequenceReuse,

    #[error("replay detected: sequence was already accepted")]
    ReplayDetected,

    #[error("sequence is older than the replay window")]
    StaleSequence,

    #[error("unsupported frame version")]
    UnsupportedVersion,

    #[error("unsupported frame kind")]
    UnsupportedKind,

    #[error("payload exceeds maximum allowed bound")]
    PayloadTooLarge,

    #[error("frame exceeds maximum allowed bound")]
    FrameTooLarge,

    #[error("ciphertext length is out of bounds")]
    CiphertextOutOfBounds,

    #[error("malformed frame: payload length mismatch")]
    PayloadLengthMismatch,

    #[error("malformed frame structure")]
    MalformedFrame,

    #[error("encryption failed")]
    EncryptFailed,

    #[error("decryption failed: authentication tag mismatch or tampering")]
    DecryptFailed,

    #[error("underlying cryptographic session error")]
    Crypto,
}

pub type FrameError = StreamFrameError;

impl From<CryptoError> for StreamFrameError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidSequence(_) => Self::ZeroSequence,
            CryptoError::SequenceReuse(_) => Self::SequenceReuse,
            CryptoError::ReplayDetected(_) => Self::ReplayDetected,
            CryptoError::StaleSequence(_) => Self::StaleSequence,
            CryptoError::EncryptFailed => Self::EncryptFailed,
            CryptoError::DecryptFailed => Self::DecryptFailed,
            CryptoError::CiphertextTooShort => Self::CiphertextOutOfBounds,
            CryptoError::UnsupportedVersion => Self::UnsupportedVersion,
            _ => Self::Crypto,
        }
    }
}

// =========================================================================
// Stream Frame Model
// =========================================================================

/// Bounded, versioned opaque market-stream frame.
///
/// Plaintext fields exist strictly inside authenticated ciphertext. Debug
/// representations strictly redact payload contents.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub version: u8,
    pub kind: StreamFrameKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

pub type Frame = StreamFrame;

impl StreamFrame {
    /// Constructs a validated stream frame with current `FRAME_VERSION`.
    pub fn new(
        kind: StreamFrameKind,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, StreamFrameError> {
        if sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }
        if payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(StreamFrameError::PayloadTooLarge);
        }
        Ok(Self {
            version: FRAME_VERSION,
            kind,
            sequence,
            payload,
        })
    }

    /// Constructs a stream frame with explicit version validation.
    pub fn with_version(
        version: u8,
        kind: StreamFrameKind,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, StreamFrameError> {
        if version != FRAME_VERSION {
            return Err(StreamFrameError::UnsupportedVersion);
        }
        if sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }
        if payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(StreamFrameError::PayloadTooLarge);
        }
        Ok(Self {
            version,
            kind,
            sequence,
            payload,
        })
    }

    /// Encodes this frame into canonical wire plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StreamFrameError> {
        StreamFrameCodec::new().encode_frame(self)
    }

    /// Decodes a stream frame from canonical wire plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamFrameError> {
        StreamFrameCodec::new().decode_frame(bytes)
    }

    /// Returns the frame wire version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the frame kind discriminator.
    pub fn kind(&self) -> StreamFrameKind {
        self.kind
    }

    /// Returns the sequence number bound to this frame.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns a reference to the opaque payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the frame and returns the owned opaque payload vector.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

impl fmt::Debug for StreamFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamFrame")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("sequence", &self.sequence)
            .field("payload_len", &self.payload.len())
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

// =========================================================================
// Stream Frame Codec
// =========================================================================

/// Bounded encoder/decoder and session cryptographic adapter for stream frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameCodec {
    max_payload_len: usize,
}

impl Default for StreamFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamFrameCodec {
    /// Constructs a codec enforcing the default `MAX_FRAME_PAYLOAD_LEN` (1 MiB).
    pub const fn new() -> Self {
        Self {
            max_payload_len: MAX_FRAME_PAYLOAD_LEN,
        }
    }

    /// Constructs a codec with an explicit payload bound.
    pub const fn with_max_payload_len(max_payload_len: usize) -> Self {
        Self { max_payload_len }
    }

    /// Returns the maximum allowed payload length configured for this codec.
    pub fn max_payload_len(&self) -> usize {
        self.max_payload_len
    }

    /// Maximum valid frame plaintext length for this codec instance.
    fn max_frame_len(&self) -> Result<usize, StreamFrameError> {
        FRAME_HEADER_LEN
            .checked_add(self.max_payload_len)
            .ok_or(StreamFrameError::FrameTooLarge)
    }

    /// Maximum valid ciphertext length for this codec instance.
    fn max_ciphertext_len(&self) -> Result<usize, StreamFrameError> {
        self.max_frame_len()?
            .checked_add(AEAD_TAG_LEN)
            .ok_or(StreamFrameError::CiphertextOutOfBounds)
    }

    /// Encodes a stream frame into a preallocated, bounded byte vector.
    pub fn encode_frame(&self, frame: &StreamFrame) -> Result<Vec<u8>, StreamFrameError> {
        if frame.version != FRAME_VERSION {
            return Err(StreamFrameError::UnsupportedVersion);
        }
        if frame.sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }
        if frame.payload.len() > self.max_payload_len {
            return Err(StreamFrameError::PayloadTooLarge);
        }

        let total_len = FRAME_HEADER_LEN
            .checked_add(frame.payload.len())
            .ok_or(StreamFrameError::FrameTooLarge)?;

        let max_frame = self.max_frame_len()?;
        if total_len > max_frame {
            return Err(StreamFrameError::FrameTooLarge);
        }

        let payload_len_u32 =
            u32::try_from(frame.payload.len()).map_err(|_| StreamFrameError::PayloadTooLarge)?;

        let mut buf = Vec::with_capacity(total_len);
        buf.push(frame.version);
        buf.push(frame.kind.as_u8());
        buf.extend_from_slice(&frame.sequence.to_be_bytes());
        buf.extend_from_slice(&payload_len_u32.to_be_bytes());
        buf.extend_from_slice(&frame.payload);

        Ok(buf)
    }

    /// Decodes a stream frame from plaintext bytes, validating boundaries fail-closed.
    pub fn decode_frame(&self, bytes: &[u8]) -> Result<StreamFrame, StreamFrameError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(StreamFrameError::MalformedFrame);
        }
        let max_frame = self.max_frame_len()?;
        if bytes.len() > max_frame {
            return Err(StreamFrameError::FrameTooLarge);
        }

        let version = bytes[0];
        if version != FRAME_VERSION {
            return Err(StreamFrameError::UnsupportedVersion);
        }

        let kind = StreamFrameKind::from_u8(bytes[1])?;

        let sequence_bytes: [u8; 8] = bytes[2..10]
            .try_into()
            .map_err(|_| StreamFrameError::MalformedFrame)?;
        let sequence = u64::from_be_bytes(sequence_bytes);
        if sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }

        let len_bytes: [u8; 4] = bytes[10..14]
            .try_into()
            .map_err(|_| StreamFrameError::MalformedFrame)?;
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        if payload_len > self.max_payload_len {
            return Err(StreamFrameError::PayloadTooLarge);
        }

        let expected_total_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(StreamFrameError::FrameTooLarge)?;

        if bytes.len() != expected_total_len {
            return Err(StreamFrameError::PayloadLengthMismatch);
        }

        let payload = bytes[FRAME_HEADER_LEN..expected_total_len].to_vec();

        Ok(StreamFrame {
            version,
            kind,
            sequence,
            payload,
        })
    }

    /// Seals a stream frame using an authenticated `SendSession`.
    ///
    /// The frame's sequence is bound to the envelope sequence. Fails closed if
    /// sequence is zero, payload is oversized, or session sequence monotonicity
    /// is violated. On failure, session state is unchanged.
    pub fn seal(
        &self,
        session: &mut SendSession,
        kid: [u8; KID_LEN],
        frame: &StreamFrame,
    ) -> Result<Envelope, StreamFrameError> {
        self.seal_bound(session, kid, frame.sequence, frame)
    }

    /// Seals a stream frame with explicit envelope sequence binding verification.
    ///
    /// Returns `StreamFrameError::SequenceMismatch` if `envelope_sequence != frame.sequence`.
    pub fn seal_bound(
        &self,
        session: &mut SendSession,
        kid: [u8; KID_LEN],
        envelope_sequence: u64,
        frame: &StreamFrame,
    ) -> Result<Envelope, StreamFrameError> {
        if frame.sequence == 0 || envelope_sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }
        if frame.sequence != envelope_sequence {
            return Err(StreamFrameError::SequenceMismatch);
        }
        let encoded = self.encode_frame(frame)?;
        session
            .seal(kid, envelope_sequence, &encoded)
            .map_err(StreamFrameError::from)
    }

    /// Receives, authenticates, validates, and decodes an opaque stream frame.
    ///
    /// Bounds and AEAD authentication are checked first. The frame is decoded
    /// and verified (including sequence binding) BEFORE the replay window advances.
    /// Malformed, tampered, replayed, or out-of-bounds frames leave replay state
    /// strictly unchanged.
    pub fn receive(
        &self,
        session: &mut ReceiveSession,
        envelope: &Envelope,
    ) -> Result<StreamFrame, StreamFrameError> {
        // Preflight sequence and ciphertext length bounds before decryption or replay tracking.
        if envelope.sequence == 0 {
            return Err(StreamFrameError::ZeroSequence);
        }
        let max_cipher = self.max_ciphertext_len()?;
        if envelope.ciphertext.len() < MIN_CIPHERTEXT_LEN || envelope.ciphertext.len() > max_cipher
        {
            return Err(StreamFrameError::CiphertextOutOfBounds);
        }

        // Authenticate and decrypt under session key without advancing replay window.
        let plaintext = session
            .open_only(envelope)
            .map_err(|_| StreamFrameError::DecryptFailed)?;

        // Decode and validate frame structure against configured limits.
        let frame = self.decode_frame(&plaintext)?;

        // Cryptographically bind inner frame sequence to authenticated envelope sequence.
        if frame.sequence != envelope.sequence {
            return Err(StreamFrameError::SequenceMismatch);
        }

        // Only after all structural, semantic, and sequence invariants pass,
        // advance the replay window.
        session
            .accept_replay(envelope.sequence)
            .map_err(StreamFrameError::from)?;

        Ok(frame)
    }

    // ---------------------------------------------------------------------
    // Static Convenience Functions
    // ---------------------------------------------------------------------

    /// Convenience wrapper to encode a frame using default limits.
    pub fn encode(frame: &StreamFrame) -> Result<Vec<u8>, StreamFrameError> {
        Self::new().encode_frame(frame)
    }

    /// Convenience wrapper to decode a frame using default limits.
    pub fn decode(bytes: &[u8]) -> Result<StreamFrame, StreamFrameError> {
        Self::new().decode_frame(bytes)
    }

    /// Convenience wrapper to seal a frame using default limits.
    pub fn seal_frame(
        session: &mut SendSession,
        kid: [u8; KID_LEN],
        frame: &StreamFrame,
    ) -> Result<Envelope, StreamFrameError> {
        Self::new().seal(session, kid, frame)
    }

    /// Convenience wrapper to seal a frame with sequence binding check using default limits.
    pub fn seal_frame_bound(
        session: &mut SendSession,
        kid: [u8; KID_LEN],
        envelope_sequence: u64,
        frame: &StreamFrame,
    ) -> Result<Envelope, StreamFrameError> {
        Self::new().seal_bound(session, kid, envelope_sequence, frame)
    }

    /// Convenience wrapper to receive and validate a frame using default limits.
    pub fn receive_frame(
        session: &mut ReceiveSession,
        envelope: &Envelope,
    ) -> Result<StreamFrame, StreamFrameError> {
        Self::new().receive(session, envelope)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KID: [u8; KID_LEN] = [0xAAu8; KID_LEN];

    #[test]
    fn seal_receive_roundtrip_all_kinds() {
        let kinds = [
            StreamFrameKind::Snapshot,
            StreamFrameKind::Delta,
            StreamFrameKind::Candle,
            StreamFrameKind::Heartbeat,
            StreamFrameKind::Resync,
            StreamFrameKind::Batch,
        ];

        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        for (idx, &kind) in kinds.iter().enumerate() {
            let sequence = (idx as u64) + 1;
            let payload = format!("payload-content-for-{kind}").into_bytes();
            let frame = StreamFrame::new(kind, sequence, payload.clone()).expect("new frame");

            let envelope = send.seal_frame(TEST_KID, &frame).expect("seal frame");
            assert_eq!(envelope.kid, TEST_KID);
            assert_eq!(envelope.sequence, sequence);

            let opened = recv.receive_frame(&envelope).expect("receive frame");
            assert_eq!(opened.version, FRAME_VERSION);
            assert_eq!(opened.kind, kind);
            assert_eq!(opened.sequence, sequence);
            assert_eq!(opened.payload, payload);
        }
    }

    #[test]
    fn seal_receive_empty_payload() {
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        let frame = StreamFrame::new(StreamFrameKind::Heartbeat, 1, Vec::new()).expect("frame");
        let envelope = send.seal_frame(TEST_KID, &frame).expect("seal");

        assert_eq!(envelope.ciphertext.len(), MIN_CIPHERTEXT_LEN);
        let opened = recv.receive_frame(&envelope).expect("receive");
        assert_eq!(opened.kind, StreamFrameKind::Heartbeat);
        assert_eq!(opened.sequence, 1);
        assert!(opened.payload.is_empty());
    }

    #[test]
    fn envelope_frame_sequence_binding_mismatch_rejected() {
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        let frame = StreamFrame::new(StreamFrameKind::Snapshot, 10, b"data".to_vec()).unwrap();

        // Sealing with mismatched sequence bound must fail immediately
        assert_eq!(
            send.seal_frame_bound(TEST_KID, 11, &frame),
            Err(StreamFrameError::SequenceMismatch)
        );
        // Session sequence must not advance
        assert_eq!(send.last_sequence(), 0);

        // Seal correctly with seq 10
        let envelope = send.seal_frame(TEST_KID, &frame).expect("seal");
        assert_eq!(send.last_sequence(), 10);

        // If envelope sequence is modified, AEAD decrypt fails because AAD binds sequence
        let mut modified_env = envelope.clone();
        modified_env.sequence = 11;
        assert_eq!(
            recv.receive_frame(&modified_env),
            Err(StreamFrameError::DecryptFailed)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);

        // Valid envelope still receives cleanly
        let opened = recv.receive_frame(&envelope).expect("valid receive");
        assert_eq!(opened.sequence, 10);
        assert_eq!(recv.highest_accepted_sequence(), 10);
    }

    #[test]
    fn inner_frame_sequence_mismatch_after_decryption() {
        // Craft a scenario where ciphertext decrypts under sequence 5, but encoded frame has sequence 4.
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        // Encode a frame with sequence 4
        let inner_frame = StreamFrame {
            version: FRAME_VERSION,
            kind: StreamFrameKind::Delta,
            sequence: 4,
            payload: b"tampered-seq".to_vec(),
        };
        let encoded_inner = inner_frame.encode().unwrap();

        // Raw seal under sequence 5
        let raw_envelope = send.seal(TEST_KID, 5, &encoded_inner).unwrap();

        // receive_frame should decrypt successfully, but reject with SequenceMismatch
        assert_eq!(
            recv.receive_frame(&raw_envelope),
            Err(StreamFrameError::SequenceMismatch)
        );

        // Replay window must NOT advance on sequence mismatch
        assert_eq!(recv.highest_accepted_sequence(), 0);

        // Now send a legitimate sequence 5 frame
        let legitimate_frame =
            StreamFrame::new(StreamFrameKind::Delta, 5, b"legitimate".to_vec()).unwrap();
        // Since sequence 5 was already used on send session, use a fresh send session
        let mut fresh_send = SendSession::with_test_key();
        let legit_env = fresh_send.seal_frame(TEST_KID, &legitimate_frame).unwrap();

        // Legitimate sequence 5 is accepted
        let received = recv.receive_frame(&legit_env).unwrap();
        assert_eq!(received.sequence, 5);
        assert_eq!(recv.highest_accepted_sequence(), 5);
    }

    #[test]
    fn zero_sequence_rejected_fail_closed() {
        assert_eq!(
            StreamFrame::new(StreamFrameKind::Snapshot, 0, b"data".to_vec()),
            Err(StreamFrameError::ZeroSequence)
        );

        let invalid_frame = StreamFrame {
            version: FRAME_VERSION,
            kind: StreamFrameKind::Snapshot,
            sequence: 0,
            payload: b"data".to_vec(),
        };
        assert_eq!(invalid_frame.encode(), Err(StreamFrameError::ZeroSequence));

        let mut send = SendSession::with_test_key();
        assert_eq!(
            send.seal_frame(TEST_KID, &invalid_frame),
            Err(StreamFrameError::ZeroSequence)
        );
        assert_eq!(send.last_sequence(), 0);

        let mut recv = ReceiveSession::with_test_key();
        let zero_env = Envelope {
            kid: TEST_KID,
            nonce: [0u8; 12],
            sequence: 0,
            ciphertext: vec![0u8; 32],
        };
        assert_eq!(
            recv.receive_frame(&zero_env),
            Err(StreamFrameError::ZeroSequence)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);
    }

    #[test]
    fn unsupported_version_rejected() {
        assert_eq!(
            StreamFrame::with_version(0, StreamFrameKind::Snapshot, 1, b"x".to_vec()),
            Err(StreamFrameError::UnsupportedVersion)
        );
        assert_eq!(
            StreamFrame::with_version(2, StreamFrameKind::Snapshot, 1, b"x".to_vec()),
            Err(StreamFrameError::UnsupportedVersion)
        );

        // Craft encoded bytes with unsupported version 2
        let mut bytes = StreamFrame::new(StreamFrameKind::Snapshot, 1, b"test".to_vec())
            .unwrap()
            .encode()
            .unwrap();
        bytes[0] = 2; // corrupt version
        assert_eq!(
            StreamFrame::decode(&bytes),
            Err(StreamFrameError::UnsupportedVersion)
        );

        // When received inside envelope
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();
        let env = send.seal(TEST_KID, 1, &bytes).unwrap();
        assert_eq!(
            recv.receive_frame(&env),
            Err(StreamFrameError::UnsupportedVersion)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);
    }

    #[test]
    fn unsupported_kind_rejected() {
        assert_eq!(
            StreamFrameKind::from_u8(0),
            Err(StreamFrameError::UnsupportedKind)
        );
        assert_eq!(
            StreamFrameKind::from_u8(7),
            Err(StreamFrameError::UnsupportedKind)
        );
        assert_eq!(
            StreamFrameKind::from_u8(255),
            Err(StreamFrameError::UnsupportedKind)
        );

        // Craft encoded bytes with unsupported kind 99
        let mut bytes = StreamFrame::new(StreamFrameKind::Snapshot, 1, b"test".to_vec())
            .unwrap()
            .encode()
            .unwrap();
        bytes[1] = 99; // corrupt kind
        assert_eq!(
            StreamFrame::decode(&bytes),
            Err(StreamFrameError::UnsupportedKind)
        );

        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();
        let env = send.seal(TEST_KID, 1, &bytes).unwrap();
        assert_eq!(
            recv.receive_frame(&env),
            Err(StreamFrameError::UnsupportedKind)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);
    }

    #[test]
    fn payload_and_frame_length_bounds_enforced() {
        let oversized = vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1];
        assert_eq!(
            StreamFrame::new(StreamFrameKind::Snapshot, 1, oversized.clone()),
            Err(StreamFrameError::PayloadTooLarge)
        );

        let frame = StreamFrame {
            version: FRAME_VERSION,
            kind: StreamFrameKind::Snapshot,
            sequence: 1,
            payload: oversized,
        };
        assert_eq!(frame.encode(), Err(StreamFrameError::PayloadTooLarge));

        let mut send = SendSession::with_test_key();
        assert_eq!(
            send.seal_frame(TEST_KID, &frame),
            Err(StreamFrameError::PayloadTooLarge)
        );
        assert_eq!(send.last_sequence(), 0);

        // Small custom codec bounds
        let codec = StreamFrameCodec::with_max_payload_len(16);
        let valid_small = StreamFrame::new(StreamFrameKind::Delta, 1, vec![0u8; 16]).unwrap();
        assert!(codec.encode_frame(&valid_small).is_ok());

        let invalid_large = StreamFrame::new(StreamFrameKind::Delta, 1, vec![0u8; 17]).unwrap();
        assert_eq!(
            codec.encode_frame(&invalid_large),
            Err(StreamFrameError::PayloadTooLarge)
        );
    }

    #[test]
    fn malformed_payload_length_mismatch_rejected() {
        let valid_bytes = StreamFrame::new(StreamFrameKind::Delta, 1, b"hello".to_vec())
            .unwrap()
            .encode()
            .unwrap();

        // 1. Length field claims more than available
        let mut inflated = valid_bytes.clone();
        inflated[13] = 100; // claims payload is 100 bytes
        assert_eq!(
            StreamFrame::decode(&inflated),
            Err(StreamFrameError::PayloadLengthMismatch)
        );

        // 2. Length field claims less than available
        let mut deflated = valid_bytes.clone();
        deflated[13] = 2; // claims payload is 2 bytes
        assert_eq!(
            StreamFrame::decode(&deflated),
            Err(StreamFrameError::PayloadLengthMismatch)
        );

        // 3. Truncated header
        assert_eq!(
            StreamFrame::decode(&valid_bytes[..10]),
            Err(StreamFrameError::MalformedFrame)
        );

        // Replay window preservation when receiving malformed payload
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();
        let env = send.seal(TEST_KID, 1, &inflated).unwrap();
        assert_eq!(
            recv.receive_frame(&env),
            Err(StreamFrameError::PayloadLengthMismatch)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);
    }

    #[test]
    fn ciphertext_bounds_rejected_before_decryption() {
        let mut recv = ReceiveSession::with_test_key();

        // Ciphertext too short (< MIN_CIPHERTEXT_LEN = 30)
        let short_env = Envelope {
            kid: TEST_KID,
            nonce: [0u8; 12],
            sequence: 1,
            ciphertext: vec![0u8; 29],
        };
        assert_eq!(
            recv.receive_frame(&short_env),
            Err(StreamFrameError::CiphertextOutOfBounds)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);

        // Ciphertext too large (> MAX_CIPHERTEXT_LEN)
        let codec = StreamFrameCodec::with_max_payload_len(10);
        let large_env = Envelope {
            kid: TEST_KID,
            nonce: [0u8; 12],
            sequence: 1,
            ciphertext: vec![0u8; 100],
        };
        assert_eq!(
            codec.receive(&mut recv, &large_env),
            Err(StreamFrameError::CiphertextOutOfBounds)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);
    }

    #[test]
    fn tamper_and_replay_behavior() {
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        let frame = StreamFrame::new(StreamFrameKind::Snapshot, 1, b"sensitive".to_vec()).unwrap();
        let envelope = send.seal_frame(TEST_KID, &frame).unwrap();

        // 1. Tamper ciphertext: fails AEAD
        let mut tampered_cipher = envelope.clone();
        tampered_cipher.ciphertext[0] ^= 0x01;
        assert_eq!(
            recv.receive_frame(&tampered_cipher),
            Err(StreamFrameError::DecryptFailed)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);

        // 2. Tamper kid: fails AEAD
        let mut tampered_kid = envelope.clone();
        tampered_kid.kid[0] ^= 0xFF;
        assert_eq!(
            recv.receive_frame(&tampered_kid),
            Err(StreamFrameError::DecryptFailed)
        );
        assert_eq!(recv.highest_accepted_sequence(), 0);

        // 3. Receive genuine envelope
        let received = recv.receive_frame(&envelope).unwrap();
        assert_eq!(received.payload, b"sensitive");
        assert_eq!(recv.highest_accepted_sequence(), 1);

        // 4. Replay rejected
        assert_eq!(
            recv.receive_frame(&envelope),
            Err(StreamFrameError::ReplayDetected)
        );
        assert_eq!(recv.highest_accepted_sequence(), 1);

        // 5. Stale sequence outside 64-window
        let frame_high = StreamFrame::new(StreamFrameKind::Delta, 100, b"high".to_vec()).unwrap();
        let env_high = send.seal_frame(TEST_KID, &frame_high).unwrap();
        assert!(recv.receive_frame(&env_high).is_ok());
        assert_eq!(recv.highest_accepted_sequence(), 100);

        // Sequence 1 is now offset 99 from 100 (> 63), so stale
        assert_eq!(
            recv.receive_frame(&envelope),
            Err(StreamFrameError::StaleSequence)
        );
    }

    #[test]
    fn failure_state_preservation_comprehensive() {
        let mut send = SendSession::with_test_key();
        let mut recv = ReceiveSession::with_test_key();

        // 1. Sequence reuse on sender leaves last_sequence unchanged
        let f1 = StreamFrame::new(StreamFrameKind::Snapshot, 5, b"f1".to_vec()).unwrap();
        let env1 = send.seal_frame(TEST_KID, &f1).unwrap();
        assert_eq!(send.last_sequence(), 5);

        let f_reuse = StreamFrame::new(StreamFrameKind::Snapshot, 5, b"reuse".to_vec()).unwrap();
        assert_eq!(
            send.seal_frame(TEST_KID, &f_reuse),
            Err(StreamFrameError::SequenceReuse)
        );
        assert_eq!(send.last_sequence(), 5);

        let f_older = StreamFrame::new(StreamFrameKind::Snapshot, 3, b"older".to_vec()).unwrap();
        assert_eq!(
            send.seal_frame(TEST_KID, &f_older),
            Err(StreamFrameError::SequenceReuse)
        );
        assert_eq!(send.last_sequence(), 5);

        // 2. Legitimate frame 10 seals fine
        let f10 = StreamFrame::new(StreamFrameKind::Delta, 10, b"f10".to_vec()).unwrap();
        let env10 = send.seal_frame(TEST_KID, &f10).unwrap();
        assert_eq!(send.last_sequence(), 10);

        // 3. Receiver accepts 10
        assert!(recv.receive_frame(&env10).is_ok());
        assert_eq!(recv.highest_accepted_sequence(), 10);

        // 4. Out of order 5 is accepted once
        assert!(recv.receive_frame(&env1).is_ok());
        assert_eq!(recv.highest_accepted_sequence(), 10);

        // 5. Replaying 5 rejected
        assert_eq!(
            recv.receive_frame(&env1),
            Err(StreamFrameError::ReplayDetected)
        );
        assert_eq!(recv.highest_accepted_sequence(), 10);
    }

    #[test]
    fn redacted_debug_and_errors() {
        let secret_payload = b"SECRET-MARKET-ORDER-PAYLOAD";
        let frame =
            StreamFrame::new(StreamFrameKind::Snapshot, 42, secret_payload.to_vec()).unwrap();

        let debug_str = format!("{frame:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("payload_len: 27"));
        assert!(debug_str.contains("sequence: 42"));
        assert!(!debug_str.contains("SECRET-MARKET-ORDER-PAYLOAD"));

        let errors = [
            StreamFrameError::ZeroSequence,
            StreamFrameError::SequenceMismatch,
            StreamFrameError::SequenceReuse,
            StreamFrameError::ReplayDetected,
            StreamFrameError::StaleSequence,
            StreamFrameError::UnsupportedVersion,
            StreamFrameError::UnsupportedKind,
            StreamFrameError::PayloadTooLarge,
            StreamFrameError::FrameTooLarge,
            StreamFrameError::CiphertextOutOfBounds,
            StreamFrameError::PayloadLengthMismatch,
            StreamFrameError::MalformedFrame,
            StreamFrameError::EncryptFailed,
            StreamFrameError::DecryptFailed,
            StreamFrameError::Crypto,
        ];

        for err in errors {
            let display = format!("{err}");
            let debug = format!("{err:?}");

            // Verify errors are content-free: no secrets, endpoints, keys, nonces, targets
            for text in [&display, &debug] {
                assert!(!text.contains("SECRET"));
                assert!(!text.contains("PAYLOAD"));
                assert!(!text.contains("nonce"));
                assert!(!text.contains("kid"));
                assert!(!text.contains("target"));
                assert!(!text.contains("token"));
                assert!(!text.contains("cred"));
            }
        }
    }
}
