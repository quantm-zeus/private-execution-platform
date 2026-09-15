//! Browser-interoperable opaque session transport.
//!
//! This crate implements the exact wire contract the private workspace payload
//! uses over the neutral `/v1/*` paths:
//!
//! * Envelope (cleartext, `application/octet-stream` body as UTF-8 JSON):
//!   `{"kid": b64, "nonce": b64, "sequence": u64, "ciphertext": b64}`.
//! * AEAD: AES-256-GCM with a fresh 12-byte random nonce and associated data
//!   exactly `kid=<kid>;seq=<sequence>` (UTF-8), matching WebCrypto
//!   (`web/workspace-payload/src/realtime/{sealer,decryptor}.ts`).
//! * Inner plaintext is UTF-8 JSON; the operation type never leaves the AEAD.
//!
//! Session keys are the HPKE-exporter app directions (see
//! [`crypto_envelope::hpke::AppDirectionKeys`]); this crate never persists,
//! logs or serializes them, and every error is value-free.
//!
//! The browser is authoritative for the framing, so this must not be "cleaned
//! up" to the Rust-internal `Envelope`/`StreamFrame` types without a lockstep
//! web change.

use std::collections::HashMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crypto_envelope::hpke::AppDirectionKeys;
use crypto_envelope::KID_LEN;

/// Key identifier length in bytes (the wire `kid` is standard base64 of this).
pub const KID_BYTES: usize = KID_LEN;
/// AES-GCM nonce length.
pub const WIRE_NONCE_LEN: usize = NONCE_LEN;
/// Provider (GCM) tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Largest accepted ciphertext (base64-decoded) in bytes, matching the web
/// `MAX_CIPHERTEXT_BYTES`.
pub const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
/// Largest accepted raw wire body in bytes, matching the web `MAX_WIRE_BYTES`.
pub const MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
/// Largest accepted `request_id`.
pub const MAX_REQUEST_ID_LEN: usize = 128;
/// Largest accepted operation name.
pub const MAX_OP_LEN: usize = 64;
/// Replay window width in sequence numbers.
const REPLAY_WINDOW: u64 = 64;

/// Value-free transport/session errors. No key material, payload or decrypted
/// content is ever included.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    #[error("session key is invalid")]
    InvalidKey,
    #[error("wire envelope is malformed")]
    MalformedEnvelope,
    #[error("wire envelope exceeded the size bound")]
    TooLarge,
    #[error("wire envelope key id did not match the session")]
    KeyIdMismatch,
    #[error("wire envelope nonce is invalid")]
    InvalidNonce,
    #[error("wire envelope ciphertext is invalid")]
    InvalidCiphertext,
    #[error("session envelope failed authentication")]
    DecryptFailed,
    #[error("session envelope could not be sealed")]
    EncryptFailed,
    #[error("sequence was already accepted (replay)")]
    ReplayDetected,
    #[error("sequence is older than the replay window")]
    StaleSequence,
    #[error("session has expired")]
    Expired,
    #[error("secure random number generator unavailable")]
    RngUnavailable,
    #[error("command plaintext is malformed")]
    MalformedCommand,
    #[error("request id is missing or malformed")]
    MalformedRequestId,
    #[error("operation name is missing or malformed")]
    MalformedOperation,
    #[error("operation is unknown")]
    UnknownOperation,
    #[error("session registry rejected a duplicate key id")]
    DuplicateSession,
    #[error("stream frame is malformed")]
    MalformedFrame,
    #[error("stream frame channel is unknown")]
    UnknownChannel,
    #[error("stream frame server time regressed for this session key")]
    StaleServerTime,
    #[error("stream sequence space was exhausted for this session key")]
    SequenceExhausted,
}

/// Direction-separated AES-256-GCM key. Redacted `Debug`, never `Clone`.
struct AeadKey(LessSafeKey);

impl AeadKey {
    fn new(raw: &[u8; 32]) -> Result<Self, SessionError> {
        let unbound = UnboundKey::new(&AES_256_GCM, raw).map_err(|_| SessionError::InvalidKey)?;
        Ok(Self(LessSafeKey::new(unbound)))
    }

    fn seal(
        &self,
        nonce: &[u8; WIRE_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let mut in_out = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| SessionError::EncryptFailed)?;
        Ok(in_out)
    }

    fn open(
        &self,
        nonce: &[u8; WIRE_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| SessionError::DecryptFailed)?;
        Ok(plaintext.to_vec())
    }
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey([REDACTED])")
    }
}

fn random_nonce() -> Result<[u8; WIRE_NONCE_LEN], SessionError> {
    let mut nonce = [0u8; WIRE_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| SessionError::RngUnavailable)?;
    Ok(nonce)
}

/// Associated data bound by both sides: exactly `kid=<kid>;seq=<sequence>`.
///
/// This must byte-for-byte match the web `sealer`/`decryptor` and the e2e mock,
/// so it is deliberately built from the *base64 string* kid, not raw bytes.
pub fn envelope_aad(kid: &str, sequence: u64) -> Vec<u8> {
    format!("kid={kid};seq={sequence}").into_bytes()
}

/// Cleartext wire envelope. `kid`/`nonce`/`ciphertext` are standard base64.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvelope {
    pub kid: String,
    pub nonce: String,
    pub sequence: u64,
    pub ciphertext: String,
}

impl fmt::Debug for WireEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireEnvelope")
            .field("kid", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("sequence", &self.sequence)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl WireEnvelope {
    /// Decode and validate the base64 `kid` as a 16-byte key id.
    pub fn decode_kid(&self) -> Result<[u8; KID_BYTES], SessionError> {
        let raw = B64
            .decode(self.kid.as_bytes())
            .map_err(|_| SessionError::MalformedEnvelope)?;
        if raw.len() != KID_BYTES {
            return Err(SessionError::MalformedEnvelope);
        }
        let mut out = [0u8; KID_BYTES];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    fn decode_nonce(&self) -> Result<[u8; WIRE_NONCE_LEN], SessionError> {
        let raw = B64
            .decode(self.nonce.as_bytes())
            .map_err(|_| SessionError::InvalidNonce)?;
        if raw.len() != WIRE_NONCE_LEN {
            return Err(SessionError::InvalidNonce);
        }
        let mut out = [0u8; WIRE_NONCE_LEN];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    fn decode_ciphertext(&self) -> Result<Vec<u8>, SessionError> {
        let raw = B64
            .decode(self.ciphertext.as_bytes())
            .map_err(|_| SessionError::InvalidCiphertext)?;
        if raw.len() < AEAD_TAG_LEN || raw.len() > MAX_CIPHERTEXT_BYTES {
            return Err(SessionError::InvalidCiphertext);
        }
        Ok(raw)
    }

    /// Serialize to the UTF-8 JSON bytes that cross the octet-stream boundary.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("wire envelope serialization is infallible")
    }
}

/// Strict parse of an untrusted wire body (`application/octet-stream`, UTF-8
/// JSON). Bounded before any decoding.
pub fn parse_wire_envelope(bytes: &[u8]) -> Result<WireEnvelope, SessionError> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err(SessionError::TooLarge);
    }
    let envelope: WireEnvelope =
        serde_json::from_slice(bytes).map_err(|_| SessionError::MalformedEnvelope)?;
    // Structural validation up-front so callers cannot observe malformed base64
    // from a "valid" envelope; decoding is repeated by the session (cheap) and
    // produces the same error class.
    if envelope.kid.is_empty()
        || envelope.kid.len() > 128
        || !envelope.kid.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b':' | b'-')
        })
    {
        return Err(SessionError::MalformedEnvelope);
    }
    envelope.decode_kid()?;
    envelope.decode_nonce()?;
    envelope.decode_ciphertext()?;
    Ok(envelope)
}

/// Sliding-window replay tracker. Sequence `0` is a legal first sequence
/// (the browser command client starts at 0), unlike the internal
/// `crypto-envelope` window.
#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> Result<(), SessionError> {
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bitmap = 1;
                Ok(())
            }
            Some(highest) if sequence > highest => {
                let delta = sequence - highest;
                self.bitmap = if delta >= REPLAY_WINDOW {
                    1
                } else {
                    (self.bitmap << delta) | 1
                };
                self.highest = Some(sequence);
                Ok(())
            }
            Some(highest) => {
                let offset = highest - sequence;
                if offset >= REPLAY_WINDOW {
                    return Err(SessionError::StaleSequence);
                }
                let bit = 1u64 << offset;
                if self.bitmap & bit != 0 {
                    return Err(SessionError::ReplayDetected);
                }
                self.bitmap |= bit;
                Ok(())
            }
        }
    }
}

fn kid_b64(kid: &[u8; KID_BYTES]) -> String {
    B64.encode(kid)
}

/// Standard-base64 wire form of a 16-byte key id, exactly as the browser sends
/// it in `kid` and as the artifact-grant flow advertises it.
pub fn wire_kid(kid: &[u8; KID_BYTES]) -> String {
    kid_b64(kid)
}

/// Logical channel a c2s envelope arrived on.
///
/// The browser seals bootstrap, sync and command requests with *independent*
/// per-endpoint sequence counters (the sync worker and the main-thread command
/// client each start at 0), so the server tracks a separate replay window per
/// purpose. Nonces are independently random, so the same key may safely seal
/// different purposes at the same sequence number; the purpose is fixed by the
/// route and is never read from the request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    Bootstrap,
    Sync,
    Command,
    /// Browser -> server realtime stream control (the encrypted `subscribe`
    /// frame that identifies the session and the client's high-water mark).
    Stream,
}

impl Purpose {
    fn index(self) -> usize {
        match self {
            Purpose::Bootstrap => 0,
            Purpose::Sync => 1,
            Purpose::Command => 2,
            Purpose::Stream => 3,
        }
    }
}

/// Closed set of realtime channels the browser decoder understands
/// (`web/workspace-payload/src/realtime/decoder.ts`).
pub const STREAM_CHANNELS: &[&str] = &[
    "ohlcv",
    "depth",
    "trades",
    "market",
    "orders",
    "execution",
    "alerts",
    "portfolio",
    "providers",
    "system",
];
/// Largest accepted inner frame payload, matching the web decoder.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 512 * 1024;
/// Largest accepted `entity_key`, matching the web decoder.
pub const MAX_ENTITY_KEY_LEN: usize = 256;

/// Inner realtime frame operation. Serialized as the bare snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamOp {
    Snapshot,
    Delta,
    Heartbeat,
    Mark,
    Error,
}

/// Decrypted realtime frame. Byte-compatible with the browser decoder: the
/// cleartext envelope stays generic, and every field here (including
/// `server_time_ms`) is authenticated by the AEAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamFrame {
    pub op: StreamOp,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    pub source_age_ms: u64,
    /// Server wall clock at emission (BR-15). AEAD-authenticated and enforced
    /// non-decreasing across the lifetime of the session key.
    pub server_time_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl StreamFrame {
    /// A state frame (`snapshot`/`delta`) with a payload.
    pub fn state(
        op: StreamOp,
        channel: impl Into<String>,
        server_time_ms: i64,
        source_age_ms: u64,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            op,
            channel: channel.into(),
            priority: None,
            entity_key: None,
            slot: None,
            source_age_ms,
            server_time_ms,
            payload: Some(payload),
        }
    }

    /// A control frame (`heartbeat`/`mark`/`error`) with no payload.
    pub fn control(
        op: StreamOp,
        channel: impl Into<String>,
        server_time_ms: i64,
        source_age_ms: u64,
    ) -> Self {
        Self {
            op,
            channel: channel.into(),
            priority: None,
            entity_key: None,
            slot: None,
            source_age_ms,
            server_time_ms,
            payload: None,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_entity_key(mut self, key: impl Into<String>) -> Self {
        self.entity_key = Some(key.into());
        self
    }

    pub fn with_slot(mut self, slot: u64) -> Self {
        self.slot = Some(slot);
        self
    }

    /// Strict validation so the server can never emit a frame the browser
    /// decoder would refuse. Value-free errors.
    pub fn validate(&self) -> Result<(), SessionError> {
        if !STREAM_CHANNELS.contains(&self.channel.as_str()) {
            return Err(SessionError::UnknownChannel);
        }
        if let Some(priority) = self.priority {
            if priority > 3 {
                return Err(SessionError::MalformedFrame);
            }
        }
        if self.source_age_ms > i64::MAX as u64 {
            return Err(SessionError::MalformedFrame);
        }
        if self.server_time_ms < 0 {
            return Err(SessionError::MalformedFrame);
        }
        if let Some(entity_key) = &self.entity_key {
            if entity_key.is_empty() || entity_key.len() > MAX_ENTITY_KEY_LEN {
                return Err(SessionError::MalformedFrame);
            }
        }
        let needs_payload = matches!(self.op, StreamOp::Snapshot | StreamOp::Delta);
        match (&self.payload, needs_payload) {
            (Some(payload), true) => {
                let encoded =
                    serde_json::to_vec(payload).map_err(|_| SessionError::MalformedFrame)?;
                if encoded.len() > MAX_FRAME_PAYLOAD_BYTES {
                    return Err(SessionError::MalformedFrame);
                }
            }
            (None, true) => return Err(SessionError::MalformedFrame),
            _ => {}
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SessionError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| SessionError::MalformedFrame)
    }
}

/// Server-side view of one established browser session.
///
/// Opens c2s (command/sync/bootstrap request) envelopes and seals s2c
/// (response/stream) envelopes under the same `kid`.
pub struct ServerSession {
    kid: String,
    kid_bytes: [u8; KID_BYTES],
    open_key: AeadKey,
    seal_key: AeadKey,
    replay: [ReplayWindow; 4],
    expires_at_ms: i64,
    /// Next s2c stream sequence. Monotonic for the lifetime of the session key
    /// (`kid`); a backend that resets its sequence space MUST do so behind a new
    /// `kid` (BR-2 epoch rule). Command responses do not consume this counter.
    stream_sequence: u64,
    /// Highest authenticated `server_time_ms` emitted on the stream (BR-15).
    max_server_time_ms: Option<i64>,
}

impl fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSession")
            .field("kid", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("stream_sequence", &self.stream_sequence)
            .finish_non_exhaustive()
    }
}

impl ServerSession {
    /// Build from the HPKE-exporter app keys. `kid` is the base64 wire form.
    pub fn new(
        kid: [u8; KID_BYTES],
        keys: &AppDirectionKeys,
        expires_at_ms: i64,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            kid: kid_b64(&kid),
            kid_bytes: kid,
            // Server receives under c2s and sends under s2c.
            open_key: AeadKey::new(keys.c2s())?,
            seal_key: AeadKey::new(keys.s2c())?,
            replay: [
                ReplayWindow::default(),
                ReplayWindow::default(),
                ReplayWindow::default(),
                ReplayWindow::default(),
            ],
            expires_at_ms,
            stream_sequence: 0,
            max_server_time_ms: None,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn kid_bytes(&self) -> &[u8; KID_BYTES] {
        &self.kid_bytes
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Authenticate, decrypt and replay-check an inbound c2s envelope for the
    /// given logical purpose.
    pub fn open(
        &mut self,
        envelope: &WireEnvelope,
        now_ms: i64,
        purpose: Purpose,
    ) -> Result<Vec<u8>, SessionError> {
        if self.is_expired(now_ms) {
            return Err(SessionError::Expired);
        }
        if envelope.kid != self.kid {
            return Err(SessionError::KeyIdMismatch);
        }
        let decoded_kid = envelope.decode_kid()?;
        if decoded_kid != self.kid_bytes {
            return Err(SessionError::KeyIdMismatch);
        }
        let nonce = envelope.decode_nonce()?;
        let ciphertext = envelope.decode_ciphertext()?;
        let aad = envelope_aad(&self.kid, envelope.sequence);
        let plaintext = self.open_key.open(&nonce, &aad, &ciphertext)?;
        // Replay state advances only after successful authentication.
        self.replay[purpose.index()].accept(envelope.sequence)?;
        Ok(plaintext)
    }

    /// Seal an s2c envelope at an explicit sequence (command responses bind the
    /// request sequence; stream frames use their own monotonic sequence).
    pub fn seal(&self, sequence: u64, plaintext: &[u8]) -> Result<WireEnvelope, SessionError> {
        let nonce = random_nonce()?;
        let aad = envelope_aad(&self.kid, sequence);
        let ciphertext = self.seal_key.seal(&nonce, &aad, plaintext)?;
        Ok(WireEnvelope {
            kid: self.kid.clone(),
            nonce: B64.encode(nonce),
            sequence,
            ciphertext: B64.encode(ciphertext),
        })
    }

    /// Next s2c stream sequence this session will emit.
    pub fn stream_sequence(&self) -> u64 {
        self.stream_sequence
    }

    /// Highest authenticated stream `server_time_ms` emitted, if any.
    pub fn max_server_time_ms(&self) -> Option<i64> {
        self.max_server_time_ms
    }

    /// Seal one realtime frame at the session's next stream sequence.
    ///
    /// Enforces the BR-15 monotonic server clock: a frame whose authenticated
    /// `server_time_ms` regresses is refused (and does not consume a sequence).
    /// The caller must not reset this counter for the same `kid`; sequence epoch
    /// resets require a fresh BR-5 handoff (new `kid`).
    pub fn seal_stream_frame(&mut self, frame: &StreamFrame) -> Result<WireEnvelope, SessionError> {
        if let Some(previous) = self.max_server_time_ms {
            if frame.server_time_ms < previous {
                return Err(SessionError::StaleServerTime);
            }
        }
        let plaintext = frame.to_bytes()?;
        let sequence = self.stream_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceExhausted)?;
        let envelope = self.seal(sequence, &plaintext)?;
        self.stream_sequence = next;
        self.max_server_time_ms = Some(frame.server_time_ms);
        Ok(envelope)
    }
}

/// Client-side mirror used by tests and the in-process end-to-end harness. It
/// reproduces the browser's exact framing and sequence behaviour.
pub struct ClientSession {
    kid: String,
    kid_bytes: [u8; KID_BYTES],
    seal_key: AeadKey,
    open_key: AeadKey,
    next_sequence: u64,
    replay: ReplayWindow,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSession([REDACTED])")
    }
}

impl ClientSession {
    pub fn new(kid: [u8; KID_BYTES], keys: &AppDirectionKeys) -> Result<Self, SessionError> {
        Ok(Self {
            kid: kid_b64(&kid),
            kid_bytes: kid,
            // Client seals under c2s and opens under s2c.
            seal_key: AeadKey::new(keys.c2s())?,
            open_key: AeadKey::new(keys.s2c())?,
            next_sequence: 0,
            replay: ReplayWindow::default(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Next sequence the browser-style client will use (0-based).
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Seal the next c2s envelope, advancing the client sequence counter.
    pub fn seal_next(&mut self, plaintext: &[u8]) -> Result<WireEnvelope, SessionError> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.seal_key.seal_at(&self.kid, sequence, plaintext)
    }

    /// Seal at an explicit sequence without consuming the counter (resync).
    pub fn seal_at(&self, sequence: u64, plaintext: &[u8]) -> Result<WireEnvelope, SessionError> {
        self.seal_key.seal_at(&self.kid, sequence, plaintext)
    }

    /// Open an s2c envelope with replay protection.
    pub fn open(&mut self, envelope: &WireEnvelope) -> Result<Vec<u8>, SessionError> {
        if envelope.kid != self.kid {
            return Err(SessionError::KeyIdMismatch);
        }
        if envelope.decode_kid()? != self.kid_bytes {
            return Err(SessionError::KeyIdMismatch);
        }
        let nonce = envelope.decode_nonce()?;
        let ciphertext = envelope.decode_ciphertext()?;
        let aad = envelope_aad(&self.kid, envelope.sequence);
        let plaintext = self.open_key.open(&nonce, &aad, &ciphertext)?;
        self.replay.accept(envelope.sequence)?;
        Ok(plaintext)
    }
}

impl AeadKey {
    fn seal_at(
        &self,
        kid: &str,
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<WireEnvelope, SessionError> {
        let nonce = random_nonce()?;
        let aad = envelope_aad(kid, sequence);
        let ciphertext = self.seal(&nonce, &aad, plaintext)?;
        Ok(WireEnvelope {
            kid: kid.to_string(),
            nonce: B64.encode(nonce),
            sequence,
            ciphertext: B64.encode(ciphertext),
        })
    }
}

/// Server-side registry of established sessions, pruned on every access.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: HashMap<[u8; KID_BYTES], ServerSession>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn insert(&mut self, session: ServerSession) -> Result<(), SessionError> {
        let kid = *session.kid_bytes();
        if self.sessions.contains_key(&kid) {
            return Err(SessionError::DuplicateSession);
        }
        self.sessions.insert(kid, session);
        Ok(())
    }

    pub fn get_mut(&mut self, kid: &[u8; KID_BYTES]) -> Option<&mut ServerSession> {
        self.sessions.get_mut(kid)
    }

    pub fn remove(&mut self, kid: &[u8; KID_BYTES]) -> Option<ServerSession> {
        self.sessions.remove(kid)
    }

    /// Drop expired sessions; returns how many were removed.
    pub fn prune(&mut self, now_ms: i64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_expired(now_ms));
        before - self.sessions.len()
    }
}

impl fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRegistry")
            .field("len", &self.sessions.len())
            .finish()
    }
}

/// Closed set of denial codes the web client understands
/// (`web/workspace-payload/src/transport/command.ts` allowed list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCode {
    Auth,
    CapabilityMissing,
    Freshness,
    Protocol,
    Server,
    Cancelled,
    Unknown,
}

impl DenialCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DenialCode::Auth => "auth",
            DenialCode::CapabilityMissing => "capability_missing",
            DenialCode::Freshness => "freshness",
            DenialCode::Protocol => "protocol",
            DenialCode::Server => "server",
            DenialCode::Cancelled => "cancelled",
            DenialCode::Unknown => "unknown",
        }
    }
}

/// Typed, AEAD-authenticated denial body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDenial {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl CommandDenial {
    pub fn new(code: DenialCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.as_str().to_string(),
            message: message.into(),
            retryable,
        }
    }

    /// A denial the client classifies as not retryable.
    pub fn determinate(code: DenialCode, message: impl Into<String>) -> Self {
        Self::new(code, message, false)
    }

    /// A denial the client must treat as indeterminate (keeping its
    /// idempotency key).
    pub fn indeterminate(code: DenialCode, message: impl Into<String>) -> Self {
        Self::new(code, message, true)
    }
}

/// Inbound command plaintext: `{op, payload, request_id, idempotency_key}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub op: String,
    #[serde(default)]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl CommandRequest {
    /// Strictly decode an authenticated command plaintext.
    pub fn parse(bytes: &[u8]) -> Result<Self, SessionError> {
        let request: CommandRequest =
            serde_json::from_slice(bytes).map_err(|_| SessionError::MalformedCommand)?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), SessionError> {
        if self.op.is_empty() || self.op.len() > MAX_OP_LEN || !self.op.is_ascii() {
            return Err(SessionError::MalformedOperation);
        }
        if self.request_id.is_empty() || self.request_id.len() > MAX_REQUEST_ID_LEN {
            return Err(SessionError::MalformedRequestId);
        }
        if let Some(key) = &self.idempotency_key {
            if key.is_empty() || key.len() > 256 || !key.is_ascii() {
                return Err(SessionError::MalformedCommand);
            }
        }
        Ok(())
    }
}

/// Outbound command response plaintext. `request_id` is always echoed so the
/// client can bind the response to its request (BR-3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<CommandDenial>,
}

impl CommandResponse {
    pub fn success(request_id: &str, result: serde_json::Value) -> Self {
        Self {
            request_id: request_id.to_string(),
            result: Some(result),
            error: None,
        }
    }

    pub fn denial(request_id: &str, denial: CommandDenial) -> Self {
        Self {
            request_id: request_id.to_string(),
            result: None,
            error: Some(denial),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("command response serialization is infallible")
    }
}

/// Inbound realtime stream control frame (browser -> server). The payload stays
/// generic; only the operation name and the client high-water mark are read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamControlRequest {
    pub op: String,
    #[serde(default)]
    pub from_seq: Option<u64>,
    #[serde(default)]
    pub request_id: String,
}

impl StreamControlRequest {
    pub const SUBSCRIBE: &'static str = "subscribe";

    /// Strictly decode an authenticated stream control plaintext. Only the
    /// encrypted `subscribe` operation is accepted on the realtime channel.
    pub fn parse(bytes: &[u8]) -> Result<Self, SessionError> {
        let request: StreamControlRequest =
            serde_json::from_slice(bytes).map_err(|_| SessionError::MalformedCommand)?;
        if request.op != Self::SUBSCRIBE {
            return Err(SessionError::UnknownOperation);
        }
        if request.request_id.len() > MAX_REQUEST_ID_LEN {
            return Err(SessionError::MalformedRequestId);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> AppDirectionKeys {
        AppDirectionKeys::from_bytes([0x11u8; 32], [0x22u8; 32])
    }

    fn established() -> (ServerSession, ClientSession) {
        let kid = [0xABu8; KID_BYTES];
        (
            ServerSession::new(kid, &keys(), i64::MAX).expect("server"),
            ClientSession::new(kid, &keys()).expect("client"),
        )
    }

    #[test]
    fn aad_matches_browser_shape() {
        assert_eq!(envelope_aad("kid-e2e", 7), b"kid=kid-e2e;seq=7".to_vec());
    }

    #[test]
    fn client_server_roundtrip_first_sequence_zero() {
        let (mut server, mut client) = established();
        assert_eq!(client.next_sequence(), 0);
        let envelope = client.seal_next(b"{\"op\":\"get_quote\"}").expect("seal");
        assert_eq!(envelope.sequence, 0);
        let plaintext = server.open(&envelope, 0, Purpose::Command).expect("open");
        assert_eq!(plaintext, b"{\"op\":\"get_quote\"}");
        assert_eq!(client.next_sequence(), 1);
    }

    #[test]
    fn response_binds_request_sequence() {
        let (mut server, mut client) = established();
        let request = client.seal_next(b"{}").expect("seal");
        let _ = server.open(&request, 0, Purpose::Command).expect("open");
        let response = server
            .seal(request.sequence, b"{\"request_id\":\"r1\"}")
            .expect("seal");
        assert_eq!(response.sequence, request.sequence);
        let opened = client.open(&response).expect("open");
        assert_eq!(opened, b"{\"request_id\":\"r1\"}");
    }

    #[test]
    fn replay_is_rejected_after_authentication() {
        let (mut server, mut client) = established();
        let envelope = client.seal_next(b"{}").expect("seal");
        assert!(server.open(&envelope, 0, Purpose::Command).is_ok());
        assert_eq!(
            server.open(&envelope, 0, Purpose::Command),
            Err(SessionError::ReplayDetected)
        );
    }

    #[test]
    fn independent_purpose_windows_allow_same_sequence_on_different_routes() {
        let (mut server, client) = established();
        // The bootstrap client and the command client each start their own
        // counter at 0; both must be accepted because the purposes are tracked
        // independently.
        let bootstrap = client.seal_at(0, b"{\"op\":\"bootstrap\"}").expect("seal");
        assert_eq!(
            server
                .open(&bootstrap, 0, Purpose::Bootstrap)
                .expect("bootstrap"),
            b"{\"op\":\"bootstrap\"}"
        );
        let command = client.seal_at(0, b"{\"op\":\"get_quote\"}").expect("seal");
        assert_eq!(
            server.open(&command, 0, Purpose::Command).expect("command"),
            b"{\"op\":\"get_quote\"}"
        );
        // Replaying within one purpose is still refused.
        assert_eq!(
            server.open(&bootstrap, 0, Purpose::Bootstrap),
            Err(SessionError::ReplayDetected)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_and_does_not_poison() {
        let (mut server, mut client) = established();
        let mut envelope = client.seal_next(b"payload").expect("seal");
        let mut raw = B64.decode(&envelope.ciphertext).unwrap();
        raw[0] ^= 0xFF;
        envelope.ciphertext = B64.encode(&raw);
        assert_eq!(
            server.open(&envelope, 0, Purpose::Command),
            Err(SessionError::DecryptFailed)
        );

        // The genuine envelope (same sequence) is still fresh: authentication
        // happened before the replay window advanced.
        let genuine = client.seal_at(0, b"payload").expect("seal at 0");
        assert_eq!(
            server.open(&genuine, 0, Purpose::Command).expect("open"),
            b"payload"
        );
    }

    #[test]
    fn kid_and_nonce_mismatch_rejected() {
        let (mut server, mut client) = established();
        let envelope = client.seal_next(b"x").expect("seal");
        let mut other = envelope.clone();
        other.kid = B64.encode([0x01u8; KID_BYTES]);
        assert_eq!(
            server.open(&other, 0, Purpose::Command),
            Err(SessionError::KeyIdMismatch)
        );

        let mut bad_nonce = envelope.clone();
        bad_nonce.nonce = B64.encode([0u8; 8]);
        assert_eq!(
            server.open(&bad_nonce, 0, Purpose::Command),
            Err(SessionError::InvalidNonce)
        );

        // Session is still usable afterwards.
        assert_eq!(
            server.open(&envelope, 0, Purpose::Command).expect("open"),
            b"x"
        );
    }

    #[test]
    fn expiry_is_enforced_before_decrypt() {
        let kid = [0xCDu8; KID_BYTES];
        let mut server = ServerSession::new(kid, &keys(), 1_000).expect("server");
        let mut client = ClientSession::new(kid, &keys()).expect("client");
        let envelope = client.seal_next(b"x").expect("seal");
        assert_eq!(
            server.open(&envelope, 1_000, Purpose::Command),
            Err(SessionError::Expired)
        );
        assert!(!server.is_expired(999));
    }

    #[test]
    fn parse_rejects_oversize_and_malformed() {
        assert_eq!(parse_wire_envelope(&[]), Err(SessionError::TooLarge));
        assert_eq!(
            parse_wire_envelope(&vec![b'x'; MAX_WIRE_BYTES + 1]),
            Err(SessionError::TooLarge)
        );
        assert_eq!(
            parse_wire_envelope(b"{}"),
            Err(SessionError::MalformedEnvelope)
        );
    }

    #[test]
    fn parse_roundtrips_wire_bytes() {
        let (_server, mut client) = established();
        let envelope = client.seal_next(b"{}").expect("seal");
        let bytes = envelope.to_wire_bytes();
        let parsed = parse_wire_envelope(&bytes).expect("parse");
        assert_eq!(parsed.sequence, 0);
        assert_eq!(parsed.kid, envelope.kid);
    }

    #[test]
    fn command_request_validation() {
        let ok = CommandRequest::parse(
            br#"{"op":"get_quote","payload":{},"request_id":"abc","idempotency_key":null}"#,
        )
        .expect("valid");
        assert_eq!(ok.op, "get_quote");
        assert!(ok.idempotency_key.is_none());

        assert_eq!(
            CommandRequest::parse(br#"{"op":"","request_id":"a"}"#).unwrap_err(),
            SessionError::MalformedOperation
        );
        assert_eq!(
            CommandRequest::parse(br#"{"op":"get_quote"}"#).unwrap_err(),
            SessionError::MalformedRequestId
        );
        assert_eq!(
            CommandRequest::parse(b"not json").unwrap_err(),
            SessionError::MalformedCommand
        );
    }

    #[test]
    fn command_response_echoes_request_id() {
        let ok = CommandResponse::success("r1", serde_json::json!({"ok": true}));
        let value: serde_json::Value = serde_json::from_slice(&ok.to_bytes()).unwrap();
        assert_eq!(value["request_id"], "r1");
        assert_eq!(value["result"]["ok"], true);
        assert!(value.get("error").is_none());

        let denial = CommandResponse::denial(
            "r2",
            CommandDenial::indeterminate(DenialCode::Unknown, "outcome unknown"),
        );
        let value: serde_json::Value = serde_json::from_slice(&denial.to_bytes()).unwrap();
        assert_eq!(value["request_id"], "r2");
        assert_eq!(value["error"]["code"], "unknown");
        assert_eq!(value["error"]["retryable"], true);
        assert!(value.get("result").is_none());
    }

    #[test]
    fn registry_prunes_expired_and_rejects_duplicates() {
        let kid = [0xEFu8; KID_BYTES];
        let mut registry = SessionRegistry::new();
        registry
            .insert(ServerSession::new(kid, &keys(), 500).unwrap())
            .expect("insert");
        assert_eq!(
            registry.insert(ServerSession::new(kid, &keys(), 500).unwrap()),
            Err(SessionError::DuplicateSession)
        );
        assert_eq!(registry.prune(500), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn debug_never_leaks_material() {
        let (server, client) = established();
        let text = format!("{server:?} {client:?}");
        assert!(text.contains("[REDACTED]"));
        assert!(!text.contains("171")); // 0xAB
        assert!(!text.contains("17")); // 0x11
    }

    fn snapshot(server_time_ms: i64) -> StreamFrame {
        StreamFrame::state(
            StreamOp::Snapshot,
            "market",
            server_time_ms,
            5,
            serde_json::json!({"pools": []}),
        )
        .with_priority(2)
        .with_entity_key("market:default")
        .with_slot(42)
    }

    #[test]
    fn stream_frame_serializes_to_the_browser_shape() {
        let frame = snapshot(1_700_000_000_000);
        let value: serde_json::Value = serde_json::from_slice(&frame.to_bytes().unwrap()).unwrap();
        assert_eq!(value["op"], "snapshot");
        assert_eq!(value["channel"], "market");
        assert_eq!(value["priority"], 2);
        assert_eq!(value["entity_key"], "market:default");
        assert_eq!(value["slot"], 42);
        assert_eq!(value["source_age_ms"], 5);
        assert_eq!(value["server_time_ms"], 1_700_000_000_000i64);
        assert_eq!(value["payload"]["pools"], serde_json::json!([]));
    }

    #[test]
    fn stream_sequence_is_monotonic_and_independent_of_command_responses() {
        let (mut server, mut client) = established();
        let first = server.seal_stream_frame(&snapshot(1_000)).unwrap();
        let second = server
            .seal_stream_frame(&StreamFrame::control(
                StreamOp::Heartbeat,
                "system",
                1_050,
                0,
            ))
            .unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(server.stream_sequence(), 2);

        // A command response sealed at the request sequence does not move the
        // stream counter.
        let request = client.seal_next(b"{}").unwrap();
        let _ = server.open(&request, 0, Purpose::Command).unwrap();
        let response = server.seal(request.sequence, b"{}").unwrap();
        assert_eq!(response.sequence, 0);
        assert_eq!(server.stream_sequence(), 2);

        // Both frames still authenticate under the s2c key.
        let opened = client.open(&first).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(value["op"], "snapshot");
    }

    #[test]
    fn stale_stream_server_time_is_refused_without_consuming_a_sequence() {
        let (mut server, _client) = established();
        let _ = server.seal_stream_frame(&snapshot(2_000)).unwrap();
        assert_eq!(
            server.seal_stream_frame(&snapshot(1_999)),
            Err(SessionError::StaleServerTime)
        );
        assert_eq!(server.stream_sequence(), 1);
        assert_eq!(server.max_server_time_ms(), Some(2_000));
        // Equal time is allowed (non-decreasing, not strictly increasing).
        assert!(server.seal_stream_frame(&snapshot(2_000)).is_ok());
    }

    #[test]
    fn stream_frame_validation_is_fail_closed() {
        let mut bad_channel = snapshot(1);
        bad_channel.channel = "not-a-channel".to_string();
        assert_eq!(bad_channel.validate(), Err(SessionError::UnknownChannel));

        let mut bad_priority = snapshot(1);
        bad_priority.priority = Some(4);
        assert_eq!(bad_priority.validate(), Err(SessionError::MalformedFrame));

        let mut missing_payload = snapshot(1);
        missing_payload.payload = None;
        assert_eq!(
            missing_payload.validate(),
            Err(SessionError::MalformedFrame)
        );

        let mut bad_time = snapshot(1);
        bad_time.server_time_ms = -1;
        assert_eq!(bad_time.validate(), Err(SessionError::MalformedFrame));

        // A control frame legitimately carries no payload.
        assert!(StreamFrame::control(StreamOp::Heartbeat, "system", 1, 0)
            .validate()
            .is_ok());
    }

    #[test]
    fn stream_subscribe_has_its_own_purpose_window() {
        let (mut server, client) = established();
        // The command client and the stream client each start at 0; the
        // subscribe frame must not collide with the command replay window.
        let command = client.seal_at(0, b"{}").unwrap();
        assert!(server.open(&command, 0, Purpose::Command).is_ok());
        let subscribe = client
            .seal_at(
                0,
                br#"{"op":"subscribe","from_seq":null,"request_id":"s1"}"#,
            )
            .unwrap();
        let plaintext = server.open(&subscribe, 0, Purpose::Stream).unwrap();
        let parsed = StreamControlRequest::parse(&plaintext).unwrap();
        assert_eq!(parsed.op, "subscribe");
        assert_eq!(parsed.request_id, "s1");
        // Replaying the subscribe inside the stream purpose is still refused.
        assert_eq!(
            server.open(&subscribe, 0, Purpose::Stream),
            Err(SessionError::ReplayDetected)
        );
    }

    #[test]
    fn stream_control_rejects_non_subscribe_operations() {
        assert_eq!(
            StreamControlRequest::parse(br#"{"op":"sync","request_id":"x"}"#).unwrap_err(),
            SessionError::UnknownOperation
        );
        assert!(StreamControlRequest::parse(
            br#"{"op":"subscribe","from_seq":9,"request_id":"x"}"#
        )
        .is_ok());
    }
}
