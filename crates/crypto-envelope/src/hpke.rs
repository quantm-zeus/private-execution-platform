//! HPKE session-establishment layer (RFC 9180, Base mode).
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.
//! Establishes two direction-separated 32-byte application session keys via
//! the HPKE exporter and constructs the existing `SendSession`/`ReceiveSession`
//! pair for each side. All key material is RAM-only and zeroized.

use crate::{
    CryptoError, Envelope, ReceiveSession, SendSession, SessionKey, StreamFrame, StreamFrameCodec,
    StreamFrameError, KID_LEN, SESSION_KEY_LEN,
};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, rand_core::SeedableRng,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

/// Suite identifier for wire negotiation.
pub const HPKE_SUITE_ID: u16 = 1;
/// Protocol version for handshake structures.
pub const HPKE_VERSION: u8 = 1;

const HANDSHAKE_INFO: &[u8] = b"private-execution/hpke-session/v1";
const EXPORTER_C2S: &[u8] = b"private-execution app session c2s v1";
const EXPORTER_S2C: &[u8] = b"private-execution app session s2c v1";
/// Additional exporter labels for the transport AEAD the *browser* consumes.
///
/// The browser app session uses WebCrypto AES-256-GCM (the only AEAD the
/// platform exposes), while the artifact envelope above uses ChaCha20-Poly1305.
/// Reusing one key across two AEADs is a cross-protocol hazard, so the app
/// directions get their own HKDF exporter outputs. These labels are part of the
/// wire protocol: changing them invalidates every outstanding session (a fresh
/// BR-5 handoff would be required), so they are frozen.
const APP_EXPORTER_C2S: &[u8] = b"private-execution app aead c2s v1";
const APP_EXPORTER_S2C: &[u8] = b"private-execution app aead s2c v1";

#[derive(Debug, Error)]
pub enum HpkeSetupError {
    #[error("malformed recipient public key")]
    MalformedPublicKey,
    #[error("malformed encapsulated key")]
    MalformedEncapsulatedKey,
    #[error("key establishment failed")]
    EstablishmentFailed,
    #[error("entropy source unavailable")]
    EntropyUnavailable,
}

pub(crate) fn fresh_rng() -> Result<ChaCha20Rng, HpkeSetupError> {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        seed.zeroize();
        return Err(HpkeSetupError::EntropyUnavailable);
    }
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
}

/// Bounded wire public key for the recipient (32 bytes, RFC 9180 X25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkePublicKey(pub [u8; 32]);

/// Bounded wire encapsulated key (32 bytes for X25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeEncapsulatedKey(pub [u8; 32]);

/// Handshake wire descriptor: version, suite, key id and recipient public key.
///
/// HPKE Base mode does not authenticate the initiator. The offer itself must
/// be delivered with integrity by the authenticated bootstrap/session channel;
/// accepting an attacker-substituted offer would permit a normal MITM key swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeHandshakeOffer {
    pub version: u8,
    pub suite_id: u16,
    pub kid: [u8; KID_LEN],
    pub recipient_public_key: HpkePublicKey,
}

impl HpkeHandshakeOffer {
    /// Generate a fresh recipient keypair and a wire-safe offer. The private
    /// key stays local to this process and is never serialized.
    pub fn generate(kid: [u8; KID_LEN]) -> Result<(Self, HpkeRecipientKeyPair), HpkeSetupError> {
        let mut rng = fresh_rng()?;
        let (private, public) = <X25519HkdfSha256 as KemTrait>::gen_keypair_with_rng(&mut rng);
        let public_bytes: [u8; 32] = public.to_bytes().into();
        let offer = Self {
            version: HPKE_VERSION,
            suite_id: HPKE_SUITE_ID,
            kid,
            recipient_public_key: HpkePublicKey(public_bytes),
        };
        let keypair = HpkeRecipientKeyPair {
            _private: private,
            kid,
            recipient_public_key: HpkePublicKey(public_bytes),
        };
        Ok((offer, keypair))
    }

    /// Structural validation for a received offer.
    pub fn validate(&self) -> Result<(), HpkeSetupError> {
        if self.version != HPKE_VERSION || self.suite_id != HPKE_SUITE_ID {
            return Err(HpkeSetupError::EstablishmentFailed);
        }
        // Length is enforced by the [u8; 32] type; public keys are validated
        // by HPKE itself during setup.
        Ok(())
    }
}

fn canonical_handshake_info(offer: &HpkeHandshakeOffer) -> Vec<u8> {
    let mut info = Vec::with_capacity(HANDSHAKE_INFO.len() + 1 + 2 + KID_LEN + 32);
    info.extend_from_slice(HANDSHAKE_INFO);
    info.push(offer.version);
    info.extend_from_slice(&offer.suite_id.to_be_bytes());
    info.extend_from_slice(&offer.kid);
    info.extend_from_slice(&offer.recipient_public_key.0);
    info
}

/// RAM-only recipient keypair. Deliberately provides no serialization or
/// byte-level export path; it can only be consumed by receiver setup.
pub struct HpkeRecipientKeyPair {
    _private: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    kid: [u8; KID_LEN],
    recipient_public_key: HpkePublicKey,
}

impl std::fmt::Debug for HpkeRecipientKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HpkeRecipientKeyPair([REDACTED])")
    }
}

/// The initiator's half of the established session.
///
/// Sends under c2s, receives under s2c.
pub struct HpkeInitiatorSession {
    kid: [u8; KID_LEN],
    send: SendSession,
    receive: ReceiveSession,
    app: AppDirectionKeys,
}

impl HpkeInitiatorSession {
    pub fn kid(&self) -> [u8; KID_LEN] {
        self.kid
    }

    /// Raw browser-facing directional app keys. Only the trusted shell should
    /// read these, and only to hand them to the payload over a same-document
    /// channel (BR-5). Never persist, log or serialize them.
    pub fn app_keys(&self) -> &AppDirectionKeys {
        &self.app
    }

    pub fn seal(&mut self, sequence: u64, plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        self.send.seal(self.kid, sequence, plaintext)
    }

    pub fn receive(&mut self, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        if envelope.kid != self.kid {
            return Err(CryptoError::KeyIdMismatch);
        }
        self.receive.receive(envelope)
    }

    pub fn seal_frame(&mut self, frame: &StreamFrame) -> Result<Envelope, StreamFrameError> {
        self.send.seal_frame(self.kid, frame)
    }

    pub fn receive_frame(&mut self, envelope: &Envelope) -> Result<StreamFrame, StreamFrameError> {
        if envelope.kid != self.kid {
            return Err(StreamFrameError::DecryptFailed);
        }
        self.receive.receive_frame(envelope)
    }

    /// Seal a stream frame with a padded inner payload of exactly
    /// `padded_payload_len` bytes. See [`StreamFrameCodec::seal_padded`].
    pub fn seal_padded(
        &mut self,
        envelope_sequence: u64,
        frame: &StreamFrame,
        padded_payload_len: usize,
    ) -> Result<Envelope, StreamFrameError> {
        StreamFrameCodec::new().seal_padded(
            &mut self.send,
            self.kid,
            envelope_sequence,
            frame,
            padded_payload_len,
        )
    }

    /// Receive a padded stream frame produced by [`Self::seal_padded`].
    ///
    /// See [`StreamFrameCodec::receive_padded`].
    pub fn receive_padded(&mut self, envelope: &Envelope) -> Result<StreamFrame, StreamFrameError> {
        if envelope.kid != self.kid {
            return Err(StreamFrameError::DecryptFailed);
        }
        StreamFrameCodec::new().receive_padded(&mut self.receive, envelope)
    }
}

impl std::fmt::Debug for HpkeInitiatorSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeInitiatorSession")
            .field("send", &"[REDACTED]")
            .field("receive", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The responder's half of the established session.
///
/// Sends under s2c, receives under c2s.
pub struct HpkeResponderSession {
    kid: [u8; KID_LEN],
    send: SendSession,
    receive: ReceiveSession,
    app: AppDirectionKeys,
}

impl HpkeResponderSession {
    pub fn kid(&self) -> [u8; KID_LEN] {
        self.kid
    }

    /// Raw browser-facing directional app keys for the server session store.
    /// Mirrored by [`HpkeInitiatorSession::app_keys`]; never persist or log.
    pub fn app_keys(&self) -> &AppDirectionKeys {
        &self.app
    }

    pub fn seal(&mut self, sequence: u64, plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        self.send.seal(self.kid, sequence, plaintext)
    }

    pub fn receive(&mut self, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        if envelope.kid != self.kid {
            return Err(CryptoError::KeyIdMismatch);
        }
        self.receive.receive(envelope)
    }

    pub fn seal_frame(&mut self, frame: &StreamFrame) -> Result<Envelope, StreamFrameError> {
        self.send.seal_frame(self.kid, frame)
    }

    pub fn receive_frame(&mut self, envelope: &Envelope) -> Result<StreamFrame, StreamFrameError> {
        if envelope.kid != self.kid {
            return Err(StreamFrameError::DecryptFailed);
        }
        self.receive.receive_frame(envelope)
    }

    /// Seal a stream frame with a padded inner payload of exactly
    /// `padded_payload_len` bytes. See [`StreamFrameCodec::seal_padded`].
    pub fn seal_padded(
        &mut self,
        envelope_sequence: u64,
        frame: &StreamFrame,
        padded_payload_len: usize,
    ) -> Result<Envelope, StreamFrameError> {
        StreamFrameCodec::new().seal_padded(
            &mut self.send,
            self.kid,
            envelope_sequence,
            frame,
            padded_payload_len,
        )
    }

    /// Receive a padded stream frame produced by [`Self::seal_padded`].
    ///
    /// See [`StreamFrameCodec::receive_padded`].
    pub fn receive_padded(&mut self, envelope: &Envelope) -> Result<StreamFrame, StreamFrameError> {
        if envelope.kid != self.kid {
            return Err(StreamFrameError::DecryptFailed);
        }
        StreamFrameCodec::new().receive_padded(&mut self.receive, envelope)
    }
}

impl std::fmt::Debug for HpkeResponderSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeResponderSession")
            .field("send", &"[REDACTED]")
            .field("receive", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Shared secret material derived once from the HPKE exporter, immediately
/// converted into `SessionKey`s and dropped.
struct ExportedMaterial {
    c2s: SessionKey,
    s2c: SessionKey,
    app: AppDirectionKeys,
}

/// Raw direction-separated 32-byte keys for the browser-facing transport AEAD
/// (AES-256-GCM in the private payload).
///
/// This is the only type that exports raw session key bytes. It exists solely
/// so the trusted same-origin shell can hand the two directional keys to the
/// sandboxed payload over a same-document `postMessage` channel (BR-5). The
/// values zeroize on drop and never serialize or log.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AppDirectionKeys {
    c2s: [u8; SESSION_KEY_LEN],
    s2c: [u8; SESSION_KEY_LEN],
}

impl AppDirectionKeys {
    /// Client -> server key (the browser seals commands with this).
    pub fn c2s(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.c2s
    }

    /// Server -> client key (the browser opens stream/response envelopes).
    pub fn s2c(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.s2c
    }

    /// Construct from raw bytes. Intended for the private-api session store and
    /// WASM handoff plumbing; callers must not log or persist the result.
    pub fn from_bytes(c2s: [u8; SESSION_KEY_LEN], s2c: [u8; SESSION_KEY_LEN]) -> Self {
        Self { c2s, s2c }
    }
}

impl std::fmt::Debug for AppDirectionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppDirectionKeys([REDACTED])")
    }
}

impl ExportedMaterial {
    fn from_ctx(
        export: impl Fn(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>,
    ) -> Result<Self, HpkeSetupError> {
        let mut c2s = Zeroizing::new([0u8; 32]);
        let mut s2c = Zeroizing::new([0u8; 32]);
        let mut app_c2s = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        let mut app_s2c = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        export(EXPORTER_C2S, &mut c2s[..]).map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        export(EXPORTER_S2C, &mut s2c[..]).map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        export(APP_EXPORTER_C2S, &mut app_c2s[..])
            .map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        export(APP_EXPORTER_S2C, &mut app_s2c[..])
            .map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        Ok(Self {
            c2s: SessionKey::from_bytes(*c2s),
            s2c: SessionKey::from_bytes(*s2c),
            app: AppDirectionKeys::from_bytes(*app_c2s, *app_s2c),
        })
    }
}

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Initiator side: uses the recipient's public key, encapsulates, exports the
/// two direction keys, and builds direction-correct sessions.
pub fn initiator_establish(
    offer: &HpkeHandshakeOffer,
) -> Result<(HpkeEncapsulatedKey, HpkeInitiatorSession), HpkeSetupError> {
    offer.validate()?;
    let recipient_pk =
        <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&offer.recipient_public_key.0)
            .map_err(|_| HpkeSetupError::MalformedPublicKey)?;

    let info = canonical_handshake_info(offer);
    let mut rng = fresh_rng()?;
    let (encapped, ctx) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &recipient_pk, &info, &mut rng)
    .map_err(|_| HpkeSetupError::EstablishmentFailed)?;

    let material = ExportedMaterial::from_ctx(|label, out| ctx.export(label, out))?;
    let wire = HpkeEncapsulatedKey(encapped.to_bytes().into());
    Ok((
        wire,
        HpkeInitiatorSession {
            kid: offer.kid,
            send: SendSession::new(material.c2s)
                .map_err(|_| HpkeSetupError::EstablishmentFailed)?,
            receive: ReceiveSession::new(material.s2c),
            app: material.app,
        },
    ))
}

/// Responder side: validates the encapsulated key, decapsulates with its own
/// private key, exports the same two direction keys, and builds mirrored
/// sessions.
pub fn responder_establish(
    offer: &HpkeHandshakeOffer,
    keypair: &HpkeRecipientKeyPair,
    encapsulated: &HpkeEncapsulatedKey,
) -> Result<HpkeResponderSession, HpkeSetupError> {
    offer.validate()?;
    if keypair.kid != offer.kid || keypair.recipient_public_key != offer.recipient_public_key {
        return Err(HpkeSetupError::EstablishmentFailed);
    }
    let encapped = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&encapsulated.0)
        .map_err(|_| HpkeSetupError::MalformedEncapsulatedKey)?;
    let info = canonical_handshake_info(offer);
    let ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &keypair._private,
        &encapped,
        &info,
    )
    .map_err(|_| HpkeSetupError::EstablishmentFailed)?;

    let material = ExportedMaterial::from_ctx(|label, out| ctx.export(label, out))?;
    Ok(HpkeResponderSession {
        kid: offer.kid,
        send: SendSession::new(material.s2c).map_err(|_| HpkeSetupError::EstablishmentFailed)?,
        receive: ReceiveSession::new(material.c2s),
        app: material.app,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SESSION_KEY_LEN;

    fn establish() -> (HpkeInitiatorSession, HpkeResponderSession) {
        let kid = [7u8; KID_LEN];
        let (offer, keypair) = HpkeHandshakeOffer::generate(kid).expect("offer");
        let (encapsulated, initiator) = initiator_establish(&offer).expect("initiator");
        let responder = responder_establish(&offer, &keypair, &encapsulated).expect("responder");
        (initiator, responder)
    }

    #[test]
    fn exporter_second_failure_returns_opaque_error() {
        let calls = std::cell::Cell::new(0u8);
        let result = ExportedMaterial::from_ctx(|label, out| {
            calls.set(calls.get() + 1);
            if label == EXPORTER_C2S {
                out.fill(0xA5);
                Ok(())
            } else {
                Err(hpke::HpkeError::ValidationError)
            }
        });
        assert_eq!(calls.get(), 2);
        assert!(matches!(result, Err(HpkeSetupError::EstablishmentFailed)));
    }

    #[test]
    fn handshake_roundtrip_and_directional_exchange() {
        let (mut init, mut resp) = establish();

        // c2s: initiator sends, responder receives.
        let c2s_env = init.seal(1, b"c2s").expect("c2s seal");
        assert_eq!(resp.receive(&c2s_env).expect("c2s open"), b"c2s");

        // s2c: responder sends, initiator receives.
        let s2c_env = resp.seal(1, b"s2c").expect("s2c seal");
        assert_eq!(init.receive(&s2c_env).expect("s2c open"), b"s2c");
    }

    #[test]
    fn opposite_direction_keys_are_separate() {
        let (mut init, mut resp) = establish();

        // c2s ciphertext must not open under the initiator's receive key
        // (which holds s2c material) — proving key separation without
        // exposing bytes.
        let c2s_env = init.seal(1, b"cross").expect("seal");
        assert!(matches!(
            init.receive(&c2s_env),
            Err(crate::CryptoError::DecryptFailed)
        ));

        // Likewise s2c under the responder's c2s receive key.
        let s2c_env = resp.seal(1, b"cross").expect("seal");
        assert!(matches!(
            resp.receive(&s2c_env),
            Err(crate::CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn replay_and_tamper_still_rejected_after_handshake() {
        let (mut init, mut resp) = establish();
        let env = init.seal(1, b"msg").expect("seal");
        assert_eq!(resp.receive(&env).expect("open"), b"msg");
        assert!(matches!(
            resp.receive(&env),
            Err(crate::CryptoError::ReplayDetected(1))
        ));

        let mut tampered = env.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            resp.receive(&tampered),
            Err(crate::CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn bound_kid_is_automatic_and_mismatch_does_not_poison_replay() {
        let (mut init, mut resp) = establish();
        let expected_kid = [7u8; KID_LEN];
        assert_eq!(init.kid(), expected_kid);
        assert_eq!(resp.kid(), expected_kid);
        let env = init.seal(1, b"bound").expect("seal");
        assert_eq!(env.kid, expected_kid);

        let mut wrong = env.clone();
        wrong.kid[0] ^= 1;
        assert!(matches!(
            resp.receive(&wrong),
            Err(CryptoError::KeyIdMismatch)
        ));
        assert_eq!(resp.receive(&env).expect("fresh original"), b"bound");
    }

    #[test]
    fn responder_rejects_offer_metadata_mismatch() {
        let (offer, keypair) = HpkeHandshakeOffer::generate([3u8; KID_LEN]).expect("offer");
        let (enc, _init) = initiator_establish(&offer).expect("init");

        let mut wrong_kid = offer.clone();
        wrong_kid.kid[0] ^= 1;
        assert!(matches!(
            responder_establish(&wrong_kid, &keypair, &enc),
            Err(HpkeSetupError::EstablishmentFailed)
        ));

        let (other_offer, _other_keypair) =
            HpkeHandshakeOffer::generate([9u8; KID_LEN]).expect("other offer");
        let mut wrong_public = offer.clone();
        wrong_public.recipient_public_key = other_offer.recipient_public_key;
        assert!(matches!(
            responder_establish(&wrong_public, &keypair, &enc),
            Err(HpkeSetupError::EstablishmentFailed)
        ));
    }

    #[test]
    fn canonical_handshake_info_binds_offer_metadata() {
        let (offer, _keypair) = HpkeHandshakeOffer::generate([4u8; KID_LEN]).expect("offer");
        let baseline = canonical_handshake_info(&offer);

        let mut kid = offer.clone();
        kid.kid[0] ^= 1;
        assert_ne!(baseline, canonical_handshake_info(&kid));

        let mut version = offer.clone();
        version.version = version.version.wrapping_add(1);
        assert_ne!(baseline, canonical_handshake_info(&version));

        let mut suite = offer.clone();
        suite.suite_id = suite.suite_id.wrapping_add(1);
        assert_ne!(baseline, canonical_handshake_info(&suite));

        let (other, _other_keypair) =
            HpkeHandshakeOffer::generate([5u8; KID_LEN]).expect("other offer");
        let mut public = offer.clone();
        public.recipient_public_key = other.recipient_public_key;
        assert_ne!(baseline, canonical_handshake_info(&public));
    }

    #[test]
    fn low_order_encapsulated_key_rejected() {
        let (offer, keypair) = HpkeHandshakeOffer::generate([1u8; KID_LEN]).expect("offer");
        // X25519 deserializes any 32-byte value; the all-zero encapsulated key
        // yields the all-zero DH result, which HPKE rejects during setup.
        let bad = HpkeEncapsulatedKey([0u8; 32]);
        assert!(matches!(
            responder_establish(&offer, &keypair, &bad),
            Err(HpkeSetupError::EstablishmentFailed)
        ));
    }

    #[test]
    fn low_order_public_key_rejected() {
        let offer = HpkeHandshakeOffer {
            version: HPKE_VERSION,
            suite_id: HPKE_SUITE_ID,
            kid: [1u8; KID_LEN],
            // X25519 deserializes any 32-byte value; the all-zero public key
            // yields the all-zero DH result, which HPKE rejects during setup.
            recipient_public_key: HpkePublicKey([0u8; 32]),
        };
        assert!(matches!(
            initiator_establish(&offer),
            Err(HpkeSetupError::EstablishmentFailed)
        ));
    }

    #[test]
    fn offer_version_and_suite_validated() {
        let (mut offer, _kp) = HpkeHandshakeOffer::generate([1u8; KID_LEN]).expect("offer");
        offer.version = 99;
        assert!(offer.validate().is_err());
        offer.version = HPKE_VERSION;
        offer.suite_id = 42;
        assert!(offer.validate().is_err());
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let (offer, keypair) = HpkeHandshakeOffer::generate([1u8; KID_LEN]).expect("offer");
        let (enc, init) = initiator_establish(&offer).expect("init");
        let resp = responder_establish(&offer, &keypair, &enc).expect("resp");

        let dbg = format!("{keypair:?}\n{init:?}\n{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("PrivateKey("));
        assert!(!dbg.contains("SessionKey("));
        assert!(!dbg.contains("c2s:"));
        assert!(!dbg.contains("s2c:"));
        assert!(!dbg.contains("send: SendSession"));
        assert!(!dbg.contains("receive: ReceiveSession"));
        assert!(!dbg.contains("[u8:"));
        let _ = SESSION_KEY_LEN;
        let _ = offer;
    }

    #[test]
    fn app_direction_keys_match_both_sides_and_are_separated() {
        let (offer, keypair) = HpkeHandshakeOffer::generate([7u8; KID_LEN]).expect("offer");
        let (enc, init) = initiator_establish(&offer).expect("init");
        let resp = responder_establish(&offer, &keypair, &enc).expect("resp");

        // The two sides derive identical directional app keys...
        assert_eq!(init.app_keys().c2s(), resp.app_keys().c2s());
        assert_eq!(init.app_keys().s2c(), resp.app_keys().s2c());
        // ...and the two directions are distinct (nonce-reuse safety).
        assert_ne!(init.app_keys().c2s(), init.app_keys().s2c());
        // A different handshake derives different app keys.
        let (other_offer, _) = HpkeHandshakeOffer::generate([8u8; KID_LEN]).expect("other");
        let (_, other_init) = initiator_establish(&other_offer).expect("other init");
        assert_ne!(init.app_keys().c2s(), other_init.app_keys().c2s());
    }

    #[test]
    fn app_direction_keys_debug_is_redacted() {
        let (offer, keypair) = HpkeHandshakeOffer::generate([7u8; KID_LEN]).expect("offer");
        let (enc, _init) = initiator_establish(&offer).expect("init");
        let resp = responder_establish(&offer, &keypair, &enc).expect("resp");
        let debug = format!("{:?}", resp.app_keys());
        assert_eq!(debug, "AppDirectionKeys([REDACTED])");
    }
}
