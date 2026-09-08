//! HPKE session-establishment layer (RFC 9180, Base mode).
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.
//! Establishes two direction-separated 32-byte application session keys via
//! the HPKE exporter and constructs the existing `SendSession`/`ReceiveSession`
//! pair for each side. All key material is RAM-only and zeroized.

use crate::{ReceiveSession, SendSession, SessionKey, KID_LEN};
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

fn fresh_rng() -> Result<ChaCha20Rng, HpkeSetupError> {
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

/// Handshake wire descriptor: version, suite, recipient public key.
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
        let offer = Self {
            version: HPKE_VERSION,
            suite_id: HPKE_SUITE_ID,
            kid,
            recipient_public_key: HpkePublicKey(public.to_bytes().into()),
        };
        Ok((offer, HpkeRecipientKeyPair { _private: private }))
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

/// RAM-only recipient keypair. Deliberately provides no serialization or
/// byte-level export path; it can only be consumed by receiver setup.
pub struct HpkeRecipientKeyPair {
    _private: <X25519HkdfSha256 as KemTrait>::PrivateKey,
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
    pub send: SendSession,
    pub receive: ReceiveSession,
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
    pub send: SendSession,
    pub receive: ReceiveSession,
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
}

impl ExportedMaterial {
    fn from_ctx(
        export: impl Fn(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>,
    ) -> Result<Self, HpkeSetupError> {
        let mut c2s = Zeroizing::new([0u8; 32]);
        let mut s2c = Zeroizing::new([0u8; 32]);
        export(EXPORTER_C2S, &mut c2s[..]).map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        export(EXPORTER_S2C, &mut s2c[..]).map_err(|_| HpkeSetupError::EstablishmentFailed)?;
        Ok(Self {
            c2s: SessionKey::from_bytes(*c2s),
            s2c: SessionKey::from_bytes(*s2c),
        })
    }
}

use zeroize::{Zeroize, Zeroizing};

/// Initiator side: uses the recipient's public key, encapsulates, exports the
/// two direction keys, and builds direction-correct sessions.
pub fn initiator_establish(
    offer: &HpkeHandshakeOffer,
) -> Result<(HpkeEncapsulatedKey, HpkeInitiatorSession), HpkeSetupError> {
    offer.validate()?;
    let recipient_pk =
        <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&offer.recipient_public_key.0)
            .map_err(|_| HpkeSetupError::MalformedPublicKey)?;

    let mut rng = fresh_rng()?;
    let (encapped, ctx) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &recipient_pk, HANDSHAKE_INFO, &mut rng)
    .map_err(|_| HpkeSetupError::EstablishmentFailed)?;

    let material = ExportedMaterial::from_ctx(|label, out| ctx.export(label, out))?;
    let wire = HpkeEncapsulatedKey(encapped.to_bytes().into());
    Ok((
        wire,
        HpkeInitiatorSession {
            send: SendSession::new(material.c2s)
                .map_err(|_| HpkeSetupError::EstablishmentFailed)?,
            receive: ReceiveSession::new(material.s2c),
        },
    ))
}

/// Responder side: validates the encapsulated key, decapsulates with its own
/// private key, exports the same two direction keys, and builds mirrored
/// sessions.
pub fn responder_establish(
    keypair: &HpkeRecipientKeyPair,
    encapsulated: &HpkeEncapsulatedKey,
) -> Result<HpkeResponderSession, HpkeSetupError> {
    let encapped = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&encapsulated.0)
        .map_err(|_| HpkeSetupError::MalformedEncapsulatedKey)?;

    let ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &keypair._private,
        &encapped,
        HANDSHAKE_INFO,
    )
    .map_err(|_| HpkeSetupError::EstablishmentFailed)?;

    let material = ExportedMaterial::from_ctx(|label, out| ctx.export(label, out))?;
    Ok(HpkeResponderSession {
        send: SendSession::new(material.s2c).map_err(|_| HpkeSetupError::EstablishmentFailed)?,
        receive: ReceiveSession::new(material.c2s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SESSION_KEY_LEN};

    fn establish() -> (HpkeInitiatorSession, HpkeResponderSession, Envelope) {
        let kid = [7u8; KID_LEN];
        let (offer, keypair) = HpkeHandshakeOffer::generate(kid).expect("offer");
        let (encapsulated, initiator) = initiator_establish(&offer).expect("initiator");
        let responder = responder_establish(&keypair, &encapsulated).expect("responder");
        (
            initiator,
            responder,
            Envelope {
                kid,
                nonce: [0u8; crate::NONCE_LEN],
                sequence: 0,
                ciphertext: Vec::new(),
            },
        )
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
        let (mut init, mut resp, _dummy) = establish();

        // c2s: initiator sends, responder receives.
        let c2s_env = init.send.seal([7u8; KID_LEN], 1, b"c2s").expect("c2s seal");
        assert_eq!(resp.receive.receive(&c2s_env).expect("c2s open"), b"c2s");

        // s2c: responder sends, initiator receives.
        let s2c_env = resp.send.seal([7u8; KID_LEN], 1, b"s2c").expect("s2c seal");
        assert_eq!(init.receive.receive(&s2c_env).expect("s2c open"), b"s2c");
    }

    #[test]
    fn opposite_direction_keys_are_separate() {
        let (mut init, mut resp, _dummy) = establish();

        // c2s ciphertext must not open under the initiator's receive key
        // (which holds s2c material) — proving key separation without
        // exposing bytes.
        let c2s_env = init.send.seal([7u8; KID_LEN], 1, b"cross").expect("seal");
        assert!(matches!(
            init.receive.receive(&c2s_env),
            Err(crate::CryptoError::DecryptFailed)
        ));

        // Likewise s2c under the responder's c2s receive key.
        let s2c_env = resp.send.seal([7u8; KID_LEN], 1, b"cross").expect("seal");
        assert!(matches!(
            resp.receive.receive(&s2c_env),
            Err(crate::CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn replay_and_tamper_still_rejected_after_handshake() {
        let (mut init, mut resp, _dummy) = establish();
        let env = init.send.seal([7u8; KID_LEN], 1, b"msg").expect("seal");
        assert_eq!(resp.receive.receive(&env).expect("open"), b"msg");
        assert!(matches!(
            resp.receive.receive(&env),
            Err(crate::CryptoError::ReplayDetected(1))
        ));

        let mut tampered = env.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            resp.receive.receive(&tampered),
            Err(crate::CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn low_order_encapsulated_key_rejected() {
        let (_offer, keypair) = HpkeHandshakeOffer::generate([1u8; KID_LEN]).expect("offer");
        // X25519 deserializes any 32-byte value; the all-zero encapsulated key
        // yields the all-zero DH result, which HPKE rejects during setup.
        let bad = HpkeEncapsulatedKey([0u8; 32]);
        assert!(matches!(
            responder_establish(&keypair, &bad),
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
        let resp = responder_establish(&keypair, &enc).expect("resp");

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
}
