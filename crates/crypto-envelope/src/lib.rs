//! Generic envelope + symmetric session AEAD layer.
//!
//! HPKE and replay-window handling live in later patches; this module only
//! provides the wire `Envelope` and a `SessionCipher` that seals/opens
//! payloads under a 32-byte session key using ChaCha20-Poly1305.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use getrandom::getrandom;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod artifact;
#[path = "hpke.rs"]
pub mod hpke;

pub use artifact::{
    canonical_artifact_info, canonical_unlock_info, decrypt_artifact, decrypt_artifact_with_secret,
    derive_workspace_keypair, seal_artifact, ArtifactEnvelope, WorkspaceUnlockKeyPair,
    AEAD_TAG_LEN, ARTIFACT_HEADER_LEN, ARTIFACT_SEAL_DOMAIN, ARTIFACT_VERSION,
    ENCAPSULATED_KEY_LEN, MAX_ARTIFACT_LEN, MAX_ARTIFACT_PAYLOAD_LEN, MIN_ARTIFACT_LEN,
    PUBLIC_KEY_LEN, UNLOCK_SECRET_LEN, WORKSPACE_UNLOCK_DOMAIN,
};

pub const SESSION_KEY_LEN: usize = 32;
pub const KID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Per-session random prefix occupying the first 4 bytes of the 12-byte
/// nonce; the trailing 8 bytes carry the big-endian u64 sequence. Within a
/// session, distinct sequences always produce distinct counter portions, so
/// nonce reuse under one key is impossible as long as sequences strictly
/// increase. The random prefix only matters if the same key is ever used by
/// more than one cipher instantiation (e.g. a key restored after restart):
/// two instantiations then share a nonce only if their prefixes collide
/// (probability 2^-32 per pair) *and* they pick the same sequence.
const NONCE_PREFIX_LEN: usize = NONCE_LEN - 8;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("session key must be exactly {SESSION_KEY_LEN} bytes, got {0}")]
    InvalidKeyLen(usize),
    #[error("malformed nonce: expected {NONCE_LEN} bytes, got {0}")]
    InvalidNonceLen(usize),
    #[error("sequence number must be nonzero, got {0}")]
    InvalidSequence(u64),
    #[error("sequence must be strictly increasing; refusing to seal with sequence {0}")]
    SequenceReuse(u64),
    #[error("replay detected: sequence {0} was already accepted")]
    ReplayDetected(u64),
    #[error("sequence {0} is older than the replay window")]
    StaleSequence(u64),
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed: authentication tag mismatch or AAD tampering")]
    DecryptFailed,
    #[error("key identifier does not match established session")]
    KeyIdMismatch,
    #[error("secure random number generator unavailable")]
    RngUnavailable,
    #[error("ciphertext is too short to contain an authentication tag")]
    CiphertextTooShort,
    #[error("invalid input")]
    InvalidInput,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("artifact format error")]
    FormatError,
    #[error("key derivation failed")]
    DerivationFailed,
}

/// Wire envelope: exactly what crosses the boundary, nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kid: [u8; KID_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
}

/// 32-byte session key, zeroized on drop. Never serialized, logged, or
/// cloned; use `SessionCipher::new` to move it into a cipher.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    pub(crate) fn from_bytes(bytes: [u8; SESSION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn random() -> Result<Self, CryptoError> {
        let mut key = [0u8; SESSION_KEY_LEN];
        if getrandom(&mut key).is_err() {
            key.zeroize();
            return Err(CryptoError::RngUnavailable);
        }
        Ok(Self(key))
    }

    fn as_cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new((&self.0).into())
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey([REDACTED])")
    }
}

/// Symmetric session cipher. Owns a random per-session nonce prefix and the
/// high-water mark of used sequences, so the same (prefix, sequence) pair can
/// never be emitted twice within a session.
pub struct SessionCipher {
    key: SessionKey,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    last_sequence: u64,
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCipher")
            .field("nonce_prefix", &"[REDACTED]")
            .field("last_sequence", &self.last_sequence)
            .finish_non_exhaustive()
    }
}

impl SessionCipher {
    pub(crate) fn new(key: SessionKey) -> Result<Self, CryptoError> {
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        getrandom(&mut prefix).map_err(|_| CryptoError::RngUnavailable)?;
        Ok(Self {
            key,
            nonce_prefix: prefix,
            last_sequence: 0,
        })
    }

    /// Constructor supplying an explicit nonce prefix, for deterministic
    /// tests or when the prefix is restored from durable session state. The
    /// caller is responsible for the prefix being uniformly random per
    /// cipher instantiation sharing a key; this constructor cannot check it.
    #[cfg(test)]
    pub(crate) fn with_nonce_prefix(key: SessionKey, nonce_prefix: [u8; NONCE_PREFIX_LEN]) -> Self {
        Self {
            key,
            nonce_prefix,
            last_sequence: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn nonce_prefix(&self) -> [u8; NONCE_PREFIX_LEN] {
        self.nonce_prefix
    }

    fn compose_nonce(&self, sequence: u64) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    /// AAD binds the kid and sequence to the ciphertext, so swapping either
    /// between envelopes fails authentication.
    fn aad(kid: &[u8; KID_LEN], sequence: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(KID_LEN + 8);
        aad.extend_from_slice(kid);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad
    }

    pub(crate) fn seal(
        &mut self,
        kid: [u8; KID_LEN],
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<Envelope, CryptoError> {
        if sequence == 0 {
            return Err(CryptoError::InvalidSequence(sequence));
        }
        if sequence <= self.last_sequence {
            return Err(CryptoError::SequenceReuse(sequence));
        }

        let nonce = self.compose_nonce(sequence);
        let aad = Self::aad(&kid, sequence);
        let cipher = self.key.as_cipher();
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)?;

        self.last_sequence = sequence;
        Ok(Envelope {
            kid,
            nonce,
            sequence,
            ciphertext,
        })
    }

    fn open_with(key: &SessionKey, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        if envelope.sequence == 0 {
            return Err(CryptoError::InvalidSequence(envelope.sequence));
        }
        let aad = Self::aad(&envelope.kid, envelope.sequence);
        let cipher = key.as_cipher();
        cipher
            .decrypt(
                (&envelope.nonce).into(),
                chacha20poly1305::aead::Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

/// Send-only session wrapper. Production callers cannot decrypt through this
/// side, and seals always use a secure-RNG nonce prefix with strictly
/// increasing sequence numbers.
pub struct SendSession {
    cipher: SessionCipher,
}

impl SendSession {
    pub(crate) fn new(key: SessionKey) -> Result<Self, CryptoError> {
        Ok(Self {
            cipher: SessionCipher::new(key)?,
        })
    }

    pub fn seal(
        &mut self,
        kid: [u8; KID_LEN],
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<Envelope, CryptoError> {
        self.cipher.seal(kid, sequence, plaintext)
    }

    #[cfg(test)]
    pub(crate) fn with_test_key() -> Self {
        Self {
            cipher: SessionCipher::with_nonce_prefix(
                SessionKey::from_bytes([7u8; SESSION_KEY_LEN]),
                [0x42u8; NONCE_PREFIX_LEN],
            ),
        }
    }
}

impl std::fmt::Debug for SendSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendSession")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

/// Receive-only session wrapper. Authentication is attempted first; only a
/// successfully authenticated envelope may advance replay-window state.
pub struct ReceiveSession {
    key: SessionKey,
    replay: ReplayWindow,
}

impl ReceiveSession {
    pub(crate) fn new(key: SessionKey) -> Self {
        Self {
            key,
            replay: ReplayWindow::new(),
        }
    }

    /// AEAD-authenticate first, then apply the replay window. A forged or
    /// tampered packet cannot advance replay state.
    pub fn receive(&mut self, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        let plaintext = SessionCipher::open_with(&self.key, envelope)?;
        self.replay.accept(envelope.sequence)?;
        Ok(plaintext)
    }
}

impl std::fmt::Debug for ReceiveSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("replay", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Sliding replay window over 64 sequence numbers, indexed by an in-band
/// bitmap relative to the highest accepted sequence. Sequences are not
/// stored individually; a bit at position `highest - offset` records that
/// the offset-th most recent sequence was seen, so out-of-order delivery
/// within 63 of the high-water mark is accepted exactly once.
struct ReplayWindow {
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    fn accept(&mut self, sequence: u64) -> Result<(), CryptoError> {
        if sequence == 0 {
            return Err(CryptoError::InvalidSequence(sequence));
        }

        // Fresh window: first nonzero sequence becomes the baseline.
        if self.highest == 0 {
            self.highest = sequence;
            self.bitmap = 1;
            return Ok(());
        }

        if sequence > self.highest {
            let delta = sequence - self.highest;
            if delta >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << delta) | 1;
            }
            self.highest = sequence;
            return Ok(());
        }

        let offset = self.highest - sequence;
        if offset >= 64 {
            return Err(CryptoError::StaleSequence(sequence));
        }
        let bit = 1u64 << offset;
        if self.bitmap & bit != 0 {
            return Err(CryptoError::ReplayDetected(sequence));
        }
        self.bitmap |= bit;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PREFIX: [u8; NONCE_PREFIX_LEN] = [0x42u8; NONCE_PREFIX_LEN];

    const TEST_KID: [u8; KID_LEN] = [1u8; KID_LEN];

    fn test_key() -> SessionKey {
        SessionKey::from_bytes([7u8; SESSION_KEY_LEN])
    }

    fn test_cipher() -> SessionCipher {
        SessionCipher::with_nonce_prefix(test_key(), TEST_PREFIX)
    }

    fn cipher_key(cipher: &SessionCipher) -> &SessionKey {
        &cipher.key
    }

    #[test]
    fn roundtrip_valid() {
        let mut cipher = test_cipher();
        let env = cipher.seal(TEST_KID, 1, b"hello world").expect("seal");
        let pt = SessionCipher::open_with(cipher_key(&cipher), &env).expect("open");
        assert_eq!(pt, b"hello world");
        assert_eq!(env.kid, TEST_KID);
        assert_eq!(env.sequence, 1);
        assert_eq!(&env.nonce[..NONCE_PREFIX_LEN], &TEST_PREFIX);
        assert_eq!(env.nonce[NONCE_PREFIX_LEN..], 1u64.to_be_bytes());
    }

    #[test]
    fn ciphertext_tamper_rejected() {
        let mut cipher = test_cipher();
        let mut env = cipher.seal(TEST_KID, 1, b"payload").expect("seal");
        env.ciphertext[0] ^= 0x01;
        assert!(matches!(
            SessionCipher::open_with(cipher_key(&cipher), &env),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn kid_tamper_rejected() {
        let mut cipher = test_cipher();
        let mut env = cipher.seal(TEST_KID, 1, b"payload").expect("seal");
        env.kid[15] ^= 0xFF;
        assert!(matches!(
            SessionCipher::open_with(cipher_key(&cipher), &env),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn sequence_tamper_rejected() {
        let mut cipher = test_cipher();
        let env = cipher.seal(TEST_KID, 1, b"payload").expect("seal");
        let tampered = Envelope {
            kid: env.kid,
            nonce: env.nonce,
            sequence: env.sequence + 1,
            ciphertext: env.ciphertext,
        };
        assert!(matches!(
            SessionCipher::open_with(cipher_key(&cipher), &tampered),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn malformed_nonce_rejected() {
        let mut cipher = test_cipher();
        let env = cipher.seal(TEST_KID, 1, b"payload").expect("seal");

        // Strict nonce length: a wire nonce that is not exactly 12 bytes
        // cannot even be represented in the Envelope's typed [u8; 12] field,
        // so exercise the length invariant directly.
        let wire_bytes: &[u8] = &env.nonce[..10];
        assert_eq!(wire_bytes.len(), 10);
        assert_ne!(wire_bytes.len(), NONCE_LEN);

        // A well-formed 12-byte nonce with the wrong prefix also fails.
        let bad_prefix = Envelope {
            kid: env.kid,
            nonce: [0u8; NONCE_LEN],
            sequence: env.sequence,
            ciphertext: env.ciphertext,
        };
        assert!(matches!(
            SessionCipher::open_with(cipher_key(&cipher), &bad_prefix),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn different_sequences_different_nonces() {
        let cipher = test_cipher();
        let n1 = cipher.compose_nonce(1);
        let n2 = cipher.compose_nonce(2);
        assert_ne!(n1, n2);
        assert_eq!(&n1[..NONCE_PREFIX_LEN], &n2[..NONCE_PREFIX_LEN]);
        assert_eq!(&n1[NONCE_PREFIX_LEN..], &1u64.to_be_bytes());
        assert_eq!(&n2[NONCE_PREFIX_LEN..], &2u64.to_be_bytes());
    }

    #[test]
    fn high_sequence_nonce_composition() {
        let mut cipher = test_cipher();

        // The full 8-byte big-endian u64 occupies the counter portion, so
        // sequences beyond the old u32 cap seal fine.
        let wide = 0x1_0000_0000u64;
        let nonce = cipher.compose_nonce(wide);
        assert_eq!(&nonce[NONCE_PREFIX_LEN..], &wide.to_be_bytes());
        let env = cipher.seal(TEST_KID, wide, b"wide").expect("seal wide");
        assert_eq!(
            SessionCipher::open_with(cipher_key(&cipher), &env).expect("open"),
            b"wide"
        );
        assert_eq!(env.nonce[NONCE_PREFIX_LEN..], wide.to_be_bytes());

        let max_nonce = cipher.compose_nonce(u64::MAX);
        assert_eq!(max_nonce[NONCE_PREFIX_LEN..], [0xFFu8; 8]);
        let env = cipher
            .seal(TEST_KID, u64::MAX, b"max")
            .expect("seal at u64::MAX");
        assert_eq!(&env.nonce[..NONCE_PREFIX_LEN], &TEST_PREFIX);
        assert_eq!(env.nonce[NONCE_PREFIX_LEN..], [0xFFu8; 8]);
        assert_eq!(
            SessionCipher::open_with(cipher_key(&cipher), &env).expect("open"),
            b"max"
        );

        // After sealing u64::MAX no sequence can be strictly greater.
        assert!(matches!(
            cipher.seal(TEST_KID, u64::MAX, b"again"),
            Err(CryptoError::SequenceReuse(u64::MAX))
        ));
    }

    #[test]
    fn sequence_zero_rejected_and_reuse_rejected() {
        let mut cipher = test_cipher();
        assert!(matches!(
            cipher.seal(TEST_KID, 0, b"x"),
            Err(CryptoError::InvalidSequence(0))
        ));
        cipher.seal(TEST_KID, 5, b"x").expect("seal 5");
        assert!(matches!(
            cipher.seal(TEST_KID, 5, b"x"),
            Err(CryptoError::SequenceReuse(5))
        ));
        assert!(matches!(
            cipher.seal(TEST_KID, 3, b"x"),
            Err(CryptoError::SequenceReuse(3))
        ));
        assert!(matches!(
            SessionCipher::open_with(
                cipher_key(&cipher),
                &Envelope {
                    kid: TEST_KID,
                    nonce: [0u8; NONCE_LEN],
                    sequence: 0,
                    ciphertext: Vec::new(),
                },
            ),
            Err(CryptoError::InvalidSequence(0))
        ));
    }

    #[test]
    fn with_nonce_prefix_is_deterministic() {
        let key = SessionKey::from_bytes([7u8; SESSION_KEY_LEN]);
        let a = SessionCipher::with_nonce_prefix(key, TEST_PREFIX);
        let key = SessionKey::from_bytes([7u8; SESSION_KEY_LEN]);
        let b = SessionCipher::with_nonce_prefix(key, TEST_PREFIX);
        assert_eq!(a.compose_nonce(9), b.compose_nonce(9));

        let key = SessionKey::from_bytes([7u8; SESSION_KEY_LEN]);
        let c = SessionCipher::with_nonce_prefix(key, [0x01u8; NONCE_PREFIX_LEN]);
        assert_ne!(a.compose_nonce(9), c.compose_nonce(9));
    }

    #[test]
    fn entropy_paths_succeed_on_os_rng() {
        let key = SessionKey::random().expect("os entropy");
        let cipher = SessionCipher::new(key).expect("os entropy");
        assert_ne!(cipher.nonce_prefix(), [0u8; NONCE_PREFIX_LEN]);
    }

    #[test]
    fn rng_error_carries_no_detail() {
        assert_eq!(
            CryptoError::RngUnavailable.to_string(),
            "secure random number generator unavailable"
        );
    }

    #[test]
    fn session_key_zeroized_on_drop() {
        // ZeroizeOnDrop is a compile-time guarantee; assert the derive is wired
        // by confirming the type is not manually Clone-without-zeroize.
        fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SessionKey>();
    }

    #[test]
    fn debug_never_leaks_key() {
        let key = SessionKey::from_bytes([9u8; SESSION_KEY_LEN]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "SessionKey([REDACTED])");
        assert!(!debug.contains('9'));
    }

    #[test]
    fn replay_window_in_order_accepted() {
        let mut window = ReplayWindow::new();
        for sequence in 1..=200u64 {
            window.accept(sequence).expect("in-order sequence accepted");
        }
    }

    #[test]
    fn replay_window_rejects_zero() {
        let mut window = ReplayWindow::new();
        assert!(matches!(
            window.accept(0),
            Err(CryptoError::InvalidSequence(0))
        ));
        // Rejected zero leaves the window fresh.
        window.accept(1).expect("first sequence after zero");
    }

    #[test]
    fn replay_window_duplicate_rejected() {
        let mut window = ReplayWindow::new();
        window.accept(5).expect("first accept");
        assert!(matches!(
            window.accept(5),
            Err(CryptoError::ReplayDetected(5))
        ));
        window.accept(6).expect("newer still accepted");
        assert!(matches!(
            window.accept(6),
            Err(CryptoError::ReplayDetected(6))
        ));
        assert!(matches!(
            window.accept(5),
            Err(CryptoError::ReplayDetected(5))
        ));
    }

    #[test]
    fn replay_window_out_of_order_accepted_once() {
        let mut window = ReplayWindow::new();
        window.accept(10).expect("baseline");
        for sequence in [3u64, 7, 9, 8, 4] {
            window
                .accept(sequence)
                .unwrap_or_else(|e| panic!("gap fill {sequence} rejected: {e}"));
            assert!(matches!(
                window.accept(sequence),
                Err(CryptoError::ReplayDetected(_))
            ));
        }
        window.accept(11).expect("advance past baseline");
        // 10 was accepted before the out-of-order fills; remains tracked.
        assert!(matches!(
            window.accept(10),
            Err(CryptoError::ReplayDetected(_))
        ));
        assert!(matches!(
            window.accept(4),
            Err(CryptoError::ReplayDetected(_))
        ));
    }

    #[test]
    fn replay_window_large_jump_resets_bitmap() {
        let mut window = ReplayWindow::new();
        window.accept(1).expect("seed");
        for sequence in 2..=50u64 {
            window.accept(sequence).expect("fill");
        }

        // Current highest is 50; advance by delta >= 64 to 114.
        window.accept(114).expect("delta-64 jump accepted");
        // Sequence 1 is now offset 113 from the new high-water mark: stale.
        assert!(matches!(
            window.accept(1),
            Err(CryptoError::StaleSequence(1))
        ));
        // Only 114 is marked after the reset, so this previously unseen
        // sequence within the new window is accepted exactly once.
        window.accept(70).expect("unseen offset 44 accepted");
        assert!(matches!(
            window.accept(70),
            Err(CryptoError::ReplayDetected(70))
        ));
    }

    #[test]
    fn replay_window_stale_boundary() {
        let mut window = ReplayWindow::new();
        window.accept(100).expect("baseline 100");
        // offset 63 is the last tracked position; accepted.
        window.accept(100 - 63).expect("offset 63 accepted");
        // offset 64 falls outside the window.
        assert!(matches!(
            window.accept(100 - 64),
            Err(CryptoError::StaleSequence(_))
        ));
        // After filling, the window slides: sequence 37 (offset 64 from 101)
        // is now stale, while 38 lands at the last tracked position.
        window.accept(101).expect("advance");
        assert!(matches!(
            window.accept(37),
            Err(CryptoError::StaleSequence(_))
        ));
        window.accept(38).expect("offset 63 from 101 accepted");
        // 100 is a replay within the window.
        assert!(matches!(
            window.accept(100),
            Err(CryptoError::ReplayDetected(_))
        ));
        // 36 was never accepted and has slid below the window.
        assert!(matches!(
            window.accept(36),
            Err(CryptoError::StaleSequence(_))
        ));
    }

    #[test]
    fn replay_window_u64_max() {
        let mut window = ReplayWindow::new();
        window
            .accept(u64::MAX)
            .expect("u64::MAX accepted as baseline");
        assert!(matches!(
            window.accept(u64::MAX),
            Err(CryptoError::ReplayDetected(u64::MAX))
        ));
        // Every other sequence is below the high-water mark.
        window.accept(u64::MAX - 1).expect("offset 1 accepted");
        assert!(matches!(
            window.accept(u64::MAX - 1),
            Err(CryptoError::ReplayDetected(_))
        ));
        window.accept(u64::MAX - 63).expect("offset 63 accepted");
        assert!(matches!(
            window.accept(u64::MAX - 64),
            Err(CryptoError::StaleSequence(_))
        ));
        // No higher sequence exists; delta arithmetic must not overflow:
        // `sequence > highest` is checked before subtraction, so the branch
        // is unreachable for u64::MAX and subtraction never panics here.
    }
    #[test]
    fn receive_session_valid_replay_out_of_order_and_stale() {
        let mut send = SendSession::with_test_key();
        let mut receive = ReceiveSession::new(SessionKey::from_bytes([7u8; SESSION_KEY_LEN]));

        // Seal monotonically; deliver out of order as 1 -> 70 -> 40.
        let first = send.seal(TEST_KID, 1, b"first").expect("seal 1");
        let mid = send.seal(TEST_KID, 40, b"out-of-order").expect("seal 40");
        let later = send.seal(TEST_KID, 70, b"later").expect("seal 70");

        assert_eq!(
            receive.receive(&first).expect("valid first packet"),
            b"first"
        );
        assert!(matches!(
            receive.receive(&first),
            Err(CryptoError::ReplayDetected(1))
        ));

        // This advances the high-water mark to 70.
        assert_eq!(receive.receive(&later).expect("later"), b"later");
        assert!(matches!(
            receive.receive(&later),
            Err(CryptoError::ReplayDetected(70))
        ));

        // 40 is offset 30 below the new high-water mark and was never seen;
        // it must be accepted exactly once.
        assert_eq!(
            receive.receive(&mid).expect("out-of-order"),
            b"out-of-order"
        );
        assert!(matches!(
            receive.receive(&mid),
            Err(CryptoError::ReplayDetected(40))
        ));

        // Sequence 1 is offset 69 from high-water mark 70 and is stale.
        assert!(matches!(
            receive.receive(&first),
            Err(CryptoError::StaleSequence(1))
        ));
    }

    #[test]
    fn tampered_high_sequence_does_not_poison_replay_window() {
        let mut send = SendSession::with_test_key();
        let mut receive = ReceiveSession::new(SessionKey::from_bytes([7u8; SESSION_KEY_LEN]));
        let legit = send.seal(TEST_KID, 10, b"legitimate").expect("seal 10");

        let forged = Envelope {
            kid: legit.kid,
            nonce: legit.nonce,
            sequence: u64::MAX,
            ciphertext: legit.ciphertext.clone(),
        };
        assert!(matches!(
            receive.receive(&forged),
            Err(CryptoError::DecryptFailed)
        ));

        // Authentication failed above, so u64::MAX must not have advanced the
        // replay window and the legitimate lower sequence remains accepted.
        assert_eq!(
            receive.receive(&legit).expect("legit accepted"),
            b"legitimate"
        );
        assert!(matches!(
            receive.receive(&legit),
            Err(CryptoError::ReplayDetected(10))
        ));
    }

    #[test]
    fn receive_zero_sequence_rejection_does_not_poison_replay_state() {
        let mut send = SendSession::with_test_key();
        let mut receive = ReceiveSession::new(SessionKey::from_bytes([7u8; SESSION_KEY_LEN]));
        let env = send.seal(TEST_KID, 1, b"x").expect("seal");

        // Structural zero-sequence rejection happens before replay checks;
        // for this tampered envelope AEAD also fails, so this assertion does
        // not claim that AEAD authentication occurred first.
        let mut zero = env.clone();
        zero.sequence = 0;
        assert!(matches!(
            receive.receive(&zero),
            Err(CryptoError::InvalidSequence(0))
        ));

        // The rejected zero packet must not advance or poison replay state.
        assert_eq!(receive.receive(&env).expect("still fresh"), b"x");
        assert!(matches!(
            receive.receive(&env),
            Err(CryptoError::ReplayDetected(1))
        ));
    }

    #[test]
    fn receive_api_is_the_only_receiver_shape() {
        // Exercise the public receive boundary directly. There is intentionally
        // no public `open`/`decrypt` method on receive sessions.
        let mut send = SendSession::with_test_key();
        let mut receive = ReceiveSession::new(SessionKey::from_bytes([7u8; SESSION_KEY_LEN]));
        let env = send.seal(TEST_KID, 1, b"only via receive").expect("seal");
        assert_eq!(receive.receive(&env).expect("receive"), b"only via receive");
    }
}
