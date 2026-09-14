//! Integration tests for length-padded encrypted stream frames (P74).
//!
//! Padded frames are produced/consumed only by `seal_padded`/`receive_padded`;
//! the padding lives inside the AEAD plaintext, so the wire ciphertext length
//! reveals only the ladder bucket, never the real payload length.
//!
//! The `crypto-envelope` crate intentionally has no `privacy` dependency, so the
//! bucket ladder is mirrored here as plain numbers; production callers compute
//! `padded_payload_len` with `privacy::PaddingPolicy::pad(real_len + PADDED_LEN_PREFIX)`.

use crypto_envelope::hpke::{
    initiator_establish, responder_establish, HpkeHandshakeOffer, HpkeInitiatorSession,
    HpkeResponderSession,
};
use crypto_envelope::{
    Envelope, StreamFrame, StreamFrameError, StreamFrameKind, AEAD_TAG_LEN, FRAME_HEADER_LEN,
    FRAME_VERSION, MAX_FRAME_PAYLOAD_LEN, MIN_CIPHERTEXT_LEN, PADDED_LEN_PREFIX,
};

const TEST_KID: [u8; 16] = [0x55u8; 16];

/// Mirror of a fixed ascending padding ladder (smallest bucket >= real + prefix).
const LADDER: [usize; 8] = [16, 64, 256, 1024, 4096, 8192, 16384, 65536];

fn setup_test_sessions() -> (HpkeInitiatorSession, HpkeResponderSession) {
    let (offer, keypair) = HpkeHandshakeOffer::generate(TEST_KID).expect("generate offer");
    let (encapped, initiator_session) = initiator_establish(&offer).expect("initiator establish");
    let responder_session =
        responder_establish(&offer, &keypair, &encapped).expect("responder establish");
    (initiator_session, responder_session)
}

/// Smallest ladder bucket that fits `real_len + PADDED_LEN_PREFIX`.
fn bucket_for(real_len: usize) -> usize {
    bucket_options(real_len)[0]
}

/// Two buckets for a real length: the smallest fitting bucket and the next one.
fn bucket_options(real_len: usize) -> [usize; 2] {
    let need = real_len + PADDED_LEN_PREFIX;
    let idx = LADDER
        .iter()
        .position(|bucket| *bucket >= need)
        .expect("real length fits the test ladder");
    let first = LADDER[idx];
    let second = LADDER.get(idx + 1).copied().unwrap_or(first);
    [first, second]
}

fn payload_of_len(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Case 1: round-trip every kind at several real lengths and buckets.
#[test]
fn padded_roundtrip_all_kinds_lengths_and_buckets() {
    let kinds = [
        StreamFrameKind::Snapshot,
        StreamFrameKind::Delta,
        StreamFrameKind::Candle,
        StreamFrameKind::Heartbeat,
        StreamFrameKind::Resync,
        StreamFrameKind::Batch,
    ];
    let lengths = [0usize, 1, 7, 1000, 4096];

    let (mut client, mut server) = setup_test_sessions();
    let mut sequence = 0u64;

    for &kind in &kinds {
        for &len in &lengths {
            let payload = payload_of_len(len);
            for &bucket in &bucket_options(len) {
                sequence += 1;
                let frame = StreamFrame::new(kind, sequence, payload.clone()).expect("frame");
                let envelope = client
                    .seal_padded(sequence, &frame, bucket)
                    .expect("seal padded");
                assert_eq!(
                    envelope.ciphertext.len(),
                    FRAME_HEADER_LEN + bucket + AEAD_TAG_LEN
                );

                let received = server.receive_padded(&envelope).expect("receive padded");
                assert_eq!(received.version(), FRAME_VERSION);
                assert_eq!(received.kind(), kind);
                assert_eq!(received.sequence(), sequence);
                assert_eq!(received.payload(), payload.as_slice());
            }
        }
    }
}

/// Case 2: the wire length is the bucket, and the inner payload is exactly the bucket.
#[test]
fn padded_ciphertext_length_is_bucket_not_real_length() {
    let (mut client, mut server) = setup_test_sessions();

    let real_a = payload_of_len(10);
    let real_b = payload_of_len(40);
    let bucket = 64;

    let frame_a = StreamFrame::new(StreamFrameKind::Heartbeat, 1, real_a.clone()).unwrap();
    let frame_b = StreamFrame::new(StreamFrameKind::Heartbeat, 2, real_b.clone()).unwrap();
    let env_a = client.seal_padded(1, &frame_a, bucket).unwrap();
    let env_b = client.seal_padded(2, &frame_b, bucket).unwrap();

    // Different real lengths, same bucket => equal-length ciphertexts.
    assert_eq!(env_a.ciphertext.len(), env_b.ciphertext.len());
    assert_eq!(
        env_a.ciphertext.len(),
        FRAME_HEADER_LEN + bucket + AEAD_TAG_LEN
    );
    assert_ne!(real_a.len(), real_b.len());

    // The unpadded reader exposes the authenticated inner padded frame: its
    // payload is exactly the bucket, with the length prefix and zero padding.
    let inner = server.receive_frame(&env_a).expect("unpadded read");
    assert_eq!(inner.payload().len(), bucket);
    assert_eq!(&inner.payload()[..PADDED_LEN_PREFIX], &10u32.to_be_bytes());
    assert_eq!(
        &inner.payload()[PADDED_LEN_PREFIX..PADDED_LEN_PREFIX + real_a.len()],
        real_a.as_slice()
    );
    assert!(inner.payload()[PADDED_LEN_PREFIX + real_a.len()..]
        .iter()
        .all(|byte| *byte == 0));

    // The paired reader recovers the other real payload exactly.
    let received = server.receive_padded(&env_b).expect("receive padded");
    assert_eq!(received.payload(), real_b.as_slice());
}

/// Case 3: exact-fit bucket (no padding bytes) is accepted; one byte less fails.
#[test]
fn padded_exact_fit_accepted_one_less_rejected() {
    let (mut client, mut server) = setup_test_sessions();

    let real = payload_of_len(20);
    let frame = StreamFrame::new(StreamFrameKind::Delta, 1, real.clone()).unwrap();
    let exact = real.len() + PADDED_LEN_PREFIX;

    // One less than real + prefix fails closed and leaves the session unchanged.
    assert_eq!(
        client.seal_padded(1, &frame, exact - 1),
        Err(StreamFrameError::PayloadTooLarge)
    );

    // The failed attempt consumed no sequence: sequence 1 seals cleanly now.
    let envelope = client.seal_padded(1, &frame, exact).unwrap();
    assert_eq!(
        envelope.ciphertext.len(),
        FRAME_HEADER_LEN + exact + AEAD_TAG_LEN
    );

    let received = server.receive_padded(&envelope).unwrap();
    assert_eq!(received.payload(), real.as_slice());
}

/// Case 4: a bucket above the effective maximum fails closed without consuming a sequence.
#[test]
fn padded_oversized_bucket_rejected_session_unchanged() {
    let (mut client, mut server) = setup_test_sessions();

    let real = payload_of_len(32);
    let frame = StreamFrame::new(StreamFrameKind::Snapshot, 1, real.clone()).unwrap();

    assert_eq!(
        client.seal_padded(1, &frame, MAX_FRAME_PAYLOAD_LEN + 1),
        Err(StreamFrameError::PayloadTooLarge)
    );

    // Session sequence is unchanged: the same sequence seals successfully after.
    let bucket = bucket_for(real.len());
    let envelope = client
        .seal_padded(1, &frame, bucket)
        .expect("session not poisoned");
    let received = server.receive_padded(&envelope).unwrap();
    assert_eq!(received.payload(), real.as_slice());
}

/// Case 5: tampering or a ciphertext-length change fails and advances no replay state.
#[test]
fn padded_tamper_and_length_change_fail_closed() {
    let (mut client, mut server) = setup_test_sessions();

    let real = payload_of_len(48);
    let frame = StreamFrame::new(StreamFrameKind::Candle, 1, real.clone()).unwrap();
    let envelope = client
        .seal_padded(1, &frame, bucket_for(real.len()))
        .unwrap();

    // Flip a byte of the ciphertext (covers the encrypted length prefix region).
    let mut tampered = envelope.clone();
    tampered.ciphertext[0] ^= 0x01;
    assert_eq!(
        server.receive_padded(&tampered),
        Err(StreamFrameError::DecryptFailed)
    );

    // A ciphertext shorter than the minimum fails the preflight bounds check.
    let mut truncated = envelope.clone();
    truncated.ciphertext.truncate(MIN_CIPHERTEXT_LEN - 1);
    assert_eq!(
        server.receive_padded(&truncated),
        Err(StreamFrameError::CiphertextOutOfBounds)
    );

    // Neither failure advanced the replay window: the genuine envelope still opens.
    let received = server
        .receive_padded(&envelope)
        .expect("genuine still opens");
    assert_eq!(received.payload(), real.as_slice());
}

fn malformed_len_payload() -> Vec<u8> {
    // Claims a 32-byte real payload but only carries 10 trailing bytes.
    let mut payload = 32u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 10]);
    payload
}

fn malformed_nonzero_padding_payload() -> Vec<u8> {
    // real_len = 4, four real bytes, then a nonzero byte inside the padding region.
    let mut payload = 4u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    payload.extend_from_slice(&[0x00, 0x00, 0x01]);
    payload
}

/// Case 6: malformed padded payloads are rejected and advance no replay state.
#[test]
fn padded_malformed_payloads_rejected_without_replay_advance() {
    let (mut client, mut server) = setup_test_sessions();

    // Seal raw, authenticated plaintext carrying a malformed padded payload so
    // that AEAD succeeds and only the padding parse can reject it.
    let mut sequence = 0u64;
    for malformed in [
        malformed_len_payload(),
        malformed_nonzero_padding_payload(),
        vec![0u8; PADDED_LEN_PREFIX - 1],
    ] {
        sequence += 1;
        let frame = StreamFrame::new(StreamFrameKind::Batch, sequence, malformed).unwrap();
        let encoded = frame.encode().unwrap();
        let envelope = client.seal(sequence, &encoded).unwrap();

        assert_eq!(
            server.receive_padded(&envelope),
            Err(StreamFrameError::PaddedFrameMalformed)
        );

        // A subsequent legitimate padded frame at the next sequence still works.
        sequence += 1;
        let good_payload = payload_of_len(12);
        let good =
            StreamFrame::new(StreamFrameKind::Batch, sequence, good_payload.clone()).unwrap();
        let good_env = client
            .seal_padded(sequence, &good, bucket_for(good_payload.len()))
            .unwrap();
        let received = server
            .receive_padded(&good_env)
            .expect("legit after malformed");
        assert_eq!(received.payload(), good_payload.as_slice());
    }
}

/// Case 7: sequence binding, replay rejection, and the documented API pairing.
#[test]
fn padded_sequence_binding_and_pairing() {
    let (mut client, mut server) = setup_test_sessions();

    // 1. Inner frame sequence 4 sealed under envelope sequence 5 is rejected.
    let mismatched = StreamFrame::new(StreamFrameKind::Delta, 4, b"real".to_vec()).unwrap();
    let encoded = mismatched.encode().unwrap();
    let mismatch_env = client.seal(5, &encoded).unwrap();
    assert_eq!(
        server.receive_padded(&mismatch_env),
        Err(StreamFrameError::SequenceMismatch)
    );

    // 2. Replay of an accepted padded envelope is rejected.
    let frame = StreamFrame::new(StreamFrameKind::Resync, 7, payload_of_len(30)).unwrap();
    let envelope = client
        .seal_padded(7, &frame, bucket_for(frame.payload_len()))
        .unwrap();
    assert!(server.receive_padded(&envelope).is_ok());
    assert_eq!(
        server.receive_padded(&envelope),
        Err(StreamFrameError::ReplayDetected)
    );

    // 3. The APIs are paired: the unpadded reader returns the padded inner frame
    //    (whose payload is the bucket), so `receive_padded` is required.
    let (mut client2, mut server2) = setup_test_sessions();
    let real = payload_of_len(24);
    let frame2 = StreamFrame::new(StreamFrameKind::Batch, 1, real.clone()).unwrap();
    let bucket = bucket_for(real.len());
    let env2 = client2.seal_padded(1, &frame2, bucket).unwrap();

    let wrong = server2.receive_frame(&env2).unwrap();
    assert_eq!(wrong.payload().len(), bucket);
    assert_ne!(wrong.payload(), real.as_slice());
    // `receive_frame` already consumed the sequence, so the paired reader now
    // reports a replay rather than silently re-reading.
    assert_eq!(
        server2.receive_padded(&env2),
        Err(StreamFrameError::ReplayDetected)
    );
}

/// Case 8: the existing unpadded seal/receive path is byte-for-byte unchanged.
#[test]
fn unpadded_seal_receive_unchanged() {
    let (mut client, mut server) = setup_test_sessions();

    let payload = payload_of_len(9);
    let frame = StreamFrame::new(StreamFrameKind::Snapshot, 1, payload.clone()).unwrap();
    let envelope = client.seal_frame(&frame).expect("seal unpadded");
    assert_eq!(envelope.sequence, 1);

    let received = server.receive_frame(&envelope).expect("receive unpadded");
    assert_eq!(received.kind(), StreamFrameKind::Snapshot);
    assert_eq!(received.payload(), payload.as_slice());
    assert_eq!(
        envelope.ciphertext.len(),
        FRAME_HEADER_LEN + payload.len() + AEAD_TAG_LEN
    );
}

/// Case 9: the new error variant is redacted in both `Debug` and `Display`.
#[test]
fn padded_frame_malformed_error_is_redacted() {
    let err = StreamFrameError::PaddedFrameMalformed;
    let debug = format!("{err:?}");
    let display = format!("{err}");

    for text in [&debug, &display] {
        assert!(!text.is_empty());
        // No lengths, payload contents, or sentinel secrets may appear.
        assert!(!text.chars().any(|ch| ch.is_ascii_digit()));
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("payload:"));
        assert!(!text.to_lowercase().contains("nonce"));
        assert!(!text.to_lowercase().contains("kid"));
    }

    // A constructed `Envelope` still never leaks key material through the reader.
    let (mut client, mut _server) = setup_test_sessions();
    let frame = StreamFrame::new(StreamFrameKind::Heartbeat, 1, Vec::new()).unwrap();
    let envelope: Envelope = client.seal_padded(1, &frame, PADDED_LEN_PREFIX).unwrap();
    let envelope_debug = format!("{envelope:?}");
    assert!(envelope_debug.contains("[REDACTED]"));
}
