//! Integration tests for bounded opaque stream frame codec and session boundaries.
//!
//! Verifies:
//! - Seal and receive roundtrip across all frame kinds
//! - Envelope and frame sequence binding (rejection of mismatches and zero)
//! - Version, kind, length, and payload bounds rejection fail-closed
//! - Ciphertext tampering, tag mismatch, and replay/stale sequence rejection
//! - State immutability under failure (no partial state, replay/session not poisoned)
//! - Redacted debug formats and content-free error invariants

use crypto_envelope::hpke::{
    initiator_establish, responder_establish, HpkeHandshakeOffer, HpkeInitiatorSession,
    HpkeResponderSession,
};
use crypto_envelope::{
    Envelope, StreamFrame, StreamFrameCodec, StreamFrameError, StreamFrameKind, FRAME_HEADER_LEN,
    FRAME_VERSION,
};

const TEST_KID: [u8; 16] = [0x55u8; 16];

fn setup_test_sessions() -> (HpkeInitiatorSession, HpkeResponderSession) {
    let (offer, keypair) = HpkeHandshakeOffer::generate(TEST_KID).expect("generate offer");
    let (encapped, initiator_session) = initiator_establish(&offer).expect("initiator establish");
    let responder_session =
        responder_establish(&offer, &keypair, &encapped).expect("responder establish");
    (initiator_session, responder_session)
}

#[test]
fn integration_seal_receive_roundtrip_all_kinds() {
    let (mut client, mut server) = setup_test_sessions();

    let test_cases = [
        (
            StreamFrameKind::Snapshot,
            1u64,
            b"depth-snapshot-bytes".to_vec(),
        ),
        (StreamFrameKind::Delta, 2u64, b"depth-delta-bytes".to_vec()),
        (StreamFrameKind::Candle, 3u64, b"candle-bytes".to_vec()),
        (StreamFrameKind::Heartbeat, 4u64, Vec::new()), // empty payload
        (StreamFrameKind::Resync, 5u64, b"resync-marker".to_vec()),
        (
            StreamFrameKind::Batch,
            6u64,
            b"consumer-batch-payload".to_vec(),
        ),
    ];

    for (kind, sequence, payload) in test_cases {
        let frame = StreamFrame::new(kind, sequence, payload.clone()).expect("valid frame");
        assert_eq!(frame.version(), FRAME_VERSION);
        assert_eq!(frame.kind(), kind);
        assert_eq!(frame.sequence(), sequence);
        assert_eq!(frame.payload(), payload.as_slice());

        let envelope = client.seal_frame(&frame).expect("seal frame");
        assert_eq!(envelope.kid, TEST_KID);
        assert_eq!(envelope.sequence, sequence);

        let received = server.receive_frame(&envelope).expect("receive frame");
        assert_eq!(received.version(), FRAME_VERSION);
        assert_eq!(received.kind(), kind);
        assert_eq!(received.sequence(), sequence);
        assert_eq!(received.into_payload(), payload);
    }
}

#[test]
fn integration_envelope_frame_sequence_binding() {
    let (mut client, mut server) = setup_test_sessions();

    let frame = StreamFrame::new(StreamFrameKind::Snapshot, 10, b"seq10".to_vec()).unwrap();
    let envelope = client.seal_frame(&frame).unwrap();

    // 1. Envelope sequence tampering fails AEAD authentication
    let mut tampered_env = envelope.clone();
    tampered_env.sequence = 11;
    assert_eq!(
        server.receive_frame(&tampered_env),
        Err(StreamFrameError::DecryptFailed)
    );

    // 2. Legitimate envelope is still accepted (state not poisoned)
    let legit = server.receive_frame(&envelope).unwrap();
    assert_eq!(legit.sequence(), 10);

    // 3. Replay of accepted envelope is rejected
    assert_eq!(
        server.receive_frame(&envelope),
        Err(StreamFrameError::ReplayDetected)
    );
}

#[test]
fn integration_zero_sequence_rejected_fail_closed() {
    assert_eq!(
        StreamFrame::new(StreamFrameKind::Snapshot, 0, b"data".to_vec()),
        Err(StreamFrameError::ZeroSequence)
    );

    let (_client, mut server) = setup_test_sessions();
    let zero_env = Envelope {
        kid: TEST_KID,
        nonce: [0u8; 12],
        sequence: 0,
        ciphertext: vec![0u8; 32],
    };
    assert_eq!(
        server.receive_frame(&zero_env),
        Err(StreamFrameError::ZeroSequence)
    );
}

#[test]
fn integration_version_and_kind_bounds_fail_closed() {
    let codec = StreamFrameCodec::new();

    // 1. Unsupported version
    assert_eq!(
        StreamFrame::with_version(0, StreamFrameKind::Snapshot, 1, b"x".to_vec()),
        Err(StreamFrameError::UnsupportedVersion)
    );
    assert_eq!(
        StreamFrame::with_version(2, StreamFrameKind::Snapshot, 1, b"x".to_vec()),
        Err(StreamFrameError::UnsupportedVersion)
    );

    // 2. Unsupported kind
    assert_eq!(
        StreamFrameKind::from_u8(0),
        Err(StreamFrameError::UnsupportedKind)
    );
    assert_eq!(
        StreamFrameKind::from_u8(7),
        Err(StreamFrameError::UnsupportedKind)
    );

    // 3. Truncated wire frame
    let truncated = vec![0u8; FRAME_HEADER_LEN - 1];
    assert_eq!(
        codec.decode_frame(&truncated),
        Err(StreamFrameError::MalformedFrame)
    );

    // 4. Length mismatch: header claims 100 bytes, wire provides 4
    let malformed = vec![
        FRAME_VERSION,
        StreamFrameKind::Snapshot.as_u8(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1, // sequence = 1
        0,
        0,
        0,
        100, // payload_len = 100
        0xAA,
        0xBB,
        0xCC,
        0xDD, // 4 bytes of payload
    ];
    assert_eq!(
        codec.decode_frame(&malformed),
        Err(StreamFrameError::PayloadLengthMismatch)
    );
}

#[test]
fn integration_custom_bound_codec() {
    let strict_codec = StreamFrameCodec::with_max_payload_len(8);

    let small_frame = StreamFrame::new(StreamFrameKind::Heartbeat, 1, vec![0u8; 8]).unwrap();
    let encoded = strict_codec
        .encode_frame(&small_frame)
        .expect("within bound");
    let decoded = strict_codec.decode_frame(&encoded).expect("decoded");
    assert_eq!(decoded.payload().len(), 8);

    let over_frame = StreamFrame::new(StreamFrameKind::Heartbeat, 2, vec![0u8; 9]).unwrap();
    assert_eq!(
        strict_codec.encode_frame(&over_frame),
        Err(StreamFrameError::PayloadTooLarge)
    );
}

#[test]
fn integration_tamper_and_content_free_redaction() {
    let (mut client, mut server) = setup_test_sessions();

    let secret = b"TOP-SECRET-MARKET-ALPHA-DATA";
    let frame = StreamFrame::new(StreamFrameKind::Candle, 1, secret.to_vec()).unwrap();

    // Check debug redaction
    let debug_str = format!("{frame:?}");
    assert!(debug_str.contains("[REDACTED]"));
    assert!(!debug_str.contains("TOP-SECRET"));
    // Frame kind must also be redacted in Debug
    assert!(!debug_str.contains("Candle"));
    assert!(!debug_str.contains("candle"));

    let mut envelope = client.seal_frame(&frame).unwrap();

    // Verify Envelope Debug redaction
    let env_debug = format!("{envelope:?}");
    assert!(env_debug.contains("[REDACTED]"));
    assert!(env_debug.contains("sequence: 1"));
    assert!(env_debug.contains("ciphertext_len:"));
    assert!(!env_debug.contains("85")); // TEST_KID 0x55 = 85

    // Tamper ciphertext
    envelope.ciphertext[10] ^= 0x55;
    let err = server.receive_frame(&envelope).unwrap_err();
    assert_eq!(err, StreamFrameError::DecryptFailed);

    let err_display = format!("{err}");
    let err_debug = format!("{err:?}");
    assert!(!err_display.contains("SECRET"));
    assert!(!err_debug.contains("SECRET"));
    assert!(!err_display.contains("nonce"));
    assert!(!err_display.contains("kid"));
}

#[test]
fn integration_oversized_codec_limit_clamped_and_hard_cap_enforced() {
    // 1. Caller passing limit > 1 MiB is clamped to MAX_FRAME_PAYLOAD_LEN
    let oversized_codec =
        StreamFrameCodec::with_max_payload_len(crypto_envelope::MAX_FRAME_PAYLOAD_LEN * 4);
    assert_eq!(
        oversized_codec.max_payload_len(),
        crypto_envelope::MAX_FRAME_PAYLOAD_LEN
    );

    let extreme_codec = StreamFrameCodec::with_max_payload_len(usize::MAX);
    assert_eq!(
        extreme_codec.max_payload_len(),
        crypto_envelope::MAX_FRAME_PAYLOAD_LEN
    );

    // 2. Direct construction of oversized frame fails
    let oversized_bytes = vec![0u8; crypto_envelope::MAX_FRAME_PAYLOAD_LEN + 1];
    assert_eq!(
        StreamFrame::new(StreamFrameKind::Snapshot, 1, oversized_bytes.clone()),
        Err(StreamFrameError::PayloadTooLarge)
    );
    assert_eq!(
        StreamFrame::with_version(FRAME_VERSION, StreamFrameKind::Snapshot, 1, oversized_bytes),
        Err(StreamFrameError::PayloadTooLarge)
    );

    // 3. Receive rejects ciphertext exceeding MAX_CIPHERTEXT_LEN before decryption
    let (_client, mut server) = setup_test_sessions();
    let oversized_env = Envelope {
        kid: TEST_KID,
        nonce: [0u8; 12],
        sequence: 1,
        ciphertext: vec![0u8; crypto_envelope::MAX_CIPHERTEXT_LEN + 1],
    };
    assert_eq!(
        server.receive_frame(&oversized_env),
        Err(StreamFrameError::CiphertextOutOfBounds)
    );
}

#[test]
fn integration_direct_construction_prevention_and_invariant_enforcement() {
    // 1. Zero sequence rejected
    assert_eq!(
        StreamFrame::new(StreamFrameKind::Delta, 0, vec![1, 2, 3]),
        Err(StreamFrameError::ZeroSequence)
    );

    // 2. Unsupported version rejected
    assert_eq!(
        StreamFrame::with_version(0, StreamFrameKind::Delta, 1, vec![1, 2, 3]),
        Err(StreamFrameError::UnsupportedVersion)
    );
    assert_eq!(
        StreamFrame::with_version(2, StreamFrameKind::Delta, 1, vec![1, 2, 3]),
        Err(StreamFrameError::UnsupportedVersion)
    );

    // 3. Safe accessors work properly
    let frame = StreamFrame::new(StreamFrameKind::Heartbeat, 99, vec![0xAA; 16]).unwrap();
    assert_eq!(frame.version(), FRAME_VERSION);
    assert_eq!(frame.kind(), StreamFrameKind::Heartbeat);
    assert_eq!(frame.sequence(), 99);
    assert_eq!(frame.payload_len(), 16);
    assert_eq!(frame.payload(), &[0xAA; 16]);
    assert_eq!(frame.into_payload(), vec![0xAA; 16]);
}

#[test]
fn integration_ciphertext_bounds_on_receive_preflight() {
    let (mut client, mut server) = setup_test_sessions();

    // 1. Ciphertext too short (< MIN_CIPHERTEXT_LEN = 30)
    for len in [0, 1, 14, 29] {
        let short_env = Envelope {
            kid: TEST_KID,
            nonce: [0u8; 12],
            sequence: 1,
            ciphertext: vec![0u8; len],
        };
        assert_eq!(
            server.receive_frame(&short_env),
            Err(StreamFrameError::CiphertextOutOfBounds)
        );
    }

    // 2. Ciphertext too long (> MAX_CIPHERTEXT_LEN)
    let long_env = Envelope {
        kid: TEST_KID,
        nonce: [0u8; 12],
        sequence: 1,
        ciphertext: vec![0u8; crypto_envelope::MAX_CIPHERTEXT_LEN + 1],
    };
    assert_eq!(
        server.receive_frame(&long_env),
        Err(StreamFrameError::CiphertextOutOfBounds)
    );

    // 3. Legitimate frame still accepted (state not poisoned)
    let legit_frame = StreamFrame::new(StreamFrameKind::Heartbeat, 1, Vec::new()).unwrap();
    let legit_env = client.seal_frame(&legit_frame).unwrap();
    let received = server.receive_frame(&legit_env).unwrap();
    assert_eq!(received.sequence(), 1);
}

#[test]
fn integration_debug_redaction_across_all_kinds() {
    let kinds = [
        (StreamFrameKind::Snapshot, "Snapshot"),
        (StreamFrameKind::Delta, "Delta"),
        (StreamFrameKind::Candle, "Candle"),
        (StreamFrameKind::Heartbeat, "Heartbeat"),
        (StreamFrameKind::Resync, "Resync"),
        (StreamFrameKind::Batch, "Batch"),
    ];

    for (kind, name) in kinds {
        let frame = StreamFrame::new(kind, 7, b"secret-payload".to_vec()).unwrap();
        let debug = format!("{frame:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("sequence: 7"));
        assert!(debug.contains("payload_len: 14"));
        assert!(!debug.contains("secret-payload"));
        // Redaction must hide kind name and enum variant
        assert!(!debug.contains(name));
    }
}

#[test]
fn integration_state_immutability_on_failure() {
    let (mut client, mut server) = setup_test_sessions();

    // 1. Seal legitimate frame 5
    let f5 = StreamFrame::new(StreamFrameKind::Snapshot, 5, b"f5".to_vec()).unwrap();
    let env5 = client.seal_frame(&f5).unwrap();

    // 2. Sequence reuse on sender rejected, sender last_sequence unchanged
    let f5_dup = StreamFrame::new(StreamFrameKind::Snapshot, 5, b"dup".to_vec()).unwrap();
    assert_eq!(
        client.seal_frame(&f5_dup),
        Err(StreamFrameError::SequenceReuse)
    );

    let f3_stale = StreamFrame::new(StreamFrameKind::Snapshot, 3, b"stale".to_vec()).unwrap();
    assert_eq!(
        client.seal_frame(&f3_stale),
        Err(StreamFrameError::SequenceReuse)
    );

    // 3. Server receives env5
    assert!(server.receive_frame(&env5).is_ok());

    // 4. Replaying env5 rejected
    assert_eq!(
        server.receive_frame(&env5),
        Err(StreamFrameError::ReplayDetected)
    );

    // 5. Tampered ciphertext rejected without poisoning
    let mut tampered = env5.clone();
    tampered.ciphertext[5] ^= 0xFF;
    assert_eq!(
        server.receive_frame(&tampered),
        Err(StreamFrameError::DecryptFailed)
    );

    // 6. Normal delivery of sequence 6 works fine
    let f6 = StreamFrame::new(StreamFrameKind::Heartbeat, 6, Vec::new()).unwrap();
    let env6 = client.seal_frame(&f6).unwrap();
    assert!(server.receive_frame(&env6).is_ok());
}
