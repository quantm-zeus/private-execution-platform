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

    let mut envelope = client.seal_frame(&frame).unwrap();

    // Tamper ciphertext
    envelope.ciphertext[10] ^= 0x55;
    let err = server.receive_frame(&envelope).unwrap_err();
    assert_eq!(err, StreamFrameError::DecryptFailed);

    let err_display = format!("{err}");
    let err_debug = format!("{err:?}");
    assert!(!err_display.contains("SECRET"));
    assert!(!err_debug.contains("SECRET"));
}
