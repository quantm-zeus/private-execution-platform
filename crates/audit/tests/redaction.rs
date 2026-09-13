//! Redaction roster: every audit error surface is payload-free.

mod support;

use audit::{AuditError, AuditKeyMaterial, AuditLookup, BlindIndexKey, SigningReference};
use crypto_envelope::SealKey;
use support::{base, execution_id, idempotency_key, intent_id, INTENT};

const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "1000",
    "250",
    "240",
    "USDC",
    "TOKEN",
    "wallet-1",
    "intent-1",
    "idem-1",
    "prepared-1",
    "http",
    "://",
    "grpc",
    "tcp",
    "unix",
    "0x",
];

fn has_hex_run(value: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn assert_redacted(label: &str, value: &str) {
    for forbidden in FORBIDDEN_SUBSTRINGS {
        assert!(
            !value.contains(forbidden),
            "redaction leak in `{label}`: `{value}` contains `{forbidden}`"
        );
    }
    assert!(
        !has_hex_run(value, 8),
        "redaction leak in `{label}`: `{value}` contains a hex run"
    );
}

#[test]
fn every_audit_error_variant_is_redacted() {
    let errors = [
        AuditError::KeyUnavailable,
        AuditError::UnknownKeyId,
        AuditError::KeyIdMismatch,
        AuditError::SealFailed,
        AuditError::OpenFailed,
        AuditError::RecordMalformed,
        AuditError::SequenceNotMonotonic,
        AuditError::SequenceGap,
        AuditError::StorageUnavailable,
        AuditError::StorageConflict,
        AuditError::EventValidationFailed("event validation failed"),
    ];
    for error in errors {
        assert_redacted("AuditError Display", &error.to_string());
        assert_redacted("AuditError Debug", &format!("{error:?}"));
    }
}

#[test]
fn key_material_and_lookup_debug_are_redacted() {
    let reference = SigningReference::new("ref-alpha").expect("reference");
    assert_redacted("SigningReference Debug", &format!("{reference:?}"));

    let blind = BlindIndexKey::from_bytes([0xABu8; 32]);
    assert_redacted("BlindIndexKey Debug", &format!("{blind:?}"));

    let material = AuditKeyMaterial {
        kid: [0x42u8; 16],
        seal: SealKey::from_bytes([0x11u8; 32]),
        blind_index: BlindIndexKey::from_bytes([0x33u8; 32]),
    };
    assert_redacted("AuditKeyMaterial Debug", &format!("{material:?}"));

    let lookup = AuditLookup::Intent {
        chain: base(),
        intent_id: intent_id(INTENT),
    };
    assert_redacted("AuditLookup Debug", &format!("{lookup:?}"));

    let execution = AuditLookup::Execution {
        chain: base(),
        intent_id: intent_id(INTENT),
        execution_id: execution_id("exec-alpha"),
    };
    assert_redacted("AuditLookup Execution Debug", &format!("{execution:?}"));

    let idempotency = AuditLookup::Idempotency {
        chain: base(),
        intent_id: intent_id(INTENT),
        idempotency_key: idempotency_key("idem-alpha"),
    };
    assert_redacted("AuditLookup Idempotency Debug", &format!("{idempotency:?}"));
}
