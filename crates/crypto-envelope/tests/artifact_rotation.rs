//! Integration tests for the P85 artifact-rotation primitive.
//!
//! `rotate_artifact` is a thin re-seal: the old wire is authenticated and
//! decrypted with the old keypair, the recovered plaintext is re-sealed to the
//! new recipient/kid, and ONLY the new wire is returned. Every failure path
//! must be a typed `CryptoError` and must not hand back a rotated wire.

use crypto_envelope::hpke::HpkePublicKey;
use crypto_envelope::{
    decrypt_artifact, derive_workspace_keypair, rotate_artifact, seal_artifact, ArtifactEnvelope,
    CryptoError, WorkspaceUnlockKeyPair, ARTIFACT_HEADER_LEN, ARTIFACT_VERSION, KID_LEN,
    MIN_ARTIFACT_LEN,
};

const OLD_SECRET: [u8; 32] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];
const OLD_KID: [u8; KID_LEN] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const NEW_SECRET: [u8; 32] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
];
const NEW_KID: [u8; KID_LEN] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];
const PAYLOAD: &[u8] = b"P85-rotation-sentinel-payload-c0ffee";

fn old_keypair() -> WorkspaceUnlockKeyPair {
    derive_workspace_keypair(&OLD_SECRET, ARTIFACT_VERSION, &OLD_KID).expect("derive old keypair")
}

fn new_keypair() -> WorkspaceUnlockKeyPair {
    derive_workspace_keypair(&NEW_SECRET, ARTIFACT_VERSION, &NEW_KID).expect("derive new keypair")
}

/// Old keypair plus a valid wire sealed to it under the old kid.
fn sealed_to_old() -> (WorkspaceUnlockKeyPair, Vec<u8>) {
    let old = old_keypair();
    let wire = seal_artifact(&old.public_key(), ARTIFACT_VERSION, &OLD_KID, PAYLOAD)
        .expect("seal to old recipient");
    (old, wire)
}

fn push_err(errors: &mut Vec<CryptoError>, result: Result<Vec<u8>, CryptoError>) {
    if let Err(err) = result {
        errors.push(err);
    }
}

/// True if `text` contains a run of 8+ ASCII hex digits, which would indicate a
/// leaked key/tag/ciphertext fragment.
fn has_long_hex_run(text: &str) -> bool {
    let mut run = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Case 1: round trip, non-vacuity, new-kid binding, and exact payload recovery.
#[test]
fn rotation_roundtrip_rekeys_to_new_recipient() {
    let (old, wire) = sealed_to_old();
    let new = new_keypair();
    let original_wire = wire.clone();

    let rotated =
        rotate_artifact(&old, &new.public_key(), &new.kid(), &wire).expect("rotation succeeds");

    // Non-vacuity: rotation actually re-sealed (fresh HPKE encapsulation), it
    // did not echo the input.
    assert_ne!(
        rotated, wire,
        "rotated wire must differ from the input wire"
    );
    // Same plaintext length => same wire layout/length, different contents.
    assert_eq!(rotated.len(), wire.len());

    // The input wire is untouched (the function takes it by shared reference).
    assert_eq!(wire, original_wire);

    // The rotated envelope carries the new kid at the current version.
    let envelope = ArtifactEnvelope::from_bytes(&rotated).expect("rotated envelope parses");
    assert_eq!(envelope.version, ARTIFACT_VERSION);
    assert_eq!(envelope.kid, NEW_KID);
    assert_ne!(envelope.kid, OLD_KID);

    // The NEW keypair recovers the exact original payload.
    let recovered = decrypt_artifact(&new, &rotated).expect("new keypair decrypts rotated wire");
    assert_eq!(recovered, PAYLOAD);

    // The old keypair can no longer open the re-keyed wire (kid moved).
    assert!(matches!(
        decrypt_artifact(&old, &rotated),
        Err(CryptoError::KeyIdMismatch)
    ));
}

/// Case 2a: wrong old keypair with a different kid -> `KeyIdMismatch`.
#[test]
fn rotation_wrong_old_kid_is_key_id_mismatch() {
    let (_, wire) = sealed_to_old();
    let new = new_keypair();

    // Deliberately derive a keypair under a different kid: the wire's kid can
    // never match it, so the old-side check rejects before any crypto.
    let mut wrong_kid = OLD_KID;
    wrong_kid[0] ^= 0x01;
    let wrong_old = derive_workspace_keypair(&OLD_SECRET, ARTIFACT_VERSION, &wrong_kid)
        .expect("derive wrong-kid keypair");

    let err = rotate_artifact(&wrong_old, &new.public_key(), &new.kid(), &wire)
        .expect_err("wrong kid must fail");
    assert!(matches!(err, CryptoError::KeyIdMismatch));
}

/// Case 2b: same kid but a different key -> `DecryptFailed` (HPKE auth failure).
#[test]
fn rotation_wrong_old_key_same_kid_is_decrypt_failed() {
    let (_, wire) = sealed_to_old();
    let new = new_keypair();

    // Same kid so the kid check passes; the derived key differs, so only HPKE
    // authentication can reject the wire.
    let mut wrong_secret = OLD_SECRET;
    wrong_secret[31] ^= 0xFF;
    let wrong_old = derive_workspace_keypair(&wrong_secret, ARTIFACT_VERSION, &OLD_KID)
        .expect("derive wrong-key keypair");
    assert_eq!(wrong_old.kid(), OLD_KID);
    assert_ne!(
        wrong_old.public_key_bytes(),
        old_keypair().public_key_bytes()
    );

    let err = rotate_artifact(&wrong_old, &new.public_key(), &new.kid(), &wire)
        .expect_err("wrong key must fail");
    assert!(matches!(err, CryptoError::DecryptFailed));
}

/// Case 3: tampering the input fails closed with a typed error and no output.
#[test]
fn rotation_tamper_fails_closed_without_output() {
    let (old, wire) = sealed_to_old();
    let new = new_keypair();

    // Ciphertext (tag) tamper.
    let mut tampered_ct = wire.clone();
    let last = tampered_ct.len() - 1;
    tampered_ct[last] ^= 0x01;
    let err = rotate_artifact(&old, &new.public_key(), &new.kid(), &tampered_ct)
        .expect_err("ciphertext tamper must fail");
    assert!(matches!(err, CryptoError::DecryptFailed));

    // Header encapsulated-key tamper.
    let mut tampered_enc = wire.clone();
    tampered_enc[ARTIFACT_HEADER_LEN - 1] ^= 0x01;
    let err = rotate_artifact(&old, &new.public_key(), &new.kid(), &tampered_enc)
        .expect_err("encapsulated-key tamper must fail");
    assert!(matches!(err, CryptoError::DecryptFailed));

    // Header kid tamper still matches the old keypair's kid? It does not.
    let mut tampered_kid = wire.clone();
    tampered_kid[1] ^= 0x01;
    let err = rotate_artifact(&old, &new.public_key(), &new.kid(), &tampered_kid)
        .expect_err("kid tamper must fail");
    assert!(matches!(err, CryptoError::KeyIdMismatch));

    // The genuine wire is unaffected by the failed attempts.
    let recovered = decrypt_artifact(&old, &wire).expect("genuine wire still opens");
    assert_eq!(recovered, PAYLOAD);
}

/// Case 4: invalid new-side inputs -> `InvalidInput`, never an "as if rotated" wire.
#[test]
fn rotation_invalid_new_side_is_invalid_input() {
    let (old, wire) = sealed_to_old();
    let new = new_keypair();

    // All-zero new kid.
    let err = rotate_artifact(&old, &new.public_key(), &[0u8; KID_LEN], &wire)
        .expect_err("all-zero new kid must fail");
    assert!(matches!(err, CryptoError::InvalidInput));

    // All-zero new recipient public key.
    let err = rotate_artifact(&old, &HpkePublicKey([0u8; 32]), &new.kid(), &wire)
        .expect_err("all-zero new recipient must fail");
    assert!(matches!(err, CryptoError::InvalidInput));

    // The old wire is still intact and openable: no partial rotation escaped.
    assert_eq!(
        decrypt_artifact(&old, &wire).expect("old wire intact"),
        PAYLOAD
    );
}

/// Case 5: version and length bounds fail closed with typed errors.
#[test]
fn rotation_version_and_bounds_fail_closed() {
    let (old, wire) = sealed_to_old();
    let new = new_keypair();

    // Non-v1 version byte.
    let mut bad_version = wire.clone();
    bad_version[0] = ARTIFACT_VERSION.wrapping_add(1);
    let err = rotate_artifact(&old, &new.public_key(), &new.kid(), &bad_version)
        .expect_err("non-v1 version must fail");
    assert!(matches!(err, CryptoError::UnsupportedVersion));

    // Truncated one byte below the minimum artifact length.
    let err = rotate_artifact(
        &old,
        &new.public_key(),
        &new.kid(),
        &wire[..MIN_ARTIFACT_LEN - 1],
    )
    .expect_err("undersized wire must fail");
    assert!(matches!(err, CryptoError::FormatError));

    // Header only (no ciphertext/tag).
    let err = rotate_artifact(
        &old,
        &new.public_key(),
        &new.kid(),
        &wire[..ARTIFACT_HEADER_LEN],
    )
    .expect_err("header-only wire must fail");
    assert!(matches!(err, CryptoError::FormatError));

    // Empty wire.
    let err = rotate_artifact(&old, &new.public_key(), &new.kid(), &[])
        .expect_err("empty wire must fail");
    assert!(matches!(err, CryptoError::FormatError));
}

/// Case 6: every produced error is payload-free and free of key/tag fragments.
#[test]
fn rotation_errors_are_payload_free() {
    let (old, wire) = sealed_to_old();
    let new = new_keypair();
    let mut errors: Vec<CryptoError> = Vec::new();

    // Wrong kid.
    let mut wrong_kid = OLD_KID;
    wrong_kid[0] ^= 0x01;
    let wrong_kid_kp = derive_workspace_keypair(&OLD_SECRET, ARTIFACT_VERSION, &wrong_kid)
        .expect("wrong-kid keypair");
    push_err(
        &mut errors,
        rotate_artifact(&wrong_kid_kp, &new.public_key(), &new.kid(), &wire),
    );

    // Same kid, wrong key.
    let mut wrong_secret = OLD_SECRET;
    wrong_secret[31] ^= 0xFF;
    let wrong_key_kp = derive_workspace_keypair(&wrong_secret, ARTIFACT_VERSION, &OLD_KID)
        .expect("wrong-key keypair");
    push_err(
        &mut errors,
        rotate_artifact(&wrong_key_kp, &new.public_key(), &new.kid(), &wire),
    );

    // Tampered ciphertext.
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    push_err(
        &mut errors,
        rotate_artifact(&old, &new.public_key(), &new.kid(), &tampered),
    );

    // Invalid new side.
    push_err(
        &mut errors,
        rotate_artifact(&old, &new.public_key(), &[0u8; KID_LEN], &wire),
    );
    push_err(
        &mut errors,
        rotate_artifact(&old, &HpkePublicKey([0u8; 32]), &new.kid(), &wire),
    );

    // Bad version.
    let mut bad_version = wire.clone();
    bad_version[0] = ARTIFACT_VERSION.wrapping_add(1);
    push_err(
        &mut errors,
        rotate_artifact(&old, &new.public_key(), &new.kid(), &bad_version),
    );

    assert!(!errors.is_empty(), "failure fixtures must produce errors");

    for err in &errors {
        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(
                !has_long_hex_run(&text),
                "error rendered a hex-like key/tag fragment: {text}"
            );
            assert!(
                !text.contains("P85"),
                "error leaked payload sentinel: {text}"
            );
            assert!(
                !text.contains("sentinel"),
                "error leaked payload sentinel: {text}"
            );
            assert!(
                !text.contains("c0ffee"),
                "error leaked payload bytes: {text}"
            );
        }
    }
}
