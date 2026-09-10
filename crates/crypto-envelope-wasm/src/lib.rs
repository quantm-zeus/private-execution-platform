//! Minimal, audited WASM boundary over `crypto-envelope`.
//!
//! Threat model / contract:
//! - WASM linear memory is NOT an isolation boundary against same-origin JS:
//!   wasm-bindgen exposes the module's memory to the JS environment, so a
//!   compromised same-origin context could inspect it. The boundary that
//!   matters is same-origin enforcement + a strict own-origin CSP at the
//!   browser layer (bootstrap/packaging, not this crate).
//! - What this binding guarantees: NO secret/private/session key material
//!   is exposed through the API surface. JS receives only the derived 32-byte
//!   public key, the 32-byte encapsulated key (public wire material), and the
//!   plaintext bytes returned by an authenticated decrypt. There are no
//!   accessors for raw secrets or private keys, and this crate persists
//!   nothing. Key-bearing types in `crypto-envelope` zeroize where practical.
//! - All failures surface as constant external errors ("invalid input" or
//!   "crypto operation failed") so JS cannot differentiate internals.
//!   Rust error text is never forwarded.
//!
//! This crate contains no ad-hoc crypto logic of its own; everything
//! delegates to the reviewed `crypto-envelope` crate.

use wasm_bindgen::prelude::*;

const CRYPTO_OPERATION_FAILED: &str = "crypto operation failed";
const INVALID_INPUT: &str = "invalid input";

const KID_LEN: usize = crypto_envelope::KID_LEN; // 16
const PK_LEN: usize = crypto_envelope::PUBLIC_KEY_LEN; // 32
const UNLOCK_SECRET_LEN: usize = crypto_envelope::UNLOCK_SECRET_LEN; // 32
const NONCE_LEN: usize = crypto_envelope::NONCE_LEN; // 12
const SEQUENCE_LEN: usize = 8;
const SESSION_ENVELOPE_HEADER_LEN: usize = KID_LEN + NONCE_LEN + SEQUENCE_LEN;

fn crypto_error() -> JsValue {
    JsValue::from_str(CRYPTO_OPERATION_FAILED)
}

fn invalid_input() -> JsValue {
    JsValue::from_str(INVALID_INPUT)
}

/// Server-published HPKE offer, validated strictly at construction.
#[wasm_bindgen]
pub struct WasmOffer {
    kid: [u8; KID_LEN],
    recipient_public_key: [u8; PK_LEN],
}

#[wasm_bindgen]
impl WasmOffer {
    /// `kid`: exactly 16 bytes; `recipient_public_key`: exactly 32 bytes and
    /// not all-zero. Structural violations fail with a generic input error.
    #[wasm_bindgen(constructor)]
    pub fn new(kid: &[u8], recipient_public_key: &[u8]) -> Result<WasmOffer, JsValue> {
        if kid.len() != KID_LEN {
            return Err(invalid_input());
        }
        if recipient_public_key.len() != PK_LEN || recipient_public_key.iter().all(|&b| b == 0) {
            return Err(invalid_input());
        }
        Ok(WasmOffer {
            kid: kid.try_into().expect("length checked"),
            recipient_public_key: recipient_public_key.try_into().expect("length checked"),
        })
    }

    /// The kid as raw bytes (public wire material).
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> Vec<u8> {
        self.kid.to_vec()
    }
}

/// WASM-owned HPKE initiator session for transport. The underlying session keys
/// are held only inside this struct in WASM memory and are never exposed.
#[wasm_bindgen]
pub struct WasmInitiatorSession {
    session: crypto_envelope::hpke::HpkeInitiatorSession,
    encapsulated: crypto_envelope::hpke::HpkeEncapsulatedKey,
}

#[wasm_bindgen]
impl WasmInitiatorSession {
    /// Runs the audited `initiator_establish` against the validated offer.
    #[wasm_bindgen]
    pub fn establish(offer: &WasmOffer) -> Result<WasmInitiatorSession, JsValue> {
        let handshake = crypto_envelope::hpke::HpkeHandshakeOffer {
            version: crypto_envelope::hpke::HPKE_VERSION,
            suite_id: crypto_envelope::hpke::HPKE_SUITE_ID,
            kid: offer.kid,
            recipient_public_key: crypto_envelope::hpke::HpkePublicKey(offer.recipient_public_key),
        };
        let (encapsulated, session) =
            crypto_envelope::hpke::initiator_establish(&handshake).map_err(|_| crypto_error())?;
        Ok(WasmInitiatorSession {
            session,
            encapsulated,
        })
    }

    /// The 32-byte encapsulated key (public wire material) for POSTing to
    /// the server.
    #[wasm_bindgen]
    pub fn encapsulated_key(&self) -> Vec<u8> {
        self.encapsulated.0.to_vec()
    }

    /// Authenticated decrypt of a server->client session envelope:
    /// `kid(16) || nonce(12) || sequence(u64 BE) || ciphertext`.
    #[wasm_bindgen]
    pub fn decrypt(&mut self, envelope_wire: &[u8]) -> Result<Vec<u8>, JsValue> {
        if envelope_wire.len() <= SESSION_ENVELOPE_HEADER_LEN {
            return Err(invalid_input());
        }
        let kid: [u8; KID_LEN] = envelope_wire[..KID_LEN]
            .try_into()
            .map_err(|_| invalid_input())?;
        let nonce: [u8; NONCE_LEN] = envelope_wire[KID_LEN..KID_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| invalid_input())?;
        let sequence_bytes: [u8; SEQUENCE_LEN] = envelope_wire
            [KID_LEN + NONCE_LEN..SESSION_ENVELOPE_HEADER_LEN]
            .try_into()
            .map_err(|_| invalid_input())?;
        let sequence = u64::from_be_bytes(sequence_bytes);
        if sequence == 0 {
            return Err(invalid_input());
        }
        let envelope = crypto_envelope::Envelope {
            kid,
            nonce,
            sequence,
            ciphertext: envelope_wire[SESSION_ENVELOPE_HEADER_LEN..].to_vec(),
        };
        self.session.receive(&envelope).map_err(|_| crypto_error())
    }
}

/// WASM-held workspace key derived deterministically from an exact 32-byte
/// unlock secret + canonical kid/version context.
///
/// Private key material lives ONLY in WASM memory, is zeroized on drop,
/// and has no accessor. ONLY the public key is exportable.
#[wasm_bindgen]
pub struct WasmWorkspaceKey {
    keypair: crypto_envelope::WorkspaceUnlockKeyPair,
}

#[wasm_bindgen]
impl WasmWorkspaceKey {
    /// Deterministically derives the workspace keypair.
    ///
    /// Requirements:
    /// - `unlock_secret`: exactly 32 bytes and not all-zero.
    /// - `version`: exactly protocol version 1.
    /// - `kid`: exactly 16 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(unlock_secret: &[u8], version: u8, kid: &[u8]) -> Result<WasmWorkspaceKey, JsValue> {
        if unlock_secret.len() != UNLOCK_SECRET_LEN || unlock_secret.iter().all(|&b| b == 0) {
            return Err(invalid_input());
        }
        if kid.len() != KID_LEN || kid.iter().all(|&b| b == 0) {
            return Err(invalid_input());
        }
        if version != crypto_envelope::ARTIFACT_VERSION {
            return Err(invalid_input());
        }

        let secret_arr: &[u8; UNLOCK_SECRET_LEN] =
            unlock_secret.try_into().map_err(|_| invalid_input())?;
        let kid_arr: &[u8; KID_LEN] = kid.try_into().map_err(|_| invalid_input())?;

        let keypair = crypto_envelope::derive_workspace_keypair(secret_arr, version, kid_arr)
            .map_err(|_| crypto_error())?;

        Ok(WasmWorkspaceKey { keypair })
    }

    /// The derived 32-byte X25519 public key (safe to export to server/build pipeline).
    #[wasm_bindgen]
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key_bytes().to_vec()
    }

    /// The key identifier (kid) associated with this workspace key.
    #[wasm_bindgen]
    pub fn kid(&self) -> Vec<u8> {
        self.keypair.kid().to_vec()
    }

    /// The protocol version of this workspace key.
    #[wasm_bindgen]
    pub fn version(&self) -> u8 {
        self.keypair.version()
    }

    /// Authenticated decrypt of a sealed workspace artifact envelope:
    /// `version(1) || kid(16) || encapsulated_key(32) || ciphertext`.
    ///
    /// Fails closed on wrong secret, wrong kid, wrong version, tampering,
    /// or truncation with generic error. Returns plaintext bytes.
    #[wasm_bindgen]
    pub fn decrypt_artifact(&self, artifact_wire: &[u8]) -> Result<Vec<u8>, JsValue> {
        crypto_envelope::decrypt_artifact(&self.keypair, artifact_wire).map_err(|_| crypto_error())
    }
}

/// Standalone convenience function to derive workspace public key from unlock secret.
/// Returns ONLY the 32-byte public key. Private key is zeroized and discarded.
#[wasm_bindgen]
pub fn derive_workspace_public_key(
    unlock_secret: &[u8],
    version: u8,
    kid: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let key = WasmWorkspaceKey::new(unlock_secret, version, kid)?;
    Ok(key.public_key())
}

/// Standalone convenience function to decrypt a workspace artifact using unlock secret.
/// Derives key in RAM, decrypts, and zeroizes key material.
#[wasm_bindgen]
pub fn decrypt_workspace_artifact(
    unlock_secret: &[u8],
    version: u8,
    kid: &[u8],
    artifact_wire: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let key = WasmWorkspaceKey::new(unlock_secret, version, kid)?;
    key.decrypt_artifact(artifact_wire)
}

/// Test-only helper to seal a payload to a recipient public key using audited Rust HPKE crypto.
/// Retained strictly for native/private testing; NOT exported across the WASM-JS boundary.
#[cfg(test)]
fn seal_workspace_artifact(
    recipient_public_key: &[u8],
    version: u8,
    kid: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if recipient_public_key.len() != PK_LEN || recipient_public_key.iter().all(|&b| b == 0) {
        return Err(invalid_input());
    }
    if kid.len() != KID_LEN || kid.iter().all(|&b| b == 0) {
        return Err(invalid_input());
    }
    if version != crypto_envelope::ARTIFACT_VERSION {
        return Err(invalid_input());
    }
    if payload.is_empty() {
        return Err(invalid_input());
    }

    let pk_arr: [u8; PK_LEN] = recipient_public_key
        .try_into()
        .map_err(|_| invalid_input())?;
    let kid_arr: [u8; KID_LEN] = kid.try_into().map_err(|_| invalid_input())?;

    let hpke_pk = crypto_envelope::hpke::HpkePublicKey(pk_arr);
    crypto_envelope::seal_artifact(&hpke_pk, version, &kid_arr, payload).map_err(|_| crypto_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const TEST_SECRET: [u8; 32] = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61,
    ];
    const TEST_KID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const EXPECTED_PUBLIC_KEY: [u8; 32] = [
        0xfc, 0x41, 0xce, 0x56, 0x69, 0xad, 0x52, 0xcf, 0xb3, 0xa5, 0x3a, 0x58, 0x1e, 0x35, 0xbd,
        0x5e, 0xe7, 0x09, 0x01, 0x15, 0xcd, 0xa8, 0x03, 0x26, 0x35, 0xc6, 0x46, 0xad, 0x2c, 0xc9,
        0xe0, 0x34,
    ];
    const TEST_VERSION: u8 = 1;

    #[wasm_bindgen_test]
    fn deterministic_derivation_known_vector() {
        let key1 = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).expect("key 1");
        let key2 = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).expect("key 2");
        assert_eq!(key1.public_key(), key2.public_key());
        assert_eq!(key1.public_key().as_slice(), &EXPECTED_PUBLIC_KEY);

        let pk_direct =
            derive_workspace_public_key(&TEST_SECRET, TEST_VERSION, &TEST_KID).expect("direct");
        assert_eq!(pk_direct.as_slice(), &EXPECTED_PUBLIC_KEY);
    }

    #[wasm_bindgen_test]
    fn domain_separation_changed_secret_kid_version() {
        let base_key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).unwrap();
        let base_pk = base_key.public_key();

        // 1-bit changed secret
        let mut diff_secret = TEST_SECRET;
        diff_secret[0] ^= 1;
        let diff_key = WasmWorkspaceKey::new(&diff_secret, TEST_VERSION, &TEST_KID).unwrap();
        assert_ne!(base_pk, diff_key.public_key());

        // 1-byte changed kid
        let mut diff_kid = TEST_KID;
        diff_kid[0] ^= 1;
        let diff_kid_key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &diff_kid).unwrap();
        assert_ne!(base_pk, diff_kid_key.public_key());

        // Changed version rejects
        assert!(WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION + 1, &TEST_KID).is_err());
    }

    #[wasm_bindgen_test]
    fn seal_and_decrypt_roundtrip_wasm_boundary() {
        let key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).unwrap();
        let pk = key.public_key();

        let payload = b"{\"message\":\"authenticated workspace artifact payload\"}";
        let sealed =
            seal_workspace_artifact(&pk, TEST_VERSION, &TEST_KID, payload).expect("seal succeeds");

        // Decrypt via instance method
        let decrypted = key.decrypt_artifact(&sealed).expect("decrypt succeeds");
        assert_eq!(decrypted, payload);

        // Decrypt via standalone function
        let decrypted_direct =
            decrypt_workspace_artifact(&TEST_SECRET, TEST_VERSION, &TEST_KID, &sealed)
                .expect("direct decrypt succeeds");
        assert_eq!(decrypted_direct, payload);
    }

    #[wasm_bindgen_test]
    fn wrong_secret_fails_closed() {
        let key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).unwrap();
        let sealed =
            seal_workspace_artifact(&key.public_key(), TEST_VERSION, &TEST_KID, b"payload")
                .unwrap();

        let mut wrong_secret = TEST_SECRET;
        wrong_secret[31] ^= 0xaa;
        let wrong_key = WasmWorkspaceKey::new(&wrong_secret, TEST_VERSION, &TEST_KID).unwrap();

        assert!(wrong_key.decrypt_artifact(&sealed).is_err());
        assert!(
            decrypt_workspace_artifact(&wrong_secret, TEST_VERSION, &TEST_KID, &sealed).is_err()
        );
    }

    #[wasm_bindgen_test]
    fn wrong_kid_and_version_fail_closed() {
        let key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).unwrap();
        let sealed =
            seal_workspace_artifact(&key.public_key(), TEST_VERSION, &TEST_KID, b"payload")
                .unwrap();

        let mut wrong_kid = TEST_KID;
        wrong_kid[15] ^= 0x01;
        let wrong_key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &wrong_kid).unwrap();
        assert!(wrong_key.decrypt_artifact(&sealed).is_err());

        // Tamper version in wire
        let mut tampered_ver = sealed.clone();
        tampered_ver[0] = 0x02;
        assert!(key.decrypt_artifact(&tampered_ver).is_err());

        // Tamper kid in wire
        let mut tampered_kid = sealed.clone();
        tampered_kid[1] ^= 0x01;
        assert!(key.decrypt_artifact(&tampered_kid).is_err());
    }

    #[wasm_bindgen_test]
    fn tampered_ciphertext_and_tag_fail_closed() {
        let key = WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &TEST_KID).unwrap();
        let sealed =
            seal_workspace_artifact(&key.public_key(), TEST_VERSION, &TEST_KID, b"payload")
                .unwrap();

        // Tamper ciphertext
        let mut tampered_ct = sealed.clone();
        let len = tampered_ct.len();
        tampered_ct[len - 1] ^= 0x01;
        assert!(key.decrypt_artifact(&tampered_ct).is_err());

        // Tamper encapsulated key in header
        let mut tampered_enc = sealed.clone();
        tampered_enc[17] ^= 0x01;
        assert!(key.decrypt_artifact(&tampered_enc).is_err());

        // Truncation
        assert!(key.decrypt_artifact(&sealed[..48]).is_err());
        assert!(key.decrypt_artifact(&[]).is_err());
    }

    #[wasm_bindgen_test]
    fn transport_session_roundtrip_and_tamper() {
        let kid = [7u8; KID_LEN];
        let (offer, keypair) =
            crypto_envelope::hpke::HpkeHandshakeOffer::generate(kid).expect("offer");
        let wasm_offer =
            WasmOffer::new(&offer.kid, &offer.recipient_public_key.0).expect("valid offer");
        let mut initiator = WasmInitiatorSession::establish(&wasm_offer).expect("establish");
        let encapsulated = crypto_envelope::hpke::HpkeEncapsulatedKey(
            initiator.encapsulated_key().try_into().expect("32 bytes"),
        );
        let mut responder =
            crypto_envelope::hpke::responder_establish(&offer, &keypair, &encapsulated)
                .expect("responder");

        let env = responder.seal(1, b"session payload").expect("seal");
        let mut wire = Vec::new();
        wire.extend_from_slice(&env.kid);
        wire.extend_from_slice(&env.nonce);
        wire.extend_from_slice(&env.sequence.to_be_bytes());
        wire.extend_from_slice(&env.ciphertext);

        let decrypted = initiator.decrypt(&wire).expect("decrypt session");
        assert_eq!(decrypted, b"session payload");

        // Replay fails
        assert!(initiator.decrypt(&wire).is_err());

        // Tamper fails
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(initiator.decrypt(&tampered).is_err());
    }

    #[wasm_bindgen_test]
    fn all_zero_kid_rejected() {
        let zero_kid = [0u8; 16];
        assert!(WasmWorkspaceKey::new(&TEST_SECRET, TEST_VERSION, &zero_kid).is_err());
        assert!(derive_workspace_public_key(&TEST_SECRET, TEST_VERSION, &zero_kid).is_err());
        assert!(
            decrypt_workspace_artifact(&TEST_SECRET, TEST_VERSION, &zero_kid, &[0u8; 65]).is_err()
        );
    }
}
