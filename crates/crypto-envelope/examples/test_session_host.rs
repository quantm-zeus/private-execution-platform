//! Audited test tooling binary for providing an HPKE responder session
//! to test transport envelope delivery in boundary verifier proofs.
//!
//! Ephemeral keypair is held in memory only, never written to disk or exported.

use base64::Engine;
use crypto_envelope::hpke::{HpkeEncapsulatedKey, HpkeHandshakeOffer, HpkeRecipientKeyPair};
use std::io::{BufRead, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let stdin = std::io::stdin();
    let mut current_state: Option<(HpkeHandshakeOffer, HpkeRecipientKeyPair)> = None;

    for line in stdin.lock().lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "OFFER" => {
                let mut kid = [0u8; crypto_envelope::KID_LEN];
                getrandom::getrandom(&mut kid).map_err(|e| format!("getrandom error: {e}"))?;
                if kid.iter().all(|&b| b == 0) {
                    kid[0] = 1;
                }
                let (offer, keypair) = HpkeHandshakeOffer::generate(kid)?;
                println!(
                    "{} {}",
                    b64.encode(offer.kid),
                    b64.encode(offer.recipient_public_key.0)
                );
                std::io::stdout().flush()?;
                current_state = Some((offer, keypair));
            }
            "SEAL" => {
                if parts.len() < 4 {
                    eprintln!("expected: SEAL <encapsulated_key_b64> <input_path> <output_path>");
                    continue;
                }
                let Some((ref offer, ref keypair)) = current_state else {
                    eprintln!("no active offer");
                    continue;
                };

                let enc_bytes = b64.decode(parts[1])?;
                let enc_arr: [u8; crypto_envelope::PUBLIC_KEY_LEN] = enc_bytes
                    .try_into()
                    .map_err(|_| "invalid encapsulated key length")?;
                let enc = HpkeEncapsulatedKey(enc_arr);

                let mut session = crypto_envelope::hpke::responder_establish(offer, keypair, &enc)?;
                let artifact_bytes = std::fs::read(parts[2])?;
                let envelope = session.seal(1, &artifact_bytes)?;

                let mut wire = Vec::with_capacity(16 + 12 + 8 + envelope.ciphertext.len());
                wire.extend_from_slice(&envelope.kid);
                wire.extend_from_slice(&envelope.nonce);
                wire.extend_from_slice(&envelope.sequence.to_be_bytes());
                wire.extend_from_slice(&envelope.ciphertext);

                std::fs::write(parts[3], &wire)?;
                println!("OK");
                std::io::stdout().flush()?;
            }
            "QUIT" => break,
            _ => {
                eprintln!("unknown command: {}", parts[0]);
            }
        }
    }
    Ok(())
}
