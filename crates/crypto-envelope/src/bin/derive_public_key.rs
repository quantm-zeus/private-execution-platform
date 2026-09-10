//! CLI binary to derive a workspace public key from an unlock secret.
//!
//! Output is ONLY the 32-byte public key in base64.
//! Private key material is derived in RAM and zeroized on drop.

use base64::Engine;
use crypto_envelope::{derive_workspace_keypair, ARTIFACT_VERSION, KID_LEN, UNLOCK_SECRET_LEN};
use std::env;

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: derive-public-key --unlock-secret-b64 <B64> [--kid-b64 <B64>] [--version <U8>]"
    );
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut unlock_secret_b64: Option<String> = None;
    let mut kid_b64: Option<String> = None;
    let mut version: u8 = ARTIFACT_VERSION;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--unlock-secret-b64" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                unlock_secret_b64 = Some(args[i].clone());
            }
            "--kid-b64" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                kid_b64 = Some(args[i].clone());
            }
            "--version" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                version = args[i].parse::<u8>().unwrap_or_else(|_| {
                    eprintln!("error: invalid version");
                    std::process::exit(1);
                });
            }
            _ => {
                eprintln!("error: unknown argument '{}'", args[i]);
                print_usage_and_exit();
            }
        }
        i += 1;
    }

    if unlock_secret_b64.is_none() {
        if let Ok(val) = env::var("WORKSPACE_UNLOCK_SECRET_B64") {
            unlock_secret_b64 = Some(val);
        }
    }
    if kid_b64.is_none() {
        if let Ok(val) = env::var("WORKSPACE_ARTIFACT_KID_B64") {
            kid_b64 = Some(val);
        }
    }

    let secret_str = unlock_secret_b64.unwrap_or_else(|| {
        eprintln!("error: --unlock-secret-b64 or WORKSPACE_UNLOCK_SECRET_B64 required");
        std::process::exit(1);
    });

    let b64_engine = base64::engine::general_purpose::STANDARD;
    let secret_bytes = b64_engine.decode(secret_str.trim()).unwrap_or_else(|_| {
        eprintln!("error: invalid base64 unlock secret");
        std::process::exit(1);
    });
    if secret_bytes.len() != UNLOCK_SECRET_LEN {
        eprintln!(
            "error: unlock secret must be exactly {} bytes, got {}",
            UNLOCK_SECRET_LEN,
            secret_bytes.len()
        );
        std::process::exit(1);
    }
    let mut secret_arr = [0u8; UNLOCK_SECRET_LEN];
    secret_arr.copy_from_slice(&secret_bytes);

    let kid: [u8; KID_LEN] = if let Some(k) = kid_b64 {
        let kid_bytes = b64_engine.decode(k.trim()).unwrap_or_else(|_| {
            eprintln!("error: invalid base64 kid");
            std::process::exit(1);
        });
        if kid_bytes.len() != KID_LEN {
            eprintln!(
                "error: kid must be exactly {} bytes, got {}",
                KID_LEN,
                kid_bytes.len()
            );
            std::process::exit(1);
        }
        let mut arr = [0u8; KID_LEN];
        arr.copy_from_slice(&kid_bytes);
        arr
    } else {
        [0u8; KID_LEN]
    };

    let keypair = derive_workspace_keypair(&secret_arr, version, &kid).unwrap_or_else(|e| {
        eprintln!("error: workspace key derivation failed: {}", e);
        std::process::exit(1);
    });

    let pk_bytes = keypair.public_key_bytes();
    let pk_b64 = b64_engine.encode(pk_bytes);
    println!("{}", pk_b64);
}
