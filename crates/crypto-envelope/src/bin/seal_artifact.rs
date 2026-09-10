//! Audited CLI binary for sealing a workspace artifact payload to a recipient public key.
//!
//! Input MUST be a canonical 32-byte WORKSPACE PUBLIC KEY.
//! No secret/private/content keys are ever accepted or held.
//! Ephemeral symmetric material is zeroized and discarded.

use base64::Engine;
use crypto_envelope::{
    hpke::HpkePublicKey, seal_artifact, ARTIFACT_VERSION, KID_LEN, PUBLIC_KEY_LEN,
};
use std::env;
use std::fs;
use std::path::PathBuf;

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: seal-artifact --public-key-b64 <B64> [--kid-b64 <B64>] [--version <U8>] --input <PATH> --output <PATH>"
    );
    std::process::exit(1);
}

fn main() {
    // Fail immediately if forbidden secret key env var is detected
    if env::var("WORKSPACE_ARTIFACT_KEY_B64").is_ok() {
        eprintln!("error: WORKSPACE_ARTIFACT_KEY_B64 is forbidden; input must be a canonical 32-byte WORKSPACE PUBLIC KEY");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
    let mut public_key_b64: Option<String> = None;
    let mut kid_b64: Option<String> = None;
    let mut version: u8 = ARTIFACT_VERSION;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--public-key-b64" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                public_key_b64 = Some(args[i].clone());
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
            "--input" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                input_path = Some(PathBuf::from(&args[i]));
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                output_path = Some(PathBuf::from(&args[i]));
            }
            _ => {
                eprintln!("error: unknown argument '{}'", args[i]);
                print_usage_and_exit();
            }
        }
        i += 1;
    }

    // Check env vars as fallback if not provided on CLI
    if public_key_b64.is_none() {
        if let Ok(val) = env::var("WORKSPACE_PUBLIC_KEY_B64") {
            public_key_b64 = Some(val);
        }
    }
    if kid_b64.is_none() {
        if let Ok(val) = env::var("WORKSPACE_ARTIFACT_KID_B64") {
            kid_b64 = Some(val);
        }
    }

    let public_key_str = public_key_b64.unwrap_or_else(|| {
        eprintln!("error: --public-key-b64 or WORKSPACE_PUBLIC_KEY_B64 required");
        std::process::exit(1);
    });
    let input = input_path.unwrap_or_else(|| {
        eprintln!("error: --input path required");
        std::process::exit(1);
    });
    let output = output_path.unwrap_or_else(|| {
        eprintln!("error: --output path required");
        std::process::exit(1);
    });

    let b64_engine = base64::engine::general_purpose::STANDARD;
    let pk_bytes = b64_engine
        .decode(public_key_str.trim())
        .unwrap_or_else(|_| {
            eprintln!("error: invalid base64 public key");
            std::process::exit(1);
        });
    if pk_bytes.len() != PUBLIC_KEY_LEN {
        eprintln!(
            "error: public key must be exactly {} bytes, got {}",
            PUBLIC_KEY_LEN,
            pk_bytes.len()
        );
        std::process::exit(1);
    }
    let mut pk_array = [0u8; PUBLIC_KEY_LEN];
    pk_array.copy_from_slice(&pk_bytes);
    if pk_array.iter().all(|&b| b == 0) {
        eprintln!("error: all-zero public key rejected");
        std::process::exit(1);
    }
    let recipient_pk = HpkePublicKey(pk_array);

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

    let payload = fs::read(&input).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to read input file {}: {}",
            input.display(),
            e
        );
        std::process::exit(1);
    });

    let sealed = seal_artifact(&recipient_pk, version, &kid, &payload).unwrap_or_else(|e| {
        eprintln!("error: artifact sealing failed: {}", e);
        std::process::exit(1);
    });

    // Atomic write
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("error: failed to create output directory: {}", e);
            std::process::exit(1);
        });
    }

    let temp_output = output.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temp_output, &sealed).unwrap_or_else(|e| {
        eprintln!("error: failed to write temporary sealed artifact: {}", e);
        std::process::exit(1);
    });

    fs::rename(&temp_output, &output).unwrap_or_else(|e| {
        let _ = fs::remove_file(&temp_output);
        eprintln!("error: failed to commit sealed artifact: {}", e);
        std::process::exit(1);
    });

    println!(
        "sealed artifact successfully written to {} ({} bytes)",
        output.display(),
        sealed.len()
    );
}
