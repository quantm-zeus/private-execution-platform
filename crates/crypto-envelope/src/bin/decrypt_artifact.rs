//! Audited CLI binary for decrypting a workspace artifact payload with an unlock secret.
//!
//! Intended for local tooling and test verification.
//! Private key material is derived in RAM and zeroized on drop.

use base64::Engine;
use crypto_envelope::{
    decrypt_artifact_with_secret, ARTIFACT_VERSION, KID_LEN, MAX_ARTIFACT_LEN, MIN_ARTIFACT_LEN,
    UNLOCK_SECRET_LEN,
};
use std::env;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: decrypt-artifact --unlock-secret-b64 <B64> --kid-b64 <B64> [--version <U8>] --input <PATH> --output <PATH>"
    );
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut unlock_secret_b64: Option<String> = None;
    let mut kid_b64: Option<String> = None;
    let mut version: u8 = ARTIFACT_VERSION;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

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
    let input = input_path.unwrap_or_else(|| {
        eprintln!("error: --input path required");
        std::process::exit(1);
    });
    let output = output_path.unwrap_or_else(|| {
        eprintln!("error: --output path required");
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

    let kid_str = kid_b64.unwrap_or_else(|| {
        eprintln!("error: --kid-b64 or WORKSPACE_ARTIFACT_KID_B64 required");
        std::process::exit(1);
    });
    let kid_bytes = b64_engine.decode(kid_str.trim()).unwrap_or_else(|_| {
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
    let mut kid = [0u8; KID_LEN];
    kid.copy_from_slice(&kid_bytes);
    if kid.iter().all(|&b| b == 0) {
        eprintln!("error: all-zero kid rejected");
        std::process::exit(1);
    }

    let input_meta = fs::metadata(&input).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to inspect input file {}: {}",
            input.display(),
            e
        );
        std::process::exit(1);
    });
    if !input_meta.is_file() {
        eprintln!(
            "error: input path {} is not a regular file",
            input.display()
        );
        std::process::exit(1);
    }
    let file_len = input_meta.len();
    if file_len < MIN_ARTIFACT_LEN as u64 {
        eprintln!(
            "error: artifact file too small ({} bytes < minimum {} bytes)",
            file_len, MIN_ARTIFACT_LEN
        );
        std::process::exit(1);
    }
    if file_len > MAX_ARTIFACT_LEN as u64 {
        eprintln!(
            "error: artifact file exceeds maximum size of {} bytes",
            MAX_ARTIFACT_LEN
        );
        std::process::exit(1);
    }

    let mut file = fs::File::open(&input).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to open input file {}: {}",
            input.display(),
            e
        );
        std::process::exit(1);
    });
    let mut artifact_wire = Vec::with_capacity(file_len as usize);
    file.by_ref()
        .take((MAX_ARTIFACT_LEN + 1) as u64)
        .read_to_end(&mut artifact_wire)
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to read input file {}: {}",
                input.display(),
                e
            );
            std::process::exit(1);
        });
    if artifact_wire.len() < MIN_ARTIFACT_LEN {
        eprintln!("error: artifact file too small");
        std::process::exit(1);
    }
    if artifact_wire.len() > MAX_ARTIFACT_LEN {
        eprintln!("error: artifact file exceeded maximum size");
        std::process::exit(1);
    }

    let plaintext = decrypt_artifact_with_secret(&secret_arr, version, &kid, &artifact_wire)
        .unwrap_or_else(|e| {
            eprintln!("error: artifact decryption failed: {}", e);
            std::process::exit(1);
        });

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("error: failed to create output directory: {}", e);
            std::process::exit(1);
        });
    }

    fs::write(&output, &plaintext).unwrap_or_else(|e| {
        eprintln!("error: failed to write decrypted output: {}", e);
        std::process::exit(1);
    });

    println!(
        "decrypted artifact successfully written to {} ({} bytes)",
        output.display(),
        plaintext.len()
    );
}
