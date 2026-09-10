use std::fs;
use std::process::Command;

const TEST_SECRET_B64: &str = "QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGE=";
const TEST_KID_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const ALL_ZERO_KID_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
const EXPECTED_PUBLIC_KEY_B64: &str = "/EHOVmmtUs+zpTpYHjW9XucJARXNqAMmNcZGrSzJ4DQ=";

#[test]
fn cli_derive_public_key_expected_vector() {
    let output = Command::new(env!("CARGO_BIN_EXE_derive-public-key"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--kid-b64",
            TEST_KID_B64,
        ])
        .output()
        .expect("derive-public-key executes");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), EXPECTED_PUBLIC_KEY_B64);
}

#[test]
fn cli_kid_enforcement_missing_and_all_zero_rejected() {
    // 1. derive-public-key requires kid and rejects all-zero
    let missing_kid_derive = Command::new(env!("CARGO_BIN_EXE_derive-public-key"))
        .args(["--unlock-secret-b64", TEST_SECRET_B64])
        .output()
        .expect("executes");
    assert!(!missing_kid_derive.status.success());

    let zero_kid_derive = Command::new(env!("CARGO_BIN_EXE_derive-public-key"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--kid-b64",
            ALL_ZERO_KID_B64,
        ])
        .output()
        .expect("executes");
    assert!(!zero_kid_derive.status.success());

    let temp = std::env::temp_dir().join(format!("test-kid-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let empty_file = temp.join("empty.bin");
    fs::write(&empty_file, b"").unwrap();
    let sample_file = temp.join("sample.bin");
    fs::write(&sample_file, b"hello payload").unwrap();
    let out_file = temp.join("out.bin");

    // 2. seal-artifact requires kid and rejects all-zero
    let missing_kid_seal = Command::new(env!("CARGO_BIN_EXE_seal-artifact"))
        .args([
            "--public-key-b64",
            EXPECTED_PUBLIC_KEY_B64,
            "--input",
            sample_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!missing_kid_seal.status.success());

    let zero_kid_seal = Command::new(env!("CARGO_BIN_EXE_seal-artifact"))
        .args([
            "--public-key-b64",
            EXPECTED_PUBLIC_KEY_B64,
            "--kid-b64",
            ALL_ZERO_KID_B64,
            "--input",
            sample_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!zero_kid_seal.status.success());

    // 3. decrypt-artifact requires kid and rejects all-zero
    let missing_kid_decrypt = Command::new(env!("CARGO_BIN_EXE_decrypt-artifact"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--input",
            sample_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!missing_kid_decrypt.status.success());

    let zero_kid_decrypt = Command::new(env!("CARGO_BIN_EXE_decrypt-artifact"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--kid-b64",
            ALL_ZERO_KID_B64,
            "--input",
            sample_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!zero_kid_decrypt.status.success());

    fs::remove_dir_all(&temp).ok();
}

#[test]
fn cli_metadata_preflight_and_bounds() {
    let temp = std::env::temp_dir().join(format!("test-bounds-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let empty_file = temp.join("empty.bin");
    fs::write(&empty_file, b"").unwrap();
    let out_file = temp.join("out.bin");

    // seal-artifact rejects empty input file
    let seal_empty = Command::new(env!("CARGO_BIN_EXE_seal-artifact"))
        .args([
            "--public-key-b64",
            EXPECTED_PUBLIC_KEY_B64,
            "--kid-b64",
            TEST_KID_B64,
            "--input",
            empty_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!seal_empty.status.success());

    // decrypt-artifact rejects truncated input (< 65 bytes)
    let trunc_file = temp.join("trunc.bin");
    fs::write(&trunc_file, [0u8; 64]).unwrap();
    let decrypt_trunc = Command::new(env!("CARGO_BIN_EXE_decrypt-artifact"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--kid-b64",
            TEST_KID_B64,
            "--input",
            trunc_file.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("executes");
    assert!(!decrypt_trunc.status.success());

    fs::remove_dir_all(&temp).ok();
}

#[test]
fn cli_seal_and_decrypt_roundtrip() {
    let temp = std::env::temp_dir().join(format!("test-roundtrip-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let input_file = temp.join("input.txt");
    let payload = b"critical test payload for cli seal and decrypt";
    fs::write(&input_file, payload).unwrap();
    let sealed_file = temp.join("sealed.bin");
    let decrypted_file = temp.join("decrypted.txt");

    let seal_res = Command::new(env!("CARGO_BIN_EXE_seal-artifact"))
        .args([
            "--public-key-b64",
            EXPECTED_PUBLIC_KEY_B64,
            "--kid-b64",
            TEST_KID_B64,
            "--input",
            input_file.to_str().unwrap(),
            "--output",
            sealed_file.to_str().unwrap(),
        ])
        .output()
        .expect("seal executes");
    assert!(seal_res.status.success());

    let decrypt_res = Command::new(env!("CARGO_BIN_EXE_decrypt-artifact"))
        .args([
            "--unlock-secret-b64",
            TEST_SECRET_B64,
            "--kid-b64",
            TEST_KID_B64,
            "--input",
            sealed_file.to_str().unwrap(),
            "--output",
            decrypted_file.to_str().unwrap(),
        ])
        .output()
        .expect("decrypt executes");
    assert!(decrypt_res.status.success());

    let decrypted = fs::read(&decrypted_file).unwrap();
    assert_eq!(decrypted, payload);

    fs::remove_dir_all(&temp).ok();
}
