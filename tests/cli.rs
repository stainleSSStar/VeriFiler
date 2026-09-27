use assert_cmd::Command;
use predicates::prelude::*;
use assert_fs::assert::PathAssert;
use assert_fs::fixture::PathChild;
use assert_fs::fixture::FileWriteStr;
use assert_fs::fixture::FileWriteBin;

#[test]
fn help_exits_zero() {
    Command::cargo_bin("verifiler").unwrap()
        .arg("help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn unknown_command_exits_two() {
    Command::cargo_bin("verifiler").unwrap()
        .arg("frobnicate")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn calculate_writes_manifest_and_verify_roundtrip() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let mut bytes = Vec::new();
    for i in 0..100_000u64 {
        bytes.extend_from_slice(&(i as u128).to_le_bytes()[..8]);
    }
    data.write_binary(&bytes).unwrap();

    let manifest = dir.child("manifest.txt");
    let file_path = data.path().to_str().unwrap();
    let manifest_path = manifest.path().to_str().unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", file_path, "-o", manifest_path, "-a", "md5,sha256,blake3"])
        .assert()
        .success()
        .stdout(predicate::str::contains("md5 "));

    manifest.assert(predicate::str::contains("md5 "));
    manifest.assert(predicate::str::contains("sha256 "));
    manifest.assert(predicate::str::contains("blake3 "));

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", file_path, manifest_path])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("file is intact"));
}

#[test]
fn verify_detects_corruption() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"hello world, this is a test file").unwrap();

    let manifest = dir.child("manifest.txt");
    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-o", manifest.path().to_str().unwrap(), "-q"])
        .assert()
        .success();

    data.write_binary(b"hello world, this is a test file CORRUPTED").unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("CORRUPTED"));
}

#[test]
fn calculate_to_stdout_works() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("f.bin");
    data.write_binary(b"abc").unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("crc32 "));
}

#[test]
fn verify_rejects_unknown_algo_in_manifest() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("f.bin");
    data.write_binary(b"abc").unwrap();
    let manifest = dir.child("bad.txt");
    manifest.write_str("rot13 xyz\n").unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn cli_selecting_unknown_algo_fails() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("f.bin");
    data.write_binary(b"abc").unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-a", "notanalgo"])
        .assert()
        .code(2);
}

#[test]
fn known_digest_values() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    data.write_binary(b"abc").unwrap();

    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-a", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "900150983cd24fb0d6963f7d28e17f72",
        ));
}
