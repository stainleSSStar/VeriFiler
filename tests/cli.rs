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

#[test]
fn help_describes_commands_and_algorithms() {
    let assert = Command::cargo_bin("verifiler").unwrap()
        .arg("help")
        .assert()
        .success();
    let out = assert.get_output().stdout.clone();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("calculate <FILE>"), "usage should explain calculate");
    assert!(out.contains("verify <FILE> <MANIFEST>"), "usage should explain verify with -a");
    assert!(out.contains("-a"), "usage should show -a option");
    for algo in ["md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "blake2b-512", "blake2s-256", "blake3", "crc32"] {
        assert!(out.contains(algo), "help should list algorithm {algo}");
    }
    assert!(out.contains("EXAMPLES"), "help should contain examples");
}

#[test]
fn verify_can_select_single_algorithm() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"payload for selective verification test").unwrap();

    let manifest = dir.child("manifest.txt");
    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-o", manifest.path().to_str().unwrap(), "-q"])
        .assert()
        .success();

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap(), "-a", "sha256"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("OK       sha256 "))
        .stdout(predicate::str::contains("1/1 checksums matched: file is intact"));

    let multi = Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap(), "-a", "md5,blake3"])
        .assert()
        .code(0);
    let out = String::from_utf8(multi.get_output().stdout.clone()).unwrap();
    assert!(out.contains("OK       md5 "), "selected md5 should be checked: {out}");
    assert!(out.contains("OK       blake3 "), "selected blake3 should be checked: {out}");
    assert!(out.contains("2/2 checksums matched"), "summary should count only selected: {out}");
    assert!(!out.contains("sha1"), "unselected algorithms should be skipped: {out}");
}

#[test]
fn verify_repeated_algo_flags_merge() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"merge flags test").unwrap();

    let manifest = dir.child("manifest.txt");
    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-o", manifest.path().to_str().unwrap(), "-a", "md5,sha256", "-q"])
        .assert()
        .success();

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap(), "-a", "md5", "-a", "sha256"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("2/2 checksums matched"));
}

#[test]
fn verify_selected_algorithm_missing_from_manifest_errors() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"abc").unwrap();

    let manifest = dir.child("manifest.txt");
    Command::cargo_bin("verifiler").unwrap()
        .args(["calculate", data.path().to_str().unwrap(), "-o", manifest.path().to_str().unwrap(), "-a", "md5", "-q"])
        .assert()
        .success();

    Command::cargo_bin("verifiler").unwrap()
        .args(["verify", data.path().to_str().unwrap(), manifest.path().to_str().unwrap(), "-a", "sha256"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no 'sha256' checksum"));
}
