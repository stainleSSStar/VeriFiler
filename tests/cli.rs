use assert_cmd::Command;
use assert_fs::assert::PathAssert;
use assert_fs::fixture::FileWriteBin;
use assert_fs::fixture::FileWriteStr;
use assert_fs::fixture::PathChild;
use predicates::prelude::*;

#[test]
fn help_exits_zero() {
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .arg("help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn unknown_command_exits_two() {
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
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

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            file_path,
            "-o",
            manifest_path,
            "-a",
            "md5,sha256,blake3",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("md5 "));

    manifest.assert(predicate::str::contains("md5 "));
    manifest.assert(predicate::str::contains("sha256 "));
    manifest.assert(predicate::str::contains("blake3 "));

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args(["verify", file_path, manifest_path])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("file is intact"));
}

#[test]
fn verify_detects_corruption() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"hello world, this is a test file")
        .unwrap();

    let manifest = dir.child("manifest.txt");
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            data.path().to_str().unwrap(),
            "-o",
            manifest.path().to_str().unwrap(),
            "-q",
        ])
        .assert()
        .success();

    data.write_binary(b"hello world, this is a test file CORRUPTED")
        .unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("CORRUPTED"));
}

#[test]
fn calculate_to_stdout_works() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("f.bin");
    data.write_binary(b"abc").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
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

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);
}

#[test]
fn cli_selecting_unknown_algo_fails() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("f.bin");
    data.write_binary(b"abc").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            data.path().to_str().unwrap(),
            "-a",
            "notanalgo",
        ])
        .assert()
        .code(2);
}

#[test]
fn known_digest_values() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    data.write_binary(b"abc").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args(["calculate", data.path().to_str().unwrap(), "-a", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("900150983cd24fb0d6963f7d28e17f72"));
}

#[test]
fn help_describes_commands_and_algorithms() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .arg("help")
        .assert()
        .success();
    let out = assert.get_output().stdout.clone();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains("calculate <FILE>"),
        "usage should explain calculate"
    );
    assert!(
        out.contains("verify <FILE> <MANIFEST>"),
        "usage should explain verify with -a"
    );
    assert!(out.contains("-a"), "usage should show -a option");
    for algo in [
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha3-256",
        "sha3-512",
        "blake2b-512",
        "blake2s-256",
        "blake3",
        "crc32",
    ] {
        assert!(out.contains(algo), "help should list algorithm {algo}");
    }
    assert!(out.contains("EXAMPLES"), "help should contain examples");
}

#[test]
fn verify_can_select_single_algorithm() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"payload for selective verification test")
        .unwrap();

    let manifest = dir.child("manifest.txt");
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            data.path().to_str().unwrap(),
            "-o",
            manifest.path().to_str().unwrap(),
            "-q",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
            "-a",
            "sha256",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("OK       sha256 "))
        .stdout(predicate::str::contains(
            "1/1 checksums matched: file is intact",
        ));

    let multi = Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
            "-a",
            "md5,blake3",
        ])
        .assert()
        .code(0);
    let out = String::from_utf8(multi.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("OK       md5 "),
        "selected md5 should be checked: {out}"
    );
    assert!(
        out.contains("OK       blake3 "),
        "selected blake3 should be checked: {out}"
    );
    assert!(
        out.contains("2/2 checksums matched"),
        "summary should count only selected: {out}"
    );
    assert!(
        !out.contains("sha1"),
        "unselected algorithms should be skipped: {out}"
    );
}

#[test]
fn verify_repeated_algo_flags_merge() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    data.write_binary(b"merge flags test").unwrap();

    let manifest = dir.child("manifest.txt");
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            data.path().to_str().unwrap(),
            "-o",
            manifest.path().to_str().unwrap(),
            "-a",
            "md5,sha256",
            "-q",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
            "-a",
            "md5",
            "-a",
            "sha256",
        ])
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
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "calculate",
            data.path().to_str().unwrap(),
            "-o",
            manifest.path().to_str().unwrap(),
            "-a",
            "md5",
            "-q",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args([
            "verify",
            data.path().to_str().unwrap(),
            manifest.path().to_str().unwrap(),
            "-a",
            "sha256",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no 'sha256' checksum"));
}

fn bin() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
}

#[test]
fn all_algorithms_match_known_abc_vectors() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    data.write_binary(b"abc").unwrap();
    let expected = include_str!("vectors/abc.vf");
    bin()
        .arg("calculate")
        .arg(data.path())
        .assert()
        .success()
        .stdout(expected);
}

#[test]
fn empty_file_roundtrip_all_algorithms() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("empty.bin");
    let manifest = dir.child("empty.vf");
    data.write_binary(b"").unwrap();
    bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(manifest.path())
        .arg("-q")
        .assert()
        .success()
        .stdout("");
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("10/10 checksums matched"));
}

#[test]
fn cannot_overwrite_input_or_hard_link() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("input.bin");
    data.write_binary(b"keep these bytes").unwrap();
    let link = dir.child("hardlink.bin");
    std::fs::hard_link(data.path(), link.path()).unwrap();
    for output in [data.path(), link.path()] {
        bin()
            .arg("calculate")
            .arg(data.path())
            .arg("-o")
            .arg(output)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("refusing to overwrite"));
        assert_eq!(std::fs::read(data.path()).unwrap(), b"keep these bytes");
        assert_eq!(std::fs::read(output).unwrap(), b"keep these bytes");
    }
}

#[cfg(unix)]
#[test]
fn cannot_overwrite_input_through_symlink() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("input.bin");
    data.write_binary(b"keep these bytes").unwrap();
    let link = dir.child("symlink.bin");
    std::os::unix::fs::symlink(data.path(), link.path()).unwrap();
    bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(link.path())
        .assert()
        .code(1);
    assert_eq!(std::fs::read(data.path()).unwrap(), b"keep these bytes");
    assert!(std::fs::symlink_metadata(link.path())
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn failed_calculation_preserves_existing_manifest() {
    let dir = assert_fs::TempDir::new().unwrap();
    let manifest = dir.child("out.vf");
    manifest.write_str("previous manifest\n").unwrap();
    bin()
        .arg("calculate")
        .arg(dir.child("missing.bin").path())
        .arg("-o")
        .arg(manifest.path())
        .assert()
        .code(1);
    manifest.assert("previous manifest\n");
}

#[test]
fn replaces_existing_manifest_and_cleans_temporary_file() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    manifest.write_str("old contents\n").unwrap();
    bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(manifest.path())
        .arg("-q")
        .assert()
        .success()
        .stdout("");
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .success();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn invalid_manifests_are_errors_even_with_selection() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let manifest = dir.child("bad.vf");
    data.write_binary(b"abc").unwrap();
    let md5 = "md5 900150983cd24fb0d6963f7d28e17f72\n";
    let cases = [
        "".to_string(),
        "# no checksums\n".to_string(),
        "md5\n".to_string(),
        "md5 xyz\n".to_string(),
        "md5 900150983cd24fb0d6963f7d28e17f7z\n".to_string(),
        format!("{md5}MD5 900150983cd24fb0d6963f7d28e17f72\n"),
        format!("{md5}md5 00000000000000000000000000000000\n"),
        format!("{md5}sha256 invalid\n"),
        "md5 900150983cd24fb0d6963f7d28e17f72 extra\n".to_string(),
        "#".repeat(4097),
    ];
    for text in cases {
        manifest.write_str(&text).unwrap();
        for select in [false, true] {
            let mut cmd = bin();
            cmd.arg("verify").arg(data.path()).arg(manifest.path());
            if select {
                cmd.args(["-a", "md5"]);
            }
            cmd.assert()
                .code(1)
                .stdout(predicate::str::contains("file is intact").not());
        }
    }
    manifest.write_binary(b"md5 \xff\n").unwrap();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .code(1);
}

#[test]
fn manifest_accepts_bom_comments_crlf_and_uppercase() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    manifest
        .write_str("\u{feff}# comment\r\n\r\n MD5\t900150983CD24FB0D6963F7D28E17F72 \r\n")
        .unwrap();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .success();
}

#[test]
fn cli_rejects_unknown_flags_missing_values_and_empty_algorithms() {
    for args in [
        vec!["calculate", "--bogus"],
        vec!["verify", "--bogus", "manifest"],
        vec!["calculate", "file", "-o", "-q"],
        vec!["calculate", "file", "-o"],
        vec!["calculate", "file", "-o", "a", "-o", "b"],
        vec!["calculate", "file", "-a", "md5,"],
        vec!["calculate", "file", "-a", ",md5"],
        vec!["calculate", "file", "-a", ""],
        vec!["verify", "file", "manifest", "-a"],
        vec!["version", "junk"],
        vec!["help", "junk"],
    ] {
        bin().args(args).assert().code(2);
    }
    bin().args(["calculate", "--help"]).assert().success();
    bin().args(["verify", "-h"]).assert().success();
}

#[test]
fn option_terminator_allows_dash_filenames() {
    let dir = assert_fs::TempDir::new().unwrap();
    dir.child("-data").write_binary(b"abc").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["calculate", "-o", "out.vf", "--", "-data"])
        .assert()
        .success();
    bin()
        .current_dir(dir.path())
        .args(["verify", "--", "-data", "out.vf"])
        .assert()
        .success();
}

#[cfg(target_os = "linux")]
#[test]
fn paths_need_not_be_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"data-\xff.bin".to_vec()));
    let manifest = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"sum-\xfe.vf".to_vec()));
    std::fs::write(&data, b"abc").unwrap();
    bin()
        .arg("calculate")
        .arg(&data)
        .arg("-o")
        .arg(&manifest)
        .assert()
        .success();
    bin()
        .arg("verify")
        .arg(&data)
        .arg(&manifest)
        .assert()
        .success();
}

#[test]
fn directories_are_rejected_as_input_manifest_and_output() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    manifest
        .write_str("md5 900150983cd24fb0d6963f7d28e17f72\n")
        .unwrap();
    bin().arg("calculate").arg(dir.path()).assert().code(1);
    bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(dir.path())
        .assert()
        .code(1);
    bin()
        .arg("verify")
        .arg(dir.path())
        .arg(manifest.path())
        .assert()
        .code(1);
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(dir.path())
        .assert()
        .code(1);
}

#[cfg(unix)]
#[test]
fn output_write_failures_are_runtime_errors() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("data.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    manifest
        .write_str("md5 900150983cd24fb0d6963f7d28e17f72\n")
        .unwrap();
    for args in [
        vec!["calculate"],
        vec!["verify"],
        vec!["calculate", "--json"],
        vec!["verify", "--json"],
        vec!["help"],
        vec!["version"],
    ] {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("verifiler"));
        cmd.args(&args);
        if args[0] == "calculate" {
            cmd.arg(data.path());
        }
        if args[0] == "verify" {
            cmd.arg(data.path()).arg(manifest.path());
        }
        // /dev/full exists on Linux, but not macOS.
        if let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") {
            let output = cmd.stdout(full).output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("cannot write stdout"));
        }
    }
}

#[test]
fn multichunk_binary_matches_independent_vectors() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("binary.bin");
    let mut bytes = (0..=255u8).cycle().take(256 * 4096).collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 255, 128]);
    data.write_binary(&bytes).unwrap();
    let expected = include_str!("vectors/multichunk.vf");
    let manifest = dir.child("reference.vf");
    manifest.write_str(expected).unwrap();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("9/9 checksums matched"));
    bin()
        .arg("calculate")
        .arg(data.path())
        .args([
            "-a",
            "md5,sha1,sha256,sha512,sha3-256,sha3-512,blake2b-512,blake2s-256,crc32",
        ])
        .assert()
        .success()
        .stdout(expected);
}

#[test]
fn unicode_paths_roundtrip() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("zażółć gęślą jaźń.bin");
    let manifest = dir.child("sumy kontrolne żółć.vf");
    data.write_binary(b"abc").unwrap();
    bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(manifest.path())
        .assert()
        .success();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .assert()
        .success();
}

#[test]
fn stdin_calculate_and_verify_binary_data() {
    let expected = include_str!("vectors/abc.vf");
    bin()
        .args(["calculate", "-"])
        .write_stdin(b"abc".to_vec())
        .assert()
        .success()
        .stdout(expected);
    let dir = assert_fs::TempDir::new().unwrap();
    let manifest = dir.child("stdin.vf");
    bin()
        .args(["calculate", "-", "-o"])
        .arg(manifest.path())
        .arg("-q")
        .write_stdin(b"abc".to_vec())
        .assert()
        .success()
        .stdout("");
    bin()
        .args(["verify", "-"])
        .arg(manifest.path())
        .write_stdin(b"abc".to_vec())
        .assert()
        .success()
        .stdout(predicate::str::contains("10/10 checksums matched"));
    bin()
        .args(["verify", "-"])
        .arg(manifest.path())
        .write_stdin(b"wrong".to_vec())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("CORRUPTED"));
    let mut bytes = (0..=255u8).cycle().take(256 * 4096).collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 255, 128]);
    manifest
        .write_str(include_str!("vectors/multichunk.vf"))
        .unwrap();
    bin()
        .args(["verify", "-"])
        .arg(manifest.path())
        .write_stdin(bytes)
        .assert()
        .success()
        .stdout(predicate::str::contains("9/9 checksums matched"));
}

#[test]
fn redirected_stdin_source_is_not_overwritten() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("input.bin");
    data.write_binary(b"keep these bytes").unwrap();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("verifiler"))
        .args(["calculate", "-", "-o"])
        .arg(data.path())
        .stdin(std::fs::File::open(data.path()).unwrap())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read(data.path()).unwrap(), b"keep these bytes");
}

#[test]
fn stdin_empty_input_and_literal_dash_filename() {
    bin()
        .args(["calculate", "-", "-a", "md5"])
        .write_stdin(Vec::new())
        .assert()
        .success()
        .stdout("md5 d41d8cd98f00b204e9800998ecf8427e\n");
    let dir = assert_fs::TempDir::new().unwrap();
    dir.child("-").write_binary(b"abc").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["calculate", "./-", "-a", "md5", "-o", "-"])
        .assert()
        .success()
        .stdout("md5 900150983cd24fb0d6963f7d28e17f72\n");
    assert_eq!(std::fs::read(dir.child("-").path()).unwrap(), b"abc");
}

#[test]
fn direct_check_matches_or_reports_corruption() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    data.write_binary(b"abc").unwrap();
    for line in include_str!("vectors/abc.vf").lines() {
        let (algo, hash) = line.split_once(' ').unwrap();
        bin()
            .arg("check")
            .arg(data.path())
            .arg(algo)
            .arg(hash.to_uppercase())
            .assert()
            .success()
            .stdout(predicate::str::contains("1/1 checksums matched"));
    }
    bin()
        .arg("check")
        .arg(data.path())
        .args(["md5", "00000000000000000000000000000000"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("CORRUPTED"));
    bin()
        .args(["check", "-", "md5", "900150983cd24fb0d6963f7d28e17f72"])
        .write_stdin(b"abc".to_vec())
        .assert()
        .success();
    for args in [
        vec!["check", "file"],
        vec!["check", "file", "md5", "bad"],
        vec!["check", "file", "unknown", "abcd"],
        vec![
            "check",
            "file",
            "md5",
            "900150983cd24fb0d6963f7d28e17f72",
            "-a",
            "md5",
        ],
    ] {
        bin().args(args).assert().code(2);
    }
}

#[test]
fn json_calculate_and_verify_are_machine_readable() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    let result = bin()
        .arg("calculate")
        .arg(data.path())
        .arg("-o")
        .arg(manifest.path())
        .args(["-a", "md5,sha256", "--json"])
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(value["operation"], "calculate");
    assert_eq!(value["checksums"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["checksums"][0]["digest"],
        "900150983cd24fb0d6963f7d28e17f72"
    );
    let text = std::fs::read_to_string(manifest.path()).unwrap();
    assert!(text.starts_with("md5 "), "manifest remains plain text");
    for (payload, expected_code, intact) in [
        (b"abc".as_slice(), 0, true),
        (b"wrong".as_slice(), 1, false),
    ] {
        let result = bin()
            .args(["verify", "-"])
            .arg(manifest.path())
            .arg("--json")
            .write_stdin(payload.to_vec())
            .assert()
            .code(expected_code)
            .stderr("");
        let value: serde_json::Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(value["operation"], "verify");
        assert_eq!(value["intact"], intact);
        assert_eq!(value["total"], 2);
        assert_eq!(value["matched"], if intact { 2 } else { 0 });
        assert_eq!(value["checksums"][0]["matched"], intact);
        assert_eq!(
            value["checksums"][0]["expected"],
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }
    let result = bin()
        .arg("check")
        .arg(data.path())
        .args(["md5", "900150983cd24fb0d6963f7d28e17f72", "--json"])
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(value["operation"], "check");
    assert_eq!(value["intact"], true);
    assert_eq!(value["total"], 1);
}

#[test]
fn quiet_verification_uses_exit_status_and_keeps_runtime_errors() {
    let dir = assert_fs::TempDir::new().unwrap();
    let data = dir.child("abc.bin");
    let manifest = dir.child("out.vf");
    data.write_binary(b"abc").unwrap();
    manifest
        .write_str("md5 900150983cd24fb0d6963f7d28e17f72\n")
        .unwrap();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .arg("-q")
        .assert()
        .success()
        .stdout("")
        .stderr("");
    data.write_binary(b"wrong").unwrap();
    bin()
        .arg("verify")
        .arg(data.path())
        .arg(manifest.path())
        .arg("-q")
        .assert()
        .code(1)
        .stdout("")
        .stderr("");
    bin()
        .arg("check")
        .arg(data.path())
        .args(["md5", "900150983cd24fb0d6963f7d28e17f72", "-q"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("");
    bin()
        .arg("verify")
        .arg(dir.child("missing").path())
        .arg(manifest.path())
        .arg("-q")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot access"));
    for args in [
        vec!["calculate", "file", "--json", "-q"],
        vec!["verify", "file", "manifest", "--json", "-q"],
    ] {
        bin().args(args).assert().code(2);
    }
}

#[test]
fn equals_options_and_algorithm_deduplication() {
    let dir = assert_fs::TempDir::new().unwrap();
    dir.child("data.bin").write_binary(b"abc").unwrap();
    bin()
        .current_dir(dir.path())
        .args([
            "calculate",
            "data.bin",
            "--output=-sum.vf",
            "--algos=MD5,md5",
            "-a",
            "Md5",
        ])
        .assert()
        .success()
        .stdout("md5 900150983cd24fb0d6963f7d28e17f72\n");
    bin()
        .current_dir(dir.path())
        .args(["verify", "--algos=md5", "--", "data.bin", "-sum.vf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1/1 checksums matched"));
    for args in [
        vec!["calculate", "data.bin", "--output="],
        vec!["calculate", "data.bin", "--algos="],
        vec!["calculate", "data.bin", "-o", "-", "--output=other"],
    ] {
        bin().args(args).assert().code(2);
    }
}
