use std::io::{self, Write};
use std::path::Path;

mod algo;
mod cli;
mod manifest;

use cli::Report;
use manifest::ManifestEntry;
use serde_json::json;

fn diagnostic(message: &str) {
    let _ = writeln!(io::stderr(), "verifiler: {message}");
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            diagnostic(&e);
            let _ = writeln!(io::stderr());
            let _ = cli::print_usage(&mut io::stderr());
            std::process::exit(2);
        }
    };
    std::process::exit(run(cmd));
}

fn run(cmd: cli::Command) -> i32 {
    let result = match cmd {
        cli::Command::Help => cli::print_usage(&mut io::stdout())
            .map(|()| true)
            .map_err(|e| format!("cannot write stdout: {e}")),
        cli::Command::Version => writeln!(io::stdout(), "verifiler {}", env!("CARGO_PKG_VERSION"))
            .map(|()| true)
            .map_err(|e| format!("cannot write stdout: {e}")),
        cli::Command::Calculate {
            file,
            output,
            algorithms,
            report,
        } => calculate(&file, output.as_deref(), &algorithms, report).map(|()| true),
        cli::Command::Verify {
            file,
            manifest,
            algorithms,
            report,
        } => verify(&file, &manifest, &algorithms, report),
        cli::Command::Check {
            file,
            algorithm,
            hash,
            report,
        } => {
            let expected = [ManifestEntry {
                algorithm: algorithm.name().into(),
                hash,
            }];
            verify_entries(&file, &expected, &[], report, "check")
        }
    };
    match result {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            diagnostic(&e);
            1
        }
    }
}

fn write_json(value: &serde_json::Value) -> Result<(), String> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    serde_json::to_writer(&mut out, value).map_err(|e| format!("cannot write stdout: {e}"))?;
    writeln!(out)
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot write stdout: {e}"))
}

fn calculate(
    file: &Path,
    output: Option<&Path>,
    algorithms: &[algo::Algorithm],
    report: Report,
) -> Result<(), String> {
    if let Some(path) = output {
        manifest::check_output(file, path)?;
    }
    let selected = if algorithms.is_empty() {
        algo::ALL
    } else {
        algorithms
    };
    let hashes = algo::digest_file_hex(file, selected)?;
    let entries: Vec<_> = selected
        .iter()
        .zip(hashes)
        .map(|(a, hash)| ManifestEntry {
            algorithm: a.name().to_string(),
            hash,
        })
        .collect();
    if let Some(path) = output {
        manifest::write_manifest(file, path, &entries)
            .map_err(|e| format!("cannot write '{}': {e}", path.display()))?;
    }
    match report {
        Report::Json => write_json(
            &json!({"operation": "calculate", "checksums": entries.iter()
            .map(|e| json!({"algorithm": e.algorithm, "digest": e.hash})).collect::<Vec<_>>() }),
        ),
        Report::Quiet if output.is_some() => Ok(()),
        _ => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            for e in &entries {
                writeln!(out, "{} {}", e.algorithm, e.hash)
                    .map_err(|e| format!("cannot write stdout: {e}"))?;
            }
            out.flush().map_err(|e| format!("cannot write stdout: {e}"))
        }
    }
}

fn verify(
    file: &Path,
    manifest_path: &Path,
    only: &[algo::Algorithm],
    report: Report,
) -> Result<bool, String> {
    let expected = manifest::parse_manifest(manifest_path)
        .map_err(|e| format!("cannot read manifest '{}': {e}", manifest_path.display()))?;
    if expected.is_empty() {
        return Err(format!(
            "manifest '{}' contains no checksums",
            manifest_path.display()
        ));
    }
    verify_entries(file, &expected, only, report, "verify")
}

fn verify_entries(
    file: &Path,
    expected: &[ManifestEntry],
    only: &[algo::Algorithm],
    report: Report,
    operation: &str,
) -> Result<bool, String> {
    let selected: Vec<_> = if only.is_empty() {
        expected.iter().collect()
    } else {
        only.iter()
            .map(|a| {
                expected
                    .iter()
                    .find(|e| e.algorithm == a.name())
                    .ok_or_else(|| format!("manifest has no '{}' checksum", a.name()))
            })
            .collect::<Result<_, _>>()?
    };
    let algorithms = selected
        .iter()
        .map(|e| algo::Algorithm::from_name(&e.algorithm))
        .collect::<Result<Vec<_>, _>>()?;
    let actual = algo::digest_file_hex(file, &algorithms)?;
    let matched = selected
        .iter()
        .zip(&actual)
        .filter(|(e, a)| e.hash.eq_ignore_ascii_case(a))
        .count();
    let all_ok = matched == selected.len();
    match report {
        Report::Quiet => {}
        Report::Json => write_json(&json!({
            "operation": operation, "intact": all_ok, "matched": matched, "total": selected.len(),
            "checksums": selected.iter().zip(&actual).map(|(e, a)| json!({
                "algorithm": e.algorithm, "expected": e.hash, "actual": a,
                "matched": e.hash.eq_ignore_ascii_case(a)
            })).collect::<Vec<_>>()
        }))?,
        Report::Text => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            let stderr = io::stderr();
            let mut err = io::BufWriter::new(stderr.lock());
            for (entry, actual) in selected.iter().zip(&actual) {
                if actual.eq_ignore_ascii_case(&entry.hash) {
                    writeln!(out, "OK       {} {}", entry.algorithm, actual)
                        .map_err(|e| format!("cannot write stdout: {e}"))?;
                } else {
                    writeln!(
                        err,
                        "FAIL     {} expected={} actual={}",
                        entry.algorithm, entry.hash, actual
                    )
                    .map_err(|e| format!("cannot write stderr: {e}"))?;
                }
            }
            if all_ok {
                writeln!(
                    out,
                    "{}/{} checksums matched: file is intact",
                    matched,
                    selected.len()
                )
                .map_err(|e| format!("cannot write stdout: {e}"))?;
            } else {
                writeln!(
                    err,
                    "{}/{} checksums matched: file is CORRUPTED",
                    matched,
                    selected.len()
                )
                .map_err(|e| format!("cannot write stderr: {e}"))?;
            }
            out.flush()
                .map_err(|e| format!("cannot write stdout: {e}"))?;
            err.flush()
                .map_err(|e| format!("cannot write stderr: {e}"))?;
        }
    }
    Ok(all_ok)
}
