use std::io::{self, Write};
use std::path::Path;

mod algo;
mod cli;
mod manifest;

use manifest::ManifestEntry;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verifiler: {e}");
            eprintln!();
            let _ = cli::print_usage(&mut std::io::stderr());
            std::process::exit(2);
        }
    };
    let code = run(cmd);
    std::process::exit(code);
}

fn run(cmd: cli::Command) -> i32 {
    match cmd {
        cli::Command::Help => match cli::print_usage(&mut io::stdout()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("verifiler: cannot write stdout: {e}");
                1
            }
        },
        cli::Command::Version => {
            match writeln!(io::stdout(), "verifiler {}", env!("CARGO_PKG_VERSION")) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("verifiler: cannot write stdout: {e}");
                    1
                }
            }
        }
        cli::Command::Calculate {
            file,
            output,
            algorithms,
            quiet,
        } => match calculate(&file, output.as_deref(), &algorithms, quiet) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("verifiler: {e}");
                1
            }
        },
        cli::Command::Verify {
            file,
            manifest,
            algorithms,
        } => match verify(&file, &manifest, &algorithms) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(e) => {
                eprintln!("verifiler: {e}");
                1
            }
        },
    }
}

fn calculate(
    file: &Path,
    output: Option<&Path>,
    algorithms: &[algo::Algorithm],
    quiet: bool,
) -> Result<(), String> {
    if let Some(path) = output {
        manifest::check_output(file, path)?;
    }

    let selected: Vec<algo::Algorithm> = if algorithms.is_empty() {
        algo::ALL.to_vec()
    } else {
        algorithms.to_vec()
    };

    let hashes = algo::digest_file_hex(file, &selected)?;
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
    if output.is_none() || !quiet {
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        for e in &entries {
            writeln!(out, "{} {}", e.algorithm, e.hash)
                .map_err(|e| format!("cannot write stdout: {e}"))?;
        }
        out.flush()
            .map_err(|e| format!("cannot write stdout: {e}"))?;
    }
    Ok(())
}

fn verify(file: &Path, manifest_path: &Path, only: &[algo::Algorithm]) -> Result<bool, String> {
    let manifest_name = manifest_path.display();
    let expected = manifest::parse_manifest(manifest_path)
        .map_err(|e| format!("cannot read manifest '{manifest_name}': {e}"))?;
    if expected.is_empty() {
        return Err(format!("manifest '{manifest_name}' contains no checksums"));
    }

    let selected: Vec<&manifest::ManifestEntry> = if only.is_empty() {
        expected.iter().collect()
    } else {
        let mut picked = Vec::with_capacity(only.len());
        for algo in only {
            let name = algo.name();
            let found = expected
                .iter()
                .find(|e| e.algorithm == name)
                .ok_or_else(|| format!("manifest '{manifest_name}' has no '{name}' checksum"))?;
            picked.push(found);
        }
        picked
    };

    let algorithms: Vec<algo::Algorithm> = selected
        .iter()
        .map(|e| algo::Algorithm::from_name(&e.algorithm))
        .collect::<Result<Vec<_>, _>>()?;

    let actual_hashes = algo::digest_file_hex(file, &algorithms)?;

    let mut ok_count = 0usize;
    let mut all_ok = true;
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let stderr = io::stderr();
    let mut err = io::BufWriter::new(stderr.lock());

    for (entry, actual) in selected.iter().zip(actual_hashes) {
        let entry = *entry;
        if actual.eq_ignore_ascii_case(&entry.hash) {
            ok_count += 1;
            writeln!(out, "OK       {} {}", entry.algorithm, actual)
                .map_err(|e| format!("cannot write stdout: {e}"))?;
        } else {
            all_ok = false;
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
            ok_count,
            selected.len()
        )
        .map_err(|e| format!("cannot write stdout: {e}"))?;
    } else {
        writeln!(
            err,
            "{}/{} checksums matched: file is CORRUPTED",
            ok_count,
            selected.len()
        )
        .map_err(|e| format!("cannot write stderr: {e}"))?;
    }
    out.flush()
        .map_err(|e| format!("cannot write stdout: {e}"))?;
    err.flush()
        .map_err(|e| format!("cannot write stderr: {e}"))?;
    Ok(all_ok)
}
