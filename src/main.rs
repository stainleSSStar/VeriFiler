use std::io::{self, Write};
use std::path::Path;

mod algo;
mod cli;
mod manifest;

use manifest::ManifestEntry;

pub const BUF_SIZE: usize = 128 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verifiler: {e}");
            eprintln!();
            cli::print_usage(&mut std::io::stderr());
            std::process::exit(2);
        }
    };
    let code = run(cmd);
    std::process::exit(code);
}

fn run(cmd: cli::Command) -> i32 {
    match cmd {
        cli::Command::Help => {
            cli::print_usage(&mut io::stdout());
            0
        }
        cli::Command::Version => {
            println!("verifiler {}", env!("CARGO_PKG_VERSION"));
            0
        }
        cli::Command::Calculate { file, output, algorithms, quiet } => match calculate(
            &file,
            output.as_deref(),
            &algorithms,
            quiet,
        ) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("verifiler: {e}");
                1
            }
        },
        cli::Command::Verify { file, manifest, algorithms } => {
            match verify(&file, &manifest, &algorithms) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(e) => {
                    eprintln!("verifiler: {e}");
                    1
                }
            }
        }
    }
}

fn calculate(
    file: &str,
    output: Option<&str>,
    algorithms: &[algo::Algorithm],
    quiet: bool,
) -> Result<(), String> {
    if let Err(e) = std::fs::metadata(Path::new(file)) {
        return Err(format!("cannot access '{file}': {e}"));
    }
    if !std::fs::metadata(Path::new(file)).map(|m| m.is_file()).unwrap_or(false) {
        return Err(format!("'{file}' is not a regular file"));
    }

    let selected: Vec<algo::Algorithm> = if algorithms.is_empty() {
        algo::ALL.to_vec()
    } else {
        algorithms.to_vec()
    };

    let mut entries = Vec::with_capacity(selected.len());
    if selected.iter().any(|a| matches!(a, algo::Algorithm::Crc32)) {
        entries.push(ManifestEntry { algorithm: "crc32".into(), hash: algo::crc32_hex(file)? });
    }
    let digest_algos: Vec<algo::Algorithm> = selected
        .iter()
        .copied()
        .filter(|a| !matches!(a, algo::Algorithm::Crc32))
        .collect();
    if !digest_algos.is_empty() {
        let hashes = algo::digest_file_hex(file, &digest_algos)?;
        for (a, h) in digest_algos.iter().zip(hashes) {
            entries.push(ManifestEntry { algorithm: a.name().to_string(), hash: h });
        }
    }

    match output {
        Some(path) => {
            manifest::write_manifest(path, &entries)
                .map_err(|e| format!("cannot write '{path}': {e}"))?;
            if !quiet {
                for e in &entries {
                    println!("{} {}", e.algorithm, e.hash);
                }
            }
        }
        None => {
            for e in &entries {
                println!("{} {}", e.algorithm, e.hash);
            }
        }
    }
    Ok(())
}

fn verify(file: &str, manifest_path: &str, only: &[algo::Algorithm]) -> Result<bool, String> {
    let expected = manifest::parse_manifest(manifest_path)
        .map_err(|e| format!("cannot read manifest '{manifest_path}': {e}"))?;
    if expected.is_empty() {
        return Err(format!("manifest '{manifest_path}' contains no checksums"));
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
                .ok_or_else(|| format!("manifest '{manifest_path}' has no '{name}' checksum"))?;
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
            let _ = writeln!(out, "OK       {} {}", entry.algorithm, actual);
        } else {
            all_ok = false;
            let _ = writeln!(
                err,
                "FAIL     {} expected={} actual={}",
                entry.algorithm,
                entry.hash,
                actual
            );
        }
    }

    if all_ok {
        let _ = writeln!(out, "{}/{} checksums matched: file is intact", ok_count, selected.len());
    } else {
        let _ = writeln!(err, "{}/{} checksums matched: file is CORRUPTED", ok_count, selected.len());
    }
    let _ = out.flush();
    let _ = err.flush();
    Ok(all_ok)
}
