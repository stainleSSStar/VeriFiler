use std::io::Write;

use crate::algo::{self, Algorithm};

pub enum Command {
    Help,
    Version,
    Calculate {
        file: String,
        output: Option<String>,
        algorithms: Vec<Algorithm>,
        quiet: bool,
    },
    Verify {
        file: String,
        manifest: String,
    },
}

pub fn print_usage<W: Write>(w: &mut W) {
    let _ = writeln!(
        w,
        "verifiler {} - portable file checksum calculator/verifier

USAGE:
    verifiler calculate <FILE> [-o <MANIFEST>] [-a <ALGO[,ALGO...]>] [-q]
    verifiler verify <FILE> <MANIFEST>
    verifiler help | version

COMMANDS:
    calculate    Compute checksums of FILE with all popular algorithms
                 (or a selected subset) and write them to MANIFEST,
                 or to stdout if -o is not given.
    verify       Check FILE against the checksums in MANIFEST and report
                 whether the file is intact.

OPTIONS (calculate):
    -o, --output <PATH>    Manifest file to write (default: stdout)
    -a, --algos <LIST>     Comma-separated algorithms to use
                           (default: all). Supported: {algs}
    -q, --quiet            Do not print checksums to the console
                           when writing a manifest file

OUTPUT:
    calculate writes lines of '<algorithm> <hex_digest>', e.g.:
        sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    verify prints 'OK <algo> <digest>' or 'FAIL <algo> expected=<e> actual=<a>'
    and exits 0 if the file is intact, 1 if corrupted, 2 on usage errors.

The manifest is a simple text file: one '<algorithm> <digest>' pair per line,
so it can be transferred alongside the downloaded file and fed back to
'verify' on any machine.",
        env!("CARGO_PKG_VERSION"),
        algs = algo::supported_names()
    );
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut it = args.iter();
    let Some(cmd) = it.next() else {
        return Ok(Command::Help);
    };

    match cmd.as_str() {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "version" | "--version" | "-V" => Ok(Command::Version),
        "calculate" => {
            let mut file: Option<String> = None;
            let mut output: Option<String> = None;
            let mut algorithms: Vec<Algorithm> = Vec::new();
            let mut quiet = false;
            let rest: Vec<String> = it.cloned().collect();
            let mut i = 0;
            while i < rest.len() {
                let a = &rest[i];
                match a.as_str() {
                    "-o" | "--output" => {
                        i += 1;
                        output = Some(
                            rest.get(i)
                                .ok_or_else(|| "missing value for -o/--output".to_string())?
                                .clone(),
                        );
                    }
                    "-a" | "--algos" => {
                        i += 1;
                        let list = rest
                            .get(i)
                            .ok_or_else(|| "missing value for -a/--algos".to_string())?;
                        algorithms = parse_algo_list(list)?;
                    }
                    "-q" | "--quiet" => quiet = true,
                    _ => {
                        if file.is_some() {
                            return Err(format!("unexpected argument '{a}'"));
                        }
                        file = Some(a.clone());
                    }
                }
                i += 1;
            }
            let file = file.ok_or_else(|| "calculate requires a FILE argument".to_string())?;
            Ok(Command::Calculate { file, output, algorithms, quiet })
        }
        "verify" => {
            let rest: Vec<String> = it.cloned().collect();
            if rest.len() != 2 {
                return Err("verify requires exactly two arguments: FILE MANIFEST".to_string());
            }
            Ok(Command::Verify { file: rest[0].clone(), manifest: rest[1].clone() })
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

fn parse_algo_list(list: &str) -> Result<Vec<Algorithm>, String> {
    let mut algos = Vec::new();
    for name in list.split(',') {
        if name.trim().is_empty() {
            continue;
        }
        let a = Algorithm::from_name(name)?;
        if !algos.contains(&a) {
            algos.push(a);
        }
    }
    if algos.is_empty() {
        return Err(format!("empty algorithm list '{list}'"));
    }
    Ok(algos)
}
