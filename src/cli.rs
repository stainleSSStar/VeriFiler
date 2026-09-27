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
        algorithms: Vec<Algorithm>,
    },
}

pub fn print_usage<W: Write>(w: &mut W) {
    let _ = writeln!(
        w,
        "verifiler {} - portable file checksum calculator/verifier

USAGE:
    verifiler calculate <FILE> [-o <MANIFEST>] [-a <ALGO>[,<ALGO>...]] [-q]
    verifiler verify <FILE> <MANIFEST> [-a <ALGO>[,<ALGO>...]]
    verifiler help
    verifiler version

COMMANDS:
    calculate    Compute checksums of FILE and write them to MANIFEST,
                 or to stdout if -o is not given. Without -a all supported
                 algorithms are computed.
    verify       Check FILE against the checksums in MANIFEST and report
                 whether the file is intact. Without -a every checksum
                 found in the manifest is checked; with -a only the listed
                 algorithms are checked (they must exist in the manifest).
    help         Show this help.
    version      Show version.

OPTIONS:
    -o, --output <PATH>    (calculate) Manifest file to write (default: stdout)
    -a, --algos <LIST>     Comma-separated algorithm names; may be repeated
                           (e.g. -a md5,sha256 -a blake3). Default: all.
                           Supported: {algs}
    -q, --quiet            (calculate) Do not print checksums to the console
                           when writing a manifest file

OUTPUT:
    calculate writes lines of '<algorithm> <hex_digest>', e.g.:
        sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    verify prints one line per checked algorithm:
        OK       <algorithm> <digest>
        FAIL     <algorithm> expected=<expected> actual=<actual>
    followed by a summary. Exit codes:
        0  success (file intact)
        1  verification failed (corrupted file) or runtime error
        2  usage error

MANIFEST:
    A plain text file, one '<algorithm> <digest>' pair per line:
        md5 e5c9b7be5d42cb48a7c2df30c5a305d8
        sha256 e9dacdd20ce34559da69c69bc9ac0258b8433622953fa59a68642324baa77606
    Blank lines and lines starting with '#' are ignored. The manifest can be
    edited manually, transferred alongside the file, and fed back to 'verify'
    on any machine.

EXAMPLES:
    verifiler calculate myfile.iso                          all algos to stdout
    verifiler calculate myfile.iso -o my.vf                 all algos to manifest
    verifiler calculate myfile.iso -o my.vf -a md5,sha256   only md5 and sha256
    verifiler verify myfile.iso my.vf                       check everything
    verifiler verify myfile.iso my.vf -a sha256             check only sha256
    verifiler verify myfile.iso my.vf -a md5,blake3         check md5 and blake3",
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
                        algorithms = merge(algorithms, parse_algo_list(list)?);
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
            let mut file: Option<String> = None;
            let mut manifest: Option<String> = None;
            let mut algorithms: Vec<Algorithm> = Vec::new();
            let rest: Vec<String> = it.cloned().collect();
            let mut i = 0;
            while i < rest.len() {
                let a = &rest[i];
                match a.as_str() {
                    "-a" | "--algos" => {
                        i += 1;
                        let list = rest
                            .get(i)
                            .ok_or_else(|| "missing value for -a/--algos".to_string())?;
                        algorithms = merge(algorithms, parse_algo_list(list)?);
                    }
                    _ => {
                        if file.is_some() && manifest.is_some() {
                            return Err(format!("unexpected argument '{a}'"));
                        }
                        if file.is_some() {
                            manifest = Some(a.clone());
                        } else {
                            file = Some(a.clone());
                        }
                    }
                }
                i += 1;
            }
            let file =
                file.ok_or_else(|| "verify requires two arguments: FILE MANIFEST".to_string())?;
            let manifest =
                manifest.ok_or_else(|| "verify requires two arguments: FILE MANIFEST".to_string())?;
            Ok(Command::Verify { file, manifest, algorithms })
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

fn merge(mut algos: Vec<Algorithm>, more: Vec<Algorithm>) -> Vec<Algorithm> {
    for a in more {
        if !algos.contains(&a) {
            algos.push(a);
        }
    }
    algos
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
