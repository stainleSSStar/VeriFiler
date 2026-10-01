use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;

use crate::algo::{self, Algorithm};

pub enum Command {
    Help,
    Version,
    Calculate {
        file: PathBuf,
        output: Option<PathBuf>,
        algorithms: Vec<Algorithm>,
        quiet: bool,
    },
    Verify {
        file: PathBuf,
        manifest: PathBuf,
        algorithms: Vec<Algorithm>,
    },
}

pub fn print_usage<W: Write>(w: &mut W) -> std::io::Result<()> {
    writeln!(
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
    -h, --help             Show command help
    --                     End options (allows filenames starting with '-')
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
    )
}

pub fn parse(args: &[OsString]) -> Result<Command, String> {
    let Some(cmd) = args.first() else {
        return Ok(Command::Help);
    };
    let cmd = cmd.to_str().ok_or("command must be UTF-8")?;
    match cmd {
        "help" | "--help" | "-h" | "version" | "--version" | "-V" => {
            if args.len() != 1 {
                return Err("unexpected arguments".into());
            }
            return Ok(if matches!(cmd, "help" | "--help" | "-h") {
                Command::Help
            } else {
                Command::Version
            });
        }
        "calculate" | "verify" => {}
        other => return Err(format!("unknown command '{other}'")),
    }
    let mut files = Vec::new();
    let mut output = None;
    let mut algorithms = Vec::new();
    let mut quiet = false;
    let mut positional = false;
    let mut it = args[1..].iter();
    while let Some(arg) = it.next() {
        if !positional {
            match arg.to_str() {
                Some("--") => {
                    positional = true;
                    continue;
                }
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("-o" | "--output") if cmd == "calculate" => {
                    if output.is_some() {
                        return Err("output specified more than once".into());
                    }
                    output = Some(PathBuf::from(value(&mut it, "-o/--output")?));
                    continue;
                }
                Some("-a" | "--algos") => {
                    let list = value(&mut it, "-a/--algos")?
                        .to_str()
                        .ok_or("algorithm names must be UTF-8")?;
                    algorithms = merge(algorithms, parse_algo_list(list)?);
                    continue;
                }
                Some("-q" | "--quiet") if cmd == "calculate" => {
                    quiet = true;
                    continue;
                }
                _ if arg.to_string_lossy().starts_with('-') => {
                    return Err(format!("unknown option '{}'", arg.to_string_lossy()));
                }
                _ => {}
            }
        }
        files.push(PathBuf::from(arg));
    }
    if cmd == "calculate" {
        if files.len() != 1 {
            return Err("calculate requires exactly one FILE argument".into());
        }
        Ok(Command::Calculate {
            file: files.remove(0),
            output,
            algorithms,
            quiet,
        })
    } else {
        if files.len() != 2 {
            return Err("verify requires exactly two arguments: FILE MANIFEST".into());
        }
        Ok(Command::Verify {
            file: files.remove(0),
            manifest: files.remove(0),
            algorithms,
        })
    }
}

fn value<'a>(it: &mut std::slice::Iter<'a, OsString>, option: &str) -> Result<&'a OsStr, String> {
    let value = it
        .next()
        .ok_or_else(|| format!("missing value for {option}"))?;
    if value.is_empty() || value.to_string_lossy().starts_with('-') {
        return Err(format!(
            "missing value for {option}; use './' for paths starting with '-'"
        ));
    }
    Ok(value)
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
            return Err(format!("empty algorithm name in '{list}'"));
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
