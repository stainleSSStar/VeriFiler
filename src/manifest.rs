use std::io::{BufRead, Read, Write};
use std::path::Path;

use crate::algo::{self, Algorithm};

pub struct ManifestEntry {
    pub algorithm: String,
    pub hash: String,
}

pub fn parse_manifest(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let file = algo::open_regular(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    let mut idx = 0;
    loop {
        let mut bytes = Vec::new();
        let n = reader
            .by_ref()
            .take(4097)
            .read_until(b'\n', &mut bytes)
            .map_err(|e| format!("read error at line {}: {e}", idx + 1))?;
        if n == 0 {
            break;
        }
        idx += 1;
        if n > 4096 {
            return Err(format!("line {idx}: exceeds 4096 bytes"));
        }
        let line =
            std::str::from_utf8(&bytes).map_err(|e| format!("line {idx}: invalid UTF-8: {e}"))?;
        let line = if idx == 1 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_ascii_whitespace();
        let algorithm = fields.next().unwrap().to_ascii_lowercase();
        let hash = fields
            .next()
            .ok_or_else(|| format!("line {idx}: expected '<algorithm> <digest>'"))?
            .to_ascii_lowercase();
        if fields.next().is_some() {
            return Err(format!("line {idx}: expected exactly two fields"));
        }
        let algo = Algorithm::from_name(&algorithm).map_err(|e| format!("line {idx}: {e}"))?;
        let length = match algo {
            Algorithm::Md5 => 32,
            Algorithm::Sha1 => 40,
            Algorithm::Sha256 | Algorithm::Sha3_256 | Algorithm::Blake2s256 | Algorithm::Blake3 => {
                64
            }
            Algorithm::Sha512 | Algorithm::Sha3_512 | Algorithm::Blake2b512 => 128,
            Algorithm::Crc32 => 8,
        };
        if hash.len() != length || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "line {idx}: {algorithm} requires {length} hexadecimal digits"
            ));
        }
        if entries
            .iter()
            .any(|e: &ManifestEntry| e.algorithm == algorithm)
        {
            return Err(format!("line {idx}: duplicate algorithm '{algorithm}'"));
        }
        entries.push(ManifestEntry { algorithm, hash });
    }
    Ok(entries)
}

pub fn check_output(input: &Path, output: &Path) -> Result<(), String> {
    let input_meta = std::fs::metadata(input)
        .map_err(|e| format!("cannot access '{}': {e}", input.display()))?;
    if !input_meta.is_file() {
        return Err(format!("'{}' is not a regular file", input.display()));
    }
    match std::fs::symlink_metadata(output) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(format!(
                    "manifest output '{}' is not a regular file (symlinks are not allowed)",
                    output.display()
                ));
            }
            if same_file::is_same_file(input, output).map_err(|e| e.to_string())? {
                return Err("manifest output is the input file; refusing to overwrite it".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot access '{}': {e}", output.display())),
    }
    Ok(())
}

pub fn write_manifest(input: &Path, path: &Path, entries: &[ManifestEntry]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("cannot create: {e}"))?;
    {
        let mut w = std::io::BufWriter::new(temp.as_file_mut());
        for e in entries {
            writeln!(w, "{} {}", e.algorithm, e.hash).map_err(|e| format!("write error: {e}"))?;
        }
        w.flush().map_err(|e| format!("write error: {e}"))?;
    }
    temp.as_file()
        .sync_all()
        .map_err(|e| format!("sync error: {e}"))?;
    check_output(input, path)?;
    temp.persist(path)
        .map_err(|e| format!("cannot replace manifest: {e}"))?;
    Ok(())
}
