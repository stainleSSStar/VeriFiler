use std::io::{BufRead, Write};

use crate::algo::Algorithm;

pub struct ManifestEntry {
    pub algorithm: String,
    pub hash: String,
}

pub fn parse_manifest(path: &str) -> Result<Vec<ManifestEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read error at line {}: {e}", idx + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (algorithm, hash) = trimmed
            .split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| format!("line {}: expected '<algorithm> <digest>', got '{trimmed}'", idx + 1))?;
        let algorithm = algorithm.trim().to_ascii_lowercase();
        let hash = hash.trim().to_ascii_lowercase();
        Algorithm::from_name(&algorithm)?;
        if entries.iter().any(|e: &ManifestEntry| e.algorithm == algorithm) {
            continue;
        }
        entries.push(ManifestEntry { algorithm, hash });
    }
    Ok(entries)
}

pub fn write_manifest(path: &str, entries: &[ManifestEntry]) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| format!("cannot create: {e}"))?;
    let mut w = std::io::BufWriter::new(file);
    for e in entries {
        writeln!(w, "{} {}", e.algorithm, e.hash).map_err(|e| format!("write error: {e}"))?;
    }
    w.flush().map_err(|e| format!("write error: {e}"))?;
    Ok(())
}
