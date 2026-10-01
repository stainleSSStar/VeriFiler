use std::io::Read;
use std::path::Path;

use blake2::digest::{Digest, Update};
use blake2::{Blake2b512, Blake2s256};
use blake3::Hasher as Blake3;
use crc32fast::Hasher as Crc32;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

pub const BUF_SIZE: usize = 128 * 1024;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b512,
    Blake2s256,
    Blake3,
    Crc32,
}

pub const ALL: &[Algorithm] = &[
    Algorithm::Md5,
    Algorithm::Sha1,
    Algorithm::Sha256,
    Algorithm::Sha512,
    Algorithm::Sha3_256,
    Algorithm::Sha3_512,
    Algorithm::Blake2b512,
    Algorithm::Blake2s256,
    Algorithm::Blake3,
    Algorithm::Crc32,
];

impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Md5 => "md5",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha3_256 => "sha3-256",
            Algorithm::Sha3_512 => "sha3-512",
            Algorithm::Blake2b512 => "blake2b-512",
            Algorithm::Blake2s256 => "blake2s-256",
            Algorithm::Blake3 => "blake3",
            Algorithm::Crc32 => "crc32",
        }
    }

    pub fn from_name(name: &str) -> Result<Algorithm, String> {
        let lower = name.trim().to_ascii_lowercase();
        ALL.iter()
            .find(|a| a.name() == lower)
            .copied()
            .ok_or_else(|| {
                format!(
                    "unknown algorithm '{name}' (supported: {})",
                    supported_names()
                )
            })
    }

    pub fn validate_hash(&self, hash: &str) -> Result<String, String> {
        let length = match self {
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
                "{} requires {length} hexadecimal digits",
                self.name()
            ));
        }
        Ok(hash.to_ascii_lowercase())
    }
}

pub fn supported_names() -> String {
    ALL.iter().map(|a| a.name()).collect::<Vec<_>>().join(", ")
}

pub fn open_regular(path: &Path) -> Result<std::fs::File, String> {
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("cannot access '{}': {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file", path.display()));
    }
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open '{}': {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("'{}' is not a regular file", path.display()));
    }
    Ok(file)
}

pub fn digest_file_hex(path: &Path, algos: &[Algorithm]) -> Result<Vec<String>, String> {
    if path == Path::new("-") {
        return digest_reader_hex(&mut std::io::stdin().lock(), algos).map(|(hashes, _)| hashes);
    }
    let mut reader = open_regular(path)?;
    let before = reader.metadata().map_err(|e| e.to_string())?;
    let identity = same_file::Handle::from_file(reader.try_clone().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let (hashes, bytes_read) = digest_reader_hex(&mut reader, algos)?;
    validate_snapshot(path, &reader, &before, &identity, bytes_read)?;
    Ok(hashes)
}

fn validate_snapshot(
    path: &Path,
    reader: &std::fs::File,
    before: &std::fs::Metadata,
    identity: &same_file::Handle,
    bytes_read: u64,
) -> Result<(), String> {
    let after = reader.metadata().map_err(|e| e.to_string())?;
    let current = std::fs::metadata(path).map_err(|e| {
        format!(
            "input '{}' became unavailable while hashing: {e}",
            path.display()
        )
    })?;
    if !current.is_file()
        || before.len() != bytes_read
        || after.len() != bytes_read
        || before.modified().ok() != after.modified().ok()
        || before.modified().ok() != current.modified().ok()
        || current.len() != bytes_read
        || same_file::Handle::from_path(path).map_err(|e| e.to_string())? != *identity
    {
        return Err(format!(
            "'{}' changed while checksums were being calculated",
            path.display()
        ));
    }
    Ok(())
}

fn digest_reader_hex(
    reader: &mut impl Read,
    algos: &[Algorithm],
) -> Result<(Vec<String>, u64), String> {
    let mut bytes_read = 0u64;
    let mut md5 = algos.contains(&Algorithm::Md5).then(Md5::default);
    let mut sha1 = algos.contains(&Algorithm::Sha1).then(Sha1::default);
    let mut sha256 = algos.contains(&Algorithm::Sha256).then(Sha256::default);
    let mut sha512 = algos.contains(&Algorithm::Sha512).then(Sha512::default);
    let mut sha3_256 = algos.contains(&Algorithm::Sha3_256).then(Sha3_256::default);
    let mut sha3_512 = algos.contains(&Algorithm::Sha3_512).then(Sha3_512::default);
    let mut blake2b = algos
        .contains(&Algorithm::Blake2b512)
        .then(Blake2b512::default);
    let mut blake2s = algos
        .contains(&Algorithm::Blake2s256)
        .then(Blake2s256::default);
    let mut blake3 = algos.contains(&Algorithm::Blake3).then(Blake3::new);
    let mut crc32 = algos.contains(&Algorithm::Crc32).then(Crc32::new);

    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read error: {e}")),
        };
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        let chunk = &buf[..n];
        if let Some(h) = md5.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = sha1.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = sha256.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = sha512.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = sha3_256.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = sha3_512.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = blake2b.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = blake2s.as_mut() {
            Update::update(h, chunk);
        }
        if let Some(h) = blake3.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = crc32.as_mut() {
            h.update(chunk);
        }
    }

    let finish = |a: &Algorithm| -> String {
        match a {
            Algorithm::Md5 => hex(md5.as_ref().unwrap().clone().finalize()),
            Algorithm::Sha1 => hex(sha1.as_ref().unwrap().clone().finalize()),
            Algorithm::Sha256 => hex(sha256.as_ref().unwrap().clone().finalize()),
            Algorithm::Sha512 => hex(sha512.as_ref().unwrap().clone().finalize()),
            Algorithm::Sha3_256 => hex(sha3_256.as_ref().unwrap().clone().finalize()),
            Algorithm::Sha3_512 => hex(sha3_512.as_ref().unwrap().clone().finalize()),
            Algorithm::Blake2b512 => hex(blake2b.as_ref().unwrap().clone().finalize()),
            Algorithm::Blake2s256 => hex(blake2s.as_ref().unwrap().clone().finalize()),
            Algorithm::Blake3 => hex(blake3.as_ref().unwrap().finalize().as_bytes()),
            Algorithm::Crc32 => format!("{:08x}", crc32.as_ref().unwrap().clone().finalize()),
        }
    };
    Ok((algos.iter().map(finish).collect(), bytes_read))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct Choppy<'a> {
        bytes: &'a [u8],
        interrupt: bool,
    }
    impl Read for Choppy<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.bytes.len().min(buf.len()).min(7);
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    #[test]
    fn interrupted_and_short_reads_match_binary_vectors() {
        let mut data = (0..=255u8).cycle().take(256 * 4096).collect::<Vec<_>>();
        data.extend_from_slice(&[0, 255, 128]);
        let mut reader = Choppy {
            bytes: &data,
            interrupt: false,
        };
        let algos: Vec<_> = ALL
            .iter()
            .copied()
            .filter(|a| *a != Algorithm::Blake3)
            .collect();
        let (hashes, count) = digest_reader_hex(&mut reader, &algos).unwrap();
        let expected: Vec<_> = include_str!("../tests/vectors/multichunk.vf")
            .lines()
            .map(|line| line.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(hashes, expected);
        assert_eq!(count, data.len() as u64);
    }

    #[test]
    fn duplicate_algorithms_produce_identical_hashes() {
        let algos: Vec<_> = ALL.iter().chain(ALL).copied().collect();
        let (hashes, count) = digest_reader_hex(&mut &b"abc"[..], &algos).unwrap();
        assert_eq!(&hashes[..ALL.len()], &hashes[ALL.len()..]);
        assert_eq!(count, 3);
    }

    #[test]
    fn read_errors_do_not_return_partial_hashes() {
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        assert!(digest_reader_hex(&mut Fails, ALL)
            .unwrap_err()
            .contains("read failed"));
    }

    #[test]
    fn snapshots_reject_truncation_replacement_and_removal() {
        for scenario in ["truncate", "replace", "remove"] {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("input.bin");
            std::fs::write(&path, b"abc").unwrap();
            let file = open_regular(&path).unwrap();
            let before = file.metadata().unwrap();
            let identity = same_file::Handle::from_file(file.try_clone().unwrap()).unwrap();
            assert!(validate_snapshot(&path, &file, &before, &identity, 3).is_ok());
            match scenario {
                "truncate" => std::fs::write(&path, b"ab").unwrap(),
                "replace" => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::write(&path, b"abc").unwrap();
                    let replacement = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                    replacement
                        .set_modified(before.modified().unwrap())
                        .unwrap();
                    assert_eq!(replacement.metadata().unwrap().len(), before.len());
                }
                _ => std::fs::remove_file(&path).unwrap(),
            }
            assert!(
                validate_snapshot(&path, &file, &before, &identity, 3).is_err(),
                "{scenario}"
            );
        }
    }
}
