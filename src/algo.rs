use std::io::Read;

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
            .ok_or_else(|| format!("unknown algorithm '{name}' (supported: {})", supported_names()))
    }
}

pub fn supported_names() -> String {
    ALL.iter().map(|a| a.name()).collect::<Vec<_>>().join(", ")
}

pub fn digest_file_hex(path: &str, algos: &[Algorithm]) -> Result<Vec<String>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
    let mut reader = std::io::BufReader::with_capacity(BUF_SIZE, file);

    let mut md5 = algos.contains(&Algorithm::Md5).then(Md5::default);
    let mut sha1 = algos.contains(&Algorithm::Sha1).then(Sha1::default);
    let mut sha256 = algos.contains(&Algorithm::Sha256).then(Sha256::default);
    let mut sha512 = algos.contains(&Algorithm::Sha512).then(Sha512::default);
    let mut sha3_256 = algos.contains(&Algorithm::Sha3_256).then(Sha3_256::default);
    let mut sha3_512 = algos.contains(&Algorithm::Sha3_512).then(Sha3_512::default);
    let mut blake2b = algos.contains(&Algorithm::Blake2b512).then(Blake2b512::default);
    let mut blake2s = algos.contains(&Algorithm::Blake2s256).then(Blake2s256::default);
    let mut blake3 = algos.contains(&Algorithm::Blake3).then(Blake3::new);
    let mut crc32 = algos.contains(&Algorithm::Crc32).then(Crc32::new);

    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
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
            Algorithm::Md5 => hex(md5.as_mut().unwrap().finalize_reset()),
            Algorithm::Sha1 => hex(sha1.as_mut().unwrap().finalize_reset()),
            Algorithm::Sha256 => hex(sha256.as_mut().unwrap().finalize_reset()),
            Algorithm::Sha512 => hex(sha512.as_mut().unwrap().finalize_reset()),
            Algorithm::Sha3_256 => hex(sha3_256.as_mut().unwrap().finalize_reset()),
            Algorithm::Sha3_512 => hex(sha3_512.as_mut().unwrap().finalize_reset()),
            Algorithm::Blake2b512 => hex(blake2b.as_mut().unwrap().finalize_reset()),
            Algorithm::Blake2s256 => hex(blake2s.as_mut().unwrap().finalize_reset()),
            Algorithm::Blake3 => hex(blake3.as_ref().unwrap().finalize().as_bytes()),
            Algorithm::Crc32 => format!("{:08x}", crc32.as_ref().unwrap().clone().finalize()),
        }
    };
    Ok(algos.iter().map(finish).collect())
}

pub fn crc32_hex(path: &str) -> Result<String, String> {
    digest_file_hex(path, &[Algorithm::Crc32]).map(|v| v[0].clone())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}
