# VeriFiler

Portable, fast, low-memory console tool for file integrity verification.

VeriFiler computes checksums of any file with popular algorithms and writes a small text *manifest*. Anyone who later downloads that file can feed it — together with the manifest — back to VeriFiler to confirm the file is intact.

## Features

- **All popular algorithms**: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b-512, BLAKE2s-256, BLAKE3, CRC32
- **Streaming**: single pass over the file with a 128 KB buffer — constant ~2 MB RAM regardless of file size (verified on a 2 GB file)
- **Fast**: all algorithms computed in one disk pass (both `calculate` and `verify`)
- **Portable**: a single static binary, no runtime libraries required (Rust, no system dependencies)
- **Console output**: results are always available in the terminal; `verify` prints `OK`/`FAIL` per algorithm and a clear final verdict

## Installation

Requires only the Rust toolchain:

```sh
cargo build --release
# binary: target/release/verifiler
```

Or install directly:

```sh
cargo install --path .
```

## Usage

### Calculate

```sh
# Compute all algorithms and write manifest to file (also prints to console)
verifiler calculate myfile.iso -o myfile.iso.vf

# Compute and print to stdout only (no manifest file)
verifiler calculate myfile.iso

# Only selected algorithms, quiet (manifest only, no console output)
verifiler calculate myfile.iso -o checksums.txt -a md5,sha256,blake3 -q
```

### Verify

```sh
# Check downloaded file against manifest (e.g. after downloading from the internet)
verifiler verify myfile.iso myfile.iso.vf
```

Output example:

```
OK       md5 e5c9b7be5d42cb48a7c2df30c5a305d8
OK       sha256 e9dacdd20ce34559da69c69bc9ac0258b8433622953fa59a68642324baa77606
...
10/10 checksums matched: file is intact
```

Exit codes: `0` intact, `1` corrupted/verification error, `2` usage error.

### Manifest format

Plain text, one `<algorithm> <hex_digest>` pair per line:

```
md5 e5c9b7be5d42cb48a7c2df30c5a305d8
sha256 e9dacdd20ce34559da69c69bc9ac0258b8433622953fa59a68642324baa77606
blake3 bacdd199e7e3fe180bc0c718f07c2dab9d0daee89555692dd28ec64f34728a3a
```

The manifest can be edited manually (e.g. keep only the algorithms you trust), transferred alongside the file, and read back by `verify` on any machine. `#`-prefixed lines and blank lines are ignored.

## Typical workflow

1. **Sender**: `verifiler calculate bigfile.zip -o bigfile.zip.vf` and publish both files.
2. **Receiver**: download both, then `verifiler verify bigfile.zip bigfile.zip.vf`.
3. Exit code `0` and `file is intact` → the downloaded copy is byte-for-byte identical.

## Performance & memory

Measured on a 2 GB file (all 10 algorithms, single pass):

| Metric | Value |
|---|---|
| Peak RAM | ~2.5 MB |
| Throughput | ~60 MB/s (all 10 algorithms combined, non-parallel) |
| Disk reads | 1 pass for `calculate`, 1 pass for `verify` |

## Development

```sh
cargo test --release    # integration tests (roundtrip, corruption, CLI)
```

## License

MIT
