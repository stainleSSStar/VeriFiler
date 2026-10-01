# VeriFiler

Portable, fast, low-memory console tool for file integrity verification.

VeriFiler computes checksums of any file with popular algorithms and writes a small text *manifest*. Anyone who later downloads that file can feed it — together with the manifest — back to VeriFiler to confirm the file is intact.

## Quick start

### Option A — download a ready binary (no build required)

Go to the [**Releases**](https://github.com/stainleSSStar/VeriFiler/releases) page and download the archive for your system:

| File | System |
|---|---|
| `verifiler-*-linux-x64.tar.gz` | Linux (Intel/AMD 64-bit) |
| `verifiler-*-linux-arm64.tar.gz` | Linux (ARM 64-bit, e.g. Raspberry Pi 4/5) |
| `verifiler-*-macos-x64.tar.gz` | macOS (Intel) |
| `verifiler-*-macos-arm64.tar.gz` | macOS (Apple Silicon M1/M2/M3/M4) |
| `verifiler-*-windows-x64.zip` | Windows 64-bit |

Then unpack and test:

**Linux / macOS:**
```sh
tar -xzf verifiler-*-linux-x64.tar.gz
./verifiler help
./verifiler calculate README.md          # checksums of any file, printed to console
```

**Windows (PowerShell):**
```powershell
Expand-Archive verifiler-*-windows-x64.zip
.\verifiler.exe help
.\verifiler.exe calculate README.md
```

> Releases are attached to git tags (`v0.1.0`, …). Until the first tag exists, CI still produces binaries on every push — grab them from **Actions → latest run → Artifacts** (the `x86_64-unknown-linux-gnu` artifact contains the `tar.gz`). You need to be logged in to GitHub to download artifacts.

### Option B — build from source

**Step 1: install the Rust toolchain** (the only requirement; works on Linux, macOS and Windows):

Go to [https://rustup.rs](https://rustup.rs) and follow the instructions, or run:

**Linux / macOS:**
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

**Windows:** download and run [rustup-init.exe](https://win.rustup.rs/x86_64), accept the defaults, then open a new terminal.

Verify the installation:
```sh
rustc --version    # should print e.g. rustc 1.xx.x
cargo --version
```

**Step 2: get the source:**
```sh
git clone https://github.com/stainleSSStar/VeriFiler.git
cd VeriFiler
```

**Step 3: build:**
```sh
cargo build --release
```
The binary appears at `target/release/verifiler` (Linux/macOS) or `target\release\verifiler.exe` (Windows). It is fully self-contained — only the standard system libraries are needed, nothing else to install.

**Step 4 (optional): make it available everywhere:**
```sh
cargo install --path .    # installs to ~/.cargo/bin/verifiler
```

### Your first test (60 seconds)

```sh
# 1. Pick or create any file
echo "hello integrity" > test.txt

# 2. Calculate all checksums into a manifest
verifiler calculate test.txt -o test.txt.vf

# 3. Verify the intact file — passes
verifiler verify test.txt test.txt.vf
# -> OK lines, "10/10 checksums matched: file is intact", exit code 0

# 4. Corrupt the file (simulate a broken download) and verify again
echo "hello integrity CORRUPTED" > test.txt
verifiler verify test.txt test.txt.vf
# -> FAIL lines, "0/10 checksums matched: file is CORRUPTED", exit code 1

# 5. Check only selected algorithms
verifiler verify test.txt test.txt.vf -a sha256
verifiler calculate test.txt -a md5,sha512
```

Full command reference: `verifiler help`.

## Features

- **All popular algorithms**: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b-512, BLAKE2s-256, BLAKE3, CRC32
- **Algorithm selection**: both `calculate` and `verify` accept `-a <ALGO>[,<ALGO>...]` to use only the algorithms you want; without the flag, `calculate` uses all algorithms and `verify` checks every entry in the manifest
- **Streaming**: single pass over the file with a 128 KB buffer — bounded memory regardless of file size
- **Fast**: all selected algorithms computed in one disk pass (both `calculate` and `verify`)
- **Portable**: a single executable with no separately installed Rust runtime; builds use standard platform libraries (Linux binaries require a compatible glibc)
- **Console output**: results are always available in the terminal; `verify` prints `OK`/`FAIL` per algorithm and a clear final verdict
- **Built-in help**: `verifiler help` explains every command, option, algorithm and exit code

## Usage

```
USAGE:
    verifiler calculate <FILE> [-o <MANIFEST>] [-a <ALGO>[,<ALGO>...]] [-q]
    verifiler verify <FILE> <MANIFEST> [-a <ALGO>[,<ALGO>...]]
    verifiler help
    verifiler version
```

### Calculate

```sh
# All algorithms, write manifest to file (also prints to console)
verifiler calculate myfile.iso -o myfile.iso.vf

# All algorithms, print to stdout only (no manifest file)
verifiler calculate myfile.iso

# Only selected algorithms (single or comma-separated list)
verifiler calculate myfile.iso -a md5
verifiler calculate myfile.iso -o checksums.txt -a md5,sha256,blake3 -q
```

### Verify

```sh
# Check downloaded file against the manifest (e.g. after downloading from the internet)
verifiler verify myfile.iso myfile.iso.vf

# Verify only selected algorithm(s); they must exist in the manifest
verifiler verify myfile.iso myfile.iso.vf -a sha256
verifiler verify myfile.iso myfile.iso.vf -a md5,blake3
```

Output example (`verify myfile.iso myfile.iso.vf -a md5,sha256`):

```
OK       md5 e5c9b7be5d42cb48a7c2df30c5a305d8
OK       sha256 e9dacdd20ce34559da69c69bc9ac0258b8433622953fa59a68642324baa77606
2/2 checksums matched: file is intact
```

Exit codes: `0` success, `1` checksum mismatch or runtime error, `2` usage error.

### Supported algorithms

`md5`, `sha1`, `sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b-512`, `blake2s-256`, `blake3`, `crc32`

### Manifest format

Plain text, one `<algorithm> <hex_digest>` pair per line:

```
md5 e5c9b7be5d42cb48a7c2df30c5a305d8
sha256 e9dacdd20ce34559da69c69bc9ac0258b8433622953fa59a68642324baa77606
blake3 bacdd199e7e3fe180bc0c718f07c2dab9d0daee89555692dd28ec64f34728a3a
```

The manifest can be edited manually (e.g. keep only the algorithms you trust), transferred alongside the file, and read back by `verify` on any machine. `#`-prefixed lines and blank lines are ignored. UTF-8 BOM, CRLF, and uppercase algorithm names/digests are accepted. Each checksum must have exactly the expected number of hexadecimal digits. Duplicate algorithms, extra fields, invalid UTF-8, and lines longer than 4096 bytes are rejected, including when `verify -a` selects only part of the manifest.

## Typical workflow

1. **Sender**: `verifiler calculate bigfile.zip -o bigfile.zip.vf` and publish both files.
2. **Receiver**: download both, then `verifiler verify bigfile.zip bigfile.zip.vf`
   (or check just one algorithm: `verifiler verify bigfile.zip bigfile.zip.vf -a sha256`).
3. Exit code `0` and `file is intact` → every selected checksum matches the manifest. Use a trusted manifest and a strong algorithm such as SHA-256 or BLAKE3 when checking untrusted downloads. CRC32, MD5, and SHA-1 do not establish authenticity.

## File handling

- All selected checksums, including CRC32, are computed during one read of the file.
- Inputs and manifests must be regular files. Inputs may be symlinks to regular files.
- The manifest output must differ from the input, including hard links. Output symlinks are rejected.
- Manifest output is written and synced to a temporary file in the destination directory, then atomically replaces the destination. A failed write leaves the previous manifest intact.
- Observable length or modification-time changes while hashing cause an error. This is a best-effort check; files should remain unchanged during calculation/verification.
- Use `--` before positional filenames that start with `-`; for `-o`, use a path such as `./-manifest.vf`.
- File paths need not be UTF-8 on Unix.

## Performance & memory

Hashing uses a fixed 128 KB buffer and one state per selected algorithm. Manifest parsing caps each line at 4096 bytes and allows at most one entry for each of the ten algorithms. Throughput depends on the selected algorithms, CPU, and storage; no benchmark is implied by these bounds.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --release --locked
```

CI (`.github/workflows/build.yml`) runs the test suite on Linux, macOS and Windows, and builds release archives for 5 platforms on every branch push and pull request; tagging a release (`v*`) uploads the binaries to a draft GitHub Release.

## License

MIT
