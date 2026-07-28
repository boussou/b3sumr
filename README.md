# b3sumr

Compare large folders recursively using BLAKE3 checksum and multithreaded per CPU core

### Started as a Go Implementation of b3rsum forked from b2rsum

A high-performance Go implementation of b3rsum - a recursive BLAKE3 hash calculator and verifier with maximum parallelization using goroutines.

## Features

- **Maximum Parallelization**: Uses goroutines for concurrent file processing
- **Configurable Workers**: Adjustable number of parallel workers (default: number of CPU cores)
- **BLAKE3 Hashing**: Fast and secure BLAKE3 algorithm
- **Compatible Output**: Fully compatible with the bash version and standard hash tools
- **Cross-Platform**: Builds on Linux, macOS, and Windows
- **Untracked Files Detection**: Identify files in the filesystem not present in checksum file
- **Progress Bar**: Visual progress feedback during long-running operations

## Usage

### Creating Checksums

```bash
# Hash all files in current directory recursively
b3sumr

# Hash specific directory
b3sumr /path/to/directory

# Output to custom file
b3sumr -o checksums.txt

# Use more workers for faster processing
b3sumr -j 16

# Show progress bar during hashing
b3sumr --progress-bar

# Custom progress update interval (0.5 seconds)
b3sumr --progress-bar --interval 0.5
```

### Verifying Checksums

```bash
# Check using default BLAKE3SUMS file
b3sumr -c

# Check using custom checksum file
b3sumr -c checksums.txt

# Show files in filesystem not present in checksum file
b3sumr -c --show-untracked

# Quiet mode (only show failures)
b3sumr -c -q

# Very quiet mode (only exit code)
b3sumr -c -s

# Check with progress bar
b3sumr -c --progress-bar

# Check with progress bar (overrides quiet mode)
b3sumr -c -q --progress-bar
```

### Progress Bar

The `--progress-bar` flag shows a percentage-based progress bar during both creating and checking modes:

- Displays `[####------] 42.0% (230542/548789)` format
- Updates at the interval specified by `--interval` (default: 1.0 second)
- Works with both create mode and check mode (`-c`)
- Can override `-q` (quiet mode) when explicitly requested
- Suppressed by `-s` (status mode)

### Check Mode Options

- `--show-untracked`: Display files present in the filesystem but not listed in the BLAKE3SUMS file. Useful for detecting new or untracked files.
- `--ignore-missing`: Don't fail for files listed in checksum file but missing from filesystem
- `--strict`: Exit with non-zero status for improperly formatted checksum lines
- `-w, --warn`: Warn about improperly formatted checksum lines

## Flags Reference

| Flag | Description |
|------|-------------|
| `-c, --check` | Read BLAKE3 sums from files and check them |
| `-o[FILE], --output[=FILE]` | Output to FILE (default: BLAKE3SUMS) |
| `-q, --quiet` | Quiet mode: suppress most messages |
| `-s, --status` | Very quiet mode: only exit code indicates status |
| `-b, --binary` | Read in binary mode |
| `-t, --text` | Read in text mode (default) |
| `--tag` | Create BSD-style checksum |
| `-l, --length` | Digest length in bits (default: 256) |
| `-j, --jobs` | Number of parallel workers (default: CPU count) |
| `-i, --interval` | Progress update interval in seconds (default: 1.0, 0 to disable) |
| `--progress-bar` | Show percentage progress bar |

## Renamed the executable

To avoid confusion with the original bash script which makes use of the CLI tool `b3sum`.

## Why rewriting it in Go?

b2rsum is very portable among Linux distros & versions, because b2sum is quite old & available.

But I struggled to make my b3rsum version work on old Debian (Debian 9, Debian 10, current is Debian 13) because you have
to compile b3sum from the sourcecode, and then you face compatibilities issues between Rust versions & b3sum dependencies.

And if you try to copy the binary => most of the time you get shared libraries dependencies failures (ie. libc version).

So I decided I needed a Go version, so that even when that happens, I still can **just copy the executable**,
since Go insures the binary is always standalone. And because on top of that there is a **BLAKE3 lib** in Go, so no need to exec the b3sum.

### Build

Use make

Or directly rebuild with `go build -o b3sumr main.go`
