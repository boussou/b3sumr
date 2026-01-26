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
```

### Check Mode Options

- `--show-untracked`: Display files present in the filesystem but not listed in the BLAKE3SUMS file. Useful for detecting new or untracked files.
- `--ignore-missing`: Don't fail for files listed in checksum file but missing from filesystem
- `--strict`: Exit with non-zero status for improperly formatted checksum lines
- `-w, --warn`: Warn about improperly formatted checksum lines

## Renamed the executable

To avoid confusion with the original bash script which makes use of the CLI tool `b3sum`.

## Why rewriting it in Go?

b2rsum is very portable among Linux distros & versions, because b2sum is quite old & available.

But I struggled to make my  b3rsum version work on old Debian (Debian 9, Debian 10, current is Debian 13) because you have 
to compile b3sum from the sourcecode, and then you face compatibilities issues between Rust versions & b3sum dependencies.

And if you try to copy the binary => most of the time you get shared libraries dependencies failures (ie. libc version).

So I decided I needed a Go version, so that even when that happens, I still can **just copy the executable**, 
since Go insures the binary is always standalone. And because on top of that there is a **BLAKE3 lib** in Go, so no need to exec the b3sum.


### Build 

Use make 

Or directly rebuild with `go build -o b3sumr main.go`

