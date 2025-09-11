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

