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

