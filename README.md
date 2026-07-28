# b3rsum (Go Implementation)

A high-performance Go implementation of b3rsum with maximum parallelization using goroutines.

## Features

- **Maximum Parallelization**: Uses goroutines and channels for concurrent file processing
- **Configurable Workers**: Adjustable number of worker goroutines (default: number of CPU cores)
- **Wide Go Version Compatibility**: Works with Go 1.7.4 (Debian 9) through modern Go versions
- **No External Dependencies**: Uses the `b3sum` command-line tool for hashing
- **Full Compatibility**: Same command-line interface and output format as the bash version
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Dependencies

- Go 1.7.4 or later (tested with Go 1.7.4 on Debian 9 and Go 1.19.8 on Debian 12)
- `b3sum` command-line tool (BLAKE3 reference implementation)

## Performance Benefits

This Go implementation provides significant performance improvements over the bash version:

- **Concurrent File Processing**: Multiple files are hashed simultaneously using goroutines
- **Worker Pool Pattern**: Efficient resource utilization with configurable worker count
- **Native BLAKE3**: Uses optimized BLAKE3 implementation
- **Memory Efficient**: Streaming hash calculation without loading entire files into memory

## Building

### Prerequisites

- Go 1.21 or later
- Internet connection (for downloading dependencies)

### Installation

1. Install the `b3sum` command-line tool:
```bash
# On Debian/Ubuntu
sudo apt install b3sum

# Or build from source
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3/b3sum
cargo build --release
sudo cp target/release/b3sum /usr/local/bin/
```

2. Build the Go binary:
```bash
make build
```

3. Install system-wide (optional):
```bash
sudo make install
```

Note: This implementation does not use Go modules and is compatible with older Go versions including Go 1.7.4 (Debian 9).

## Usage

The Go version maintains full compatibility with the bash version:

```bash
# Hash current directory
./b3rsum

# Hash specific files/directories
./b3rsum /path/to/file /path/to/directory

# Use custom number of workers
./b3rsum -j 8 /path/to/directory

# Check existing hash file
./b3rsum -c BLAKE3SUMS

# Output to file
./b3rsum -o output.txt /path/to/directory
```

## Performance Tuning

### Worker Count

The `-j` or `--jobs` flag controls the number of parallel workers:

```bash
# Use 16 workers (good for I/O bound workloads)
./b3rsum -j 16 /large/directory

# Use number of CPU cores (default)
./b3rsum /directory

# Use single worker (sequential processing)
./b3rsum -j 1 /directory
```

### Recommendations

- **SSD Storage**: Use worker count = 2-4x CPU cores
- **HDD Storage**: Use worker count = CPU cores or less
- **Network Storage**: Start with CPU cores, adjust based on network latency
- **Memory Constrained**: Reduce worker count to avoid memory pressure

## Architecture

The Go implementation uses several concurrent components:

1. **Directory Walker**: Traverses directory trees and queues file jobs
2. **Worker Pool**: Configurable number of goroutines that hash files in parallel
3. **Result Collector**: Aggregates results and handles output formatting
4. **Channel Communication**: Efficient job distribution and result collection

## Compatibility

- **Output Format**: Identical to bash version and standard hash tools
- **Command Line**: Same flags and options as bash version
- **Hash Files**: Can check hash files created by bash version and vice versa

## Development

```bash
# Format code
make fmt

# Run static analysis
make vet

# Run tests
make test

# Clean build artifacts
make clean
```
