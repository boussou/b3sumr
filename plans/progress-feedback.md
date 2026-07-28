# Progress Feedback Plan for b3sumr

## Overview

Add periodic status updates to stderr during file processing, showing how many files have been processed and elapsed time.

## Design

### 1. New Configuration Option

Add to [`Config`](main.go:22) struct:

```go
type Config struct {
    // ... existing fields ...
    interval float64  // seconds between progress updates
}
```

New flag:
- `-i, --interval float` — progress update interval in seconds (default: 1.0)

### 2. Thread-Safe Counters

Use `sync/atomic` counters in `resultCollector` to track:
- `processedCount` — number of successfully hashed files
- `errorCount` — number of files with errors
- `totalCount` — total files encountered

These counters are updated atomically in the result loop (line 329-352), making them safe for concurrent access from the progress ticker.

### 3. Progress Ticker Implementation

A goroutine using `time.NewTicker` that:
- Runs every `interval` seconds while processing is active
- Reads atomic counters and prints progress to stderr
- Format: `"Processed 500 files in 2.3s (250 files/s, 10 errors)"`
- Stops when a channel signal is received

### 4. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        createMode / checkMode                │
│                                                              │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  File     │    │  Worker      │    │  Result          │   │
│  │  Walker   │───>│  Pool        │───>│  Collector       │   │
│  │  Goroutine│    │  Goroutines  │    │  Goroutine       │   │
│  └──────────┘    └──────────────┘    └────────┬─────────┘   │
│                                               │              │
│                    ┌──────────────────────────┘              │
│                    │                                         │
│                    ▼                                         │
│            ┌───────────────┐    ┌─────────────────────┐     │
│            │  Progress     │<───│  Atomic Counters    │     │
│            │  Ticker       │    │  (sync/atomic)      │     │
│            │  Goroutine    │    │                     │     │
│            └───────┬───────┘    └─────────────────────┘     │
│                    │                                         │
│                    ▼                                         │
│            stderr: "Processed N files in Xs"                 │
└─────────────────────────────────────────────────────────────┘
```

### 5. Data Flow

```
File Walker ──jobs──> [Worker Pool] ──results──> Result Collector
                                                        │
                                                        ▼
                                               Atomic Counters
                                                        │
                                                        ▼
                                               Progress Ticker (every N seconds)
                                                        │
                                                        ▼
                                                   stderr output
```

### 6. Implementation Details

#### Changes to `Config` struct (line 22-36):

```go
type Config struct {
    // ... existing fields ...
    interval float64  // seconds between progress updates
}
```

#### Changes to `parseFlags` (line 85-155):

```go
flag.Float64Var(&config.interval, "i", 1.0, "progress update interval in seconds")
flag.Float64Var(&config.interval, "interval", 1.0, "progress update interval in seconds")
```

#### Changes to `resultCollector` (line 311-362):

Add atomic counters:

```go
type HashResult struct {
    hash     string
    filename string
    err      error
}

func resultCollector(results <-chan HashResult, config *Config, wg *sync.WaitGroup) {
    defer wg.Done()
    
    var processedCount, errorCount, totalCount int64
    
    // ... existing code ...
    
    for result := range results {
        atomic.AddInt64(&totalCount, 1)
        if result.err != nil {
            atomic.AddInt64(&errorCount, 1)
            // ... existing error handling ...
            continue
        }
        atomic.AddInt64(&processedCount, 1)
        // ... existing output writing ...
    }
}
```

#### Progress Ticker in `createMode` (after line 179):

```go
// Start progress ticker if interval > 0 and not in quiet/status mode
if config.interval > 0 && !config.quiet && !config.status {
    startProgressTicker(config, processedCount, errorCount, stopChan)
}
```

#### New `startProgressTicker` function:

```go
func startProgressTicker(config *Config, processed, errors *int64, stop <-chan struct{}) {
    ticker := time.NewTicker(time.Duration(config.interval * float64(time.Second)))
    defer ticker.Stop()
    
    startTime := time.Now()
    
    for {
        select {
        case <-ticker.C:
            elapsed := time.Since(startTime).Seconds()
            p := atomic.LoadInt64(processed)
            e := atomic.LoadInt64(errors)
            rate := float64(0)
            if elapsed > 0 {
                rate = float64(p) / elapsed
            }
            fmt.Fprintf(os.Stderr, "\rProcessed %d files in %.1fs (%.0f files/s, %d errors)  ", p, elapsed, rate, e)
        case <-stop:
            // Final newline to clean up the progress line
            fmt.Fprintln(os.Stderr)
            return
        }
    }
}
```

#### Changes to `checkMode` (line 364-471):

Similar progress ticker implementation for check mode, tracking:
- `totalFiles` — total checksums checked
- `okFiles` — files that passed
- `failedFiles` — files that failed

### 7. Output Examples

**createMode:**
```
Using 8 CPU workers
Processed 100 files in 1.0s (100 files/s, 0 errors)  
Processed 250 files in 2.0s (125 files/s, 2 errors)
Processed 500 files in 3.0s (167 files/s, 2 errors)

#### Summary
Total files processed: 523
Files hashed: 521
Files with errors: 2
#### Ended
```

**checkMode:**
```
Reading checksums from BLAKE3SUMS
Processed 100 files in 1.0s (100 files/s, 0 errors)
Processed 250 files in 2.0s (125 files/s, 3 errors)

#### Summary
Total files checked: 300
Files OK: 297
Files FAILED: 3
#### Ended
```

### 8. Edge Cases

1. **interval = 0**: Progress updates disabled
2. **quiet mode (`-q`)**: Progress updates disabled
3. **status mode (`-s`)**: Progress updates disabled
4. **Small file sets**: If processing completes before first tick, no progress shown
5. **Concurrent updates**: Using `sync/atomic` ensures thread safety

### 9. Files Modified

| File | Changes |
|------|---------|
| [`main.go`](main.go:22) | Add `interval` field to `Config` |
| [`main.go`](main.go:85) | Add `--interval` flag in `parseFlags` |
| [`main.go`](main.go:157) | Add progress ticker in `createMode` |
| [`main.go`](main.go:311) | Add atomic counters in `resultCollector` |
| [`main.go`](main.go:364) | Add progress ticker in `checkMode` |
| [`main.go`](main.go:600) | Update help text |

### 10. New Helper Function

Add `startProgressTicker` function that:
- Takes config, atomic counters, and a stop channel
- Uses `time.Ticker` for periodic updates
- Prints progress to stderr with carriage return for in-place updates
- Cleans up with newline on stop
