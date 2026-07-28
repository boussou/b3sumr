# Two-Pass Percentage Progress Bar for b3sumr

Add an opt-in `--progress-bar` flag that does an initial scan to count total files, then renders an in-place percentage bar (file-count based) during hashing/checking, for both create and check modes, alongside the existing `-i/--interval` ticker.

## New Flag

- `--progress-bar` (bool, default `false`): enables the two-pass percentage bar.
- When set, this takes precedence over `-i/--interval` ticker output (avoid printing both simultaneously) — bar disabled by `-q`/`-s` same as ticker.

## Design

### 1. `Config` struct (`@/home/me/rnd/b3sumr/main.go:24-39`)
- Add `progressBar bool` field.

### 2. `parseFlags` (`@/home/me/rnd/b3sumr/main.go:94-...`)
- `flag.BoolVar(&config.progressBar, "progress-bar", false, "show a two-pass percentage progress bar")`

### 3. Create Mode — Pre-scan Pass
- Before starting workers in `createMode` (`@/home/me/rnd/b3sumr/main.go:157-`), if `config.progressBar` is set:
  - Run a first `filepath.Walk` over `paths` (same regular-file filter as the real pass, skipping dirs/non-regular/output file) purely to count total eligible files.
  - Store as `totalFiles int64`.
  - Skip this pass if a path is `-` (stdin) — bar not meaningful there.
- This doubles the walk cost but is I/O-metadata only (no hashing), acceptable per user's chosen tradeoff.

### 4. Create Mode — Progress Bar Rendering
- Reuse `processedFiles`/`errorFiles` atomic counters already in `resultCollector`.
- New goroutine `startProgressBar(config, processed, errors, total, stop)`:
  - Ticker every `interval` seconds (reuse `config.interval`, default 1.0s, still respects `0` to disable... but `--progress-bar` implies wanting feedback, so treat `interval <= 0` as fallback `1.0s` for the bar specifically).
  - Each tick: compute `pct := float64(processed+errors) / float64(total) * 100`, render `\r[####------] 42% (126/300, 2 errors)` (fixed-width 20-30 char bar) to stderr, no trailing newline.
  - On `stop` signal: print final 100% state (or actual final counts) then `\n` to clean up the line.
- In `resultCollector`, branch: if `config.progressBar` → start `startProgressBar` with pre-scanned total; else if `config.interval > 0` → existing `startProgressTicker` (mutually exclusive).

### 5. Check Mode — Pre-scan Pass
- Before the main verification loop in `checkMode` (`@/home/me/rnd/b3sumr/main.go:364-`), if `config.progressBar` is set:
  - Read through each `hashFile` once with `bufio.Scanner`, counting non-empty/non-`#`/non-`#### Ended` lines → `totalLines int64`.
  - Re-open/re-seek the file(s) afterward for the actual verification pass (for `-` stdin, pre-scan isn't possible — skip bar for stdin input, fall back to ticker or no feedback).
- Reuse `okFiles`/`failedFiles` atomic counters for the bar, same rendering function as create mode.
- Branch similarly: `progressBar` → bar with pre-scanned total; else `interval > 0` → existing ticker.

### 6. Shared Rendering Helper
```go
func renderProgressBar(processed, total int64) string {
    const width = 30
    pct := 0.0
    if total > 0 {
        pct = float64(processed) / float64(total) * 100
    }
    filled := int(float64(width) * pct / 100)
    bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
    return fmt.Sprintf("[%s] %5.1f%% (%d/%d)", bar, pct, processed, total)
}
```
Used by both `startProgressBar` variants (create: processed+errors vs total; check: okFiles+failedFiles vs total).

### 7. Edge Cases
- `total == 0` (empty tree / empty checksum file): bar shows 0%, avoid div-by-zero.
- stdin (`-`) input: no pre-scan possible; progress bar silently skipped (fall back to plain summary, no ticker either, to avoid confusing partial bar).
- `--progress-bar` + `-q`/`-s`: suppressed same as ticker.
- Terminal width: fixed-width bar (30 chars) regardless of actual terminal size (no `golang.org/x/term` dependency added).

## Files Modified

| File | Change |
|------|--------|
| `@/home/me/rnd/b3sumr/main.go` | Add `progressBar` config field + flag |
| `@/home/me/rnd/b3sumr/main.go` | Pre-scan walk in `createMode` |
| `@/home/me/rnd/b3sumr/main.go` | Pre-scan line count in `checkMode` |
| `@/home/me/rnd/b3sumr/main.go` | New `renderProgressBar` + `startProgressBar` helpers |
| `@/home/me/rnd/b3sumr/main.go` | Branch in `resultCollector`/`checkMode` between bar vs ticker |
| `@/home/me/rnd/b3sumr/main.go` | Help text: document `--progress-bar` |

## Testing
- Manual: run `--progress-bar` against a directory with many small files, confirm bar reaches 100% and cleans up before summary.
- Manual: run `-c --progress-bar` against a generated `BLAKE3SUMS` file, confirm bar tracks OK/FAILED counts.
- Confirm `-q`/`-s` suppress the bar.
- Confirm stdin (`-`) input doesn't crash (bar skipped).
