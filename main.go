package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

const (
	version           = "0.2.0"
	defaultOutputFile = "BLAKE3SUMS"
)

type Config struct {
	check         bool
	output        string
	quiet         bool
	status        bool
	binary        bool
	text          bool
	tag           bool
	length        int
	ignoreMissing bool
	strict        bool
	warn          bool
	workers       int
	showUntracked bool
}

type FileJob struct {
	path     string
	baseDir  string
	relative string
}

type HashResult struct {
	hash     string
	filename string
	err      error
}

func main() {
	config := parseFlags()

	if config.workers <= 0 {
		config.workers = runtime.NumCPU()
	}

	if !config.quiet && !config.status {
		fmt.Printf("Using %d CPU workers\n", config.workers)
	}

	args := flag.Args()
	if len(args) == 0 {
		if config.check {
			args = []string{defaultOutputFile} // Use BLAKE3SUMS as default input for check mode
		} else {
			args = []string{"."} // Use current directory for create mode
		}
	}

	var err error
	if config.check {
		err = checkMode(config, args)
	} else {
		err = createMode(config, args)
	}

	if err != nil {
		if !config.status {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func parseFlags() *Config {
	config := &Config{
		workers: runtime.NumCPU(),
	}

	flag.BoolVar(&config.check, "c", false, "read BLAKE3 sums from the FILEs and check them")
	flag.BoolVar(&config.check, "check", false, "read BLAKE3 sums from the FILEs and check them")
	flag.StringVar(&config.output, "o", "", "output to FILE instead of standard output, or BLAKE3SUMS if no FILE specified")
	flag.StringVar(&config.output, "output", "", "output to FILE instead of standard output, or BLAKE3SUMS if no FILE specified")
	flag.BoolVar(&config.quiet, "q", false, "quiet mode")
	flag.BoolVar(&config.quiet, "quiet", false, "quiet mode")
	flag.BoolVar(&config.status, "s", false, "very quiet mode")
	flag.BoolVar(&config.status, "status", false, "very quiet mode")
	flag.BoolVar(&config.binary, "b", false, "read in binary mode")
	flag.BoolVar(&config.binary, "binary", false, "read in binary mode")
	flag.BoolVar(&config.text, "t", false, "read in text mode")
	flag.BoolVar(&config.text, "text", false, "read in text mode")
	flag.BoolVar(&config.tag, "tag", false, "create a BSD-style checksum")
	flag.IntVar(&config.length, "l", 256, "digest length in bits")
	flag.IntVar(&config.length, "length", 256, "digest length in bits")
	flag.BoolVar(&config.ignoreMissing, "ignore-missing", false, "don't fail for missing files")
	flag.BoolVar(&config.strict, "strict", false, "exit non-zero for improperly formatted checksum lines")
	flag.BoolVar(&config.warn, "w", false, "warn about improperly formatted checksum lines")
	flag.BoolVar(&config.warn, "warn", false, "warn about improperly formatted checksum lines")
	flag.BoolVar(&config.showUntracked, "show-untracked", false, "show files in filesystem not present in checksum file")
	flag.IntVar(&config.workers, "j", runtime.NumCPU(), "number of parallel workers")
	flag.IntVar(&config.workers, "jobs", runtime.NumCPU(), "number of parallel workers")

	var showVersion, showHelp, showLicense bool
	flag.BoolVar(&showVersion, "version", false, "show version information and exit")
	flag.BoolVar(&showHelp, "h", false, "show help and exit")
	flag.BoolVar(&showHelp, "help", false, "show help and exit")
	flag.BoolVar(&showLicense, "license", false, "show license and exit")

	// Custom handling for -o without filename
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "-o" && (i+1 >= len(args) || strings.HasPrefix(args[i+1], "-")) {
			// -o is alone or followed by another flag, use default
			config.output = defaultOutputFile
			// Replace -o with -o=BLAKE3SUMS to make flag parsing work
			os.Args[i+1] = "-o=" + defaultOutputFile
			break
		}
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("b3sumr v%s\n", version)
		os.Exit(0)
	}

	if showHelp {
		showHelpText()
		os.Exit(0)
	}

	if showLicense {
		showLicenseText()
		os.Exit(0)
	}

	// Handle output file logic
	if config.output == "" && !config.check {
		// No output specified and not in check mode, use default
		config.output = defaultOutputFile
	}

	return config
}

func createMode(config *Config, paths []string) error {
	if !config.quiet && !config.status {
		fmt.Fprintf(os.Stderr, "b3sumr v%s GPL v3\n\n", version)
		if config.output != "" {
			fmt.Fprintf(os.Stderr, "Saving results in %s\n", config.output)
		}
	}

	// Channel for file jobs
	jobs := make(chan FileJob, 1000)
	results := make(chan HashResult, 1000)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.workers; i++ {
		wg.Add(1)
		go hashWorker(jobs, results, config, &wg)
	}

	// Start result collector goroutine
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go resultCollector(results, config, &collectorWg)

	// Walk directories and send jobs
	go func() {
		defer close(jobs)
		for _, path := range paths {
			if path == "-" {
				// Handle stdin
				hash, err := hashReader(os.Stdin, config)
				if err != nil {
					results <- HashResult{err: err}
				} else {
					results <- HashResult{hash: hash, filename: "-"}
				}
				continue
			}

			err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					if !config.ignoreMissing {
						return err
					}
					return nil
				}

				if info.IsDir() {
					return nil
				}

				// Skip output file
				if config.output != "" && filePath == config.output {
					return nil
				}

				relPath, err := filepath.Rel(".", filePath)
				if err != nil {
					relPath = filePath
				}

				jobs <- FileJob{
					path:     filePath,
					baseDir:  path,
					relative: relPath,
				}
				return nil
			})

			if err != nil {
				results <- HashResult{err: err}
			}
		}
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Wait for result collector to finish
	collectorWg.Wait()

	// After all goroutines have finished, print final message
	// this is intended for (tail -f tracking)
	if config.output != "" {
		f, err := os.OpenFile(config.output, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString("#### Ended\n")
		}
	} else {
		fmt.Println("#### Ended")
	}

	return nil
}

func hashWorker(jobs <-chan FileJob, results chan<- HashResult, config *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		file, err := os.Open(job.path)
		if err != nil {
			results <- HashResult{filename: job.relative, err: err}
			continue
		}

		hash, err := hashReader(file, config)
		file.Close()

		if err != nil {
			results <- HashResult{filename: job.relative, err: err}
		} else {
			results <- HashResult{hash: hash, filename: job.relative}
		}
	}
}

func hashReader(reader io.Reader, config *Config) (string, error) {
	hasher := blake3.New()
	_, err := io.Copy(hasher, reader)
	if err != nil {
		return "", err
	}

	hash := hasher.Sum(nil)

	// Truncate to specified length if needed
	if config.length < 256 && config.length > 0 {
		bitLength := config.length / 8
		if bitLength < len(hash) {
			hash = hash[:bitLength]
		}
	}

	return fmt.Sprintf("%x", hash), nil
}

func resultCollector(results <-chan HashResult, config *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	var output *os.File
	var err error
	var totalFiles, processedFiles, errorFiles int

	if config.output != "" {
		output, err = os.Create(config.output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			return
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	for result := range results {
		totalFiles++
		if result.err != nil {
			errorFiles++
			if !config.status {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.filename, result.err)
			}
			continue
		}

		processedFiles++
		var line string
		if config.tag {
			line = fmt.Sprintf("BLAKE3 (%s) = %s\n", result.filename, result.hash)
		} else {
			mode := " "
			if config.binary {
				mode = "*"
			}
			line = fmt.Sprintf("%s %s%s\n", result.hash, mode, result.filename)
		}

		output.WriteString(line)
	}

	// Display summary
	fmt.Fprintf(os.Stderr, "\n#### Summary\n")
	fmt.Fprintf(os.Stderr, "Total files processed: %d\n", totalFiles)
	fmt.Fprintf(os.Stderr, "Files hashed: %d\n", processedFiles)
	if errorFiles > 0 {
		fmt.Fprintf(os.Stderr, "Files with errors: %d\n", errorFiles)
	}
	fmt.Fprintf(os.Stderr, "#### Ended\n")
}

func checkMode(config *Config, hashFiles []string) error {
	if !config.quiet && !config.status {
		fmt.Fprintf(os.Stderr, "b3sumr v%s GPL v3\n\n", version)
		if len(hashFiles) > 0 {
			fmt.Fprintf(os.Stderr, "Reading checksums from %s\n", hashFiles[0])
		}
		if config.output != "" {
			fmt.Fprintf(os.Stderr, "Saving check results in %s\n", config.output)
		}
	}

	// Setup output file for check results
	var output *os.File
	var err error
	if config.output != "" {
		output, err = os.Create(config.output)
		if err != nil {
			return fmt.Errorf("error creating output file: %v", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	var allOk = true
	var totalFiles, okFiles, failedFiles int
	trackedFiles := make(map[string]bool)

	for _, hashFile := range hashFiles {
		var file *os.File
		var err error

		if hashFile == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(hashFile)
			if err != nil {
				if !config.status {
					fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", hashFile, err)
				}
				allOk = false
				continue
			}
			defer file.Close()
		}

		scanner := bufio.NewScanner(file)
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || line == "#### Ended" {
				continue
			}

			filename := extractFilename(line)
			if filename != "" {
				trackedFiles[filename] = true
			}

			ok := checkLine(line, config, lineNum, hashFile, output)
			totalFiles++
			if ok {
				okFiles++
			} else {
				failedFiles++
				allOk = false
			}
		}

		if err := scanner.Err(); err != nil {
			if !config.status {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", hashFile, err)
			}
			allOk = false
		}
	}

	// Find untracked files if requested
	var untrackedFiles []string
	if config.showUntracked {
		untrackedFiles = findUntrackedFiles(trackedFiles, config)
	}

	// Display summary
	//	if !config.quiet && !config.status {
	fmt.Fprintf(os.Stderr, "\n#### Summary\n")
	fmt.Fprintf(os.Stderr, "Total files checked: %d\n", totalFiles)
	fmt.Fprintf(os.Stderr, "Files OK: %d\n", okFiles)
	if failedFiles > 0 {
		fmt.Fprintf(os.Stderr, "Files FAILED: %d\n", failedFiles)
	}
	if config.showUntracked && len(untrackedFiles) > 0 {
		fmt.Fprintf(os.Stderr, "\nFiles not in checksum file: %d\n", len(untrackedFiles))
		for _, file := range untrackedFiles {
			fmt.Fprintf(os.Stderr, "  %s\n", file)
		}
	}
	fmt.Fprintf(os.Stderr, "#### Ended\n")
	//	}

	if !allOk {
		return fmt.Errorf("checksum verification failed")
	}

	return nil
}

func extractFilename(line string) string {
	firstSpace := strings.Index(line, " ")
	if firstSpace == -1 || firstSpace == len(line)-1 {
		return ""
	}
	remainder := line[firstSpace+1:]
	if len(remainder) < 2 {
		return ""
	}
	return remainder[1:]
}

func findUntrackedFiles(trackedFiles map[string]bool, config *Config) []string {
	var untracked []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(".", path)
		if err != nil {
			relPath = path
		}
		if relPath == defaultOutputFile || relPath == config.output {
			return nil
		}
		if !trackedFiles[relPath] {
			untracked = append(untracked, relPath)
		}
		return nil
	})
	if err != nil {
		return untracked
	}
	return untracked
}

func checkLine(line string, config *Config, lineNum int, hashFile string, output *os.File) bool {
	// Parse line format: hash mode filename
	// We need to be careful with filenames that contain spaces
	// The format is: "hash<space>mode<filename>" where mode is a single character
	
	// Find the first space (after hash)
	firstSpace := strings.Index(line, " ")
	if firstSpace == -1 || firstSpace == len(line)-1 {
		if config.warn && !config.status {
			fmt.Fprintf(os.Stderr, "%s:%d: improperly formatted line\n", hashFile, lineNum)
		}
		return !config.strict
	}

	expectedHash := line[:firstSpace]
	remainder := line[firstSpace+1:]
	
	// The remainder should be "mode<filename>" where mode is a single character
	if len(remainder) < 2 {
		if config.warn && !config.status {
			fmt.Fprintf(os.Stderr, "%s:%d: improperly formatted line\n", hashFile, lineNum)
		}
		return !config.strict
	}

	// Extract mode character and filename
	mode := remainder[0]
	filename := remainder[1:]
	
	// Validate mode character
	if mode != '*' && mode != ' ' {
		if config.warn && !config.status {
			fmt.Fprintf(os.Stderr, "%s:%d: invalid mode character\n", hashFile, lineNum)
		}
		return !config.strict
	}

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if config.ignoreMissing {
			return true
		}
		if !config.status {
			fmt.Fprintf(os.Stderr, "%s: FAILED file absent\n", filename)
		}
		return false
	}

	// Calculate actual hash
	file, err := os.Open(filename)
	if err != nil {
		if !config.status {
			fmt.Fprintf(os.Stderr, "%s: FAILED could not open file\n", filename)
		}
		return false
	}
	defer file.Close()

	actualHash, err := hashReader(file, config)
	if err != nil {
		if !config.status {
			fmt.Fprintf(os.Stderr, "%s: FAILED could not read file\n", filename)
		}
		return false
	}

	// Compare hashes
	// Why EqualFold is better:
	// Unicode-safe: Handles international characters correctly
	// More efficient: No temporary string allocation
	// Go best practice: strings.EqualFold() is the best way for case-insensitive cmp
	if strings.EqualFold(actualHash, expectedHash) {
		if !config.quiet && !config.status {
			fmt.Fprintf(output, "%s: OK\n", filename)
		}
		return true
	} else {
		if !config.status {
			fmt.Fprintf(output, "%s: FAILED\n", filename)
		}
		return false
	}
}

func showHelpText() {
	fmt.Printf(`b3sumr v%s GPL v3

Usage: b3sumr [OPTION]... [FILE or DIRECTORY]...

Print or check BLAKE3 checksums recursively.
If no FILE or DIRECTORY is indicated, or it's a dot (.), then the current
directory is processed.
The default mode is to compute checksums. Check mode is indicated with --check.

Options:
  -c, --check                read BLAKE3 sums from the FILEs and check them
  -o[FILE], --output[=FILE]  output to FILE instead of standard output, or a
                             file named %s in the current
                             directory if FILE is not specified
  -q, --quiet                quiet mode: don't print messages, only hashes;
                             during check mode, don't print OK for each
                             successfully verified file
  -s, --status               very quiet mode: output only hashes, no messages;
                             status code shows success
  -j, --jobs N               number of parallel workers (default: %d for your CPU)
      --license              show license and exit
      --version              show version information and exit
  -h, --help                 show this text and exit

The following four options are useful only when computing checksums:
  -t, --text                 read in text mode (default)
  -b, --binary               read in binary mode
      --tag                  create a BSD-style checksum
  -l, --length               digest length in bits; must be a multiple of 8

The following four options are useful only when verifying checksums:
      --ignore-missing       don't fail or report status for missing files
      --strict               exit non-zero for improperly formatted checksum lines
  -w, --warn                 warn about improperly formatted checksum lines
      --show-untracked       show files in filesystem not present in checksum file

Sums are computed using the BLAKE3 algorithm. Full documentation at:
  <https://github.com/BLAKE3-team/BLAKE3>.
The default mode is to print a line with checksum, a space, a character 
indicating input mode ('*' for binary, ' ' for text), and name for each FILE.

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain
conditions; type 'b3sumr --license' for details.

More information may be found in the b3sumr(1) man page.
`, version, defaultOutputFile, runtime.NumCPU())
}

func showLicenseText() {
	fmt.Printf(`b3sumr: recursive BLAKE3 hash maker and verifier
Licence GPL Version 3, 29 June 2007

Fork rewrite of original b2rsum by HacKan (https://github.com/HacKanCuBa/b2rsum)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
`)
}
