package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"go-bozocrack/pkg/cache"
	"go-bozocrack/pkg/cracker"
	"go-bozocrack/pkg/utils"
)

const cacheFilePath = "cache.txt"

// ExitError is a custom error type to represent exit codes.
type ExitError struct {
	Code int
	Err  error // Optional underlying error message
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	// Default message if no specific error message is provided
	return fmt.Sprintf("cli error with exit code %d", e.Code)
}

func main() {
	// Pass os.Stdout and os.Stderr as default writers to runCliLogic
	err := runCliLogic(os.Args, os.Stdout, os.Stderr, cacheFilePath) // Pass the global cacheFilePath
	if err != nil {
		// If runCliLogic prints specific messages to its stderr, we might not need to print err.Error() here.
		// However, if it returns an error that's not user-facing, printing it might be useful.
		// For now, assume runCliLogic handles user-facing error messages.
		if exitErr, ok := err.(*ExitError); ok {
			// If runCliLogic didn't print the error message and it's in ExitError.Err
			if exitErr.Err != nil && exitErr.Code != 0 { // Code 0 usually means success, but error is set.
				fmt.Fprintln(os.Stderr, exitErr.Err)
			}
			os.Exit(exitErr.Code)
		} else {
			// Generic error
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1) // Default exit code for unexpected errors
		}
	}
	os.Exit(0) // Explicitly exit with 0 on success
}

// runCliLogic contains the core application logic.
// It takes arguments, I/O writers, and the cache path to allow for easier testing.
func runCliLogic(args []string, stdout io.Writer, stderr io.Writer, cachePath string) error {
	// Create a new FlagSet for each call to runCliLogic to avoid issues with
	// test runs interfering with each other's flag states.
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError) // ContinueOnError allows error handling
	fs.SetOutput(stderr) // Direct help/error messages from flag parsing to stderr

	singleHash := fs.String("s", "", "Single MD5 hash to crack")
	filePath := fs.String("f", "", "Path to a file containing hashes to crack")

	// Parse flags from args[1:]
	if err := fs.Parse(args[1:]); err != nil {
		// fs.Parse will print usage to stderr if flag.ContinueOnError is set.
		// Return an error that indicates parsing failure.
		return &ExitError{Code: 1, Err: fmt.Errorf("flag parsing error: %w", err)}
	}

	if (*singleHash == "" && *filePath == "") || (*singleHash != "" && *filePath != "") {
		fmt.Fprintln(stderr, "Error: Please use either -s <hash> or -f <file_path>, but not both.")
		fs.Usage() // Print usage to the FlagSet's output (stderr)
		return &ExitError{Code: 1}
	}

	appCache, err := cache.NewCache(cachePath) // Use passed cachePath
	if err != nil {
		fmt.Fprintf(stderr, "Error initializing cache at %s: %v\n", cachePath, err)
		return &ExitError{Code: 1} // No underlying error needed as it's printed
	}

	if *singleHash != "" {
		return processSingleHashLogic(*singleHash, appCache, stdout, stderr)
	} else if *filePath != "" {
		return processFileLogic(*filePath, appCache, stdout, stderr)
	}

	// Should not be reached if flag validation is correct
	return &ExitError{Code: 1, Err: fmt.Errorf("internal error: unhandled CLI state")}
}

// processSingleHashLogic is the refactored logic for -s flag.
func processSingleHashLogic(hash string, appCache *cache.Cache, stdout io.Writer, stderr io.Writer) error {
	fmt.Fprintf(stdout, "Processing single hash: %s\n", hash)
	plaintext, found := appCache.Get(hash)
	if found {
		fmt.Fprintf(stdout, "%s:%s (cached)\n", hash, plaintext)
		return nil // Success
	}

	fmt.Fprintf(stdout, "Hash %s not found in cache, attempting to crack...\n", hash)
	crackedPlaintext, err := cracker.CrackSingleHash(hash, utils.FetchURL)
	if err != nil {
		fmt.Fprintf(stderr, "Error cracking hash %s: %v\n", hash, err)
		// This error might indicate a problem with the cracking process itself (e.g., network).
		// Depending on desired CLI behavior, we might return an error or just indicate not cracked.
		// For now, treat as a cracking failure, not a CLI exit error unless specified.
		return fmt.Errorf("cracking process failed for %s: %w", hash, err) // Not an ExitError
	}

	if crackedPlaintext != "" {
		fmt.Fprintf(stdout, "%s:%s\n", hash, crackedPlaintext)
		if setErr := appCache.Set(hash, crackedPlaintext); setErr != nil {
			fmt.Fprintf(stderr, "Error saving to cache for hash %s: %v\n", hash, setErr)
			// This is a non-fatal error for the current hash processing.
		}
	} else {
		fmt.Fprintf(stdout, "Could not crack hash: %s\n", hash)
	}
	return nil // Success (operation completed, even if hash not cracked)
}

// processFileLogic is the refactored logic for -f flag.
func processFileLogic(filePath string, appCache *cache.Cache, stdout io.Writer, stderr io.Writer) error {
	fmt.Fprintf(stdout, "Processing file: %s\n", filePath)
	hashes, err := utils.ExtractHashesFromFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "Error extracting hashes from file %s: %v\n", filePath, err)
		return &ExitError{Code: 1} // File processing failed fundamentally.
	}

	if len(hashes) == 0 {
		fmt.Fprintln(stdout, "No hashes found in the file.")
		return nil // Success, nothing to do.
	}

	fmt.Fprintf(stdout, "Loaded %d unique hashes from %s.\n", len(hashes), filePath)
	crackedCount := 0
	anyCrackingProcessError := false // Flag to track if any non-fatal cracking error occurred

	for _, hash := range hashes {
		plaintext, found := appCache.Get(hash)
		if found {
			fmt.Fprintf(stdout, "%s:%s (cached)\n", hash, plaintext)
			crackedCount++
			continue
		}

		fmt.Fprintf(stdout, "Attempting to crack hash: %s\n", hash)
		// DEBUG: Log the exact hash string and its length from processFileLogic
		fmt.Fprintf(stderr, "[PROCESS FILE DEBUG] Processing hash: '%s' (len: %d)\n", hash, len(hash))
		crackedPlaintext, crackErr := cracker.CrackSingleHash(hash, utils.FetchURL)
		if crackErr != nil {
			fmt.Fprintf(stderr, "Error cracking hash %s: %v\n", hash, crackErr)
			anyCrackingProcessError = true // Mark that an error occurred
			continue // Continue with other hashes
		}

		if crackedPlaintext != "" {
			fmt.Fprintf(stdout, "%s:%s\n", hash, crackedPlaintext)
			crackedCount++
			if setErr := appCache.Set(hash, crackedPlaintext); setErr != nil {
				fmt.Fprintf(stderr, "Error saving to cache for hash %s: %v\n", hash, setErr)
				// Non-fatal for overall process
			}
		} else {
			fmt.Fprintf(stdout, "Could not crack hash: %s\n", hash)
		}
	}

	if crackedCount > 0 {
		fmt.Fprintf(stdout, "Successfully cracked %d out of %d hashes.\n", crackedCount, len(hashes))
	} else {
		fmt.Fprintln(stdout, "No hashes were cracked from the file.")
	}

	if anyCrackingProcessError {
		// Optionally return a specific error or code if any hash cracking failed due to system/network issues.
		// For now, completing the file processing is considered a "CLI success" unless file read failed.
		// The errors are printed to stderr.
	}
	return nil // Success for CLI operation
}
