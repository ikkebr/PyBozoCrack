package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go-bozocrack/pkg/utils"
)

var (
	originalArgs    = os.Args
	originalStdout  *os.File
	originalStderr  *os.File
	originalFetchFn func(string) (string, error)
)

var mockFetcher struct {
	mu      sync.Mutex
	fetches map[string]struct {
		content string
		err     error
		hits    int
	}
	defaultContent string
	defaultErr     error
}

func mockFetchURL(url string) (string, error) {
	mockFetcher.mu.Lock()
	defer mockFetcher.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[MockFetcher DEBUG] mockFetchURL called with URL: %s\n", url)

	if mockFetcher.fetches == nil {
		mockFetcher.fetches = make(map[string]struct{ content string; err error; hits int })
	}

	if res, ok := mockFetcher.fetches[url]; ok {
		res.hits++
		mockFetcher.fetches[url] = res
		fmt.Fprintf(os.Stderr, "[MockFetcher DEBUG] mockFetchURL found specific mock for URL: %s, returning content: '%s', hits: %d\n", url, res.content, res.hits)
		return res.content, res.err
	}
	fmt.Fprintf(os.Stderr, "[MockFetcher DEBUG] mockFetchURL using default for URL: %s\n", url)
	return mockFetcher.defaultContent, mockFetcher.defaultErr
}

func setupTestExecution(t *testing.T) (stdoutReader *os.File, stderrReader *os.File, stdoutWriter *os.File, stderrWriter *os.File) {
	originalStdout = os.Stdout
	originalStderr = os.Stderr
	originalFetchFn = utils.FetchURL

	stdoutReader, stdoutWriter, _ = os.Pipe()
	stderrReader, stderrWriter, _ = os.Pipe()
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter

	utils.FetchURL = mockFetchURL
	mockFetcher.mu.Lock()
	mockFetcher.fetches = make(map[string]struct {
		content string
		err     error
		hits    int
	})
	mockFetcher.defaultContent = "Default mock content: No hash found here."
	mockFetcher.defaultErr = nil
	mockFetcher.mu.Unlock()

	return
}

func teardownTestExecution(t *testing.T, stdoutReader *os.File, stderrReader *os.File, stdoutWriter *os.File, stderrWriter *os.File) {
	stdoutWriter.Close()
	stderrWriter.Close()

	os.Stdout = originalStdout
	os.Stderr = originalStderr
	utils.FetchURL = originalFetchFn
}

func captureOutput(stdoutReader *os.File, stderrReader *os.File) (string, string) {
	var outBuf, errBuf bytes.Buffer
	io.Copy(&outBuf, stdoutReader)
	io.Copy(&errBuf, stderrReader)
	return outBuf.String(), errBuf.String()
}

func createTempInputFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "testinput-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp input file: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		t.Fatalf("Failed to write to temp input file: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func TestMainCLI(t *testing.T) {
	// Test cases for argument validation
	t.Run("NoFlags", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		args := []string{"go-bozocrack"}
		err := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		_, stderr := captureOutput(rOut, rErr)

		if exitErr, ok := err.(*ExitError); !ok || exitErr.Code != 1 {
			t.Errorf("Expected ExitError with code 1, got %T: %v", err, err)
		}
		if !strings.Contains(stderr, "Error: Please use either -s <hash> or -f <file_path>, but not both.") {
			t.Errorf("Expected error for no flags, got stderr: %s", stderr)
		}
	})

	t.Run("BothFlags", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		args := []string{"go-bozocrack", "-s", "somehash", "-f", "somefile.txt"}
		err := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		_, stderr := captureOutput(rOut, rErr)

		if exitErr, ok := err.(*ExitError); !ok || exitErr.Code != 1 {
			t.Errorf("Expected ExitError with code 1, got %T: %v", err, err)
		}
		if !strings.Contains(stderr, "Error: Please use either -s <hash> or -f <file_path>, but not both.") {
			t.Errorf("Expected error for both flags, got stderr: %s", stderr)
		}
	})

	t.Run("FileFlag_FileNotFound", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		args := []string{"go-bozocrack", "-f", "nonexistentfile.txt"}
		err := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		_, stderr := captureOutput(rOut, rErr)

		if exitErr, ok := err.(*ExitError); !ok || exitErr.Code != 1 {
			t.Errorf("Expected ExitError with code 1 for file not found, got %T: %v", err, err)
		}
		if !strings.Contains(stderr, "Error extracting hashes from file nonexistentfile.txt:") {
			t.Errorf("Expected error for file not found, got stderr: %s", stderr)
		}
	})

	hashOnline := "098f6bcd4621d373cade4e832627b4f6" // md5("test")
	plaintextOnline := "test"
	searchURLOnline := fmt.Sprintf("http://www.google.com/search?q=%s", hashOnline)

	t.Run("SingleHash_CrackOnline_NoCache", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		mockFetcher.mu.Lock()
		mockFetcher.fetches[searchURLOnline] = struct{content string; err error; hits int}{content: plaintextOnline, err: nil}
		mockFetcher.mu.Unlock()

		args := []string{"go-bozocrack", "-s", hashOnline}
		err := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		stdout, stderr := captureOutput(rOut, rErr)
		t.Logf("[SingleHash_CrackOnline_NoCache] stdout:\n%s", stdout)
		t.Logf("[SingleHash_CrackOnline_NoCache] stderr:\n%s", stderr)

		if err != nil {
			t.Errorf("Expected no error from runCliLogic, got %v", err)
		}
		expectedOutput := fmt.Sprintf("%s:%s", hashOnline, plaintextOnline)
		if !strings.Contains(stdout, expectedOutput) {
			t.Errorf("Expected output '%s', got stdout: %s", expectedOutput, stdout)
		}
		if !strings.Contains(stdout, "not found in cache") {
			t.Error("Expected 'not found in cache' message.")
		}

		mockFetcher.mu.Lock()
		if mockFetcher.fetches[searchURLOnline].hits != 1 {
			t.Errorf("Expected FetchURL to be called once, got %d hits", mockFetcher.fetches[searchURLOnline].hits)
		}
		mockFetcher.mu.Unlock()

		absPathTestRead, _ := filepath.Abs(testCachePath)
		t.Logf("[SingleHash_CrackOnline_NoCache] Test trying to read cache file: %s (abs: %s)", testCachePath, absPathTestRead)
		cacheContent, readErr := os.ReadFile(testCachePath)
		if readErr != nil {
			t.Fatalf("Failed to read cache file %s (abs: %s): %v", testCachePath, absPathTestRead, readErr)
		}
		if !strings.Contains(string(cacheContent), fmt.Sprintf("%s:%s", hashOnline, plaintextOnline)) {
			t.Errorf("Cache file does not contain the cracked hash. Content:\n%s", string(cacheContent))
		}
	})

	t.Run("SingleHash_FoundInCache", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		errWrite := os.WriteFile(testCachePath, []byte(fmt.Sprintf("%s:%s\n", hashOnline, plaintextOnline)), 0644)
		if errWrite != nil {
			t.Fatalf("Failed to create manual cache file: %v", errWrite)
		}

		mockFetcher.mu.Lock()
		mockFetcher.fetches[searchURLOnline] = struct{content string; err error; hits int}{content: "Error: Should not be called", err: fmt.Errorf("FetchURL called when cache should hit")}
		mockFetcher.mu.Unlock()

		args := []string{"go-bozocrack", "-s", hashOnline}
		err := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		stdout, _ := captureOutput(rOut, rErr)

		if err != nil {
			t.Errorf("Expected no error from runCliLogic, got %v", err)
		}
		expectedOutput := fmt.Sprintf("%s:%s (cached)", hashOnline, plaintextOnline)
		if !strings.Contains(stdout, expectedOutput) {
			t.Errorf("Expected output '%s' from cache, got stdout: %s", expectedOutput, stdout)
		}

		mockFetcher.mu.Lock()
		if mockFetcher.fetches[searchURLOnline].hits != 0 {
			t.Errorf("Expected FetchURL not to be called (0 hits), got %d hits", mockFetcher.fetches[searchURLOnline].hits)
		}
		mockFetcher.mu.Unlock()
	})

	t.Run("SingleHash_CrackFail_Online", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		unknownHash := "12345abcdef12345abcdef12345abcdef"
		searchURLUnknown := fmt.Sprintf("http://www.google.com/search?q=%s", unknownHash)

		mockFetcher.mu.Lock()
		mockFetcher.fetches[searchURLUnknown] = struct{content string; err error; hits int}{content: "No relevant info found", err: nil}
		mockFetcher.mu.Unlock()

		args := []string{"go-bozocrack", "-s", unknownHash}
		logicErr := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		stdout, _ := captureOutput(rOut, rErr)

		if logicErr != nil {
			t.Errorf("Expected nil error from runCliLogic for 'could not crack', got: %v", logicErr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Could not crack hash: %s", unknownHash)) {
			t.Errorf("Expected 'Could not crack hash' message, got: %s", stdout)
		}

		cacheContent, readErr := os.ReadFile(testCachePath)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatalf("Error reading cache file: %v", readErr)
		}
		if readErr == nil && string(cacheContent) != "" {
			t.Errorf("Cache file should be empty if hash not cracked, content: %s", string(cacheContent))
		}
	})

	// Variables needed for File_CrackSome_CacheInteraction
	hashInFile1 := "6cb1ab627545f991c49394aec4f0102b" // md5("apple")
	plainInFile1 := "apple"
	searchURLFile1 := fmt.Sprintf("http://www.google.com/search?q=%s", hashInFile1)

	hashInFile2 := "1a37260f62bf9951688860a8066195e0" // md5("banana")
	plainInFile2 := "banana"
	searchURLFile2 := fmt.Sprintf("http://www.google.com/search?q=%s", hashInFile2)

	hashInFileUncrackable := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	t.Run("File_CrackSome_CacheInteraction", func(t *testing.T) {
		tempDir := t.TempDir()
		testCachePath := filepath.Join(tempDir, "test_cache.txt")
		rOut, rErr, wOut, wErr := setupTestExecution(t)

		errWrite := os.WriteFile(testCachePath, []byte(fmt.Sprintf("%s:%s\n", hashInFile1, plainInFile1)), 0644)
		if errWrite != nil {
			t.Fatalf("Failed to create manual cache file: %v", errWrite)
		}

		inputFileContent := fmt.Sprintf("%s\n%s\n%s", hashInFile1, hashInFile2, hashInFileUncrackable)
		tempFilePath := createTempInputFile(t, inputFileContent)

		mockFetcher.mu.Lock()
		mockFetcher.fetches[searchURLFile1] = struct{content string; err error; hits int}{content: "Error: Should be cached", err: fmt.Errorf("fetcher for hash1 called")}
		mockFetcher.fetches[searchURLFile2] = struct{content string; err error; hits int}{content: plainInFile2, err: nil}
		mockFetcher.fetches[fmt.Sprintf("http://www.google.com/search?q=%s", hashInFileUncrackable)] = struct{content string; err error; hits int}{content: "Cannot find this one aaaaaaaaaa", err: nil}
		mockFetcher.mu.Unlock()

		args := []string{"go-bozocrack", "-f", tempFilePath}
		logicErr := runCliLogic(args, wOut, wErr, testCachePath)

		teardownTestExecution(t,rOut, rErr, wOut, wErr)
		stdout, stderr := captureOutput(rOut, rErr)
		t.Logf("[File_CrackSome_CacheInteraction] stdout:\n%s", stdout)
		t.Logf("[File_CrackSome_CacheInteraction] stderr:\n%s", stderr)


		if logicErr != nil {
			t.Errorf("Expected nil error from runCliLogic for file processing, got: %v", logicErr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("%s:%s (cached)", hashInFile1, plainInFile1)) {
			t.Errorf("Expected hashInFile1 to be reported from cache. Stdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("%s:%s", hashInFile2, plainInFile2)) {
			t.Errorf("Expected hashInFile2 to be cracked and reported. Stdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Could not crack hash: %s", hashInFileUncrackable)) {
			t.Errorf("Expected hashInFileUncrackable to be reported as not cracked. Stdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Successfully cracked 2 out of 3 hashes.") {
			t.Errorf("Expected cracked count message 'Successfully cracked 2 out of 3 hashes.'. Stdout:\n%s", stdout)
		}

		mockFetcher.mu.Lock()
		if mockFetcher.fetches[searchURLFile1].hits != 0 {
			t.Errorf("Fetcher for hashInFile1 (cached) should not have been called (hits: %d)", mockFetcher.fetches[searchURLFile1].hits)
		}
		if val, ok := mockFetcher.fetches[searchURLFile2]; !ok || val.hits != 1 {
			t.Errorf("Fetcher for hashInFile2 should have been called once (hits: %d, ok: %v)", val.hits, ok)
		}
		mockFetcher.mu.Unlock()

		finalCache := readCacheFileToMapHelper(t, testCachePath)
		if val, ok := finalCache[hashInFile1]; !ok || val != plainInFile1 {
			t.Errorf("Final cache missing or incorrect for hashInFile1. Cache: %v", finalCache)
		}
		if val, ok := finalCache[hashInFile2]; !ok || val != plainInFile2 {
			t.Errorf("Final cache missing or incorrect for hashInFile2. Cache: %v", finalCache)
		}
		if _, ok := finalCache[hashInFileUncrackable]; ok {
			t.Errorf("Final cache should not contain uncrackable hash. Cache: %v", finalCache)
		}
	})
}

func readCacheFileToMapHelper(t *testing.T, filePath string) map[string]string {
	t.Helper()
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string)
		}
		t.Fatalf("Failed to read cache file %s: %v", filePath, err)
	}

	store := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			store[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return store
}

func TestMD5Reference(t *testing.T) {
	h := md5.New()
	h.Write([]byte("test"))
	hex.EncodeToString(h.Sum(nil))
}

var _ = httptest.NewServer
// No TestMain(m *testing.M) needed if individual test cases don't cause full process exit
// or if the refactored runCliLogic handles exits by returning errors.
// The os.Exit calls are now only in the actual main() func, not runCliLogic().
