package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestFetchURL tests the FetchURL function.
func TestFetchURL(t *testing.T) {
	// Case 1: Successful fetch
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("User-Agent header not set")
		}
		fmt.Fprintln(w, "Hello, client")
	}))
	defer server1.Close()

	body, err := FetchURL(server1.URL)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.TrimSpace(body) != "Hello, client" {
		t.Errorf("expected 'Hello, client', got '%s'", body)
	}

	// Case 2: Server error (404 Not Found)
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server2.Close()

	_, err = FetchURL(server2.URL)
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	// Check if the error message contains the status code
	if !strings.Contains(err.Error(), "status code 404") {
		t.Errorf("expected error to contain 'status code 404', got %v", err)
	}

	// Case 3: Server error (500 Internal Server Error)
	server3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server3.Close()

	_, err = FetchURL(server3.URL)
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "status code 500") {
		t.Errorf("expected error to contain 'status code 500', got %v", err)
	}


	// Case 4: Network error (unreachable server) - difficult to test directly without external tools.
	// We can test a non-existent URL.
	// This will likely result in a DNS error or connection refused, wrapped by our function.
	_, err = FetchURL("http://localhost:12345/nonexistent")
	if err == nil {
		t.Fatalf("expected an error for non-existent server, got nil")
	}
}

// Helper function to create a temporary file with content.
func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "testfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func TestExtractHashesFromFile(t *testing.T) {
	testCases := []struct {
		name           string
		fileContent    string
		expectedHashes []string
		expectError    bool
		isNonExistent  bool
	}{
		{
			name:           "Empty file",
			fileContent:    "",
			expectedHashes: []string{},
			expectError:    false,
		},
		{
			name:           "File with no hashes",
			fileContent:    "This is a test file without any hashes.",
			expectedHashes: []string{},
			expectError:    false,
		},
		{
			name: "File with valid MD5 hashes",
			fileContent: "fcf1eed8596699624167416a1e7e122e\n" + // lowercase
				"BED128365216C019988915ED3ADD75FB\n" + // uppercase
				"d0763edAa9d9Bd2a9516280e9044D885", // mixed case
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
				"d0763edaa9d9bd2a9516280e9044d885",
			},
			expectError: false,
		},
		{
			name: "File with hashes mixed with text",
			fileContent: "Hash1: fcf1eed8596699624167416a1e7e122e is here.\n" +
				"Another one BED128365216C019988915ED3ADD75FB.",
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
			},
			expectError: false,
		},
		{
			name: "File with multiple hashes per line",
			fileContent: "Line has fcf1eed8596699624167416a1e7e122e and BED128365216C019988915ED3ADD75FB",
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
			},
			expectError: false,
		},
		{
			name: "File with duplicate hashes",
			fileContent: "fcf1eed8596699624167416a1e7e122e\n" +
				"fcf1eed8596699624167416a1e7e122e\n" + // duplicate
				"BED128365216C019988915ED3ADD75FB",
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
			},
			expectError: false,
		},
		{
			name:          "Non-existent file",
			fileContent:   "", // Not used
			isNonExistent: true,
			expectError:   true,
		},
		{
			name: "Hashes are converted to lowercase",
			fileContent: "FCF1EED8596699624167416A1E7E122E\n" + // uppercase
				"bed128365216c019988915ed3add75fb", // lowercase
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
			},
			expectError: false,
		},
		{
			name:           "File with invalid hashes only",
			fileContent:    "thisisnotavalidhash\nanotherinvalid12345",
			expectedHashes: []string{},
			expectError:    false,
		},
		{
			name: "File with mixed valid and invalid hashes",
			fileContent: "fcf1eed8596699624167416a1e7e122e\n" +
				"notahash\n" +
				"BED128365216C019988915ED3ADD75FB",
			expectedHashes: []string{
				"fcf1eed8596699624167416a1e7e122e",
				"bed128365216c019988915ed3add75fb",
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var filePath string
			if tc.isNonExistent {
				// Create a temporary directory and then use a path within it that doesn't exist.
				tempDir := t.TempDir()
				filePath = filepath.Join(tempDir, "non_existent_file.txt")
			} else {
				filePath = createTempFile(t, tc.fileContent)
			}

			hashes, err := ExtractHashesFromFile(filePath)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				// Sort both slices for consistent comparison
				sort.Strings(hashes)
				sort.Strings(tc.expectedHashes)
				if !reflect.DeepEqual(hashes, tc.expectedHashes) {
					t.Errorf("Expected hashes %v, but got %v", tc.expectedHashes, hashes)
				}
			}
		})
	}
}
