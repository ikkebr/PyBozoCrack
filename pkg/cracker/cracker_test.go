package cracker

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// TestDictionaryAttack tests the DictionaryAttack function.
func TestDictionaryAttack(t *testing.T) {
	// Pre-calculate some MD5 hashes for known words
	word1 := "password"
	hasher1 := md5.New()
	hasher1.Write([]byte(word1))
	hash1 := hex.EncodeToString(hasher1.Sum(nil)) // 5f4dcc3b5aa765d61d8327deb882cf99

	word2 := "test"
	hasher2 := md5.New()
	hasher2.Write([]byte(word2))
	hash2 := hex.EncodeToString(hasher2.Sum(nil)) // 098f6bcd4621d373cade4e832627b4f6

	testCases := []struct {
		name     string
		hash     string
		wordlist []string
		expected string
	}{
		{
			name:     "Empty wordlist",
			hash:     hash1,
			wordlist: []string{},
			expected: "",
		},
		{
			name:     "Hash present in wordlist",
			hash:     hash1,
			wordlist: []string{"apple", "banana", word1, "orange"},
			expected: word1,
		},
		{
			name:     "Hash not present in wordlist",
			hash:     "nonexistenthash123",
			wordlist: []string{"apple", "banana", word1, "orange"},
			expected: "",
		},
		{
			name:     "Hash present (another known hash)",
			hash:     hash2,
			wordlist: []string{word1, word2, "qwerty"},
			expected: word2,
		},
		{
			name:     "Wordlist with different casing (should not match if hash is for lowercase)",
			hash:     hash1, // hash of "password"
			wordlist: []string{"Password", "PASSWORD"},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := DictionaryAttack(tc.hash, tc.wordlist)
			if result != tc.expected {
				t.Errorf("Expected plaintext '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// Mock fetcher for SearchHash tests
type mockFetcher struct {
	content string
	err     error
}

func (mf *mockFetcher) Fetch(url string) (string, error) {
	// We can add checks for the URL if needed for specific tests
	// For now, just return the pre-set content/error
	return mf.content, mf.err
}

func TestSearchHash(t *testing.T) {
	testCases := []struct {
		name           string
		hash           string
		fetcher        *mockFetcher
		expectedWords  []string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:        "Fetcher returns an error",
			hash:        "somehash",
			fetcher:     &mockFetcher{err: errors.New("network problem")},
			expectError: true,
			expectedErrMsg: "failed to fetch search results: network problem",
		},
		{
			name:        "Fetcher returns content with no potential plaintexts (but regex still finds parts of tags)",
			hash:        "somehash",
			fetcher:     &mockFetcher{content: "<html><body>No useful words here</body></html>"},
			// According to the regex, parts of HTML tags and the words themselves are extracted.
			// Correctly sorted:
			expectedWords:  []string{"/body", "/html", "No", "body", "here", "html", "useful", "words"},
			expectError: false,
		},
		{
			name:    "Fetcher returns content with various words",
			hash:    "somehash",
			fetcher: &mockFetcher{content: "Found: password123 (secret) or test:value. Maybe another_word?"},
			expectedWords:  []string{"Found", "Maybe", "another_word", "or", "password123", "secret", "test", "value"}, // Sorted
			expectError: false,
		},
		{
			name:    "Fetcher returns content with duplicate words",
			hash:    "somehash",
			fetcher: &mockFetcher{content: "word word word test test"},
			expectedWords:  []string{"test", "word"}, // Sorted
			expectError: false,
		},
		{
			name:    "Fetcher returns empty content",
			hash:    "somehash",
			fetcher: &mockFetcher{content: ""},
			expectedWords:  nil, // SearchHash returns nil for empty result
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			words, err := SearchHash(tc.hash, tc.fetcher.Fetch)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected an error, but got nil")
				}
				if tc.expectedErrMsg != "" && err.Error() != tc.expectedErrMsg {
					t.Errorf("Expected error message '%s', got '%s'", tc.expectedErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, but got: %v", err)
				}
				// Sort the actual words slice before comparison because the order from SearchHash is not guaranteed
				// (due to map usage for deduplication). Expected words are already defined as sorted.
				if words != nil { // Only sort if not nil
					sort.Strings(words)
				}
				if !reflect.DeepEqual(words, tc.expectedWords) {
					t.Errorf("Expected words %v, got %v", tc.expectedWords, words)
				}
			}
		})
	}
}

func TestCrackSingleHash(t *testing.T) {
	knownWord := "supersecret"
	hasher := md5.New()
	hasher.Write([]byte(knownWord))
	knownHash := hex.EncodeToString(hasher.Sum(nil))

	testCases := []struct {
		name             string
		hash             string
		mockFetcher      *mockFetcher
		expectedPlain    string
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name:        "SearchHash returns an error",
			hash:        "anyhash",
			mockFetcher: &mockFetcher{err: errors.New("fetch failed")},
			expectError: true,
			expectedErrorMsg: "error searching for hash: failed to fetch search results: fetch failed",
		},
		{
			name:        "SearchHash returns empty wordlist",
			hash:        "anyhash",
			mockFetcher: &mockFetcher{content: "no words here"}, // SearchHash will parse this to nil/empty
			expectedPlain: "",
			expectError: false,
		},
		{
			name:        "SearchHash finds words, DictionaryAttack matches",
			hash:        knownHash, // Hash of "supersecret"
			mockFetcher: &mockFetcher{content: fmt.Sprintf("The password is %s or maybe test1", knownWord)},
			expectedPlain: knownWord,
			expectError: false,
		},
		{
			name:        "SearchHash finds words, DictionaryAttack no match",
			hash:        "unknownhash123",
			mockFetcher: &mockFetcher{content: "Some words here like example and test"},
			expectedPlain: "",
			expectError: false,
		},
		{
			name:        "SearchHash finds different words, DictionaryAttack no match for target hash",
			hash:        knownHash, // Hash of "supersecret"
			mockFetcher: &mockFetcher{content: "Only other words: apple banana"},
			expectedPlain: "",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := CrackSingleHash(tc.hash, tc.mockFetcher.Fetch)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected an error, but got nil")
				}
				if tc.expectedErrorMsg != "" && err.Error() != tc.expectedErrorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tc.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, but got: %v", err)
				}
				if plaintext != tc.expectedPlain {
					t.Errorf("Expected plaintext '%s', got '%s'", tc.expectedPlain, plaintext)
				}
			}
		})
	}
}
