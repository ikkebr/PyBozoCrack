package cracker

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os" // For debug printing
	// "regexp" // No longer used by SearchHash
	"strings" // For NewReplacer, Fields, TrimSpace
)

// SearchHash searches Google for a hash and extracts potential plaintext words.
func SearchHash(hash string, utilsFetcher func(string) (string, error)) ([]string, error) {
	searchURL := fmt.Sprintf("http://www.google.com/search?q=%s", hash)
	pageContent, err := utilsFetcher(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch search results: %w", err)
	}

	// Normalize various punctuation to spaces.
	// This list can be expanded. The goal is to isolate words.
	replacer := strings.NewReplacer(
		".", " ", ",", " ", ":", " ", ";", " ",
		"?", " ", "!", " ", "(", " ", ")", " ",
		"[", " ", "]", " ", "{", " ", "}", " ",
		"<", " ", ">", " ", "\"", " ", "'", " ",
		"`", " ", "_", " ", "-", " ", "/", " ",
		"\\", " ", "|", " ", "@", " ", "#", " ",
		"$", " ", "%", " ", "^", " ", "&", " ",
		"*", " ", "+", " ", "=", " ", "~", " ",
	)
	cleanedContent := replacer.Replace(pageContent)

	// Split into words by whitespace. strings.Fields handles multiple spaces.
	tempWordlist := strings.Fields(cleanedContent)

	uniqueWords := make(map[string]struct{})
	var finalWordlist []string
	for _, word := range tempWordlist {
		// TrimSpace is good, but Fields already handles most surrounding space.
		// However, if a "word" itself is just punctuation that got spaced, TrimSpace might reduce it to "".
		trimmedWord := strings.TrimSpace(word) // Should be redundant if Fields is used correctly.
		if trimmedWord != "" {
			// Optional: Add further filtering here, e.g., ensure word has min length, or contains alphanum.
			if _, exists := uniqueWords[trimmedWord]; !exists {
				uniqueWords[trimmedWord] = struct{}{}
				finalWordlist = append(finalWordlist, trimmedWord)
			}
		}
	}

	if len(finalWordlist) == 0 {
		return nil, nil
	}
	return finalWordlist, nil
}

// DictionaryAttack tries to find a hash match in a given wordlist.
func DictionaryAttack(hash string, wordlist []string) string {
	for _, word := range wordlist {
		hasher := md5.New()
		hasher.Write([]byte(word))
		calculatedHash := hex.EncodeToString(hasher.Sum(nil))
		if calculatedHash == hash {
			return word
		}
	}
	return ""
}

// CrackSingleHash attempts to crack a single hash using search and dictionary attack.
func CrackSingleHash(hash string, utilsFetcher func(string) (string, error)) (string, error) {
	potentialPlaintexts, err := SearchHash(hash, utilsFetcher)
	if err != nil {
		return "", fmt.Errorf("error searching for hash: %w", err)
	}

	if potentialPlaintexts == nil || len(potentialPlaintexts) == 0 {
		return "", nil
	}

	foundPlaintext := DictionaryAttack(hash, potentialPlaintexts)
	return foundPlaintext, nil
}
