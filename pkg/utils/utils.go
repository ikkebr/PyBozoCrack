package utils

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// FetchURL is a function variable to allow mocking in tests.
// It fetches the content of a given URL.
var FetchURL = func(url string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch URL %s: status code %d", url, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// originalFetchURL holds the original implementation if ever needed, though not strictly necessary for this pattern.
// var originalFetchURL = FetchURL

// ExtractHashesFromFile reads a file and extracts all unique MD5 hashes.
func ExtractHashesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	hashes := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	// MD5 hash regex: 32 hexadecimal characters, case-insensitive
	re := regexp.MustCompile(`([a-fA-F0-9]{32})`)

	for scanner.Scan() {
		line := scanner.Text()
		foundHashes := re.FindAllString(line, -1)
		for _, hash := range foundHashes {
			// Convert to lowercase to ensure uniqueness and consistency
			lowerHash := strings.ToLower(hash)
			if _, ok := hashes[lowerHash]; !ok {
				hashes[lowerHash] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	if len(hashes) == 0 {
		return []string{}, nil // Return empty slice instead of nil
	}
	result := make([]string, 0, len(hashes))
	for hash := range hashes {
		result = append(result, hash)
	}

	return result, nil
}
