//! `pybozocrack_rust` is a Rust application for cracking MD5 hashes by searching
//! for them on Google and performing a dictionary attack on the words found in the
//! search results. It supports cracking single hashes, processing files containing
//! multiple hashes, and caching results to avoid re-cracking known hashes.

use md5::{Md5, Digest};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use clap::Parser;

/// Type alias for the cache structure, mapping a hash string to its plaintext.
type Cache = HashMap<String, String>;

/// Defines command-line arguments accepted by the application.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(name = "pybozocrack_rust")] // Added explicit name for help message
struct Cli {
    #[clap(short = 's', long = "single", help = "Single MD5 hash to crack")]
    single_hash: Option<String>,

    #[clap(short = 'f', long = "file", help = "File containing hashes to crack")]
    hash_file: Option<String>,
}

/// Loads previously cracked hashes from a cache file.
///
/// The cache file is expected to have one `hash:plaintext` entry per line.
/// Lines that do not conform to this format are skipped.
/// If the cache file does not exist, an empty cache is returned.
///
/// # Arguments
/// * `cache_file_path`: Path to the cache file.
///
/// # Returns
/// A `Result` containing the loaded `Cache` or an `io::Error` if file reading fails.
fn load_cache(cache_file_path: &str) -> Result<Cache, io::Error> {
    let mut cache = HashMap::new();
    let path = Path::new(cache_file_path);

    if !path.exists() {
        return Ok(cache);
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result?;
        if let Some(colon_idx) = line.find(':') {
            let hash = line[..colon_idx].to_string();
            let plaintext = line[colon_idx + 1..].to_string();
            // Ensure that both hash and plaintext are non-empty after split
            if !hash.is_empty() && !plaintext.is_empty() {
                cache.insert(hash, plaintext);
            }
        }
    }
    Ok(cache)
}

/// Appends a newly cracked hash and its plaintext to the cache file.
///
/// If the cache file does not exist, it is created.
///
/// # Arguments
/// * `cache_file_path`: Path to the cache file.
/// * `hash`: The MD5 hash string.
/// * `plaintext`: The corresponding plaintext.
///
/// # Returns
/// A `Result` indicating success or an `io::Error` if file operations fail.
fn append_to_cache(cache_file_path: &str, hash: &str, plaintext: &str) -> Result<(), io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(cache_file_path)?;

    writeln!(file, "{}:{}", hash, plaintext)?;
    Ok(())
}

/// Loads MD5 hashes from a specified file.
///
/// Each line in the file is scanned for 32-character hexadecimal strings.
/// Found hashes are converted to lowercase and deduplicated.
/// The resulting list of unique hashes is sorted alphabetically.
///
/// # Arguments
/// * `file_path`: Path to the file containing hashes.
///
/// # Returns
/// A `Result` containing a sorted `Vec<String>` of unique hashes or an `io::Error`.
fn load_hashes_from_file(file_path: &str) -> Result<Vec<String>, io::Error> {
    let path = Path::new(file_path);
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // Regex to find 32-character hexadecimal strings (MD5 hashes)
    let hash_regex = Regex::new(r"([a-fA-F0-9]{32})").unwrap();
    let mut unique_hashes = HashSet::new();

    for line_result in reader.lines() {
        let line = line_result?;
        for cap in hash_regex.captures_iter(&line) {
            unique_hashes.insert(cap[1].to_lowercase());
        }
    }

    let mut sorted_hashes: Vec<String> = unique_hashes.into_iter().collect();
    sorted_hashes.sort();
    Ok(sorted_hashes)
}

/// Performs a dictionary attack on a given hash using a list of words.
///
/// Each word in the `wordlist` is converted to lowercase, MD5 hashed, and
/// compared against the target `hash`.
///
/// # Arguments
/// * `hash`: The target MD5 hash string (expected to be lowercase).
/// * `wordlist`: A `HashSet` of words to try.
///
/// # Returns
/// An `Option<String>` containing the plaintext if found, otherwise `None`.
fn dictionary_attack(hash: &str, wordlist: &HashSet<String>) -> Option<String> {
    for word_candidate in wordlist {
        let lower_word = word_candidate.to_lowercase();
        let mut hasher = Md5::new();
        hasher.input(lower_word.as_bytes());
        let result = hasher.result();
        let hex_digest = format!("{:x}", result);
        if hex_digest == hash {
            return Some(lower_word);
        }
    }
    None
}

/// Attempts to crack a single MD5 hash.
///
/// This function fetches content from Google based on the hash, extracts words,
/// and then calls `dictionary_attack`.
///
/// # Arguments
/// * `hash`: The MD5 hash string to crack.
///
/// # Returns
/// An `Option<String>` containing the plaintext if cracked, otherwise `None`.
fn perform_crack_attempt(hash: &str) -> Option<String> {
    let url = format!("http://www.google.com/search?q={}", hash);
    println!("Searching URL for {}: {}", hash, url);

    let client = Client::new();
    match client.get(&url)
        .header(USER_AGENT, "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0")
        .send()
    {
        Ok(response) => {
            if !response.status().is_success() {
                eprintln!("Request to {} failed with status: {}", url, response.status());
                return None;
            }
            match response.text() {
                Ok(text) => {
                    let text_processed = text
                        .replace('.', " ")
                        .replace(':', " ")
                        .replace('?', " ")
                        .replace("'(", "")
                        .replace("'", "");

                    let alphanumeric_re = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
                    let words: HashSet<String> = text_processed
                        .split_whitespace()
                        .filter(|s| s.len() >= 4 && s.len() < 15) // Adjusted length filter
                        .filter(|s| alphanumeric_re.is_match(s))
                        .map(|s| s.to_string())
                        .collect();

                    if words.is_empty() {
                        println!("No suitable words extracted from Google search for {}.", hash);
                    }
                    dictionary_attack(hash, &words)
                }
                Err(e) => {
                    eprintln!("Error reading response text from {}: {}", url, e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Network error when fetching {}: {}", url, e);
            None
        }
    }
}

// --- Main Application Logic Handlers ---

/// Handles the logic for cracking a single hash provided via CLI.
///
/// Checks the cache, attempts cracking if not found, and updates the cache.
///
/// # Arguments
/// * `cache`: A mutable reference to the in-memory `Cache`.
/// * `cache_file`: Path to the cache file for persistence.
/// * `hash_to_crack_orig`: The hash string from the CLI.
fn handle_single_hash_mode(cache: &mut Cache, cache_file: &str, hash_to_crack_orig: &str) {
    let hash_to_crack = hash_to_crack_orig.to_lowercase();
    println!("\nProcessing single hash: {}", hash_to_crack);
    if let Some(plaintext) = cache.get(&hash_to_crack) {
        println!("Found in cache: {}:{}", hash_to_crack, plaintext);
    } else {
        println!("Not in cache. Attempting to crack: {}", hash_to_crack);
        let crack_result = perform_crack_attempt(&hash_to_crack);
        match crack_result {
            Some(password) => {
                println!("{}:{}", hash_to_crack, password);
                if let Err(e) = append_to_cache(cache_file, &hash_to_crack, &password) {
                    eprintln!("Error appending to cache: {}", e);
                }
                cache.insert(hash_to_crack.to_string(), password);
            }
            None => {
                println!("Password not found for: {}", hash_to_crack);
            }
        }
    }
}

/// Handles the logic for cracking hashes from a specified file.
///
/// Loads hashes, then for each hash, checks the cache, attempts cracking if not found,
/// and updates the cache.
///
/// # Arguments
/// * `cache`: A mutable reference to the in-memory `Cache`.
/// * `cache_file`: Path to the cache file for persistence.
/// * `file_path`: Path to the file containing hashes.
///
/// # Returns
/// `bool` indicating if any new hashes were successfully cracked in this run.
fn handle_file_hash_mode(cache: &mut Cache, cache_file: &str, file_path: &str) -> bool {
    let mut hashes_cracked_in_this_run = false;
    println!("\nProcessing hashes from file: {}", file_path);
    match load_hashes_from_file(file_path) {
        Ok(hashes) => {
            println!("Loaded {} unique hashes from {}.", hashes.len(), file_path);
            for hash_to_crack in hashes { // hash_to_crack is already lowercase from load_hashes_from_file
                println!("\nProcessing hash: {}", hash_to_crack);
                if let Some(plaintext) = cache.get(&hash_to_crack) {
                    println!("Found in cache: {}:{}", hash_to_crack, plaintext);
                } else {
                    println!("Not in cache. Attempting to crack: {}", hash_to_crack);
                    let crack_result = perform_crack_attempt(&hash_to_crack);
                    match crack_result {
                        Some(password) => {
                            println!("{}:{}", hash_to_crack, password);
                            hashes_cracked_in_this_run = true;
                            if let Err(e) = append_to_cache(cache_file, &hash_to_crack, &password) {
                                eprintln!("Error appending to cache: {}", e);
                            }
                            cache.insert(hash_to_crack.to_string(), password);
                        }
                        None => {
                            // No "not found" message per hash in file mode (matching original behavior)
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error loading hashes from file {}: {}", file_path, e);
        }
    }
    hashes_cracked_in_this_run
}

/// Main entry point for the application.
/// Parses CLI arguments, loads cache, and dispatches to appropriate handlers.
fn main() {
    let cli = Cli::parse();
    let cache_file = "cache.txt";
    let mut cache = match load_cache(cache_file) {
        Ok(loaded_cache) => {
            println!("Loaded {} items from cache.", loaded_cache.len());
            loaded_cache
        }
        Err(e) => {
            eprintln!("Error loading cache file '{}': {}. Starting with an empty cache.", cache_file, e);
            HashMap::new()
        }
    };

    if let Some(ref hash_to_crack_orig) = cli.single_hash {
        handle_single_hash_mode(&mut cache, cache_file, hash_to_crack_orig);
    } else if let Some(ref file_path) = cli.hash_file {
        let cracked_in_file_mode = handle_file_hash_mode(&mut cache, cache_file, file_path);
        if !cracked_in_file_mode { // Only print if -f was used and no new hashes were cracked in this specific run.
            println!("No hashes were cracked.");
        }
    } else {
        // clap should ideally handle this by default if no arguments are truly optional
        // or if a subcommand structure is used. For now, this manual check is fine.
        eprintln!("Error: Please provide a hash to crack (-s/--single HASH) or a file of hashes (-f/--file FILE_PATH).");
        eprintln!("Use --help for more information.");
        std::process::exit(1); // Exit with an error code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // --- Tests for dictionary_attack ---
    #[test]
    fn test_dictionary_attack_found() {
        let mut wordlist = HashSet::new();
        wordlist.insert("apple".to_string());
        wordlist.insert("banana".to_string());
        wordlist.insert("octopus".to_string());

        let hash = "fcf1eed8596699624167416a1e7e122e";
        assert_eq!(dictionary_attack(hash, &wordlist), Some("octopus".to_string()));
    }

    #[test]
    fn test_dictionary_attack_not_found() {
        let mut wordlist = HashSet::new();
        wordlist.insert("apple".to_string());
        wordlist.insert("banana".to_string());

        let hash = "fcf1eed8596699624167416a1e7e122e"; // octopus
        assert_eq!(dictionary_attack(hash, &wordlist), None);
    }

    #[test]
    fn test_dictionary_attack_empty_wordlist() {
        let wordlist = HashSet::new();
        let hash = "fcf1eed8596699624167416a1e7e122e";
        assert_eq!(dictionary_attack(hash, &wordlist), None);
    }

    #[test]
    fn test_dictionary_attack_case_insensitivity_of_input_word() {
        let mut wordlist = HashSet::new();
        wordlist.insert("Octopus".to_string());

        let hash = "fcf1eed8596699624167416a1e7e122e";
        assert_eq!(dictionary_attack(hash, &wordlist), Some("octopus".to_string()));
    }
     #[test]
    fn test_dictionary_attack_hash_is_lowercase() {
        let mut wordlist = HashSet::new();
        wordlist.insert("octopus".to_string());

        let hash_uppercase = "FCF1EED8596699624167416A1E7E122E";
        assert_eq!(dictionary_attack(hash_uppercase, &wordlist), None);
    }

    // --- Tests for load_hashes_from_file ---
    #[test]
    fn test_load_hashes_from_file_valid_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "This line has fcf1eed8596699624167416a1e7e122e (octopus)").unwrap();
        writeln!(file, "e10adc3949ba59abbe56e057f20f883e:123456").unwrap();
        writeln!(file, "No hash here").unwrap();
        writeln!(file, "098F6BCD4621D373CADE4E832627B4F6 surrounding text").unwrap();
        writeln!(file, "Duplicate: e10adc3949ba59abbe56e057f20f883e").unwrap();
        writeln!(file, "Invalid gggggggggggggggggggggggggggggggg hash").unwrap();

        let file_path = file.path().to_str().unwrap();
        let hashes = load_hashes_from_file(file_path).unwrap();

        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], "098f6bcd4621d373cade4e832627b4f6");
        assert_eq!(hashes[1], "e10adc3949ba59abbe56e057f20f883e");
        assert_eq!(hashes[2], "fcf1eed8596699624167416a1e7e122e");
    }

    #[test]
    fn test_load_hashes_from_file_non_existent() {
        let result = load_hashes_from_file("non_existent_file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_hashes_from_file_empty_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "").unwrap();

        let file_path = file.path().to_str().unwrap();
        let hashes = load_hashes_from_file(file_path).unwrap();

        assert!(hashes.is_empty());
    }

    #[test]
    fn test_load_hashes_from_file_no_hashes_in_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "This file contains no valid md5 hashes.").unwrap();
        writeln!(file, "Just some regular text here.").unwrap();

        let file_path = file.path().to_str().unwrap();
        let hashes = load_hashes_from_file(file_path).unwrap();

        assert!(hashes.is_empty());
    }

    // --- Tests for cache functions (load_cache, append_to_cache) ---
    #[test]
    fn test_load_cache_non_existent() {
        let cache = load_cache("non_existent_cache.txt").unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_load_cache_valid_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hash1:plain1").unwrap();
        writeln!(file, "hash2:plain2").unwrap();

        let cache_path = file.path().to_str().unwrap();
        let cache = load_cache(cache_path).unwrap();

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("hash1"), Some(&"plain1".to_string()));
        assert_eq!(cache.get("hash2"), Some(&"plain2".to_string()));
    }

    #[test]
    fn test_load_cache_malformed_lines() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hash1:plain1").unwrap();
        writeln!(file, "malformed_line_no_colon").unwrap();
        writeln!(file, "hash2:plain2").unwrap();
        writeln!(file, ":empty_hash_empty_plain").unwrap();
        writeln!(file, "hash3:").unwrap();
        writeln!(file, ":plain4").unwrap();

        let cache_path = file.path().to_str().unwrap();
        let cache = load_cache(cache_path).unwrap();

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("hash1"), Some(&"plain1".to_string()));
        assert_eq!(cache.get("hash2"), Some(&"plain2".to_string()));
    }

    #[test]
    fn test_append_to_cache_creates_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("new_cache.txt");

        assert!(!cache_path.exists());
        append_to_cache(cache_path.to_str().unwrap(), "newhash", "newplain").unwrap();
        assert!(cache_path.exists());

        let cache = load_cache(cache_path.to_str().unwrap()).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("newhash"), Some(&"newplain".to_string()));
    }

    #[test]
    fn test_append_to_cache_appends_to_existing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hash1:plain1").unwrap();
        let cache_path = file.path().to_str().unwrap();

        append_to_cache(cache_path, "hash2", "plain2").unwrap();

        let cache = load_cache(cache_path).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("hash1"), Some(&"plain1".to_string()));
        assert_eq!(cache.get("hash2"), Some(&"plain2".to_string()));
    }

    #[test]
    fn test_cache_combined_load_append_reload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path_buf = temp_dir.path().join("combined_cache.txt");
        let cache_path = cache_path_buf.to_str().unwrap();

        // Load non-existent, should be empty
        let _cache = load_cache(cache_path).unwrap(); // _cache not mutated, load_cache returns new
        assert!(_cache.is_empty()); // Check the returned cache

        append_to_cache(cache_path, "h1", "p1").unwrap();

        let loaded_cache1 = load_cache(cache_path).unwrap();
        assert_eq!(loaded_cache1.len(), 1);
        assert_eq!(loaded_cache1.get("h1"), Some(&"p1".to_string()));

        append_to_cache(cache_path, "h2", "p2").unwrap();

        let loaded_cache2 = load_cache(cache_path).unwrap();
        assert_eq!(loaded_cache2.len(), 2);
        assert_eq!(loaded_cache2.get("h1"), Some(&"p1".to_string()));
        assert_eq!(loaded_cache2.get("h2"), Some(&"p2".to_string()));
    }
}
