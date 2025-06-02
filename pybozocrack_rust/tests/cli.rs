use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs
use std::fs::{self, File};
use std::io::Write;
use std::path::Path; // Added for checking cache.txt existence
use tempfile::tempdir; // For temporary directories and files

// Helper function to create a temporary file with content
fn create_temp_file(dir: &tempfile::TempDir, file_name: &str, content: &str) -> std::path::PathBuf {
    let file_path = dir.path().join(file_name);
    let mut file = File::create(&file_path).expect("Failed to create temp file");
    writeln!(file, "{}", content).expect("Failed to write to temp file");
    file_path
}

#[test]
fn test_no_arguments() {
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error: Please provide a hash to crack").and(predicate::str::contains("Use --help for more information.")));
}

#[test]
fn test_help_short_flag() {
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.arg("-h");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: pybozocrack_rust [OPTIONS]"));
}

#[test]
fn test_help_long_flag() {
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: pybozocrack_rust [OPTIONS]"));
}

#[test]
fn test_version_flag() {
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_single_hash_not_found() {
    // Use a hash that's unlikely to be found or cached
    let unknown_hash = "11111111111111111111111111111111";
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    // Ensure clean cache for this test
    let temp_dir = tempdir().unwrap();
    let cache_file_path = temp_dir.path().join("test_cache_not_found.txt");
    if cache_file_path.exists() {
        fs::remove_file(&cache_file_path).unwrap();
    }

    cmd.arg("-s").arg(unknown_hash);
    // If CACHE_FILE_PATH env var is supported by app:
    // cmd.env("CACHE_FILE_PATH", cache_file_path.to_str().unwrap());
    // For now, assumes cache.txt is created in CWD if not overridden
    // To make tests independent, we should ideally manage cache.txt or make its path configurable.
    // For this test, we assume it tries to create/use "cache.txt" in the current test execution directory.
    // And since it's unlikely to be found, we check for "Password not found".

    cmd.assert()
        .success() // Program itself doesn't fail, just doesn't find it
        .stdout(predicate::str::contains(format!("Password not found for: {}", unknown_hash)));

    // Clean up any cache created in CWD if necessary, or handle via temp_dir if app supports it.
    if Path::new("cache.txt").exists() {
        fs::remove_file("cache.txt").unwrap_or_default();
    }
}


#[test]
fn test_file_input_non_existent() {
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.arg("-f").arg("non_existent_test_file.txt");
    cmd.assert()
        .success() // The program currently prints an error to stderr but doesn't exit with failure code for this
        .stderr(predicate::str::contains("Error loading hashes from file non_existent_test_file.txt"));
}


// More tests to come:
// - Cracking single known hash (octopus) + caching
// - Cracking from file + caching
// - "No hashes were cracked" message
//
// To manage cache for integration tests more robustly:
// 1. Modify app to accept CACHE_FILE_PATH from env var.
// 2. Or, ensure each test runs in a unique temp directory where it can create its own cache.txt.
//    `assert_cmd` allows setting current_dir for the Command.

#[test]
fn test_crack_single_hash_octopus_and_cache() {
    let temp_dir = tempdir().unwrap(); // Each test gets its own temp dir
    let cache_file_path = temp_dir.path().join("cache.txt");
    let octopus_hash = "fcf1eed8596699624167416a1e7e122e";

    // Run 1: Crack and cache
    let mut cmd1 = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd1.current_dir(temp_dir.path()); // Run command in temp_dir so cache.txt is created there
    cmd1.arg("-s").arg(octopus_hash);

    cmd1.assert()
        .success()
        .stdout(predicate::str::contains(format!("{}:octopus", octopus_hash)))
        .stdout(predicate::str::contains("Not in cache. Attempting to crack:"));

    assert!(cache_file_path.exists(), "Cache file should have been created");

    // Run 2: Load from cache
    let mut cmd2 = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd2.current_dir(temp_dir.path());
    cmd2.arg("-s").arg(octopus_hash);

    cmd2.assert()
        .success()
        .stdout(predicate::str::contains(format!("Found in cache: {}:octopus", octopus_hash)));
}

#[test]
fn test_crack_from_file_and_cache() {
    let temp_dir = tempdir().unwrap();
    let cache_file_path = temp_dir.path().join("cache.txt");

    let octopus_hash = "fcf1eed8596699624167416a1e7e122e"; // octopus
    let test_hash = "098f6bcd4621d373cade4e832627b4f6";    // test
    let unknown_hash = "11111111111111111111111111111111";

    let content = format!("{}\n{}\n{}", octopus_hash, test_hash, unknown_hash);
    let hash_file_path = create_temp_file(&temp_dir, "test_hashes.txt", &content);

    // Run 1: Crack octopus, test; unknown not found; cache them.
    let mut cmd1 = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd1.current_dir(temp_dir.path());
    cmd1.arg("-f").arg(hash_file_path.to_str().unwrap());

    cmd1.assert()
        .success()
        .stdout(predicate::str::contains(format!("{}:octopus", octopus_hash)))
        .stdout(predicate::str::contains(format!("{}:test", test_hash)))
        .stdout(predicate::str::contains(format!("Not in cache. Attempting to crack: {}", octopus_hash)))
        .stdout(predicate::str::contains(format!("Not in cache. Attempting to crack: {}", test_hash)))
        // It WILL search for unknown_hash, just won't find it. So no .not() here.
        .stdout(predicate::str::contains(format!("Searching URL for {}:", unknown_hash)));

    assert!(cache_file_path.exists());
    // Verify cache content (optional here, can be done by next run)
    // let cache_content = fs::read_to_string(&cache_file_path).unwrap();
    // assert!(cache_content.contains("octopus"));
    // assert!(cache_content.contains("test"));

    // Run 2: Load octopus, test from cache; unknown still not found.
    let mut cmd2 = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd2.current_dir(temp_dir.path());
    cmd2.arg("-f").arg(hash_file_path.to_str().unwrap());

    cmd2.assert()
        .success()
        .stdout(predicate::str::contains(format!("Found in cache: {}:octopus", octopus_hash)))
        .stdout(predicate::str::contains(format!("Found in cache: {}:test", test_hash)))
        // On the second run, unknown_hash is still not in cache, so it WILL attempt to crack it again.
        .stdout(predicate::str::contains(format!("Not in cache. Attempting to crack: {}", unknown_hash)));
}

#[test]
fn test_file_input_no_hashes_cracked_message() {
    let temp_dir = tempdir().unwrap();
    let unknown_hash = "11111111111111111111111111111111";
    let hash_file_path = create_temp_file(&temp_dir, "only_unknown.txt", unknown_hash);

    // Run with a hash that won't be cracked and isn't in cache
    let mut cmd = Command::cargo_bin("pybozocrack_rust").unwrap();
    cmd.current_dir(temp_dir.path());
    cmd.arg("-f").arg(hash_file_path.to_str().unwrap());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("No hashes were cracked."));
}
