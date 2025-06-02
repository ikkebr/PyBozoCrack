# BozoCrack-rs (PyBozoCrack Rust Port)

BozoCrack-rs is a Rust application designed to "crack" MD5 hashes by searching for them on Google. If Google has indexed the hash (often found on sites that list MD5 hashes and their corresponding plaintexts), BozoCrack-rs can extract potential plaintexts from the search results and verify them. This tool is a Rust port of the original PyBozoCrack by Julio C. S. Arruda.

## Why?

This tool, like its predecessor, serves as a reminder of how insecure plain MD5 hashes are. If your hash is indexed by Google, it's effectively public knowledge. **Do not use plain MD5 for anything that requires security.** Always use strong, salted hashing algorithms.

## Features

*   Cracks MD5 hashes by searching for them on Google.
*   Supports cracking a single hash provided on the command line.
*   Supports cracking multiple hashes from a specified input file.
*   Caches successfully cracked hash:plaintext pairs to avoid redundant work.
*   Simple command-line interface.

## Requirements

*   **Rust:** Version 1.75.0 or later (developed with 1.75.0).
*   **Cargo:** Rust's build system and package manager (usually comes with Rust).
*   **Internet Connection:** Required for querying Google.

## Building the Project

1.  **Clone the project:**
    ```bash
    # git clone <repository_url>
    # (Replace <repository_url> with the actual URL when available)
    # For now, navigate to your project directory if you have the source code.
    ```
2.  **Navigate to the project directory:**
    ```bash
    cd pybozocrack_rust
    ```
3.  **Build the release version:**
    ```bash
    cargo build --release
    ```
    The executable will be available at `target/release/pybozocrack_rust`.

## Running the Application

The main executable is `target/release/pybozocrack_rust`.

### Basic Usage Examples

*   **Cracking a single hash:**
    ```bash
    target/release/pybozocrack_rust -s <MD5_HASH>
    ```
    Example:
    ```bash
    target/release/pybozocrack_rust -s fcf1eed8596699624167416a1e7e122e
    ```
    Output might be:
    ```
    Loaded 0 items from cache.

    Processing single hash: fcf1eed8596699624167416a1e7e122e
    Not in cache. Attempting to crack: fcf1eed8596699624167416a1e7e122e
    Searching URL for fcf1eed8596699624167416a1e7e122e: http://www.google.com/search?q=fcf1eed8596699624167416a1e7e122e
    fcf1eed8596699624167416a1e7e122e:octopus
    ```

*   **Cracking hashes from a file:**
    ```bash
    target/release/pybozocrack_rust -f <FILE_PATH>
    ```
    Example (using the provided `example.txt`):
    ```bash
    target/release/pybozocrack_rust -f example.txt
    ```
    The input file (`example.txt` or your own) does not need a specific format. The tool scans each line and extracts any 32-character hexadecimal strings it finds, treating them as potential MD5 hashes.

### Cache Behavior

*   The application uses a cache file named `cache.txt` (created in the directory where you run the command).
*   Successfully cracked hashes are stored in this file in the format `hash:plaintext`.
*   On startup, the cache is loaded. If a hash is already in the cache, its plaintext is used directly without querying Google.

## Differences from PyBozoCrack (Python)

*   This is a Rust port of the original PyBozoCrack, aiming to replicate its core functionality.
*   The command-line interface and operational behavior are intended to be very similar.
*   Being a compiled Rust application, it might offer performance improvements in certain areas (e.g., text processing, concurrent requests if implemented) compared to the original Python script, though the primary bottleneck remains network latency to Google.
*   Error messages and exact output formatting might have minor differences.

## License

This project is intended to be licensed under the BSD license, similar to the original PyBozoCrack. (A `LICENSE` file should be included in the repository if this is the case).
