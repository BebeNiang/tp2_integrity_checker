# TP2 – File Integrity Checker and IOC Matcher in Rust

## Technical Information
* **Module:** 7.1 – Programming with Rust (2025–2026)
* **Instructor:** S. Biha
* **Student Name:** Kadiata Niang
* **Student Matricule:** 22017
* **Affiliation:** Master in Cybersecurity, Institut Supérieur du Numérique (SupNum), Mauritania
* **Execution Environment:** Docker Compose (`rustlab` container)

---

## Project Overview
This repository contains a secure, high-performance command-line utility built in Rust designed for defensive security workflows. The tool walks through a target directory or evaluates a specific file, computes its cryptographic SHA-256 hash using the `sha2` crate, and cross-references the computed signatures against a local file containing Indicators of Compromise (IOCs). 

Finally, it outputs a human-readable diagnostic summary to the terminal and records an immutable log of its execution findings to a reproducible CSV report.

### Key Architectural & Safety Highlights
* **Zero Panic Policy:** The core execution path entirely avoids uncontrolled `.unwrap()` or `.expect()` calls, opting instead for Rust's idiomatic `Result<T, E>` monadic error handling to ensure production resilience.
* **Memory Safety & No Unsafe:** Developed fully under Rust's default safety guardrails, guaranteeing memory protection without invoking a single `unsafe` block.
* **Streaming File Hashing:** Uses fixed-size chunk buffers (4KB) to stream byte chunks sequentially into the SHA-256 digest machine, maintaining a strictly bounded memory footprint ($O(1)$ space complexity) regardless of target file sizes.
* **Robust Parsing Engine:** Fault-tolerant parsing logic comfortably strips out metadata, handles arbitrary whitespace, discards comment tags (`#`), and logs invalid hash definitions without breaking the running routine.
* **Recursive Scanning:** Implements an iterative stack-driven directory traversal algorithm to traverse nested file systems.

---

## Directory Structure
The workspace matches the requested lab configuration layout exactly:

```text
tp2_integrity_checker/
|-- Cargo.toml
|-- README.md
|-- src/
|   |-- main.rs          # CLI argument parsing, control flow orchestration
|   |-- hashing.rs       # Streamed SHA-256 hashing mechanism & regex rules
|   |-- ioc.rs           # Non-crashing CSV/IOC parsing logic
|   |-- scanner.rs       # Directory walking engine & match logic
|   |-- report.rs        # Format-compliant CSV generator
|-- samples/
|   |-- files/           # Target clean and malicious testing files
|   |-- iocs.txt         # Threat intelligence input manifest
|-- reports/
|   |-- scan_report.csv  # Final evidence deliverable
|-- screenshots/         # Required lab validation captures
Installation & Environment Setup
Ensure you are inside your deployed Docker Compose container environment before building:

Bash
# Move into the shared workspace directory
cd /workspace/tp2_integrity_checker

# Validate local toolchain states
rustc --version
cargo --version

# Pull down missing dependencies and compile the target binary
cargo build --release
Practical Usage Guide
Run the full integrity verification test sequence using the explicit long-form command switches:

Bash
cargo run -- --target samples/files --ioc samples/iocs.txt --report reports/scan_report.csv
Standard Terminal Console Layout Example
Plaintext
TP2 File Integrity Checker and IOC Matcher
Target: samples/files
IOC file: samples/iocs.txt
Report: reports/scan_report.csv

Summary:
  * Files scanned: 3
  * IOC entries loaded: 2
  * Invalid IOC lines: 1
  * Matches found: 1
  * Errors: 0

Matches:
  [ALERT] samples/files/suspicious_dropper.txt
    SHA-256: 44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b
    IOC label: Demo suspicious test sample

CSV report written to reports/scan_report.csv
Quality Assurance & Verification Commands
To guarantee complete compliance with academic standard grading rubrics, run these automated check pipes prior to submission:

1. Automatic Source Tree Formatting
Enforce standardized canonical source formatting rules via rustfmt:

Bash
cargo fmt --check
2. Static Application Code Analysis (Linting)
Run strict compilation checks treating style rules, architectural anti-patterns, or warnings as critical hard errors:

Bash
cargo clippy -- -D warnings
3. Unit Test Validation
Execute the integrated core module unit test validations:

Bash
cargo test
Defensive Engineering Discussion
Why SHA-256 is Selected Over Legacy MD5/SHA-1
Legacy algorithms such as MD5 and SHA-1 suffer from severe cryptographic vulnerabilities involving collision attacks (e.g., SHAttered). Threat actors can easily abuse these flaws by generating two entirely different files—one harmless and one a highly malicious implant—that resolve to identical hash representations.

By employing SHA-256, this utility provides reliable cryptographic resistance against both pre-image attacks and second pre-image attacks, guaranteeing that trusted system files cannot be spoofed by an adversary.

Error Resiliency Strategies
File input/output pipelines are inherently unsafe and subject to external environment variables (missing permissions, unexpected symlink loops, locked system directories). Rather than invoking abrupt crashes, this codebase systematically translates runtime std::io::Error records into structured domain data (ScanStatus::Error(String)). This mechanism logs failed states elegantly inside the final CSV deliverable while permitting the core threat scanner loop to advance seamlessly through the remaining target files.
