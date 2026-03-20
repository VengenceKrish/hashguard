# hashguard

A file integrity monitor written in Rust. Uses SHA256 hashing to detect unauthorized modifications to log files, storing baseline hashes in a secure SQLite database.

## How It Works

On first use, hashguard computes and stores a SHA256 hash of each log file as a baseline. On subsequent runs, it recomputes the hash and compares it against the stored value. Any difference means the file has been modified.

All discrepancies are logged to the database with a timestamp, the original hash, the new hash, and whether the baseline was overwritten — giving you a full audit trail.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- SQLite development library

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libsqlite3-dev
```

## Installation

```bash
git clone https://github.com/VengenceKrish/hashguard.git
cd hashguard
cargo build --release
```

The compiled binary will be at `target/release/file_integrity_checker`.

Optionally move it to your PATH so you can run it from anywhere.

## Usage

Run the program:
```bash
cargo run
```

Or if installed to PATH:
```bash
hashguard
```

You will be prompted to enter a file or directory path:
```
Enter log file or directory PATH:
> /var/log/auth.log
```

**Single file** — hashguard will process that file only.

**Directory** — hashguard will scan the directory and process all `.log` files found in it.

## What to Expect

**First run on a file:**
```
File opened successfully
Baseline hash stored for 'auth.log'
```

**File is unchanged:**
```
File 'auth.log' has no modifications. No changes required.
```

**File has been modified:**
```
WARNING: File 'auth.log' has been modified!
Would you like to overwrite the stored hash? (yes/no)
```

- Typing `yes` updates the stored baseline and logs the overwrite
- Typing `no` leaves the baseline unchanged and logs the discrepancy
- After 3 invalid inputs the prompt aborts automatically

## Database

hashguard creates a `hashes.db` SQLite file in the directory you run it from. It contains two tables:

- `file_hashes` — stores the current baseline hash for each file
- `discrepancies` — audit log of every detected modification, including timestamp and whether it was overwritten

**The database should be stored in a location only accessible to admins.** The security model assumes attackers can access the log files but not the database.

## Threat Model

hashguard is designed for environments where:
- Log files may be accessed or modified by bad actors
- The database is secured and accessible only to administrators

An attacker renaming or modifying a log file will trigger a mismatch alert. An attacker cannot spoof a clean result without access to the database.

## Idea Source

https://roadmap.sh/projects/file-integrity-checker