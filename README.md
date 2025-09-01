# pwny.sh — Automated Web Vulnerability Scanner

`pwny.sh` is a fast, modular, Bash-based scanner for detecting common web vulnerabilities. It supports custom payloads, subdomain bruteforcing, logging, and JSON/CSV output. Intended for authorized testing only.

---

## Features

* Detects the following vulnerabilities:

  * SQL Injection (SQLi)
  * Cross-site Scripting (XSS)
  * Command Injection
  * Local File Inclusion (LFI)
  * Path Traversal
  * Open Redirect
  * Insecure Direct Object References (IDOR)
  * Cross-Site Request Forgery (CSRF)
* Loads payloads from modular `./payloads/*.txt` files
* Automatic protocol detection (`http` or `https`)
* Subdomain bruteforcing with optional DNS probing
* Dry-run and verbose modes
* CSV and JSON output
* Minimal dependencies (`curl`, `jq`, `dig` optional)

---

## Installation

```bash
git clone https://github.com/yourusername/pwny.sh.git
cd pwny.sh
chmod +x pwny.sh
```

Ensure the following are installed:

* `bash`
* `curl`
* `jq`
* `dig` (optional, for DNS probing)

---

## Usage

```bash
./pwny.sh [options]
```

### Options

| Option         | Description                                |
| -------------- | ------------------------------------------ |
| `--sqli`       | Test for SQL Injection                     |
| `--xss`        | Test for Cross-site Scripting              |
| `--lfi`        | Test for Local File Inclusion              |
| `--cmdi`       | Test for Command Injection                 |
| `--path-trav`  | Test for Path Traversal                    |
| `--redirect`   | Test for Open Redirect                     |
| `--idor`       | Test for IDOR                              |
| `--csrf`       | Test for Cross-Site Request Forgery (CSRF) |
| `--all`        | Run all tests                              |
| `--verbose`    | Enable verbose output                      |
| `--dry-run`    | Simulate requests only                     |
| `--help`, `-h` | Show help                                  |

---

## Input Format

You will be prompted to enter a target domain:

```
Enter target domain (e.g. https://example.com or example.com):
```

Accepted formats:

* `example.com`
* `https://example.com`
* `http://sub.example.com`

The protocol (`http` or `https`) is detected automatically.

---

## Subdomain Bruteforcing

The tool can enumerate subdomains by applying words from a wordlist to the target domain.

### How it works

* Provide a wordlist of possible subdomain names (e.g. `subdomains.txt`).
* The script appends those words to the base domain (e.g. `admin.example.com`, `dev.example.com`).
* If `USE_DNS_PROBE` is set to `true`, the tool checks whether the subdomain actually resolves (DNS lookup).
* Discovered subdomains are then tested for vulnerabilities.

### Example

1. Create a wordlist `subdomains.txt` with entries like:

```
admin
dev
test
mail
```

2. Set the environment variables and run the script:

```bash
WORDLIST=subdomains.txt USE_DNS_PROBE=true ./pwny.sh --all
```

This will automatically test `admin.example.com`, `dev.example.com`, etc.

---

## Optional Configuration File

If present, the script loads settings from `config.cfg` in the same directory:

```bash
# Example config.cfg
COOKIE="sessionid=abc123"
CONCURRENCY=30
USE_DNS_PROBE=true
LOGFILE="my_scan.log"
OUTPUT_JSON="output.json"
OUTPUT_CSV="output.csv"
```

---

## Environment Variables

| Variable        | Description                                      |
| --------------- | ------------------------------------------------ |
| `WORDLIST`      | Wordlist for subdomain bruteforcing              |
| `CONCURRENCY`   | Parallelism for subdomain scanning (default: 20) |
| `USE_DNS_PROBE` | If `true`, performs DNS resolution checks        |
| `COOKIE`        | Session cookie for requests                      |
| `LOGFILE`       | Log file (default: `scan.log`)                   |
| `OUTPUT_JSON`   | JSON output file (default: `results.json`)       |
| `OUTPUT_CSV`    | CSV output file (default: `results.csv`)         |

---

## Examples

```bash
# Run all tests against a domain
./pwny.sh --all

# Run only specific tests
./pwny.sh --xss --sqli --csrf

# Subdomain bruteforcing with custom wordlist
WORDLIST=subdomains.txt USE_DNS_PROBE=true ./pwny.sh --all

# LFI test with cookie and verbose output
COOKIE="session=abc123" ./pwny.sh --lfi --verbose
```

---

## Output

* JSON results: `results.json`
* CSV results: `results.csv`
* Log file: `scan.log`

Each finding includes timestamp, domain, URL, vulnerability type, payload details, and context.

---

## Legal Notice

The tool is intended only for authorized security testing, education, and research.

Do not run `pwny.sh` against systems you do not have explicit permission to test. Unauthorized scanning is illegal and unethical.

---

## License

MIT License — see the `LICENSE` file.
