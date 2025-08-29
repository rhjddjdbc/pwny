#!/usr/bin/env bash

# Define directories
LOG_DIR="./logs"
RESULTS_DIR="./results"
TMP_DIR="./tmp"

# Create directories if they don't exist
mkdir -p "$LOG_DIR" "$RESULTS_DIR" "$TMP_DIR"

# File paths
LOGFILE="${LOG_DIR}/scan.log"
CURL_ERR_LOG="${LOG_DIR}/curl_err.log"
OUTPUT_JSON="${RESULTS_DIR}/results.json"
OUTPUT_CSV="${RESULTS_DIR}/results.csv"
JSON_TMP="${TMP_DIR}/results.tmp.jsonl"

# Default settings
SCHEME="${SCHEME:-http}"
CONCURRENCY="${CONCURRENCY:-20}"
SAFE_MODE="${SAFE_MODE:-true}"
DRY_RUN="${DRY_RUN:-false}"
RETRIES="${RETRIES:-1}"
BACKOFF="${BACKOFF:-1}"
USE_DNS_PROBE="${USE_DNS_PROBE:-false}"

show_help() {
  cat <<'EOF'
┌──────────────────────────────────────────────┐
│                  pwny.sh                     │
│      Automated Web Vulnerability Scanner     │
└──────────────────────────────────────────────┘

Usage: ./pwny.sh [options]

Options:
  --sqli           Test for SQL injection
  --xss            Test for Cross-site scripting
  --lfi            Test for Local File Inclusion
  --cmdi           Test for Command Injection
  --path-trav      Test for Path Traversal
  --redirect       Test for Open Redirect
  --idor           Test for Insecure Direct Object References
  --all            Run all vulnerability tests
  --verbose        Enable verbose output
  --dry-run        Simulate requests without sending them
  --help, -h       Show this help message and exit

Input:
  You'll be prompted to enter a target domain.
  Accepted formats:
    - example.com
    - https://example.com
    - http://sub.domain.com

  The scheme (http or https) will be automatically detected.

Environment Variables:
  WORDLIST=filename.txt    Wordlist for subdomain brute-forcing
  CONCURRENCY=N            Number of parallel subdomain tests (default: 20)
  USE_DNS_PROBE=true       Enable DNS checking before subdomain scan
  COOKIE="SESSIONID=abc"   Send cookie with requests
  LOGFILE=scan.log         Output logfile
  OUTPUT_JSON=results.json Output JSON results file
  OUTPUT_CSV=results.csv   Output CSV results file

Examples:
  ./pwny.sh --all
  ./pwny.sh --xss --sqli
  WORDLIST=subs.txt ./pwny.sh --all
  COOKIE="token=xyz" ./pwny.sh --lfi --verbose

Notes:
- Results are saved as CSV and JSON.
- Payloads are loaded from ./payloads/*.txt
- Designed for authorized testing and research only.

EOF
}


# Initialisierung der Variablen
RUN_SQLI=false
RUN_XSS=false
RUN_LFI=false
RUN_CMDI=false
RUN_PATH_TRAV=false
RUN_REDIRECT=false
RUN_IDOR=false
RUN_ALL=false

# Parse CLI flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --sqli) RUN_SQLI=true ;;
    --xss) RUN_XSS=true ;;
    --lfi) RUN_LFI=true ;;
    --cmdi) RUN_CMDI=true ;;
    --path-trav) RUN_PATH_TRAV=true ;;
    --redirect) RUN_REDIRECT=true ;;
    --idor) RUN_IDOR=true ;;
    --verbose) VERBOSE=true ;;
    --dry-run) DRY_RUN=true ;;
    --all)  RUN_ALL=true;;
    --help|-h) show_help; exit 0 ;;
    *) echo "[!] Unknown option: $1"; exit 1 ;;
  esac
  shift
done

# Wenn kein Test gesetzt wurde, dann RUN_ALL=true setzen
if ! $RUN_SQLI && ! $RUN_XSS && ! $RUN_LFI && ! $RUN_CMDI && ! $RUN_PATH_TRAV && ! $RUN_REDIRECT && ! $RUN_IDOR && ! $RUN_ALL; then
  RUN_ALL=true
fi

# Load config file if exists
CONFIG_FILE="./config.cfg"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# Network and tools checks
ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || { echo "[!] No network connectivity."; exit 1; }
command -v jq >/dev/null || { echo "[!] 'jq' not found."; exit 1; }
command -v curl >/dev/null || { echo "[!] 'curl' not found."; exit 1; }
if [[ "$USE_DNS_PROBE" == "true" ]]; then
  command -v dig >/dev/null || { echo "[!] 'dig' not found but required."; exit 1; }
fi

# Prompt for domain
#read -rp "Enter target domain (e.g. example.com): " DOMAIN
#[[ -z "$DOMAIN" || ! "$DOMAIN" =~ ^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]] && { echo "[!] Invalid domain."; exit 1; }
read -rp "Enter target domain (e.g. https://example.com or example.com): " INPUT

# Extract scheme and domain
if [[ "$INPUT" =~ ^(https?)://([^/]+) ]]; then
  SCHEME="${BASH_REMATCH[1]}"
  DOMAIN="${BASH_REMATCH[2]}"
else
  SCHEME="${SCHEME:-http}"
  DOMAIN="$INPUT"
fi

# Validate domain
if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
  echo "[!] Invalid domain: $DOMAIN"
  exit 1
fi
