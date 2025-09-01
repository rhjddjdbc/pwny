#!/usr/bin/env bash

# Load components
source "$(dirname "$0")/lib/config.sh"
source "$(dirname "$0")/lib/helpers.sh"
source "$(dirname "$0")/lib/payloads.sh"
source "$(dirname "$0")/lib/tests.sh"
source "$(dirname "$0")/lib/subdomain_scan.sh"

log "[*] Target domain: $DOMAIN"
log "[*] Scheme: $SCHEME"
log "[*] Logfile: $LOGFILE"
log "[*] JSON interim: $JSON_TMP"
log "[*] CSV output: $OUTPUT_CSV"
log "[*] Starting automated scan..."

BASE_URL="${SCHEME}://${DOMAIN}"

if $RUN_ALL; then
  log "[*] Running all tests in background on: $BASE_URL"
  test_all_for "$BASE_URL" &
  PID=$!
  wait $PID
else
  log "[*] Running selected tests synchronously on: $BASE_URL"
  
  if $RUN_SQLI; then
    test_sqli "$BASE_URL"
  fi
  
  if [[ "$FLAG_TEST_BLIND_SQLI" == true ]]; then
    test_blind_sqli "$BASE_URL"
  fi

  if $RUN_XSS; then
    test_xss "$BASE_URL"
  fi
  
  if $RUN_PATH_TRAV; then
    test_path_traversal "$BASE_URL"
  fi

  if $RUN_CMDI; then
    test_cmd_injection "$BASE_URL"
  fi

  if $RUN_LFI; then
    test_lfi "$BASE_URL"
  fi

  if $RUN_REDIRECT; then
    test_redirect "$BASE_URL"
  fi

  if $RUN_IDOR; then
    test_idor "$BASE_URL"
  fi

  if [[ "$FLAG_TEST_CSRF" == true ]]; then
    test_csrf "$BASE_URL"
  fi
fi

if [[ -n "$WORDLIST" ]]; then
  if [[ ! -f "$WORDLIST" ]]; then
    log "[!] Wordlist not found: $WORDLIST"
  else
    log "[*] Starting subdomain brute using $WORDLIST (concurrency=$CONCURRENCY)..."
    sed -e 's/#.*$//' -e '/^\s*$/d' "$WORDLIST" | xargs -n1 -P "$CONCURRENCY" -I{} bash -c 'test_subdomain_and_scan "$@"' _ {}
    log "[*] Subdomain brute finished."
  fi
fi

if [[ -s "$JSON_TMP" ]]; then
  jq -s '.' "$JSON_TMP" > "$OUTPUT_JSON"
  log "[*] JSON results written to $OUTPUT_JSON"
else
  log "[*] No JSON results to write."
fi

log "[*] CSV results written to $OUTPUT_CSV"
log "[*] Scan complete. Log: $LOGFILE"

if [ -f "$CURL_ERR_LOG" ] && [ ! -s "$CURL_ERR_LOG" ]; then
  rm "$CURL_ERR_LOG"
fi

if [ -f "$JSON_TMP" ]; then
  rm "$JSON_TMP"
fi
