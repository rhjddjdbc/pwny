#!/usr/bin/env bash

test_subdomain_and_scan() {
  local subword="$1"
  local host="${subword}.${DOMAIN}"

  subword=$(echo "$subword" | tr '[:upper:]' '[:lower:]')
  if ! [[ "$subword" =~ ^[a-z0-9-]+$ ]]; then
    log_warn "Skipping invalid subdomain word: $subword"
    return
  fi

  if [[ "${USE_DNS_PROBE:-false}" == "true" ]]; then
    if ! dig +short A "$host" | grep -q .; then
      log_warn "No DNS record for $host"
      return
    fi
  fi

  local url="${SCHEME}://${host}"
  local code; code=$(curl_head_code "$url")

  if [[ "$code" == "000" ]]; then
    log_warn "No HTTP response from $host"
    return
  fi

  log "[+] Found host: $host (HTTP $code)"
  record_finding "$host" "$url" "host_found" "http_code:$code" ""
  test_all_for "$url"
}

export -f test_subdomain_and_scan

