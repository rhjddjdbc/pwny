#!/usr/bin/env bash

test_cmd_injection() {
  local base="$1"
  for p in "${CMD_INJ_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "host" "$enc")
    local resp; resp=$(curl_get "$target" -m 5)
    if [[ -n "$resp" ]]; then
      if printf '%s' "$resp" | grep -q "INJECTION_MARKER"; then
        log "[+] Command injection likely (marker found): $target"
        record_finding "$base" "$target" "cmd_injection" "marker reflected" "$p"
        echo "[*] Tested payload '$p': Found"
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': No response"
    fi
  done
}

test_lfi() {
  local base="$1"
  for p in "${LFI_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "page" "$enc")
    local resp; resp=$(curl_get "$target")
    local code; code=$(curl_head_code "$target")
    if [[ "$code" == "200" ]] && [[ -n "$resp" ]]; then
      if printf '%s' "$resp" | grep -qE "root:|/bin/bash|/bin/sh"; then
        log "[+] LFI likely: $target"
        record_finding "$base" "$target" "lfi" "found typical passwd marker" "$p"
        echo "[*] Tested payload '$p': Found"
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found (HTTP $code)"
    fi
  done
}

test_redirect() {
  local base="$1"
  for p in "${REDIRECT_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "url" "$enc")
    if [[ "$DRY_RUN" == "true" ]]; then
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Dry run, skipped"
      continue
    fi
    local headers
    headers=$(curl -sSI --max-time 6 -b "$COOKIE" -A "web_tester/1.0" "$target" 2>/dev/null || true)
    local code; code=$(printf '%s' "$headers" | grep -i '^HTTP/' | tail -n1 | awk '{print $2}')
    if [[ "$code" =~ ^3[0-9][0-9]$ ]]; then
      if printf '%s' "$headers" | tr -d '\r' | grep -i '^location:' >/dev/null; then
        local locs
        locs=$(printf '%s' "$headers" | tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^location:[ \t]*/,""); print}')
        local found=0
        while IFS= read -r loc; do
          if printf '%s' "$loc" | grep -qiE "example\.com|evil\.com|//"; then
            log "[+] Open redirect likely: $target -> $loc"
            record_finding "$base" "$target" "open_redirect" "$loc" "$p"
            echo "[*] Tested payload '$p': Found (Redirect to $loc)"
            found=1
          fi
        done <<< "$locs"
        if [[ $found -eq 0 ]]; then
          [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found (no suspicious redirect)"
        fi
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found (no Location header)"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found (HTTP $code)"
    fi
  done
}

test_idor() {
  local base="$1"
  local baseline; baseline=$(curl_get "$base" || true)
  local base_code; base_code=$(curl_head_code "$base")
  local base_hash; base_hash=$(echo "$baseline" | sha1sum | cut -d' ' -f1)
  for id in {1..20}; do
    local target; target=$(append_query "$base" "id" "$id")
    local resp; resp=$(curl_get "$target")
    local code; code=$(curl_head_code "$target")
    local hash; hash=$(echo "$resp" | sha1sum | cut -d' ' -f1)
    if [[ "$code" == "$base_code" ]] && [[ "$hash" != "$base_hash" ]]; then
      record_finding "$base" "$target" "idor" "response_hash_diff" "id=$id"
      echo "[*] Tested payload 'id=$id': Found (response hash differs)"
    elif [[ "$code" != "$base_code" ]]; then
      record_finding "$base" "$target" "idor" "status_code_diff:$code" "id=$id"
      echo "[*] Tested payload 'id=$id': Found (status code differs: $code)"
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload 'id=$id': Not found"
    fi
  done
}

test_xss() {
  local base="$1"
  for p in "${XSS_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "q" "$enc")
    local resp; resp=$(curl_get "$target")
    if [[ -n "$resp" ]]; then
      if printf '%s' "$resp" | grep -Fq "$p" || printf '%s' "$resp" | grep -qi "<script"; then
        log "[+] XSS likely/reflection: $target"
        record_finding "$base" "$target" "xss" "reflected or script tag found" "$p"
        echo "[*] Tested payload '$p': Found"
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': No response"
    fi
  done
}

test_sqli() {
  local base="$1"
  local baseline; baseline=$(curl_get "$base" || true)
  for p in "${SQLI_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "id" "$enc")
    local resp; resp=$(curl_get "$target")
    if [[ -n "$resp" ]]; then
      local blen rlen diff
      blen=${#baseline}; rlen=${#resp}; diff=$(( rlen - blen ))
      if printf '%s' "$resp" | grep -qiE "sql|syntax|mysql|oracle|postgres|first name|error in your SQL"; then
        log "[+] SQLi likely: $target"
        record_finding "$base" "$target" "sqli" "error page or keyword match" "$p"
        echo "[*] Tested payload '$p': Found"
      elif (( diff > 1000 || diff < -1000 )); then
        log "[+] SQLi candidate (response size delta): $target (Δ=$diff)"
        record_finding "$base" "$target" "sqli_suspect" "size_delta:$diff" "$p"
        echo "[*] Tested payload '$p': Found"
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': No response"
    fi
  done
}

test_path_traversal() {
  local base="$1"
  for p in "${PATH_TRAV_PAYLOADS[@]}"; do
    local enc; enc=$(urlencode "$p")
    local target; target=$(append_query "$base" "file" "$enc")
    local resp; resp=$(curl_get "$target")
    local code; code=$(curl_head_code "$target")
    if [[ "$code" == "200" ]] && [[ -n "$resp" ]]; then
      if printf '%s' "$resp" | grep -qE "root:|/bin/bash|/bin/sh"; then
        log "[+] Path traversal likely: $target"
        record_finding "$base" "$target" "path_traversal" "passwd marker" "$p"
        echo "[*] Tested payload '$p': Found"
      else
        [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found"
      fi
    else
      [[ "$VERBOSE" == "true" ]] && echo "[*] Tested payload '$p': Not found (HTTP $code)"
    fi
  done
}

test_all_for() {
  local url=$1
  test_sqli "$url"
  test_xss "$url"
  test_path_traversal "$url"
  test_cmd_injection "$url"
  test_lfi "$url"
  test_redirect "$url"
  test_idor "$url"
}

