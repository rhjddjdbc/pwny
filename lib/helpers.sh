#!/usr/bin/env bash

log() { printf '%s\n' "$1" | tee -a "$LOGFILE"; }
log_warn() { printf '[!] %s\n' "$1" | tee -a "$LOGFILE"; }

urlencode() {
  printf '%s' "$1" | jq -sRr @uri
}

append_query() {
  local url="$1"; local name="$2"; local value="$3"
  if [[ "$url" == *\?* ]]; then
    printf '%s&%s=%s' "$url" "$name" "$value"
  else
    printf '%s?%s=%s' "$url" "$name" "$value"
  fi
}

# curl helpers with retries/backoff and optional dry-run
curl_get() {
  local url=$1
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY-RUN] Would GET: $url"
    echo ""
    return
  fi

  local attempt=0
  local resp=""
  local curl_opts=(-sS --compressed --http2 --max-time 8 --connect-timeout 4 -A "web_tester/1.0")
  [[ -n "$COOKIE" ]] && curl_opts+=(-b "$COOKIE")

  while :; do
    attempt=$((attempt+1))
    if ! resp=$(curl "${curl_opts[@]}" "$url" 2>curl_err.log); then
      local err_msg
      err_msg=$(<curl_err.log)
      log_warn "[curl_get] Error on attempt $attempt for $url: $err_msg"
      if [[ $attempt -le $RETRIES ]]; then
        sleep "$BACKOFF"
        continue
      else
        echo ""
        return 1
      fi
    else
      echo "$resp"
      return 0
    fi
  done
}

curl_head_code() {
  local url=$1
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY-RUN] Would HEAD: $url"
    echo "000"
    return
  fi

  local attempt=0
  local code="000"
  local curl_opts=(-sS --compressed --http2 --connect-timeout 4 --max-time 6 -I -A "web_tester/1.0")
  [[ -n "$COOKIE" ]] && curl_opts+=(-b "$COOKIE")

  while :; do
    attempt=$((attempt+1))
    if ! code=$(curl "${curl_opts[@]}" -w "%{http_code}" -o /dev/null "$url" 2>curl_err.log); then
      local err_msg
      err_msg=$(<curl_err.log)
      log_warn "[curl_head] Error on attempt $attempt for $url: $err_msg"
      if [[ $attempt -le $RETRIES ]]; then
        sleep "$BACKOFF"
        continue
      else
        echo "000"
        return 1
      fi
    else
      echo "$code"
      return 0
    fi
  done
}

# record a finding: write JSONL and CSV line
record_finding() {
  local domain="$1"; local url="$2"; local test="$3"; local detail="$4"; local extra="${5:-}"
  local ts

  if date --version >/dev/null 2>&1; then
    ts=$(date --iso-8601=seconds)
  else
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  fi

  jq -n --arg ts "$ts" --arg domain "$domain" --arg url "$url" --arg test "$test" --arg detail "$detail" --arg extra "$extra" \
    '{timestamp:$ts,domain:$domain,url:$url,test:$test,detail:$detail,extra:$extra}' >> "$JSON_TMP"

  if [[ ! -s "$OUTPUT_CSV" ]]; then
    echo '"timestamp","domain","url","test","detail","extra"' > "$OUTPUT_CSV"
  fi
  jq -n --arg ts "$ts" --arg domain "$domain" --arg url "$url" \
       --arg test "$test" --arg detail "$detail" --arg extra "$extra" \
       '[$ts,$domain,$url,$test,$detail,$extra] | @csv' >> "$OUTPUT_CSV"
}

