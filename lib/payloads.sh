#!/usr/bin/env bash

declare -a SQLI_PAYLOADS XSS_PAYLOADS PATH_TRAV_PAYLOADS CMD_INJ_PAYLOADS LFI_PAYLOADS REDIRECT_PAYLOADS

load_payloads() {
  local name="$1"
  local varname="$2"
  local file="payloads/${name}.txt"
  local arr=()
  if [[ -f "$file" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && arr+=("$line")
    done < "$file"
  fi
  eval "$varname=(${arr[@]@Q})"
}

load_payloads "sqli" SQLI_PAYLOADS
load_payloads "xss" XSS_PAYLOADS
load_payloads "path_traversal" PATH_TRAV_PAYLOADS
load_payloads "cmd_injection" CMD_INJ_PAYLOADS
load_payloads "lfi" LFI_PAYLOADS
load_payloads "redirect" REDIRECT_PAYLOADS

