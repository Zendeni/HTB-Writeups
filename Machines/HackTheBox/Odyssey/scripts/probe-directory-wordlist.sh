#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 2 )) || {
  printf 'Usage: %s ROOT LABEL\n' "$0" >&2
  exit 2
}

root="${1%/}"
label="$2"
[[ "$root" =~ ^/[A-Za-z0-9._/@-]+$ ]] || exit 2
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2

wordlist=${ODYSSEY_DIRECTORY_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}
[[ -r "$wordlist" ]] || {
  printf 'wordlist not readable: %s\n' "$wordlist" >&2
  exit 1
}

batch_size=100
batch_number=0
declare -a batch=()

run_batch() {
  local response_path probe_label
  (( ${#batch[@]} )) || return 0
  batch_number=$((batch_number + 1))
  probe_label=$(printf 'dirword-%s-%03d' "$label" "$batch_number")
  "$script_dir/probe-module-paths.sh" "$probe_label" "${batch[@]}" >/dev/null
  response_path="$odyssey_root/responses/module-multi-$probe_label.body"
  jq -r '.[0].probe[] |
    select(.state == "ok" or ((.error // "") | startswith("Error: can\u0027t open for reading") | not)) |
    [.path, .state, (.error // "")] | @tsv' \
    "$response_path" 2>/dev/null
  batch=()
  if (( batch_number % 10 == 0 )); then
    printf 'progress root=%s batches=%d\n' "$root" "$batch_number" >&2
  fi
}

while IFS= read -r word; do
  [[ "$word" =~ ^[A-Za-z0-9._@-]+$ ]] || continue
  [[ "$word" == '.' || "$word" == '..' ]] && continue
  batch+=("$root/$word")
  if (( ${#batch[@]} == batch_size )); then
    run_batch
  fi
done < "$wordlist"

run_batch
printf 'complete root=%s batches=%d\n' "$root" "$batch_number" >&2
