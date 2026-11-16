#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

base='http://aegis.korvia.htb:3000/api/v1/aegis-mds/search'

probe() {
  local label="$1"
  local pipeline="$2"
  local body="$odyssey_root/responses/pipeline-${label}.body"
  local headers="$odyssey_root/responses/pipeline-${label}.headers"
  local code bytes
  curl --connect-timeout 5 --max-time 15 -sS -G \
    -D "$headers" -o "$body" \
    --data-urlencode "pipeline=${pipeline}" "$base"
  code=$(awk 'NR==1{print $2}' "$headers")
  bytes=$(wc -c < "$body")
  printf '\n### %-14s status=%s bytes=%s pipeline=%s\n' \
    "$label" "$code" "$bytes" "$pipeline"
  jq -c 'if type=="array" then {count:length,first:(.[0]//null|if type=="object" then {vendor,description} else . end)} else . end' \
    "$body" 2>/dev/null || tr '\n' ' ' < "$body" | head -c 500
  printf '\n'
}

probe empty       '[]'
probe match_hit   '[{"$match":{"vendor":"Yubico"}}]'
probe match_miss  '[{"$match":{"vendor":"no-such-control-7f3c92"}}]'
probe limit_one   '[{"$limit":1}]'
probe project     '[{"$project":{"_id":0,"vendor":1,"description":1}}]'
probe object      '{}'
probe malformed   'not-json'
