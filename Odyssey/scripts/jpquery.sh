#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 3 )) || {
  printf 'Usage: %s LABEL CONTEXT EXPR\n' "$0" >&2
  exit 2
}

label="$1"
context="$2"
expr="$3"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
[[ "$context" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
if [[ "$expr" == @* ]]; then
  expr_file=${expr#@}
  [[ "$expr_file" =~ ^artifacts/[A-Za-z0-9._/-]+$ ]] || exit 2
  expr_file="$odyssey_root/$expr_file"
  expr=$(<"$expr_file")
fi

token=${MDS_DIAG_TOKEN:-}
source_body="$odyssey_root/responses/template-render-mds-diag-env.body"
if [[ -z "$token" && -f "$source_body" ]]; then
  token=$(jq -r '.stages[]|.stderr//empty' "$source_body" |
    sed -n 's/^FILELINE:[0-9][0-9]*:MDS_DIAG_TOKEN=\([^[:space:]]*\).*/\1/p' |
    head -n 1)
fi
[[ -n "$token" ]] || {
  printf 'diagnostic token not found\n' >&2
  exit 1
}

body="$odyssey_root/responses/jpquery-$label.body"
headers="$odyssey_root/responses/jpquery-$label.headers"
payload=$(jq -cn --arg expr "$expr" --arg context "$context" '{expr:$expr,context:$context}')

curl --connect-timeout 5 --max-time 20 -sS \
  -H 'Content-Type: application/json' \
  -X POST --data-binary "$payload" \
  -D "$headers" -o "$body" \
  "http://aegis.korvia.htb:3000/api/v1/aegis-mds/_diag/$token/jpquery"

awk 'NR==1{print "status=" $2}' "$headers"
jq '{error,detail,context,profile,matchCount,truncated}' "$body"
