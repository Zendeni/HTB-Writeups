#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 2 || $# == 3 )) || {
  printf 'Usage: %s LABEL TEMPLATE_BODY [OVERRIDES_JSON]\n' "$0" >&2
  exit 2
}

label="$1"
template_body="$2"
overrides_json='{}'
if (( $# == 3 )); then
  overrides_json="$3"
fi
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
if [[ "$template_body" == @* ]]; then
  template_file=${template_body#@}
  [[ "$template_file" =~ ^artifacts/[A-Za-z0-9._/-]+$ ]] || exit 2
  template_file="$odyssey_root/$template_file"
  template_body=$(<"$template_file")
fi

cookie_header=${AEGIS_COOKIE:-}
if [[ -z "$cookie_header" && -f "$odyssey_root/responses/webauthn-admin.json" ]]; then
  cookie_header=$(jq -r '.cookie_header // empty' "$odyssey_root/responses/webauthn-admin.json")
fi
[[ -n "$cookie_header" ]] || {
  printf 'set AEGIS_COOKIE or create responses/webauthn-admin.json\n' >&2
  exit 1
}
url='http://aegis.korvia.htb:3000/admin/templates/legacy-codesign-v1/render'
body="$odyssey_root/responses/template-render-$label.body"
headers="$odyssey_root/responses/template-render-$label.headers"
if ! jq -e . >/dev/null 2>&1 <<<"$overrides_json"; then
  printf 'invalid overrides JSON\n' >&2
  exit 2
fi
payload=$(jq -cn --arg body "$template_body" --argjson overrides "$overrides_json" \
  '{body:$body,overrides:$overrides}')

curl --connect-timeout 5 --max-time 30 -sS \
  -H "Cookie: $cookie_header" \
  -H 'Content-Type: application/json' \
  -X POST --data-binary "$payload" \
  -D "$headers" -o "$body" "$url"

awk 'NR==1{print "status=" $2}' "$headers"
jq -r '
  "ok=\(.ok) finalStage=\(.finalStage)",
  (.stages[] | "stage=\(.stage) code=\(.code)"),
  (.stages[] | (.stderr // "") | split("\n")[] | select(test("AEGIS-(LEAK|HIT|MISS|FORCE)")))
' "$body"
