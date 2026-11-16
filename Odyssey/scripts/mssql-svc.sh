#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

password=${SVC_MSSQL_PASSWORD:-}
if [[ -z "$password" && -f "$odyssey_root/responses/svc-mssql.cracked" ]]; then
  password=$(head -n 1 "$odyssey_root/responses/svc-mssql.cracked")
fi
: "${password:?set SVC_MSSQL_PASSWORD or create responses/svc-mssql.cracked}"
exec proxychains4 -q "$script_dir/impacket-example.sh" mssqlclient \
  -windows-auth -db master "ODYSSEY/svc-mssql:$password@172.16.0.11" "$@"
