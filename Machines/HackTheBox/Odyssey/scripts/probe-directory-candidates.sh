#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

paths_list='/opt/korvia /opt/d9 /opt/mds /opt/aegis-mds /opt/service /opt/backend /opt/config /opt/secrets /opt/keys /opt/mongo /opt/mongodb /srv/korvia /srv/d9 /srv/mds /srv/aegis-mds /srv/service /srv/backend /srv/config /srv/secrets /srv/keys /usr/src/aegis /usr/src/odyssey /usr/src/mds /usr/src/service /usr/src/backend /usr/src/node /home/i.demko /home/idemko /home/demko /home/aegis /home/node /home/app /home/ubuntu /home/webadmin /home/webadmin/aegis'
index=0

for read_path in $paths_list; do
  index=$((index + 1))
  label=$(printf 'child%02d' "$index")
  "$script_dir/mongodb-module-read.sh" "$label" "$read_path" >/dev/null
  body="$odyssey_root/responses/module-read-$label.body"
  state=$(jq -r '.[0].probe.state // .error // "unknown"' "$body")
  message=$(jq -r '.[0].probe.error // .detail // ""' "$body")
  printf '%-32s %-8s %s\n' "$read_path" "$state" "$message"
done
