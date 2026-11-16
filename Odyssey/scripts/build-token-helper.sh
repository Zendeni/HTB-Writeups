#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

godpotato_dir=${GODPOTATO_DIR:-$odyssey_root/tools/GodPotato}
godpotato_commit='59f66583474fb0297b7447551460e1072de324c0'
if [[ ! -d "$godpotato_dir/.git" ]]; then
  git clone https://github.com/BeichenDream/GodPotato "$godpotato_dir"
fi
git -C "$godpotato_dir" fetch --quiet origin "$godpotato_commit"
git -C "$godpotato_dir" checkout --quiet "$godpotato_commit"

build_dir=$(mktemp -d -p /tmp odyssey-token-helper.XXXXXX)
cleanup() {
  [[ "$build_dir" == /tmp/odyssey-token-helper.* ]] && rm -rf -- "$build_dir"
}
trap cleanup EXIT

cp -a "$godpotato_dir/." "$build_dir/"
find "$build_dir" -type f -name '*.cs' -print0 |
  xargs -0 sed -i 's/GodPotato/AuditWorker/g'
sed -i \
  -e "s/\.Split(',')/.Split(new char[] { ',' })/g" \
  -e "s/\.Split('-')/.Split(new char[] { '-' })/g" \
  "$build_dir/ArgsParse.cs"

mapfile -d '' sources < <(find "$build_dir" -type f -name '*.cs' -print0)
mcs -platform:anycpu -optimize+ -target:exe \
  -r:System.Data.dll -r:System.Xml.dll \
  -out:"$odyssey_root/artifacts/AuditWorker.exe" "${sources[@]}"

mcs -platform:anycpu -optimize+ -target:library \
  -r:System.Data.dll -r:System.Xml.dll \
  -out:"$odyssey_root/artifacts/AuditWorkerSql.dll" \
  "${sources[@]}" "$odyssey_root/artifacts/SqlEntry.cs"

file "$odyssey_root/artifacts/AuditWorker.exe"
sha256sum "$odyssey_root/artifacts/AuditWorker.exe"
file "$odyssey_root/artifacts/AuditWorkerSql.dll"
sha256sum "$odyssey_root/artifacts/AuditWorkerSql.dll"
sha512sum "$odyssey_root/artifacts/AuditWorkerSql.dll"
