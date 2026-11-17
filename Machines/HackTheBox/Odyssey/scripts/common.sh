#!/usr/bin/env bash

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
odyssey_root=$(cd -- "$script_dir/.." && pwd)
mkdir -p "$odyssey_root"/{artifacts,responses,scans,smb-share,tools}

require_socks() {
  ss -ltnH '( sport = :1080 )' | grep -q '127.0.0.1:1080' || {
    printf 'SOCKS listener 127.0.0.1:1080 is not running\n' >&2
    return 1
  }
}
