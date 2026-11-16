#!/usr/bin/env bash

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
odyssey_root=$(cd -- "$script_dir/.." && pwd)
mkdir -p "$odyssey_root"/{artifacts,responses,scans,smb-share,tools}
