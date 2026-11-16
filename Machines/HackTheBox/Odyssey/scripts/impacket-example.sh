#!/usr/bin/env bash
set -euo pipefail

(( $# >= 1 )) || {
  printf 'Usage: %s EXAMPLE [ARG ...]\n' "$0" >&2
  exit 2
}

example="$1"
shift
[[ "$example" =~ ^[A-Za-z0-9_-]+$ ]] || exit 2

kali_example="/usr/share/doc/python3-impacket/examples/$example.py"
if [[ -x /usr/bin/python3 && -r "$kali_example" ]] &&
   /usr/bin/python3 -c 'import impacket' >/dev/null 2>&1; then
  exec /usr/bin/python3 "$kali_example" "$@"
fi

for candidate in "impacket-$example" "$example.py"; do
  if executable=$(command -v "$candidate" 2>/dev/null); then
    exec "$executable" "$@"
  fi
done

printf 'Impacket example not found: %s\n' "$example" >&2
exit 1
