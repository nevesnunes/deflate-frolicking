#!/usr/bin/env bash

set -u

test -d "$1"

for i in "$1"/*; do
  if echo "$i" | grep -q ".zip$"; then
    printf '\n%s\n' '# unzip -p -- ...'
    unzip -p -- "$i" 2>&1 | sed 's/^\(.\{128\}\).*/\1 [...]/g'

    printf '\n%s\n' '# jar xf ...'
    jar xf "$i" 2>&1
  else
    printf '\n%s\n' '# zlib.decompress(..., -15) | tail'
    python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' "$i" 2>&1 \
      | sed 's/^\(.\{128\}\).*/\1 [...]/g' \
      | tail

    printf '\n%s\n' '# zlib.decompressobj(-15).decompress(...) | tail'
    python3 -c 'import sys,zlib; o=zlib.decompressobj(-15); data=open(sys.argv[1], "rb").read(); [sys.stdout.buffer.write(o.decompress(bytes([b]))) for b in data]' "$i" 2>&1 \
      | sed 's/^\(.\{128\}\).*/\1 [...]/g' \
      | tail

    printf '\n%s\n' '# infgen -d ... | grep WARN'
    infgen -d "$i" 2>&1 | grep WARN
  fi
done
