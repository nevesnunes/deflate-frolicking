#!/usr/bin/env bash

set -u

e() {
  # Escape special characters for `sed` replacement string
  printf '%s\n' "$1" | sed -e 's/[\/&]/\\&/g'
}

printf '\n%s\n' 'hexdiff.py -c -l 40 ...'
hexdiff.py -c -l 40 "$1" "$2"

printf '\n%s\n' 'xxd ...'
diff -aU 1 \
  <(xxd "$1") \
  <(xxd "$2") \
  | sed '1s/\/dev\/fd\/.*/'"$(e "$1")"'/; 2s/\/dev\/fd\/.*/'"$(e "$2")"'/;'

printf '\n%s\n' 'infgen -d ...'
diff -au \
  <(infgen -d "$1" 2>&1) \
  <(infgen -d "$2" 2>&1) \
  | sed '1s/\/dev\/fd\/.*/'"$(e "$1")"'/; 2s/\/dev\/fd\/.*/'"$(e "$2")"'/;'
