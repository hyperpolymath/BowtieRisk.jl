#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# TEMPORARY (#61): publish the tail of a failing step's output as check
# annotations, since raw job logs are not retrievable outside the UI.
# Remove together with the `diag` steps in julia-ci.yml.
set -uo pipefail
f="${1:-}"
if [ -z "$f" ] || [ ! -s "$f" ]; then
  echo "::error title=diag::(no log captured: ${f:-unset})"
  exit 0
fi
# Last 40 KB of output, in 3 KB pieces. Escape % and newlines per the
# workflow-command rules so each piece is one annotation.
tail -c 40000 "$f" | split -b 3000 - /tmp/diag-piece.
n=0
for piece in /tmp/diag-piece.*; do
  esc=$(sed -e 's/%/%25/g' -e 's/\r/%0D/g' "$piece" | awk 'BEGIN{ORS=""} NR>1{print "%0A"} {print}')
  echo "::error title=diag ${n}::${esc}"
  n=$((n + 1))
done
rm -f /tmp/diag-piece.*
exit 0
