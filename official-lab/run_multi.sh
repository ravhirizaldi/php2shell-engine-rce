#!/bin/bash
# Multi-worker PHP2SHELL lab: same stock image and ini as run.sh, but a
# bounded prefork pool and KeepAlive On.
#
#   image:      php:8.4.26-apache (same digest as the official target)
#   ini:        stock php.ini-production (display_errors=Off, 128M, 8M)
#   apache:     prefork, StartServers 4, MaxRequestWorkers 4, ServerLimit 4
#   keepalive:  On
#   page:       <?php echo "OK\n"; ?> plus pid.php for diagnostics
#   /out:       mounted from ./multi-out, writable by www-data
#
# The pool is deliberately capped at four. A cap larger than the A1 wave lets
# prefork spawn a fifth spare during the OOM churn; B1 then lands on that
# unpoisoned child. See experiments/ERROR_LEDGER.md.
#
# usage:
#   ./run_multi.sh
#   PORT=18112 ./run_multi.sh
#   IMAGE=php:8.4.26-apache ./run_multi.sh
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGE=${IMAGE:-php:8.4.26-apache}
MULTI_NAME=${MULTI_NAME:-p2s-multi-18112}
PORT=${PORT:-18112}

if [ -n "${DOCKER:-}" ]; then
  :
elif docker info >/dev/null 2>&1; then
  DOCKER=docker
else
  DOCKER="sudo docker"
fi

OLD=$($DOCKER ps -q --filter "publish=$PORT" 2>/dev/null || true)
if [ -n "$OLD" ]; then
  # shellcheck disable=SC2086
  $DOCKER rm -f $OLD >/dev/null 2>&1 || true
fi
$DOCKER rm -f "$MULTI_NAME" >/dev/null 2>&1 || true
mkdir -p "$HERE/multi-out"

$DOCKER run -d --name "$MULTI_NAME" \
  -p "127.0.0.1:$PORT:80" \
  -v "$HERE/docker/apache-multi.conf:/etc/apache2/conf-enabled/zz-p2s.conf:ro" \
  -v "$HERE/docker/www:/var/www/html:ro" \
  -v "$HERE/multi-out:/out" \
  "$IMAGE" /bin/sh -c \
  'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini;
   chown -R www-data:www-data /out 2>/dev/null || true;
   exec apache2-foreground' >/dev/null

for _ in $(seq 1 40); do
  if curl -s -m 2 "http://127.0.0.1:$PORT/index.php" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "target: $(curl -s -m 3 "http://127.0.0.1:$PORT/index.php")"
$DOCKER exec "$MULTI_NAME" php -v | head -1
$DOCKER exec "$MULTI_NAME" apache2 -v | head -1
$DOCKER exec "$MULTI_NAME" php -i 2>/dev/null | \
  grep -E '^display_errors|^memory_limit|^post_max_size' | head -5
echo 'workers:'
$DOCKER exec "$MULTI_NAME" sh -c \
  'ps -eo pid,ppid,stat,comm,args | grep -E "apache2|httpd" | grep -v grep'
echo 'prefork:'
$DOCKER exec "$MULTI_NAME" sh -c \
  'grep -E "StartServers|MinSpare|MaxSpare|MaxRequestWorkers|ServerLimit|KeepAlive" \
   /etc/apache2/conf-enabled/zz-p2s.conf'
$DOCKER ps --filter "publish=$PORT" --format 'container: {{.Names}} ({{.ID}})'
echo
echo "tool: python3 pure_shell.py --port $PORT --multi --outdir multi-out --exec 'id'"
