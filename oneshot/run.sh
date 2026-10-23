#!/bin/bash
# PHP2SHELL one-shot lab target: stock php:8.4.26-apache, stock php.ini-production.
#
#   display_errors=Off, memory_limit=128M, post_max_size=8M
#   Apache prefork, one worker, KeepAlive Off
#   target page: <?php echo "OK\n"; ?>
#   /out is mounted from ./out and is writable by www-data
#
# usage:
#   ./run.sh
#   PORT=18119 ./run.sh
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGE=${IMAGE:-php:8.4.26-apache}
NAME=${NAME:-p2s-oneshot}
PORT=${PORT:-18118}

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
$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p "$HERE/out"

$DOCKER run -d --name "$NAME" \
  -p "127.0.0.1:$PORT:80" \
  -v "$HERE/docker/apache.conf:/etc/apache2/conf-enabled/zz-p2s.conf:ro" \
  -v "$HERE/docker/www:/var/www/html:ro" \
  -v "$HERE/out:/out" \
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
$DOCKER exec "$NAME" php -v | head -1
echo "url:     http://127.0.0.1:$PORT/index.php"
echo "next:    python3 $HERE/exploit.py   (paste the URL above)"
$DOCKER ps --filter "publish=$PORT" --format 'container: {{.Names}} ({{.ID}})'
