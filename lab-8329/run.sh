#!/bin/bash
# 8.3.29 calibration lab target: stock php:8.3.29-apache, stock php.ini-production.
#
#   display_errors=Off, memory_limit=128M, post_max_size=8M
#   Apache prefork, one worker, KeepAlive Off
#   target page: <?php echo "OK\n"; ?>
#   /out is mounted from ./out and is writable by www-data
#
# usage:
#   ./run.sh
#   PORT=18129 ./run.sh
#   IMAGE=php:8.3.29-apache ./run.sh
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGE=${IMAGE:-php:8.3.29-apache}
CTR=${CTR:-p2s-8329}
PORT=${PORT:-18129}

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
$DOCKER rm -f "$CTR" >/dev/null 2>&1 || true
mkdir -p "$HERE/out"

$DOCKER run -d --name "$CTR" \
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
$DOCKER exec "$CTR" php -v | head -1
$DOCKER exec "$CTR" php -i 2>/dev/null | \
  grep -E '^display_errors|^display_startup_errors|^memory_limit|^post_max_size|^output_buffering|^session.sid_length|^session.use_strict_mode|^session.save_path|^max_file_uploads|^max_input_vars|^max_multipart_body_parts' | head -20
$DOCKER ps --filter "publish=$PORT" --format 'container: {{.Names}} ({{.ID}})'
