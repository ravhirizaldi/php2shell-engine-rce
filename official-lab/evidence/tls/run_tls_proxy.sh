#!/bin/bash
# Local HTTPS reverse proxy in front of the official lab target.
#
# Terminates TLS on 127.0.0.1:18443 with a self-signed cert and forwards
# plain HTTP to the target container over a dedicated Docker network alias
# (p2s-target:80). This lets the tool's TLS bridge be exercised end-to-end
# without touching the target's Apache config.
#
# usage:
#   ./experiments/run_tls_proxy.sh
#   TARGET=DESKTOP-GQ7T0MS PORT=18443 ./experiments/run_tls_proxy.sh
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET=${TARGET:-DESKTOP-GQ7T0MS}
NET=${NET:-p2s-tls-net}
TLS_NAME=${TLS_NAME:-p2s-tls}
PORT=${PORT:-18443}
IMAGE=${IMAGE:-nginx:alpine}

if [ -n "${DOCKER:-}" ]; then
  :
elif docker info >/dev/null 2>&1; then
  DOCKER=docker
else
  DOCKER="sudo docker"
fi

mkdir -p "$HERE/docker/tls"
if [ ! -f "$HERE/docker/tls/cert.pem" ] || [ ! -f "$HERE/docker/tls/key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=localhost" \
    -keyout "$HERE/docker/tls/key.pem" \
    -out "$HERE/docker/tls/cert.pem" >/dev/null 2>&1
fi

$DOCKER network create "$NET" >/dev/null 2>&1 || true
$DOCKER network connect --alias p2s-target "$NET" "$TARGET" >/dev/null 2>&1 || true

$DOCKER rm -f "$TLS_NAME" >/dev/null 2>&1 || true
$DOCKER run -d --name "$TLS_NAME" --network "$NET" \
  -p "127.0.0.1:$PORT:$PORT" \
  -v "$HERE/docker/nginx-tls.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$HERE/docker/tls:/etc/nginx/tls:ro" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 40); do
  if curl -sSk -m 2 "https://127.0.0.1:$PORT/index.php" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "tls proxy: $TLS_NAME (https://127.0.0.1:$PORT -> $TARGET:80)"
echo "health:    $(curl -sSk -m 3 "https://127.0.0.1:$PORT/index.php" || true)"
echo
echo "tool: python3 pure_shell.py --port $PORT --https --insecure --exec 'id'"
