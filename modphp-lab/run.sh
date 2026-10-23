#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
docker rm -f f2s-apache 2>/dev/null || true
docker build -t f2s-modphp .
docker run -d --name f2s-apache --cap-add=SYS_PTRACE -p 18130:80 f2s-modphp
sleep 2
curl -s http://127.0.0.1:18130/index.php
