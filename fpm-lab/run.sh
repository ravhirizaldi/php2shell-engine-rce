#!/usr/bin/env bash
# FPM2SHELL lab: nginx + php:8.3-fpm, single php-fpm worker pool, stock-ish ini
# with a low memory_limit so the OOM fatal is cheap to reach.
set -e
cd "$(dirname "$0")"
docker rm -f f2s-php f2s-ngx 2>/dev/null || true
docker network create f2snet 2>/dev/null || true
docker run -d --name f2s-php --network f2snet \
  -v "$PWD/app":/var/www/html -v "$PWD/conf/php.ini":/usr/local/etc/php/conf.d/zz-f2s.ini \
  -e PHP_FPM_PM=static -e PHP_FPM_PM_MAX_CHILDREN=1 \
  php:8.3-fpm
docker exec f2s-php sh -c "sed -i 's/pm = dynamic/pm = static/; s/pm.max_children = 5/pm.max_children = 1/' /usr/local/etc/php-fpm.d/www.conf" || true
docker run -d --name f2s-ngx --network f2snet -p 18120:80 \
  -v "$PWD/app":/var/www/html:ro -v "$PWD/conf/nginx.conf":/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine
sleep 2
curl -s http://127.0.0.1:18120/index.php
