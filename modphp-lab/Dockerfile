FROM php:8.3.33-apache

# gdb is for lab calibration only; the exploit itself is pure HTTP.
RUN apt-get update && apt-get install -y --no-install-recommends gdb procps \
    && rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/zz-f2s.ini
COPY apache-single.conf /etc/apache2/conf-enabled/zz-f2s.conf
COPY app/ /var/www/html/
RUN mkdir -p /var/www/html/out && chown -R www-data:www-data /var/www/html/out

EXPOSE 80
