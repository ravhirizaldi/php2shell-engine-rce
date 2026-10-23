#!/bin/bash
# offsets.sh — read the two build-specific symbol offsets from the lab image's
# libphp.so and print the tool flags.
#
# usage: ./offsets.sh [IMAGE]
set -eu
IMAGE=${IMAGE:-php:8.3.35-apache}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB=${LIB:-$HERE/libphp.so}

if [ ! -f "$LIB" ]; then
  cid=$(docker create "${IMAGE}")
  docker cp "$cid:/usr/lib/apache2/modules/libphp.so" "$LIB"
  docker rm -f "$cid" >/dev/null
fi

echo "libphp.so: $LIB"
sha256sum "$LIB"
echo "--- symbols ---"
readelf -Ws "$LIB" | awk '
  $8 == "zif_system"    { printf "zif_system    %s\n", $2 }
  $8 == "zval_ptr_dtor" { printf "zval_ptr_dtor %s\n", $2 }
  $8 == "php_session_reset_id" { printf "php_session_reset_id %s\n", $2 }
'
