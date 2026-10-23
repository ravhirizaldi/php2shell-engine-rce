<?php
// Minimal out-of-band capture endpoint for the --oob mode.
// Runs under the stock php:8.4.26-apache image via `php -S`.
// Writes the raw POST body plus source metadata to /capture/oob.txt.
$dir = '/capture';
if (!is_dir($dir)) {
    @mkdir($dir, 0777, true);
}
$body = file_get_contents('php://input');
$meta = sprintf(
    "--- %s %s %s ---\n",
    $_SERVER['REMOTE_ADDR'] ?? '-',
    $_SERVER['REQUEST_METHOD'] ?? '-',
    $_SERVER['REQUEST_URI'] ?? '-'
);
@file_put_contents($dir . '/oob.txt', $meta . $body . "\n", FILE_APPEND | LOCK_EX);
header('Content-Type: text/plain');
echo "OK\n";
