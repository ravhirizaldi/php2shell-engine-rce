<?php
/* Write a raw session record for SID (lab helper: replaces the session file
 * without going through PHP's serializer so the record can carry the forged
 * structures). */
$sid = $_GET['sid'] ?? '';
if (!preg_match('/^[A-Za-z0-9,\-]{22,64}$/', $sid)) {
    http_response_code(400);
    echo "bad sid\n";
    exit;
}
$path = ini_get('session.save_path');
if ($path === '' || $path === false) {
    $path = sys_get_temp_dir();
}
$dst = rtrim($path, '/') . '/sess_' . $sid;
$data = file_get_contents(__DIR__ . '/record.bin');
if ($data === false) {
    http_response_code(500);
    echo "no record\n";
    exit;
}
file_put_contents($dst, $data);
echo "RAW " . strlen($data) . " -> " . $dst . "\n";
