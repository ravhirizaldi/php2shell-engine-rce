<?php
$sid = isset($_POST['sid']) ? $_POST['sid'] : 'f2sleakp0000000000000000000001';
session_id($sid);
$n = isset($_POST['n']) ? (int)$_POST['n'] : 12000000;
$pad = str_repeat('A', $n);
$hr = isset($_POST['hr']) ? (int)$_POST['hr'] : 1024;
$b = [memory_get_usage(), memory_get_usage(true), ini_get('memory_limit')];
$ok = ini_set('memory_limit', (string)(memory_get_usage(true) + $hr));
$a = [memory_get_usage(), memory_get_usage(true), ini_get('memory_limit'), $ok];
session_start();
echo json_encode(['b' => $b, 'a' => $a, 'after' => [memory_get_usage(), memory_get_usage(true), ini_get('memory_limit')], 'ok' => $ok]), "\n";
