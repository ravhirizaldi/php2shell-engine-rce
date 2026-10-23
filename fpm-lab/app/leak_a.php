<?php
/* Lab precondition probe for the post-RINIT cookie-OOM state.
 * The app pre-sets a session id, fills memory, then lowers the limit so the
 * next allocation happens inside session_start().  We want the fatal to land
 * after php_session_start() set PS(send_cookie)=1 but before reset_id clears
 * it, while session_start() has not yet produced output. */
$sid = isset($_POST['sid']) ? $_POST['sid'] : 'f2sleakid000000000000000000001';
if (isset($_POST['nid']) && (int)$_POST['nid'] > 0) {
    $sid = str_repeat('a', (int)$_POST['nid']);
}
session_id($sid);
$n = isset($_POST['n']) ? (int)$_POST['n'] : 13000000;
$pad = str_repeat('A', $n);
$hr = isset($_POST['hr']) ? (int)$_POST['hr'] : 32;
if ($hr > 0) {
    ini_set('memory_limit', (string)(memory_get_usage(true) + $hr));
}
session_start();
echo "SURVIVED\n";
