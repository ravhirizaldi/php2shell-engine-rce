<?php
/* Lab victim pattern: the application stores an attacker-controlled binary
 * value in the session and keeps a reference to it (token/session alias
 * shape).  This is the only application precondition for the FPM chain:
 *   - a session value whose bytes survive the php session serializer
 *     (length-prefixed string, NUL/binary safe);
 *   - any reference to a session value, so the encoder emits an R: token.
 * Everything else (forged decoder, fake reference/array) lives in the value
 * bytes at a fixed file offset. */
session_start();
if (isset($_POST['p'])) {
    $_SESSION['p'] = $_POST['p'];
    $_SESSION['upload_progress_fk1'] = &$_SESSION['p'];
}
session_write_close();
echo "STORED pid=" . getmypid() . " len=" . (isset($_POST['p']) ? strlen($_POST['p']) : 0) . "\n";
