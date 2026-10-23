<?php
session_start();
if (isset($_POST['p'])) {
    $_SESSION['p'] = $_POST['p'];
    $_SESSION['upload_progress_fk1'] = &$_SESSION['p'];
}
session_write_close();
echo "STORED pid=" . getmypid() . " len=" . (isset($_POST['p']) ? strlen($_POST['p']) : 0) . "\n";
