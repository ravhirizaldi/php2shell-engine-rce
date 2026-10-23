<?php
$d = $_POST['data'] ?? '';
if ($d !== '') {
    set_error_handler(function(){});
    $obj = @unserialize($d);
    restore_error_handler();
}
echo "OK pid=" . getmypid() . " mem=" . memory_get_usage(true) . "\n";
