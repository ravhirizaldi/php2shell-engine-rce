<?php
session_start();
$_SESSION['blob'] = file_get_contents(__DIR__ . '/payload.bin');
session_write_close();
echo "POISONED pid=" . getmypid() . "\n";
