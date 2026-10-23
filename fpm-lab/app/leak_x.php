<?php
/* Probe: post-RINIT fatal inside session_start() after PS(send_cookie)=1.
 * A user save handler that throws in open() gives a deterministic fatal at
 * exactly the point we need: php_session_start() has set send_cookie=1 and
 * PS(id) is our pre-set id, but php_session_reset_id() never ran. */
class F2SThrowHandler implements SessionHandlerInterface
{
    public function open(string $path, string $name): bool
    {
        throw new Exception("f2s-open");
    }
    public function close(): bool { return true; }
    public function read(string $id): string|false { return ""; }
    public function write(string $id, string $data): bool { return true; }
    public function destroy(string $id): bool { return true; }
    public function gc(int $max_lifetime): int|false { return 0; }
}
session_set_save_handler(new F2SThrowHandler(), true);
session_id(isset($_POST['sid']) ? $_POST['sid'] : 'f2sx00000000000000000000000001');
session_start();
echo "SURVIVED\n";
