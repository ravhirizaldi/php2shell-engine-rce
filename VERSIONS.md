# Version matrix — engine-level PHP2SHELL

All rows use the official `php:<version>-apache` image, stock
`php.ini-production` (`display_errors=Off`, `memory_limit=128M`,
`post_max_size=8M`), a single prefork worker, and the page
`<?php echo "OK\n"; ?>`. No application PHP is involved; the chain runs
from the `session.upload_progress` callback before RINIT.

**Vulnerable** means the engine chain reached `zif_system` and returned
command output.

| Build | Status | Evidence | Driver |
|---|---|---|---|
| 8.2.34 | **VULNERABLE — SOLID** | [`lab-8234/RESULT.md`](lab-8234/RESULT.md) | `PROFILES["8.2"]` |
| 8.3.29 | **VULNERABLE — SOLID** | [`lab-8329/RESULT.md`](lab-8329/RESULT.md) | `PROFILES["8.3"]` |
| 8.3.35 | **VULNERABLE — SOLID** | [`lab-8335/RESULT.md`](lab-8335/RESULT.md) | `PROFILES["8.3.35"]` |
| 8.4.26 | **VULNERABLE — SOLID** | [`REPORT.md`](REPORT.md), [`official-lab/EVIDENCE.md`](official-lab/EVIDENCE.md) | `PROFILES["8.4"]` |
| 8.5.11 | **PARKED — A1 primitive proven, B1 uncalibrated** | local `lab-8511/`, not published | none |

8.2.34 is the last affected 8.2 release; 8.3.35 is the last affected 8.3
release; 8.4.26 is the last affected 8.4 release; 8.5.11 is the last
affected 8.5 release and remains parked. 8.3.29 is a calibrated mid-branch
build; 8.3.30–8.3.34 remain affected but uncalibrated.

## Chain parameters

| Build | A1 progress | B1 spec | `fake_len` | `page_off` | S anchor | `zif_system` | `zval_ptr_dtor` |
|---|---|---|---|---|---|---|---|
| 8.2.34 | `1000` | `G:300:0xE2 ×16 + X:900` | `0xC8000` | `0x968` | `(dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` | `+0x39B8A0` | `+0x487650` |
| 8.3.29 | `1000` | `G:300:0xE2 ×16 + X:900` | `0xC8000` | `0x968` | `(dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` | `+0x3ABDC0` | `+0x49DB50` |
| 8.3.35 | `1000` | `G:300:0xE2 ×16 + X:900` | `0xC8000` | `0x968` | `(dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` | `+0x3AC080` | `+0x49EC50` |
| 8.4.26 | `4000` | `G:511:0x137 ×14 + G:400:0x137 + G:511:0x137 + X:900` | `0xC8000` | `0` | main leak bucket + `0xF8398` | `+0x465370` | `+0x65EB60` |

The 8.2/8.3 geometry is the same; only the engine offsets differ. On
8.3.35 the 8.3.29 geometry transferred unchanged; the offsets moved by
`+0x2C0` (`zif_system`) and `+0x1100` (`zval_ptr_dtor`). The 8.4 geometry
uses the main leak bucket directly and the 8.4 profile's
`FAKE_ARRAY_DELTA`.

## Target identity

| Build | Image digest | `libphp.so` SHA-256 |
|---|---|---|
| 8.2.34 | `sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` | `42ae9f69550e036ff5ad3d25d7ebf6b40bf2dd6531e8f891de53bea0d1663e9b` |
| 8.3.29 | `sha256:59e644d448b18e78c36bcbec33cf473a6ba64d812e994e821715d1b666519627` | `29b728904da3de4bbd9da723c198e4a834c4d59e2e56b0974a65edef9f0f26ae` |
| 8.3.35 | `sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` | `ea069762fa225a2d61ebf613db5686d7c29823acf641424d596f78fcaa1cdccb` |
| 8.4.26 | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |

## Fixed-release gate

PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and 8.5.12**. The driver
reads `X-Powered-By` before sending a chain request and refuses to run
against any banner at or above the fixed release:

- `8.2.35+`, `8.3.36+`, `8.4.27+`, `8.5.12+` → **NOT VULNERABLE**, no chain.
- Calibrated `8.2.34`, `8.3.29`, `8.3.35`, `8.4.26` → full chain.
- Other affected but uncalibrated builds → branch profile best-effort with
  a warning where supported; otherwise no attempt.

No dedicated fixed-build negative-control lab is included in this
repository. The published matrix is vulnerable-build evidence plus the
parked 8.5.11 primitive; the fixed-release check is a driver gate, not a
lab claim.

## 8.5 status

The 8.5.11 A1 primitive is confirmed: the OOM lands in
`php_url_encode`'s `e_id` allocation (121 B → bin 128) with
`send_cookie=1` and a valid stale `PS(id)`. The B1 leak is not calibrated:
the stale `ps_files` at page `0x56` offset `0xa0` is clobbered by the B1
progress field name, and the stale id at pages `0x1FD`/`0x1FE` needs a new
forge length. This branch is parked; none of its results are part of the
8.2/8.3/8.4 claims above.

## Reproduction

```sh
# one build per lab
cd lab-8234   # or lab-8329, lab-8335, official-lab
./run.sh
# in another shell, use the one-shot driver from the repository root
python3 oneshot/exploit.py
# paste the printed URL; subsequent lines are commands

# 8.4 interactive reference
cd official-lab
./run.sh
python3 pure_shell.py --exec 'id'
```

Each `lab-*/RESULT.md` carries the exact raw-chain command, offsets,
proof outputs, and evidence manifest. All runs are local Docker only.
