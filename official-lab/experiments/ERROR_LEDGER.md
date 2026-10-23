# Error ledger — PHP2SHELL multi-worker work

Failure → root cause → fix → evidence. The single-worker official chain is
unaffected unless noted.

## E-01 — Leak parser treated `0x41…` fillers as pointers

- **Symptom:** every candidate failed; no proof; the parse range upper bound
  was `0x7fffffffffffffff`.
- **Root cause:** the leak window contains `0x4141414141414141` filler; the
  full 64-bit range admits it, and it becomes the most common "pointer".
- **Fix:** use the 48-bit user-space bound `0x7fffffffffff`; the observed
  pointer buckets then separate cleanly.
- **Evidence:** `evidence/debug_first_try_parse_range_bug.log`;
  `CALIBRATION.md` §4.

## E-02 — Keep-alive pinning across A1 fails

- **Symptom:** after A1, the socket is closed; a follow-up request on the
  same connection is not served.
- **Root cause:** A1 ends in an END-cleanup `send_cookie` OOM and Apache
  answers `HTTP/1.0 500` with `Connection: close`, regardless of the request's
  keep-alive header. A2 behaves the same.
- **Fix:** do not rely on keep-alive for A1→B1 or A2→B2; use independent
  connections and pool poisoning.
- **Evidence:** `experiments/keepalive_a1.log`, `experiments/solo_a2.log`,
  `evidence/multi/README.md` §2.

## E-03 — HTTP pipelining A2+B2 fails

- **Symptom:** A2 returns 500 with `Connection: close`; the pipelined B2 gets
  `EOF` before headers; no proof.
- **Root cause:** A2 closes the connection and the child discards buffered
  pipelined requests; there is no same-connection handoff.
- **Fix:** same as E-02 — separate connections plus poisoning.
- **Evidence:** `experiments/pipeline_1.log`.

## E-04 — A1/A2 hit the initial workers, B2 hits a fresh child

- **Symptom:** four A1s hit PIDs 19–22; B1 leaked from PID 20; four A2s hit
  19–22; B2 landed on PID 32 and returned the normal 3-byte page; no proof.
- **Root cause:** the A2 OOM churn made prefork spawn a replacement child
  (32) that the four-connection A2 wave never touched.
- **Fix:** spray A2 in two waves of eight (`--a2-waves 2 --a2-workers 8`), so
  the replacement child is poisoned by the second wave.
- **Evidence:** `evidence/multi/experiments/poison_pid_1.log`,
  `evidence/multi/access_pids_full.log`, then the successful
  `evidence/multi/experiments/a2b2_1.log` and
  `evidence/multi/proof_multi_id_uname.txt`.

## E-05 — One 8-connection A1 wave is too much churn

- **Symptom:** eight concurrent A1s hit all five current workers, but B1 then
  closed before headers; the pool had already grown again.
- **Root cause:** more concurrency makes prefork spawn more spares; B1 can
  land on a child that was created after the wave.
- **Fix:** keep the A1 wave at the pool size (four in the fixed lab), retry
  B1, and cap the pool so it cannot grow past the wave.
- **Evidence:** `evidence/multi/experiments/poison_pid_8_1.log`.

## E-06 — Two A1 waves without a pool cap make it worse

- **Symptom:** 2 x 4 A1 waves; B1 alternately closed or returned a normal
  cookie; no leak.
- **Root cause:** each wave creates more churn; the B1 target set keeps
  changing. More A1 traffic is not a substitute for a bounded pool.
- **Fix:** `MaxRequestWorkers 4` / `ServerLimit 4` in
  `docker/apache-multi.conf`, then one A1 wave of four and B1 retries.
- **Evidence:** `evidence/multi/tool_multi_leak_waves.log` (negative),
  `evidence/multi/tool_multi_leak_fixed4.log` (positive).

## E-07 — `--multi` against the single-worker official target

- **Symptom:** four A1s on the single child; B1 got `EOF` or `no heap
  pointers`; no leak.
- **Root cause:** the multi path assumes a pool. On one child the repeated A1
  requests overwrite the same stale state instead of poisoning distinct
  children.
- **Fix:** use the default single-worker chain for `run.sh`/port 18110; use
  `--multi` only on a prefork pool.
- **Evidence:** `evidence/multi/tool_multi_official_single.log`; the default
  regression proof `evidence/proof_single_regression.txt`.

## E-08 — Misreading B1 failure modes

- **Symptom:** `no heap pointers in leak window` and `closed before response
  headers` were treated as separate chain bugs.
- **Root cause:** both are scheduling misses. A normal 50-byte session cookie
  means B1 hit an unpoisoned child; an EOF means the child had no usable
  stale state and closed. Neither proves the chain geometry is wrong.
- **Fix:** classify them as pool misses; retry B1 and/or re-poison. Only a
  decoded leak with the expected 87-count bucket is a chain success.
- **Evidence:** `evidence/multi/experiments/poison_pid_1.log` (B1 leak) vs
  `evidence/multi/tool_multi_leak_waves.log` (misses).

## E-09 — Using the HTTP status as the B2 success signal

- **Symptom:** a successful B2 often returns `EOF` or 500, while an
  unpoisoned B2 returns a clean 200 with 3 bytes.
- **Root cause:** the `zif_system` call runs at request shutdown and the child
  aborts/closes; there is no reliable success response.
- **Fix:** always check the proof file; the tool polls for up to 4 seconds
  after B2. The status is diagnostic only.
- **Evidence:** `evidence/multi/tool_multi_exec_id.log` (`B2 status=EOF`,
  then `[+] output`).

## E-10 — Pool larger than the A1 wave

- **Symptom:** same shape as E-04, but on a target whose pool is larger than
  the configured `--a1-workers`.
- **Root cause:** the first wave cannot poison children it never reaches.
- **Fix:** set `--a1-workers` to the target's `MaxRequestWorkers` (or at
  least the live child count), keep B1 retries, and use at least two A2
  waves. The lab cap is four because that is the validated configuration.
- **Evidence:** `evidence/multi/README.md` §6–7.

## E-11 — Cosmetic: `zif_system candidates` log repeats one address

- **Symptom:** the leak summary prints the same `zif_system` for every main
  candidate.
- **Root cause:** `zif_system` depends only on the `libphp` base, not on the
  main-chunk candidate; the label is misleading.
- **Impact:** none; the candidate loop still varies `S`. Left as-is to avoid
  churn in the validated tool.
- **Evidence:** `evidence/multi/tool_multi_leak_fixed4.log`.

## E-12 — Generic `NAME` env removed the official target twice

- **Symptom:** starting the OOB listener reported
  `listener: DESKTOP-GQ7T0MS (172.17.0.2:18999)` and the official target
  disappeared; later the TLS proxy did the same and nginx exited with
  `host not found in upstream "p2s-target"`.
- **Root cause:** this workspace exports `NAME=DESKTOP-GQ7T0MS`. The new
  helper scripts used `NAME=${NAME:-...}`, inherited that value, ran
  `docker rm -f "$NAME"`, and created the helper under the target's name.
  The helper then replaced the target instead of running beside it.
- **Fix:** every launcher now uses a dedicated variable:
  `OFFICIAL_NAME`, `MULTI_NAME`, `OOB_NAME`, `TLS_NAME`. `run.sh` and
  `run_multi.sh` were changed too, so a stray `NAME` cannot move or remove
  the lab containers.
- **Evidence:** `evidence/tls/nginx_p2s_tls.log` (upstream missing),
  container list in the session, restored target `bcbcbe31657c`.

## E-13 — nginx 502 on the B1 header, then unstable full chain

- **Symptom:** the TLS leak through nginx returned a 309-byte 502:
  `upstream sent too big header while reading response header from upstream`.
  After raising the buffer, the leak succeeded but the full chain often hit
  a respawned child.
- **Root cause:** the B1 `Set-Cookie` header is ~1.68 MB; nginx's default
  `proxy_buffer_size` (4–8 KB) rejects it. `proxy_buffering off` does not
  change response-header buffering. With the header accepted, the HTTP proxy
  still changes the target's child lifecycle enough that the A1/B1 ->
  A2/B2 same-child handoff becomes unreliable in the single-worker lab.
- **Fix:** set `proxy_buffer_size 4m` / `proxy_buffers 8 4m` for the leak;
  use the raw TCP-level TLS terminator (`experiments/tls_tcp_forward.py`) or
  mod_ssl for the full chain. The TCP path completed leak + A2/B2 + OOB.
- **Evidence:** `evidence/tls/nginx_p2s_tls.log`,
  `evidence/tool_tls_leak.log` (nginx leak),
  `evidence/tool_tls_oob_id.log` (TCP terminator full chain).

## E-14 — OOB capture overwritten between runs

- **Symptom:** the single-worker callback capture was lost when the
  multi-worker run reused `oob-out/oob.txt`; only the multi capture remained.
- **Root cause:** the listener appends to one file and both runs shared it;
  the first capture was not copied before the second run.
- **Fix:** copy each capture to a distinct evidence file immediately after
  the run (`evidence/oob_id.txt`, `evidence/multi/oob_multi_id.txt`,
  `evidence/oob_tls_id.txt`), and split by the `--- <source> ---` marker when
  needed. The single-worker OOB was re-run to regenerate its capture.
- **Evidence:** `evidence/oob_id.txt`, `evidence/multi/oob_multi_id.txt`,
  `evidence/oob_tls_id.txt`.

## E-15 — Transient `docker exec` failure after restart

- **Symptom:** `target_tls.txt` records
  `OCI runtime exec failed: ... setns process ...` for `docker exec` while
  the target was serving requests and the TLS chain succeeded.
- **Root cause:** a transient Docker shim/exec failure after
  `docker restart`; the container runtime and the Apache process were
  healthy.
- **Fix:** use the running target's HTTP behavior and the stable image
  digest/ini as identity evidence; retry the exec if a live shell check is
  needed. This is not a chain failure.
- **Evidence:** `evidence/tls/target_tls.txt`, `evidence/tool_tls_oob_id.log`.
