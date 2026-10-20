# Performance

Targets from the ABI contract:

| Metric | Target |
|---|---|
| round-trip median, MAPPED mode | < 20 us |
| idle CPU (worker thread) | < 0.1 % |
| `kc_kernel_stop` latency | <= 100 ms |
| max payload | 64 KiB - 64 (ring permitting) |

## Methodology

`kchannel-ctl latency` measures the full `kc_call()` round-trip with QPC around
the call, after 64 warm-up calls:

- request: `KC_TOp_ECHO` with 64 bytes payload, 64-byte reply;
- `--count 2000` samples; median/p90/p99/min/max reported in nanoseconds;
- after the hot loop the tool sleeps 1 s and issues 20 spaced pings, reporting
  `cold_median_ns` - this is the "kernel after idle backoff" number;
- the same binary runs the SCM-loaded driver and the manually mapped driver, so
  the numbers are directly comparable.

`kchannel-ctl idle-cpu` attaches, samples `GetSystemTimes` over N idle seconds
and reports total system busy time. On an otherwise idle lab VM this is an
upper bound for the worker thread's cost (other system activity is included);
it is measured with an ACTIVE session that is doing nothing.

Stop latency and the backoff schedule are structural: the worker waits on a
`KEVENT` with a relative timeout capped at `poll_idle_max_us` (50 ms), and
`kc_kernel_stop` signals that event, so the join is bounded by the current wait
interval plus scheduling, well inside 100 ms.

## Measured numbers

_To be filled from the VM e2e evidence run (`docs/evidence/<date>-vm-e2e/`)._

| Scenario | median | p99 | cold median | notes |
|---|---|---|---|---|
| MAPPED (signed `sc` load) | pending | pending | pending | 64 B echo |
| MAPPED (manual map) | pending | pending | pending | 64 B echo |
| COPY mode | pending | pending | pending | 64 B echo, no resident mapping |
| 64 KiB-class payload (65470 B) | pending | - | - | single call |
| idle system CPU, MAPPED session | pending | - | - | 10 s sample |
| idle system CPU, COPY session | pending | - | - | 10 s sample |

Raw JSON is stored next to the evidence: `latency-scm.json`,
`latency-mapped.json`, `idle-scm.json`, `idle-mapped.json`,
`latency-copy.json`, `idle-copy.json`.

## Why it is fast

- One page-aligned region, no copies in MAPPED mode: the kernel owns a system
  VA for the locked pages, so ring access is plain memory.
- The worker busy-polls for `poll_spin_us` (50 us) after any activity, so a
  request that arrives while a reply is being produced is picked up in
  microseconds; only an idle session pays the sleep backoff.
- HMAC-SHA256 uses precomputed ipad/opad midstates; a 64-byte frame costs two
  SHA-256 compressions for the tag.
- ChaCha20 keystream work is proportional to payload only.

## Backoff schedule

After `poll_spin_us` of `_mm_pause` polling with no work, the worker waits
`1, 2, 4, 8, 16, 32, 50, 50, ... ms` on the stop event. With the 50 us spin
window that is ~0.1 % of one core at the ceiling, and the first request after
idle pays at most ~50 ms (reported as `cold_median_ns`).
