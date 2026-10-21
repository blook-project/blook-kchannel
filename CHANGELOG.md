# Changelog

All notable changes to `blook-kchannel` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to the ABI version in `include/blook/kchannel.h`
(`KC_ABI_MAJOR` / `KC_ABI_MINOR`).

## [1.0.0] - 2026-10-21

### Signing and CI kernel execution

- Drivers are signed with the prebuilt SPC signer (signer/, same assets
  blook-drv ships): legacy Authenticode that loads on stock Windows, so the
  lab image runs with test signing disabled.
- New CI job kernel-smoke: SPC-signs kchannel_test.sys/kcmapload.sys from
  repo secrets, loads the driver on a hosted windows-latest runner, asserts
  STATE: 4 RUNNING, runs the client handshake/echo and manual-map paths, then
  stops/deletes both services. Real kernel execution in CI, no VT-x needed.


### Known issues

- **KC-001 (shipped as known issue, fix in 1.0.1)**: an intermittent guest
  hang on the loader-exit-without-BYE path in `KC_MODE_MAPPED` (corrupted-key
  bootstrap, or a MAPPED loader killed without a clean detach). `KC_MODE_COPY`
  is unaffected. Do not use MAPPED sessions with untrusted/killable loaders
  until 1.0.1; diagnosis and evidence in `docs/known-issues.md`. The CI
  matrix reports `wrong_key_rejected` and `scm_loader_kill_recovery` as
  `known-issue: KC-001` skips; all other cases run for real.

- **KC-001 (open, critical)**: attaching a corrupted-key bootstrap and exiting
  before the handshake hangs a lab guest; VM e2e evidence and the release tag
  are blocked on it. See docs/known-issues.md.


### Hardening, tests and tooling (pre-1.0.0 work)

- Host-safety guards: guest e2e scripts refuse to run outside a bvmenv VMware
  guest (VMware Tools + provision marker or explicit guest env marker);
  `kchannel-ctl` refuses driver IOCTLs outside a VMware guest; the host
  orchestrator never loads drivers; `scripts/check-host-safety.ps1` + CI
  `host-safety` job fail on any host-side driver-load pattern, CI workflow
  driver load, or committed `.sys/.inf/.cat`.
- Reactor concurrency fix: sequence reservation, sealing and ring publication
  now happen in one critical section, so worker replies and `kc_kernel_emit`
  events can never be observed out of sequence order (would have dropped a
  valid reply under concurrent call+event traffic).
- Watchdog clamp (`watchdog_ms >= 2 * heartbeat interval`) prevents false
  peer-gone on a healthy idle session.
- Extra host tests (52 total): 12k-iteration random-mutation fuzz for
  framing/ring/reactor, concurrent call+event, heartbeat/watchdog edges,
  64 KiB-class payload on a 0x100000 region, header-only C++ wrapper tests,
  C11 / C++17 / C++20 compile-only ABI consumers.
- Copy-mode e2e coverage, transport-tagged perf JSON, worker busy-cycle
  diagnostics (`kc_kernel_worker_busy_cycles`, `kc_kernel_tsc_hz`) and
  automatic performance-table rendering from evidence metrics.
- Docs: ABI change policy, host-safety sections, examples README.

### Added

- Implementation: src/common (SHA-256, HMAC-SHA256, ChaCha20, AES-128-CTR,
  SPSC byte rings, record framing, protocol reactor), src/user (attach /
  bootstrap / handshake / call / ping / detach / events / stats) and
  src/kernel (single PASSIVE_LEVEL worker with adaptive backoff, MAPPED and
  COPY modes, watchdog, peer-gone reporting, no CNG dependency).
- Host unit suite (41 tests): crypto RFC vectors, ABI layout, ring corruption,
  framing tamper/truncation, in-process mock kernel end-to-end, replay and
  malformed-input fuzz.
- Guest e2e assets: kchannel_test.sys (echo/delay/error/crash/emit handlers,
  mapped + SCM load paths), kcmapload.sys (minimal manual-map loader) and
  kchannel-ctl.exe (functional matrix, latency, idle CPU, wrong-key,
  second-attach, loader-kill, trace scan).
- CI (ci.yml: build + unit tests + format + source package) and release
  workflow on *; package manifest and scripts/publish-registry.ps1.

- Authoritative ABI headers `include/blook/kchannel.h` and
  `include/blook/kchannel_km.h` (ABI 1.0):
  - `kc_bootstrap` (0x80 bytes) delivered through the manual-map entry
    parameter, with `kc_attach()` / `kc_get_bootstrap()` /
    `kc_attach_finish()` split for manual-map timing;
  - control page `kc_ctrl` (0x1000 bytes, fixed field offsets) with dual
    SPSC byte rings, per-direction nonce prefixes, heartbeats and
    `session_tag`;
  - wire frames `kc_record` (16 B header) and `kc_msg_header` (0x40 B,
    AAD = `header[0, 0x30)`), HMAC-SHA256 truncated tag, ChaCha20 payload
    encryption (AES-128-CTR optional);
  - `kc_mode` / `kc_cipher` / `kc_state` / `kc_status` enums, opcode map
    (`HELLO`, `HELLO_ACK`, `CALL`, `REPLY`, `EVENT`, `BYE`, `PING`, `PONG`,
    application opcodes >= 0x8000);
  - user API: `kc_attach`, `kc_get_bootstrap`, `kc_attach_finish`,
    `kc_call`, `kc_ping`, `kc_detach`, `kc_state`, `kc_status_str`, plus
    `kc_tick`, `kc_set_event_handler`, `kc_get_stats`, `kc_attach_id`;
  - kernel API: `kc_kernel_create`, `kc_kernel_register`,
    `kc_kernel_start`, `kc_kernel_stop`, `kc_kernel_destroy`,
    `kc_kernel_emit`, `kc_kernel_state`.
- `docs/integration.md`: xmake consumption (source drop and release
  package), manual-map bootstrap recipe and kernel handler registration.
