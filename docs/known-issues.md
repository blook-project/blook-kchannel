# Known issues

## KC-001 (critical, open): guest hang when a corrupted bootstrap is attached and the loader exits before the handshake

**Status:** open, blocks the VM e2e evidence and therefore the `v1.0.0`
release. Reproduced on a fresh `vm-kchannel` fork with bvmenv 0.1.12
(`dist\bvmenv-6e83eb6.exe`), test signing enabled.

**Symptom**

1. Signed `kchannel_test.sys` is staged in `System32\drivers` and started via
   `sc create` / `sc start` -> service RUNNING, DriverEntry returned 0.
2. `kchannel-ctl.exe wrong-key --device \\.\kchannel_test` (or the isolation
   variant `iso-c-attach`, which only sends a bootstrap whose `session_key`
   differs from the loader's and then exits without finishing or destroying the
   session) never returns.
3. Every following `bvmenv exec` - including `cmd /c echo` - times out, i.e.
   the guest becomes unresponsive. The VM stays powered on; a host-side
   screenshot is not a Windows bugcheck blue screen (hard hang, no dump taken).
4. Resetting the VM restores it; the hang is reproducible.

**What works on the same VM / same build**

- `kchannel-ctl attach-test`: complete handshake (valid key), ping, echo
  small/empty/64 KiB-class, delay handlers, error/oversized-reply mapping,
  then `kc_detach` -> `BYE`; guest stays alive and responsive afterwards.
- Host tests: the same wrong-key + destroy sequence passes in the in-process
  mock kernel (52/52 host tests green), so the bug is kernel-specific, not in
  the framing/reactor logic that the host tests exercise.

**Isolation matrix (fresh clone per case, driver loaded per case)**

| Case | Bootstrap | Loader action | Result |
|---|---|---|---|
| `attach-test` | valid | handshake + detach (BYE) | pass, guest alive |
| `iso-c-attach` | corrupted key | exit after IOCTL_ATTACH (no finish, no destroy) | **hang** |
| `iso-c-finish` | corrupted key | finish handshake (AUTH) | aborted after the first hang |
| `iso-c-destroy` | corrupted key | IOCTL_DESTROY after attach | aborted after the first hang |

**Narrowed trigger:** the driver creates a session whose `session_key` differs
from the loader's key; the loader process then disappears while the driver
session is still `READY` (before `HELLO`). The normal path (valid key ->
`HELLO` -> `ACTIVE` -> `BYE`) is fine, so the hang is in the
`READY`-with-dead-peer path (handshake timeout / watchdog transition), not in
the handshake itself or in framing.

**Suspected code areas** (to be confirmed with a kernel debugger)

- `kc::Reactor::tick()` / `check_watchdog()` -> `fail_session(TIMEOUT)` while
  the loader process is exiting: the reactor still touches the loader-owned
  pages through the MDL mapping and transitions `READY -> FAILED`.
- `kc_kernel_stop` / `kc_kernel_destroy` when the peer is gone without a
  clean BYE (deferred cleanup from the worker thread).
- Test driver `HandleIoctl` returning while a `READY` session has no peer.

**Next step:** reproduce with kernel debugging enabled
(`bvmenv create <vm> --kd-pipe`, `bvmenv kd <vm>`) and WinDbg attached to the
guest; capture the stack of the hanging worker and any deadlock. Then fix and
re-run `tests/e2e/step-run.ps1`, which already isolates each step.

## KC-002 (workaround in place): stale kernel service leaves a device with a previous SYSTEM logon DACL

An interrupted e2e run can leave `kchannel_test.sys` loaded while the SCM
service is half-deleted. The old device object's default DACL belongs to the
previous SYSTEM logon session, so a later `DeviceIoControl` fails with Win32
1359 (`ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION`). Both guest scripts now stop
and delete stale services in a retry loop and wait for the SCM to forget them
before staging binaries; `step-run.ps1` additionally verifies the service
state after `sc start`.

## KC-003 (lab harness, external): `bvmenv` readiness / agent limitations

`bvmenv e2e` requires an interactive "ready" desktop; clones can sit at the
logon UI while guest operations already work through the SYSTEM fallback. Use
`tests/e2e/exec-run.ps1` or `tests/e2e/step-run.ps1` in that case. Keep to the
team VM budget (max 3-4 guests) and stop forks after each run; the host was
power-cycled twice on 2026-10-21 while many guests were running.
