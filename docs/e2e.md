# End-to-end testing (lab VM)

The VM suite proves the parts host tests cannot: real MDL mapping by a real
driver, test-signed loading, manual mapping, trace absence, unload residue and
the user-mode driver stack.

## 1. Prerequisites

- `bvmenv.exe` from `blook-project/blook-vmware-environment`, with the base
  image built (`bvmenv base build` + `bvmenv base verify`).
- A fork of the base image, e.g. `bvmenv create vm-kchannel`. The base image
  has test signing enabled and UAC disabled, so `sc create/start` works from
  the e2e entry.
- Host: Visual Studio + WDK 10.0.26100.0 (`signtool.exe`), xmake 3.0.8.
- The first run creates a self-signed code-signing certificate
  `CN=blook-kchannel-test` in the **current user** store and exports only the
  public `.cer` into the evidence/bundle. No private key is committed.

## 2. Run it

```powershell
# from the repo root
pwsh tests/e2e/run-e2e.ps1
# or with explicit paths / existing evidence directory
pwsh tests/e2e/run-e2e.ps1 -Vm vm-kchannel -Out docs/evidence/20261021-vm-e2e
```

The script:

1. builds release (`xmake f -y -m release && xmake -y`) and runs the host unit
   tests;
2. signs `kchannel_test.sys` and `kcmapload.sys` with the test certificate;
3. creates/resets the VM;
4. pushes a bundle (`kchannel_test.sys`, `kcmapload.sys`, `kchannel-ctl.exe`,
   `.cer`, `guest-run.ps1`, `run-e2e.cmd`) and runs it through
   `bvmenv e2e ... --out <Out>/main`;
5. pushes a crash bundle and runs `crash-run.ps1` through
   `bvmenv e2e ... --out <Out>/crash`, expecting the host-side classifier to
   report `outcome == "bsod"`;
6. writes `<Out>/result.json` with the summary.

## 3. What the guest matrix does (`guest-run.ps1`)

Phase A - test-signed SCM load of `kchannel_test.sys`:

| Check | Expected |
|---|---|
| `sc start kchannel_test` | RUNNING |
| `kchannel-ctl wrong-key` | kernel rejects the corrupted bootstrap: `KC_ERR_AUTH` |
| `kchannel-ctl attach-test` | handshake, ping, 64 B echo, empty echo, 64 KiB-class echo (65470 B), 20 ms and 200 ms handlers, handler error `KC_ERR_HANDLER`, oversized reply -> `KC_ERR_INTERNAL`, unknown opcode -> `KC_ERR_NOT_FOUND` |
| `kchannel-ctl second-attach` | second bootstrap -> `KC_ERR_ALREADY` |
| `kchannel-ctl event-test` | kernel -> user `EVENT` delivered |
| `kchannel-ctl latency` | median/p99/cold median JSON |
| `kchannel-ctl idle-cpu` | system busy % over 10 s |
| `kchannel-ctl loader-kill` | child attaches and is `TerminateProcess`ed: watchdog fires, driver reports peer gone, tear-down completes, a fresh attach + ping succeeds |
| `kchannel-ctl trace-scan` | SCM-scope report |
| unload (`sc stop` + `sc delete`) | `device_present=false`, `service_key_present=false` |

Phase B - manual map by `kcmapload.sys` (test-signed helper, `sc` loaded):

| Check | Expected |
|---|---|
| `ctl map-test` | image mapped, entry receives the bootstrap, handshake, full functional matrix |
| `ctl event-test` | EVENTS work in mapped mode |
| `ctl latency` / `idle-cpu` | mapped-mode numbers |
| `ctl trace-scan --image` | `device_present=false`, `service_key_present=false`, `named_object_match=false`, `driver_module_present=false` for the *mapped* driver |
| `ctl loader-kill --image` | loader dies; guest driver log shows `peer_gone` + `kc_kernel_destroy`; MDL/pools/thread released |

Phase C - deliberate BSOD (`crash-run.ps1`, separate `bvmenv e2e` run): the
crash handler faults in kernel, bvmenv must classify `outcome == "bsod"` and
capture the host-side screenshot/state. This validates the harness so that a
`pass` in phase A/B is meaningful.

## 4. Evidence layout

```
docs/evidence/<YYYYMMDD>-vm-e2e/
  result.json                 # summary (bvmenv outcomes, commit, timestamp)
  main/<run_id>/
    result.json               # bvmenv.e2e.v1
    stdout.txt                # guest matrix output (JSON lines)
    stderr.txt
    state.json / state-before.json
    screen.png                # host-side frame
  crash/<run_id>/             # same, outcome=bsod, screenshot of the bugcheck
  bundle/                     # scripts + signed binaries used (no private keys)
    results.jsonl             # one JSON line per check, copied back by bvmenv
    latency-scm.json, latency-mapped.json
    idle-scm.json, idle-mapped.json
    trace-mapped.json
    driver-log.txt            # guest driver log for the mapped peer-gone test
  blook-kchannel-test.cer     # public test certificate
```

`bvmenv e2e` copies the whole bundle back into the host artifact directory, so
`results.jsonl` and the driver log are available even when the guest dies.

## 5. Cleanup

The script leaves the VM running with `--reset-on never` for the main matrix so
the artifacts stay inspectable; run `bvmenv reset vm-kchannel` to go back to
the base snapshot. `bvmenv e2e --reset-on always` is used for the crash run.

## 6. Troubleshooting

- `sc start` fails with 577/1275: the test certificate is not trusted in the
  guest (re-run with the `.cer` present) or test signing was turned off in the
  fork.
- `guest_queryable=false` right after `create`: the VM is still booting; wait
  with `bvmenv wait-ready vm-kchannel`.
- Host-side screen classified as `bsod` on an idle VM is a false positive on
  the OOBE/login blue background; the `state.json` of the run is authoritative.
