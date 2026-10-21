# blook-kchannel

Stealthy kernel <-> user shared-memory IPC: authenticated, encrypted,
manual-map capable. One peer, one anonymous section, no device object, no
registry, no named object, no notify routine.

`blook-kchannel` is the single IPC transport used by `blook-kdu`,
`blook-drv` and `blook-drv-lite`. The binding contract is
[`../docs/contracts/kchannel-abi-v0.md`](../docs/contracts/kchannel-abi-v0.md);
the authoritative declarations are
[`include/blook/kchannel.h`](include/blook/kchannel.h) (user) and
[`include/blook/kchannel_km.h`](include/blook/kchannel_km.h) (kernel).

> Authorized security research and testing only. This software is not
> intended for production or malicious use.

## Status

- **ABI 1.0** - headers are frozen; breaking changes bump `KC_ABI_MINOR` and
  are announced to every consumer.
- **Host unit suite: 52 tests green** (no VM, no driver): crypto RFC vectors,
  ABI layout, ring/framing corruption and tamper, replay, fuzz, timeout, and an
  in-process mock kernel that drives the same protocol code as the driver.
- **Kernel execution in CI**: `kernel-e2e` runs the full feature matrix on a
  hosted `windows-latest` runner with an SPC SHA-1 signed driver (trust:
  `tsa-root.cer` in Root, VeriSign chain in CA, XINDA leaf in TrustedPublisher),
  asserts `/kp` verification and `STATE 4 RUNNING`, exercises handshake, echo,
  tamper cases, latency/soak/worker CPU, trace scan and unload residue, and
  uploads `ci-e2e-result.json` (cases/failures/skip reasons). The deliberate
  BSOD phase and the manual-map path are reported as documented skips
  (`requires VM reboot/BSOD`, `KVA-shadow platform`).
- **Signing**: SPC SHA-1 with the shipped `signer/` works on a stock 26100 OS
  with `testsigning No` and `nointegritychecks No` (evidence:
  `docs/evidence/20261021-vm-spc/`); SHA-256 and a missing TSA root are the two
  failure modes (0x80096010 / 0x80096005 → 577).
- **VM e2e (lab)**: `tests/e2e/step-run.ps1` / `exec-run.ps1` drive the same
  matrix inside a bvmenv VMware fork; committed VM evidence is still gated on
  the KC-001 fix below.
- **Known issue KC-001 (fix in 1.0.1)**: an intermittent guest hang on the
  loader-exit-without-BYE path in `KC_MODE_MAPPED` (wrong-key bootstrap, or a
  MAPPED loader that is killed without a clean detach). Do not use MAPPED
  sessions with untrusted or killable loaders until 1.0.1; `KC_MODE_COPY` is
  unaffected. Details and diagnosis: `docs/known-issues.md`.
- **CI**: `.github/workflows/ci.yml` builds on `windows-latest` (WDK from the
  NuGet package), runs the unit suite, gates clang-format and host safety,
  packages a source drop, and runs `kernel-e2e`. `release.yml` publishes the
  Windows and source zips with sha256 on every `v*` tag.

## Architecture

```
  loader process (non-admin)                          kernel (mapped or SCM loaded)
  ─────────────────────────                           ─────────────────────────────
  kc_attach()                                         kc_kernel_create(boot)
    CreateFileMapping(INVALID_HANDLE_VALUE)             validate bootstrap
    MapViewOfFile  ──────────────┐                      MDL + ProbeAndLock +
    random key/salt/attach_id    │                      MapLockedPages(MmCached)
  kc_get_bootstrap()             │                      write ctrl (READY,
    └─> manual-map entry param   │                        session_tag, nonce_rs)
                                 v
  +---------------------------------------------------------------+
  | anonymous pagefile-backed region (default 0x10000, no name)   |
  | 0x0000 control page  kc_ctrl (magic KCHN, rings, heartbeats)  |
  | 0x1000 request  ring  R  bytes   user  -> kernel  (SPSC)      |
  | 0x1000+R response ring R bytes   kernel -> user   (SPSC)     |
  +---------------------------------------------------------------+
        │ user: head/seq_next                     kernel: tail/acked │
        v                                                            v
  kc_call(op,in)  ── record = kc_record{len,magic,seq} ──>  single PASSIVE_LEVEL
  wait REPLY      ── kc_msg_header + ChaCha20 ciphertext ──>  worker: HMAC verify,
  kc_detach()     <── HMAC-SHA256 tag over header[0,0x30) ──  replay check, decrypt,
                                                             dispatch handler, reply
```

- **Handshake**: kernel writes `session_tag = HMAC-SHA256(session_key,
  "kchannel/session"||salt||attach_id||pid)`; the loader recomputes it to
  prove the kernel holds the same key, then `HELLO`/`HELLO_ACK` flips the
  session to ACTIVE. Nothing but the handshake is processed before that.
- **Crypto**: self-contained SHA-256, HMAC-SHA256, ChaCha20 (RFC 8439,
  default) and AES-128-CTR (optional). No CNG/BCrypt in kernel mode, so it
  works inside a manually mapped image. Every header field is authenticated as
  AAD; payloads are encrypted; each direction has its own nonce prefix and
  sequence space; replay is rejected by strict sequence monotonicity.
- **Modes**: `KC_MODE_MAPPED` (default, MDL locked user pages mapped to a
  system VA) and `KC_MODE_COPY` (no resident mapping; every access goes
  through `MmCopyVirtualMemory`, crash-safe even if the loader is dying).
- **Stealth**: no `IoCreateDevice`, no symbolic link, no registry, no
  named object, no `Ps*Notify`, no SSDT hook, no image-load notify, no
  exported symbol. The only production bootstrap channel is the
  manual-map entry parameter. A compile-time test-only `KCHANNEL_TESTING`
  build may add an IOCTL that hands the bootstrap to a test-signed driver
  (`tests/guest`); it is never enabled in release.
- **Robustness**: every offset/size/length/seq/state is validated; ring
  offsets must lie inside the region, records must fit, tags are compared
  in constant time, malformed or truncated input returns `KC_ERR_*` and
  never bugchecks.

## Repository layout

```
include/blook/kchannel.h       authoritative user-side ABI + API
include/blook/kchannel_km.h    authoritative kernel-side API
src/common/                    crypto, ring, framing, reactor (shared, CRT-free)
src/user/                      user library (kc_attach / kc_call / ...)
src/kernel/                    kernel library (kc_kernel_*)
tests/unit/                    host tests (41): vectors, rings, fuzz, mock e2e
tests/guest/kchannel_test/     test driver (echo/delay/error/crash/emit handlers)
tests/guest/kcmapload/         minimal manual-map loader driver
tests/guest/ctl/               kchannel-ctl e2e control tool
tests/e2e/                     bvmenv-driven VM e2e (host + guest scripts)
docs/                          integration, abi, e2e, performance, threat model
```

## Build and test

```powershell
xmake f -y -m release
xmake -y                         # user lib + kernel lib + host tests + guest tools
xmake run kchannel-unit-tests    # 41 host tests, no VM, no driver
pwsh scripts/check-format.ps1    # clang-format 20.1.0 gate
```

Kernel targets need WDK 10.0.26100.0; point xmake at it with
`xmake f --wdk="<Windows Kits 10 root>"` when it is not in the default
location (CI installs it from the `Microsoft.Windows.WDK.x64` NuGet package).
Host unit tests never load a driver and do not need a VM.

## Use it

- Consumers: see [docs/integration.md](docs/integration.md) for the exact
  xmake snippets, the manual-map bootstrap, handler registration and the
  CI pinning rules.
- ABI summary and wire layout: [docs/abi.md](docs/abi.md).
- VM end-to-end suite: [docs/e2e.md](docs/e2e.md).
- Measured latency, idle CPU and methodology: [docs/performance.md](docs/performance.md).
- Threat model: [docs/threat-model.md](docs/threat-model.md).

Minimal user-side flow:

```c
kc_client* cli;
kc_attach_opts opts = {0};
opts.region_size = 0x40000;
kc_attach(&opts, &cli);
kc_bootstrap boot;
kc_get_bootstrap(cli, &boot);      /* -> manual-map entry parameter */
/* map image here, then: */
kc_attach_finish(cli, 5000);
uint32_t out_len;
uint8_t out[256];
kc_status st = kc_call(cli, 0x8001, NULL, 0, out, sizeof(out), &out_len, 2000);
kc_detach(cli);
```


## Host safety

Kernel code (test drivers, manual mapping, deliberate faults) is only ever
executed inside a bvmenv VMware guest fork. The repository enforces this:

- `tests/e2e/guest-run.ps1` and `tests/e2e/crash-run.ps1` refuse to run unless
  VMware Tools is present in the guest registry ("REFUSING to run: kernel e2e
  must execute inside a bvmenv VMware guest, not on the host").
- `tests/e2e/run-e2e.ps1` only builds/signs on the host and drives `bvmenv`;
  it never loads a driver and refuses to run inside a guest.
- `kchannel-ctl.exe` refuses driver IOCTLs on a non-VMware host unless
  `KCHANNEL_ALLOW_HOST=1` is set (disposable test machines only).
- `scripts/check-host-safety.ps1` is a CI gate: it fails if any script other
  than the two guarded guest scripts contains `sc create/start`, `New-Service`,
  `NtLoadDriver`, `bcdedit` or `vmrun`, if a CI workflow tries to load a
  driver, if a guest script lost its guard, or if a compiled `.sys/.inf/.cat`
  is committed.

Host unit tests (`xmake run kchannel-unit-tests`), format checks and builds
never load kernel code.
## Security notes

- The session key only ever travels through the bootstrap descriptor, never
  through the shared region.
- The region is the loader's anonymous section: no name, no file, no
  surviving handle on the kernel side, and contents are encrypted.
- Single peer: a second attach while a session is ACTIVE returns
  `KC_ERR_ALREADY`; stale/dead peers are detected by the user heartbeat and
  the `attach_id`.
- The library is deliberately paranoid about user memory: the kernel never
  dereferences user pointers directly and never trusts control-page
  contents owned by the user.
- **Known issue KC-001 (fixed in 1.0.1)**: a corrupted-key bootstrap whose loader exits
  before the handshake hangs the guest; VM e2e evidence and the 1.0.0 tag are
  clean `BYE`, can wedge the guest. `v1.0.0` ships with this documented as a
- See [docs/threat-model.md](docs/threat-model.md) for the full model and
  residual risks.

## License

MIT, see [LICENSE](LICENSE).
