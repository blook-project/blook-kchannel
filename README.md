# blook-kchannel

Stealthy kernel <-> user shared-memory IPC: authenticated, encrypted,
manual-map capable. One peer, one anonymous section, no device object, no
registry, no named object, no notify routine.

`blook-kchannel` is the single IPC transport used by `blook-kdu`,
`blook-drv` and `blook-drv-lite`. The binding contract is
[`../docs/contracts/kchannel-abi-v0.md`](../docs/contracts/kchannel-abi-v0.md).

> Authorized security research and testing only. This software is not
> intended for production or malicious use.

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
  default) and AES-128-CTR (optional). No CNG/BCrypt in kernel mode, so
  it works inside a manually mapped image. Every header field is
  authenticated as AAD; payloads are encrypted; each direction has its
  own nonce prefix and sequence space; replay is rejected by strict
  sequence monotonicity.
- **Modes**: `KC_MODE_MAPPED` (default, MDL locked user pages mapped to a
  system VA) and `KC_MODE_COPY` (no resident mapping; every touch goes
  through a crash-safe kernel copy primitive).
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
src/user/                      user library (kc_attach/kc_call/...)
src/kernel/                    kernel library (kc_kernel_*)
tests/unit/                    host tests (no VM): vectors, rings, fuzz, mock e2e
tests/guest/kchannel_test/     test driver (echo/64KiB/delay/error/crash handlers)
tests/guest/kcmapload/         minimal manual-map loader driver
tests/guest/ctl/               host-side e2e control tool
tests/e2e/                     bvmenv-driven VM e2e
docs/                          integration, abi, e2e, performance, threat model
```

## Build

```powershell
xmake f -y -m release
xmake -y                 # user lib + kernel lib + host unit tests
xmake run kchannel-unit-tests
```

Kernel targets need WDK 10.0.26100.0; override with
`xmake f --wdk_dir="D:\..."` when it is not in the default location.
Host unit tests never load a driver and do not need a VM.

## Use it

- Consumers: see [docs/integration.md](docs/integration.md) for the exact
  xmake snippets, the manual-map bootstrap and handler registration code.
- ABI summary: [docs/abi.md](docs/abi.md).
- VM end-to-end evidence: [docs/e2e.md](docs/e2e.md).
- Measured latency and methodology: [docs/performance.md](docs/performance.md).
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
- Test signing / `KCHANNEL_TESTING` builds are documented in
  [docs/e2e.md](docs/e2e.md) and are not part of the shipped ABI.

## License

MIT, see [LICENSE](LICENSE).
