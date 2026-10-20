# Integrating blook-kchannel

This page is the copy-paste guide for every consumer of
`blook-kchannel` (`blook-kdu`, `blook-drv`, `blook-drv-lite`).
The binding wire/API contract is
[`docs/contracts/kchannel-abi-v0.md`](../docs/contracts/kchannel-abi-v0.md)
and the authoritative declarations are
[`include/blook/kchannel.h`](../include/blook/kchannel.h) (user) and
[`include/blook/kchannel_km.h`](../include/blook/kchannel_km.h) (kernel).

ABI version: **1.0** (`KC_ABI_MAJOR=1`, `KC_ABI_MINOR=0`).
Any breaking header change bumps `abi_minor` and is announced to every
consumer; pin the commit hash when vendoring.

---

## 1. xmake consumption

### 1a. Source drop (recommended while the registry package is young)

Point the build at this repository and compile the library straight into
your target. This has no toolchain/flag mismatch risk and works for both
the user library and the kernel library.

```lua
--- user-mode tools / SDK -------------------------------------------------
local kchannel_dir = get_config("kchannel_dir") or os.getenv("KCHANNEL_DIR")
assert(kchannel_dir, "pass --kchannel_dir=<path to blook-kchannel>")

target("kdu")
    set_kind("binary")
    set_languages("cxx20")
    add_includedirs(path.join(kchannel_dir, "include"))
    add_files(path.join(kchannel_dir, "src/user/*.cpp"))
    add_files(path.join(kchannel_dir, "src/common/*.cpp"))
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    add_syslinks("advapi32", "bcrypt")
```

```lua
--- kernel driver ---------------------------------------------------------
target("drv")
    add_rules("wdk.driver", "wdk.env.wdm")
    set_languages("cxx17")
    set_values("wdk.env.winver", "win10_vb")
    add_includedirs(path.join(kchannel_dir, "include"))
    add_files(path.join(kchannel_dir, "src/kernel/*.cpp"))
    add_files(path.join(kchannel_dir, "src/common/*.cpp"))
    add_defines("NOMINMAX", "POOL_NX_OPTIN=1")
    add_syslinks("ntoskrnl", "wdmsec")
```

`xmake f -y --kchannel_dir=D:\blook-kernel-project\blook-kchannel`
is the local-dev switch the repo conventions already reserve.

### 1b. Prebuilt library from the release package

```lua
add_repositories("blook https://github.com/blook-project/blook-xmake-repo.git")
add_requires("blook-kchannel 1.0.0")

target("kdu")
    add_packages("blook-kchannel")   -- headers + link dirs
    add_links("kchannel")            -- user library

target("drv")                        -- kernel driver
    add_packages("blook-kchannel")
    add_links("kchannel_km")         -- kernel library
```

The package installs `include/blook/*.h`, `lib/kchannel.lib` (user,
C++20) and `lib/kchannel_km.lib` (kernel, C++17 `/kernel`). Release
artifacts are built with WDK 10.0.26100.0 and MSVC 19.4x.

### 1c. Kernel include order

```cpp
#include <ntddk.h>
#include <blook/kchannel_km.h>   // pulls in kchannel.h in ABI-only mode
```

The kernel header supplies the few fixed-width typedefs it needs because
the WDK kernel include path has no `<stdint.h>`.

---

## 2. Manual-map bootstrap (loader side)

The bootstrap descriptor is the *only* driver load parameter. Never put
it into a device IOCTL, registry value, file or named object in the
production path.

```c
#include <blook/kchannel.h>

kc_client* cli = NULL;
kc_attach_opts opts;
memset(&opts, 0, sizeof(opts));
opts.region_size = 0x40000;          /* 256 KiB: 64 KiB payloads fit */
opts.mode        = KC_MODE_MAPPED;   /* default */
opts.cipher      = KC_CIPHER_CHACHA20;
opts.peer_pid    = 0;                /* current process */
if (kc_attach(&opts, &cli) != KC_OK) { /* error path */ }

kc_bootstrap boot;
kc_get_bootstrap(cli, &boot);        /* session_key/salt/attach_id/shared_va */

/* Map the driver image; pass a KERNEL copy of `boot` as the entry point
 * parameter (DriverObject slot), exactly like a normal manual map.
 * kcmapload.sys in this repo is a minimal reference implementation. */
load_driver_image(img, img_size, &boot);

/* The driver's kc_kernel_create() wrote ctrl, state=READY and session_tag. */
if (kc_attach_finish(cli, 5000) != KC_OK) { /* KC_ERR_AUTH / KC_ERR_TIMEOUT */ }

/* normal operation */
uint32_t out_len = 0;
uint8_t  reply[256];
kc_status st = kc_call(cli, MY_OP_QUERY, NULL, 0, reply, sizeof(reply),
                       &out_len, 2000);

kc_detach(cli);                      /* BYE + unmap + close section */
```

Loader requirements:

- the region is an **anonymous pagefile-backed section**
  (`CreateFileMapping(INVALID_HANDLE_VALUE, ..., SEC_COMMIT, ...)`,
  no name) mapped with `MapViewOfFile` and page aligned;
- the bootstrap struct travels in **kernel memory** (mapper copies it);
  `boot.shared_va` is a user VA in `boot.peer_pid`'s address space;
- the driver entry runs at `PASSIVE_LEVEL` in the loader thread (manual
  map) or in the system process (service load, dev only).

## 3. Kernel handler registration

```cpp
#include <ntddk.h>
#include <blook/kchannel_km.h>

static kc_status Echo(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                      void* out, uint32_t* out_cap, uint32_t* out_len) {
    if (in_len > *out_cap) return KC_ERR_PARAM;
    if (in_len) RtlCopyMemory(out, in, in_len);
    *out_len = in_len;
    return KC_OK;
}

extern "C" NTSTATUS DriverEntry(PVOID param, PVOID registry_path) {
    (void)registry_path;
    kc_kernel_config cfg;
    RtlZeroMemory(&cfg, sizeof(cfg));
    cfg.max_payload = KC_MAX_PAYLOAD;
    cfg.watchdog_ms = KC_DEFAULT_WATCHDOG_MS;
    cfg.flags       = KC_KFLAG_EVENTS;

    kc_kernel* k = nullptr;
    kc_status st = kc_kernel_create((const kc_bootstrap*)param, &cfg, &k);
    if (st != KC_OK) return STATUS_UNSUCCESSFUL;

    kc_kernel_register(k, KC_OP_APP_MIN + 1, Echo, nullptr);
    kc_kernel_start(k);
    return STATUS_SUCCESS;
}
```

Semantics that matter to consumers:

- **opcodes >= 0x8000** (`KC_OP_APP_MIN`) are delivered verbatim to the
  handler. `1..8` are reserved for the transport and never reach a
  handler.
- `in_len == 0` with `in == NULL` is legal (empty request).
- Handlers run on the single `PASSIVE_LEVEL` worker thread with no lock
  held. They may block for a few milliseconds (EPT broadcast etc.); the
  `kc_call()` timeout is the real bound, and the user heartbeat keeps
  running on its own thread, so a slow handler does not trip the
  peer-gone watchdog. Keep handlers under ~50 ms when latency matters,
  and never exceed the caller's timeout.
- Handler output: set `*out_len <= *out_cap`; the worker copies it into
  the response ring.
- Error mapping used by the transport:
  - unknown/unregistered opcode -> `KC_ERR_NOT_FOUND`;
  - request payload > `cfg.max_payload` (or ring limit) ->
    `KC_ERR_PARAM` **before** the handler runs;
  - handler claims `*out_len > *out_cap` -> `KC_ERR_INTERNAL`;
  - malformed frame / bad tag / replay / bad state -> `KC_ERR_AUTH`,
    `KC_ERR_MAGIC`, `KC_ERR_VERSION`, `KC_ERR_STATE`, `KC_ERR_IO`;
  - a handler's own `kc_status` is returned verbatim by `kc_call()`.
  Handlers should stay inside the `KC_OK..KC_ERR_UNSUPPORTED` range.

## 4. Service-load bootstrap (dev/debug only)

Contract section 2 covers manual-map only. For `sc create/start` local
debugging the driver may read a bootstrap blob itself (for example a
`REG_BINARY` value written by its loader before `sc start`) and call the
*same* entry point:

```cpp
kc_status st = kc_kernel_create(kernel_copy_of_boot, &cfg, &k);
```

Set `boot.peer_pid` to the loader process. `kc_kernel_create()` detects
that the current process (System) is not the peer and attaches to
`peer_pid` while it probes/locks/maps the shared pages. No extra API is
needed and no second IPC path is allowed: `kc_bootstrap` in, nothing
else. This path is for development images only; it is never part of the
manual-map production flow.

## 5. Rules

- Do not define a custom IPC path in any downstream repo. All kernel <->
  user traffic goes through this library.
- Do not read/write the control page yourself; use the API.
- The region must be zeroed before `kc_get_bootstrap()` is handed to the
  loader (the library zeroes it for you; do not reuse a dirty view).
- `kc_call()` is thread-safe (internally serialized) but synchronous;
  one call at a time per client.
- `kc_detach()` must run before the loader process exits. If the process
  dies anyway, the kernel watchdog notices within `watchdog_ms` and calls
  `on_peer_gone`.
- A second attach against an ACTIVE session returns `KC_ERR_ALREADY`.
