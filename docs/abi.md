# blook-kchannel ABI 1.0 - implementation summary

This page summarises the authoritative declarations in
[`include/blook/kchannel.h`](../include/blook/kchannel.h) and
[`include/blook/kchannel_km.h`](../include/blook/kchannel_km.h). The binding
contract is
[`../../docs/contracts/kchannel-abi-v0.md`](../../docs/contracts/kchannel-abi-v0.md);
the header wins on any conflict, and this page records the decisions the header
makes where the contract leaves room.

ABI version: **1.0** (`KC_ABI_MAJOR = 1`, `KC_ABI_MINOR = 0`).
Any breaking change bumps `KC_ABI_MINOR` and is announced to every consumer.

## 1. Load model

- The loader creates an anonymous (unnamed) pagefile-backed section with
  `CreateFileMappingW(INVALID_HANDLE_VALUE, ..., PAGE_READWRITE, ...)` and maps
  it read/write. The section is the *only* shared transport.
- `kc_attach()` creates/maps that region, generates the per-attach
  `session_key[32]`, `salt[32]`, `attach_id`, and the user-direction nonce
  prefix. It does not write the control page.
- `kc_get_bootstrap()` returns a `kc_bootstrap` (0x90 bytes) whose bytes are
  the only out-of-band data channel. The loader passes **a kernel copy** of it
  as the manual-map entry parameter (`DriverObject` slot).
- `kc_kernel_create()` validates the bootstrap, obtains access to the pages,
  publishes the driver half of the control page, and sets `state = READY`.
  It is called at `PASSIVE_LEVEL`; when `boot.peer_pid` is not the current
  process (service-load path) it attaches to the peer while probing/locking.
- `kc_attach_finish()` verifies the driver half (including `session_tag`),
  publishes the user nonce prefix, performs `HELLO`/`HELLO_ACK` and leaves the
  session `ACTIVE`.

## 2. Bootstrap (`kc_bootstrap`, 0x90 bytes)

| off | field | type | notes |
|---|---|---|---|
| 0x00 | magic | u32 | `'KCB1'` = 0x3142434B |
| 0x04 | abi_major | u16 | 1 |
| 0x06 | abi_minor | u16 | 0 |
| 0x08 | struct_size | u32 | 0x90 |
| 0x0C | mode | u32 | 0 = MAPPED, 1 = COPY |
| 0x10 | cipher | u32 | 0 = ChaCha20, 1 = AES-128-CTR |
| 0x14 | peer_pid | u32 | 0 = current process |
| 0x18 | attach_id | u64 | random, never 0 |
| 0x20 | shared_va | u64 | user VA, page aligned |
| 0x28 | shared_size | u64 | page aligned, [0x4000, 0x100000] |
| 0x30 | session_key | u8[32] | never written to the region |
| 0x50 | salt | u8[32] | copied to `ctrl.salt` |
| 0x70 | reserved | u8[32] | zero |

> Contract erratum: `kchannel-abi-v0.md` annotates the struct as "0x80
> bytes" but its own field list sums to 0x90. Every offset matches the
> contract; only that annotation was wrong. The Lead approved using 0x90
> (`KC_BOOTSTRAP_SIZE`), which is what `struct_size` carries.

## 3. Control page (`kc_ctrl`, one 4 KiB page)

| off | field | writer | notes |
|---|---|---|---|
| 0x000 | magic | kernel | `'KCHN'` |
| 0x004/0x006 | abi_major/minor | kernel | 1 / 0 |
| 0x008 | header_size | kernel | 0x1000 |
| 0x00C | state | kernel | `KC_STATE_*` |
| 0x010 | flags | kernel | `KC_CTRL_FLAG_*` |
| 0x014 | error | kernel | `kc_status` when FAILED |
| 0x018 | peer_pid | kernel | |
| 0x01C | cipher | kernel | |
| 0x020 | req_off | kernel | 0x1000 |
| 0x028 | req_size | kernel | R |
| 0x030 | rsp_off | kernel | 0x1000 + R |
| 0x038 | rsp_size | kernel | R |
| 0x040 | req_seq_next | user | next request seq |
| 0x048 | rsp_seq_next | kernel | next response seq |
| 0x050 | req_seq_acked | kernel | |
| 0x058 | rsp_seq_acked | user | |
| 0x060 | req_head | user | request ring producer offset |
| 0x068 | req_tail | kernel | request ring consumer offset |
| 0x070 | rsp_head | kernel | response ring producer offset |
| 0x078 | rsp_tail | user | response ring consumer offset |
| 0x080 | user_heartbeat_ns | user | boot-relative ns, every 500 ms |
| 0x088 | kernel_heartbeat_ns | kernel | boot-relative ns, every 500 ms |
| 0x090 | attach_id | kernel | |
| 0x098 | last_error_seq | kernel | last dropped reply seq |
| 0x0A0 | nonce_prefix_rq | user | user -> kernel direction |
| 0x0A8 | nonce_prefix_rs | kernel | kernel -> user direction |
| 0x0B0 | salt | kernel | from bootstrap |
| 0x0D0 | session_tag | kernel | see section 5 |
| 0x0F0 | peer_token | - | reserved, zero |
| 0x100..0xFFF | reserved | - | zero |

Region geometry: `R = round_down_4k((shared_size - 0x1000) / 2)`;
request ring at 0x1000, response ring at 0x1000 + R.

**The region is user-owned memory.** The kernel re-validates magic, version,
header_size, geometry, attach_id, peer_pid and cipher on every poll, re-validates
every head/tail (`< ring_size`, 8-byte aligned, queued bytes <= ring_size - 8)
and never indexes outside `[off, off+size)`. Any mismatch fails the session with
a `KC_ERR_*` - it never bugchecks.

## 4. Frames

```
kc_record (16 B):   u32 length | u32 magic 'KCR1' | u64 seq | data[length-16]
data              = kc_msg_header (64 B) || ciphertext(payload_len) || pad
```

`kc_msg_header` (0x40):

| off | field | notes |
|---|---|---|
| 0x00 | magic | `'KCM1'` |
| 0x04 | version | u16 = 1 |
| 0x06 | opcode | u16, see section 5 |
| 0x08 | payload_len | ciphertext length (plaintext length) |
| 0x0C | status | `kc_status`, meaningful for REPLY |
| 0x10 | seq | equals `kc_record.seq` |
| 0x18 | request_id | CALL/REPLY pairing |
| 0x20 | nonce_suffix | reserved 0 |
| 0x28 | reserved0/1 | must be 0 |
| 0x30 | tag | HMAC-SHA256 truncated to 16 bytes |

- **Authenticated**: `header[0, 0x30) || ciphertext` (AAD = 48 bytes).
- **Encrypted**: payload only. Default ChaCha20 (RFC 8439); AES-128-CTR
  optional. Both directions use independent nonce prefixes and sequence spaces.
- **Alignment**: record length is a multiple of 8. `payload_len` stays the
  exact plaintext length; up to 7 zero padding bytes follow the ciphertext and
  are not authenticated (they are validated to be zero on receive).
- **Nonce**: ChaCha20 uses `nonce12 = prefix[8] || uint32(seq)` and a 32-bit
  block counter starting at 0; a session may send at most 2^32 records per
  direction (`KC_ERR_STATE` after that). AES-128-CTR uses the full 128-bit
  counter block `prefix[8] || uint64(seq)` and has no practical limit.
- **Replay protection**: strictly increasing `seq` per direction, checked by
  both sides; stale/replayed records are rejected (`KC_ERR_AUTH`).
- **Limits**: `payload_len <= KC_MAX_PAYLOAD` (64 KiB - 64) and
  `record <= ring_size - 16`. Application payload is at most
  `KC_MAX_PAYLOAD - 2` because CALL/EVENT carry a 2-byte app opcode prefix.

## 5. Opcodes and payload conventions

| opcode | value | direction | plaintext |
|---|---|---|---|
| HELLO | 1 | user -> kernel | `kc_hello_payload` (24 B) |
| HELLO_ACK | 2 | kernel -> user | `kc_hello_ack_payload` (24 B) |
| CALL | 3 | user -> kernel | `u16 app_op \|\| request bytes` |
| REPLY | 4 | kernel -> user | reply bytes, `header.status` = handler status |
| EVENT | 5 | kernel -> user | `u16 app_op \|\| event bytes` |
| BYE | 6 | user -> kernel | empty |
| PING | 7 | user -> kernel | empty, answered by an empty REPLY |
| PONG | 8 | - | reserved |

Application opcodes are `>= KC_OP_APP_MIN (0x8000)` and are delivered to
handlers verbatim. Opcodes 1..8 are transport-owned and never reach a handler.

## 6. Handshake and session authentication

1. Kernel writes the control page, computes
   `session_tag = HMAC-SHA256(session_key, "kchannel/session" || salt ||
   attach_id_le || peer_pid_le)`, sets `state = READY`, and publishes its
   nonce prefix. The user recomputes the tag: a match proves the kernel holds
   the same session key. A mismatch is `KC_ERR_AUTH`.
2. User publishes `nonce_prefix_rq`, writes `HELLO` (seq 1) and waits for
   `HELLO_ACK` (seq 1). The kernel only accepts `HELLO` in `READY`, checks
   attach_id/pid/key, then flips both sides to `ACTIVE`.
3. No application opcode is processed before `ACTIVE`; early calls are
   answered with `KC_ERR_STATE` (or rejected).
4. A second bootstrap while a session exists returns `KC_ERR_ALREADY`; the
   kernel writes `state = FAILED, error = KC_ERR_ALREADY` into the new region
   so the second loader sees the reason instead of a timeout.
5. `BYE`, watchdog expiry, or a fatal validation error moves the kernel side to
   `STOPPED`/`DEAD` and invokes `on_peer_gone` exactly once.

## 7. Status codes

`KC_OK=0, KC_ERR_PARAM=1, KC_ERR_NOMEM=2, KC_ERR_MAGIC=3, KC_ERR_VERSION=4,
KC_ERR_STATE=5, KC_ERR_AUTH=6, KC_ERR_TIMEOUT=7, KC_ERR_BUSY=8, KC_ERR_IO=9,
KC_ERR_MAP=10, KC_ERR_NOT_FOUND=11, KC_ERR_ALREADY=12, KC_ERR_INTERNAL=13,
KC_ERR_PEER_GONE=14, KC_ERR_HANDLER=15, KC_ERR_UNSUPPORTED=16`.

Mapping used by the transport: unregistered opcode -> `KC_ERR_NOT_FOUND`;
oversized request -> `KC_ERR_PARAM`; handler claiming `out_len > out_cap` ->
`KC_ERR_INTERNAL`; malformed/tampered frames -> `KC_ERR_AUTH`/`MAGIC`/
`VERSION`/`IO`; handler results are returned verbatim by `kc_call()`.

## 8. Names and C compatibility

- Both headers are `extern "C"` and C11-clean; the kernel header defines the
  fixed-width integer types itself because the WDK kernel include path has no
  `<stdint.h>`.
- The state enum type is `kc_state_t` because the contract also requires the
  function `kc_state()`, and C/C++ do not allow both names.
- `kc_kernel_create` and friends take a kernel-memory copy of the bootstrap.
- `kc_kernel.h`-level additions in 1.0 (non-breaking, appended):
  `kc_kernel_peer_pid`, `kc_kernel_attach_id`, `kc_kernel_set_peer_gone`;
  `kc_kernel_config` gained `poll_idle_max_us` at the end. User API additions:
  `kc_tick`, `kc_set_event_handler`, `kc_get_stats`, `kc_attach_id`,
  `kc_state_error`.
