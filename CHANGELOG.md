# Changelog

All notable changes to `blook-kchannel` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to the ABI version in `include/blook/kchannel.h`
(`KC_ABI_MAJOR` / `KC_ABI_MINOR`).

## [1.0.0] - 2026-10-21

### Added

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
