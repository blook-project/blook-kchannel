/*
 * Compile-only ABI consumer test, C++17 mode (built as kchannel-abi-cxx17).
 *
 * The kernel header must be includable in C++17 exactly as a driver pulls it
 * in: <ntifs.h> first is a kernel-build concern and is not simulated here, but
 * all ABI types and the C ABI declarations must be present.
 */
#include <blook/kchannel.h>
#include <blook/kchannel_km.h>

#include <cstddef>
#include <cstdint>

namespace {

static_assert(sizeof(kc_bootstrap) == KC_BOOTSTRAP_SIZE, "bootstrap size");
static_assert(sizeof(kc_ctrl) == KC_CTRL_SIZE, "ctrl size");
static_assert(sizeof(kc_msg_header) == KC_MSG_HEADER_SIZE, "header size");
static_assert(sizeof(kc_record) == KC_RECORD_HEADER_SIZE, "record size");
static_assert(offsetof(kc_ctrl, session_tag) == 0xD0, "session tag offset");
static_assert(KC_MSG_AAD_SIZE == 0x30, "AAD size");

} /* namespace */

int main() {
    kc_bootstrap boot{};
    kc_attach_opts options{};
    kc_kernel_config config{};
    boot.struct_size = KC_BOOTSTRAP_SIZE;
    options.region_size = KC_DEFAULT_REGION_SIZE;
    config.watchdog_ms = KC_DEFAULT_WATCHDOG_MS;
    kc_status (*handler)(void*, uint16_t, const void*, uint32_t, void*,
                         uint32_t*, uint32_t*) = nullptr;
    (void)handler;
    return boot.struct_size == KC_BOOTSTRAP_SIZE ? 0 : 1;
}
