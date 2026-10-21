/*
 * Compile-only ABI consumer test, C11 mode.
 *
 * Proves the authoritative headers are usable from plain C (not just C++):
 * both headers are included, every public struct/enum/constant is touched and
 * the layout assertions compiled. Built by the `kchannel-abi-c` target.
 */
#include <blook/kchannel.h>
#include <blook/kchannel_km.h>

#include <stddef.h>

int main(void) {
    kc_bootstrap boot;
    kc_ctrl ctrl;
    kc_msg_header header;
    kc_record record;
    kc_attach_opts options = {0};
    kc_kernel_config config = {0};
    kc_mode mode = KC_MODE_MAPPED;
    kc_cipher cipher = KC_CIPHER_CHACHA20;
    kc_state_t state = KC_STATE_ACTIVE;
    kc_status status = KC_OK;

    boot.magic = KC_BOOTSTRAP_MAGIC;
    ctrl.magic = KC_CTRL_MAGIC;
    header.magic = KC_MSG_MAGIC;
    record.magic = KC_RECORD_MAGIC;
    options.region_size = KC_DEFAULT_REGION_SIZE;
    config.max_payload = KC_MAX_PAYLOAD;
    (void)mode;
    (void)cipher;
    (void)state;
    (void)status;
    (void)offsetof(kc_ctrl, session_tag);
    (void)sizeof(header.tag);

    return (sizeof(kc_bootstrap) == KC_BOOTSTRAP_SIZE &&
            sizeof(kc_ctrl) == KC_CTRL_SIZE &&
            sizeof(kc_msg_header) == KC_MSG_HEADER_SIZE &&
            sizeof(kc_record) == KC_RECORD_HEADER_SIZE)
               ? 0
               : 1;
}
