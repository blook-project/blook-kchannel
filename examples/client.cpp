/*
 * Minimal example: attach, hand the bootstrap to a mapper, finish the
 * handshake, issue calls, detach.
 *
 * Build: xmake -y && build/windows/x64/release/kchannel-example.exe
 *
 * The mapper callback is the only part a real consumer replaces. This example
 * prints the bootstrap fields so the flow is obvious; it deliberately does not
 * bundle a mapper (that belongs to the caller / blook-kdu).
 */
#include <blook/kchannel.hpp>

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

namespace {

struct EchoMessage {
    uint32_t value;
};

/* Replace with kdu/drv/drv-lite's manual mapper:
 *   - allocate kernel memory, copy the image, apply relocations,
 *   - resolve the ntoskrnl import table,
 *   - call DriverEntry with a KERNEL copy of `boot` as the entry parameter. */
kc_status MapDriver(const kc_bootstrap& boot) {
    std::printf(
        "map-driver: bootstrap ready (mode=%u cipher=%u attach_id=%016llx "
        "va=0x%llx size=0x%llx pid=%u)\n",
        boot.mode, boot.cipher,
        static_cast<unsigned long long>(boot.attach_id),
        static_cast<unsigned long long>(boot.shared_va),
        static_cast<unsigned long long>(boot.shared_size), boot.peer_pid);
    std::printf("map-driver: add your manual mapper here, then return KC_OK\n");
    return KC_ERR_UNSUPPORTED;
}

kc_status ExampleEcho(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                      void* out, uint32_t* out_cap, uint32_t* out_len) {
    (void)ctx;
    (void)op;
    if (in_len > *out_cap) {
        return KC_ERR_PARAM;
    }
    if (in_len != 0) {
        std::memcpy(out, in, in_len);
    }
    *out_len = in_len;
    return KC_OK;
}

} /* namespace */

int main(int argc, char** argv) {
    (void)argv;
    (void)argc;
    blook::kchannel::Client client;
    kc_status status = client.attach("kchannel-example");
    if (status != KC_OK) {
        std::printf("attach failed: %s\n", blook::kchannel::to_string(status));
        return 1;
    }

    kc_bootstrap boot;
    std::memset(&boot, 0, sizeof(boot));
    status = client.bootstrap(&boot);
    if (status != KC_OK) {
        std::printf("bootstrap failed: %s\n",
                    blook::kchannel::to_string(status));
        return 1;
    }

    status = MapDriver(boot);
    if (status != KC_OK) {
        std::printf(
            "no mapper: this example stops after printing the bootstrap. "
            "The driver side must call kc_kernel_create/register/start with "
            "these bytes.\n");
        return 0;
    }

    status = client.finish();
    if (status != KC_OK) {
        std::printf("handshake failed: %s\n",
                    blook::kchannel::to_string(status));
        return 1;
    }

    /* Struct request/reply over the same kc_call() machinery. */
    const EchoMessage request{0x1234};
    EchoMessage reply{0};
    status = client.call_struct<EchoMessage, EchoMessage>(0x8001, request,
                                                          &reply);
    if (status == KC_OK) {
        std::printf("struct echo: 0x%x\n", reply.value);
    }
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    const blook::kchannel::Reply echo = client.call(0x8001, payload);
    std::printf("echo: %s (%zu bytes)\n",
                blook::kchannel::to_string(echo.status), echo.data.size());
    std::printf("ping: %s\n",
                blook::kchannel::to_string(client.ping(2000)));
    std::printf("state=%u attach_id=%016llx\n", client.state(),
                static_cast<unsigned long long>(client.attach_id()));
    return 0;
}
