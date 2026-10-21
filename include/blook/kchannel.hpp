/*
 * Ergonomic C++ wrapper for the blook-kchannel user library.
 *
 * C++ only (the C ABI stays in kchannel.h). RAII over kc_client:
 *
 *   blook::kchannel::Client client;
 *   if (client.attach() != KC_OK) ...
 *   kc_bootstrap boot;
 *   client.bootstrap(&boot);
 *   map_driver(&boot);              // your manual mapper
 *   if (client.finish() != KC_OK) ...
 *   auto reply = client.call(0x8001, "ping", 4);
 *   if (reply.status == KC_OK) ...
 *   // ~Client() detaches
 *
 * The wrapper never hides errors: every call returns a kc_status, and the
 * reply payload is only populated when the status is KC_OK.
 */
#ifndef BLOOK_KCHANNEL_HPP
#define BLOOK_KCHANNEL_HPP

#include <blook/kchannel.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace blook {
namespace kchannel {

struct Reply {
    kc_status status = KC_ERR_INTERNAL;
    std::vector<uint8_t> data;
};

class Client {
public:
    Client() = default;
    explicit Client(const kc_attach_opts& options) { (void)attach(options); }
    ~Client() { detach(); }

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Client(Client&& other) noexcept : client_(other.client_) {
        other.client_ = nullptr;
    }
    Client& operator=(Client&& other) noexcept {
        if (this != &other) {
            detach();
            client_ = other.client_;
            other.client_ = nullptr;
        }
        return *this;
    }

    /* Creates the anonymous section and the session material. */
    kc_status attach(const kc_attach_opts& options) {
        detach();
        kc_client* created = nullptr;
        const kc_status status = kc_attach(&options, &created);
        if (status == KC_OK) {
            client_ = created;
        }
        return status;
    }

    /* Defaults: 0x10000 region, MAPPED mode, ChaCha20. */
    kc_status attach(const char* debug_tag = nullptr) {
        kc_attach_opts options;
        std::memset(&options, 0, sizeof(options));
        options.region_size = KC_DEFAULT_REGION_SIZE;
        options.mode = KC_MODE_MAPPED;
        options.cipher = KC_CIPHER_CHACHA20;
        options.debug_tag = debug_tag;
        return attach(options);
    }

    kc_status bootstrap(kc_bootstrap* out) const {
        return kc_get_bootstrap(client_, out);
    }

    /* Call after the driver entry ran (manual map / service bootstrap). */
    kc_status finish(uint32_t timeout_ms = KC_DEFAULT_TIMEOUT_MS) {
        return kc_attach_finish(client_, timeout_ms);
    }

    Reply call(uint16_t op, const void* in = nullptr, uint32_t in_len = 0,
               uint32_t timeout_ms = KC_DEFAULT_TIMEOUT_MS) {
        Reply reply;
        std::vector<uint8_t> buffer(KC_MAX_PAYLOAD);
        uint32_t length = 0;
        reply.status = kc_call(client_, op, in, in_len, buffer.data(),
                               static_cast<uint32_t>(buffer.size()), &length,
                               timeout_ms);
        if (reply.status == KC_OK && length != 0) {
            reply.data.assign(buffer.begin(), buffer.begin() + length);
        }
        return reply;
    }

    Reply call(uint16_t op, const std::vector<uint8_t>& request,
               uint32_t timeout_ms = KC_DEFAULT_TIMEOUT_MS) {
        return call(op, request.empty() ? nullptr : request.data(),
                    static_cast<uint32_t>(request.size()), timeout_ms);
    }

    /* Fixed-size struct request/reply helper. */
    template <typename Request, typename Response>
    kc_status call_struct(uint16_t op, const Request& request,
                          Response* response,
                          uint32_t timeout_ms = KC_DEFAULT_TIMEOUT_MS) {
        uint32_t length = 0;
        const kc_status status = kc_call(
            client_, op, &request, sizeof(request), response, sizeof(*response),
            &length, timeout_ms);
        if (status != KC_OK) {
            return status;
        }
        return length == sizeof(*response) ? KC_OK : KC_ERR_IO;
    }

    kc_status ping(uint32_t timeout_ms = KC_DEFAULT_TIMEOUT_MS) {
        return kc_ping(client_, timeout_ms);
    }

    void detach() {
        if (client_ != nullptr) {
            kc_detach(client_);
            client_ = nullptr;
        }
    }

    bool valid() const { return client_ != nullptr; }
    kc_client* raw() const { return client_; }

    uint32_t state() const { return kc_state(client_); }
    uint32_t error() const { return kc_state_error(client_); }
    uint64_t attach_id() const { return kc_attach_id(client_); }

    void set_event_handler(kc_event_fn fn, void* ctx) {
        kc_set_event_handler(client_, fn, ctx);
    }
    kc_client_stats stats() const {
        kc_client_stats result;
        std::memset(&result, 0, sizeof(result));
        kc_get_stats(client_, &result);
        return result;
    }

private:
    kc_client* client_ = nullptr;
};

/* Human readable status, same as kc_status_str but C++-friendly. */
inline const char* to_string(kc_status status) { return kc_status_str(status); }

} /* namespace kchannel */
} /* namespace blook */

#endif /* BLOOK_KCHANNEL_HPP */
