/*
 * Host-side "mock kernel" for unit tests.
 *
 * It instantiates the very same kc::Reactor that the real driver uses and
 * drives it from a thread against the region created by kc_attach(). The user
 * library talks to it exactly like it talks to a real driver, so host tests
 * exercise the production protocol/framing/ring code paths end to end.
 */
#ifndef BLOOK_KCHANNEL_TESTS_UNIT_MOCK_KERNEL_H
#define BLOOK_KCHANNEL_TESTS_UNIT_MOCK_KERNEL_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include <blook/kchannel.h>

#include "common/kc_reactor.h"

class MockKernel {
   public:
    explicit MockKernel(uint32_t watchdog_ms = 5000);
    ~MockKernel();

    MockKernel(const MockKernel&) = delete;
    MockKernel& operator=(const MockKernel&) = delete;

    /* Validates the bootstrap and publishes the driver control page, mirroring
     * kc_kernel_create(). `key_override` simulates a kernel that holds a
     * different session key. */
    kc_status create(const kc_bootstrap& boot,
                     const uint8_t* key_override = nullptr);

    void set_watchdog(uint32_t watchdog_ms) { watchdog_ms_ = watchdog_ms; }

    void start();
    void stop();

    /* Stops polling without stopping the thread (simulates a stuck kernel). */
    void set_paused(bool paused) { paused_ = paused; }

    /* Simulates a dead kernel: stops the thread and disables polling. */
    void kill();

    kc_status register_handler(uint16_t op, kc_handler_fn fn, void* ctx);
    kc_status emit(uint16_t op, const void* data, uint32_t len);

    kc::Reactor& reactor() { return reactor_; }
    bool peer_gone() const { return peer_gone_.load(); }
    uint32_t state() { return reactor_.state(); }
    uint8_t* region() { return region_; }
    uint64_t region_size() const { return region_size_; }
    kc_ctrl* ctrl() { return reinterpret_cast<kc_ctrl*>(region_); }
    uint32_t max_payload() const { return max_payload_; }
    uint32_t ring_size() const { return ring_size_; }
    std::mutex& region_mutex() { return mutex_; }
    void on_peer_gone() { peer_gone_.store(true); }

    static kc_status echo_handler(void* ctx, uint16_t op, const void* in,
                                  uint32_t in_len, void* out, uint32_t* out_cap,
                                  uint32_t* out_len);

   private:
    void loop();

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> peer_gone_{false};
    std::mutex mutex_;

    kc::Reactor reactor_;
    kc::ReactorHandler handlers_[KC_MAX_HANDLERS];
    uint32_t handler_count_ = 0;
    uint32_t watchdog_ms_ = 5000;
    kc::DirectRegion direct_{};
    kc_ctrl* ctrl_scratch_ = nullptr;
    uint8_t* region_ = nullptr;
    uint64_t region_size_ = 0;
    uint32_t max_payload_ = 0;
    uint32_t ring_size_ = 0;

    std::vector<uint8_t> record_buf_;
    std::vector<uint8_t> plain_buf_;
    std::vector<uint8_t> out_buf_;
    std::vector<uint8_t> reply_buf_;
    std::vector<uint8_t> event_buf_;
    std::vector<uint8_t> event_record_buf_;
};

#endif /* BLOOK_KCHANNEL_TESTS_UNIT_MOCK_KERNEL_H */
