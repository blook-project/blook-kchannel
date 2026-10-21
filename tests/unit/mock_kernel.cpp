#include "mock_kernel.h"

#include <windows.h>

#include <realtimeapiset.h>

#include <chrono>
#include <cstring>
#include <random>

#include "common/kc_internal.h"

namespace {

uint64_t mock_now_ns(void* ctx) {
    (void)ctx;
    ULONGLONG ticks = 0;
    QueryUnbiasedInterruptTime(&ticks);
    return static_cast<uint64_t>(ticks) * 100ull;
}

void mock_lock(void* ctx) {
    static_cast<MockKernel*>(ctx)->region_mutex().lock();
}

void mock_unlock(void* ctx) {
    static_cast<MockKernel*>(ctx)->region_mutex().unlock();
}

void mock_delay(void* ctx, uint32_t ms) {
    (void)ctx;
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

void mock_peer_gone(void* ctx) {
    static_cast<MockKernel*>(ctx)->on_peer_gone();
}

void random_prefix(uint8_t out[KC_NONCE_PREFIX_SIZE]) {
    std::random_device device;
    std::mt19937 generator(device());
    do {
        for (uint32_t i = 0; i < KC_NONCE_PREFIX_SIZE; i += 4) {
            const uint32_t value = generator();
            kc::put_le32(out + i, value);
        }
    } while (kc::is_all_zero(out, KC_NONCE_PREFIX_SIZE));
}

} /* namespace */

/* Expose the mock's mutex/peer-gone to the free functions above. */
struct MockKernelAccess;

MockKernel::MockKernel(uint32_t watchdog_ms) : watchdog_ms_(watchdog_ms) {}

MockKernel::~MockKernel() {
    stop();
}

void MockKernel::loop() {
    while (running_.load()) {
        if (paused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        const int processed = reactor_.poll(16);
        if (processed == 0) {
            /* Reactor::tick() acquires the region lock internally; taking it
             * here as well would self-deadlock (non-recursive mutex). */
            reactor_.tick();
            SwitchToThread(); /* sub-millisecond; sleep_for rounds up to 15.6 ms
                               */
        }
    }
}

kc_status MockKernel::create(const kc_bootstrap& boot,
                             const uint8_t* key_override) {
    if (boot.magic != KC_BOOTSTRAP_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (boot.abi_major != KC_ABI_MAJOR ||
        boot.struct_size != KC_BOOTSTRAP_SIZE) {
        return KC_ERR_VERSION;
    }
    if (boot.shared_size < KC_MIN_REGION_SIZE ||
        boot.shared_size > KC_MAX_REGION_SIZE ||
        (boot.shared_size % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    uint64_t req_off = 0;
    uint64_t ring = 0;
    if (kc::region_geometry(boot.shared_size, &req_off, &ring) != KC_OK) {
        return KC_ERR_PARAM;
    }
    region_ = reinterpret_cast<uint8_t*>(boot.shared_va);
    region_size_ = boot.shared_size;
    ring_size_ = static_cast<uint32_t>(ring);
    kc::direct_region_init(&direct_, region_, region_size_);

    uint64_t max_payload = KC_MAX_PAYLOAD;
    const uint64_t limit =
        ring - KC_RECORD_HEADER_SIZE - KC_MSG_HEADER_SIZE - KC_CALL_PREFIX_SIZE;
    if (limit < max_payload) {
        max_payload = limit;
    }
    max_payload_ = static_cast<uint32_t>(max_payload);

    const uint32_t record_cap =
        static_cast<uint32_t>(KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE +
                              KC_CALL_PREFIX_SIZE + max_payload_);
    record_buf_.assign(record_cap, 0);
    plain_buf_.assign(max_payload_ + 2, 0);
    out_buf_.assign(max_payload_, 0);
    reply_buf_.assign(record_cap, 0);
    event_buf_.assign(max_payload_ + 2, 0);
    event_record_buf_.assign(record_cap, 0);
    ctrl_scratch_ = new kc_ctrl();

    uint8_t nonce_tx[KC_NONCE_PREFIX_SIZE];
    random_prefix(nonce_tx);
    static const uint8_t kZeroPrefix[KC_NONCE_PREFIX_SIZE] = {0};

    kc::ReactorConfig config;
    kc::mem_zero(&config, sizeof(config));
    config.ops = kc::direct_mem_ops();
    config.ops_ctx = &direct_;
    config.region_size = region_size_;
    config.session_key =
        key_override != nullptr ? key_override : boot.session_key;
    config.salt = boot.salt;
    config.nonce_tx = nonce_tx;
    config.nonce_rx = kZeroPrefix;
    config.cipher = boot.cipher;
    config.peer_pid =
        boot.peer_pid != 0 ? boot.peer_pid : GetCurrentProcessId();
    config.attach_id = boot.attach_id;
    config.max_payload = max_payload_;
    config.watchdog_ms = watchdog_ms_;
    config.handshake_ms = watchdog_ms_;
    config.handlers = handlers_;
    config.handler_count = 0;
    config.ctrl_scratch = ctrl_scratch_;
    config.record_buf = record_buf_.data();
    config.record_buf_cap = record_cap;
    config.plain_buf = plain_buf_.data();
    config.plain_buf_cap = max_payload_ + 2;
    config.out_buf = out_buf_.data();
    config.out_buf_cap = max_payload_;
    config.reply_buf = reply_buf_.data();
    config.reply_buf_cap = record_cap;
    config.event_buf = event_buf_.data();
    config.event_buf_cap = max_payload_ + 2;
    config.event_record_buf = event_record_buf_.data();
    config.event_record_buf_cap = record_cap;
    config.lock = mock_lock;
    config.unlock = mock_unlock;
    config.lock_ctx = this;
    config.now_ns = mock_now_ns;
    config.now_ctx = this;
    config.delay_ms = mock_delay;
    config.delay_ctx = this;
    config.on_peer_gone = mock_peer_gone;
    config.ctx = this;
    config.flags = KC_KFLAG_EVENTS;

    kc_status status = reactor_.init(config);
    kc::mem_zero(nonce_tx, sizeof(nonce_tx));
    return status;
}

void MockKernel::start() {
    if (thread_.joinable()) {
        return;
    }
    running_.store(true);
    thread_ = std::thread(&MockKernel::loop, this);
}

void MockKernel::stop() {
    running_.store(false);
    if (thread_.joinable()) {
        thread_.join();
    }
}

void MockKernel::kill() {
    paused_.store(true);
    stop();
}

kc_status MockKernel::register_handler(uint16_t op, kc_handler_fn fn,
                                       void* ctx) {
    if (handler_count_ >= KC_MAX_HANDLERS) {
        return KC_ERR_NOMEM;
    }
    handlers_[handler_count_].op = op;
    handlers_[handler_count_].fn = fn;
    handlers_[handler_count_].ctx = ctx;
    ++handler_count_;
    reactor_.set_handler_count(handler_count_);
    return KC_OK;
}

kc_status MockKernel::emit(uint16_t op, const void* data, uint32_t len) {
    return reactor_.emit(op, data, len);
}

kc_status MockKernel::echo_handler(void* ctx, uint16_t op, const void* in,
                                   uint32_t in_len, void* out,
                                   uint32_t* out_cap, uint32_t* out_len) {
    (void)ctx;
    (void)op;
    if (in_len > *out_cap) {
        return KC_ERR_PARAM;
    }
    if (in_len != 0) {
        kc::mem_copy(out, in, in_len);
    }
    *out_len = in_len;
    return KC_OK;
}
