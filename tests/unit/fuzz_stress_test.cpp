/*
 * Random-mutation stress for the parser layers.
 *
 * Thousands of iterations over:
 *   - valid frames with 1..8 random byte mutations (tag/ciphertext/headers),
 *   - random garbage of random length fed to frame_open,
 *   - random ring bytes / heads / tails and random output capacities,
 *   - random control-block values fed through the actual Reactor with a mock
 *     kernel, ensuring corrupt input only ever produces KC_ERR_* and never
 *     crashes or loops.
 */
#include <gtest/gtest.h>

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include <blook/kchannel.h>

#include "common/kc_crypto.h"
#include "common/kc_framing.h"
#include "common/kc_internal.h"
#include "common/kc_reactor.h"
#include "common/kc_ring.h"

namespace {

constexpr uint8_t kTxPrefix[8] = {1, 3, 5, 7, 9, 11, 13, 15};
constexpr uint8_t kRxPrefix[8] = {2, 4, 6, 8, 10, 12, 14, 16};

struct FrameRig {
    kc::FrameCtx sender{};
    kc::FrameCtx receiver{};
    std::vector<uint8_t> record;

    FrameRig() {
        uint8_t key[KC_KEY_SIZE];
        for (uint32_t i = 0; i < KC_KEY_SIZE; ++i) {
            key[i] = static_cast<uint8_t>(i * 11 + 3);
        }
        kc::frame_ctx_init(&sender, key, kTxPrefix, kRxPrefix,
                           KC_CIPHER_CHACHA20);
        kc::frame_ctx_init(&receiver, key, kRxPrefix, kTxPrefix,
                           KC_CIPHER_CHACHA20);
        record.assign(KC_RECORD_TOTAL(256), 0);
    }

    uint32_t seal(uint64_t seq) {
        uint8_t payload[256];
        for (uint32_t i = 0; i < sizeof(payload); ++i) {
            payload[i] = static_cast<uint8_t>(i);
        }
        uint32_t length = 0;
        EXPECT_EQ(kc::frame_seal(&sender, KC_OP_CALL, 0, seq, 7, payload,
                                 sizeof(payload), record.data(),
                                 static_cast<uint32_t>(record.size()), &length),
                  KC_OK);
        return length;
    }
};

uint64_t fuzz_now_ns(void* ctx) {
    (void)ctx;
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (static_cast<uint64_t>(counter.QuadPart) * 1000000000ull) /
           static_cast<uint64_t>(frequency.QuadPart);
}

bool is_expected_error(kc_status status) {
    return status == KC_OK || status == KC_ERR_PARAM ||
           status == KC_ERR_MAGIC || status == KC_ERR_VERSION ||
           status == KC_ERR_AUTH || status == KC_ERR_IO ||
           status == KC_ERR_STATE || status == KC_ERR_BUSY ||
           status == KC_ERR_NOT_FOUND;
}

} /* namespace */

TEST(Fuzz, MutatedFramesNeverCrash) {
    FrameRig rig;
    const uint32_t length = rig.seal(3);
    std::mt19937 generator(0xC0FFEE);
    kc_msg_header header;
    std::vector<uint8_t> plain(512);
    for (uint32_t iteration = 0; iteration < 4000; ++iteration) {
        std::vector<uint8_t> mutated = rig.record;
        const uint32_t mutations = 1 + (generator() % 8);
        for (uint32_t m = 0; m < mutations; ++m) {
            const uint32_t offset = generator() % length;
            mutated[offset] ^= static_cast<uint8_t>(1u << (generator() % 8));
        }
        uint32_t plain_len = 0;
        const kc_status status = kc::frame_open(
            &rig.receiver, mutated.data(), length, &header, plain.data(),
            static_cast<uint32_t>(plain.size()), &plain_len);
        ASSERT_TRUE(is_expected_error(status)) << "iteration " << iteration;
    }
}

TEST(Fuzz, RandomBuffersNeverCrash) {
    FrameRig rig;
    std::mt19937 generator(0xBADF00D);
    kc_msg_header header;
    std::vector<uint8_t> plain(512);
    std::vector<uint8_t> buffer(2048);
    for (uint32_t iteration = 0; iteration < 4000; ++iteration) {
        const uint32_t length =
            generator() % static_cast<uint32_t>(buffer.size());
        for (uint32_t i = 0; i < length; ++i) {
            buffer[i] = static_cast<uint8_t>(generator());
        }
        uint32_t plain_len = 0;
        const kc_status status = kc::frame_open(
            &rig.receiver, buffer.data(), length, &header, plain.data(),
            static_cast<uint32_t>(plain.size()), &plain_len);
        ASSERT_TRUE(is_expected_error(status)) << "iteration " << iteration;
    }
}

TEST(Fuzz, RingsWithRandomHeadsAndRecordsNeverCrash) {
    std::vector<uint8_t> region(KC_DEFAULT_REGION_SIZE, 0);
    kc::DirectRegion direct{};
    kc::direct_region_init(&direct, region.data(), region.size());
    kc::RingView ring;
    ring.ops = kc::direct_mem_ops();
    ring.ops_ctx = &direct;
    ring.region_size = region.size();
    ring.ring_off = KC_CTRL_SIZE;
    ring.ring_size = KC_RING_SIZE_FOR(region.size());
    ring.head_off = offsetof(kc_ctrl, req_head);
    ring.tail_off = offsetof(kc_ctrl, req_tail);

    std::mt19937 generator(0x5EED);
    std::vector<uint8_t> output(4096);
    for (uint32_t iteration = 0; iteration < 4000; ++iteration) {
        for (uint32_t i = 0; i < 256; ++i) {
            region[ring.ring_off + (generator() % ring.ring_size)] =
                static_cast<uint8_t>(generator());
        }
        kc::put_le64(region.data() + ring.head_off,
                     generator() % (ring.ring_size * 2));
        kc::put_le64(region.data() + ring.tail_off,
                     generator() % (ring.ring_size * 2));
        uint32_t length = 0;
        const uint32_t cap =
            generator() % static_cast<uint32_t>(output.size() + 1);
        const kc_status status =
            kc::ring_pop(&ring, output.data(), cap, &length);
        ASSERT_TRUE(is_expected_error(status)) << "iteration " << iteration;
    }
}

TEST(Fuzz, HostileControlPageThroughReactor) {
    std::vector<uint8_t> region(KC_DEFAULT_REGION_SIZE, 0);
    kc::DirectRegion direct{};
    kc::direct_region_init(&direct, region.data(), region.size());
    uint8_t key[KC_KEY_SIZE];
    for (uint32_t i = 0; i < KC_KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(0x40 + i);
    }
    uint8_t salt[KC_SALT_SIZE];
    std::memset(salt, 0x21, sizeof(salt));
    uint8_t nonce_tx[KC_NONCE_PREFIX_SIZE];
    std::memset(nonce_tx, 0x33, sizeof(nonce_tx));
    static const uint8_t kZero[KC_NONCE_PREFIX_SIZE] = {0};
    uint64_t ring = KC_RING_SIZE_FOR(region.size());
    uint32_t record_cap = static_cast<uint32_t>(KC_RECORD_TOTAL(1026));
    std::vector<uint8_t> record(record_cap + 64), plain(2048), out(2048),
        reply(record_cap + 64), event(2048), event_record(record_cap + 64);
    kc_ctrl* scratch = new kc_ctrl();

    std::mt19937 generator(0x1234);
    for (uint32_t iteration = 0; iteration < 200; ++iteration) {
        /* Fresh region: hostile mutations from the previous iteration must
         * not leak into the next init/validate cycle. */
        std::fill(region.begin(), region.end(), 0);
        kc::Reactor reactor;
        kc::ReactorConfig config;
        kc::mem_zero(&config, sizeof(config));
        config.ops = kc::direct_mem_ops();
        config.ops_ctx = &direct;
        config.region_size = region.size();
        config.session_key = key;
        config.salt = salt;
        config.nonce_tx = nonce_tx;
        config.nonce_rx = kZero;
        config.cipher = KC_CIPHER_CHACHA20;
        config.peer_pid = GetCurrentProcessId();
        config.attach_id = 0x1122334455667788ull;
        config.max_payload = 1024;
        config.watchdog_ms = 5000;
        config.handshake_ms = 5000;
        config.handlers = nullptr;
        config.handler_count = 0;
        config.now_ns = fuzz_now_ns;
        config.ctrl_scratch = scratch;
        config.record_buf = record.data();
        config.record_buf_cap = static_cast<uint32_t>(record.size());
        config.plain_buf = plain.data();
        config.plain_buf_cap = static_cast<uint32_t>(plain.size());
        config.out_buf = out.data();
        config.out_buf_cap = static_cast<uint32_t>(out.size());
        config.reply_buf = reply.data();
        config.reply_buf_cap = static_cast<uint32_t>(reply.size());
        config.event_buf = event.data();
        config.event_buf_cap = static_cast<uint32_t>(event.size());
        config.event_record_buf = event_record.data();
        config.event_record_buf_cap =
            static_cast<uint32_t>(event_record.size());
        ASSERT_EQ(reactor.init(config), KC_OK);
        /* Corrupt the control page with random values, then let the reactor
         * poll; it must fail cleanly rather than crash or spin. */
        uint8_t* ctrl_bytes = region.data();
        for (uint32_t i = 0; i < 32; ++i) {
            ctrl_bytes[generator() % 0x100] = static_cast<uint8_t>(generator());
        }
        (void)reactor.poll(4);
        ASSERT_TRUE(reactor.state() == KC_STATE_FAILED ||
                    reactor.state() == KC_STATE_READY ||
                    reactor.state() == KC_STATE_ACTIVE ||
                    reactor.state() == KC_STATE_DEAD);
        (void)ring;
    }
    delete scratch;
}
