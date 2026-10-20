#include <gtest/gtest.h>

#include <windows.h>

#include <realtimeapiset.h>

#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

#include <blook/kchannel.h>

#include "common/kc_internal.h"
#include "common/kc_ring.h"
#include "mock_kernel.h"

namespace {

constexpr uint16_t kOpEcho = 0x8001;
constexpr uint16_t kOpEvent = 0x8100;

uint64_t heartbeat_now_ns() {
    ULONGLONG ticks = 0;
    QueryUnbiasedInterruptTime(&ticks);
    return static_cast<uint64_t>(ticks) * 100ull;
}

struct Channel {
    kc_client* client = nullptr;
    MockKernel mock;
    kc_bootstrap boot{};
    bool started = false;

    kc_status attach(uint32_t region_size = KC_DEFAULT_REGION_SIZE,
                     uint32_t flags = 0, uint32_t watchdog_ms = 5000,
                     const uint8_t* key_override = nullptr,
                     uint32_t cipher = KC_CIPHER_CHACHA20) {
        kc_attach_opts opts;
        kc::mem_zero(&opts, sizeof(opts));
        opts.region_size = region_size;
        opts.mode = KC_MODE_MAPPED;
        opts.cipher = cipher;
        opts.flags = flags;
        kc_status status = kc_attach(&opts, &client);
        if (status != KC_OK) {
            return status;
        }
        status = kc_get_bootstrap(client, &boot);
        if (status != KC_OK) {
            return status;
        }
        watchdog_ms_ = watchdog_ms;
        mock.set_watchdog(watchdog_ms);
        status = mock.create(boot, key_override);
        if (status != KC_OK) {
            return status;
        }
        mock.start();
        started = true;
        return kc_attach_finish(client, 3000);
    }

    ~Channel() { close(); }

    void close() {
        if (started) {
            mock.stop();
            started = false;
        }
        if (client != nullptr) {
            kc_detach(client);
            client = nullptr;
        }
    }

    uint32_t watchdog_ms_ = 5000;
};

kc::RingView request_ring(MockKernel& mock) {
    static kc::DirectRegion direct;
    kc::direct_region_init(&direct, mock.region(), mock.region_size());
    kc::RingView view;
    view.ops = kc::direct_mem_ops();
    view.ops_ctx = &direct;
    view.region_size = mock.region_size();
    view.ring_off = KC_CTRL_SIZE;
    view.ring_size = KC_RING_SIZE_FOR(mock.region_size());
    view.head_off = offsetof(kc_ctrl, req_head);
    view.tail_off = offsetof(kc_ctrl, req_tail);
    return view;
}

bool wait_for_state(MockKernel& mock, uint32_t wanted, uint32_t timeout_ms) {
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    while (GetTickCount64() < deadline) {
        if (mock.state() == wanted) {
            return true;
        }
        Sleep(1);
    }
    return mock.state() == wanted;
}

void push_garbage(MockKernel& mock, const std::vector<uint8_t>& bytes) {
    kc::RingView ring = request_ring(mock);
    const kc_status status =
        kc::ring_push(&ring, bytes.data(), static_cast<uint32_t>(bytes.size()));
    ASSERT_EQ(status, KC_OK);
}

} /* namespace */

TEST(MockE2e, AttachHandshakeAndEcho) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    EXPECT_EQ(kc_state(channel.client), KC_STATE_ACTIVE);

    uint8_t output[64] = {0};
    uint32_t output_len = 0;
    const kc_status status = kc_call(channel.client, kOpEcho, "hello", 5,
                                     output, sizeof(output), &output_len, 2000);
    EXPECT_EQ(status, KC_OK);
    EXPECT_EQ(output_len, 5u);
    EXPECT_EQ(std::memcmp(output, "hello", 5), 0);

    kc_client_stats stats{};
    kc_get_stats(channel.client, &stats);
    EXPECT_EQ(stats.calls, 1u);
    EXPECT_EQ(stats.replies_received, 1u);
    EXPECT_GT(stats.last_rtt_ns, 0u);
}

TEST(MockE2e, EmptyPayloadAndUnknownOpcode) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    uint32_t output_len = 0;
    EXPECT_EQ(kc_call(channel.client, kOpEcho, nullptr, 0, nullptr, 0,
                      &output_len, 2000),
              KC_OK);
    EXPECT_EQ(output_len, 0u);
    EXPECT_EQ(kc_call(channel.client, 0x8123, nullptr, 0, nullptr, 0,
                      &output_len, 2000),
              KC_ERR_NOT_FOUND);
}

TEST(MockE2e, PingAndState) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    EXPECT_EQ(kc_ping(channel.client, 2000), KC_OK);
    EXPECT_EQ(kc_state(channel.client), KC_STATE_ACTIVE);
    EXPECT_EQ(kc_state_error(channel.client), KC_OK);
    EXPECT_EQ(channel.mock.reactor().peer_pid(), channel.boot.peer_pid);
}

TEST(MockE2e, LargePayload) {
    Channel channel;
    ASSERT_EQ(channel.attach(0x40000), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    const uint32_t payload = KC_MAX_PAYLOAD - KC_CALL_PREFIX_SIZE;
    std::vector<uint8_t> input(payload);
    for (uint32_t i = 0; i < payload; ++i) {
        input[i] = static_cast<uint8_t>(i * 13);
    }
    std::vector<uint8_t> output(payload, 0);
    uint32_t output_len = 0;
    const kc_status status =
        kc_call(channel.client, kOpEcho, input.data(), payload, output.data(),
                payload, &output_len, 5000);
    EXPECT_EQ(status, KC_OK);
    EXPECT_EQ(output_len, payload);
    EXPECT_EQ(input, output);
}

TEST(MockE2e, WrongKeyRejected) {
    Channel channel;
    uint8_t other_key[KC_KEY_SIZE];
    std::memset(other_key, 0x42, sizeof(other_key));
    EXPECT_EQ(channel.attach(KC_DEFAULT_REGION_SIZE, 0, 5000, other_key),
              KC_ERR_AUTH);
    EXPECT_EQ(kc_state_error(channel.client), KC_ERR_AUTH);
}

TEST(MockE2e, TimeoutAndRecovery) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    channel.mock.set_paused(true);
    uint32_t output_len = 0;
    const kc_status status =
        kc_call(channel.client, kOpEcho, "x", 1, nullptr, 0, &output_len, 150);
    EXPECT_EQ(status, KC_ERR_TIMEOUT);
    channel.mock.set_paused(false);
    /* The late reply is stale (request_id mismatch) and must be discarded. */
    EXPECT_EQ(
        kc_call(channel.client, kOpEcho, "y", 1, nullptr, 0, &output_len, 2000),
        KC_OK);
    EXPECT_EQ(kc_state(channel.client), KC_STATE_ACTIVE);
}

TEST(MockE2e, EventDelivery) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    static std::atomic<int> event_count{0};
    static std::atomic<uint16_t> event_op{0};
    static std::vector<uint8_t> event_data;
    event_count = 0;
    event_data.clear();
    kc_set_event_handler(
        channel.client,
        [](void* ctx, uint16_t op, const void* data, uint32_t len) {
            (void)ctx;
            event_count++;
            event_op = op;
            event_data.assign(static_cast<const uint8_t*>(data),
                              static_cast<const uint8_t*>(data) + len);
        },
        nullptr);
    ASSERT_EQ(channel.mock.emit(kOpEvent, "abc", 3), KC_OK);
    /* kc_ping drains queued events as part of waiting for its reply. */
    EXPECT_EQ(kc_ping(channel.client, 2000), KC_OK);
    EXPECT_EQ(event_count.load(), 1);
    EXPECT_EQ(event_op.load(), kOpEvent);
    EXPECT_EQ(event_data, std::vector<uint8_t>({'a', 'b', 'c'}));
}

TEST(MockE2e, DetachReportsPeerGone) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    kc_detach(channel.client);
    channel.client = nullptr;
    EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_STOPPED, 2000));
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (!channel.mock.peer_gone() && GetTickCount64() < deadline) {
        Sleep(1);
    }
    EXPECT_TRUE(channel.mock.peer_gone());
}

TEST(MockE2e, WatchdogDetectsDeadPeer) {
    Channel channel;
    ASSERT_EQ(channel.attach(KC_DEFAULT_REGION_SIZE,
                             KC_ATTACH_FLAG_NO_HEARTBEAT, 250),
              KC_OK);
    /* Pretend the client stopped beating a second ago. */
    channel.mock.ctrl()->user_heartbeat_ns = heartbeat_now_ns() - 1000000000ull;
    EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_DEAD, 3000));
    EXPECT_TRUE(channel.mock.peer_gone());
    EXPECT_EQ(kc_state(channel.client), KC_STATE_DEAD);
}

TEST(MockE2e, TamperedControlPageFailsSession) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    channel.mock.stop();
    channel.mock.ctrl()->rsp_off += 8; /* user-owned memory, hostile */
    channel.mock.start();
    EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_FAILED, 3000));
    uint32_t output_len = 0;
    EXPECT_NE(
        kc_call(channel.client, kOpEcho, "x", 1, nullptr, 0, &output_len, 500),
        KC_OK);
}

TEST(MockE2e, MalformedRecordsDoNotCrash) {
    struct Case {
        const char* name;
        std::vector<uint8_t> bytes;
    };
    std::vector<Case> cases;
    {
        std::vector<uint8_t> garbage(0x60, 0xAA);
        kc::put_le32(garbage.data(), 0x60);
        kc::put_le32(garbage.data() + 4, 0x12345678); /* bad record magic */
        cases.push_back({"bad record magic", garbage});
    }
    {
        std::vector<uint8_t> shortv(0x50, 0);
        kc::put_le32(shortv.data(), 0x100); /* claims more than is queued */
        kc::put_le32(shortv.data() + 4, KC_RECORD_MAGIC);
        cases.push_back({"length beyond queued", shortv});
    }
    {
        std::vector<uint8_t> badmsg(0x90, 0);
        kc::put_le32(badmsg.data(), 0x90);
        kc::put_le32(badmsg.data() + 4, KC_RECORD_MAGIC);
        kc::put_le64(badmsg.data() + 8, 1);
        kc::put_le32(badmsg.data() + 0x10, 0xDEADBEEF); /* bad msg magic */
        cases.push_back({"bad msg magic", badmsg});
    }
    {
        std::vector<uint8_t> huge(0x50, 0);
        kc::put_le32(huge.data(), 0xFFFFFFFFu); /* absurd length */
        kc::put_le32(huge.data() + 4, KC_RECORD_MAGIC);
        cases.push_back({"absurd length", huge});
    }
    for (const Case& test_case : cases) {
        SCOPED_TRACE(test_case.name);
        Channel channel;
        ASSERT_EQ(channel.attach(), KC_OK);
        push_garbage(channel.mock, test_case.bytes);
        EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_FAILED, 2000));
        uint32_t output_len = 0;
        EXPECT_NE(kc_call(channel.client, kOpEcho, "x", 1, nullptr, 0,
                          &output_len, 300),
                  KC_OK);
    }
}

TEST(MockE2e, CorruptRingPointersDoNotCrash) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    channel.mock.ctrl()->req_head = 0xDEADBEEF; /* hostile head */
    EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_FAILED, 2000));
    kc_client_stats stats{};
    kc_get_stats(channel.client, &stats);
    (void)stats;
}

TEST(MockE2e, ReplayedRecordRejected) {
    Channel channel;
    ASSERT_EQ(channel.attach(), KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    kc_ctrl* ctrl = channel.mock.ctrl();
    const uint64_t seq = ctrl->req_seq_next;
    uint8_t tx_prefix[KC_NONCE_PREFIX_SIZE];
    kc::mem_copy(tx_prefix, ctrl->nonce_prefix_rq, sizeof(tx_prefix));

    kc::FrameCtx frame;
    kc::frame_ctx_init(&frame, channel.boot.session_key, tx_prefix,
                       ctrl->nonce_prefix_rs, channel.boot.cipher);
    uint8_t plain[3] = {0x01, 0x80, 'z'}; /* op 0x8001 || 'z' */
    uint8_t record[0x100];
    uint32_t record_len = 0;
    ASSERT_EQ(
        kc::frame_seal(&frame, KC_OP_CALL, 0, seq, 777, plain, sizeof(plain),
                       record, sizeof(record), &record_len),
        KC_OK);
    push_garbage(channel.mock,
                 std::vector<uint8_t>(record, record + record_len));
    push_garbage(channel.mock,
                 std::vector<uint8_t>(record, record + record_len));
    EXPECT_TRUE(wait_for_state(channel.mock, KC_STATE_FAILED, 2000));
    EXPECT_EQ(channel.mock.reactor().error(), KC_ERR_AUTH);
}

TEST(MockE2e, InvalidAttachOptions) {
    kc_client* client = nullptr;
    kc_attach_opts opts;
    kc::mem_zero(&opts, sizeof(opts));
    opts.region_size = 0x1001;
    EXPECT_EQ(kc_attach(&opts, &client), KC_ERR_PARAM);
    opts.region_size = KC_DEFAULT_REGION_SIZE;
    opts.mode = 7;
    EXPECT_EQ(kc_attach(&opts, &client), KC_ERR_PARAM);
    opts.mode = KC_MODE_MAPPED;
    opts.cipher = 9;
    EXPECT_EQ(kc_attach(&opts, &client), KC_ERR_PARAM);
    opts.cipher = KC_CIPHER_AES128CTR;
    opts.flags = KC_ATTACH_FLAG_REQUIRE_CHACHA20;
    EXPECT_EQ(kc_attach(&opts, &client), KC_ERR_UNSUPPORTED);
    EXPECT_EQ(kc_attach(nullptr, nullptr), KC_ERR_PARAM);
    EXPECT_EQ(kc_get_bootstrap(nullptr, nullptr), KC_ERR_PARAM);
    EXPECT_NE(kc_status_str(KC_ERR_AUTH), nullptr);
    EXPECT_STREQ(kc_status_str(KC_ERR_AUTH), "KC_ERR_AUTH");
}

TEST(MockE2e, Aes128CtrSession) {
    Channel channel;
    ASSERT_EQ(channel.attach(KC_DEFAULT_REGION_SIZE, 0, 5000, nullptr,
                             KC_CIPHER_AES128CTR),
              KC_OK);
    ASSERT_EQ(channel.mock.register_handler(kOpEcho, MockKernel::echo_handler,
                                            nullptr),
              KC_OK);
    char output[8] = {0};
    uint32_t output_len = 0;
    EXPECT_EQ(kc_call(channel.client, kOpEcho, "aes", 3, output, sizeof(output),
                      &output_len, 2000),
              KC_OK);
    EXPECT_EQ(std::memcmp(output, "aes", 3), 0);
}
