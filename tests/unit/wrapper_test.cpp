/*
 * Tests for the header-only C++ wrapper (include/blook/kchannel.hpp).
 *
 * Uses the same in-process mock kernel as the raw-API tests, so the wrapper is
 * covered against real framing/handshake code rather than a stub.
 */
#include <gtest/gtest.h>

#include <cstring>

#include <blook/kchannel.hpp>

#include "mock_kernel.h"

namespace {

constexpr uint16_t kOpEcho = 0x8001;

} /* namespace */

TEST(Wrapper, AttachHandshakeCallDetach) {
    blook::kchannel::Client client;
    kc_status status = client.attach();
    ASSERT_EQ(status, KC_OK);
    ASSERT_TRUE(client.valid());

    kc_bootstrap boot;
    std::memset(&boot, 0, sizeof(boot));
    ASSERT_EQ(client.bootstrap(&boot), KC_OK);

    MockKernel mock(5000);
    ASSERT_EQ(mock.create(boot), KC_OK);
    ASSERT_EQ(mock.register_handler(kOpEcho, MockKernel::echo_handler, nullptr),
              KC_OK);
    mock.start();

    ASSERT_EQ(client.finish(3000), KC_OK);
    EXPECT_EQ(client.state(), KC_STATE_ACTIVE);

    const std::vector<uint8_t> request = {'a', 'b', 'c'};
    const blook::kchannel::Reply reply = client.call(kOpEcho, request);
    EXPECT_EQ(reply.status, KC_OK);
    EXPECT_EQ(reply.data, request);

    EXPECT_EQ(client.ping(2000), KC_OK);
    EXPECT_GT(client.attach_id(), 0u);
    EXPECT_EQ(client.error(), KC_OK);
    const kc_client_stats stats = client.stats();
    EXPECT_GE(stats.calls, 1u);

    mock.stop();
    client.detach();
    EXPECT_FALSE(client.valid());
    EXPECT_EQ(client.state(), KC_STATE_EMPTY);
}

TEST(Wrapper, StructCallAndMoveSemantics) {
    struct Ping {
        uint32_t value;
    };
    struct Pong {
        uint32_t value;
    };
    blook::kchannel::Client source;
    ASSERT_EQ(source.attach(), KC_OK);
    kc_bootstrap boot;
    ASSERT_EQ(source.bootstrap(&boot), KC_OK);
    MockKernel mock(5000);
    ASSERT_EQ(mock.create(boot), KC_OK);
    ASSERT_EQ(mock.register_handler(kOpEcho, MockKernel::echo_handler, nullptr),
              KC_OK);
    mock.start();
    ASSERT_EQ(source.finish(3000), KC_OK);

    blook::kchannel::Client moved = std::move(source);
    EXPECT_FALSE(source.valid());
    EXPECT_TRUE(moved.valid());

    const Ping request{0xABCDEF01};
    Pong response{0};
    const kc_status struct_status =
        moved.call_struct<Ping, Pong>(kOpEcho, request, &response);
    EXPECT_EQ(struct_status, KC_OK);
    EXPECT_EQ(response.value, request.value);

    mock.stop();
} /* moved's destructor detaches */

TEST(Wrapper, AttachFailureIsReported) {
    blook::kchannel::Client client;
    kc_attach_opts options;
    std::memset(&options, 0, sizeof(options));
    options.region_size = 0x1001; /* not page aligned */
    EXPECT_EQ(client.attach(options), KC_ERR_PARAM);
    EXPECT_FALSE(client.valid());
    EXPECT_EQ(client.state(), KC_STATE_EMPTY);
}
