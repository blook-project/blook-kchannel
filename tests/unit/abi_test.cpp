/*
 * ABI conformance test: every offset/size/constant the Lead's QA cross-checks
 * against docs/contracts/kchannel-abi-v0.md. Kept as runtime assertions so the
 * values are verified by the compiled binary, not just by static_assert.
 */
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include <blook/kchannel.h>
#include <blook/kchannel_km.h>

#include "common/kc_reactor.h"

TEST(Abi, MagicValues) {
    EXPECT_EQ(KC_BOOTSTRAP_MAGIC, 0x3142434Bu);
    EXPECT_EQ(KC_CTRL_MAGIC, 0x4E48434Bu);
    EXPECT_EQ(KC_RECORD_MAGIC, 0x3152434Bu);
    EXPECT_EQ(KC_MSG_MAGIC, 0x314D434Bu);
    EXPECT_EQ(KC_CLIENT_MAGIC, 0x3143434Bu);
    EXPECT_EQ(KC_SERVER_MAGIC, 0x3153434Bu);
    EXPECT_EQ(KC_ABI_MAJOR, 1u);
    EXPECT_EQ(KC_ABI_MINOR, 0u);
}

TEST(Abi, BootstrapLayout) {
    EXPECT_EQ(sizeof(kc_bootstrap), 0x90u);
    EXPECT_EQ(offsetof(kc_bootstrap, magic), 0x00u);
    EXPECT_EQ(offsetof(kc_bootstrap, abi_major), 0x04u);
    EXPECT_EQ(offsetof(kc_bootstrap, abi_minor), 0x06u);
    EXPECT_EQ(offsetof(kc_bootstrap, struct_size), 0x08u);
    EXPECT_EQ(offsetof(kc_bootstrap, mode), 0x0Cu);
    EXPECT_EQ(offsetof(kc_bootstrap, cipher), 0x10u);
    EXPECT_EQ(offsetof(kc_bootstrap, peer_pid), 0x14u);
    EXPECT_EQ(offsetof(kc_bootstrap, attach_id), 0x18u);
    EXPECT_EQ(offsetof(kc_bootstrap, shared_va), 0x20u);
    EXPECT_EQ(offsetof(kc_bootstrap, shared_size), 0x28u);
    EXPECT_EQ(offsetof(kc_bootstrap, session_key), 0x30u);
    EXPECT_EQ(offsetof(kc_bootstrap, salt), 0x50u);
    EXPECT_EQ(offsetof(kc_bootstrap, reserved), 0x70u);
}

TEST(Abi, ControlPageLayout) {
    EXPECT_EQ(sizeof(kc_ctrl), KC_CTRL_SIZE);
    EXPECT_EQ(offsetof(kc_ctrl, magic), 0x000u);
    EXPECT_EQ(offsetof(kc_ctrl, abi_major), 0x004u);
    EXPECT_EQ(offsetof(kc_ctrl, abi_minor), 0x006u);
    EXPECT_EQ(offsetof(kc_ctrl, header_size), 0x008u);
    EXPECT_EQ(offsetof(kc_ctrl, state), 0x00Cu);
    EXPECT_EQ(offsetof(kc_ctrl, flags), 0x010u);
    EXPECT_EQ(offsetof(kc_ctrl, error), 0x014u);
    EXPECT_EQ(offsetof(kc_ctrl, peer_pid), 0x018u);
    EXPECT_EQ(offsetof(kc_ctrl, cipher), 0x01Cu);
    EXPECT_EQ(offsetof(kc_ctrl, req_off), 0x020u);
    EXPECT_EQ(offsetof(kc_ctrl, req_size), 0x028u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_off), 0x030u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_size), 0x038u);
    EXPECT_EQ(offsetof(kc_ctrl, req_seq_next), 0x040u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_seq_next), 0x048u);
    EXPECT_EQ(offsetof(kc_ctrl, req_seq_acked), 0x050u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_seq_acked), 0x058u);
    EXPECT_EQ(offsetof(kc_ctrl, req_head), 0x060u);
    EXPECT_EQ(offsetof(kc_ctrl, req_tail), 0x068u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_head), 0x070u);
    EXPECT_EQ(offsetof(kc_ctrl, rsp_tail), 0x078u);
    EXPECT_EQ(offsetof(kc_ctrl, user_heartbeat_ns), 0x080u);
    EXPECT_EQ(offsetof(kc_ctrl, kernel_heartbeat_ns), 0x088u);
    EXPECT_EQ(offsetof(kc_ctrl, attach_id), 0x090u);
    EXPECT_EQ(offsetof(kc_ctrl, last_error_seq), 0x098u);
    EXPECT_EQ(offsetof(kc_ctrl, nonce_prefix_rq), 0x0A0u);
    EXPECT_EQ(offsetof(kc_ctrl, nonce_prefix_rs), 0x0A8u);
    EXPECT_EQ(offsetof(kc_ctrl, salt), 0x0B0u);
    EXPECT_EQ(offsetof(kc_ctrl, session_tag), 0x0D0u);
    EXPECT_EQ(offsetof(kc_ctrl, peer_token), 0x0F0u);
    EXPECT_EQ(offsetof(kc_ctrl, reserved), 0x100u);
}

TEST(Abi, WireLayout) {
    EXPECT_EQ(sizeof(kc_record), 0x10u);
    EXPECT_EQ(sizeof(kc_msg_header), 0x40u);
    EXPECT_EQ(offsetof(kc_msg_header, magic), 0x00u);
    EXPECT_EQ(offsetof(kc_msg_header, version), 0x04u);
    EXPECT_EQ(offsetof(kc_msg_header, opcode), 0x06u);
    EXPECT_EQ(offsetof(kc_msg_header, payload_len), 0x08u);
    EXPECT_EQ(offsetof(kc_msg_header, status), 0x0Cu);
    EXPECT_EQ(offsetof(kc_msg_header, seq), 0x10u);
    EXPECT_EQ(offsetof(kc_msg_header, request_id), 0x18u);
    EXPECT_EQ(offsetof(kc_msg_header, nonce_suffix), 0x20u);
    EXPECT_EQ(offsetof(kc_msg_header, tag), KC_MSG_AAD_SIZE);
    EXPECT_EQ(KC_MSG_AAD_SIZE, 0x30u);
    EXPECT_EQ(KC_RECORD_TOTAL(0), 0x50u);
}

TEST(Abi, RingGeometry) {
    uint64_t req_off = 0;
    uint64_t ring = 0;
    ASSERT_EQ(kc::region_geometry(0x4000, &req_off, &ring), KC_OK);
    EXPECT_EQ(req_off, 0x1000u);
    EXPECT_EQ(ring, 0x1000u); /* (0x4000-0x1000)/2 = 0x1800 -> 0x1000 */
    ASSERT_EQ(kc::region_geometry(0x10000, &req_off, &ring), KC_OK);
    EXPECT_EQ(ring, 0x7000u);
    ASSERT_EQ(kc::region_geometry(0x20000, &req_off, &ring), KC_OK);
    EXPECT_EQ(ring, 0xF000u);
    ASSERT_EQ(kc::region_geometry(0x40000, &req_off, &ring), KC_OK);
    EXPECT_EQ(ring, 0x1F000u);
    EXPECT_EQ(kc::region_geometry(0x3000, &req_off, &ring), KC_ERR_PARAM);
    EXPECT_EQ(kc::region_geometry(0x200000, &req_off, &ring), KC_ERR_PARAM);
    EXPECT_EQ(kc::region_geometry(0x10001, &req_off, &ring), KC_ERR_PARAM);
}

TEST(Abi, StatusValues) {
    EXPECT_EQ(static_cast<int>(KC_OK), 0);
    EXPECT_EQ(static_cast<int>(KC_ERR_PARAM), 1);
    EXPECT_EQ(static_cast<int>(KC_ERR_NOMEM), 2);
    EXPECT_EQ(static_cast<int>(KC_ERR_MAGIC), 3);
    EXPECT_EQ(static_cast<int>(KC_ERR_VERSION), 4);
    EXPECT_EQ(static_cast<int>(KC_ERR_STATE), 5);
    EXPECT_EQ(static_cast<int>(KC_ERR_AUTH), 6);
    EXPECT_EQ(static_cast<int>(KC_ERR_TIMEOUT), 7);
    EXPECT_EQ(static_cast<int>(KC_ERR_BUSY), 8);
    EXPECT_EQ(static_cast<int>(KC_ERR_IO), 9);
    EXPECT_EQ(static_cast<int>(KC_ERR_MAP), 10);
    EXPECT_EQ(static_cast<int>(KC_ERR_NOT_FOUND), 11);
    EXPECT_EQ(static_cast<int>(KC_ERR_ALREADY), 12);
    EXPECT_EQ(static_cast<int>(KC_ERR_INTERNAL), 13);
    EXPECT_EQ(static_cast<int>(KC_ERR_PEER_GONE), 14);
    EXPECT_EQ(static_cast<int>(KC_ERR_HANDLER), 15);
    EXPECT_EQ(static_cast<int>(KC_ERR_UNSUPPORTED), 16);
}

TEST(Abi, StatesAndOpcodes) {
    EXPECT_EQ(static_cast<int>(KC_STATE_EMPTY), 0);
    EXPECT_EQ(static_cast<int>(KC_STATE_INIT), 1);
    EXPECT_EQ(static_cast<int>(KC_STATE_READY), 2);
    EXPECT_EQ(static_cast<int>(KC_STATE_ACTIVE), 3);
    EXPECT_EQ(static_cast<int>(KC_STATE_FAILED), 4);
    EXPECT_EQ(static_cast<int>(KC_STATE_STOPPED), 5);
    EXPECT_EQ(static_cast<int>(KC_STATE_DEAD), 6);
    EXPECT_EQ(KC_OP_HELLO, 1u);
    EXPECT_EQ(KC_OP_HELLO_ACK, 2u);
    EXPECT_EQ(KC_OP_CALL, 3u);
    EXPECT_EQ(KC_OP_REPLY, 4u);
    EXPECT_EQ(KC_OP_EVENT, 5u);
    EXPECT_EQ(KC_OP_BYE, 6u);
    EXPECT_EQ(KC_OP_PING, 7u);
    EXPECT_EQ(KC_OP_PONG, 8u);
    EXPECT_EQ(KC_OP_APP_MIN, 0x8000u);
}
