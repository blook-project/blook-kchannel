#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "common/kc_framing.h"
#include "common/kc_internal.h"

namespace {

constexpr uint8_t kTxPrefix[8] = {1, 2, 3, 4, 5, 6, 7, 8};
constexpr uint8_t kRxPrefix[8] = {9, 10, 11, 12, 13, 14, 15, 16};

struct Fixture {
    kc::FrameCtx sender{};
    kc::FrameCtx receiver{};
    std::vector<uint8_t> record;

    explicit Fixture(uint32_t cipher = KC_CIPHER_CHACHA20) {
        uint8_t key[KC_KEY_SIZE];
        for (uint32_t i = 0; i < KC_KEY_SIZE; ++i) {
            key[i] = static_cast<uint8_t>(i * 7 + 1);
        }
        /* sender: tx = kTxPrefix, rx = kRxPrefix
         * receiver: tx = kRxPrefix, rx = kTxPrefix */
        kc::frame_ctx_init(&sender, key, kTxPrefix, kRxPrefix, cipher);
        kc::frame_ctx_init(&receiver, key, kRxPrefix, kTxPrefix, cipher);
        record.assign(KC_RECORD_TOTAL(1024), 0);
    }
};

std::vector<uint8_t> payload_of(uint32_t len) {
    std::vector<uint8_t> data(len);
    for (uint32_t i = 0; i < len; ++i) {
        data[i] = static_cast<uint8_t>(i * 31 + 3);
    }
    return data;
}

} /* namespace */

TEST(Framing, RoundTripChaCha20) {
    Fixture fixture(KC_CIPHER_CHACHA20);
    const std::vector<uint8_t> plaintext = payload_of(300);
    uint32_t record_len = 0;
    ASSERT_EQ(
        kc::frame_seal(
            &fixture.sender, KC_OP_CALL, 0, 5, 0x1234, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), fixture.record.data(),
            static_cast<uint32_t>(fixture.record.size()), &record_len),
        KC_OK);
    EXPECT_EQ(record_len, 0x180u); /* 0x17C rounded up to 8 */
    kc_msg_header header;
    std::vector<uint8_t> output(1024);
    uint32_t plain_len = 0;
    ASSERT_EQ(kc::frame_open(&fixture.receiver, fixture.record.data(),
                             record_len, &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_OK);
    EXPECT_EQ(plain_len, 300u);
    EXPECT_EQ(std::vector<uint8_t>(output.begin(), output.begin() + 300),
              plaintext);
    EXPECT_EQ(header.opcode, KC_OP_CALL);
    EXPECT_EQ(header.seq, 5u);
    EXPECT_EQ(header.request_id, 0x1234u);
    EXPECT_EQ(header.status, 0u);
}

TEST(Framing, RoundTripAes128Ctr) {
    Fixture fixture(KC_CIPHER_AES128CTR);
    const std::vector<uint8_t> plaintext = payload_of(257);
    uint32_t record_len = 0;
    ASSERT_EQ(
        kc::frame_seal(
            &fixture.sender, KC_OP_REPLY, 7, 2, 42, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), fixture.record.data(),
            static_cast<uint32_t>(fixture.record.size()), &record_len),
        KC_OK);
    kc_msg_header header;
    std::vector<uint8_t> output(1024);
    uint32_t plain_len = 0;
    ASSERT_EQ(kc::frame_open(&fixture.receiver, fixture.record.data(),
                             record_len, &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_OK);
    EXPECT_EQ(header.status, 7u);
    EXPECT_EQ(std::vector<uint8_t>(output.begin(), output.begin() + 257),
              plaintext);
}

TEST(Framing, RejectsTamperedAad) {
    Fixture fixture;
    const std::vector<uint8_t> plaintext = payload_of(64);
    uint32_t record_len = 0;
    ASSERT_EQ(
        kc::frame_seal(
            &fixture.sender, KC_OP_CALL, 0, 3, 99, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), fixture.record.data(),
            static_cast<uint32_t>(fixture.record.size()), &record_len),
        KC_OK);
    kc_msg_header header;
    std::vector<uint8_t> output(256);
    uint32_t plain_len = 0;
    const uint32_t header_off = KC_RECORD_HEADER_SIZE;
    /* status and request_id live inside the authenticated range */
    for (uint32_t field_offset :
         {offsetof(kc_msg_header, status), offsetof(kc_msg_header, request_id),
          offsetof(kc_msg_header, nonce_suffix)}) {
        std::vector<uint8_t> tampered = fixture.record;
        tampered[header_off + field_offset] ^= 0x40;
        EXPECT_EQ(
            kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                           &header, output.data(),
                           static_cast<uint32_t>(output.size()), &plain_len),
            KC_ERR_AUTH);
    }
    /* payload ciphertext is authenticated too */
    std::vector<uint8_t> tampered = fixture.record;
    tampered[header_off + KC_MSG_HEADER_SIZE] ^= 0x01;
    EXPECT_EQ(kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_AUTH);
    /* tag itself */
    tampered = fixture.record;
    tampered[header_off + KC_MSG_AAD_SIZE] ^= 0x80;
    EXPECT_EQ(kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_AUTH);
}

TEST(Framing, RejectsStructuralCorruption) {
    Fixture fixture;
    const std::vector<uint8_t> plaintext = payload_of(64);
    uint32_t record_len = 0;
    ASSERT_EQ(
        kc::frame_seal(
            &fixture.sender, KC_OP_CALL, 0, 3, 99, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), fixture.record.data(),
            static_cast<uint32_t>(fixture.record.size()), &record_len),
        KC_OK);
    kc_msg_header header;
    std::vector<uint8_t> output(256);
    uint32_t plain_len = 0;
    /* record magic */
    std::vector<uint8_t> tampered = fixture.record;
    kc::put_le32(tampered.data() + 4, 0xDEADBEEF);
    EXPECT_EQ(kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_MAGIC);
    /* message magic */
    tampered = fixture.record;
    kc::put_le32(tampered.data() + KC_RECORD_HEADER_SIZE, 0xDEADBEEF);
    EXPECT_EQ(kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_MAGIC);
    /* version */
    tampered = fixture.record;
    kc::put_le32(tampered.data() + KC_RECORD_HEADER_SIZE + 4, 0x00090000);
    EXPECT_EQ(kc::frame_open(&fixture.receiver, tampered.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_VERSION);
    /* record length disagreeing with the buffer we were handed */
    EXPECT_EQ(kc::frame_open(&fixture.receiver, fixture.record.data(),
                             record_len - 8, &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_IO);
    /* non 8-byte-aligned record length */
    EXPECT_EQ(kc::frame_open(&fixture.receiver, fixture.record.data(),
                             record_len - 1, &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_IO);
    /* truncated record */
    EXPECT_EQ(kc::frame_open(&fixture.receiver, fixture.record.data(),
                             KC_RECORD_HEADER_SIZE, &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_PARAM);
    /* output buffer too small */
    EXPECT_EQ(
        kc::frame_open(&fixture.receiver, fixture.record.data(), record_len,
                       &header, output.data(), 16, &plain_len),
        KC_ERR_PARAM);
    /* wrong key: tag must not validate */
    uint8_t wrong_key[KC_KEY_SIZE];
    std::memset(wrong_key, 0xA5, sizeof(wrong_key));
    kc::FrameCtx attacker;
    kc::frame_ctx_init(&attacker, wrong_key, kRxPrefix, kTxPrefix,
                       KC_CIPHER_CHACHA20);
    EXPECT_EQ(kc::frame_open(&attacker, fixture.record.data(), record_len,
                             &header, output.data(),
                             static_cast<uint32_t>(output.size()), &plain_len),
              KC_ERR_AUTH);
}

TEST(Framing, EnforcesChaCha20SequenceCeiling) {
    Fixture fixture;
    const std::vector<uint8_t> plaintext = payload_of(8);
    uint32_t record_len = 0;
    EXPECT_EQ(
        kc::frame_seal(
            &fixture.sender, KC_OP_CALL, 0,
            static_cast<uint64_t>(KC_CHACHA20_MAX_SEQ) + 1, 1, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), fixture.record.data(),
            static_cast<uint32_t>(fixture.record.size()), &record_len),
        KC_ERR_STATE);
    /* AES-128-CTR consumes the full 128-bit nonce and has no ceiling. */
    Fixture aes(KC_CIPHER_AES128CTR);
    EXPECT_EQ(
        kc::frame_seal(
            &aes.sender, KC_OP_CALL, 0,
            static_cast<uint64_t>(KC_CHACHA20_MAX_SEQ) + 1, 1, plaintext.data(),
            static_cast<uint32_t>(plaintext.size()), aes.record.data(),
            static_cast<uint32_t>(aes.record.size()), &record_len),
        KC_OK);
}

TEST(Framing, SessionTagDependsOnEveryInput) {
    uint8_t key[KC_KEY_SIZE];
    uint8_t salt[KC_SALT_SIZE];
    for (uint32_t i = 0; i < KC_KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(i);
    }
    for (uint32_t i = 0; i < KC_SALT_SIZE; ++i) {
        salt[i] = static_cast<uint8_t>(0xA0 + i);
    }
    uint8_t a[32];
    uint8_t b[32];
    kc::session_tag_compute(key, salt, 0x1122334455667788ull, 4242, a);
    kc::session_tag_compute(key, salt, 0x1122334455667788ull, 4242, b);
    EXPECT_EQ(std::memcmp(a, b, 32), 0);
    kc::session_tag_compute(key, salt, 0x1122334455667789ull, 4242, b);
    EXPECT_NE(std::memcmp(a, b, 32), 0);
    kc::session_tag_compute(key, salt, 0x1122334455667788ull, 4243, b);
    EXPECT_NE(std::memcmp(a, b, 32), 0);
    salt[0] ^= 1;
    kc::session_tag_compute(key, salt, 0x1122334455667788ull, 4242, b);
    EXPECT_NE(std::memcmp(a, b, 32), 0);
}

TEST(Framing, NonceDerivation) {
    uint8_t nonce[12];
    kc::frame_nonce12(kTxPrefix, 0x01020304, nonce);
    EXPECT_EQ(nonce[0], 1);
    EXPECT_EQ(nonce[7], 8);
    EXPECT_EQ(nonce[8], 0x04);
    EXPECT_EQ(nonce[9], 0x03);
    EXPECT_EQ(nonce[10], 0x02);
    EXPECT_EQ(nonce[11], 0x01);
}
