#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "common/kc_crypto.h"
#include "common/kc_internal.h"

namespace {

std::vector<uint8_t> from_hex(const char* hex) {
    std::vector<uint8_t> out;
    const size_t len = std::strlen(hex);
    for (size_t i = 0; i + 1 < len; i += 2) {
        unsigned value = 0;
        std::sscanf(hex + i, "%2x", &value);
        out.push_back(static_cast<uint8_t>(value));
    }
    return out;
}

std::vector<uint8_t> bytes_of(const char* text) {
    return std::vector<uint8_t>(text, text + std::strlen(text));
}

} /* namespace */

TEST(Crypto, Sha256KnownVectors) {
    uint8_t digest[32];
    kc::sha256("abc", 3, digest);
    EXPECT_EQ(std::vector<uint8_t>(digest, digest + 32),
              from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff"
                       "61f20015ad"));
    kc::sha256("", 0, digest);
    EXPECT_EQ(std::vector<uint8_t>(digest, digest + 32),
              from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca4959"
                       "91b7852b855"));
    const std::string million(1000000, 'a');
    kc::sha256(million.data(), static_cast<uint32_t>(million.size()), digest);
    EXPECT_EQ(std::vector<uint8_t>(digest, digest + 32),
              from_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39"
                       "ccc7112cd0"));
    /* streaming split must match one-shot */
    kc::Sha256 streaming;
    kc::sha256_init(&streaming);
    kc::sha256_update(&streaming, million.data(), 500000);
    kc::sha256_update(&streaming, million.data() + 500000, 500000);
    uint8_t streamed[32];
    kc::sha256_final(&streaming, streamed);
    EXPECT_EQ(std::memcmp(digest, streamed, 32), 0);
}

TEST(Crypto, HmacSha256Rfc4231) {
    uint8_t digest[32];
    /* Test case 1 */
    std::vector<uint8_t> key1(20, 0x0b);
    kc::hmac_sha256(key1.data(), 20, "Hi There", 8, digest);
    EXPECT_EQ(std::memcmp(digest,
                          from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc20"
                                   "0c9833da726e9376c2e32cff7")
                              .data(),
                          32),
              0);
    /* Test case 2 */
    kc::hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, digest);
    EXPECT_EQ(std::memcmp(digest,
                          from_hex("5bdcc146bf60754e6a042426089575c75a003f0"
                                   "89d2739839dec58b964ec3843")
                              .data(),
                          32),
              0);
    /* Test case 6: key larger than the block size */
    std::vector<uint8_t> key6(131, 0xaa);
    const char* data6 =
        "Test Using Larger Than Block-Size Key - Hash Key First";
    kc::hmac_sha256(key6.data(), 131, data6,
                    static_cast<uint32_t>(std::strlen(data6)), digest);
    EXPECT_EQ(std::memcmp(digest,
                          from_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc62"
                                   "13728c5140546040f0ee37f54")
                              .data(),
                          32),
              0);
    /* Streaming form must agree with the one-shot form. */
    kc::HmacKey hmac_key;
    kc::Hmac hmac;
    kc::hmac_key_init(&hmac_key, key6.data(), 131);
    kc::hmac_init(&hmac_key, &hmac);
    kc::hmac_update(&hmac, data6, 10);
    kc::hmac_update(&hmac, data6 + 10,
                    static_cast<uint32_t>(std::strlen(data6)) - 10);
    uint8_t streamed[32];
    kc::hmac_final(&hmac, streamed);
    EXPECT_EQ(std::memcmp(digest, streamed, 32), 0);
}

TEST(Crypto, ChaCha20Rfc8439) {
    uint8_t key[32];
    for (uint32_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(i);
    }
    uint8_t nonce[12] = {0};
    nonce[7] = 0x4a;
    const std::string text =
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> ciphertext(text.size());
    kc::chacha20_xor(key, nonce, 1, text.data(), ciphertext.data(),
                     static_cast<uint32_t>(text.size()));
    EXPECT_EQ(ciphertext,
              from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27a"
                       "fccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e"
                       "65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b"
                       "65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40"
                       "b8eedf2785e42874d"));
    /* The keystream is an involution: decrypting restores the plaintext. */
    std::vector<uint8_t> restored(text.size());
    kc::chacha20_xor(key, nonce, 1, ciphertext.data(), restored.data(),
                     static_cast<uint32_t>(text.size()));
    EXPECT_EQ(std::vector<uint8_t>(text.begin(), text.end()), restored);
}

TEST(Crypto, Aes128CtrSp80038a) {
    const std::vector<uint8_t> key =
        from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    const std::vector<uint8_t> counter =
        from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const std::vector<uint8_t> plaintext = from_hex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51");
    std::vector<uint8_t> ciphertext(plaintext.size());
    kc::aes128_ctr_xor(key.data(), counter.data(), plaintext.data(),
                       ciphertext.data(),
                       static_cast<uint32_t>(plaintext.size()));
    EXPECT_EQ(ciphertext, from_hex("874d6191b620e3261bef6864990db6ce"
                                   "9806f66b7970fdff8617187bb9fffdff"));
}

TEST(Crypto, ConstantTimeCompare) {
    uint8_t a[16] = {1, 2, 3, 4};
    uint8_t b[16] = {1, 2, 3, 4};
    EXPECT_TRUE(kc::mem_equal_ct(a, b, 16));
    b[15] = 5;
    EXPECT_FALSE(kc::mem_equal_ct(a, b, 16));
}
