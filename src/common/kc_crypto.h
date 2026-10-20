/*
 * Self-contained crypto for blook-kchannel (kernel and user).
 *
 * Everything here is dependency free on purpose: a manually mapped driver
 * cannot rely on CNG/BCrypt, and the same code is used by the host unit
 * tests, the in-process mock kernel and the real kernel worker.
 *
 * Primitives:
 *   - SHA-256 (FIPS 180-4)
 *   - HMAC-SHA256 (RFC 2104 / RFC 4231) with precomputed ipad/opad states
 *   - ChaCha20 (RFC 8439), default payload cipher
 *   - AES-128-CTR (FIPS 197 + SP 800-38A), optional payload cipher
 */
#ifndef BLOOK_KCHANNEL_COMMON_KC_CRYPTO_H
#define BLOOK_KCHANNEL_COMMON_KC_CRYPTO_H

#include <blook/kchannel.h>

namespace kc {

/* ------------------------------ SHA-256 ------------------------------ */

struct Sha256 {
    uint32_t h[8];
    uint64_t total; /* bytes fed so far */
    uint8_t buf[64];
    uint32_t buflen;
};

void sha256_init(Sha256* ctx);
void sha256_update(Sha256* ctx, const void* data, uint32_t len);
void sha256_final(Sha256* ctx, uint8_t out[32]);
void sha256(const void* data, uint32_t len, uint8_t out[32]);

/* Compress exactly one 64 byte block into an initialized state. Used to
 * precompute the HMAC ipad/opad midstates. */
void sha256_compress(uint32_t state[8], const uint8_t block[64]);

/* --------------------------- HMAC-SHA256 ----------------------------- */

struct HmacKey {
    uint32_t inner[8];
    uint32_t outer[8];
};

struct Hmac {
    uint32_t h[8];
    uint32_t outer[8]; /* opad midstate, kept for hmac_final */
    uint64_t total;
    uint8_t buf[64];
    uint32_t buflen;
};

void hmac_key_init(HmacKey* key, const void* raw_key, uint32_t key_len);
void hmac_init(const HmacKey* key, Hmac* ctx);
void hmac_update(Hmac* ctx, const void* data, uint32_t len);
void hmac_final(Hmac* ctx, uint8_t out[32]);
void hmac_sha256(const void* raw_key, uint32_t key_len, const void* data,
                 uint32_t len, uint8_t out[32]);

/* ----------------------------- ChaCha20 ------------------------------ */

void chacha20_block(const uint8_t key[KC_KEY_SIZE], const uint8_t nonce[12],
                    uint32_t counter, uint8_t out[64]);
void chacha20_xor(const uint8_t key[KC_KEY_SIZE], const uint8_t nonce[12],
                  uint32_t counter, const void* in, void* out, uint32_t len);

/* ---------------------------- AES-128-CTR ---------------------------- */

struct Aes128Key {
    uint8_t round_keys[176]; /* 11 * 16 */
};

void aes128_expand_key(Aes128Key* key, const uint8_t raw_key[16]);
void aes128_encrypt_block(const Aes128Key* key, const uint8_t in[16],
                          uint8_t out[16]);
/* counter_block is incremented as a 128-bit big-endian counter per block. */
void aes128_ctr_xor(const uint8_t raw_key[16], const uint8_t counter_block[16],
                    const void* in, void* out, uint32_t len);

} /* namespace kc */

#endif /* BLOOK_KCHANNEL_COMMON_KC_CRYPTO_H */
