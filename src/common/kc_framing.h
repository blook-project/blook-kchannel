/*
 * Record / message framing + authentication for blook-kchannel.
 *
 * One record is:
 *   kc_record (16) || kc_msg_header (64) || ciphertext(payload_len)
 * The tag authenticates header[0, 0x30) || ciphertext (AAD includes
 * magic/version/opcode/length/status/seq/request_id). Payloads are encrypted
 * with ChaCha20 (default) or AES-128-CTR. Each direction has its own nonce
 * prefix and sequence space.
 */
#ifndef BLOOK_KCHANNEL_COMMON_KC_FRAMING_H
#define BLOOK_KCHANNEL_COMMON_KC_FRAMING_H

#include <blook/kchannel.h>

#include "common/kc_crypto.h"

namespace kc {

struct FrameCtx {
    HmacKey hmac;
    uint8_t raw_key[KC_KEY_SIZE];
    uint8_t tx_prefix[KC_NONCE_PREFIX_SIZE];
    uint8_t rx_prefix[KC_NONCE_PREFIX_SIZE];
    uint32_t cipher;
};

void frame_ctx_init(FrameCtx* ctx, const uint8_t key[KC_KEY_SIZE],
                    const uint8_t tx_prefix[KC_NONCE_PREFIX_SIZE],
                    const uint8_t rx_prefix[KC_NONCE_PREFIX_SIZE],
                    uint32_t cipher);

/* nonce12 = prefix[8] || uint32(seq) little endian (ChaCha20). */
void frame_nonce12(const uint8_t prefix[KC_NONCE_PREFIX_SIZE], uint64_t seq,
                   uint8_t nonce[12]);

/* Builds one record. `record_cap` must be >= KC_RECORD_TOTAL(payload_len). */
kc_status frame_seal(FrameCtx* ctx, uint16_t opcode, uint32_t status,
                     uint64_t seq, uint64_t request_id, const void* payload,
                     uint32_t payload_len, void* record, uint32_t record_cap,
                     uint32_t* record_len);

/*
 * Validates magic/length/version/tag (constant time) and decrypts. On any
 * failure `plain` is untouched and a KC_ERR_* is returned. `plain_cap` must
 * be at least header->payload_len (checked before decrypt).
 */
kc_status frame_open(FrameCtx* ctx, const void* record, uint32_t record_len,
                     kc_msg_header* out_header, void* plain, uint32_t plain_cap,
                     uint32_t* plain_len);

/* HMAC-SHA256(key, "kchannel/session" || salt || attach_id || peer_pid). */
void session_tag_compute(const uint8_t key[KC_KEY_SIZE],
                         const uint8_t salt[KC_SALT_SIZE], uint64_t attach_id,
                         uint32_t peer_pid, uint8_t out[32]);

} /* namespace kc */

#endif /* BLOOK_KCHANNEL_COMMON_KC_FRAMING_H */
