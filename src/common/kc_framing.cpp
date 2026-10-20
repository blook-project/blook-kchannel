#include "common/kc_framing.h"

#include "common/kc_internal.h"

namespace kc {
namespace {

const uint8_t kSessionTagLabel[16] = {'k', 'c', 'h', 'a', 'n', 'n', 'e', 'l',
                                      '/', 's', 'e', 's', 's', 'i', 'o', 'n'};

void put_tag(uint8_t* dst, const uint8_t digest[32]) {
    mem_copy(dst, digest, KC_TAG_SIZE);
}

} /* namespace */

void frame_ctx_init(FrameCtx* ctx, const uint8_t key[KC_KEY_SIZE],
                    const uint8_t tx_prefix[KC_NONCE_PREFIX_SIZE],
                    const uint8_t rx_prefix[KC_NONCE_PREFIX_SIZE],
                    uint32_t cipher) {
    mem_copy(ctx->raw_key, key, KC_KEY_SIZE);
    mem_copy(ctx->tx_prefix, tx_prefix, KC_NONCE_PREFIX_SIZE);
    mem_copy(ctx->rx_prefix, rx_prefix, KC_NONCE_PREFIX_SIZE);
    ctx->cipher = cipher;
    hmac_key_init(&ctx->hmac, key, KC_KEY_SIZE);
}

void frame_nonce12(const uint8_t prefix[KC_NONCE_PREFIX_SIZE], uint64_t seq,
                   uint8_t nonce[12]) {
    mem_copy(nonce, prefix, KC_NONCE_PREFIX_SIZE);
    put_le32(nonce + KC_NONCE_PREFIX_SIZE, static_cast<uint32_t>(seq));
}

kc_status frame_seal(FrameCtx* ctx, uint16_t opcode, uint32_t status,
                     uint64_t seq, uint64_t request_id, const void* payload,
                     uint32_t payload_len, void* record, uint32_t record_cap,
                     uint32_t* record_len) {
    if (ctx == nullptr || record == nullptr || record_len == nullptr) {
        return KC_ERR_PARAM;
    }
    if (payload_len != 0 && payload == nullptr) {
        return KC_ERR_PARAM;
    }
    if (payload_len > KC_MAX_PAYLOAD) {
        return KC_ERR_PARAM;
    }
    /* Records are 8 byte aligned: payload_len stays the exact plaintext
     * length and up to 7 zero bytes of padding follow the ciphertext. */
    const uint64_t raw_total =
        KC_RECORD_TOTAL(static_cast<uint64_t>(payload_len));
    const uint64_t total = (raw_total + 7u) & ~static_cast<uint64_t>(7u);
    if (total > record_cap) {
        return KC_ERR_PARAM;
    }
    if (ctx->cipher == KC_CIPHER_CHACHA20 && seq > KC_CHACHA20_MAX_SEQ) {
        return KC_ERR_STATE;
    }
    if (ctx->cipher != KC_CIPHER_CHACHA20 &&
        ctx->cipher != KC_CIPHER_AES128CTR) {
        return KC_ERR_PARAM;
    }

    uint8_t* rec = static_cast<uint8_t*>(record);
    put_le32(rec, static_cast<uint32_t>(total));
    put_le32(rec + 4, KC_RECORD_MAGIC);
    put_le64(rec + 8, seq);

    uint8_t* raw_header = rec + KC_RECORD_HEADER_SIZE;
    mem_zero(raw_header, KC_MSG_HEADER_SIZE);
    kc_msg_header* header = reinterpret_cast<kc_msg_header*>(raw_header);
    header->magic = KC_MSG_MAGIC;
    header->version = static_cast<uint16_t>(KC_ABI_MAJOR);
    header->opcode = opcode;
    header->payload_len = payload_len;
    header->status = status;
    header->seq = seq;
    header->request_id = request_id;
    header->nonce_suffix = 0;
    header->reserved0 = 0;
    header->reserved1 = 0;

    uint8_t* ciphertext = raw_header + KC_MSG_HEADER_SIZE;
    if (payload_len != 0) {
        mem_copy(ciphertext, payload, payload_len);
        if (ctx->cipher == KC_CIPHER_CHACHA20) {
            uint8_t nonce[12];
            frame_nonce12(ctx->tx_prefix, seq, nonce);
            chacha20_xor(ctx->raw_key, nonce, 0, ciphertext, ciphertext,
                         payload_len);
            mem_zero(nonce, sizeof(nonce));
        } else {
            uint8_t counter[16];
            mem_copy(counter, ctx->tx_prefix, KC_NONCE_PREFIX_SIZE);
            put_le64(counter + KC_NONCE_PREFIX_SIZE, seq);
            aes128_ctr_xor(ctx->raw_key, counter, ciphertext, ciphertext,
                           payload_len);
            mem_zero(counter, sizeof(counter));
        }
    }

    if (total > raw_total) {
        mem_zero(ciphertext + payload_len,
                 static_cast<uint32_t>(total - raw_total));
    }
    Hmac hmac;
    hmac_init(&ctx->hmac, &hmac);
    hmac_update(&hmac, raw_header, KC_MSG_AAD_SIZE);
    if (payload_len != 0) {
        hmac_update(&hmac, ciphertext, payload_len);
    }
    uint8_t digest[32];
    hmac_final(&hmac, digest);
    put_tag(header->tag, digest);
    mem_zero(digest, sizeof(digest));

    *record_len = static_cast<uint32_t>(total);
    return KC_OK;
}

kc_status frame_open(FrameCtx* ctx, const void* record, uint32_t record_len,
                     kc_msg_header* out_header, void* plain, uint32_t plain_cap,
                     uint32_t* plain_len) {
    if (ctx == nullptr || record == nullptr || plain_len == nullptr) {
        return KC_ERR_PARAM;
    }
    if (record_len < KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE) {
        return KC_ERR_PARAM;
    }
    if ((record_len % KC_RING_ALIGN) != 0) {
        return KC_ERR_IO;
    }
    const uint8_t* rec = static_cast<const uint8_t*>(record);
    const uint32_t record_length = get_le32(rec);
    const uint32_t record_magic = get_le32(rec + 4);
    const uint64_t record_seq = get_le64(rec + 8);
    if (record_magic != KC_RECORD_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (record_length != record_len) {
        return KC_ERR_IO;
    }
    const uint8_t* raw_header = rec + KC_RECORD_HEADER_SIZE;
    const kc_msg_header* header =
        reinterpret_cast<const kc_msg_header*>(raw_header);
    if (header->magic != KC_MSG_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (header->version != KC_ABI_MAJOR) {
        return KC_ERR_VERSION;
    }
    {
        const uint64_t raw_total =
            KC_RECORD_TOTAL(static_cast<uint64_t>(header->payload_len));
        const uint64_t expected = (raw_total + 7u) & ~static_cast<uint64_t>(7u);
        if (expected != record_len) {
            return KC_ERR_IO;
        }
        for (uint64_t i = raw_total; i < expected; ++i) {
            if (rec[i] != 0) {
                return KC_ERR_IO;
            }
        }
    }
    if (header->seq != record_seq) {
        return KC_ERR_IO;
    }

    const uint32_t payload_len = header->payload_len;
    if (payload_len > KC_MAX_PAYLOAD) {
        return KC_ERR_PARAM;
    }
    const uint8_t* ciphertext = raw_header + KC_MSG_HEADER_SIZE;

    Hmac hmac;
    hmac_init(&ctx->hmac, &hmac);
    hmac_update(&hmac, raw_header, KC_MSG_AAD_SIZE);
    if (payload_len != 0) {
        hmac_update(&hmac, ciphertext, payload_len);
    }
    uint8_t digest[32];
    hmac_final(&hmac, digest);
    const bool tag_ok = mem_equal_ct(digest, header->tag, KC_TAG_SIZE);
    mem_zero(digest, sizeof(digest));
    if (tag_ok == false) {
        return KC_ERR_AUTH;
    }
    if (header->nonce_suffix != 0 || header->reserved0 != 0 ||
        header->reserved1 != 0) {
        return KC_ERR_PARAM;
    }

    if (payload_len > plain_cap) {
        return KC_ERR_PARAM;
    }
    if (plain_len == nullptr) {
        return KC_ERR_PARAM;
    }
    if (payload_len != 0) {
        uint8_t* dst = static_cast<uint8_t*>(plain);
        if (dst == nullptr) {
            return KC_ERR_PARAM;
        }
        mem_copy(dst, ciphertext, payload_len);
        if (ctx->cipher == KC_CIPHER_CHACHA20) {
            uint8_t nonce[12];
            frame_nonce12(ctx->rx_prefix, record_seq, nonce);
            chacha20_xor(ctx->raw_key, nonce, 0, dst, dst, payload_len);
            mem_zero(nonce, sizeof(nonce));
        } else {
            uint8_t counter[16];
            mem_copy(counter, ctx->rx_prefix, KC_NONCE_PREFIX_SIZE);
            put_le64(counter + KC_NONCE_PREFIX_SIZE, record_seq);
            aes128_ctr_xor(ctx->raw_key, counter, dst, dst, payload_len);
            mem_zero(counter, sizeof(counter));
        }
    }
    if (out_header != nullptr) {
        mem_copy(out_header, header, sizeof(kc_msg_header));
    }
    *plain_len = payload_len;
    return KC_OK;
}

void session_tag_compute(const uint8_t key[KC_KEY_SIZE],
                         const uint8_t salt[KC_SALT_SIZE], uint64_t attach_id,
                         uint32_t peer_pid, uint8_t out[32]) {
    HmacKey hmac_key;
    Hmac hmac;
    hmac_key_init(&hmac_key, key, KC_KEY_SIZE);
    hmac_init(&hmac_key, &hmac);
    hmac_update(&hmac, kSessionTagLabel, sizeof(kSessionTagLabel));
    hmac_update(&hmac, salt, KC_SALT_SIZE);
    uint8_t tmp[8];
    put_le64(tmp, attach_id);
    hmac_update(&hmac, tmp, 8);
    put_le32(tmp, peer_pid);
    hmac_update(&hmac, tmp, 4);
    hmac_final(&hmac, out);
    mem_zero(&hmac_key, sizeof(hmac_key));
    mem_zero(tmp, sizeof(tmp));
}

} /* namespace kc */
