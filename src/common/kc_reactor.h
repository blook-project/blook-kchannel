/*
 * blook-kchannel reactor: kernel-side protocol engine.
 *
 * The reactor owns everything protocol related (ctrl page, both SPSC rings,
 * handshake, watchdog, request dispatch, replies, events) and is independent
 * of how shared memory is reached. The real kernel worker and the host-side
 * "mock kernel" used by tests instantiate the same class, so host unit tests
 * exercise the exact production protocol code.
 *
 * All access to the loader-owned memory goes through MemOps and is treated as
 * hostile: geometry, record lengths, heads/tails and sequence numbers are
 * re-validated on every poll. Corrupt input fails the session with a
 * KC_ERR_* and never indexes outside the region.
 */
#ifndef BLOOK_KCHANNEL_COMMON_KC_REACTOR_H
#define BLOOK_KCHANNEL_COMMON_KC_REACTOR_H

#include <blook/kchannel.h>

#include "common/kc_framing.h"
#include "common/kc_ring.h"

namespace kc {

struct ReactorHandler {
    uint16_t op;
    kc_handler_fn fn;
    void* ctx;
};

struct ReactorConfig {
    const MemOps* ops;
    void* ops_ctx;
    uint64_t region_size;

    const uint8_t* session_key; /* 32 bytes */
    const uint8_t* salt;        /* 32 bytes */
    const uint8_t* nonce_tx;    /* 8 bytes, kernel -> user */
    const uint8_t* nonce_rx;    /* 8 bytes, user -> kernel */
    uint32_t cipher;
    uint32_t peer_pid;
    uint64_t attach_id;

    uint32_t max_payload;  /* 0 => computed from geometry */
    uint32_t watchdog_ms;  /* 0 => KC_DEFAULT_WATCHDOG_MS */
    uint32_t flags;        /* KC_KFLAG_* */
    uint32_t handshake_ms; /* 0 => watchdog_ms */

    const ReactorHandler* handlers;
    uint32_t handler_count;

    /* Caller-provided buffers (kernel pool / host heap). */
    kc_ctrl* ctrl_scratch; /* 0x1000 bytes, used as a snapshot buffer */
    uint8_t* record_buf;
    uint32_t record_buf_cap;
    uint8_t* plain_buf;
    uint32_t plain_buf_cap;
    uint8_t* out_buf;
    uint32_t out_buf_cap;
    uint8_t* reply_buf;
    uint32_t reply_buf_cap;
    /* Dedicated buffers for kc_kernel_emit() so an event can be produced from
     * another thread without racing the worker's reply buffers. */
    uint8_t* event_buf;
    uint32_t event_buf_cap;
    uint8_t* event_record_buf;
    uint32_t event_record_buf_cap;

    void (*lock)(void* ctx);
    void (*unlock)(void* ctx);
    void* lock_ctx;
    uint64_t (*now_ns)(void* ctx);
    void* now_ctx;
    /* Sleeps roughly `ms` milliseconds (used only for reply backpressure). */
    void (*delay_ms)(void* ctx, uint32_t ms);
    void* delay_ctx;
    void (*on_peer_gone)(void* ctx);
    void* ctx;
    /* Optional: checked before touching the mapping; return false to stop the
     * session without any further access to the loader region (KC-001). */
    bool (*peer_alive)(void* ctx);
    void* peer_ctx;
};

class Reactor {
   public:
    Reactor();
    ~Reactor();

    kc_status init(const ReactorConfig& cfg);
    void reset(); /* zero key material */

    uint32_t state() const { return state_; }
    uint32_t error() const { return error_; }
    uint32_t peer_pid() const { return peer_pid_; }
    uint64_t attach_id() const { return attach_id_; }
    uint32_t max_payload() const { return max_payload_; }

    /* Processes up to max_records queued requests; returns how many were
     * consumed. A corrupt/failed session returns 0 afterwards. */
    int poll(int max_records);

    /* Kernel-originated event (KC_OP_EVENT), only while ACTIVE. */
    kc_status emit(uint16_t op, const void* data, uint32_t len);

    /* Called by the worker for bookkeeping even when no record arrived. */
    void tick();

    /* External failure injection (I/O error, mapping trouble). */
    void force_fail(kc_status error);

    /* Replaces the peer-gone callback after initialization. */
    void set_peer_gone_callback(void (*fn)(void*), void* ctx);

    /* Updates the visible handler count after a runtime registration. */
    void set_handler_count(uint32_t count);

   private:
    kc_status read_ctrl_snapshot();
    kc_status write_ctrl32(uint64_t off, uint32_t value);
    kc_status write_ctrl64(uint64_t off, uint64_t value);
    void fail_session(kc_status error);
    void mark_peer_gone(uint32_t new_state);
    void set_state(uint32_t new_state);

    void handle_record(uint32_t record_len);
    void handle_hello(const kc_msg_header& header, uint32_t plain_len);
    void handle_call(const kc_msg_header& header, uint32_t plain_len);
    void handle_ping(const kc_msg_header& header);
    void handle_bye();
    void send_reply(const kc_msg_header& request, kc_status status,
                    const void* payload, uint32_t len);
    void send_reply_record(const kc_msg_header& request, uint16_t opcode,
                           kc_status status, const void* payload, uint32_t len);
    void refresh_handshake_rx_prefix();
    void check_watchdog(uint64_t now_ns);

    ReactorConfig cfg_;
    FrameCtx frames_;
    RingView req_;
    RingView rsp_;
    uint64_t req_off_;
    uint64_t req_size_;
    uint64_t rsp_off_;
    uint64_t rsp_size_;
    uint32_t max_payload_;
    uint64_t attach_id_;
    uint32_t peer_pid_;
    uint32_t cipher_;
    uint32_t watchdog_ms_;
    uint32_t handshake_ms_;

    uint32_t state_;
    uint32_t error_;
    uint64_t rx_seq_last_;
    uint64_t tx_seq_next_;
    uint64_t created_ns_;
    uint64_t last_kernel_hb_ns_;
    uint64_t last_user_hb_ns_;
    bool peer_gone_reported_;
    bool hello_seen_;
};

/* Computes the ring geometry for a region (contract section 3). */
kc_status region_geometry(uint64_t region_size, uint64_t* req_off,
                          uint64_t* ring_size);

} /* namespace kc */

#endif /* BLOOK_KCHANNEL_COMMON_KC_REACTOR_H */
