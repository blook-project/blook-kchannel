#include "common/kc_reactor.h"

#include "common/kc_internal.h"

namespace kc {
namespace {

constexpr uint64_t kNsPerMs = 1000000ull;

uint32_t ctrl_off_state() {
    return static_cast<uint32_t>(offsetof(kc_ctrl, state));
}
uint32_t ctrl_off_error() {
    return static_cast<uint32_t>(offsetof(kc_ctrl, error));
}
uint32_t ctrl_off_flags() {
    return static_cast<uint32_t>(offsetof(kc_ctrl, flags));
}
uint32_t ctrl_off_hb() {
    return static_cast<uint32_t>(offsetof(kc_ctrl, kernel_heartbeat_ns));
}
uint32_t ctrl_off_rq_prefix() {
    return static_cast<uint32_t>(offsetof(kc_ctrl, nonce_prefix_rq));
}

kc_status map_session_error(kc_status st) {
    switch (st) {
        case KC_ERR_AUTH:
        case KC_ERR_MAGIC:
        case KC_ERR_VERSION:
        case KC_ERR_IO:
        case KC_ERR_PARAM:
        case KC_ERR_STATE:
            return st;
        default:
            return KC_ERR_IO;
    }
}

} /* namespace */

kc_status region_geometry(uint64_t region_size, uint64_t* req_off,
                          uint64_t* ring_size) {
    if (req_off == nullptr || ring_size == nullptr) {
        return KC_ERR_PARAM;
    }
    if (region_size < KC_MIN_REGION_SIZE || region_size > KC_MAX_REGION_SIZE) {
        return KC_ERR_PARAM;
    }
    if ((region_size % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    uint64_t ring = KC_RING_SIZE_FOR(region_size);
    if (ring < 0x200 || (ring % KC_RING_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    if (KC_CTRL_SIZE + 2 * ring > region_size) {
        return KC_ERR_PARAM;
    }
    *req_off = KC_CTRL_SIZE;
    *ring_size = ring;
    return KC_OK;
}

Reactor::Reactor() {
    mem_zero(this, sizeof(*this));
}
Reactor::~Reactor() {
    reset();
}

void Reactor::reset() {
    mem_zero(&frames_, sizeof(frames_));
    mem_zero(&cfg_, sizeof(cfg_));
    state_ = KC_STATE_EMPTY;
}

kc_status Reactor::init(const ReactorConfig& cfg) {
    reset();
    cfg_ = cfg;

    if (cfg_.ops == nullptr || cfg_.ops_ctx == nullptr ||
        cfg_.session_key == nullptr || cfg_.salt == nullptr ||
        cfg_.nonce_tx == nullptr || cfg_.nonce_rx == nullptr ||
        cfg_.ctrl_scratch == nullptr || cfg_.record_buf == nullptr ||
        cfg_.plain_buf == nullptr || cfg_.out_buf == nullptr ||
        cfg_.reply_buf == nullptr || cfg_.event_buf == nullptr ||
        cfg_.event_record_buf == nullptr || cfg_.now_ns == nullptr) {
        return KC_ERR_PARAM;
    }
    if (cfg_.cipher != KC_CIPHER_CHACHA20 &&
        cfg_.cipher != KC_CIPHER_AES128CTR) {
        return KC_ERR_PARAM;
    }
    if (cfg_.attach_id == 0) {
        return KC_ERR_PARAM;
    }

    uint64_t req_off = 0;
    uint64_t ring = 0;
    kc_status st = region_geometry(cfg_.region_size, &req_off, &ring);
    if (st != KC_OK) {
        return st;
    }
    req_off_ = req_off;
    req_size_ = ring;
    rsp_off_ = req_off + ring;
    rsp_size_ = ring;

    /* application payload cap: the CALL prefix is not application data. */
    max_payload_ = KC_MAX_PAYLOAD - KC_CALL_PREFIX_SIZE;
    if (cfg_.max_payload != 0 && cfg_.max_payload < max_payload_) {
        max_payload_ = cfg_.max_payload;
    }
    /* record total = 16 (record) + 64 (header) + 2 (call prefix) + payload */
    if (ring >
        KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE + KC_CALL_PREFIX_SIZE) {
        uint64_t ring_limit = ring - KC_RECORD_HEADER_SIZE -
                              KC_MSG_HEADER_SIZE - KC_CALL_PREFIX_SIZE;
        if (ring_limit < max_payload_) {
            max_payload_ = static_cast<uint32_t>(ring_limit);
        }
    } else {
        return KC_ERR_PARAM;
    }
    if (max_payload_ < KC_CALL_PREFIX_SIZE) {
        return KC_ERR_PARAM;
    }
    if (cfg_.record_buf_cap <
            KC_RECORD_TOTAL(max_payload_ + KC_CALL_PREFIX_SIZE) ||
        cfg_.reply_buf_cap < KC_RECORD_TOTAL(max_payload_) ||
        cfg_.event_record_buf_cap <
            KC_RECORD_TOTAL(max_payload_ + KC_EVENT_PREFIX_SIZE)) {
        return KC_ERR_PARAM;
    }
    if (cfg_.plain_buf_cap < max_payload_ + KC_CALL_PREFIX_SIZE) {
        return KC_ERR_PARAM;
    }
    if (cfg_.event_buf_cap < max_payload_ + KC_EVENT_PREFIX_SIZE) {
        return KC_ERR_PARAM;
    }
    if (cfg_.out_buf_cap < max_payload_) {
        return KC_ERR_PARAM;
    }

    req_.ops = cfg_.ops;
    req_.ops_ctx = cfg_.ops_ctx;
    req_.region_size = cfg_.region_size;
    req_.ring_off = req_off_;
    req_.ring_size = req_size_;
    req_.head_off = offsetof(kc_ctrl, req_head);
    req_.tail_off = offsetof(kc_ctrl, req_tail);
    rsp_.ops = cfg_.ops;
    rsp_.ops_ctx = cfg_.ops_ctx;
    rsp_.region_size = cfg_.region_size;
    rsp_.ring_off = rsp_off_;
    rsp_.ring_size = rsp_size_;
    rsp_.head_off = offsetof(kc_ctrl, rsp_head);
    rsp_.tail_off = offsetof(kc_ctrl, rsp_tail);

    st = ring_validate(&req_);
    if (st != KC_OK) {
        return st;
    }
    st = ring_validate(&rsp_);
    if (st != KC_OK) {
        return st;
    }

    attach_id_ = cfg_.attach_id;
    peer_pid_ = cfg_.peer_pid;
    cipher_ = cfg_.cipher;
    watchdog_ms_ =
        cfg_.watchdog_ms != 0 ? cfg_.watchdog_ms : KC_DEFAULT_WATCHDOG_MS;
    handshake_ms_ = cfg_.handshake_ms != 0 ? cfg_.handshake_ms : watchdog_ms_;

    frames_ = FrameCtx{};
    frame_ctx_init(&frames_, cfg_.session_key, cfg_.nonce_tx, cfg_.nonce_rx,
                   cfg_.cipher);

    /* Publish the driver half of the control page. Everything is derived by
     * us; nothing from the region is trusted. */
    mem_zero(cfg_.ctrl_scratch, KC_CTRL_SIZE);
    kc_ctrl* ctrl = cfg_.ctrl_scratch;
    ctrl->magic = KC_CTRL_MAGIC;
    ctrl->abi_major = static_cast<uint16_t>(KC_ABI_MAJOR);
    ctrl->abi_minor = static_cast<uint16_t>(KC_ABI_MINOR);
    ctrl->header_size = KC_CTRL_SIZE;
    ctrl->state = KC_STATE_INIT;
    ctrl->flags = KC_CTRL_FLAG_KERNEL_READY;
    if ((cfg_.flags & KC_KFLAG_EVENTS) != 0) {
        ctrl->flags |= KC_CTRL_FLAG_EVENTS_ENABLED;
    }
    ctrl->error = KC_OK;
    ctrl->peer_pid = peer_pid_;
    ctrl->cipher = cipher_;
    ctrl->req_off = req_off_;
    ctrl->req_size = req_size_;
    ctrl->rsp_off = rsp_off_;
    ctrl->rsp_size = rsp_size_;
    ctrl->req_seq_next = 0;
    ctrl->rsp_seq_next = 1;
    ctrl->req_seq_acked = 0;
    ctrl->rsp_seq_acked = 0;
    ctrl->req_head = 0;
    ctrl->req_tail = 0;
    ctrl->rsp_head = 0;
    ctrl->rsp_tail = 0;
    ctrl->user_heartbeat_ns = 0;
    ctrl->kernel_heartbeat_ns = cfg_.now_ns(cfg_.now_ctx);
    ctrl->attach_id = attach_id_;
    ctrl->last_error_seq = 0;
    mem_copy(ctrl->nonce_prefix_rs, cfg_.nonce_tx, KC_NONCE_PREFIX_SIZE);
    mem_copy(ctrl->salt, cfg_.salt, KC_SALT_SIZE);
    uint8_t tag[32];
    session_tag_compute(cfg_.session_key, cfg_.salt, attach_id_, peer_pid_,
                        tag);
    mem_copy(ctrl->session_tag, tag, 32);
    mem_zero(tag, sizeof(tag));

    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    st = cfg_.ops->write(cfg_.ops_ctx, 0, ctrl, KC_CTRL_SIZE);
    if (st == KC_OK) {
        uint32_t ready = KC_STATE_READY;
        st = cfg_.ops->write(cfg_.ops_ctx, ctrl_off_state(), &ready,
                             sizeof(ready));
    }
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
    if (st != KC_OK) {
        mem_zero(&frames_, sizeof(frames_));
        return KC_ERR_IO;
    }

    created_ns_ = cfg_.now_ns(cfg_.now_ctx);
    last_kernel_hb_ns_ = created_ns_;
    last_user_hb_ns_ = created_ns_;
    rx_seq_last_ = 0;
    tx_seq_next_ = 1;
    peer_gone_reported_ = false;
    hello_seen_ = false;
    error_ = KC_OK;
    state_ = KC_STATE_READY;
    return KC_OK;
}

kc_status Reactor::write_ctrl32(uint64_t off, uint32_t value) {
    return cfg_.ops->write(cfg_.ops_ctx, off, &value, sizeof(value));
}

kc_status Reactor::write_ctrl64(uint64_t off, uint64_t value) {
    return cfg_.ops->write(cfg_.ops_ctx, off, &value, sizeof(value));
}

void Reactor::set_state(uint32_t new_state) {
    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    state_ = new_state;
    write_ctrl32(ctrl_off_state(), new_state);
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
}

void Reactor::fail_session(kc_status error) {
    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    const bool already_failed = (state_ == KC_STATE_FAILED);
    if (already_failed == false) {
        state_ = KC_STATE_FAILED;
        error_ = static_cast<uint32_t>(error);
        write_ctrl32(ctrl_off_error(), static_cast<uint32_t>(error));
        write_ctrl32(ctrl_off_state(), KC_STATE_FAILED);
    }
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
}

void Reactor::mark_peer_gone(uint32_t new_state) {
    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    if (state_ == KC_STATE_DEAD || state_ == KC_STATE_STOPPED) {
        if (cfg_.unlock != nullptr) {
            cfg_.unlock(cfg_.lock_ctx);
        }
        return;
    }
    state_ = new_state;
    uint32_t flags = KC_CTRL_FLAG_KERNEL_READY | KC_CTRL_FLAG_PEER_GONE;
    if ((cfg_.flags & KC_KFLAG_EVENTS) != 0) {
        flags |= KC_CTRL_FLAG_EVENTS_ENABLED;
    }
    write_ctrl32(ctrl_off_state(), new_state);
    write_ctrl32(ctrl_off_flags(), flags);
    const bool report = (peer_gone_reported_ == false);
    peer_gone_reported_ = true;
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
    if (report && cfg_.on_peer_gone != nullptr) {
        cfg_.on_peer_gone(cfg_.ctx);
    }
}

kc_status Reactor::read_ctrl_snapshot() {
    kc_status st =
        cfg_.ops->read(cfg_.ops_ctx, 0, cfg_.ctrl_scratch, KC_CTRL_SIZE);
    if (st != KC_OK) {
        return KC_ERR_IO;
    }
    const kc_ctrl* ctrl = cfg_.ctrl_scratch;
    if (ctrl->magic != KC_CTRL_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (ctrl->abi_major != KC_ABI_MAJOR || ctrl->header_size != KC_CTRL_SIZE) {
        return KC_ERR_VERSION;
    }
    /* The region is user-owned: geometry and identity must still match what
     * the driver negotiated, otherwise somebody is playing games. */
    if (ctrl->req_off != req_off_ || ctrl->req_size != req_size_ ||
        ctrl->rsp_off != rsp_off_ || ctrl->rsp_size != rsp_size_) {
        return KC_ERR_IO;
    }
    if (ctrl->attach_id != attach_id_ || ctrl->peer_pid != peer_pid_) {
        return KC_ERR_AUTH;
    }
    if (ctrl->cipher != cipher_) {
        return KC_ERR_IO;
    }
    if (ctrl->state != state_) {
        return KC_ERR_STATE;
    }
    return KC_OK;
}

void Reactor::refresh_handshake_rx_prefix() {
    uint8_t prefix[KC_NONCE_PREFIX_SIZE];
    mem_zero(prefix, sizeof(prefix));
    kc_status st = cfg_.ops->read(cfg_.ops_ctx, ctrl_off_rq_prefix(), prefix,
                                  KC_NONCE_PREFIX_SIZE);
    if (st != KC_OK || is_all_zero(prefix, sizeof(prefix))) {
        mem_zero(prefix, sizeof(prefix));
        fail_session(KC_ERR_AUTH);
        return;
    }
    mem_copy(frames_.rx_prefix, prefix, KC_NONCE_PREFIX_SIZE);
    mem_zero(prefix, sizeof(prefix));
}

void Reactor::check_watchdog(uint64_t now_ns) {
    KC_DEBUG_TRACE("watchdog check state=%d", static_cast<int>(state_));
    if (state_ == KC_STATE_READY) {
        if (now_ns > created_ns_ &&
            now_ns - created_ns_ >
                static_cast<uint64_t>(handshake_ms_) * kNsPerMs) {
            fail_session(KC_ERR_TIMEOUT);
        }
        return;
    }
    if (state_ != KC_STATE_ACTIVE) {
        return;
    }
    uint64_t hb = 0;
    cfg_.ops->read(cfg_.ops_ctx, offsetof(kc_ctrl, user_heartbeat_ns), &hb,
                   sizeof(hb));
    if (hb > last_user_hb_ns_) {
        last_user_hb_ns_ = hb;
    }
    if (now_ns > last_user_hb_ns_ &&
        now_ns - last_user_hb_ns_ >
            static_cast<uint64_t>(watchdog_ms_) * kNsPerMs) {
        mark_peer_gone(KC_STATE_DEAD);
    }
}

void Reactor::tick() {
    if (state_ == KC_STATE_FAILED || state_ == KC_STATE_DEAD ||
        state_ == KC_STATE_STOPPED) {
        return;
    }
    const uint64_t now = cfg_.now_ns(cfg_.now_ctx);
    if (now > last_kernel_hb_ns_ &&
        now - last_kernel_hb_ns_ >= KC_HEARTBEAT_INTERVAL_MS * kNsPerMs) {
        debug_log("reactor: before lock");
        if (cfg_.lock != nullptr) {
            cfg_.lock(cfg_.lock_ctx);
            debug_log("reactor: lock ok");
        }
        write_ctrl64(ctrl_off_hb(), now);
        if (cfg_.unlock != nullptr) {
            cfg_.unlock(cfg_.lock_ctx);
        }
        last_kernel_hb_ns_ = now;
    }
    check_watchdog(now);
}

int Reactor::poll(int max_records) {
    if (state_ == KC_STATE_FAILED || state_ == KC_STATE_DEAD ||
        state_ == KC_STATE_STOPPED || max_records <= 0) {
        return 0;
    }
    int handled = 0;
    debug_log("reactor: poll enter");
    for (int i = 0; i < max_records; ++i) {
        debug_log("reactor: before lock");
        if (cfg_.lock != nullptr) {
            cfg_.lock(cfg_.lock_ctx);
            debug_log("reactor: lock ok");
        }
        debug_log("reactor: ctrl read begin");
        kc_status st = read_ctrl_snapshot();
        debug_log("reactor: ctrl read done");
        if (st != KC_OK) {
            if (cfg_.unlock != nullptr) {
                cfg_.unlock(cfg_.lock_ctx);
            }
            fail_session(st);
            break;
        }
        uint32_t record_len = 0;
        debug_log("reactor: ring pop begin");
        st = ring_pop(&req_, cfg_.record_buf, cfg_.record_buf_cap, &record_len);
        debug_log("reactor: ring pop done");
        if (cfg_.unlock != nullptr) {
            cfg_.unlock(cfg_.lock_ctx);
        }
        if (st == KC_ERR_NOT_FOUND) {
            tick();
            break;
        }
        if (st != KC_OK) {
            fail_session(map_session_error(st));
            break;
        }
        handle_record(record_len);
        ++handled;
        if (state_ == KC_STATE_FAILED || state_ == KC_STATE_DEAD ||
            state_ == KC_STATE_STOPPED) {
            break;
        }
    }
    if (handled == 0) {
        tick();
    }
    return handled;
}

void Reactor::send_reply_record(const kc_msg_header& request, uint16_t opcode,
                                kc_status status, const void* payload,
                                uint32_t len) {
    if (state_ != KC_STATE_ACTIVE && state_ != KC_STATE_READY) {
        return;
    }
    /* Sequence reservation AND the ring push must happen under the same lock:
     * otherwise two producers (worker replies and kc_kernel_emit) can publish
     * records out of seq order, and the consumer's replay check would drop a
     * perfectly valid reply. */
    for (uint32_t attempt = 0; attempt < 1000; ++attempt) {
        debug_log("reactor: before lock");
        if (cfg_.lock != nullptr) {
            cfg_.lock(cfg_.lock_ctx);
            debug_log("reactor: lock ok");
        }
        const uint64_t seq = tx_seq_next_++;
        uint32_t record_len = 0;
        kc_status st =
            frame_seal(&frames_, opcode, static_cast<uint32_t>(status), seq,
                       request.request_id, payload, len, cfg_.reply_buf,
                       cfg_.reply_buf_cap, &record_len);
        if (st == KC_OK) {
            st = ring_push(&rsp_, cfg_.reply_buf, record_len);
        }
        if (cfg_.unlock != nullptr) {
            cfg_.unlock(cfg_.lock_ctx);
        }
        if (st == KC_OK) {
            return;
        }
        if (st != KC_ERR_BUSY) {
            fail_session(map_session_error(st));
            return;
        }
        if (cfg_.delay_ms != nullptr) {
            cfg_.delay_ms(cfg_.delay_ctx, 1);
        } else {
            break;
        }
    }
    /* Reply dropped: the sequence was already consumed, never reuse it. */
    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    write_ctrl64(offsetof(kc_ctrl, last_error_seq), tx_seq_next_ - 1);
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
}

void Reactor::send_reply(const kc_msg_header& request, kc_status status,
                         const void* payload, uint32_t len) {
    send_reply_record(request, KC_OP_REPLY, status, payload, len);
}

void Reactor::handle_record(uint32_t record_len) {
    if (state_ == KC_STATE_READY && hello_seen_ == false) {
        refresh_handshake_rx_prefix();
        if (state_ != KC_STATE_READY) {
            return;
        }
    }
    kc_msg_header header;
    mem_zero(&header, sizeof(header));
    uint32_t plain_len = 0;
    kc_status st = frame_open(&frames_, cfg_.record_buf, record_len, &header,
                              cfg_.plain_buf, cfg_.plain_buf_cap, &plain_len);
    if (st != KC_OK) {
        fail_session(map_session_error(st));
        return;
    }
    if (header.seq == 0) {
        fail_session(KC_ERR_AUTH);
        return;
    }
    if (header.seq <= rx_seq_last_) {
        /* replay or reordering: never accept */
        fail_session(KC_ERR_AUTH);
        return;
    }
    rx_seq_last_ = header.seq;

    switch (header.opcode) {
        case KC_OP_HELLO:
            handle_hello(header, plain_len);
            break;
        case KC_OP_CALL:
            handle_call(header, plain_len);
            break;
        case KC_OP_PING:
            if (state_ == KC_STATE_ACTIVE) {
                send_reply(header, KC_OK, nullptr, 0);
            } else {
                send_reply(header, KC_ERR_STATE, nullptr, 0);
            }
            break;
        case KC_OP_BYE:
            mark_peer_gone(KC_STATE_STOPPED);
            break;
        default:
            if (state_ == KC_STATE_ACTIVE) {
                send_reply(header, KC_ERR_NOT_FOUND, nullptr, 0);
            } else {
                send_reply(header, KC_ERR_STATE, nullptr, 0);
            }
            break;
    }
}

void Reactor::handle_hello(const kc_msg_header& header, uint32_t plain_len) {
    if (state_ != KC_STATE_READY || hello_seen_) {
        send_reply(header, KC_ERR_STATE, nullptr, 0);
        return;
    }
    if (plain_len != sizeof(kc_hello_payload)) {
        fail_session(KC_ERR_PARAM);
        return;
    }
    kc_hello_payload hello;
    mem_copy(&hello, cfg_.plain_buf, sizeof(hello));
    if (hello.client_magic != KC_CLIENT_MAGIC ||
        hello.attach_id != attach_id_ || hello.pid != peer_pid_) {
        mem_zero(&hello, sizeof(hello));
        fail_session(KC_ERR_AUTH);
        return;
    }
    mem_zero(&hello, sizeof(hello));

    if (cfg_.lock != nullptr) {
        cfg_.lock(cfg_.lock_ctx);
    }
    state_ = KC_STATE_ACTIVE;
    write_ctrl32(ctrl_off_state(), KC_STATE_ACTIVE);
    if (cfg_.unlock != nullptr) {
        cfg_.unlock(cfg_.lock_ctx);
    }
    hello_seen_ = true;
    last_user_hb_ns_ = cfg_.now_ns(cfg_.now_ctx);

    kc_hello_ack_payload ack;
    mem_zero(&ack, sizeof(ack));
    ack.server_magic = KC_SERVER_MAGIC;
    ack.pid = peer_pid_;
    ack.attach_id = attach_id_;
    ack.flags =
        (cfg_.flags & KC_KFLAG_EVENTS) != 0 ? KC_CTRL_FLAG_EVENTS_ENABLED : 0;
    send_reply_record(header, KC_OP_HELLO_ACK, KC_OK, &ack, sizeof(ack));
    mem_zero(&ack, sizeof(ack));
}

void Reactor::handle_call(const kc_msg_header& header, uint32_t plain_len) {
    if (state_ != KC_STATE_ACTIVE) {
        send_reply(header, KC_ERR_STATE, nullptr, 0);
        return;
    }
    if (plain_len < KC_CALL_PREFIX_SIZE) {
        fail_session(KC_ERR_PARAM);
        return;
    }
    const uint16_t op = static_cast<uint16_t>(
        static_cast<uint16_t>(cfg_.plain_buf[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(cfg_.plain_buf[1]) << 8));
    const uint8_t* in = cfg_.plain_buf + KC_CALL_PREFIX_SIZE;
    const uint32_t in_len = plain_len - KC_CALL_PREFIX_SIZE;
    if (in_len > max_payload_) {
        send_reply(header, KC_ERR_PARAM, nullptr, 0);
        return;
    }
    if (op < KC_OP_APP_MIN) {
        send_reply(header, KC_ERR_NOT_FOUND, nullptr, 0);
        return;
    }
    const ReactorHandler* handler = nullptr;
    const uint32_t count = cfg_.handler_count;
    for (uint32_t i = 0; i < count; ++i) {
        if (cfg_.handlers[i].op == op) {
            handler = &cfg_.handlers[i];
            break;
        }
    }
    if (handler == nullptr || handler->fn == nullptr) {
        send_reply(header, KC_ERR_NOT_FOUND, nullptr, 0);
        return;
    }
    uint32_t out_cap = max_payload_;
    uint32_t out_len = 0;
    kc_status status =
        handler->fn(handler->ctx, op, in_len != 0 ? in : nullptr, in_len,
                    out_cap != 0 ? cfg_.out_buf : nullptr, &out_cap, &out_len);
    if (out_len > out_cap || out_len > cfg_.out_buf_cap) {
        status = KC_ERR_INTERNAL;
        out_len = 0;
    }
    if (status == KC_OK) {
        send_reply(header, KC_OK, cfg_.out_buf, out_len);
    } else {
        send_reply(header, status, nullptr, 0);
    }
}

void Reactor::handle_bye() {
    mark_peer_gone(KC_STATE_STOPPED);
}

void Reactor::force_fail(kc_status error) {
    fail_session(error);
}

void Reactor::set_peer_gone_callback(void (*fn)(void*), void* ctx) {
    cfg_.on_peer_gone = fn;
    cfg_.ctx = ctx;
}

void Reactor::set_handler_count(uint32_t count) {
    if (count > KC_MAX_HANDLERS) {
        count = KC_MAX_HANDLERS;
    }
    cfg_.handler_count = count;
}

kc_status Reactor::emit(uint16_t op, const void* data, uint32_t len) {
    if (state_ != KC_STATE_ACTIVE) {
        return KC_ERR_STATE;
    }
    if (op < KC_OP_APP_MIN) {
        return KC_ERR_PARAM;
    }
    if (len > max_payload_ - KC_EVENT_PREFIX_SIZE) {
        return KC_ERR_PARAM;
    }
    if (len != 0 && data == nullptr) {
        return KC_ERR_PARAM;
    }
    /* plaintext = u16 op || data; seq reservation + seal + push are one
     * critical section so concurrent producers cannot publish out of order. */
    uint8_t* plain = cfg_.event_buf;
    put_le32(plain, op);
    if (len != 0) {
        mem_copy(plain + KC_EVENT_PREFIX_SIZE, data, len);
    }
    for (uint32_t attempt = 0; attempt < 1000; ++attempt) {
        debug_log("reactor: before lock");
        if (cfg_.lock != nullptr) {
            cfg_.lock(cfg_.lock_ctx);
            debug_log("reactor: lock ok");
        }
        const uint64_t seq = tx_seq_next_++;
        uint32_t record_len = 0;
        kc_status st = frame_seal(
            &frames_, KC_OP_EVENT, 0, seq, 0, plain, len + KC_EVENT_PREFIX_SIZE,
            cfg_.event_record_buf, cfg_.event_record_buf_cap, &record_len);
        if (st == KC_OK) {
            st = ring_push(&rsp_, cfg_.event_record_buf, record_len);
        }
        if (cfg_.unlock != nullptr) {
            cfg_.unlock(cfg_.lock_ctx);
        }
        if (st == KC_OK) {
            return KC_OK;
        }
        if (st != KC_ERR_BUSY) {
            return map_session_error(st);
        }
        if (cfg_.delay_ms != nullptr) {
            cfg_.delay_ms(cfg_.delay_ctx, 1);
        } else {
            break;
        }
    }
    return KC_ERR_BUSY;
}

} /* namespace kc */
