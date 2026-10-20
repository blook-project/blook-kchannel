/*
 * blook-kchannel user library: kc_attach / kc_get_bootstrap /
 * kc_attach_finish / kc_call / kc_ping / kc_detach.
 *
 * The loader owns the section and the region; the kernel only ever reads it
 * through its MDL mapping or through copy primitives. Everything here is
 * normal Win32 user-mode code.
 */
#include <windows.h>

#include <bcrypt.h>
#include <realtimeapiset.h>

#include <blook/kchannel.h>

#include <new>

#include "common/kc_framing.h"
#include "common/kc_internal.h"
#include "common/kc_reactor.h"
#include "common/kc_ring.h"

namespace {

constexpr uint32_t kMaxRecordExtra = KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE;

uint64_t qpc_frequency() {
    static volatile LONG64 cached = 0;
    LONG64 value = cached;
    if (value == 0) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        value = freq.QuadPart;
        InterlockedExchange64(&cached, value);
    }
    return static_cast<uint64_t>(value);
}

uint64_t now_qpc_ns() {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    const double ns_per_tick =
        1000000000.0 / static_cast<double>(qpc_frequency());
    return static_cast<uint64_t>(static_cast<double>(counter.QuadPart) *
                                 ns_per_tick);
}

/* KeQueryUnbiasedInterruptTime / QueryUnbiasedInterruptTime share the same
 * boot-relative 100 ns epoch, which is what the peer-gone watchdog compares. */
uint64_t now_heartbeat_ns() {
    ULONGLONG ticks = 0;
    QueryUnbiasedInterruptTime(&ticks);
    return static_cast<uint64_t>(ticks) * 100ull;
}

bool random_bytes(void* dst, uint32_t len) {
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(dst), len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

uint32_t current_pid() {
    return GetCurrentProcessId();
}

} /* namespace */

struct kc_client {
    HANDLE section;
    uint8_t* region;
    uint64_t region_size;
    kc_bootstrap boot;
    kc::FrameCtx frames;
    kc::DirectRegion direct;
    uint64_t req_off;
    uint64_t req_size;
    uint64_t rsp_off;
    uint64_t rsp_size;
    uint32_t max_payload;
    uint32_t mode;
    uint32_t cipher;
    uint32_t flags;
    uint32_t peer_pid;
    uint64_t tx_seq;
    uint64_t rx_last_seq;
    uint64_t next_request_id;
    uint8_t tx_prefix_storage[KC_NONCE_PREFIX_SIZE];
    CRITICAL_SECTION lock;
    bool lock_initialized;
    HANDLE hb_thread;
    HANDLE hb_stop;
    uint32_t local_state;
    uint32_t state_error;
    uint8_t* tx_record;
    uint32_t tx_record_cap;
    uint8_t* rx_record;
    uint32_t rx_record_cap;
    uint8_t* tx_plain;
    uint32_t tx_plain_cap;
    uint8_t* rx_plain;
    uint32_t rx_plain_cap;
    kc_event_fn event_fn;
    void* event_ctx;
    kc_client_stats stats;
};

namespace {

kc_ctrl* ctrl_of(kc_client* client) {
    return reinterpret_cast<kc_ctrl*>(client->region);
}

uint8_t* region_base(kc_client* client) {
    return client->region;
}

kc::RingView req_ring(kc_client* client) {
    kc::RingView view;
    view.ops = kc::direct_mem_ops();
    view.ops_ctx = &client->direct;
    view.region_size = client->region_size;
    view.ring_off = client->req_off;
    view.ring_size = client->req_size;
    view.head_off = offsetof(kc_ctrl, req_head);
    view.tail_off = offsetof(kc_ctrl, req_tail);
    return view;
}

kc::RingView rsp_ring(kc_client* client) {
    kc::RingView view;
    view.ops = kc::direct_mem_ops();
    view.ops_ctx = &client->direct;
    view.region_size = client->region_size;
    view.ring_off = client->rsp_off;
    view.ring_size = client->rsp_size;
    view.head_off = offsetof(kc_ctrl, rsp_head);
    view.tail_off = offsetof(kc_ctrl, rsp_tail);
    return view;
}

void write_heartbeat(kc_client* client) {
    if (client->region == nullptr) {
        return;
    }
    ctrl_of(client)->user_heartbeat_ns = now_heartbeat_ns();
}

void dispatch_event(kc_client* client, const kc_msg_header& header,
                    uint32_t plain_len) {
    client->stats.events_received++;
    if (client->event_fn == nullptr || plain_len < KC_EVENT_PREFIX_SIZE) {
        return;
    }
    const uint16_t op = static_cast<uint16_t>(
        static_cast<uint16_t>(client->rx_plain[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(client->rx_plain[1]) << 8));
    client->event_fn(client->event_ctx, op,
                     client->rx_plain + KC_EVENT_PREFIX_SIZE,
                     plain_len - KC_EVENT_PREFIX_SIZE);
    (void)header;
}

/* Pops one authenticated record. Returns KC_ERR_NOT_FOUND when empty. */
kc_status pop_record(kc_client* client, kc_msg_header* header,
                     uint32_t* plain_len) {
    kc::RingView ring = rsp_ring(client);
    uint32_t record_len = 0;
    kc_status st = kc::ring_pop(&ring, client->rx_record, client->rx_record_cap,
                                &record_len);
    if (st != KC_OK) {
        return st;
    }
    st = kc::frame_open(&client->frames, client->rx_record, record_len, header,
                        client->rx_plain, client->rx_plain_cap, plain_len);
    if (st != KC_OK) {
        client->state_error = static_cast<uint32_t>(st);
        return st;
    }
    if (header->seq <= client->rx_last_seq) {
        return KC_ERR_ALREADY; /* stale/replayed, caller drains on */
    }
    client->rx_last_seq = header->seq;
    return KC_OK;
}

kc_status push_announce(kc_client* client, const uint8_t* record,
                        uint32_t record_len, uint64_t deadline_ns) {
    kc::RingView ring = req_ring(client);
    for (;;) {
        kc_status st = kc::ring_push(&ring, record, record_len);
        if (st == KC_OK) {
            return KC_OK;
        }
        if (st != KC_ERR_BUSY) {
            return st;
        }
        client->stats.ring_full_retries++;
        if (now_qpc_ns() >= deadline_ns) {
            return KC_ERR_BUSY;
        }
        SwitchToThread();
    }
}

/*
 * Waits until the reply with `request_id` arrives (or the deadline hits).
 * EVENT records are dispatched to the callback, stale replies are discarded.
 */
kc_status wait_for(kc_client* client, uint64_t request_id, uint32_t timeout_ms,
                   kc_msg_header* out_header, uint8_t* payload,
                   uint32_t payload_cap, uint32_t* out_len) {
    const uint64_t deadline =
        now_qpc_ns() + static_cast<uint64_t>(timeout_ms) * 1000000ull;
    uint32_t idle = 0;
    for (;;) {
        for (;;) {
            kc_msg_header header;
            uint32_t plain_len = 0;
            kc_status st = pop_record(client, &header, &plain_len);
            if (st == KC_ERR_NOT_FOUND) {
                break;
            }
            if (st == KC_ERR_ALREADY) {
                continue;
            }
            if (st != KC_OK) {
                return st;
            }
            if (header.opcode == KC_OP_EVENT) {
                dispatch_event(client, header, plain_len);
                continue;
            }
            if (header.request_id != request_id) {
                continue; /* stale reply from a timed-out call */
            }
            if (out_header != nullptr) {
                *out_header = header;
            }
            if (out_len != nullptr) {
                *out_len = plain_len;
            }
            if (payload != nullptr && payload_cap != 0 && plain_len != 0) {
                if (plain_len > payload_cap) {
                    return KC_ERR_PARAM;
                }
                kc::mem_copy(payload, client->rx_plain, plain_len);
            }
            client->stats.rx_bytes += plain_len;
            return KC_OK;
        }

        const kc_ctrl* ctrl = ctrl_of(client);
        if (ctrl->state == KC_STATE_FAILED) {
            client->local_state = KC_STATE_FAILED;
            client->state_error = ctrl->error;
            return static_cast<kc_status>(ctrl->error);
        }
        if (ctrl->state == KC_STATE_DEAD || ctrl->state == KC_STATE_STOPPED) {
            client->local_state = ctrl->state;
            return KC_ERR_PEER_GONE;
        }
        if (now_qpc_ns() >= deadline) {
            client->stats.timeouts++;
            return KC_ERR_TIMEOUT;
        }

        /* Backoff: busy-pause first (the kernel worker is usually spinning
         * right after a request), then yield, then sleep. */
        if (idle < 100) {
            YieldProcessor();
        } else if (idle < 300) {
            SwitchToThread();
        } else if (idle < 600) {
            Sleep(0);
        } else {
            Sleep(1);
        }
        ++idle;
    }
}

/* Builds+pushes a record, then waits for the reply with the same id. */
kc_status call_locked(kc_client* client, uint16_t op, const void* in,
                      uint32_t in_len, uint8_t* out, uint32_t out_cap,
                      uint32_t* out_len, uint32_t timeout_ms) {
    if (client->local_state != KC_STATE_ACTIVE) {
        return KC_ERR_STATE;
    }
    if (in_len > client->max_payload) {
        return KC_ERR_PARAM;
    }
    const uint64_t request_id = client->next_request_id++;
    const uint64_t seq = client->tx_seq;

    uint8_t* plain = client->tx_plain;
    kc::put_le32(plain, op);
    if (in_len != 0) {
        kc::mem_copy(plain + KC_CALL_PREFIX_SIZE, in, in_len);
    }
    uint32_t record_len = 0;
    kc_status st =
        kc::frame_seal(&client->frames, KC_OP_CALL, 0, seq, request_id, plain,
                       in_len + KC_CALL_PREFIX_SIZE, client->tx_record,
                       client->tx_record_cap, &record_len);
    if (st != KC_OK) {
        return st;
    }
    const uint64_t deadline =
        now_qpc_ns() + static_cast<uint64_t>(timeout_ms) * 1000000ull;
    st = push_announce(client, client->tx_record, record_len, deadline);
    if (st != KC_OK) {
        return st;
    }
    client->tx_seq = seq + 1;
    write_heartbeat(client);
    ctrl_of(client)->req_seq_next = seq + 1;
    client->stats.requests_sent++;
    client->stats.tx_bytes += in_len;

    kc_msg_header header;
    uint32_t reply_len = 0;
    const uint64_t start = now_qpc_ns();
    st = wait_for(client, request_id, timeout_ms, &header, out, out_cap,
                  &reply_len);
    const uint64_t rtt = now_qpc_ns() - start;
    if (st != KC_OK) {
        client->stats.errors++;
        return st;
    }
    client->stats.replies_received++;
    client->stats.calls++;
    client->stats.last_rtt_ns = rtt;
    if (rtt > client->stats.max_rtt_ns) {
        client->stats.max_rtt_ns = rtt;
    }
    if (client->stats.min_rtt_ns == 0 || rtt < client->stats.min_rtt_ns) {
        client->stats.min_rtt_ns = rtt;
    }
    if (out_len != nullptr) {
        *out_len = reply_len;
    }
    return static_cast<kc_status>(header.status);
}

DWORD WINAPI heartbeat_thread(LPVOID param) {
    kc_client* client = static_cast<kc_client*>(param);
    for (;;) {
        if (WaitForSingleObject(client->hb_stop, KC_HEARTBEAT_INTERVAL_MS) !=
            WAIT_TIMEOUT) {
            break;
        }
        write_heartbeat(client);
        if (TryEnterCriticalSection(&client->lock) != 0) {
            for (;;) {
                kc_msg_header header;
                uint32_t plain_len = 0;
                kc_status st = pop_record(client, &header, &plain_len);
                if (st == KC_ERR_NOT_FOUND) {
                    break;
                }
                if (st == KC_ERR_ALREADY) {
                    continue;
                }
                if (st != KC_OK) {
                    break;
                }
                if (header.opcode == KC_OP_EVENT) {
                    dispatch_event(client, header, plain_len);
                }
            }
            LeaveCriticalSection(&client->lock);
        }
    }
    return 0;
}

kc_status validate_bootstrap(const kc_bootstrap& boot) {
    if (boot.magic != KC_BOOTSTRAP_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (boot.abi_major != KC_ABI_MAJOR ||
        boot.struct_size != KC_BOOTSTRAP_SIZE) {
        return KC_ERR_VERSION;
    }
    if (boot.mode != KC_MODE_MAPPED && boot.mode != KC_MODE_COPY) {
        return KC_ERR_PARAM;
    }
    if (boot.cipher != KC_CIPHER_CHACHA20 &&
        boot.cipher != KC_CIPHER_AES128CTR) {
        return KC_ERR_PARAM;
    }
    if (boot.attach_id == 0) {
        return KC_ERR_PARAM;
    }
    if (boot.shared_size < KC_MIN_REGION_SIZE ||
        boot.shared_size > KC_MAX_REGION_SIZE ||
        (boot.shared_size % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    if ((boot.shared_va % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    if (kc::is_all_zero(boot.session_key, KC_KEY_SIZE)) {
        return KC_ERR_PARAM;
    }
    return KC_OK;
}

} /* namespace */

extern "C" {

kc_status kc_attach(const kc_attach_opts* opts, kc_client** out) {
    if (out == nullptr) {
        return KC_ERR_PARAM;
    }
    *out = nullptr;
    kc_attach_opts local;
    RtlZeroMemory(&local, sizeof(local));
    local.region_size = KC_DEFAULT_REGION_SIZE;
    local.mode = KC_MODE_MAPPED;
    local.cipher = KC_CIPHER_CHACHA20;
    if (opts != nullptr) {
        local = *opts;
    }
    if (local.region_size == 0) {
        local.region_size = KC_DEFAULT_REGION_SIZE;
    }
    if (local.mode != KC_MODE_MAPPED && local.mode != KC_MODE_COPY) {
        return KC_ERR_PARAM;
    }
    if (local.cipher != KC_CIPHER_CHACHA20 &&
        local.cipher != KC_CIPHER_AES128CTR) {
        return KC_ERR_PARAM;
    }
    if ((local.flags & KC_ATTACH_FLAG_REQUIRE_CHACHA20) != 0 &&
        local.cipher != KC_CIPHER_CHACHA20) {
        return KC_ERR_UNSUPPORTED;
    }
    if (local.region_size < KC_MIN_REGION_SIZE ||
        local.region_size > KC_MAX_REGION_SIZE ||
        (local.region_size % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    uint64_t req_off = 0;
    uint64_t ring_size = 0;
    if (kc::region_geometry(local.region_size, &req_off, &ring_size) != KC_OK) {
        return KC_ERR_PARAM;
    }

    kc_client* client = new (std::nothrow) kc_client();
    if (client == nullptr) {
        return KC_ERR_NOMEM;
    }
    RtlZeroMemory(client, sizeof(kc_client));
    client->local_state = KC_STATE_INIT;

    client->section =
        CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                           local.region_size, nullptr);
    if (client->section == nullptr) {
        delete client;
        return KC_ERR_NOMEM;
    }
    client->region = static_cast<uint8_t*>(MapViewOfFile(
        client->section, FILE_MAP_ALL_ACCESS, 0, 0, local.region_size));
    if (client->region == nullptr) {
        CloseHandle(client->section);
        delete client;
        return KC_ERR_MAP;
    }
    client->region_size = local.region_size;
    kc::mem_zero(client->region, static_cast<uint32_t>(local.region_size));
    kc::direct_region_init(&client->direct, client->region, local.region_size);

    client->req_off = req_off;
    client->req_size = ring_size;
    client->rsp_off = req_off + ring_size;
    client->rsp_size = ring_size;
    client->mode = local.mode;
    client->cipher = local.cipher;
    client->flags = local.flags;

    const uint64_t in_limit = ring_size - kMaxRecordExtra - KC_CALL_PREFIX_SIZE;
    const uint64_t out_limit = ring_size - kMaxRecordExtra;
    uint64_t max_payload = KC_MAX_PAYLOAD - KC_CALL_PREFIX_SIZE;
    if (in_limit < max_payload) {
        max_payload = in_limit;
    }
    if (out_limit < max_payload) {
        max_payload = out_limit;
    }
    if (max_payload < KC_CALL_PREFIX_SIZE) {
        CloseHandle(client->section);
        delete client;
        return KC_ERR_PARAM;
    }
    client->max_payload = static_cast<uint32_t>(max_payload);

    client->tx_record_cap = static_cast<uint32_t>(ring_size);
    client->rx_record_cap = static_cast<uint32_t>(ring_size);
    client->tx_plain_cap = client->max_payload + KC_CALL_PREFIX_SIZE;
    client->rx_plain_cap = client->max_payload + KC_EVENT_PREFIX_SIZE;
    client->tx_record = static_cast<uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, client->tx_record_cap));
    client->rx_record = static_cast<uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, client->rx_record_cap));
    client->tx_plain = static_cast<uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, client->tx_plain_cap));
    client->rx_plain = static_cast<uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, client->rx_plain_cap));
    if (client->tx_record == nullptr || client->rx_record == nullptr ||
        client->tx_plain == nullptr || client->rx_plain == nullptr) {
        if (client->tx_record != nullptr) {
            HeapFree(GetProcessHeap(), 0, client->tx_record);
        }
        if (client->rx_record != nullptr) {
            HeapFree(GetProcessHeap(), 0, client->rx_record);
        }
        if (client->tx_plain != nullptr) {
            HeapFree(GetProcessHeap(), 0, client->tx_plain);
        }
        if (client->rx_plain != nullptr) {
            HeapFree(GetProcessHeap(), 0, client->rx_plain);
        }
        UnmapViewOfFile(client->region);
        CloseHandle(client->section);
        delete client;
        return KC_ERR_NOMEM;
    }

    kc_bootstrap* boot = &client->boot;
    RtlZeroMemory(boot, sizeof(*boot));
    boot->magic = KC_BOOTSTRAP_MAGIC;
    boot->abi_major = static_cast<uint16_t>(KC_ABI_MAJOR);
    boot->abi_minor = static_cast<uint16_t>(KC_ABI_MINOR);
    boot->struct_size = KC_BOOTSTRAP_SIZE;
    boot->mode = local.mode;
    boot->cipher = local.cipher;
    boot->peer_pid = (local.peer_pid != 0) ? local.peer_pid : current_pid();
    boot->shared_va = reinterpret_cast<uint64_t>(client->region);
    boot->shared_size = local.region_size;
    if (random_bytes(boot->session_key, KC_KEY_SIZE) == false ||
        random_bytes(boot->salt, KC_SALT_SIZE) == false) {
        /* fall through: validate_bootstrap rejects zero keys */
    }
    for (;;) {
        uint64_t attach_id = 0;
        if (random_bytes(&attach_id, sizeof(attach_id)) == false) {
            attach_id = 0;
        }
        if (attach_id != 0) {
            boot->attach_id = attach_id;
            break;
        }
        Sleep(0);
    }
    if (validate_bootstrap(*boot) != KC_OK) {
        UnmapViewOfFile(client->region);
        CloseHandle(client->section);
        HeapFree(GetProcessHeap(), 0, client->tx_record);
        HeapFree(GetProcessHeap(), 0, client->rx_record);
        HeapFree(GetProcessHeap(), 0, client->tx_plain);
        HeapFree(GetProcessHeap(), 0, client->rx_plain);
        delete client;
        return KC_ERR_INTERNAL;
    }

    uint8_t rx_prefix[KC_NONCE_PREFIX_SIZE];
    kc::mem_zero(rx_prefix, sizeof(rx_prefix));
    uint8_t tx_prefix[KC_NONCE_PREFIX_SIZE];
    do {
        if (random_bytes(tx_prefix, sizeof(tx_prefix)) == false) {
            RtlZeroMemory(tx_prefix, sizeof(tx_prefix));
        }
    } while (kc::is_all_zero(tx_prefix, sizeof(tx_prefix)));
    kc::mem_copy(client->tx_prefix_storage, tx_prefix, sizeof(tx_prefix));
    kc::frame_ctx_init(&client->frames, boot->session_key,
                       client->tx_prefix_storage, rx_prefix, local.cipher);

    client->tx_seq = 1;
    client->rx_last_seq = 0;
    client->next_request_id = 1;
    InitializeCriticalSection(&client->lock);
    client->lock_initialized = true;
    write_heartbeat(client);

    if ((local.flags & KC_ATTACH_FLAG_NO_HEARTBEAT) == 0) {
        client->hb_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (client->hb_stop != nullptr) {
            client->hb_thread =
                CreateThread(nullptr, 0, heartbeat_thread, client, 0, nullptr);
        }
        if (client->hb_thread == nullptr) {
            if (client->hb_stop != nullptr) {
                CloseHandle(client->hb_stop);
                client->hb_stop = nullptr;
            }
            client->local_state = KC_STATE_INIT;
        }
    }

    *out = client;
    return KC_OK;
}

kc_status kc_get_bootstrap(kc_client* client, kc_bootstrap* out) {
    if (client == nullptr || out == nullptr) {
        return KC_ERR_PARAM;
    }
    *out = client->boot;
    return KC_OK;
}

kc_status kc_attach_finish(kc_client* client, uint32_t timeout_ms) {
    if (client == nullptr) {
        return KC_ERR_PARAM;
    }
    if (timeout_ms == 0) {
        timeout_ms = KC_DEFAULT_TIMEOUT_MS;
    }
    if (client->local_state == KC_STATE_ACTIVE) {
        return KC_OK;
    }
    if (client->local_state == KC_STATE_FAILED) {
        return static_cast<kc_status>(client->state_error);
    }
    const uint64_t deadline =
        now_qpc_ns() + static_cast<uint64_t>(timeout_ms) * 1000000ull;
    kc_ctrl* ctrl = ctrl_of(client);
    for (;;) {
        write_heartbeat(client);
        const uint32_t state = ctrl->state;
        if (state == KC_STATE_FAILED) {
            client->local_state = KC_STATE_FAILED;
            client->state_error = ctrl->error;
            return static_cast<kc_status>(ctrl->error);
        }
        if (state == KC_STATE_DEAD || state == KC_STATE_STOPPED) {
            client->local_state = state;
            return KC_ERR_PEER_GONE;
        }
        if (state == KC_STATE_READY || state == KC_STATE_ACTIVE) {
            break;
        }
        if (now_qpc_ns() >= deadline) {
            return KC_ERR_TIMEOUT;
        }
        Sleep(1);
    }

    /* Verify the driver half of the control page. */
    if (ctrl->magic != KC_CTRL_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (ctrl->abi_major != KC_ABI_MAJOR || ctrl->abi_minor != KC_ABI_MINOR ||
        ctrl->header_size != KC_CTRL_SIZE) {
        return KC_ERR_VERSION;
    }
    if (ctrl->req_off != client->req_off ||
        ctrl->req_size != client->req_size ||
        ctrl->rsp_off != client->rsp_off ||
        ctrl->rsp_size != client->rsp_size) {
        return KC_ERR_IO;
    }
    if (ctrl->peer_pid != client->boot.peer_pid ||
        ctrl->cipher != client->boot.cipher ||
        ctrl->attach_id != client->boot.attach_id) {
        return KC_ERR_AUTH;
    }
    if (kc::mem_equal_ct(ctrl->salt, client->boot.salt, KC_SALT_SIZE) ==
        false) {
        return KC_ERR_AUTH;
    }
    uint8_t tag[32];
    kc::session_tag_compute(client->boot.session_key, client->boot.salt,
                            client->boot.attach_id, client->boot.peer_pid, tag);
    const bool tag_ok = kc::mem_equal_ct(tag, ctrl->session_tag, 32);
    kc::mem_zero(tag, sizeof(tag));
    if (tag_ok == false) {
        /* the kernel does not hold the same session key */
        client->local_state = KC_STATE_FAILED;
        client->state_error = KC_ERR_AUTH;
        return KC_ERR_AUTH;
    }
    if (kc::is_all_zero(ctrl->nonce_prefix_rs, KC_NONCE_PREFIX_SIZE)) {
        return KC_ERR_PARAM;
    }
    kc::mem_copy(client->frames.rx_prefix, ctrl->nonce_prefix_rs,
                 KC_NONCE_PREFIX_SIZE);

    if (ctrl->state == KC_STATE_ACTIVE) {
        client->local_state = KC_STATE_ACTIVE;
        return KC_OK;
    }

    /* Publish our request nonce prefix before the first record. */
    kc::mem_copy(ctrl->nonce_prefix_rq, client->tx_prefix_storage,
                 KC_NONCE_PREFIX_SIZE);
    ctrl->req_seq_next = 1;
    write_heartbeat(client);

    EnterCriticalSection(&client->lock);
    const uint64_t request_id = client->next_request_id++;
    const uint64_t seq = client->tx_seq;
    kc_hello_payload hello;
    RtlZeroMemory(&hello, sizeof(hello));
    hello.client_magic = KC_CLIENT_MAGIC;
    hello.pid = client->boot.peer_pid;
    hello.attach_id = client->boot.attach_id;
    uint32_t record_len = 0;
    kc_status st = kc::frame_seal(
        &client->frames, KC_OP_HELLO, 0, seq, request_id, &hello, sizeof(hello),
        client->tx_record, client->tx_record_cap, &record_len);
    if (st != KC_OK) {
        LeaveCriticalSection(&client->lock);
        return st;
    }
    st = push_announce(
        client, client->tx_record, record_len,
        now_qpc_ns() + static_cast<uint64_t>(timeout_ms) * 1000000ull);
    if (st != KC_OK) {
        LeaveCriticalSection(&client->lock);
        return st;
    }
    client->tx_seq = seq + 1;
    ctrl->req_seq_next = seq + 1;

    kc_msg_header ack;
    uint32_t ack_len = 0;
    st = wait_for(client, request_id, timeout_ms, &ack, nullptr, 0, &ack_len);
    LeaveCriticalSection(&client->lock);
    if (st != KC_OK) {
        return st;
    }
    if (ack.opcode != KC_OP_HELLO_ACK ||
        ack_len != sizeof(kc_hello_ack_payload)) {
        client->local_state = KC_STATE_FAILED;
        client->state_error = KC_ERR_AUTH;
        return KC_ERR_AUTH;
    }
    kc_hello_ack_payload ack_payload;
    kc::mem_copy(&ack_payload, client->rx_plain, sizeof(ack_payload));
    const bool ack_ok = ack_payload.server_magic == KC_SERVER_MAGIC &&
                        ack_payload.attach_id == client->boot.attach_id &&
                        ack_payload.pid == client->boot.peer_pid;
    kc::mem_zero(&ack_payload, sizeof(ack_payload));
    if (ack_ok == false) {
        client->local_state = KC_STATE_FAILED;
        client->state_error = KC_ERR_AUTH;
        return KC_ERR_AUTH;
    }
    if (ctrl->state != KC_STATE_ACTIVE) {
        return KC_ERR_STATE;
    }
    client->local_state = KC_STATE_ACTIVE;
    write_heartbeat(client);
    return KC_OK;
}

void kc_detach(kc_client* client) {
    if (client == nullptr) {
        return;
    }
    if (client->local_state == KC_STATE_ACTIVE && client->region != nullptr) {
        EnterCriticalSection(&client->lock);
        const uint64_t seq = client->tx_seq;
        uint32_t record_len = 0;
        if (kc::frame_seal(&client->frames, KC_OP_BYE, 0, seq, 0, nullptr, 0,
                           client->tx_record, client->tx_record_cap,
                           &record_len) == KC_OK) {
            kc::RingView ring = req_ring(client);
            (void)kc::ring_push(&ring, client->tx_record, record_len);
            client->tx_seq = seq + 1;
        }
        kc_ctrl* ctrl = ctrl_of(client);
        ctrl->flags |= KC_CTRL_FLAG_DETACHING;
        write_heartbeat(client);
        LeaveCriticalSection(&client->lock);
        /* Give the worker a moment to see BYE and drop the MDL. */
        const ULONGLONG detach_deadline = GetTickCount64() + 200;
        while (GetTickCount64() < detach_deadline) {
            if (ctrl->state == KC_STATE_STOPPED ||
                ctrl->state == KC_STATE_DEAD) {
                break;
            }
            Sleep(1);
        }
    }
    if (client->hb_thread != nullptr) {
        SetEvent(client->hb_stop);
        WaitForSingleObject(client->hb_thread, 2000);
        CloseHandle(client->hb_thread);
        client->hb_thread = nullptr;
    }
    if (client->hb_stop != nullptr) {
        CloseHandle(client->hb_stop);
        client->hb_stop = nullptr;
    }
    if (client->lock_initialized) {
        DeleteCriticalSection(&client->lock);
        client->lock_initialized = false;
    }
    if (client->tx_record != nullptr) {
        HeapFree(GetProcessHeap(), 0, client->tx_record);
    }
    if (client->rx_record != nullptr) {
        HeapFree(GetProcessHeap(), 0, client->rx_record);
    }
    if (client->tx_plain != nullptr) {
        HeapFree(GetProcessHeap(), 0, client->tx_plain);
    }
    if (client->rx_plain != nullptr) {
        HeapFree(GetProcessHeap(), 0, client->rx_plain);
    }
    if (client->region != nullptr) {
        UnmapViewOfFile(client->region);
    }
    if (client->section != nullptr) {
        CloseHandle(client->section);
    }
    client->local_state = KC_STATE_STOPPED;
    delete client;
}

kc_status kc_call(kc_client* client, uint16_t op, const void* in,
                  uint32_t in_len, void* out, uint32_t out_cap,
                  uint32_t* out_len, uint32_t timeout_ms) {
    if (client == nullptr) {
        return KC_ERR_PARAM;
    }
    if (op < KC_OP_APP_MIN) {
        return KC_ERR_PARAM;
    }
    if (in_len != 0 && in == nullptr) {
        return KC_ERR_PARAM;
    }
    if (out_cap != 0 && out == nullptr) {
        return KC_ERR_PARAM;
    }
    if (timeout_ms == 0) {
        timeout_ms = KC_DEFAULT_TIMEOUT_MS;
    }
    EnterCriticalSection(&client->lock);
    kc_status st =
        call_locked(client, op, in, in_len, static_cast<uint8_t*>(out), out_cap,
                    out_len, timeout_ms);
    LeaveCriticalSection(&client->lock);
    return st;
}

kc_status kc_ping(kc_client* client, uint32_t timeout_ms) {
    if (client == nullptr) {
        return KC_ERR_PARAM;
    }
    if (timeout_ms == 0) {
        timeout_ms = KC_DEFAULT_TIMEOUT_MS;
    }
    EnterCriticalSection(&client->lock);
    if (client->local_state != KC_STATE_ACTIVE) {
        LeaveCriticalSection(&client->lock);
        return KC_ERR_STATE;
    }
    const uint64_t request_id = client->next_request_id++;
    const uint64_t seq = client->tx_seq;
    uint32_t record_len = 0;
    kc_status st = kc::frame_seal(&client->frames, KC_OP_PING, 0, seq,
                                  request_id, nullptr, 0, client->tx_record,
                                  client->tx_record_cap, &record_len);
    if (st != KC_OK) {
        LeaveCriticalSection(&client->lock);
        return st;
    }
    st = push_announce(
        client, client->tx_record, record_len,
        now_qpc_ns() + static_cast<uint64_t>(timeout_ms) * 1000000ull);
    if (st != KC_OK) {
        LeaveCriticalSection(&client->lock);
        return st;
    }
    client->tx_seq = seq + 1;
    write_heartbeat(client);
    ctrl_of(client)->req_seq_next = seq + 1;
    client->stats.requests_sent++;

    kc_msg_header header;
    uint32_t reply_len = 0;
    st = wait_for(client, request_id, timeout_ms, &header, nullptr, 0,
                  &reply_len);
    if (st == KC_OK) {
        client->stats.replies_received++;
        client->stats.calls++;
        st = static_cast<kc_status>(header.status);
    } else {
        client->stats.errors++;
    }
    LeaveCriticalSection(&client->lock);
    return st;
}

uint32_t kc_state(kc_client* client) {
    if (client == nullptr || client->region == nullptr) {
        return KC_STATE_EMPTY;
    }
    const uint32_t state = ctrl_of(client)->state;
    if (state == KC_STATE_FAILED) {
        client->state_error = ctrl_of(client)->error;
    }
    return state;
}

uint32_t kc_state_error(kc_client* client) {
    if (client == nullptr) {
        return KC_OK;
    }
    if (client->state_error != 0) {
        return client->state_error;
    }
    if (client->region != nullptr) {
        return ctrl_of(client)->error;
    }
    return KC_OK;
}

uint64_t kc_attach_id(kc_client* client) {
    if (client == nullptr) {
        return 0;
    }
    return client->boot.attach_id;
}

kc_status kc_tick(kc_client* client) {
    if (client == nullptr || client->region == nullptr) {
        return KC_ERR_PARAM;
    }
    write_heartbeat(client);
    return KC_OK;
}

void kc_set_event_handler(kc_client* client, kc_event_fn fn, void* ctx) {
    if (client == nullptr) {
        return;
    }
    client->event_fn = fn;
    client->event_ctx = ctx;
}

void kc_get_stats(kc_client* client, kc_client_stats* out) {
    if (client == nullptr || out == nullptr) {
        return;
    }
    *out = client->stats;
}

const char* kc_status_str(kc_status s) {
    switch (s) {
        case KC_OK:
            return "KC_OK";
        case KC_ERR_PARAM:
            return "KC_ERR_PARAM";
        case KC_ERR_NOMEM:
            return "KC_ERR_NOMEM";
        case KC_ERR_MAGIC:
            return "KC_ERR_MAGIC";
        case KC_ERR_VERSION:
            return "KC_ERR_VERSION";
        case KC_ERR_STATE:
            return "KC_ERR_STATE";
        case KC_ERR_AUTH:
            return "KC_ERR_AUTH";
        case KC_ERR_TIMEOUT:
            return "KC_ERR_TIMEOUT";
        case KC_ERR_BUSY:
            return "KC_ERR_BUSY";
        case KC_ERR_IO:
            return "KC_ERR_IO";
        case KC_ERR_MAP:
            return "KC_ERR_MAP";
        case KC_ERR_NOT_FOUND:
            return "KC_ERR_NOT_FOUND";
        case KC_ERR_ALREADY:
            return "KC_ERR_ALREADY";
        case KC_ERR_INTERNAL:
            return "KC_ERR_INTERNAL";
        case KC_ERR_PEER_GONE:
            return "KC_ERR_PEER_GONE";
        case KC_ERR_HANDLER:
            return "KC_ERR_HANDLER";
        case KC_ERR_UNSUPPORTED:
            return "KC_ERR_UNSUPPORTED";
        default:
            return "KC_ERR_UNKNOWN";
    }
}

} /* extern "C" */
