/*
 * blook-kchannel - authoritative kernel<->user IPC ABI (user side).
 *
 * This header is the single source of truth for the blook-kchannel wire
 * format and public user-mode API. It implements
 * blook-kernel-project/docs/contracts/kchannel-abi-v0.md (ABI 1.0).
 *
 * Design in one paragraph:
 *   The loader allocates an anonymous (unnamed) pagefile-backed section, maps
 *   it read/write, fills a kc_bootstrap descriptor, and hands it to a
 *   manual-mapped kernel driver through the map entry point. The driver turns
 *   that section into a system VA (MAPPED) or keeps the user VA and copies
 *   through it (COPY), then both sides talk over two single-producer /
 *   single-consumer byte rings. Every record carries a kc_msg_header that is
 *   HMAC-SHA256 authenticated (tag truncated to 16 bytes) and whose payload
 *   is encrypted with ChaCha20 (default) or AES-128-CTR. Each direction has
 *   its own nonce prefix and its own strictly monotonic sequence space.
 *
 * Hard invariants (do not change without bumping KC_ABI_MINOR and telling
 * every downstream consumer):
 *   - magic values, version, control-page field offsets,
 *   - kc_record / kc_msg_header layout and authentication coverage,
 *   - status values and API names/semantics,
 *   - one peer per kernel instance.
 *
 * Only authorized security research / testing is supported.
 */
#ifndef BLOOK_KCHANNEL_H
#define BLOOK_KCHANNEL_H

/*
 * Fixed width types.
 *
 * The WDK kernel include path intentionally has no <stdint.h>, so for kernel
 * builds this header defines the standard names itself (guarded so a future
 * WDK that does provide them keeps working). User builds simply use the CRT.
 */
#if defined(_KERNEL_MODE)
#ifndef KC_KERNEL_STDINT_DEFINED
#define KC_KERNEL_STDINT_DEFINED 1
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef signed __int8 int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;
#endif
#else
#include <stdint.h>
#endif
#include <stddef.h>

#define KC_ABI_MAJOR 1u
#define KC_ABI_MINOR 0u
#define KC_ABI_VERSION_STRING "1.0.0"

/* Bootstrap magic: 'KCB1' little endian. */
#define KC_BOOTSTRAP_MAGIC 0x3142434Bu
/* Control page magic: 'KCHN'. */
#define KC_CTRL_MAGIC 0x4E48434Bu
/* Ring record magic: 'KCR1'. */
#define KC_RECORD_MAGIC 0x3152434Bu
/* Message header magic: 'KCM1'. */
#define KC_MSG_MAGIC 0x314D434Bu
/* HELLO payload client magic: 'KCC1'. */
#define KC_CLIENT_MAGIC 0x3143434Bu
/* HELLO_ACK payload server magic: 'KCS1'. */
#define KC_SERVER_MAGIC 0x3153434Bu

#define KC_CTRL_SIZE 0x1000u
/* Contract v0 annotates kc_bootstrap as "0x80 bytes", but its own field list
 * sums to 0x90 (0x70 after salt + reserved[32]). All field offsets match the
 * contract; only that arithmetic annotation is wrong, so the header keeps the
 * contract fields and uses the real size. Reported to the Lead as an erratum.
 */
#define KC_BOOTSTRAP_SIZE 0x90u
#define KC_RECORD_HEADER_SIZE 0x10u
#define KC_MSG_HEADER_SIZE 0x40u
/* HMAC-SHA256 covers header[0, KC_MSG_AAD_SIZE) || ciphertext. */
#define KC_MSG_AAD_SIZE 0x30u
#define KC_TAG_SIZE 16u
#define KC_KEY_SIZE 32u
#define KC_SALT_SIZE 32u
#define KC_NONCE_PREFIX_SIZE 8u

#define KC_DEFAULT_REGION_SIZE 0x10000u
#define KC_MIN_REGION_SIZE 0x4000u
#define KC_MAX_REGION_SIZE 0x100000u
#define KC_REGION_ALIGN 0x1000u

/* Payload ceiling independent of the ring: ring must still hold the record. */
#define KC_MAX_PAYLOAD (64u * 1024u - 64u)
/* One publish slot (8 bytes) is kept free so head==tail is unambiguously
 * empty. A whole record therefore never exceeds ring_size - 16. */
#define KC_RING_RESERVE 8u
#define KC_RING_ALIGN 8u

#define KC_DEFAULT_TIMEOUT_MS 5000u
#define KC_HEARTBEAT_INTERVAL_MS 500u
#define KC_DEFAULT_WATCHDOG_MS 5000u
#define KC_DEFAULT_POLL_SPIN_US 50u
#define KC_DEFAULT_POLL_IDLE_US 1000u
#define KC_DEFAULT_POLL_IDLE_MAX_US 50000u
#define KC_MAX_HANDLERS 64u

/* ChaCha20 as specified below uses a 96-bit nonce; the derived nonce is
 * prefix[8] || (uint32)seq, so a single session may not send more than
 * 2^32 records per direction. kc_call() fails with KC_ERR_STATE beyond that
 * (AES-128-CTR, which consumes the full 128-bit nonce, has no such limit). */
#define KC_CHACHA20_MAX_SEQ 0xFFFFFFFFull

#if defined(__cplusplus)
#define KC_STATIC_ASSERT(cond, msg) static_assert((cond), msg)
#else
#define KC_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#pragma pack(push, 8)

/* ------------------------------------------------------------------ */
/* Bootstrap descriptor (contract section 2)                          */
/* ------------------------------------------------------------------ */

/*
 * Filled by the loader, handed to the manual-map entry point. The structure
 * travels out of band: it is never written into the shared region.
 *
 * kc_attach() fills most fields; kc_get_bootstrap() hands the bytes to the
 * loader; kc_attach_finish() completes the handshake afterwards.
 */
typedef struct kc_bootstrap {
    uint32_t magic;     /* KC_BOOTSTRAP_MAGIC */
    uint16_t abi_major; /* KC_ABI_MAJOR */
    uint16_t abi_minor; /* KC_ABI_MINOR */
    uint32_t struct_size;
    uint32_t mode;        /* kc_mode */
    uint32_t cipher;      /* kc_cipher */
    uint32_t peer_pid;    /* expected client pid, 0 => current process */
    uint64_t attach_id;   /* random 64 bit id, never 0 */
    uint64_t shared_va;   /* client VA of the region, page aligned */
    uint64_t shared_size; /* page aligned, [0x4000, 0x100000] */
    uint8_t session_key[KC_KEY_SIZE]; /* never written to the region */
    uint8_t salt[KC_SALT_SIZE];       /* copied into ctrl.salt */
    uint8_t reserved[32];
} kc_bootstrap;

/* Registry record written into a ring (contract section 3). */
typedef struct kc_record {
    uint32_t length; /* total record bytes, multiple of 8, >= 0x50 */
    uint32_t magic;  /* KC_RECORD_MAGIC */
    uint64_t seq;    /* per direction monotonic, matches kc_msg_header.seq */
    /* uint8_t data[];  kc_msg_header + ciphertext */
} kc_record;

/* Wire frame (contract section 5). AAD = bytes [0, KC_MSG_AAD_SIZE). */
typedef struct kc_msg_header {
    uint32_t magic;           /* KC_MSG_MAGIC */
    uint16_t version;         /* KC_ABI_MAJOR */
    uint16_t opcode;          /* kc_opcode */
    uint32_t payload_len;     /* ciphertext length */
    uint32_t status;          /* kc_status, meaningful for REPLY */
    uint64_t seq;             /* equals the enclosing kc_record.seq */
    uint64_t request_id;      /* CALL/REPLY pairing, echoed by the kernel */
    uint64_t nonce_suffix;    /* reserved for future nonce schemes; must be 0 */
    uint32_t reserved0;       /* must be 0 */
    uint32_t reserved1;       /* must be 0 */
    uint8_t tag[KC_TAG_SIZE]; /* HMAC-SHA256(session_key, AAD||ciphertext) */
} kc_msg_header;

/* Handshake payloads (contract section 6); both are AEAD protected. */
typedef struct kc_hello_payload {
    uint32_t client_magic; /* KC_CLIENT_MAGIC */
    uint32_t pid;
    uint64_t attach_id;
    uint32_t flags;
    uint32_t reserved;
} kc_hello_payload;

typedef struct kc_hello_ack_payload {
    uint32_t server_magic; /* KC_SERVER_MAGIC */
    uint32_t pid;
    uint64_t attach_id;
    uint32_t flags;
    uint32_t reserved;
} kc_hello_ack_payload;

/* ------------------------------------------------------------------ */
/* Control page (contract section 4)                                  */
/* ------------------------------------------------------------------ */

/*
 * First 0x100 bytes of the shared region. The kernel owns everything except
 * req_head / req_seq_next / rsp_tail / rsp_seq_acked / user_heartbeat_ns /
 * nonce_prefix_rq, which are user-writable by contract. Everything is
 * validated by both sides; neither side trusts the other's contents.
 */
typedef struct kc_ctrl {
    uint32_t magic;               /* 0x000 */
    uint16_t abi_major;           /* 0x004 */
    uint16_t abi_minor;           /* 0x006 */
    uint32_t header_size;         /* 0x008, KC_CTRL_SIZE */
    uint32_t state;               /* 0x00C, kc_state */
    uint32_t flags;               /* 0x010, KC_CTRL_FLAG_* */
    uint32_t error;               /* 0x014, kc_status when state == FAILED */
    uint32_t peer_pid;            /* 0x018 */
    uint32_t cipher;              /* 0x01C, kc_cipher */
    uint64_t req_off;             /* 0x020 */
    uint64_t req_size;            /* 0x028 */
    uint64_t rsp_off;             /* 0x030 */
    uint64_t rsp_size;            /* 0x038 */
    uint64_t req_seq_next;        /* 0x040 user writes */
    uint64_t rsp_seq_next;        /* 0x048 kernel writes */
    uint64_t req_seq_acked;       /* 0x050 kernel writes */
    uint64_t rsp_seq_acked;       /* 0x058 user writes */
    uint64_t req_head;            /* 0x060 user writes */
    uint64_t req_tail;            /* 0x068 kernel writes */
    uint64_t rsp_head;            /* 0x070 kernel writes */
    uint64_t rsp_tail;            /* 0x078 user writes */
    uint64_t user_heartbeat_ns;   /* 0x080 */
    uint64_t kernel_heartbeat_ns; /* 0x088 */
    uint64_t attach_id;           /* 0x090 */
    uint64_t last_error_seq;      /* 0x098 */
    uint8_t nonce_prefix_rq[KC_NONCE_PREFIX_SIZE]; /* 0x0A0 */
    uint8_t nonce_prefix_rs[KC_NONCE_PREFIX_SIZE]; /* 0x0A8 */
    uint8_t salt[KC_SALT_SIZE];                    /* 0x0B0 */
    uint8_t session_tag[32];                       /* 0x0D0 */
    uint8_t peer_token[16];                        /* 0x0F0 */
    uint8_t reserved[KC_CTRL_SIZE - 0x100];        /* 0x100..0xFFF */
} kc_ctrl;

#pragma pack(pop)

KC_STATIC_ASSERT(sizeof(kc_bootstrap) == KC_BOOTSTRAP_SIZE,
                 "kc_bootstrap must stay 0x90 bytes");
KC_STATIC_ASSERT(sizeof(kc_record) == KC_RECORD_HEADER_SIZE,
                 "kc_record header must stay 16 bytes");
KC_STATIC_ASSERT(sizeof(kc_msg_header) == KC_MSG_HEADER_SIZE,
                 "kc_msg_header must stay 0x40 bytes");
KC_STATIC_ASSERT(sizeof(kc_ctrl) == KC_CTRL_SIZE,
                 "kc_ctrl must fill exactly one page");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, mode) == 0x0C, "bootstrap.mode offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, cipher) == 0x10,
                 "bootstrap.cipher offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, peer_pid) == 0x14,
                 "bootstrap.peer_pid offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, attach_id) == 0x18,
                 "bootstrap.attach_id offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, shared_va) == 0x20,
                 "bootstrap.shared_va offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, shared_size) == 0x28,
                 "bootstrap.shared_size offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, session_key) == 0x30,
                 "bootstrap.session_key offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, salt) == 0x50, "bootstrap.salt offset");
KC_STATIC_ASSERT(offsetof(kc_bootstrap, reserved) == 0x70,
                 "bootstrap.reserved offset");
KC_STATIC_ASSERT(offsetof(kc_msg_header, tag) == KC_MSG_AAD_SIZE,
                 "msg tag offset defines the authenticated byte range");
KC_STATIC_ASSERT(offsetof(kc_ctrl, magic) == 0x000, "ctrl.magic offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, abi_major) == 0x004, "ctrl.abi_major");
KC_STATIC_ASSERT(offsetof(kc_ctrl, abi_minor) == 0x006, "ctrl.abi_minor");
KC_STATIC_ASSERT(offsetof(kc_ctrl, header_size) == 0x008, "ctrl.header_size");
KC_STATIC_ASSERT(offsetof(kc_ctrl, state) == 0x00C, "ctrl.state");
KC_STATIC_ASSERT(offsetof(kc_ctrl, flags) == 0x010, "ctrl.flags");
KC_STATIC_ASSERT(offsetof(kc_ctrl, error) == 0x014, "ctrl.error");
KC_STATIC_ASSERT(offsetof(kc_ctrl, peer_pid) == 0x018, "ctrl.peer_pid");
KC_STATIC_ASSERT(offsetof(kc_ctrl, cipher) == 0x01C, "ctrl.cipher");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_off) == 0x20, "ctrl.req_off offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_size) == 0x28, "ctrl.req_size offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_off) == 0x30, "ctrl.rsp_off offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_size) == 0x38, "ctrl.rsp_size offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_seq_next) == 0x40,
                 "ctrl.req_seq_next offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_seq_next) == 0x48,
                 "ctrl.rsp_seq_next offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_seq_acked) == 0x50,
                 "ctrl.req_seq_acked offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_seq_acked) == 0x58,
                 "ctrl.rsp_seq_acked offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_head) == 0x60, "ctrl.req_head offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, req_tail) == 0x68, "ctrl.req_tail offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_head) == 0x70, "ctrl.rsp_head offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, rsp_tail) == 0x78, "ctrl.rsp_tail offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, user_heartbeat_ns) == 0x80,
                 "ctrl.user_heartbeat_ns offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, kernel_heartbeat_ns) == 0x88,
                 "ctrl.kernel_heartbeat_ns offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, attach_id) == 0x90, "ctrl.attach_id");
KC_STATIC_ASSERT(offsetof(kc_ctrl, last_error_seq) == 0x98,
                 "ctrl.last_error_seq");
KC_STATIC_ASSERT(offsetof(kc_ctrl, nonce_prefix_rq) == 0xA0,
                 "ctrl.nonce_prefix_rq offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, nonce_prefix_rs) == 0xA8,
                 "ctrl.nonce_prefix_rs offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, salt) == 0xB0, "ctrl.salt offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, session_tag) == 0xD0,
                 "ctrl.session_tag offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, peer_token) == 0xF0,
                 "ctrl.peer_token offset");
KC_STATIC_ASSERT(offsetof(kc_ctrl, reserved) == 0x100, "ctrl.reserved offset");
KC_STATIC_ASSERT(sizeof(((kc_ctrl*)0)->reserved) == KC_CTRL_SIZE - 0x100,
                 "ctrl.reserved size");

/* ------------------------------------------------------------------ */
/* Enumerations and small helpers                                     */
/* ------------------------------------------------------------------ */

typedef enum kc_mode {
    KC_MODE_MAPPED = 0, /* MDL + MmProbeAndLockPages + MmMapLockedPages */
    KC_MODE_COPY = 1    /* no resident mapping, copy through per message */
} kc_mode;

typedef enum kc_cipher {
    KC_CIPHER_CHACHA20 = 0, /* RFC 8439, default */
    KC_CIPHER_AES128CTR = 1 /* AES-128-CTR, tag still HMAC-SHA256 */
} kc_cipher;

typedef enum kc_state_t {
    KC_STATE_EMPTY = 0,
    KC_STATE_INIT = 1,
    KC_STATE_READY = 2,
    KC_STATE_ACTIVE = 3,
    KC_STATE_FAILED = 4,
    KC_STATE_STOPPED = 5,
    KC_STATE_DEAD = 6
} kc_state_t;

/* Wire status values (contract section 10). Also used as API return codes. */
typedef enum kc_status {
    KC_OK = 0,
    KC_ERR_PARAM = 1,
    KC_ERR_NOMEM = 2,
    KC_ERR_MAGIC = 3,
    KC_ERR_VERSION = 4,
    KC_ERR_STATE = 5,
    KC_ERR_AUTH = 6,
    KC_ERR_TIMEOUT = 7,
    KC_ERR_BUSY = 8,
    KC_ERR_IO = 9,
    KC_ERR_MAP = 10,
    KC_ERR_NOT_FOUND = 11,
    KC_ERR_ALREADY = 12,
    KC_ERR_INTERNAL = 13,
    KC_ERR_PEER_GONE = 14,
    KC_ERR_HANDLER = 15,
    KC_ERR_UNSUPPORTED = 16,
    KC_STATUS_COUNT = 17
} kc_status;

/*
 * Kernel handler signature (kernel side only, declared here so the shared
 * reactor code can be compiled for both sides).
 */
typedef kc_status (*kc_handler_fn)(void* ctx, uint16_t op, const void* in,
                                   uint32_t in_len, void* out,
                                   uint32_t* out_cap, uint32_t* out_len);
/* Built-in opcodes. Application specific opcodes are >= 0x8000. */
#define KC_OP_HELLO 0x0001u
#define KC_OP_HELLO_ACK 0x0002u
#define KC_OP_CALL 0x0003u
#define KC_OP_REPLY 0x0004u
#define KC_OP_EVENT 0x0005u
#define KC_OP_BYE 0x0006u
#define KC_OP_PING 0x0007u
#define KC_OP_PONG 0x0008u
#define KC_OP_APP_MIN 0x8000u
#define KC_OP_RESERVED_MAX 0x0008u

/*
 * Payload conventions (see docs/abi.md):
 *   HELLO     : kc_hello_payload (plaintext, AEAD protected)
 *   HELLO_ACK : kc_hello_ack_payload
 *   CALL      : uint16 app_op || application request bytes
 *   REPLY     : application reply bytes (header.status = handler status)
 *   EVENT     : uint16 app_op || application event bytes
 *   PING      : empty; answered with an empty REPLY
 *   BYE       : empty; no reply
 * The 2-byte application opcode prefix keeps kc_msg_header.opcode exactly as
 * the contract defines it (1..8 transport, >= 0x8000 application).
 */
#define KC_CALL_PREFIX_SIZE 2u
#define KC_EVENT_PREFIX_SIZE 2u

/* ctrl.flags */
#define KC_CTRL_FLAG_EVENTS_ENABLED 0x00000001u
#define KC_CTRL_FLAG_KERNEL_READY 0x00000002u
#define KC_CTRL_FLAG_PEER_GONE 0x00000004u
#define KC_CTRL_FLAG_DETACHING 0x00000008u

/* kc_kernel_config.flags */
#define KC_KFLAG_EVENTS 0x00000001u
/* Keep looping on a full response ring instead of dropping the request. */
#define KC_KFLAG_BLOCK_ON_BACKPRESSURE 0x00000002u

/* kc_attach_opts.flags */
#define KC_ATTACH_FLAG_NO_HEARTBEAT 0x00000001u
#define KC_ATTACH_FLAG_NO_EVENTS 0x00000002u
#define KC_ATTACH_FLAG_REQUIRE_CHACHA20 0x00000004u

/* region geometry helpers (contract section 3) */
#define KC_RING_SIZE_FOR(region_size) \
    ((((region_size) - KC_CTRL_SIZE) / 2u) & ~(uint64_t)(KC_REGION_ALIGN - 1))
#define KC_RSP_OFFSET_FOR(region_size) \
    (KC_CTRL_SIZE + KC_RING_SIZE_FOR(region_size))
#define KC_RECORD_TOTAL(payload_len) \
    (KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE + (uint64_t)(payload_len))

/* ------------------------------------------------------------------ */
/* User-mode API (contract section 9)                                 */
/* ------------------------------------------------------------------ */

#ifndef KCHANNEL_ABI_ONLY

typedef struct kc_client kc_client;

typedef struct kc_attach_opts {
    uint32_t region_size;  /* 0 => KC_DEFAULT_REGION_SIZE */
    uint32_t mode;         /* kc_mode, default KC_MODE_MAPPED */
    uint32_t cipher;       /* kc_cipher, default KC_CIPHER_CHACHA20 */
    uint32_t peer_pid;     /* 0 => current process */
    uint32_t flags;        /* KC_ATTACH_FLAG_* */
    const char* debug_tag; /* logging only, may be NULL */
} kc_attach_opts;

typedef struct kc_client_stats {
    uint64_t calls;
    uint64_t requests_sent;
    uint64_t replies_received;
    uint64_t events_received;
    uint64_t errors;
    uint64_t timeouts;
    uint64_t ring_full_retries;
    uint64_t last_rtt_ns;
    uint64_t max_rtt_ns;
    uint64_t min_rtt_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} kc_client_stats;

/* Optional unsolicited event callback. Runs on the heartbeat thread. */
typedef void (*kc_event_fn)(void* ctx, uint16_t op, const void* data,
                            uint32_t len);

/*
 * Creates the anonymous pagefile-backed section, maps it, generates the
 * per-attach session key / salt / attach_id and both nonce prefixes.
 * Nothing is written into the control page yet: the kernel owns the first
 * half of the handshake.
 */
KC_STATIC_ASSERT(sizeof(kc_attach_opts) == 32, "keep kc_attach_opts stable");
kc_status kc_attach(const kc_attach_opts* opts, kc_client** out);

/* Copy the bootstrap descriptor out; hand it to the manual-map loader. */
kc_status kc_get_bootstrap(kc_client* client, kc_bootstrap* out);

/*
 * Waits for the driver to publish state READY, verifies session_tag (proves
 * the kernel holds the same session key), then performs HELLO/HELLO_ACK and
 * leaves the session ACTIVE. timeout_ms == 0 uses KC_DEFAULT_TIMEOUT_MS.
 */
kc_status kc_attach_finish(kc_client* client, uint32_t timeout_ms);

/* Best effort BYE, releases every user-side resource. NULL tolerated. */
void kc_detach(kc_client* client);

/*
 * Synchronous CALL -> REPLY. Returns KC_OK and the handler status is the
 * return value: the reply status is returned as the function result, so a
 * handler failure surfaces as that handler's kc_status. ^ Only KC_ERR_*
 * values are transport failures; application handlers should use the
 * KC_ERR_* range too so the caller can tell them apart from transport.
 */
kc_status kc_call(kc_client* client, uint16_t op, const void* in,
                  uint32_t in_len, void* out, uint32_t out_cap,
                  uint32_t* out_len, uint32_t timeout_ms);

/* Round trip without payload. */
kc_status kc_ping(kc_client* client, uint32_t timeout_ms);

/* Current kc_state read from the control page. */
uint32_t kc_state(kc_client* client);

/* Human readable status ("KC_OK", "KC_ERR_AUTH", ...). Never NULL. */
const char* kc_status_str(kc_status s);

/* Last observed kc_status error value, for diagnostics. */
uint32_t kc_state_error(kc_client* client);

/* attach_id of the current session (0 if not attached). */
uint64_t kc_attach_id(kc_client* client);

/* Push the user heartbeat once (done automatically unless disabled). */
kc_status kc_tick(kc_client* client);

/* Register/replace the event callback (KC_OP_EVENT messages). */
void kc_set_event_handler(kc_client* client, kc_event_fn fn, void* ctx);

/* Zeroed statistics for the session. */
void kc_get_stats(kc_client* client, kc_client_stats* out);

#endif /* KCHANNEL_ABI_ONLY */

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* BLOOK_KCHANNEL_H */
