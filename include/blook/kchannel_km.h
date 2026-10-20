/*
 * blook-kchannel - kernel side API (WDK, C++17).
 *
 * Include order for kernel translation units:
 *     #include <ntddk.h>
 *     #include <blook/kchannel_km.h>
 *
 * kchannel_km.h pulls in kchannel.h in ABI-only mode (no user API), so the
 * same wire types are shared by both sides. The kernel library is written so
 * that it can be linked into a manually mapped image: it only imports
 * documented WDM/ntoskrnl entry points (Mm*, Io*, Ke*, Ex*, Ps*, Rtl*) that
 * the mapper resolves from the ntoskrnl import descriptor. It never calls
 * IoCreateDevice/IoCreateSymbolicLink, never touches the registry, never
 * registers a notify routine and never exports a symbol.
 *
 * Bootstrap delivery (contract section 2):
 *   - manual map: the loader passes a pointer to a kc_bootstrap (kernel
 *     memory copy) as the entry-point parameter;
 *   - service load (`sc create/start`, dev/debug only): the driver reads its
 *     own bootstrap blob and calls kc_kernel_create with the same structure.
 *   In both cases kc_kernel_create() is called at PASSIVE_LEVEL. When
 *   boot->peer_pid names a process other than the current one, the library
 *   temporarily attaches to it before probing/locking the shared pages, so
 *   the identical call works from DriverEntry when loaded by the SCM.
 */
#ifndef BLOOK_KCHANNEL_KM_H
#define BLOOK_KCHANNEL_KM_H

#define KCHANNEL_ABI_ONLY 1
#include <blook/kchannel.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct kc_kernel kc_kernel;

/*
 * Handler contract:
 *   - always invoked on the single PASSIVE_LEVEL worker thread, never with
 *     a lock held; may block, may call kc_kernel_emit(), may take a few ms
 *     (the kernel worker does not police handler duration);
 *   - `in` may be NULL when in_len == 0; `out` may be NULL when *out_cap == 0;
 *   - on success set *out_len <= *out_cap and return KC_OK;
 *   - for errors return a kc_status; the reply carries it and kc_call()
 *     returns it to the caller;
 *   - never touch user pointers; only the validated buffers are provided;
 *   - handler output is copied into the response ring by the worker.
 */

typedef struct kc_kernel_config {
    uint32_t max_payload;  /* 0 => min(KC_MAX_PAYLOAD, ring limit) */
    uint32_t poll_spin_us; /* default 50: busy window per poll cycle */
    uint32_t poll_idle_us; /* default 1000: first KeDelayExecutionThread */
    uint32_t watchdog_ms;  /* default 5000: user heartbeat timeout */
    uint32_t flags;        /* KC_KFLAG_* */
    void (*on_peer_gone)(void* ctx); /* optional; from the worker thread */
    void* ctx;
    /* -- appended in ABI 1.0 (must stay zero/ignored by old callers) -- */
    uint32_t poll_idle_max_us; /* default 50000: exponential backoff ceiling */
    uint32_t reserved[3];
} kc_kernel_config;

/*
 * Validates the bootstrap, maps or resolves the shared region and writes the
 * driver half of the control page (state READY, session_tag, nonce prefix).
 * Returns KC_ERR_ALREADY if a live peer is already attached to this kernel.
 */
kc_status kc_kernel_create(const kc_bootstrap* boot,
                           const kc_kernel_config* cfg, kc_kernel** out);

/* Register a handler for one opcode. Call before kc_kernel_start(); the
 * function itself is lock protected, so late registration is safe too. */
kc_status kc_kernel_register(kc_kernel* kernel, uint16_t op, kc_handler_fn fn,
                             void* ctx);

/* Creates the single worker thread (PASSIVE_LEVEL). Idempotent. */
kc_status kc_kernel_start(kc_kernel* kernel);

/* Idempotent; signals the worker and joins it (<= 100 ms). Safe from the
 * worker thread itself: it then returns after the current reply. */
void kc_kernel_stop(kc_kernel* kernel);

/* stop + unmap/unlock the shared pages + release every pool allocation.
 * Safe from the worker thread (deferred cleanup on thread exit). */
void kc_kernel_destroy(kc_kernel* kernel);

/* Optional out-of-band event to the peer (KC_OP_EVENT). */
kc_status kc_kernel_emit(kc_kernel* kernel, uint16_t op, const void* data,
                         uint32_t len);

/* kc_state snapshot (ENUM/INIT/READY/ACTIVE/FAILED/STOPPED/DEAD). */
uint32_t kc_kernel_state(kc_kernel* kernel);

/* Client pid of the current session (0 when none). */
uint32_t kc_kernel_peer_pid(kc_kernel* kernel);

/* attach_id of the current session (0 when none). */
uint64_t kc_kernel_attach_id(kc_kernel* kernel);

/* Set/replace the peer-gone callback after creation. */
void kc_kernel_set_peer_gone(kc_kernel* kernel, void (*fn)(void*), void* ctx);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* BLOOK_KCHANNEL_KM_H */
