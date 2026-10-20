/*
 * blook-kchannel kernel library.
 *
 * One peer, one worker thread (PASSIVE_LEVEL), one anonymous shared region.
 * No device object, no symbolic link, no registry, no named object, no notify
 * routine, no exported symbol. The only import surface is the documented
 * WDM/ntoskrnl API, which a manual mapper resolves from the ntoskrnl import
 * descriptor.
 *
 * Resource discipline (contract section 11): one MDL + system PTEs (MAPPED
 * only), one system thread, a handful of non-paged worker buffers. COPY mode
 * has no resident mapping at all.
 */
/* ntifs.h must be the first kernel header: it sets _NTIFS_INCLUDED_ before
 * pulling in ntddk.h/wdm.h, which changes PEPROCESS to the full type and
 * declares KAPC_STATE / PsLookupProcessByProcessId / KeStackAttachProcess. */
#include <ntifs.h>

#include <blook/kchannel_km.h>

#include "common/kc_framing.h"
#include "common/kc_internal.h"
#include "common/kc_reactor.h"
#include "common/kc_ring.h"

#define KC_POOL_TAG 'KCHK'

/*
 * Exported by ntoskrnl but not declared by the public WDK headers. Used for
 * COPY mode: the primitive attaches internally and, unlike a manual
 * KeStackAttachProcess, returns STATUS_PROCESS_IS_TERMINATING instead of
 * bugchecking when the loader is going away.
 */
extern "C" NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess,
    PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);

extern "C" NTSYSAPI NTSTATUS NTAPI PsGetProcessExitStatus(PEPROCESS Process);

namespace {

/* Only one live kernel session exists per loaded driver image. */
kc_kernel* volatile g_live_kernel = nullptr;

} /* namespace */

struct kc_kernel {
    FAST_MUTEX lock; /* serializes ring producers and ctrl writes */
    KSPIN_LOCK handler_lock;

    kc::Reactor reactor;
    kc::ReactorHandler handlers[KC_MAX_HANDLERS];
    uint32_t handler_count;

    /* MAPPED */
    PMDL mdl;
    PVOID mapped_va;
    kc::DirectRegion direct;

    /* COPY */
    PEPROCESS peer_process;
    PVOID user_va;

    uint64_t region_size;
    uint32_t mode;
    uint32_t cipher;
    uint32_t peer_pid;
    uint64_t attach_id;

    kc_ctrl* ctrl_scratch;
    uint8_t* record_buf;
    uint8_t* plain_buf;
    uint8_t* out_buf;
    uint8_t* reply_buf;
    uint8_t* event_buf;
    uint8_t* event_record_buf;
    uint32_t max_payload;
    uint32_t ring_size;

    PETHREAD thread;
    KEVENT stop_event;
    volatile LONG stop_requested;
    volatile LONG destroy_pending;
    volatile LONG io_errors;
    volatile LONG peer_gone;

    kc_kernel_config config;
    uint32_t flags;
    uint32_t watchdog_ms;
    uint32_t poll_spin_us;
    uint32_t poll_idle_us;
    uint32_t poll_idle_max_us;
    kc_bootstrap boot;
};

namespace {

/* ------------------------------ helpers ------------------------------ */

uint64_t kernel_now_ns(void* ctx) {
    (void)ctx;
    return static_cast<uint64_t>(KeQueryUnbiasedInterruptTime()) * 100ull;
}

void kernel_delay_ms(void* ctx, uint32_t ms) {
    (void)ctx;
    LARGE_INTEGER interval;
    interval.QuadPart = -static_cast<LONGLONG>(ms) * 10000ll;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

void kernel_lock(void* ctx) {
    kc_kernel* kernel = static_cast<kc_kernel*>(ctx);
    ExAcquireFastMutex(&kernel->lock);
}

void kernel_unlock(void* ctx) {
    kc_kernel* kernel = static_cast<kc_kernel*>(ctx);
    ExReleaseFastMutex(&kernel->lock);
}

void kernel_peer_gone(void* ctx) {
    kc_kernel* kernel = static_cast<kc_kernel*>(ctx);
    InterlockedExchange(&kernel->peer_gone, 1);
    void (*callback)(void*) = kernel->config.on_peer_gone;
    if (callback != nullptr) {
        callback(kernel->config.ctx);
    }
}

kc_status ensure_user_range(uint64_t va, uint64_t size) {
    const uint64_t limit = static_cast<uint64_t>(
        reinterpret_cast<ULONG_PTR>(MmHighestUserAddress));
    if (va < KC_REGION_ALIGN) {
        return KC_ERR_PARAM;
    }
    if (va > limit || size > limit - va) {
        return KC_ERR_PARAM;
    }
    return KC_OK;
}

kc_status copy_region(void* ctx, uint64_t off, void* buffer, uint32_t len,
                      bool to_user) {
    kc_kernel* kernel = static_cast<kc_kernel*>(ctx);
    if (kernel->peer_process == nullptr) {
        return KC_ERR_STATE;
    }
    if (PsGetProcessExitStatus(kernel->peer_process) != STATUS_PENDING) {
        return KC_ERR_PEER_GONE;
    }
    if (off > kernel->region_size || len > kernel->region_size - off) {
        return KC_ERR_IO;
    }
    SIZE_T copied = 0;
    PVOID user_address =
        static_cast<PVOID>(static_cast<uint8_t*>(kernel->user_va) + off);
    NTSTATUS status;
    if (to_user) {
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer,
                                     kernel->peer_process, user_address, len,
                                     KernelMode, &copied);
    } else {
        status = MmCopyVirtualMemory(kernel->peer_process, user_address,
                                     PsGetCurrentProcess(), buffer, len,
                                     KernelMode, &copied);
    }
    if (!NT_SUCCESS(status) || copied != len) {
        InterlockedIncrement(&kernel->io_errors);
        return KC_ERR_IO;
    }
    return KC_OK;
}

kc_status copy_read(void* ctx, uint64_t off, void* dst, uint32_t len) {
    return copy_region(ctx, off, dst, len, false);
}

kc_status copy_write(void* ctx, uint64_t off, const void* src, uint32_t len) {
    return copy_region(ctx, off, const_cast<void*>(src), len, true);
}

uint64_t copy_load64(void* ctx, uint64_t off) {
    uint64_t value = 0;
    if (copy_read(ctx, off, &value, sizeof(value)) != KC_OK) {
        return 0;
    }
    return value;
}

void copy_store64(void* ctx, uint64_t off, uint64_t value) {
    (void)copy_write(ctx, off, &value, sizeof(value));
}

const kc::MemOps kCopyOps = {copy_read, copy_write, copy_load64, copy_store64};

/* Derives the kernel->user nonce prefix from the session key (keyed, so it is
 * unpredictable and unique per attach; collisions are harmless anyway). */
void derive_nonce_tx(kc_kernel* kernel, uint8_t out[KC_NONCE_PREFIX_SIZE]) {
    uint8_t material[32];
    uint8_t digest[32];
    static const uint8_t label[] = "kchannel/nonce-tx";
    const uint64_t now = KeQueryUnbiasedInterruptTime();
    const uint64_t tick = __rdtsc();
    kc::mem_zero(material, sizeof(material));
    kc::mem_copy(material, label, 16);
    kc::put_le64(material + 16, kernel->attach_id);
    kc::put_le64(material + 24, now ^ tick);
    kc::hmac_sha256(kernel->boot.session_key, KC_KEY_SIZE, material,
                    sizeof(material), digest);
    kc::mem_copy(out, digest, KC_NONCE_PREFIX_SIZE);
    kc::mem_zero(digest, sizeof(digest));
    kc::mem_zero(material, sizeof(material));
}

/* Maps the loader's pages into system VA. Must run in the peer's context. */
kc_status map_region(kc_kernel* kernel, const kc_bootstrap* boot) {
    PMDL mdl = IoAllocateMdl(reinterpret_cast<PVOID>(boot->shared_va),
                             static_cast<ULONG>(boot->shared_size), FALSE,
                             FALSE, nullptr);
    if (mdl == nullptr) {
        return KC_ERR_NOMEM;
    }
    bool locked = false;
    kc_status result = KC_OK;
    __try {
        MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
        locked = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = KC_ERR_MAP;
    }
    if (result != KC_OK) {
        IoFreeMdl(mdl);
        return result;
    }
    PVOID system_va = nullptr;
    __try {
        system_va = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        system_va = nullptr;
    }
    if (system_va == nullptr) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return KC_ERR_MAP;
    }
    kernel->mdl = mdl;
    kernel->mapped_va = system_va;
    (void)locked;
    return KC_OK;
}

void unmap_region(kc_kernel* kernel) {
    if (kernel->mapped_va != nullptr) {
        MmUnmapLockedPages(kernel->mapped_va, kernel->mdl);
        kernel->mapped_va = nullptr;
    }
    if (kernel->mdl != nullptr) {
        MmUnlockPages(kernel->mdl);
        IoFreeMdl(kernel->mdl);
        kernel->mdl = nullptr;
    }
}

void free_buffers(kc_kernel* kernel) {
    if (kernel->ctrl_scratch != nullptr) {
        ExFreePoolWithTag(kernel->ctrl_scratch, KC_POOL_TAG);
        kernel->ctrl_scratch = nullptr;
    }
    uint8_t** buffers[] = {&kernel->record_buf, &kernel->plain_buf,
                           &kernel->out_buf,    &kernel->reply_buf,
                           &kernel->event_buf,  &kernel->event_record_buf};
    for (uint32_t i = 0; i < sizeof(buffers) / sizeof(buffers[0]); ++i) {
        if (*buffers[i] != nullptr) {
            ExFreePoolWithTag(*buffers[i], KC_POOL_TAG);
            *buffers[i] = nullptr;
        }
    }
}

void kernel_cleanup(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return;
    }
    if (InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_live_kernel), kernel,
            kernel) == kernel) {
        InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_live_kernel), nullptr);
    }
    if (kernel->thread != nullptr) {
        if (PsGetCurrentThread() != kernel->thread) {
            KeWaitForSingleObject(kernel->thread, Executive, KernelMode, FALSE,
                                  nullptr);
        }
        ObDereferenceObject(kernel->thread);
        kernel->thread = nullptr;
    }
    unmap_region(kernel);
    if (kernel->peer_process != nullptr) {
        ObDereferenceObject(kernel->peer_process);
        kernel->peer_process = nullptr;
    }
    free_buffers(kernel);
    kc::mem_zero(&kernel->boot, sizeof(kernel->boot));
    ExFreePoolWithTag(kernel, KC_POOL_TAG);
}

/* Writes a failed control page into a region we are about to reject. */
kc_status reject_bootstrap(const kc_bootstrap* boot, kc_status error) {
    const ULONG mode = boot->mode;
    PEPROCESS peer = nullptr;
    bool attached = false;
    KAPC_STATE apc;
    RtlZeroMemory(&apc, sizeof(apc));
    uint32_t pid = boot->peer_pid;
    if (pid == 0) {
        pid = static_cast<uint32_t>(
            reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
    }
    if (mode == KC_MODE_MAPPED &&
        pid != static_cast<uint32_t>(
                   reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()))) {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)),
                &peer))) {
            return error;
        }
        KeStackAttachProcess(peer, &apc);
        attached = true;
    }
    PMDL mdl = IoAllocateMdl(reinterpret_cast<PVOID>(boot->shared_va),
                             static_cast<ULONG>(boot->shared_size), FALSE,
                             FALSE, nullptr);
    if (mdl != nullptr) {
        bool locked = false;
        __try {
            MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
            locked = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            locked = false;
        }
        if (locked) {
            PVOID system_va = nullptr;
            __try {
                system_va = MmMapLockedPagesSpecifyCache(
                    mdl, KernelMode, MmCached, nullptr, FALSE,
                    NormalPagePriority);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                system_va = nullptr;
            }
            if (system_va != nullptr) {
                kc_ctrl* ctrl = static_cast<kc_ctrl*>(system_va);
                kc::mem_zero(ctrl, KC_CTRL_SIZE);
                ctrl->magic = KC_CTRL_MAGIC;
                ctrl->abi_major = static_cast<uint16_t>(KC_ABI_MAJOR);
                ctrl->abi_minor = static_cast<uint16_t>(KC_ABI_MINOR);
                ctrl->header_size = KC_CTRL_SIZE;
                ctrl->state = KC_STATE_FAILED;
                ctrl->error = static_cast<uint32_t>(error);
                ctrl->attach_id = boot->attach_id;
                ctrl->peer_pid = pid;
                MmUnmapLockedPages(system_va, mdl);
            }
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
    }
    if (attached) {
        KeUnstackDetachProcess(&apc);
    }
    if (peer != nullptr) {
        ObDereferenceObject(peer);
    }
    return error;
}

/* ------------------------------ worker ------------------------------- */

VOID WorkerThread(PVOID context) {
    kc_kernel* kernel = static_cast<kc_kernel*>(context);
    uint32_t idle = 0;
    for (;;) {
        if (InterlockedCompareExchange(&kernel->stop_requested, 1, 1) != 0) {
            break;
        }
        const int processed = kernel->reactor.poll(16);
        if (InterlockedCompareExchange(&kernel->stop_requested, 1, 1) != 0) {
            break;
        }
        if (processed > 0) {
            idle = 0;
            continue;
        }
        if (InterlockedCompareExchange(&kernel->io_errors, 0, 0) != 0) {
            kernel->reactor.force_fail(KC_ERR_IO);
            InterlockedExchange(&kernel->io_errors, 0);
        }

        /* Busy window: the peer usually answers within microseconds. */
        LARGE_INTEGER frequency;
        LARGE_INTEGER start = KeQueryPerformanceCounter(&frequency);
        const LONGLONG budget =
            (frequency.QuadPart * static_cast<LONGLONG>(kernel->poll_spin_us)) /
            1000000ll;
        bool worked = false;
        for (;;) {
            if (InterlockedCompareExchange(&kernel->stop_requested, 1, 1) !=
                0) {
                break;
            }
            LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
            if (now.QuadPart - start.QuadPart >= budget) {
                break;
            }
            _mm_pause();
            if (kernel->reactor.poll(2) > 0) {
                worked = true;
                break;
            }
        }
        if (InterlockedCompareExchange(&kernel->stop_requested, 1, 1) != 0) {
            break;
        }
        if (worked) {
            idle = 0;
            continue;
        }

        /* Exponential idle backoff: 1 ms, 2 ms, ... up to the ceiling.
         * The stop event wakes the wait immediately, so a stop completes
         * well inside the 100 ms contract bound. */
        uint32_t delay_us = kernel->poll_idle_us;
        for (uint32_t i = 0; i < idle; ++i) {
            if (delay_us >= kernel->poll_idle_max_us) {
                break;
            }
            delay_us *= 2;
        }
        if (delay_us > kernel->poll_idle_max_us) {
            delay_us = kernel->poll_idle_max_us;
        }
        if (delay_us < 100) {
            delay_us = 100;
        }
        LARGE_INTEGER interval;
        interval.QuadPart = -static_cast<LONGLONG>(delay_us) * 10ll;
        KeWaitForSingleObject(&kernel->stop_event, Executive, KernelMode, FALSE,
                              &interval);
        if (idle < 16) {
            ++idle;
        }
    }
    if (InterlockedCompareExchange(&kernel->destroy_pending, 1, 1) != 0) {
        kernel_cleanup(kernel);
    }
}

} /* namespace */

extern "C" {

kc_status kc_kernel_create(const kc_bootstrap* boot,
                           const kc_kernel_config* config, kc_kernel** out) {
    if (boot == nullptr || out == nullptr) {
        return KC_ERR_PARAM;
    }
    *out = nullptr;

    /* ---- bootstrap validation (contract section 2) ---- */
    if (boot->magic != KC_BOOTSTRAP_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (boot->abi_major != KC_ABI_MAJOR || boot->abi_minor > KC_ABI_MINOR ||
        boot->struct_size != KC_BOOTSTRAP_SIZE) {
        return KC_ERR_VERSION;
    }
    if (boot->mode != KC_MODE_MAPPED && boot->mode != KC_MODE_COPY) {
        return KC_ERR_PARAM;
    }
    if (boot->cipher != KC_CIPHER_CHACHA20 &&
        boot->cipher != KC_CIPHER_AES128CTR) {
        return KC_ERR_PARAM;
    }
    if (boot->attach_id == 0) {
        return KC_ERR_PARAM;
    }
    if (boot->shared_size < KC_MIN_REGION_SIZE ||
        boot->shared_size > KC_MAX_REGION_SIZE ||
        (boot->shared_size % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    if ((boot->shared_va % KC_REGION_ALIGN) != 0) {
        return KC_ERR_PARAM;
    }
    if (ensure_user_range(boot->shared_va, boot->shared_size) != KC_OK) {
        return KC_ERR_PARAM;
    }
    if (kc::is_all_zero(boot->session_key, KC_KEY_SIZE)) {
        return KC_ERR_PARAM;
    }
    uint64_t req_off = 0;
    uint64_t ring_size = 0;
    if (kc::region_geometry(boot->shared_size, &req_off, &ring_size) != KC_OK) {
        return KC_ERR_PARAM;
    }

    uint32_t peer_pid = boot->peer_pid;
    if (peer_pid == 0) {
        peer_pid = static_cast<uint32_t>(
            reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
    }

    /* Single peer: reject a second bootstrap while a session is live. */
    if (InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_live_kernel), nullptr,
            nullptr) != nullptr) {
        return reject_bootstrap(boot, KC_ERR_ALREADY);
    }

    kc_kernel* kernel = static_cast<kc_kernel*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(kc_kernel), KC_POOL_TAG));
    if (kernel == nullptr) {
        return KC_ERR_NOMEM;
    }
    if (InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_live_kernel), kernel,
            nullptr) != nullptr) {
        ExFreePoolWithTag(kernel, KC_POOL_TAG);
        return reject_bootstrap(boot, KC_ERR_ALREADY);
    }

    kernel->boot = *boot;
    kernel->mode = boot->mode;
    kernel->cipher = boot->cipher;
    kernel->peer_pid = peer_pid;
    kernel->attach_id = boot->attach_id;
    kernel->region_size = boot->shared_size;
    kernel->ring_size = static_cast<uint32_t>(ring_size);
    ExInitializeFastMutex(&kernel->lock);
    KeInitializeSpinLock(&kernel->handler_lock);
    KeInitializeEvent(&kernel->stop_event, NotificationEvent, FALSE);

    /* ---- access to the loader pages ---- */
    kc_status status = KC_OK;
    if (boot->mode == KC_MODE_MAPPED) {
        const bool need_attach =
            peer_pid != static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(
                            PsGetCurrentProcessId()));
        PEPROCESS peer = nullptr;
        KAPC_STATE apc;
        bool attached = false;
        if (need_attach) {
            status =
                NT_SUCCESS(PsLookupProcessByProcessId(
                    reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(peer_pid)),
                    &peer))
                    ? KC_OK
                    : KC_ERR_MAP;
            if (status == KC_OK) {
                KeStackAttachProcess(peer, &apc);
                attached = true;
            }
        }
        if (status == KC_OK) {
            status = map_region(kernel, boot);
        }
        if (attached) {
            KeUnstackDetachProcess(&apc);
        }
        if (peer != nullptr) {
            ObDereferenceObject(peer);
        }
        if (status == KC_OK) {
            if (kernel->mapped_va == nullptr) {
                status = KC_ERR_MAP;
            } else {
                kc::direct_region_init(&kernel->direct, kernel->mapped_va,
                                       boot->shared_size);
            }
        }
    } else {
        PEPROCESS peer = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(peer_pid)),
                &peer))) {
            kernel->peer_process = peer;
        } else {
            status = KC_ERR_MAP;
        }
        kernel->user_va = reinterpret_cast<PVOID>(boot->shared_va);
    }
    if (status != KC_OK) {
        kernel_cleanup(kernel);
        return status;
    }

    /* ---- worker buffers, sized from the negotiated geometry ---- */
    uint64_t max_payload = KC_MAX_PAYLOAD - KC_CALL_PREFIX_SIZE;
    if (config != nullptr && config->max_payload != 0 &&
        config->max_payload < max_payload) {
        max_payload = config->max_payload;
    }
    if (ring_size >
        KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE + KC_CALL_PREFIX_SIZE) {
        const uint64_t limit = ring_size - KC_RECORD_HEADER_SIZE -
                               KC_MSG_HEADER_SIZE - KC_CALL_PREFIX_SIZE;
        if (limit < max_payload) {
            max_payload = limit;
        }
    }
    if (max_payload < KC_CALL_PREFIX_SIZE) {
        kernel_cleanup(kernel);
        return KC_ERR_PARAM;
    }
    kernel->max_payload = static_cast<uint32_t>(max_payload);
    const uint32_t record_cap =
        static_cast<uint32_t>(KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE +
                              KC_CALL_PREFIX_SIZE + max_payload);
    kernel->ctrl_scratch = static_cast<kc_ctrl*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, KC_CTRL_SIZE, KC_POOL_TAG));
    kernel->record_buf = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, record_cap, KC_POOL_TAG));
    kernel->plain_buf = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        static_cast<SIZE_T>(max_payload) + 2, KC_POOL_TAG));
    kernel->out_buf = static_cast<uint8_t*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED, static_cast<SIZE_T>(max_payload), KC_POOL_TAG));
    kernel->reply_buf = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, record_cap, KC_POOL_TAG));
    kernel->event_buf = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        static_cast<SIZE_T>(max_payload) + 2, KC_POOL_TAG));
    kernel->event_record_buf = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, record_cap, KC_POOL_TAG));
    if (kernel->ctrl_scratch == nullptr || kernel->record_buf == nullptr ||
        kernel->plain_buf == nullptr || kernel->out_buf == nullptr ||
        kernel->reply_buf == nullptr || kernel->event_buf == nullptr ||
        kernel->event_record_buf == nullptr) {
        kernel_cleanup(kernel);
        return KC_ERR_NOMEM;
    }

    /* ---- reactor ---- */
    uint8_t nonce_tx[KC_NONCE_PREFIX_SIZE];
    derive_nonce_tx(kernel, nonce_tx);

    kc::ReactorConfig reactor_config;
    kc::mem_zero(&reactor_config, sizeof(reactor_config));
    const kc::MemOps* ops = kc::direct_mem_ops();
    void* ops_ctx = &kernel->direct;
    if (kernel->mode == KC_MODE_COPY) {
        ops = &kCopyOps;
        ops_ctx = kernel;
    }
    reactor_config.ops = ops;
    reactor_config.ops_ctx = ops_ctx;
    reactor_config.region_size = boot->shared_size;
    reactor_config.session_key = boot->session_key;
    reactor_config.salt = boot->salt;
    reactor_config.nonce_tx = nonce_tx;
    /* The user publishes nonce_prefix_rq in the control page before HELLO;
     * the reactor refreshes it at handshake time. Start with a placeholder. */
    static const uint8_t kZeroPrefix[KC_NONCE_PREFIX_SIZE] = {0};
    reactor_config.nonce_rx = kZeroPrefix;
    reactor_config.cipher = boot->cipher;
    reactor_config.peer_pid = peer_pid;
    reactor_config.attach_id = boot->attach_id;
    reactor_config.max_payload = kernel->max_payload;
    reactor_config.watchdog_ms = (config != nullptr && config->watchdog_ms != 0)
                                     ? config->watchdog_ms
                                     : KC_DEFAULT_WATCHDOG_MS;
    reactor_config.handshake_ms = reactor_config.watchdog_ms;
    reactor_config.flags = (config != nullptr) ? config->flags : 0;
    reactor_config.handlers = kernel->handlers;
    reactor_config.handler_count = 0;
    reactor_config.ctrl_scratch = kernel->ctrl_scratch;
    reactor_config.record_buf = kernel->record_buf;
    reactor_config.record_buf_cap = record_cap;
    reactor_config.plain_buf = kernel->plain_buf;
    reactor_config.plain_buf_cap = static_cast<uint32_t>(max_payload) + 2;
    reactor_config.out_buf = kernel->out_buf;
    reactor_config.out_buf_cap = static_cast<uint32_t>(max_payload);
    reactor_config.reply_buf = kernel->reply_buf;
    reactor_config.reply_buf_cap = record_cap;
    reactor_config.event_buf = kernel->event_buf;
    reactor_config.event_buf_cap = static_cast<uint32_t>(max_payload) + 2;
    reactor_config.event_record_buf = kernel->event_record_buf;
    reactor_config.event_record_buf_cap = record_cap;
    reactor_config.lock = kernel_lock;
    reactor_config.unlock = kernel_unlock;
    reactor_config.lock_ctx = kernel;
    reactor_config.now_ns = kernel_now_ns;
    reactor_config.now_ctx = kernel;
    reactor_config.delay_ms = kernel_delay_ms;
    reactor_config.delay_ctx = kernel;
    reactor_config.on_peer_gone = kernel_peer_gone;
    reactor_config.ctx = kernel;

    status = kernel->reactor.init(reactor_config);
    kc::mem_zero(nonce_tx, sizeof(nonce_tx));
    if (status != KC_OK) {
        kernel_cleanup(kernel);
        return status;
    }

    /* ---- configuration knobs ---- */
    kernel->config = (config != nullptr) ? *config : kc_kernel_config{};
    kernel->flags = kernel->config.flags;
    kernel->watchdog_ms = reactor_config.watchdog_ms;
    kernel->poll_spin_us = KC_DEFAULT_POLL_SPIN_US;
    kernel->poll_idle_us = KC_DEFAULT_POLL_IDLE_US;
    kernel->poll_idle_max_us = KC_DEFAULT_POLL_IDLE_MAX_US;
    if (config != nullptr) {
        if (config->poll_spin_us != 0) {
            kernel->poll_spin_us = config->poll_spin_us;
        }
        if (config->poll_idle_us != 0) {
            kernel->poll_idle_us = config->poll_idle_us;
        }
        if (config->poll_idle_max_us != 0) {
            kernel->poll_idle_max_us = config->poll_idle_max_us;
        }
    }
    if (kernel->poll_idle_max_us < kernel->poll_idle_us) {
        kernel->poll_idle_max_us = kernel->poll_idle_us;
    }
    kernel->handler_count = 0;

    *out = kernel;
    return KC_OK;
}

kc_status kc_kernel_register(kc_kernel* kernel, uint16_t op, kc_handler_fn fn,
                             void* ctx) {
    if (kernel == nullptr || fn == nullptr) {
        return KC_ERR_PARAM;
    }
    if (op < KC_OP_APP_MIN) {
        return KC_ERR_PARAM;
    }
    KIRQL old_irql;
    KeAcquireSpinLock(&kernel->handler_lock, &old_irql);
    kc_status status = KC_OK;
    bool replaced = false;
    for (uint32_t i = 0; i < kernel->handler_count; ++i) {
        if (kernel->handlers[i].op == op) {
            kernel->handlers[i].fn = fn;
            kernel->handlers[i].ctx = ctx;
            replaced = true;
            break;
        }
    }
    if (replaced == false) {
        if (kernel->handler_count >= KC_MAX_HANDLERS) {
            status = KC_ERR_NOMEM;
        } else {
            kernel->handlers[kernel->handler_count].op = op;
            kernel->handlers[kernel->handler_count].fn = fn;
            kernel->handlers[kernel->handler_count].ctx = ctx;
            ++kernel->handler_count;
        }
    }
    KeReleaseSpinLock(&kernel->handler_lock, old_irql);
    if (status == KC_OK) {
        kernel->reactor.set_handler_count(kernel->handler_count);
    }
    return status;
}

kc_status kc_kernel_start(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return KC_ERR_PARAM;
    }
    if (kernel->thread != nullptr) {
        return KC_OK;
    }
    HANDLE thread_handle = nullptr;
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    NTSTATUS status =
        PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, &attributes,
                             nullptr, nullptr, WorkerThread, kernel);
    if (!NT_SUCCESS(status)) {
        return KC_ERR_INTERNAL;
    }
    PETHREAD thread = nullptr;
    status = ObReferenceObjectByHandle(
        thread_handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
        reinterpret_cast<PVOID*>(&thread), nullptr);
    ZwClose(thread_handle);
    if (!NT_SUCCESS(status)) {
        return KC_ERR_INTERNAL;
    }
    kernel->thread = thread;
    return KC_OK;
}

void kc_kernel_stop(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return;
    }
    InterlockedExchange(&kernel->stop_requested, 1);
    KeSetEvent(&kernel->stop_event, IO_NO_INCREMENT, FALSE);
    if (kernel->thread != nullptr && PsGetCurrentThread() != kernel->thread) {
        KeWaitForSingleObject(kernel->thread, Executive, KernelMode, FALSE,
                              nullptr);
        ObDereferenceObject(kernel->thread);
        kernel->thread = nullptr;
    }
}

void kc_kernel_destroy(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return;
    }
    if (kernel->thread != nullptr && PsGetCurrentThread() == kernel->thread) {
        /* Called from on_peer_gone / a handler: finish cleanup on thread
         * exit, never free our own stack's owner. */
        InterlockedExchange(&kernel->destroy_pending, 1);
        InterlockedExchange(&kernel->stop_requested, 1);
        KeSetEvent(&kernel->stop_event, IO_NO_INCREMENT, FALSE);
        return;
    }
    kc_kernel_stop(kernel);
    kernel_cleanup(kernel);
}

kc_status kc_kernel_emit(kc_kernel* kernel, uint16_t op, const void* data,
                         uint32_t len) {
    if (kernel == nullptr) {
        return KC_ERR_PARAM;
    }
    return kernel->reactor.emit(op, data, len);
}

uint32_t kc_kernel_state(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return KC_STATE_EMPTY;
    }
    return kernel->reactor.state();
}

uint32_t kc_kernel_peer_pid(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return 0;
    }
    return kernel->peer_pid;
}

uint64_t kc_kernel_attach_id(kc_kernel* kernel) {
    if (kernel == nullptr) {
        return 0;
    }
    return kernel->attach_id;
}

void kc_kernel_set_peer_gone(kc_kernel* kernel, void (*fn)(void*), void* ctx) {
    if (kernel == nullptr) {
        return;
    }
    kernel->config.on_peer_gone = fn;
    kernel->config.ctx = ctx;
    kernel->reactor.set_peer_gone_callback(fn, ctx);
}

} /* extern "C" */
