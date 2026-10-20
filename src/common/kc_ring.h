/*
 * Byte ring shared-memory access for blook-kchannel.
 *
 * The control page and both SPSC rings live in the loader-owned section. The
 * kernel must never trust that memory: offsets/sizes/heads/tails are treated
 * as hostile input and validated on every access. All access goes through
 * MemOps so the exact same ring code works for
 *   - MAPPED mode (direct system VA),
 *   - COPY mode (MmCopyVirtualMemory),
 *   - the host mock kernel (plain pointers).
 */
#ifndef BLOOK_KCHANNEL_COMMON_KC_RING_H
#define BLOOK_KCHANNEL_COMMON_KC_RING_H

#include <blook/kchannel.h>

namespace kc {

struct MemOps {
    kc_status (*read)(void* ctx, uint64_t off, void* dst, uint32_t len);
    kc_status (*write)(void* ctx, uint64_t off, const void* src, uint32_t len);
    uint64_t (*load64)(void* ctx, uint64_t off);
    void (*store64)(void* ctx, uint64_t off, uint64_t value);
};

/* Direct access to a contiguous region (user library / MAPPED kernel). */
struct DirectRegion {
    uint8_t* base;
    uint64_t size;
};

const MemOps* direct_mem_ops();
void direct_region_init(DirectRegion* region, void* base, uint64_t size);

struct RingView {
    const MemOps* ops;
    void* ops_ctx;
    uint64_t region_size; /* total shared region size, for validation */
    uint64_t ring_off;
    uint64_t ring_size;
    uint64_t head_off; /* absolute region offset of the u64 head */
    uint64_t tail_off; /* absolute region offset of the u64 tail */
};

/*
 * Validates static geometry. Returns KC_OK, or KC_ERR_PARAM/IO when the
 * caller-provided ring description or the region bounds are nonsense.
 */
kc_status ring_validate(const RingView* ring);

/* Bytes currently queued (0 .. ring_size). KC_ERR_IO when corrupt. */
kc_status ring_used(const RingView* ring, uint64_t* out_used);

/* Producer: append one record. KC_OK / KC_ERR_BUSY (no space) / KC_ERR_* */
kc_status ring_push(const RingView* ring, const void* record, uint32_t len);

/* Consumer: copy the next record into out. Returns
 *   KC_OK          - one record copied, *out_len set
 *   KC_ERR_NOT_FOUND - ring empty
 *   KC_ERR_IO      - corrupt geometry/length (caller should fail the session)
 *   KC_ERR_PARAM   - record larger than out_cap
 */
kc_status ring_pop(const RingView* ring, void* out, uint32_t cap,
                   uint32_t* out_len);

/* Reads len bytes starting at byte offset `start` inside the ring, wrapping. */
kc_status ring_read_bytes(const RingView* ring, uint64_t start, void* dst,
                          uint32_t len);
kc_status ring_write_bytes(const RingView* ring, uint64_t start,
                           const void* src, uint32_t len);

} /* namespace kc */

#endif /* BLOOK_KCHANNEL_COMMON_KC_RING_H */
