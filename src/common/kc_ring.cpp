#include "common/kc_ring.h"

#include "common/kc_internal.h"

namespace kc {
namespace {

void direct_init(DirectRegion* region, void* base, uint64_t size) {
    region->base = static_cast<uint8_t*>(base);
    region->size = size;
}

kc_status direct_read(void* ctx, uint64_t off, void* dst, uint32_t len) {
    DirectRegion* region = static_cast<DirectRegion*>(ctx);
    if (off > region->size || len > region->size - off) {
        return KC_ERR_IO;
    }
    mem_copy(dst, region->base + off, len);
    return KC_OK;
}

kc_status direct_write(void* ctx, uint64_t off, const void* src, uint32_t len) {
    DirectRegion* region = static_cast<DirectRegion*>(ctx);
    if (off > region->size || len > region->size - off) {
        return KC_ERR_IO;
    }
    mem_copy(region->base + off, src, len);
    return KC_OK;
}

uint64_t direct_load64(void* ctx, uint64_t off) {
    DirectRegion* region = static_cast<DirectRegion*>(ctx);
    if (off > region->size || 8 > region->size - off) {
        return 0;
    }
    uint64_t value = 0;
    mem_copy(&value, region->base + off, 8);
    return value;
}

void direct_store64(void* ctx, uint64_t off, uint64_t value) {
    DirectRegion* region = static_cast<DirectRegion*>(ctx);
    if (off > region->size || 8 > region->size - off) {
        return;
    }
    mem_copy(region->base + off, &value, 8);
}

const MemOps kDirectOps = {direct_read, direct_write, direct_load64,
                           direct_store64};

bool ring_ok(uint64_t ring_size) {
    return ring_size >= 0x200 && ring_size <= KC_MAX_REGION_SIZE &&
           (ring_size % KC_RING_ALIGN) == 0;
}

/* Returns the used byte count and validates head/tail. */
kc_status used_internal(const RingView* ring, uint64_t* out_used) {
    if (ring_ok(ring->ring_size) == false) {
        return KC_ERR_PARAM;
    }
    if (ring->ring_off > ring->region_size ||
        ring->ring_size > ring->region_size - ring->ring_off) {
        return KC_ERR_PARAM;
    }
    if (ring->head_off > ring->region_size ||
        8 > ring->region_size - ring->head_off) {
        return KC_ERR_PARAM;
    }
    if (ring->tail_off > ring->region_size ||
        8 > ring->region_size - ring->tail_off) {
        return KC_ERR_PARAM;
    }
    uint64_t head = ring->ops->load64(ring->ops_ctx, ring->head_off);
    uint64_t tail = ring->ops->load64(ring->ops_ctx, ring->tail_off);
    if (head >= ring->ring_size || tail >= ring->ring_size) {
        return KC_ERR_IO;
    }
    if ((head % KC_RING_ALIGN) != 0 || (tail % KC_RING_ALIGN) != 0) {
        return KC_ERR_IO;
    }
    uint64_t used = (head + ring->ring_size - tail) % ring->ring_size;
    if (used > ring->ring_size - KC_RING_RESERVE) {
        return KC_ERR_IO;
    }
    *out_used = used;
    return KC_OK;
}

} /* namespace */

void direct_region_init(DirectRegion* region, void* base, uint64_t size) {
    direct_init(region, base, size);
}

const MemOps* direct_mem_ops() {
    return &kDirectOps;
}

kc_status ring_validate(const RingView* ring) {
    if (ring == nullptr || ring->ops == nullptr || ring->ops_ctx == nullptr) {
        return KC_ERR_PARAM;
    }
    if (ring_ok(ring->ring_size) == false) {
        return KC_ERR_PARAM;
    }
    if (ring->ring_off < KC_CTRL_SIZE || ring->ring_off > ring->region_size ||
        ring->ring_size > ring->region_size - ring->ring_off) {
        return KC_ERR_PARAM;
    }
    /* head/tail live inside the control page, so only region bounds apply. */
    if (ring->head_off > ring->region_size ||
        ring->head_off + 8 > ring->region_size) {
        return KC_ERR_PARAM;
    }
    if (ring->tail_off > ring->region_size ||
        ring->tail_off + 8 > ring->region_size) {
        return KC_ERR_PARAM;
    }
    uint64_t used = 0;
    return used_internal(ring, &used);
}

kc_status ring_used(const RingView* ring, uint64_t* out_used) {
    if (out_used == nullptr) {
        return KC_ERR_PARAM;
    }
    return used_internal(ring, out_used);
}

kc_status ring_read_bytes(const RingView* ring, uint64_t start, void* dst,
                          uint32_t len) {
    if (ring_ok(ring->ring_size) == false || start >= ring->ring_size ||
        len > ring->ring_size) {
        return KC_ERR_PARAM;
    }
    uint8_t* out = static_cast<uint8_t*>(dst);
    uint64_t first = ring->ring_size - start;
    if (first > len) {
        first = len;
    }
    kc_status st = ring->ops->read(ring->ops_ctx, ring->ring_off + start, out,
                                   static_cast<uint32_t>(first));
    if (st != KC_OK) {
        return st;
    }
    if (len > first) {
        st = ring->ops->read(ring->ops_ctx, ring->ring_off, out + first,
                             static_cast<uint32_t>(len - first));
    }
    return st;
}

kc_status ring_write_bytes(const RingView* ring, uint64_t start,
                           const void* src, uint32_t len) {
    if (ring_ok(ring->ring_size) == false || start >= ring->ring_size ||
        len > ring->ring_size) {
        return KC_ERR_PARAM;
    }
    const uint8_t* in = static_cast<const uint8_t*>(src);
    uint64_t first = ring->ring_size - start;
    if (first > len) {
        first = len;
    }
    kc_status st = ring->ops->write(ring->ops_ctx, ring->ring_off + start, in,
                                    static_cast<uint32_t>(first));
    if (st != KC_OK) {
        return st;
    }
    if (len > first) {
        st = ring->ops->write(ring->ops_ctx, ring->ring_off, in + first,
                              static_cast<uint32_t>(len - first));
    }
    return st;
}

kc_status ring_push(const RingView* ring, const void* record, uint32_t len) {
    if (ring == nullptr || record == nullptr) {
        return KC_ERR_PARAM;
    }
    if (len > ring->ring_size - 16) {
        return KC_ERR_PARAM;
    }
    uint64_t used = 0;
    kc_status st = used_internal(ring, &used);
    if (st != KC_OK) {
        return st;
    }
    uint64_t head = ring->ops->load64(ring->ops_ctx, ring->head_off);
    if (head >= ring->ring_size) {
        return KC_ERR_IO;
    }
    uint64_t free_bytes = ring->ring_size - KC_RING_RESERVE - used;
    if (len > free_bytes) {
        return KC_ERR_BUSY;
    }
    st = ring_write_bytes(ring, head, record, len);
    if (st != KC_OK) {
        return st;
    }
    compiler_barrier(); /* payload must be visible before head */
    ring->ops->store64(ring->ops_ctx, ring->head_off,
                       (head + len) % ring->ring_size);
    return KC_OK;
}

kc_status ring_pop(const RingView* ring, void* out, uint32_t cap,
                   uint32_t* out_len) {
    if (ring == nullptr || out == nullptr || out_len == nullptr) {
        return KC_ERR_PARAM;
    }
    uint64_t used = 0;
    kc_status st = used_internal(ring, &used);
    if (st != KC_OK) {
        return st;
    }
    if (used == 0) {
        return KC_ERR_NOT_FOUND;
    }
    if (used < KC_RECORD_HEADER_SIZE) {
        return KC_ERR_IO;
    }
    uint64_t tail = ring->ops->load64(ring->ops_ctx, ring->tail_off);
    if (tail >= ring->ring_size) {
        return KC_ERR_IO;
    }
    uint8_t header[KC_RECORD_HEADER_SIZE];
    st = ring_read_bytes(ring, tail, header, KC_RECORD_HEADER_SIZE);
    if (st != KC_OK) {
        return st;
    }
    uint32_t length = get_le32(header);
    uint32_t magic = get_le32(header + 4);
    if (magic != KC_RECORD_MAGIC) {
        return KC_ERR_MAGIC;
    }
    if (length < KC_RECORD_HEADER_SIZE + KC_MSG_HEADER_SIZE ||
        (length % KC_RING_ALIGN) != 0 || length > used) {
        return KC_ERR_IO;
    }
    if (length > cap) {
        return KC_ERR_PARAM;
    }
    st = ring_read_bytes(ring, tail, out, length);
    if (st != KC_OK) {
        return st;
    }
    compiler_barrier();
    ring->ops->store64(ring->ops_ctx, ring->tail_off,
                       (tail + length) % ring->ring_size);
    *out_len = length;
    return KC_OK;
}

} /* namespace kc */
