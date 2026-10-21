/*
 * Shared internals for blook-kchannel common code.
 *
 * src/common/*.cpp is compiled into BOTH the user library and the kernel
 * library, so it must not touch the CRT, the STL, exceptions or RTTI. The
 * helpers below replace the handful of libc primitives that are needed.
 */
#ifndef BLOOK_KCHANNEL_COMMON_KC_INTERNAL_H
#define BLOOK_KCHANNEL_COMMON_KC_INTERNAL_H

#include <blook/kchannel.h>

#if defined(_MSC_VER)
#include <intrin.h> /* _ReadWriteBarrier, __rdtsc, _mm_pause */
#endif

#if defined(_KERNEL_MODE) && defined(KCHANNEL_TESTING)
extern "C" unsigned long DbgPrint(const char* format, ...);
#define KC_DEBUG_TRACE(...) DbgPrint("kchannel: " __VA_ARGS__)
#else
#define KC_DEBUG_TRACE(...) ((void)0)
#endif

/* Optional debug sink (test builds only): null in production/user builds. */
inline void (*g_debug_log)(const char* message) = nullptr;
inline void debug_log(const char* message) {
    if (g_debug_log != nullptr) {
        g_debug_log(message);
    }
}

namespace kc {

inline void mem_copy(void* dst, const void* src, uint32_t len) {
    uint8_t* d = static_cast<uint8_t*>(dst);
    const uint8_t* s = static_cast<const uint8_t*>(src);
    for (uint32_t i = 0; i < len; ++i) {
        d[i] = s[i];
    }
}

inline void mem_set(void* dst, uint8_t value, uint32_t len) {
    uint8_t* d = static_cast<uint8_t*>(dst);
    for (uint32_t i = 0; i < len; ++i) {
        d[i] = value;
    }
}

inline void mem_zero(void* dst, uint32_t len) {
    mem_set(dst, 0, len);
}

/* Constant time compare; returns true when equal. */
inline bool mem_equal_ct(const void* a, const void* b, uint32_t len) {
    const uint8_t* pa = static_cast<const uint8_t*>(a);
    const uint8_t* pb = static_cast<const uint8_t*>(b);
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

inline void put_le32(void* p, uint32_t v) {
    uint8_t* b = static_cast<uint8_t*>(p);
    b[0] = static_cast<uint8_t>(v);
    b[1] = static_cast<uint8_t>(v >> 8);
    b[2] = static_cast<uint8_t>(v >> 16);
    b[3] = static_cast<uint8_t>(v >> 24);
}

inline void put_le64(void* p, uint64_t v) {
    uint8_t* b = static_cast<uint8_t*>(p);
    for (uint32_t i = 0; i < 8; ++i) {
        b[i] = static_cast<uint8_t>(v >> (8 * i));
    }
}

inline uint32_t get_le32(const void* p) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
}

inline uint64_t get_le64(const void* p) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    uint64_t v = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(b[i]) << (8 * i);
    }
    return v;
}

inline uint32_t get_be32(const void* p) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return (static_cast<uint32_t>(b[0]) << 24) |
           (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
}

inline void put_be32(void* p, uint32_t v) {
    uint8_t* b = static_cast<uint8_t*>(p);
    b[0] = static_cast<uint8_t>(v >> 24);
    b[1] = static_cast<uint8_t>(v >> 16);
    b[2] = static_cast<uint8_t>(v >> 8);
    b[3] = static_cast<uint8_t>(v);
}

inline bool is_all_zero(const void* p, uint32_t len) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    uint8_t acc = 0;
    for (uint32_t i = 0; i < len; ++i) {
        acc |= b[i];
    }
    return acc == 0;
}

inline bool is_pow2_aligned(uint64_t v, uint64_t align) {
    return align != 0 && (v & (align - 1)) == 0;
}

/* Compiler barrier; memory ordering is provided by the platform-specific
 * load/store implementations in kc_region.cpp. */
inline void compiler_barrier() {
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

} /* namespace kc */

#endif /* BLOOK_KCHANNEL_COMMON_KC_INTERNAL_H */
