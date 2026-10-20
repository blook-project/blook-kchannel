/*
 * Test-only IOCTL surface for kcmapload.sys (minimal manual-map loader).
 *
 * Loaded through the SCM with test signing; maps a driver image that the
 * user-mode test tool passes in (bootstrap + PE file bytes).
 */
#ifndef BLOOK_KCHANNEL_TESTS_GUEST_KCMAPLOAD_IOCTL_H
#define BLOOK_KCHANNEL_TESTS_GUEST_KCMAPLOAD_IOCTL_H

#include <blook/kchannel.h>

#define KC_MAPLOAD_DEVICE_TYPE 0x8C32u
#define KC_MAPLOAD_CTL(function) \
    (((KC_MAPLOAD_DEVICE_TYPE) << 16) | ((((ULONG)(function)) & 0xFFFu) << 2))

#define KC_MAPLOAD_DEVICE_NAME L"\\Device\\kcmapload"
#define KC_MAPLOAD_SYMLINK_NAME L"\\??\\kcmapload"
#define KC_MAPLOAD_WIN32_NAME L"\\\\.\\kcmapload"

#define KC_MAPLOAD_FN_LOAD 0x900u /* in: kc_mapload_request + image bytes */

#define KC_MAPLOAD_IOCTL_LOAD KC_MAPLOAD_CTL(KC_MAPLOAD_FN_LOAD)

#define KC_MAPLOAD_REQUEST_MAGIC 0x454D434Bu /* 'KCME' */

typedef struct kc_mapload_request {
    uint32_t magic;
    uint32_t flags;
    uint64_t image_size; /* PE bytes following this header */
    kc_bootstrap boot;   /* copied into kernel memory and passed to entry */
} kc_mapload_request;

typedef struct kc_mapload_result {
    uint32_t status;       /* kc_status-like: 0 ok, 1 param, 2 nomem, 3 map */
    uint32_t entry_status; /* NTSTATUS returned by the mapped DriverEntry */
    uint64_t image_base;
    uint64_t image_size;
} kc_mapload_result;

#define KC_MAPLOAD_OK 0u
#define KC_MAPLOAD_ERR_PARAM 1u
#define KC_MAPLOAD_ERR_NOMEM 2u
#define KC_MAPLOAD_ERR_MAP 3u
#define KC_MAPLOAD_ERR_ENTRY 4u

#endif /* BLOOK_KCHANNEL_TESTS_GUEST_KCMAPLOAD_IOCTL_H */
