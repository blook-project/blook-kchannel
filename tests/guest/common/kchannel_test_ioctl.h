/*
 * Test-only IOCTL surface for kchannel_test.sys.
 *
 * Used exclusively by the e2e suite:
 *   (a) `sc create/start` loaded driver: the loader sends the bootstrap with
 *       IOCTL_ATTACH, then talks to the driver through blook-kchannel.
 *   (b) manual-mapped driver: no device at all; the mapper passes the
 *       bootstrap as the entry parameter.
 *
 * This header is compiled for both kernel and user mode, so it avoids
 * <windows.h>/<ntddk.h> dependencies by defining the CTL_CODE layout itself.
 */
#ifndef BLOOK_KCHANNEL_TESTS_GUEST_KCHANNEL_TEST_IOCTL_H
#define BLOOK_KCHANNEL_TESTS_GUEST_KCHANNEL_TEST_IOCTL_H

#include <blook/kchannel.h>

#define KC_TEST_DEVICE_TYPE 0x8C31u

/* (device << 16) | (function << 2) | method; method 0 == METHOD_BUFFERED. */
#define KC_TEST_CTL(function) \
    (((KC_TEST_DEVICE_TYPE) << 16) | ((((ULONG)(function)) & 0xFFFu) << 2))

#define KC_TEST_DEVICE_NAME L"\\Device\\kchannel_test"
#define KC_TEST_SYMLINK_NAME L"\\??\\kchannel_test"
#define KC_TEST_WIN32_NAME L"\\\\.\\kchannel_test"

/* IOCTL functions. */
#define KC_TEST_FN_ATTACH 0x800u /* in: kc_bootstrap */
#define KC_TEST_FN_SECOND_ATTACH \
    0x801u                          /* in: kc_bootstrap, out: kc_test_result */
#define KC_TEST_FN_STATE 0x802u     /* out: kc_test_state */
#define KC_TEST_FN_EMIT 0x803u      /* in: kc_test_emit + payload */
#define KC_TEST_FN_DESTROY 0x804u   /* out: kc_test_result */
#define KC_TEST_FN_DRIVER_OP 0x805u /* in: kc_test_driver_op, out: result */

#define KC_TEST_IOCTL_ATTACH KC_TEST_CTL(KC_TEST_FN_ATTACH)
#define KC_TEST_IOCTL_SECOND_ATTACH KC_TEST_CTL(KC_TEST_FN_SECOND_ATTACH)
#define KC_TEST_IOCTL_STATE KC_TEST_CTL(KC_TEST_FN_STATE)
#define KC_TEST_IOCTL_EMIT KC_TEST_CTL(KC_TEST_FN_EMIT)
#define KC_TEST_IOCTL_DESTROY KC_TEST_CTL(KC_TEST_FN_DESTROY)
#define KC_TEST_FN_PERF_STATS 0x806u   /* out: kc_test_perf */
#define KC_TEST_FN_STOP_RESTART 0x807u /* out: kc_test_stop */

#define KC_TEST_IOCTL_DRIVER_OP KC_TEST_CTL(KC_TEST_FN_DRIVER_OP)
#define KC_TEST_IOCTL_PERF_STATS KC_TEST_CTL(KC_TEST_FN_PERF_STATS)
#define KC_TEST_IOCTL_STOP_RESTART KC_TEST_CTL(KC_TEST_FN_STOP_RESTART)

/* Application opcodes served by kchannel_test.sys. */
#define KC_TOp_ECHO 0x8001u
#define KC_TOp_DELAY 0x8002u /* in: uint32 milliseconds */
#define KC_TOp_ERROR 0x8003u /* returns KC_ERR_HANDLER */
#define KC_TOp_CRASH 0x8004u /* intentionally faults (BSOD-safety harness) */
#define KC_TOp_EMIT 0x8005u  /* in: uint16 event op + payload */
#define KC_TOp_REPLY_HUGE 0x8006u /* claims a huge reply, must be rejected */

typedef struct kc_test_attach {
    kc_bootstrap boot;
    uint32_t flags;
    uint32_t reserved;
} kc_test_attach;

typedef struct kc_test_result {
    uint32_t status; /* kc_status */
    uint32_t reserved;
} kc_test_result;

typedef struct kc_test_state {
    uint32_t state; /* kc_state */
    uint32_t error; /* kc_status */
    uint32_t peer_pid;
    uint32_t reserved;
    uint64_t attach_id;
} kc_test_state;

typedef struct kc_test_emit {
    uint16_t op;
    uint16_t reserved;
    uint32_t len;
    /* uint8_t data[] */
} kc_test_emit;

typedef struct kc_test_driver_op {
    uint32_t op;
    uint32_t value;
} kc_test_driver_op;

typedef struct kc_test_perf {
    uint64_t worker_cycles;
    uint64_t cycle_frequency;
} kc_test_perf;

typedef struct kc_test_stop {
    uint32_t status;
    uint32_t reserved;
    uint64_t stop_ns;
} kc_test_stop;

/* kc_test_driver_op.op values */
#define KC_TDRVOP_PING_THREAD 1u /* returns whether the worker is alive */

#endif /* BLOOK_KCHANNEL_TESTS_GUEST_KCHANNEL_TEST_IOCTL_H */
