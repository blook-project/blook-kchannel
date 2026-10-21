/*
 * kchannel_test.sys - test-only driver for the blook-kchannel e2e suite.
 *
 * Two load paths are exercised:
 *   (a) `sc create` + `sc start` (test signing): DriverEntry gets a real
 *       DRIVER_OBJECT and creates a device so the test tool can hand over the
 *       bootstrap.  This path exists only in KCHANNEL_TESTING builds.
 *   (b) manual map by kcmapload.sys: DriverEntry receives a kernel copy of
 *       `kc_bootstrap` as the entry parameter.  No device, no symbolic link,
 *       no registry access is performed - the stealth path.
 *
 * Handlers: echo, delay, error, intentional crash (BSOD-safety harness),
 * event emit, oversized reply.
 *
 * Test builds may write diagnostics to C:\blook-kchannel-e2e.log; that file
 * I/O exists only to prove cleanup claims (worker exit, MDL release) from
 * inside the guest, and is compiled out of any non-KCHANNEL_TESTING build.
 */
#include <ntifs.h>
#include <ntstrsafe.h>

#include <blook/kchannel_km.h>

#include "guest/common/kchannel_test_ioctl.h"

#define KC_TEST_POOL_TAG 'KCTK'
#define KC_TEST_LOG_PATH L"\\??\\C:\\blook-kchannel-e2e.log"

extern "C" {
NTSTATUS DriverEntry(PVOID entry_parameter, PVOID registry_path);
DRIVER_UNLOAD KcTestUnload;
}

namespace {

PDEVICE_OBJECT g_device = nullptr;
UNICODE_STRING g_symlink;
kc_kernel* g_kernel = nullptr;
bool g_mapped = false;
volatile LONG g_attach_count = 0;

uint32_t own_strlen(const char* text) {
    uint32_t length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

/* Appends one line to the test log; best effort, never fails the caller. */
void KcLog(const char* text) {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, KC_TEST_LOG_PATH);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE handle = nullptr;
    IO_STATUS_BLOCK status_block;
    NTSTATUS status = ZwCreateFile(
        &handle, FILE_APPEND_DATA | SYNCHRONIZE, &attributes, &status_block,
        nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr, 0);
    if (!NT_SUCCESS(status)) {
        return;
    }
    char line[320];
    RtlStringCchCopyA(line, RTL_NUMBER_OF(line), text);
    RtlStringCchCatA(line, RTL_NUMBER_OF(line), "\r\n");
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    FILE_STANDARD_INFORMATION info;
    if (NT_SUCCESS(ZwQueryInformationFile(handle, &status_block, &info,
                                          sizeof(info),
                                          FileStandardInformation))) {
        offset = info.EndOfFile;
    }
    ZwWriteFile(handle, nullptr, nullptr, nullptr, &status_block, line,
                own_strlen(line), &offset, nullptr);
    ZwClose(handle);
}

void KcLogStatus(const char* prefix, int32_t value) {
    char line[320];
    RtlStringCchPrintfA(line, RTL_NUMBER_OF(line), "%s %ld", prefix,
                        static_cast<long>(value));
    KcLog(line);
}

/* ----------------------------- handlers ------------------------------ */

kc_status HandlerEcho(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                      void* out, uint32_t* out_cap, uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    if (in_len > *out_cap) {
        return KC_ERR_PARAM;
    }
    if (in_len != 0) {
        RtlCopyMemory(out, in, in_len);
    }
    *out_len = in_len;
    return KC_OK;
}

kc_status HandlerDelay(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                       void* out, uint32_t* out_cap, uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    UNREFERENCED_PARAMETER(out);
    UNREFERENCED_PARAMETER(out_cap);
    if (in_len < sizeof(uint32_t)) {
        return KC_ERR_PARAM;
    }
    uint32_t milliseconds = *static_cast<const uint32_t*>(in);
    if (milliseconds > 5000) {
        milliseconds = 5000;
    }
    LARGE_INTEGER interval;
    interval.QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000ll;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    *out_len = 0;
    return KC_OK;
}

kc_status HandlerError(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                       void* out, uint32_t* out_cap, uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    UNREFERENCED_PARAMETER(in);
    UNREFERENCED_PARAMETER(in_len);
    UNREFERENCED_PARAMETER(out);
    UNREFERENCED_PARAMETER(out_cap);
    *out_len = 0;
    return KC_ERR_HANDLER;
}

/* Intentional fault: proves bvmenv detects a real BSOD, and that no *other*
 * e2e case ever reaches this path. */
kc_status HandlerCrash(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                       void* out, uint32_t* out_cap, uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    UNREFERENCED_PARAMETER(in);
    UNREFERENCED_PARAMETER(in_len);
    UNREFERENCED_PARAMETER(out);
    UNREFERENCED_PARAMETER(out_cap);
    UNREFERENCED_PARAMETER(out_len);
    KcLog("handler_crash: triggering deliberate kernel fault");
    *static_cast<volatile uint32_t*>(reinterpret_cast<void*>(0x10)) = 0xDEAD;
    return KC_OK;
}

kc_status HandlerEmit(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                      void* out, uint32_t* out_cap, uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    UNREFERENCED_PARAMETER(out);
    UNREFERENCED_PARAMETER(out_cap);
    if (in_len < sizeof(uint16_t)) {
        return KC_ERR_PARAM;
    }
    const uint16_t event_op = *static_cast<const uint16_t*>(in);
    *out_len = 0;
    return kc_kernel_emit(g_kernel, event_op,
                          static_cast<const uint8_t*>(in) + sizeof(uint16_t),
                          in_len - sizeof(uint16_t));
}

kc_status HandlerHugeReply(void* ctx, uint16_t op, const void* in,
                           uint32_t in_len, void* out, uint32_t* out_cap,
                           uint32_t* out_len) {
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(op);
    UNREFERENCED_PARAMETER(in);
    UNREFERENCED_PARAMETER(in_len);
    UNREFERENCED_PARAMETER(out);
    *out_len =
        *out_cap + 1; /* the transport must turn this into KC_ERR_INTERNAL */
    return KC_OK;
}

NTSTATUS RegisterHandlers(kc_kernel* kernel) {
    kc_status status =
        kc_kernel_register(kernel, KC_TOp_ECHO, HandlerEcho, nullptr);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_register(kernel, KC_TOp_DELAY, HandlerDelay, nullptr);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_register(kernel, KC_TOp_ERROR, HandlerError, nullptr);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_register(kernel, KC_TOp_CRASH, HandlerCrash, nullptr);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_register(kernel, KC_TOp_EMIT, HandlerEmit, nullptr);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_register(kernel, KC_TOp_REPLY_HUGE, HandlerHugeReply,
                                nullptr);
    return status == KC_OK ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

void OnPeerGone(void* context) {
    UNREFERENCED_PARAMETER(context);
    KcLog("peer_gone: callback entered on the worker thread");
    kc_kernel* kernel = g_kernel;
    g_kernel = nullptr;
    if (kernel != nullptr) {
        kc_kernel_destroy(kernel); /* deferred: we run on the worker thread */
        KcLog("peer_gone: kc_kernel_destroy requested; worker will free pools");
    }
}

NTSTATUS StartKernel(const kc_bootstrap* boot) {
    if (g_kernel != nullptr) {
        return STATUS_ALREADY_REGISTERED;
    }
    kc_kernel_config config;
    RtlZeroMemory(&config, sizeof(config));
    config.max_payload = KC_MAX_PAYLOAD;
    config.poll_spin_us = KC_DEFAULT_POLL_SPIN_US;
    config.poll_idle_us = KC_DEFAULT_POLL_IDLE_US;
    config.poll_idle_max_us = KC_DEFAULT_POLL_IDLE_MAX_US;
    config.watchdog_ms = KC_DEFAULT_WATCHDOG_MS;
    config.flags = KC_KFLAG_EVENTS;
    config.on_peer_gone = OnPeerGone;
    config.ctx = nullptr;

    kc_kernel* kernel = nullptr;
    kc_status status = kc_kernel_create(boot, &config, &kernel);
    if (status != KC_OK) {
        KcLogStatus("start: kc_kernel_create failed", status);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(RegisterHandlers(kernel))) {
        kc_kernel_destroy(kernel);
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_start(kernel);
    if (status != KC_OK) {
        kc_kernel_destroy(kernel);
        return STATUS_UNSUCCESSFUL;
    }
    g_kernel = kernel;
    InterlockedIncrement(&g_attach_count);
    KcLogStatus("start: kchannel started, attach_count",
                InterlockedCompareExchange(&g_attach_count, 0, 0));
    return STATUS_SUCCESS;
}

} /* namespace */

/* --------------------------- SCM test path --------------------------- */

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS HandleIoctl(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG input_length =
        stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_length =
        stack->Parameters.DeviceIoControl.OutputBufferLength;
    void* buffer = irp->AssociatedIrp.SystemBuffer;
    ULONG information = 0;
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
        case KC_TEST_IOCTL_ATTACH: {
            if (buffer == nullptr || input_length < sizeof(kc_bootstrap)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = StartKernel(static_cast<const kc_bootstrap*>(buffer));
            break;
        }
        case KC_TEST_IOCTL_SECOND_ATTACH: {
            if (buffer == nullptr || input_length < sizeof(kc_bootstrap)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            kc_kernel* rejected = nullptr;
            const kc_status result = kc_kernel_create(
                static_cast<const kc_bootstrap*>(buffer), nullptr, &rejected);
            if (output_length >= sizeof(kc_test_result)) {
                kc_test_result* response = static_cast<kc_test_result*>(buffer);
                response->status = static_cast<uint32_t>(result);
                response->reserved = 0;
                information = sizeof(kc_test_result);
            }
            status = STATUS_SUCCESS;
            break;
        }
        case KC_TEST_IOCTL_STATE: {
            if (output_length < sizeof(kc_test_state) || buffer == nullptr) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            kc_test_state* state = static_cast<kc_test_state*>(buffer);
            RtlZeroMemory(state, sizeof(*state));
            state->state = g_kernel != nullptr ? kc_kernel_state(g_kernel)
                                               : KC_STATE_EMPTY;
            state->peer_pid =
                g_kernel != nullptr ? kc_kernel_peer_pid(g_kernel) : 0;
            state->attach_id =
                g_kernel != nullptr ? kc_kernel_attach_id(g_kernel) : 0;
            information = sizeof(*state);
            break;
        }
        case KC_TEST_IOCTL_EMIT: {
            if (buffer == nullptr || input_length < sizeof(kc_test_emit) ||
                g_kernel == nullptr) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            const kc_test_emit* request =
                static_cast<const kc_test_emit*>(buffer);
            if (request->len > input_length - sizeof(kc_test_emit)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            const kc_status result = kc_kernel_emit(
                g_kernel, request->op,
                reinterpret_cast<const uint8_t*>(buffer) + sizeof(kc_test_emit),
                request->len);
            if (output_length >= sizeof(kc_test_result)) {
                kc_test_result* response = static_cast<kc_test_result*>(buffer);
                response->status = static_cast<uint32_t>(result);
                response->reserved = 0;
                information = sizeof(kc_test_result);
            }
            break;
        }
        case KC_TEST_IOCTL_DESTROY: {
            kc_kernel* kernel = g_kernel;
            g_kernel = nullptr;
            if (kernel != nullptr) {
                kc_kernel_destroy(kernel);
            }
            if (output_length >= sizeof(kc_test_result)) {
                kc_test_result* response = static_cast<kc_test_result*>(buffer);
                response->status = KC_OK;
                response->reserved = 0;
                information = sizeof(kc_test_result);
            }
            break;
        }
        case KC_TEST_IOCTL_PERF_STATS: {
            if (output_length < sizeof(kc_test_perf) || buffer == nullptr) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            kc_test_perf* performance = static_cast<kc_test_perf*>(buffer);
            RtlZeroMemory(performance, sizeof(*performance));
            performance->worker_cycles = kc_kernel_worker_busy_cycles(g_kernel);
            performance->cycle_frequency = kc_kernel_tsc_hz();
            information = sizeof(*performance);
            break;
        }
        case KC_TEST_IOCTL_STOP_RESTART: {
            if (output_length < sizeof(kc_test_stop) || buffer == nullptr) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            kc_test_stop* response = static_cast<kc_test_stop*>(buffer);
            RtlZeroMemory(response, sizeof(*response));
            if (g_kernel == nullptr) {
                response->status = KC_ERR_STATE;
                information = sizeof(*response);
                break;
            }
            LARGE_INTEGER start;
            LARGE_INTEGER end;
            start = KeQueryPerformanceCounter(nullptr);
            kc_kernel_stop(g_kernel);
            end = KeQueryPerformanceCounter(nullptr);
            LARGE_INTEGER frequency;
            frequency = KeQueryPerformanceCounter(&frequency);
            const uint64_t ticks =
                static_cast<uint64_t>(end.QuadPart - start.QuadPart);
            response->stop_ns = (ticks * 1000000000ull) /
                                static_cast<uint64_t>(frequency.QuadPart);
            response->status = kc_kernel_start(g_kernel);
            information = sizeof(*response);
            break;
        }
        case KC_TEST_IOCTL_DRIVER_OP: {
            if (buffer == nullptr || input_length < sizeof(kc_test_driver_op)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            kc_test_driver_op* request =
                static_cast<kc_test_driver_op*>(buffer);
            if (request->op == KC_TDRVOP_PING_THREAD) {
                request->value = g_kernel != nullptr ? kc_kernel_state(g_kernel)
                                                     : KC_STATE_EMPTY;
            }
            information = sizeof(*request);
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

void KcTestUnload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    KcLog("unload: driver unload entered");
    kc_kernel* kernel = g_kernel;
    g_kernel = nullptr;
    if (kernel != nullptr) {
        kc_kernel_destroy(kernel);
        KcLog(
            "unload: kc_kernel_destroy completed (MDL/pools/thread released)");
    }
    if (g_device != nullptr) {
        IoDeleteSymbolicLink(&g_symlink);
        IoDeleteDevice(g_device);
        g_device = nullptr;
    }
    KcLog("unload: device and symbolic link deleted, unload complete");
}

NTSTATUS CreateScmDevice(PDRIVER_OBJECT driver) {
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, KC_TEST_DEVICE_NAME);
    PDEVICE_OBJECT device = nullptr;
    NTSTATUS status =
        IoCreateDevice(driver, 0, &device_name, KC_TEST_DEVICE_TYPE,
                       FILE_DEVICE_UNKNOWN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNICODE_STRING device_name_for_link;
    RtlInitUnicodeString(&device_name_for_link, KC_TEST_DEVICE_NAME);
    RtlInitUnicodeString(&g_symlink, KC_TEST_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&g_symlink, &device_name_for_link);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    driver->Flags |= DO_BUFFERED_IO;
    driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctl;
    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    driver->DriverUnload = KcTestUnload;
    g_device = device;
    return STATUS_SUCCESS;
}

/* ---------------------------- entry point ---------------------------- */

extern "C" NTSTATUS DriverEntry(PVOID entry_parameter, PVOID registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    /* Manual-map path: the entry parameter is a kernel copy of kc_bootstrap. */
    if (entry_parameter != nullptr &&
        *static_cast<const uint32_t*>(entry_parameter) == KC_BOOTSTRAP_MAGIC) {
        g_mapped = true;
        KcLog(
            "entry: manual-map path (bootstrap in entry parameter, "
            "no device created)");
        const NTSTATUS status =
            StartKernel(static_cast<const kc_bootstrap*>(entry_parameter));
        KcLogStatus("entry: mapped StartKernel status", status);
        return status;
    }

    KcLog("entry: SCM path (test-only device for bootstrap delivery)");
    PDRIVER_OBJECT driver = static_cast<PDRIVER_OBJECT>(entry_parameter);
    const NTSTATUS status = CreateScmDevice(driver);
    KcLogStatus("entry: CreateScmDevice status", status);
    return status;
}
