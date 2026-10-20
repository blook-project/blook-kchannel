/*
 * kchannel-ctl - host-side driver for the blook-kchannel e2e suite.
 *
 * Commands (all print one JSON object on stdout):
 *   state       --device <path>                     driver kc_state snapshot
 *   attach-test --device <path> [--region N]        functional test matrix
 *   map-test    --mapper <path> --image <sys>       functional matrix (mapped)
 *   latency     --device|--mapper... [--count N]    round-trip statistics
 *   idle-cpu    --device|--mapper... [--seconds N]  system CPU during idle
 *   wrong-key   --device <path>                     expect KC_ERR_AUTH
 *   second-attach --device <path>                   expect KC_ERR_ALREADY
 *   loader-kill (--device | --mapper/--image)       spawn child, hard-terminate
 *   trace-scan  [--mapped]                          device/registry/module
 * probe event-test  --device|--mapper...                kernel -> user event
 *   crash       --device|--mapper...                deliberate BSOD (harness)
 *   loader-child ...                                child used by loader-kill
 *
 * Exit code is non-zero when a check fails, so the e2e script can gate on it.
 */
#include <windows.h>

#include <winternl.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cwchar>

#define KC_DIRECTORY_QUERY 0x0001

#include <blook/kchannel.h>

#include "guest/common/kcmapload_ioctl.h"
#include "guest/common/kchannel_test_ioctl.h"

extern "C" {
NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN,
                                      PULONG, PULONG);
void NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
}

/* winternl.h does not describe these layouts; they are stable and documented
 * by the reversed NT API. */
typedef struct _KC_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KC_OBJECT_DIRECTORY_INFORMATION;

typedef struct _KC_SYSTEM_MODULE {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    USHORT Id;
    USHORT Rank;
    USHORT LoadCount;
    USHORT NameOffset;
    CHAR Name[256];
} KC_SYSTEM_MODULE;

typedef struct _KC_SYSTEM_MODULES {
    ULONG NumberOfModules;
    KC_SYSTEM_MODULE Modules[1];
} KC_SYSTEM_MODULES;

namespace {

struct Options {
    std::string command;
    std::wstring device = KC_TEST_WIN32_NAME;
    std::wstring mapper = KC_MAPLOAD_WIN32_NAME;
    std::wstring image;
    std::string cipher = "chacha20";
    uint32_t region = 0x40000;
    uint32_t mode = KC_MODE_MAPPED;
    uint32_t count = 2000;
    uint32_t seconds = 10;
    uint32_t timeout_ms = 5000;
    bool json = true;
};

uint32_t g_failures = 0;

uint64_t now_ns() {
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return static_cast<uint64_t>(
        (static_cast<double>(counter.QuadPart) * 1000000000.0) /
        static_cast<double>(frequency.QuadPart));
}

void json_escape(const std::string& input, std::string* output) {
    for (char c : input) {
        if (c == '"' || c == '\\') {
            output->push_back('\\');
        }
        output->push_back(c);
    }
}

std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr,
                                         0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), size,
                        nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

void print(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

HANDLE open_device(const std::wstring& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    return handle == INVALID_HANDLE_VALUE ? nullptr : handle;
}

bool device_ioctl(HANDLE device, DWORD code, void* in, DWORD in_size, void* out,
                  DWORD out_size, DWORD* returned) {
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(device, code, in, in_size, out, out_size,
                                    &bytes, nullptr);
    if (returned != nullptr) {
        *returned = bytes;
    }
    return ok != 0;
}

struct Session {
    kc_client* client = nullptr;
    HANDLE device = nullptr;
    kc_bootstrap boot{};

    ~Session() {
        if (client != nullptr) {
            kc_detach(client);
            client = nullptr;
        }
        if (device != nullptr) {
            CloseHandle(device);
            device = nullptr;
        }
    }
};

bool open_test_device(Session* session, const std::wstring& path) {
    session->device = open_device(path);
    if (session->device == nullptr) {
        print("{\"ok\":false,\"error\":\"open device failed\"}\n");
        return false;
    }
    return true;
}

bool attach_client(Session* session, const Options& options) {
    kc_attach_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.region_size = options.region;
    opts.mode = options.mode;
    opts.cipher =
        (options.cipher == "aes") ? KC_CIPHER_AES128CTR : KC_CIPHER_CHACHA20;
    opts.flags = 0;
    const kc_status status = kc_attach(&opts, &session->client);
    if (status != KC_OK) {
        print("{\"ok\":false,\"error\":\"kc_attach %s\"}\n",
              kc_status_str(status));
        return false;
    }
    if (kc_get_bootstrap(session->client, &session->boot) != KC_OK) {
        print("{\"ok\":false,\"error\":\"kc_get_bootstrap\"}\n");
        return false;
    }
    return true;
}

/* SCM path: hand the bootstrap to the driver through the test-only device. */
bool attach_scm(Session* session, const Options& options, bool finish) {
    if (!open_test_device(session, options.device)) {
        return false;
    }
    if (!attach_client(session, options)) {
        return false;
    }
    if (!device_ioctl(session->device, KC_TEST_IOCTL_ATTACH, &session->boot,
                      sizeof(session->boot), nullptr, 0, nullptr)) {
        print("{\"ok\":false,\"error\":\"IOCTL_ATTACH failed\"}\n");
        return false;
    }
    if (finish) {
        const kc_status status =
            kc_attach_finish(session->client, options.timeout_ms);
        if (status != KC_OK) {
            print("{\"ok\":false,\"error\":\"attach_finish %s\"}\n",
                  kc_status_str(status));
            return false;
        }
    }
    return true;
}

/* Manual-map path: map the image with the bootstrap as the entry parameter. */
bool attach_mapped(Session* session, const Options& options) {
    if (options.image.empty()) {
        print("{\"ok\":false,\"error\":\"--image required\"}\n");
        return false;
    }
    HANDLE image_file =
        CreateFileW(options.image.c_str(), GENERIC_READ, FILE_SHARE_READ,
                    nullptr, OPEN_EXISTING, 0, nullptr);
    if (image_file == INVALID_HANDLE_VALUE) {
        print("{\"ok\":false,\"error\":\"open image failed\"}\n");
        return false;
    }
    LARGE_INTEGER image_size;
    GetFileSizeEx(image_file, &image_size);
    std::vector<uint8_t> image(static_cast<size_t>(image_size.QuadPart));
    DWORD read = 0;
    const bool read_ok =
        ReadFile(image_file, image.data(), static_cast<DWORD>(image.size()),
                 &read, nullptr) != 0 &&
        read == image.size();
    CloseHandle(image_file);
    if (!read_ok) {
        print("{\"ok\":false,\"error\":\"read image failed\"}\n");
        return false;
    }

    session->device = open_device(options.mapper);
    if (session->device == nullptr) {
        print("{\"ok\":false,\"error\":\"open mapper failed\"}\n");
        return false;
    }
    if (!attach_client(session, options)) {
        return false;
    }

    std::vector<uint8_t> request(sizeof(kc_mapload_request) + image.size());
    kc_mapload_request* header =
        reinterpret_cast<kc_mapload_request*>(request.data());
    header->magic = KC_MAPLOAD_REQUEST_MAGIC;
    header->flags = 0;
    header->image_size = image.size();
    header->boot = session->boot;
    memcpy(request.data() + sizeof(kc_mapload_request), image.data(),
           image.size());

    kc_mapload_result result{};
    DWORD returned = 0;
    const bool ioctl_ok = device_ioctl(
        session->device, KC_MAPLOAD_IOCTL_LOAD, request.data(),
        static_cast<DWORD>(request.size()), &result, sizeof(result), &returned);
    if (!ioctl_ok || result.status != KC_MAPLOAD_OK) {
        print(
            "{\"ok\":false,\"error\":\"map failed\",\"status\":%u,"
            "\"entry\":%d}\n",
            result.status, static_cast<int32_t>(result.entry_status));
        return false;
    }
    const kc_status status =
        kc_attach_finish(session->client, options.timeout_ms);
    if (status != KC_OK) {
        print("{\"ok\":false,\"error\":\"attach_finish %s\"}\n",
              kc_status_str(status));
        return false;
    }
    return true;
}

bool attach_any(Session* session, const Options& options) {
    if (!options.image.empty()) {
        return attach_mapped(session, options);
    }
    return attach_scm(session, options, true);
}

struct CheckResult {
    const char* name;
    kc_status expected;
    kc_status actual;
};

void report_checks(const std::vector<CheckResult>& checks,
                   const char* extra_json = nullptr) {
    uint32_t failed = 0;
    for (const CheckResult& check : checks) {
        if (check.actual != check.expected) {
            ++failed;
        }
    }
    g_failures += failed;
    print("{\"ok\":%s,\"checks\":[", failed == 0 ? "true" : "false");
    for (size_t i = 0; i < checks.size(); ++i) {
        print(
            "%s{\"name\":\"%s\",\"expected\":\"%s\",\"actual\":\"%s\","
            "\"ok\":%s}",
            i == 0 ? "" : ",", checks[i].name,
            kc_status_str(checks[i].expected), kc_status_str(checks[i].actual),
            checks[i].actual == checks[i].expected ? "true" : "false");
    }
    print("]%s%s}\n", extra_json != nullptr ? "," : "",
          extra_json != nullptr ? extra_json : "");
}

std::vector<CheckResult> run_functional_tests(kc_client* client,
                                              uint32_t max_payload) {
    std::vector<CheckResult> checks;

    checks.push_back({"ping", KC_OK, kc_ping(client, 2000)});

    char echo_out[64] = {0};
    uint32_t echo_len = 0;
    checks.push_back({"echo_small", KC_OK,
                      kc_call(client, KC_TOp_ECHO, "hello kchannel", 15,
                              echo_out, sizeof(echo_out), &echo_len, 2000)});
    checks.push_back({"echo_empty", KC_OK,
                      kc_call(client, KC_TOp_ECHO, nullptr, 0, nullptr, 0,
                              &echo_len, 2000)});

    std::vector<uint8_t> large(max_payload);
    for (uint32_t i = 0; i < max_payload; ++i) {
        large[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    std::vector<uint8_t> large_out(max_payload, 0);
    const kc_status large_status =
        kc_call(client, KC_TOp_ECHO, large.data(), max_payload,
                large_out.data(), max_payload, &echo_len, 10000);
    const bool large_ok =
        large_status == KC_OK && echo_len == max_payload &&
        memcmp(large.data(), large_out.data(), max_payload) == 0;
    checks.push_back({"echo_large", KC_OK, large_ok ? KC_OK : KC_ERR_INTERNAL});

    uint32_t delay_ms = 20;
    checks.push_back({"delay_20ms", KC_OK,
                      kc_call(client, KC_TOp_DELAY, &delay_ms, sizeof(delay_ms),
                              nullptr, 0, nullptr, 5000)});
    delay_ms = 200;
    checks.push_back({"delay_200ms", KC_OK,
                      kc_call(client, KC_TOp_DELAY, &delay_ms, sizeof(delay_ms),
                              nullptr, 0, nullptr, 5000)});
    checks.push_back(
        {"handler_error", KC_ERR_HANDLER,
         kc_call(client, KC_TOp_ERROR, nullptr, 0, nullptr, 0, nullptr, 2000)});
    checks.push_back({"huge_reply", KC_ERR_INTERNAL,
                      kc_call(client, KC_TOp_REPLY_HUGE, nullptr, 0, nullptr, 0,
                              nullptr, 2000)});
    checks.push_back(
        {"unknown_opcode", KC_ERR_NOT_FOUND,
         kc_call(client, 0x8123, nullptr, 0, nullptr, 0, nullptr, 2000)});
    return checks;
}

int command_state(const Options& options) {
    HANDLE device = open_device(options.device);
    if (device == nullptr) {
        print("{\"ok\":false,\"error\":\"open device failed\"}\n");
        return 1;
    }
    kc_test_state state{};
    DWORD returned = 0;
    const bool ok = device_ioctl(device, KC_TEST_IOCTL_STATE, nullptr, 0,
                                 &state, sizeof(state), &returned);
    CloseHandle(device);
    if (!ok) {
        print("{\"ok\":false,\"error\":\"IOCTL_STATE failed\"}\n");
        return 1;
    }
    print(
        "{\"ok\":true,\"state\":%u,\"error\":%u,\"peer_pid\":%u,"
        "\"attach_id\":%llu}\n",
        state.state, state.error, state.peer_pid,
        static_cast<unsigned long long>(state.attach_id));
    return 0;
}

int command_functional(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    const uint32_t max_payload = options.region >= 0x40000
                                     ? KC_MAX_PAYLOAD - KC_CALL_PREFIX_SIZE
                                     : 16384;
    auto checks = run_functional_tests(session.client, max_payload);
    char extra[160];
    snprintf(extra, sizeof(extra), "\"mode\":\"%s\",\"attach_id\":%llu",
             options.image.empty() ? "scm" : "mapped",
             static_cast<unsigned long long>(kc_attach_id(session.client)));
    report_checks(checks, extra);
    return g_failures == 0 ? 0 : 1;
}

int command_latency(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    /* Warm up. */
    for (uint32_t i = 0; i < 64; ++i) {
        (void)kc_ping(session.client, 3000);
    }
    std::vector<uint64_t> samples;
    samples.reserve(options.count);
    char payload[64];
    memset(payload, 0x5A, sizeof(payload));
    char reply[64] = {0};
    uint32_t reply_len = 0;
    for (uint32_t i = 0; i < options.count; ++i) {
        const uint64_t start = now_ns();
        const kc_status status =
            kc_call(session.client, KC_TOp_ECHO, payload, sizeof(payload),
                    reply, sizeof(reply), &reply_len, 3000);
        const uint64_t elapsed = now_ns() - start;
        if (status != KC_OK) {
            print(
                "{\"ok\":false,\"error\":\"call failed at %u\","
                "\"status\":\"%s\"}\n",
                i, kc_status_str(status));
            return 1;
        }
        samples.push_back(elapsed);
    }
    /* Cold samples: one second of idleness exercises the idle backoff. */
    Sleep(1000);
    std::vector<uint64_t> cold;
    for (uint32_t i = 0; i < 20; ++i) {
        const uint64_t start = now_ns();
        (void)kc_ping(session.client, 3000);
        cold.push_back(now_ns() - start);
        Sleep(100);
    }
    auto percentile = [](std::vector<uint64_t>& values, double p) {
        if (values.empty()) {
            return static_cast<uint64_t>(0);
        }
        std::vector<uint64_t> sorted = values;
        std::sort(sorted.begin(), sorted.end());
        size_t index = static_cast<size_t>(p * (sorted.size() - 1));
        return sorted[index];
    };
    std::vector<uint64_t> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    const uint64_t median = sorted[sorted.size() / 2];
    const uint64_t p90 = percentile(samples, 0.90);
    const uint64_t p99 = percentile(samples, 0.99);
    const uint64_t minimum = sorted.front();
    const uint64_t maximum = sorted.back();
    std::vector<uint64_t> cold_sorted = cold;
    std::sort(cold_sorted.begin(), cold_sorted.end());
    const uint64_t cold_median = cold_sorted[cold_sorted.size() / 2];
    print(
        "{\"ok\":true,\"mode\":\"%s\",\"cipher\":\"%s\",\"region\":%u,"
        "\"calls\":%u,\"median_ns\":%llu,\"p90_ns\":%llu,\"p99_ns\":%llu,"
        "\"min_ns\":%llu,\"max_ns\":%llu,\"cold_median_ns\":%llu}\n",
        options.image.empty() ? "scm" : "mapped", options.cipher.c_str(),
        options.region, options.count, static_cast<unsigned long long>(median),
        static_cast<unsigned long long>(p90),
        static_cast<unsigned long long>(p99),
        static_cast<unsigned long long>(minimum),
        static_cast<unsigned long long>(maximum),
        static_cast<unsigned long long>(cold_median));
    return 0;
}

int command_idle_cpu(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    FILETIME idle{};
    FILETIME kernel{};
    FILETIME user{};
    GetSystemTimes(&idle, &kernel, &user);
    auto to_u64 = [](const FILETIME& value) {
        ULARGE_INTEGER integer;
        integer.LowPart = value.dwLowDateTime;
        integer.HighPart = value.dwHighDateTime;
        return integer.QuadPart;
    };
    const uint64_t idle_start = to_u64(idle);
    const uint64_t total_start = to_u64(kernel) + to_u64(user);
    Sleep(options.seconds * 1000);
    GetSystemTimes(&idle, &kernel, &user);
    const uint64_t idle_delta = to_u64(idle) - idle_start;
    const uint64_t total_delta = to_u64(kernel) + to_u64(user) - total_start;
    const double busy_percent =
        total_delta == 0
            ? 0.0
            : (100.0 * static_cast<double>(total_delta - idle_delta) /
               static_cast<double>(total_delta));
    print(
        "{\"ok\":true,\"seconds\":%u,\"system_busy_percent\":%.4f,"
        "\"mode\":\"%s\"}\n",
        options.seconds, busy_percent,
        options.image.empty() ? "scm" : "mapped");
    (void)kc_ping(session.client, 2000);
    return 0;
}

int command_wrong_key(const Options& options) {
    Session session;
    if (!attach_scm(&session, options, false)) {
        return 1;
    }
    /* Corrupt the bootstrap we hand to the kernel; the client keeps the
     * original key, so the session_tag comparison must fail. */
    kc_bootstrap corrupted = session.boot;
    corrupted.session_key[0] ^= 0xFF;
    corrupted.session_key[31] ^= 0x0F;
    if (!device_ioctl(session.device, KC_TEST_IOCTL_ATTACH, &corrupted,
                      sizeof(corrupted), nullptr, 0, nullptr)) {
        print("{\"ok\":false,\"error\":\"IOCTL_ATTACH failed\"}\n");
        return 1;
    }
    const kc_status status = kc_attach_finish(session.client, 3000);
    print("{\"ok\":%s,\"expected\":\"KC_ERR_AUTH\",\"actual\":\"%s\"}\n",
          status == KC_ERR_AUTH ? "true" : "false", kc_status_str(status));
    /* The driver now holds a broken session; clean it up. */
    (void)device_ioctl(session.device, KC_TEST_IOCTL_DESTROY, nullptr, 0,
                       nullptr, 0, nullptr);
    return status == KC_ERR_AUTH ? 0 : 1;
}

int command_second_attach(const Options& options) {
    Session first;
    if (!attach_scm(&first, options, true)) {
        return 1;
    }
    Session second;
    if (!attach_scm(&second, options, false)) {
        return 1;
    }
    kc_test_result result{};
    DWORD returned = 0;
    const bool ioctl_ok =
        device_ioctl(second.device, KC_TEST_IOCTL_SECOND_ATTACH, &second.boot,
                     sizeof(second.boot), &result, sizeof(result), &returned);
    const kc_status finish_status = kc_attach_finish(second.client, 1500);
    const bool ok = ioctl_ok && (result.status == KC_ERR_ALREADY ||
                                 finish_status == KC_ERR_ALREADY);
    print(
        "{\"ok\":%s,\"expected\":\"KC_ERR_ALREADY\","
        "\"driver_status\":\"%s\",\"client_status\":\"%s\"}\n",
        ok ? "true" : "false",
        kc_status_str(static_cast<kc_status>(result.status)),
        kc_status_str(finish_status));
    (void)device_ioctl(first.device, KC_TEST_IOCTL_DESTROY, nullptr, 0, nullptr,
                       0, nullptr);
    return ok ? 0 : 1;
}

int command_event(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    static volatile LONG event_count = 0;
    static uint16_t last_op = 0;
    static uint32_t last_len = 0;
    event_count = 0;
    kc_set_event_handler(
        session.client,
        [](void* ctx, uint16_t op, const void* data, uint32_t len) {
            (void)ctx;
            (void)data;
            InterlockedIncrement(&event_count);
            last_op = op;
            last_len = len;
        },
        nullptr);
    uint8_t in[8] = {0};
    const uint16_t event_op = 0x9001;
    memcpy(in, &event_op, sizeof(event_op));
    memcpy(in + sizeof(event_op), "evt", 3);
    const kc_status status =
        kc_call(session.client, KC_TOp_EMIT, in, sizeof(event_op) + 3, nullptr,
                0, nullptr, 2000);
    (void)kc_ping(session.client, 2000); /* drains the event */
    const bool ok = status == KC_OK && event_count > 0 && last_op == event_op &&
                    last_len == 3;
    print(
        "{\"ok\":%s,\"emit_status\":\"%s\",\"events\":%ld,"
        "\"event_op\":%u,\"event_len\":%u}\n",
        ok ? "true" : "false", kc_status_str(status), event_count, last_op,
        last_len);
    return ok ? 0 : 1;
}

int command_loader_kill(const Options& options) {
    /* Spawn ourselves as a child that attaches and then dies without detach. */
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring child = L"\"";
    child += self;
    child += L"\" loader-child";
    if (!options.image.empty()) {
        child += L" --image \"";
        child += options.image;
        child += L"\" --mapper \"";
        child += options.mapper;
        child += L"\"";
    } else {
        child += L" --device \"";
        child += options.device;
        child += L"\"";
    }
    child += L" --region ";
    child += std::to_wstring(options.region);

    STARTUPINFOW startup;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, child.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &startup, &process)) {
        print("{\"ok\":false,\"error\":\"CreateProcess failed\"}\n");
        return 1;
    }
    WaitForSingleObject(process.hProcess, 15000);
    DWORD exit_code = 0;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    /* Give the kernel watchdog time to notice and tear down. */
    Sleep(options.image.empty() ? 7000 : 7000);

    bool recovered = true;
    kc_test_state state{};
    if (options.image.empty()) {
        HANDLE device = open_device(options.device);
        if (device != nullptr) {
            DWORD returned = 0;
            if (device_ioctl(device, KC_TEST_IOCTL_STATE, nullptr, 0, &state,
                             sizeof(state), &returned)) {
                recovered = state.state == KC_STATE_EMPTY;
            } else {
                recovered = false;
            }
            CloseHandle(device);
        } else {
            recovered = false;
        }
        /* The driver must accept a fresh attach after the dead peer. */
        if (recovered) {
            Options retry = options;
            Session session;
            recovered = attach_scm(&session, retry, true) &&
                        kc_ping(session.client, 2000) == KC_OK;
        }
    }
    print(
        "{\"ok\":%s,\"child_exit\":%lu,\"driver_state_after_watchdog\":%u,"
        "\"recovered\":%s}\n",
        recovered ? "true" : "false", static_cast<unsigned long>(exit_code),
        state.state, recovered ? "true" : "false");
    return recovered ? 0 : 1;
}

int command_loader_child(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    print("{\"ok\":true,\"note\":\"child attached, terminating abruptly\"}\n");
    fflush(stdout);
    Sleep(200);
    /* Hard death: no detach, no BYE, leaked section mapping. */
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
    return 0;
}

int command_crash(const Options& options) {
    Session session;
    if (!attach_any(&session, options)) {
        return 1;
    }
    print("{\"ok\":true,\"note\":\"invoking deliberate kernel fault\"}\n");
    fflush(stdout);
    (void)kc_call(session.client, KC_TOp_CRASH, nullptr, 0, nullptr, 0, nullptr,
                  5000);
    print("{\"ok\":false,\"note\":\"kernel survived the crash handler\"}\n");
    return 1;
}

/* --------------------------- trace scanning --------------------------- */

struct NamedObjectScan {
    uint32_t count = 0;
    bool matched = false;
};

bool scan_named_objects(NamedObjectScan* result) {
    UNICODE_STRING directory_name;
    RtlInitUnicodeString(&directory_name, L"\\BaseNamedObjects");
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &directory_name,
                               OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE directory = nullptr;
    if (!NT_SUCCESS(NtOpenDirectoryObject(&directory, KC_DIRECTORY_QUERY,
                                          &attributes))) {
        return false;
    }
    std::vector<uint8_t> buffer(64 * 1024);
    ULONG context = 0;
    ULONG returned = 0;
    for (;;) {
        const NTSTATUS status = NtQueryDirectoryObject(
            directory, buffer.data(), static_cast<ULONG>(buffer.size()), FALSE,
            TRUE, &context, &returned);
        if (status == 0x80000005L /* STATUS_NO_MORE_ENTRIES */ ||
            returned == 0) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            break;
        }
        for (ULONG offset = 0; offset < returned;) {
            const auto* entry =
                reinterpret_cast<const KC_OBJECT_DIRECTORY_INFORMATION*>(
                    buffer.data() + offset);
            if (entry->Name.Length == 0) {
                break;
            }
            ++result->count;
            if (entry->Name.Buffer != nullptr &&
                wcsstr(entry->Name.Buffer, L"kchannel") != nullptr) {
                result->matched = true;
            }
            offset += sizeof(KC_OBJECT_DIRECTORY_INFORMATION);
        }
    }
    NtClose(directory);
    return true;
}

struct ModuleScan {
    uint32_t count = 0;
    bool matched = false;
};

bool scan_modules(ModuleScan* result) {
    ULONG size = 1 << 20;
    std::vector<uint8_t> buffer(size);
    ULONG needed = 0;
    NTSTATUS status =
        NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11),
                                 buffer.data(), size, &needed);
    if (status == 0xC0000004L /* STATUS_INFO_LENGTH_MISMATCH */) {
        buffer.resize(needed);
        status =
            NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11),
                                     buffer.data(), needed, &needed);
    }
    if (!NT_SUCCESS(status)) {
        return false;
    }
    const auto* module =
        reinterpret_cast<const KC_SYSTEM_MODULES*>(buffer.data());
    result->count = module->NumberOfModules;
    for (ULONG i = 0; i < module->NumberOfModules; ++i) {
        const char* name = module->Modules[i].Name;
        if (name != nullptr && strstr(name, "kchannel_test") != nullptr) {
            result->matched = true;
        }
    }
    return true;
}

int command_trace_scan(const Options& options) {
    const bool mapped = !options.image.empty();
    bool scm_device_present = false;
    {
        HANDLE device = open_device(options.device);
        scm_device_present = device != nullptr;
        if (device != nullptr) {
            CloseHandle(device);
        }
    }
    bool service_key_present = false;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\kchannel_test", 0,
                      KEY_READ, &key) == ERROR_SUCCESS) {
        service_key_present = true;
        RegCloseKey(key);
    }
    bool mapper_service_present = false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\kcmapload", 0,
                      KEY_READ, &key) == ERROR_SUCCESS) {
        mapper_service_present = true;
        RegCloseKey(key);
    }
    NamedObjectScan named;
    const bool named_ok = scan_named_objects(&named);
    ModuleScan modules;
    const bool modules_ok = scan_modules(&modules);

    bool ok = true;
    if (mapped) {
        /* In the mapped path the test driver must exist in neither the device
         * namespace, nor the registry, nor the loaded module list.  The mapper
         * itself is a test-signed helper and is expected to be present. */
        ok = !scm_device_present && !service_key_present && !named.matched &&
             !modules.matched;
    }
    print(
        "{\"ok\":%s,\"mapped_expectation\":%s,\"device_present\":%s,"
        "\"service_key_present\":%s,\"mapper_service_present\":%s,"
        "\"named_object_scan\":%s,\"named_object_count\":%u,"
        "\"named_object_match\":%s,\"module_scan\":%s,"
        "\"module_count\":%u,\"driver_module_present\":%s}\n",
        ok ? "true" : "false", mapped ? "true" : "false",
        scm_device_present ? "true" : "false",
        service_key_present ? "true" : "false",
        mapper_service_present ? "true" : "false", named_ok ? "true" : "false",
        named.count, named.matched ? "true" : "false",
        modules_ok ? "true" : "false", modules.count,
        modules.matched ? "true" : "false");
    return ok ? 0 : 1;
}

Options parse_options(int argc, char** argv) {
    Options options;
    if (argc > 1) {
        options.command = argv[1];
    }
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        auto next = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for %s\n", name);
                exit(2);
            }
            return argv[++i];
        };
        if (argument == "--device") {
            const char* value = next("--device");
            const int size =
                MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
            options.device.resize(static_cast<size_t>(size));
            MultiByteToWideChar(CP_UTF8, 0, value, -1, options.device.data(),
                                size);
            if (!options.device.empty() && options.device.back() == L'\0') {
                options.device.pop_back();
            }
        } else if (argument == "--mapper") {
            const char* value = next("--mapper");
            const int size =
                MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
            options.mapper.resize(static_cast<size_t>(size));
            MultiByteToWideChar(CP_UTF8, 0, value, -1, options.mapper.data(),
                                size);
            if (!options.mapper.empty() && options.mapper.back() == L'\0') {
                options.mapper.pop_back();
            }
        } else if (argument == "--image") {
            const char* value = next("--image");
            const int size =
                MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
            options.image.resize(static_cast<size_t>(size));
            MultiByteToWideChar(CP_UTF8, 0, value, -1, options.image.data(),
                                size);
            if (!options.image.empty() && options.image.back() == L'\0') {
                options.image.pop_back();
            }
        } else if (argument == "--region") {
            options.region =
                static_cast<uint32_t>(strtoul(next("--region"), nullptr, 0));
        } else if (argument == "--count") {
            options.count =
                static_cast<uint32_t>(strtoul(next("--count"), nullptr, 0));
        } else if (argument == "--seconds") {
            options.seconds =
                static_cast<uint32_t>(strtoul(next("--seconds"), nullptr, 0));
        } else if (argument == "--cipher") {
            options.cipher = next("--cipher");
        } else if (argument == "--mode") {
            const std::string mode = next("--mode");
            options.mode = (mode == "copy") ? KC_MODE_COPY : KC_MODE_MAPPED;
        } else if (argument == "--timeout") {
            options.timeout_ms =
                static_cast<uint32_t>(strtoul(next("--timeout"), nullptr, 0));
        } else {
            fprintf(stderr, "unknown option: %s\n", argument.c_str());
            exit(2);
        }
    }
    return options;
}

} /* namespace */

int main(int argc, char** argv) {
    const Options options = parse_options(argc, argv);
    if (options.command == "state") {
        return command_state(options);
    }
    if (options.command == "attach-test") {
        return command_functional(options);
    }
    if (options.command == "map-test") {
        return command_functional(options);
    }
    if (options.command == "latency") {
        return command_latency(options);
    }
    if (options.command == "idle-cpu") {
        return command_idle_cpu(options);
    }
    if (options.command == "wrong-key") {
        return command_wrong_key(options);
    }
    if (options.command == "second-attach") {
        return command_second_attach(options);
    }
    if (options.command == "loader-kill") {
        return command_loader_kill(options);
    }
    if (options.command == "loader-child") {
        return command_loader_child(options);
    }
    if (options.command == "trace-scan") {
        return command_trace_scan(options);
    }
    if (options.command == "event-test") {
        return command_event(options);
    }
    if (options.command == "crash") {
        return command_crash(options);
    }
    fprintf(stderr,
            "usage: kchannel-ctl <state|attach-test|map-test|latency|idle-cpu|"
            "wrong-key|second-attach|loader-kill|trace-scan|event-test|crash>"
            " [options]\n");
    return 2;
}
