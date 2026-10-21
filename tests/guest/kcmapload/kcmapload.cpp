/*
 * kcmapload.sys - minimal manual-map loader for the blook-kchannel e2e suite.
 *
 * The driver is loaded through the SCM with test signing and exposes a
 * test-only device. The host tool sends a PE image (kchannel_test.sys) plus
 * the kc_bootstrap descriptor; the mapper:
 *   1. validates the PE headers (x64, PE32+, bounded),
 *   2. allocates non-paged executable pool for SizeOfImage,
 *   3. copies headers + sections,
 *   4. applies base relocations,
 *   5. resolves the ntoskrnl import table through MmGetSystemRoutineAddress,
 *   6. calls the mapped DriverEntry with a kernel copy of kc_bootstrap as the
 *      entry parameter.
 *
 * The mapped image is intentionally not unloaded here: proving "unload
 * leaves no residue" for a mapped driver is the job of blook-kdu's mapper.
 * kchannel's own e2e proves the *library* releases its MDL/pools/thread when
 * the loader dies (peer-gone path).
 */
#include <ntifs.h>
#include <ntimage.h> /* IMAGE_NT_HEADERS64 and friends */

#include <blook/kchannel.h>

#include "guest/common/kcmapload_ioctl.h"

#define KC_MAPLOAD_POOL_TAG 'KCLM'

extern "C" {
NTSTATUS DriverEntry(PVOID entry_parameter, PVOID registry_path);
DRIVER_UNLOAD KcMapUnload;
}

namespace {

static uint32_t g_map_stage = 0;

PDEVICE_OBJECT g_device = nullptr;
UNICODE_STRING g_symlink;

void ascii_to_unicode(const char* name, WCHAR* out, uint32_t capacity) {
    uint32_t i = 0;
    while (name[i] != '\0' && i + 1 < capacity) {
        out[i] = static_cast<WCHAR>(static_cast<uint8_t>(name[i]));
        ++i;
    }
    out[i] = L'\0';
}

/* Resolves one imported function by name (ntoskrnl/hal exports). */
PVOID ResolveImport(const char* name) {
    WCHAR wide[256];
    ascii_to_unicode(name, wide, RTL_NUMBER_OF(wide));
    UNICODE_STRING routine;
    RtlInitUnicodeString(&routine, wide);
    return MmGetSystemRoutineAddress(&routine);
}

bool ApplyRelocations(uint8_t* image, uint32_t size_of_image,
                      const IMAGE_NT_HEADERS64* nt, ULONG_PTR base,
                      ULONG_PTR preferred_base) {
    const IMAGE_DATA_DIRECTORY* directory =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return true;
    }
    const ULONG_PTR delta = base - preferred_base;
    uint32_t offset = 0;
    while (offset + sizeof(IMAGE_BASE_RELOCATION) <= directory->Size) {
        const IMAGE_BASE_RELOCATION* block =
            reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                image + directory->VirtualAddress + offset);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            block->VirtualAddress > size_of_image ||
            directory->Size - offset < block->SizeOfBlock) {
            return false;
        }
        const uint32_t count =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(uint16_t);
        const uint16_t* entries = reinterpret_cast<const uint16_t*>(block + 1);
        for (uint32_t i = 0; i < count; ++i) {
            const uint16_t entry = entries[i];
            const uint16_t type = static_cast<uint16_t>(entry >> 12);
            const uint32_t page_offset =
                block->VirtualAddress + (entry & 0x0FFF);
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
            if (page_offset + sizeof(uint64_t) > size_of_image) {
                return false;
            }
            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* fixup =
                    reinterpret_cast<uint64_t*>(image + page_offset);
                *fixup += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                uint32_t* fixup =
                    reinterpret_cast<uint32_t*>(image + page_offset);
                *fixup += static_cast<uint32_t>(delta);
            } else {
                return false; /* unsupported relocation type */
            }
        }
        offset += block->SizeOfBlock;
    }
    return true;
}

bool ResolveImports(uint8_t* image, uint32_t size_of_image,
                    const IMAGE_NT_HEADERS64* nt) {
    const IMAGE_DATA_DIRECTORY* directory =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return true;
    }
    uint32_t descriptor_offset = directory->VirtualAddress;
    for (uint32_t guard = 0; guard < 256; ++guard) {
        if (descriptor_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) >
            size_of_image) {
            return false;
        }
        const IMAGE_IMPORT_DESCRIPTOR* descriptor =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(image +
                                                             descriptor_offset);
        if (descriptor->Name == 0 && descriptor->FirstThunk == 0) {
            return true;
        }
        if (descriptor->Name == 0 || descriptor->Name > size_of_image ||
            descriptor->FirstThunk > size_of_image) {
            return false;
        }
        const char* module_name =
            reinterpret_cast<const char*>(image + descriptor->Name);
        (void)module_name;
        uint32_t thunk_offset = descriptor->FirstThunk;
        while (thunk_offset + sizeof(uint64_t) <= size_of_image) {
            IMAGE_THUNK_DATA64* thunk =
                reinterpret_cast<IMAGE_THUNK_DATA64*>(image + thunk_offset);
            if (thunk->u1.Function == 0) {
                break;
            }
            if ((thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) != 0) {
                return false; /* ordinal imports are not supported */
            }
            const uint32_t name_offset =
                static_cast<uint32_t>(thunk->u1.AddressOfData);
            if (name_offset + 2 > size_of_image) {
                return false;
            }
            const IMAGE_IMPORT_BY_NAME* import =
                reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(image +
                                                              name_offset);
            const char* function_name =
                reinterpret_cast<const char*>(import->Name);
            PVOID address = ResolveImport(function_name);
            if (address == nullptr) {
                return false;
            }
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(address);
            thunk_offset += sizeof(uint64_t);
        }
        descriptor_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return false;
}

/*
 * Maps the PE image and calls its entry point. `bootstrap` is copied to
 * kernel pool so the mapped driver never touches user memory.
 */
NTSTATUS MapAndCallEntry(const uint8_t* file, uint32_t file_size,
                         const kc_bootstrap* bootstrap, uint64_t* out_base,
                         uint64_t* out_size, NTSTATUS* out_entry_status) {
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        } /* stage 1 */
    }
    const IMAGE_DOS_HEADER* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(file);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    const uint32_t nt_offset = static_cast<uint32_t>(dos->e_lfanew);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > file_size) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    const IMAGE_NT_HEADERS64* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(file + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    const uint32_t size_of_image = nt->OptionalHeader.SizeOfImage;
    if (size_of_image < 0x1000 || size_of_image > 0x08000000) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    if (nt->OptionalHeader.SizeOfHeaders > file_size) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    const uint16_t section_count = nt->FileHeader.NumberOfSections;
    if (section_count > 96) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    const uint32_t section_table = nt_offset + sizeof(IMAGE_NT_HEADERS64);
    if (section_table + section_count * sizeof(IMAGE_SECTION_HEADER) >
        file_size) {
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    uint8_t* image = static_cast<uint8_t*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE, size_of_image, KC_MAPLOAD_POOL_TAG));
    if (image == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(image, size_of_image);
    RtlCopyMemory(image, file, nt->OptionalHeader.SizeOfHeaders);

    const IMAGE_SECTION_HEADER* sections =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(file + section_table);
    for (uint16_t i = 0; i < section_count; ++i) {
        const IMAGE_SECTION_HEADER& section = sections[i];
        if (section.SizeOfRawData == 0) {
            continue;
        }
        if (section.PointerToRawData > file_size ||
            section.SizeOfRawData > file_size - section.PointerToRawData ||
            section.VirtualAddress >= size_of_image ||
            section.SizeOfRawData > size_of_image - section.VirtualAddress) {
            ExFreePoolWithTag(image, KC_MAPLOAD_POOL_TAG);
            {
                g_map_stage = __LINE__;
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
        RtlCopyMemory(image + section.VirtualAddress,
                      file + section.PointerToRawData, section.SizeOfRawData);
    }

    if (!ApplyRelocations(
            image, size_of_image, nt, reinterpret_cast<ULONG_PTR>(image),
            static_cast<ULONG_PTR>(nt->OptionalHeader.ImageBase))) {
        ExFreePoolWithTag(image, KC_MAPLOAD_POOL_TAG);
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    if (!ResolveImports(image, size_of_image, nt)) {
        ExFreePoolWithTag(image, KC_MAPLOAD_POOL_TAG);
        {
            g_map_stage = __LINE__;
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    kc_bootstrap* boot_copy = static_cast<kc_bootstrap*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(kc_bootstrap), KC_MAPLOAD_POOL_TAG));
    if (boot_copy == nullptr) {
        ExFreePoolWithTag(image, KC_MAPLOAD_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(boot_copy, bootstrap, sizeof(kc_bootstrap));

    typedef NTSTATUS (*KcMappedEntry)(PVOID, PVOID);
    KcMappedEntry entry = reinterpret_cast<KcMappedEntry>(
        image + nt->OptionalHeader.AddressOfEntryPoint);
    const NTSTATUS entry_status = entry(boot_copy, nullptr);
    RtlSecureZeroMemory(boot_copy, sizeof(kc_bootstrap));
    ExFreePoolWithTag(boot_copy, KC_MAPLOAD_POOL_TAG);

    *out_base = reinterpret_cast<uint64_t>(image);
    *out_size = size_of_image;
    *out_entry_status = entry_status;
    return STATUS_SUCCESS;
}

} /* namespace */

/* ------------------------------- device ------------------------------ */

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

    if (code == KC_MAPLOAD_IOCTL_LOAD) {
        if (buffer == nullptr || input_length < sizeof(kc_mapload_request)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            const kc_mapload_request* request =
                static_cast<const kc_mapload_request*>(buffer);
            if (request->magic != KC_MAPLOAD_REQUEST_MAGIC ||
                request->image_size > input_length - sizeof(*request) ||
                request->image_size > 0x08000000 ||
                output_length < sizeof(kc_mapload_result)) {
                status = STATUS_INVALID_PARAMETER;
            } else {
                /* METHOD_BUFFERED shares one buffer for input+output: snapshot
                 * the request before the result overwrites it. */
                const uint64_t request_image_size = request->image_size;
                kc_bootstrap boot_copy = request->boot;
                kc_mapload_result* result =
                    static_cast<kc_mapload_result*>(buffer);
                RtlZeroMemory(result, sizeof(*result));
                uint64_t image_base = 0;
                uint64_t image_size = 0;
                NTSTATUS entry_status = STATUS_UNSUCCESSFUL;
                const NTSTATUS map_status = MapAndCallEntry(
                    reinterpret_cast<const uint8_t*>(buffer) + sizeof(*request),
                    static_cast<uint32_t>(request_image_size), &boot_copy,
                    &image_base, &image_size, &entry_status);
                RtlSecureZeroMemory(&boot_copy, sizeof(boot_copy));
                if (!NT_SUCCESS(map_status)) {
                    result->stage = g_map_stage;
                    result->status =
                        (map_status == STATUS_INSUFFICIENT_RESOURCES)
                            ? KC_MAPLOAD_ERR_NOMEM
                            : KC_MAPLOAD_ERR_MAP;
                    result->entry_status = static_cast<uint32_t>(map_status);
                } else {
                    result->status = KC_MAPLOAD_OK;
                    result->entry_status = static_cast<uint32_t>(entry_status);
                    result->image_base = image_base;
                    result->image_size = image_size;
                }
                information = sizeof(*result);
            }
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

void KcMapUnload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    if (g_device != nullptr) {
        IoDeleteSymbolicLink(&g_symlink);
        IoDeleteDevice(g_device);
        g_device = nullptr;
    }
}

/* ---------------------------- entry point ---------------------------- */

extern "C" NTSTATUS DriverEntry(PVOID entry_parameter, PVOID registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    PDRIVER_OBJECT driver = static_cast<PDRIVER_OBJECT>(entry_parameter);
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, KC_MAPLOAD_DEVICE_NAME);
    PDEVICE_OBJECT device = nullptr;
    NTSTATUS status =
        IoCreateDevice(driver, 0, &device_name, KC_MAPLOAD_DEVICE_TYPE,
                       FILE_DEVICE_UNKNOWN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNICODE_STRING device_name_for_link;
    RtlInitUnicodeString(&device_name_for_link, KC_MAPLOAD_DEVICE_NAME);
    RtlInitUnicodeString(&g_symlink, KC_MAPLOAD_SYMLINK_NAME);
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
    driver->DriverUnload = KcMapUnload;
    g_device = device;
    return STATUS_SUCCESS;
}
