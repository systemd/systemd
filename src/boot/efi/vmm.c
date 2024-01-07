/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#  include <cpuid.h>
#endif

#include "confidential-virt-fundamental.h"
#include "device-path-util.h"
#include "drivers.h"
#include "efi-string.h"
#include "proto/device-path.h"
#include "string-util-fundamental.h"
#include "util.h"
#include "vmm.h"

#define QEMU_KERNEL_LOADER_FS_MEDIA_GUID \
        { 0x1428f772, 0xb64a, 0x441e, { 0xb8, 0xc3, 0x9e, 0xbd, 0xd7, 0xf8, 0x93, 0xc7 } }

#define VMM_BOOT_ORDER_GUID \
        { 0x668f4529, 0x63d0, 0x4bb5, { 0xb6, 0x5d, 0x6f, 0xbb, 0x9d, 0x36, 0xa4, 0x4a } }

/* detect direct boot */
bool is_direct_boot(EFI_HANDLE device) {
        EFI_STATUS err;
        VENDOR_DEVICE_PATH *dp;
        void *dp_raw;

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &dp_raw);
        if (err != EFI_SUCCESS)
                return false;

        /* 'qemu -kernel systemd-bootx64.efi' */
        dp = dp_raw;
        if (dp->Header.Type == MEDIA_DEVICE_PATH &&
            dp->Header.SubType == MEDIA_VENDOR_DP &&
            memcmp(&dp->Guid, MAKE_GUID_PTR(QEMU_KERNEL_LOADER_FS_MEDIA), sizeof(EFI_GUID)) == 0)
                return true;

        /* loaded from firmware volume (sd-boot added to ovmf) */
        if (dp->Header.Type == MEDIA_DEVICE_PATH &&
            dp->Header.SubType == MEDIA_PIWG_FW_VOL_DP)
                return true;

        return false;
}

/*
 * Try find ESP when not loaded from ESP
 *
 * Inspect all filesystems known to the firmware, try find the ESP.  In case VMMBootOrderNNNN variables are
 * present they are used to inspect the filesystems in the specified order.  When nothing was found or the
 * variables are not present the function will do one final search pass over all filesystems.
 *
 * Recent OVMF builds store the qemu boot order (as specified using the bootindex property on the qemu
 * command line) in VMMBootOrderNNNN.  The variables contain a device path.
 *
 * Example qemu command line:
 *     qemu -virtio-scsi-pci,addr=14.0 -device scsi-cd,scsi-id=4,bootindex=1
 *
 * Resulting variable:
 *     VMMBootOrder0000 = PciRoot(0x0)/Pci(0x14,0x0)/Scsi(0x4,0x0)
 */
EFI_STATUS vmm_open(EFI_HANDLE *ret_vmm_dev, EFI_FILE **ret_vmm_dir) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles;
        EFI_STATUS err, dp_err;

        assert(ret_vmm_dev);
        assert(ret_vmm_dir);

        /* Make sure all file systems have been initialized. Only do this in VMs as this is slow
         * on some real firmwares. */
        (void) reconnect_all_drivers();

        /* find all file system handles */
        err = BS->LocateHandleBuffer(
                        ByProtocol, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return err;

        for (size_t order = 0;; order++) {
                _cleanup_free_ void *dp_raw = NULL;
                EFI_DEVICE_PATH *dp;

                _cleanup_free_ char16_t *order_str = xasprintf("VMMBootOrder%04zx", order);
                dp_err = efivar_get_raw(MAKE_GUID_PTR(VMM_BOOT_ORDER), order_str, &dp_raw, NULL);
                dp = dp_raw;

                for (size_t i = 0; i < n_handles; i++) {
                        _cleanup_(file_closep) EFI_FILE *root_dir = NULL, *efi_dir = NULL;
                        EFI_DEVICE_PATH *fs;
                        void *fs_raw;

                        err = BS->HandleProtocol(
                                        handles[i], MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &fs_raw);
                        if (err != EFI_SUCCESS)
                                return err;

                        /* check against VMMBootOrderNNNN (if set) */
                        fs = fs_raw;
                        if (dp_err == EFI_SUCCESS && !device_path_startswith(fs, dp))
                                continue;

                        err = open_volume(handles[i], &root_dir);
                        if (err != EFI_SUCCESS)
                                continue;

                        /* simple ESP check */
                        err = root_dir->Open(root_dir, &efi_dir, (char16_t*) u"\\EFI",
                                             EFI_FILE_MODE_READ,
                                             EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY);
                        if (err != EFI_SUCCESS)
                                continue;

                        *ret_vmm_dev = handles[i];
                        *ret_vmm_dir = TAKE_PTR(root_dir);
                        return EFI_SUCCESS;
                }

                if (dp_err != EFI_SUCCESS)
                        return EFI_NOT_FOUND;
        }
        assert_not_reached();
}

static bool cpuid_in_hypervisor(void) {
#if defined(__i386__) || defined(__x86_64__)
        unsigned eax, ebx, ecx, edx;

        /* This is a dumbed down version of src/basic/virt.c's detect_vm() that safely works in the UEFI
         * environment. */

        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
                return false;

        if (FLAGS_SET(ecx, 0x80000000U))
                return true;
#endif

        return false;
}

#define SMBIOS_TABLE_GUID \
        GUID_DEF(0xeb9d2d31, 0x2d88, 0x11d3, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)
#define SMBIOS3_TABLE_GUID \
        GUID_DEF(0xf2fd1544, 0x9794, 0x4a2c, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94)

typedef struct {
        uint8_t anchor_string[4];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint16_t max_structure_size;
        uint8_t entry_point_revision;
        uint8_t formatted_area[5];
        uint8_t intermediate_anchor_string[5];
        uint8_t intermediate_checksum;
        uint16_t table_length;
        uint32_t table_address;
        uint16_t number_of_smbios_structures;
        uint8_t smbios_bcd_revision;
} _packed_ SmbiosEntryPoint;

typedef struct {
        uint8_t anchor_string[5];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint8_t docrev;
        uint8_t entry_point_revision;
        uint8_t reserved;
        uint32_t table_maximum_size;
        uint64_t table_address;
} _packed_ Smbios3EntryPoint;

typedef struct {
        uint8_t type;
        uint8_t length;
        uint8_t handle[2];
} _packed_ SmbiosHeader;

typedef struct {
        SmbiosHeader header;
        uint8_t vendor;
        uint8_t bios_version;
        uint16_t bios_segment;
        uint8_t bios_release_date;
        uint8_t bios_size;
        uint64_t bios_characteristics;
        uint8_t bios_characteristics_ext[2];
} _packed_ SmbiosTableType0;

typedef struct {
        SmbiosHeader header;
        uint8_t count;
        char contents[];
} _packed_ SmbiosTableType11;

static const void *find_smbios_configuration_table(uint64_t *ret_size) {
        assert(ret_size);

        const Smbios3EntryPoint *entry3 = find_configuration_table(MAKE_GUID_PTR(SMBIOS3_TABLE));
        if (entry3 && memcmp(entry3->anchor_string, "_SM3_", 5) == 0 &&
            entry3->entry_point_length <= sizeof(*entry3)) {
                *ret_size = entry3->table_maximum_size;
                return PHYSICAL_ADDRESS_TO_POINTER(entry3->table_address);
        }

        const SmbiosEntryPoint *entry = find_configuration_table(MAKE_GUID_PTR(SMBIOS_TABLE));
        if (entry && memcmp(entry->anchor_string, "_SM_", 4) == 0 &&
            entry->entry_point_length <= sizeof(*entry)) {
                *ret_size = entry->table_length;
                return PHYSICAL_ADDRESS_TO_POINTER(entry->table_address);
        }

        return NULL;
}

static const void *get_smbios_table(uint8_t type, uint64_t *ret_size_left) {
        uint64_t size = 0;
        const void *p = find_smbios_configuration_table(&size);
        if (!p)
                return NULL;

        for (;;) {
                if (size < sizeof(SmbiosHeader))
                        return NULL;

                const SmbiosHeader *header = p;
                const u_int8_t *base = p;

                /* End of table. */
                if (header->type == 127)
                        return NULL;

                if (size < header->length)
                        return NULL;

                if (header->type == type) {
                        if (ret_size_left)
                                *ret_size_left = size;
                        return header; /* Yay! */
                }

                /* Skip over formatted area. */
                size -= header->length;
                base += header->length;

                /* Skip over string table. */
                for (;;) {
                        const uint8_t *e = memchr(base, 0, size);
                        if (!e)
                                return NULL;

                        if (e == base) {/* Double NUL byte means we've reached the end of the string table. */
                                p = base + 1;
                                size--;
                                break;
                        }

                        size -= e + 1 - base;
                        p = e + 1;
                }
        }

        return NULL;
}

static bool smbios_in_hypervisor(void) {
        /* Look up BIOS Information (Type 0). */
        const SmbiosTableType0 *type0 = (const SmbiosTableType0 *) get_smbios_table(0, NULL);
        if (!type0 || type0->header.length < sizeof(SmbiosTableType0))
                return false;

        /* Bit 4 of 2nd BIOS characteristics extension bytes indicates virtualization. */
        return FLAGS_SET(type0->bios_characteristics_ext[1], 1 << 4);
}

bool in_hypervisor(void) {
        static int cache = -1;
        if (cache >= 0)
                return cache;

        cache = cpuid_in_hypervisor() || smbios_in_hypervisor();
        return cache;
}

const char* smbios_find_oem_string(const char *name) {
        uint64_t left;

        assert(name);

        const SmbiosTableType11 *type11 = (const SmbiosTableType11 *) get_smbios_table(11, &left);
        if (!type11 || type11->header.length < sizeof(SmbiosTableType11))
                return NULL;

        assert(left >= type11->header.length);

        const char *s = type11->contents;
        left -= type11->header.length;

        for (const char *p = s; p < s + left; ) {
                const char *e = memchr(p, 0, s + left - p);
                if (!e || e == p) /* Double NUL byte means we've reached the end of the OEM strings. */
                        break;

                const char *eq = startswith8(p, name);
                if (eq && *eq == '=')
                        return eq + 1;

                p = e + 1;
        }

        return NULL;
}

#if defined(__i386__) || defined(__x86_64__)
static uint32_t cpuid_leaf(uint32_t eax, char ret_sig[static 13], bool swapped) {
        /* zero-init as some queries explicitly require subleaf == 0 */
        uint32_t sig[3] = {};

        if (swapped)
                __cpuid_count(eax, 0, eax, sig[0], sig[2], sig[1]);
        else
                __cpuid_count(eax, 0, eax, sig[0], sig[1], sig[2]);

        memcpy(ret_sig, sig, sizeof(sig));
        ret_sig[12] = 0; /* \0-terminate the string to make string comparison possible */

        return eax;
}

static uint64_t msr(uint32_t index) {
        uint64_t val;
#ifdef __x86_64__
        uint32_t low, high;
        asm volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(index) : "memory");
        val = ((uint64_t)high << 32) | low;
#else
        asm volatile ("rdmsr" : "=A"(val) : "c"(index) : "memory");
#endif
        return val;
}

static bool detect_hyperv_sev(void) {
        uint32_t eax, ebx, ecx, edx, feat;
        char sig[13] = {};

        feat = cpuid_leaf(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS, sig, false);

        if (feat < CPUID_HYPERV_MIN || feat > CPUID_HYPERV_MAX)
                return false;

        if (memcmp(sig, CPUID_SIG_HYPERV, sizeof(sig)) != 0)
                return false;

        __cpuid(CPUID_HYPERV_FEATURES, eax, ebx, ecx, edx);

        if (ebx & CPUID_HYPERV_ISOLATION && !(ebx & CPUID_HYPERV_CPU_MANAGEMENT)) {
                __cpuid(CPUID_HYPERV_ISOLATION_CONFIG, eax, ebx, ecx, edx);

                if ((ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) == CPUID_HYPERV_ISOLATION_TYPE_SNP)
                        return true;
        }

        return false;
}

static bool detect_sev(void) {
        uint32_t eax, ebx, ecx, edx;
        uint64_t msrval;

        __cpuid(CPUID_GET_HIGHEST_FUNCTION, eax, ebx, ecx, edx);

        if (eax < CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES)
                return false;

        __cpuid(CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES, eax, ebx, ecx, edx);

        /* bit 1 == CPU supports SEV feature
         *
         * Note, Azure blocks this CPUID leaf from its SEV-SNP
         * guests, so we must fallback to trying some HyperV
         * specific CPUID checks.
         */
        if (!(eax & EAX_SEV))
                return detect_hyperv_sev();

        msrval = msr(MSR_AMD64_SEV);

        if (msrval & (MSR_SEV_SNP | MSR_SEV_ES | MSR_SEV))
                return true;

        return false;
}

static bool detect_tdx(void) {
        uint32_t eax, ebx, ecx, edx;
        char sig[13] = {};

        __cpuid(CPUID_GET_HIGHEST_FUNCTION, eax, ebx, ecx, edx);

        if (eax < CPUID_INTEL_TDX_ENUMERATION)
                return false;

        cpuid_leaf(CPUID_INTEL_TDX_ENUMERATION, sig, true);

        if (memcmp(sig, CPUID_SIG_INTEL_TDX, sizeof(sig)) == 0)
                return true;

        return false;
}
#endif /* ! __i386__ && ! __x86_64__ */

bool is_confidential_vm(void) {
#if defined(__i386__) || defined(__x86_64__)
        char sig[13] = {};

        if (!cpuid_in_hypervisor())
                return false;

        cpuid_leaf(0, sig, true);

        if (memcmp(sig, CPUID_SIG_AMD, sizeof(sig)) == 0)
                return detect_sev();
        if (memcmp(sig, CPUID_SIG_INTEL, sizeof(sig)) == 0)
                return detect_tdx();
#endif /* ! __i386__ && ! __x86_64__ */

        return false;
}
