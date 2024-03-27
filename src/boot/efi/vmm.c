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
#include "smbios.h"
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

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return false;

        /* 'qemu -kernel systemd-bootx64.efi' */
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
                _cleanup_free_ EFI_DEVICE_PATH *dp = NULL;

                _cleanup_free_ char16_t *order_str = xasprintf("VMMBootOrder%04zx", order);
                dp_err = efivar_get_raw(MAKE_GUID_PTR(VMM_BOOT_ORDER), order_str, (char **) &dp, NULL);

                for (size_t i = 0; i < n_handles; i++) {
                        _cleanup_(file_closep) EFI_FILE *root_dir = NULL, *efi_dir = NULL;
                        EFI_DEVICE_PATH *fs;

                        err = BS->HandleProtocol(
                                        handles[i], MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &fs);
                        if (err != EFI_SUCCESS)
                                return err;

                        /* check against VMMBootOrderNNNN (if set) */
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

bool in_hypervisor(void) {
        static int cache = -1;
        if (cache >= 0)
                return cache;

        cache = cpuid_in_hypervisor() || smbios_in_hypervisor();
        return cache;
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
