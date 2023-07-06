/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "confidential-virt.h"
#include "fd-util.h"
#include "missing_threads.h"
#include "string-table.h"
#include "utf8.h"

#define CPUID_PROCESSOR_INFO_AND_FEATURE_BITS UINT32_C(0x1)

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.1 - Maximum Extended Function Number and Vendor String
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_GET_HIGHEST_FUNCTION UINT32_C(0x80000000)

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.17 - Encrypted Memory Capabilities
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES UINT32_C(0x8000001f)

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: 15.34.10 - SEV_STATUS MSR
 * https://www.amd.com/system/files/TechDocs/24593.pdf
 */
#define MSR_AMD64_SEV UINT32_C(0xc0010131)

/*
 * Intel® TDX Module v1.5 Base Architecture Specification
 * Chapter: 11.2
 * https://www.intel.com/content/www/us/en/content-details/733575/intel-tdx-module-v1-5-base-architecture-specification.html
 */

#define CPUID_INTEL_TDX_ENUMERATION UINT32_C(0x21)

/* Requirements for Implementing the Microsoft Hypervisor Interface
 * https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
 */
#define CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS UINT32_C(0x40000000)

#define CPUID_HYPERV_FEATURES UINT32_C(0x40000003)

#define CPUID_HYPERV_ISOLATION_CONFIG UINT32_C(0x4000000C)

#define CPUID_HYPERV_MIN UINT32_C(0x40000005)
#define CPUID_HYPERV_MAX UINT32_C(0x4000ffff)

#define CPUID_SIG_AMD       "AuthenticAMD"
#define CPUID_SIG_INTEL     "GenuineIntel"
#define CPUID_SIG_INTEL_TDX "IntelTDX    "
#define CPUID_SIG_HYPERV    "Microsoft Hv"

/* ecx bit 31: set => hyperpvisor, unset => bare metal */
#define CPUID_FEATURE_HYPERVISOR (UINT32_C(1) << 31)

/* Linux include/asm-generic/hyperv-tlfs.h */
#define CPUID_HYPERV_CPU_MANAGEMENT (UINT32_C(1) << 12) /* root partition */
#define CPUID_HYPERV_ISOLATION      (UINT32_C(1) << 22) /* confidential VM partition */

#define CPUID_HYPERV_ISOLATION_TYPE_MASK UINT32_C(0xf)
#define CPUID_HYPERV_ISOLATION_TYPE_SNP 2

#define EAX_SEV     (UINT32_C(1) << 1)
#define MSR_SEV     (UINT64_C(1) << 0)
#define MSR_SEV_ES  (UINT64_C(1) << 1)
#define MSR_SEV_SNP (UINT64_C(1) << 2)

#if defined(__x86_64__)

static void cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
        log_debug("CPUID func %" PRIx32 " %" PRIx32, *eax, *ecx);
        __cpuid_count(*eax, *ecx, *eax, *ebx, *ecx, *edx);
        log_debug("CPUID result %" PRIx32 " %" PRIx32 " %" PRIx32 " %" PRIx32, *eax, *ebx, *ecx, *edx);
}

static uint32_t cpuid_leaf(uint32_t eax, char ret_sig[static 13], bool swapped) {
        /* zero-init as some queries explicitly require subleaf == 0 */
        uint32_t sig[3] = {};

        if (swapped)
                cpuid(&eax, &sig[0], &sig[2], &sig[1]);
        else
                cpuid(&eax, &sig[0], &sig[1], &sig[2]);
        memcpy(ret_sig, sig, sizeof(sig));
        ret_sig[12] = 0; /* \0-terminate the string to make string comparison possible */

        /* In some CI tests ret_sig doesn't contain valid UTF8 and prints garbage to the console */
        log_debug("CPUID sig '%s'", strna(utf8_is_valid(ret_sig)));

        return eax;
}

#define MSR_DEVICE "/dev/cpu/0/msr"

static uint64_t msr(uint64_t index) {
        uint64_t ret;
        ssize_t rv;
        _cleanup_close_ int fd = -EBADF;

        fd = open(MSR_DEVICE, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                log_debug_errno(errno,
                                "Cannot open MSR device %s (index %" PRIu64 "), ignoring: %m",
                                MSR_DEVICE,
                                index);
                return 0;
        }

        rv = pread(fd, &ret, sizeof(ret), index);
        if (rv < 0) {
                log_debug_errno(errno,
                                "Cannot read MSR device %s (index %" PRIu64 "), ignoring: %m",
                                MSR_DEVICE,
                                index);
                return 0;
        } else if (rv != sizeof(ret)) {
                log_debug("Short read %ld bytes from MSR device %s (index %" PRIu64 "), ignoring",
                          rv,
                          MSR_DEVICE,
                          index);
                return 0;
        }

        log_debug("MSR %" PRIu64 " result %" PRIu64 "", index, ret);
        return ret;
}

static bool detect_hyperv_sev(void) {
        uint32_t eax, ebx, ecx, edx, feat;
        char sig[13] = {};

        feat = cpuid_leaf(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS, sig, false);

        if (feat < CPUID_HYPERV_MIN || feat > CPUID_HYPERV_MAX)
                return false;

        if (memcmp(sig, CPUID_SIG_HYPERV, sizeof(sig)) != 0)
                return false;

        log_debug("CPUID is on hyperv");
        eax = CPUID_HYPERV_FEATURES;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        if (ebx & CPUID_HYPERV_ISOLATION && !(ebx & CPUID_HYPERV_CPU_MANAGEMENT)) {

                eax = CPUID_HYPERV_ISOLATION_CONFIG;
                ebx = ecx = edx = 0;
                cpuid(&eax, &ebx, &ecx, &edx);

                if ((ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) == CPUID_HYPERV_ISOLATION_TYPE_SNP)
                        return true;
        }

        return false;
}

static ConfidentialVirtualization detect_sev(void) {
        uint32_t eax, ebx, ecx, edx;
        uint64_t msrval;

        eax = CPUID_GET_HIGHEST_FUNCTION;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        if (eax < CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES)
                return CONFIDENTIAL_VIRTUALIZATION_NONE;

        eax = CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        /* bit 1 == CPU supports SEV feature
         *
         * Note, Azure blocks this CPUID leaf from its SEV-SNP
         * guests, so we must fallback to trying some HyperV
         * specific CPUID checks.
         */
        if (!(eax & EAX_SEV)) {
                log_debug("No sev in CPUID, trying hyperv CPUID");

                if (detect_hyperv_sev())
                        return CONFIDENTIAL_VIRTUALIZATION_SEV_SNP;

                log_debug("No hyperv CPUID");
                return CONFIDENTIAL_VIRTUALIZATION_NONE;
        }

        msrval = msr(MSR_AMD64_SEV);

        /* Test reverse order, since the SEV-SNP bit implies
         * the SEV-ES bit, which implies the SEV bit */
        if (msrval & MSR_SEV_SNP)
                return CONFIDENTIAL_VIRTUALIZATION_SEV_SNP;
        if (msrval & MSR_SEV_ES)
                return CONFIDENTIAL_VIRTUALIZATION_SEV_ES;
        if (msrval & MSR_SEV)
                return CONFIDENTIAL_VIRTUALIZATION_SEV;

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}

static ConfidentialVirtualization detect_tdx(void) {
        uint32_t eax, ebx, ecx, edx;
        char sig[13] = {};

        eax = CPUID_GET_HIGHEST_FUNCTION;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        if (eax < CPUID_INTEL_TDX_ENUMERATION)
                return CONFIDENTIAL_VIRTUALIZATION_NONE;

        cpuid_leaf(CPUID_INTEL_TDX_ENUMERATION, sig, true);

        if (memcmp(sig, CPUID_SIG_INTEL_TDX, sizeof(sig)) == 0)
                return CONFIDENTIAL_VIRTUALIZATION_TDX;

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}

static bool detect_hypervisor(void) {
        uint32_t eax, ebx, ecx, edx;
        bool is_hv;

        eax = CPUID_PROCESSOR_INFO_AND_FEATURE_BITS;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        is_hv = ecx & CPUID_FEATURE_HYPERVISOR;

        log_debug("CPUID is hypervisor: %s", yes_no(is_hv));
        return is_hv;
}

ConfidentialVirtualization detect_confidential_virtualization(void) {
        static thread_local ConfidentialVirtualization cached_found = _CONFIDENTIAL_VIRTUALIZATION_INVALID;
        char sig[13] = {};
        ConfidentialVirtualization cv = CONFIDENTIAL_VIRTUALIZATION_NONE;

        if (cached_found >= 0)
                return cached_found;

        /* Skip everything on bare metal */
        if (detect_hypervisor()) {
                cpuid_leaf(0, sig, true);

                if (memcmp(sig, CPUID_SIG_AMD, sizeof(sig)) == 0)
                        cv = detect_sev();
                else if (memcmp(sig, CPUID_SIG_INTEL, sizeof(sig)) == 0)
                        cv = detect_tdx();
        }

        cached_found = cv;
        return cv;
}
#else /* ! x86_64 */
ConfidentialVirtualization detect_confidential_virtualization(void) {
        log_debug("No confidential virtualization detection on this architecture");
        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}
#endif /* ! x86_64 */

static const char *const confidential_virtualization_table[_CONFIDENTIAL_VIRTUALIZATION_MAX] = {
        [CONFIDENTIAL_VIRTUALIZATION_NONE]    = "none",
        [CONFIDENTIAL_VIRTUALIZATION_SEV]     = "sev",
        [CONFIDENTIAL_VIRTUALIZATION_SEV_ES]  = "sev-es",
        [CONFIDENTIAL_VIRTUALIZATION_SEV_SNP] = "sev-snp",
        [CONFIDENTIAL_VIRTUALIZATION_TDX]     = "tdx",
};

DEFINE_STRING_TABLE_LOOKUP(confidential_virtualization, ConfidentialVirtualization);
