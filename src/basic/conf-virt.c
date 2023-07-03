/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "conf-virt.h"
#include "string-table.h"

#define CPUID_PROCESSOR_INFO_AND_FEATURE_BITS 0x1

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.1 - Maximum Extended Function Number and Vendor String
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_GET_HIGHEST_FUNCTION 0x80000000

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.17 - Encrypted Memory Capabilities
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES 0x8000001f

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: 15.34.10 - SEV_STATUS MSR
 * https://www.amd.com/system/files/TechDocs/24593.pdf
 */
#define MSR_AMD64_SEV 0xc0010131

/*
 * Intel® TDX Module v1.5 Base Architecture Specification
 * Chapter: 11.2
 * https://www.intel.com/content/www/us/en/content-details/733575/intel-tdx-module-v1-5-base-architecture-specification.html
 */

#define CPUID_INTEL_TDX_ENUMERATION 0x21

/* Requirements for Implementing the Microsoft Hypervisor Interface
 * https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
 */
#define CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS 0x40000000

#define CPUID_HYPERV_FEATURES 0x40000003

#define CPUID_HYPERV_ISOLATION_CONFIG 0x4000000C

#define CPUID_HYPERV_MIN 0x40000005
#define CPUID_HYPERV_MAX 0x4000ffff

#define CPUID_SIG_AMD       "AuthenticAMD"
#define CPUID_SIG_INTEL     "GenuineIntel"
#define CPUID_SIG_INTEL_TDX "IntelTDX    "
#define CPUID_SIG_HYPERV    "Microsoft Hv"

/* ecx bit 31: set => hyperpvisor, unset => bare metal */
#define CPUID_FEATURE_HYPERVISOR (1U << 31)

/* Linux include/asm-generic/hyperv-tlfs.h */
#define CPUID_HYPERV_CPU_MANAGEMENT (1 << 12) /* root partition */
#define CPUID_HYPERV_ISOLATION      (1 << 22) /* confidential VM partition */

#define CPUID_HYPERV_ISOLATION_TYPE_MASK 0xf
#define CPUID_HYPERV_ISOLATION_TYPE_SNP 2


#if defined(__x86_64__)

/* Copied from the Linux kernel definition in
 * arch/x86/include/asm/processor.h
 */
static inline void
cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
        log_debug("CPUID func %x %x", *eax, *ecx);
        __cpuid(*eax, *eax, *ebx, *ecx, *edx);
        log_debug("CPUID result %x %x %x %x", *eax, *ebx, *ecx, *edx);
}


static uint32_t
cpuid_leaf(uint32_t eax, char *sig, bool swapped)
{
        uint32_t *sig32 = (uint32_t *) sig;

        if (swapped)
                cpuid(&eax, &sig32[0], &sig32[2], &sig32[1]);
        else
                cpuid(&eax, &sig32[0], &sig32[1], &sig32[2]);
        sig[12] = 0; /* \0-terminate the string to make string comparison possible */
        log_debug("CPUID sig %s", sig);
        return eax;
}

#define MSR_DEVICE "/dev/cpu/0/msr"

static uint64_t
msr(off_t index)
{
        uint64_t ret;
        int fd = open(MSR_DEVICE, O_RDONLY);
        if (fd < 0) {
                log_debug("Cannot open MSR device %s", MSR_DEVICE);
                return 0;
        }

        if (pread(fd, &ret, sizeof(ret), index) != sizeof(ret))
                ret = 0;

        close(fd);

        log_debug("MSR %llx result %llx", (unsigned long long)index,
                  (unsigned long long)ret);
        return ret;
}


static bool
detect_hyperv_sev(void)
{
        uint32_t eax, ebx, ecx, edx;
        char sig[13];
        uint32_t feat;

        feat = cpuid_leaf(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS, sig, false);

        if (feat < CPUID_HYPERV_MIN ||
            feat > CPUID_HYPERV_MAX)
                return false;

        if (memcmp(sig, CPUID_SIG_HYPERV, sizeof(sig)) != 0)
                return false;

        log_debug("CPUID is on hyperv");
        eax = CPUID_HYPERV_FEATURES;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        if (ebx & CPUID_HYPERV_ISOLATION &&
            !(ebx & CPUID_HYPERV_CPU_MANAGEMENT)) {

                eax = CPUID_HYPERV_ISOLATION_CONFIG;
                ebx = ecx = edx = 0;
                cpuid(&eax, &ebx, &ecx, &edx);

                if ((ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) ==
                    CPUID_HYPERV_ISOLATION_TYPE_SNP) {
                        return true;
                }
        }

        return false;
}

static ConfidentialVirtualization
detect_sev(void)
{
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
         * guests, so we must fallback to probing the TPM which
         * exposes a SEV-SNP attestation report as evidence.
         */
        if (!(eax & (1 << 1))) {
                log_debug("No sev in CPUID, try hyperv CPUID");

                if (detect_hyperv_sev()) {
                        return CONFIDENTIAL_VIRTUALIZATION_SEV_SNP;
                } else {
                        log_debug("No hyperv CPUID");
                }
                return CONFIDENTIAL_VIRTUALIZATION_NONE;
        }

        msrval = msr(MSR_AMD64_SEV);

        /* Test reverse order, since the SEV-SNP bit implies
         * the SEV-ES bit, which implies the SEV bit */
        if (msrval & (1 << 2)) {
                return CONFIDENTIAL_VIRTUALIZATION_SEV_SNP;
        } else if (msrval & (1 << 1)) {
                return CONFIDENTIAL_VIRTUALIZATION_SEV_ES;
        } else if (msrval & (1 << 0)) {
                return CONFIDENTIAL_VIRTUALIZATION_SEV;
        }
        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}

static ConfidentialVirtualization detect_tdx(void)
{
        uint32_t eax, ebx, ecx, edx;
        char sig[13];

        eax = CPUID_GET_HIGHEST_FUNCTION;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);
        log_debug("CPUID max function: %x %x %x %x", eax, ebx, ecx,edx);

        if (eax < CPUID_INTEL_TDX_ENUMERATION)
                return CONFIDENTIAL_VIRTUALIZATION_NONE;

        memset(sig, 0, sizeof sig);
        cpuid_leaf(CPUID_INTEL_TDX_ENUMERATION, sig, true);

        if (memcmp(sig, CPUID_SIG_INTEL_TDX, sizeof(sig)) == 0)
                return CONFIDENTIAL_VIRTUALIZATION_TDX;

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}

static bool
detect_hypervisor(void)
{
        uint32_t eax, ebx, ecx, edx;
        bool is_hv;

        eax = CPUID_PROCESSOR_INFO_AND_FEATURE_BITS;
        ebx = ecx = edx = 0;

        cpuid(&eax, &ebx, &ecx, &edx);

        is_hv = ecx & CPUID_FEATURE_HYPERVISOR;

        log_debug("CPUID is hypervisor: %s", is_hv ? "yes" : "no");
        return is_hv;
}


ConfidentialVirtualization detect_confidential_virtualization(void) {
        char sig[13];

        /* Skip everything on bare metal */
        if (!detect_hypervisor())
                return CONFIDENTIAL_VIRTUALIZATION_NONE;

        memset(sig, 0, sizeof sig);
        cpuid_leaf(0, sig, true);

        if (memcmp(sig, CPUID_SIG_AMD, sizeof(sig)) == 0)
                return detect_sev();
        else if (memcmp(sig, CPUID_SIG_INTEL, sizeof(sig)) == 0)
                return detect_tdx();

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
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
