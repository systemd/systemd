/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "confidential-virt-fundamental.h"
#include "confidential-virt.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "missing_threads.h"
#include "string-table.h"
#include "utf8.h"

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
                log_debug("Short read %zd bytes from MSR device %s (index %" PRIu64 "), ignoring",
                          rv,
                          MSR_DEVICE,
                          index);
                return 0;
        }

        log_debug("MSR %" PRIu64 " result %" PRIu64 "", index, ret);
        return ret;
}

static bool detect_hyperv_cvm(uint32_t isoltype) {
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

                if ((ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) == isoltype)
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

                if (detect_hyperv_cvm(CPUID_HYPERV_ISOLATION_TYPE_SNP))
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

        log_debug("No tdx in CPUID, trying hyperv CPUID");

        if (detect_hyperv_cvm(CPUID_HYPERV_ISOLATION_TYPE_TDX))
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

static ConfidentialVirtualization detect_confidential_virtualization_impl(void) {
        char sig[13] = {};

        /* Skip everything on bare metal */
        if (detect_hypervisor()) {
                cpuid_leaf(0, sig, true);

                if (memcmp(sig, CPUID_SIG_AMD, sizeof(sig)) == 0)
                        return detect_sev();
                else if (memcmp(sig, CPUID_SIG_INTEL, sizeof(sig)) == 0)
                        return detect_tdx();
        }

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}
#elif defined(__s390x__)
static ConfidentialVirtualization detect_confidential_virtualization_impl(void) {
        _cleanup_free_ char *s = NULL;
        size_t readsize;
        int r;

        r = read_full_virtual_file("/sys/firmware/uv/prot_virt_guest", &s, &readsize);
        if (r < 0) {
                log_debug_errno(r, "Unable to read /sys/firmware/uv/prot_virt_guest: %m");
                return CONFIDENTIAL_VIRTUALIZATION_NONE;
        }

        if (readsize >= 1 && s[0] == '1')
                return CONFIDENTIAL_VIRTUALIZATION_PROTVIRT;

        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}
#elif defined(__aarch64__)
static ConfidentialVirtualization detect_confidential_virtualization_impl(void) {
        int r;

        r = RET_NERRNO(access("/sys/devices/platform/arm-cca-dev", F_OK));
        if (r < 0) {
                log_debug_errno(r, "Unable to check /sys/devices/platform/arm-cca-dev: %m");
                return CONFIDENTIAL_VIRTUALIZATION_NONE;
        }

        return CONFIDENTIAL_VIRTUALIZATION_CCA;
}
#else /* ! x86_64 */
static ConfidentialVirtualization detect_confidential_virtualization_impl(void) {
        log_debug("No confidential virtualization detection on this architecture");
        return CONFIDENTIAL_VIRTUALIZATION_NONE;
}
#endif /* ! x86_64 */

ConfidentialVirtualization detect_confidential_virtualization(void) {
        static thread_local ConfidentialVirtualization cached_found = _CONFIDENTIAL_VIRTUALIZATION_INVALID;

        if (cached_found == _CONFIDENTIAL_VIRTUALIZATION_INVALID)
                cached_found = detect_confidential_virtualization_impl();

        return cached_found;
}

static const char *const confidential_virtualization_table[_CONFIDENTIAL_VIRTUALIZATION_MAX] = {
        [CONFIDENTIAL_VIRTUALIZATION_NONE]     = "none",
        [CONFIDENTIAL_VIRTUALIZATION_SEV]      = "sev",
        [CONFIDENTIAL_VIRTUALIZATION_SEV_ES]   = "sev-es",
        [CONFIDENTIAL_VIRTUALIZATION_SEV_SNP]  = "sev-snp",
        [CONFIDENTIAL_VIRTUALIZATION_TDX]      = "tdx",
        [CONFIDENTIAL_VIRTUALIZATION_PROTVIRT] = "protvirt",
        [CONFIDENTIAL_VIRTUALIZATION_CCA]      = "cca",
};

DEFINE_STRING_TABLE_LOOKUP(confidential_virtualization, ConfidentialVirtualization);
