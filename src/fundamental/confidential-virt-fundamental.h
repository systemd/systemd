/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>

/* Keep CVM detection logic in this file at feature parity with
 * that in src/efi/boot/vmm.c */

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
#define CPUID_HYPERV_ISOLATION_TYPE_TDX 3

#define EAX_SEV     (UINT32_C(1) << 1)
#define MSR_SEV     (UINT64_C(1) << 0)
#define MSR_SEV_ES  (UINT64_C(1) << 1)
#define MSR_SEV_SNP (UINT64_C(1) << 2)
