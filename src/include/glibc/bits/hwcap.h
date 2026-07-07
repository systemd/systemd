/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <bits/hwcap.h> /* IWYU pragma: export */

/* All other capabilities are defined in glibc-2.34 or earlier */
#if defined(__aarch64__)
#ifndef HWCAP_GCS
#define HWCAP_GCS                       (1UL << 32)
#endif
#ifndef HWCAP_CMPBR
#define HWCAP_CMPBR                     (1UL << 33)
#endif
#ifndef HWCAP_FPRCVT
#define HWCAP_FPRCVT                    (1UL << 34)
#endif
#ifndef HWCAP_F8MM8
#define HWCAP_F8MM8                     (1UL << 35)
#endif
#ifndef HWCAP_F8MM4
#define HWCAP_F8MM4                     (1UL << 36)
#endif
#ifndef HWCAP_SVE_F16MM
#define HWCAP_SVE_F16MM                 (1UL << 37)
#endif
#ifndef HWCAP_SVE_ELTPERM
#define HWCAP_SVE_ELTPERM               (1UL << 38)
#endif
#ifndef HWCAP_SVE_AES2
#define HWCAP_SVE_AES2                  (1UL << 39)
#endif
#ifndef HWCAP_SVE_BFSCALE
#define HWCAP_SVE_BFSCALE               (1UL << 40)
#endif
#ifndef HWCAP_SVE2P2
#define HWCAP_SVE2P2                    (1UL << 41)
#endif
#ifndef HWCAP_SME2P2
#define HWCAP_SME2P2                    (1UL << 42)
#endif
#ifndef HWCAP_SME_SBITPERM
#define HWCAP_SME_SBITPERM              (1UL << 43)
#endif
#ifndef HWCAP_SME_AES
#define HWCAP_SME_AES                   (1UL << 44)
#endif
#ifndef HWCAP_SME_SFEXPA
#define HWCAP_SME_SFEXPA                (1UL << 45)
#endif
#ifndef HWCAP_SME_STMOP
#define HWCAP_SME_STMOP                 (1UL << 46)
#endif
#ifndef HWCAP_SME_SMOP4
#define HWCAP_SME_SMOP4                 (1UL << 47)
#endif

#ifndef HWCAP2_ECV
#define HWCAP2_ECV                      (1 << 19)
#endif
#ifndef HWCAP2_AFP
#define HWCAP2_AFP                      (1 << 20)
#endif
#ifndef HWCAP2_RPRES
#define HWCAP2_RPRES                    (1 << 21)
#endif
#ifndef HWCAP2_MTE3
#define HWCAP2_MTE3                     (1 << 22)
#endif
#ifndef HWCAP2_SME
#define HWCAP2_SME                      (1 << 23)
#endif
#ifndef HWCAP2_SME_I16I64
#define HWCAP2_SME_I16I64               (1 << 24)
#endif
#ifndef HWCAP2_SME_F64F64
#define HWCAP2_SME_F64F64               (1 << 25)
#endif
#ifndef HWCAP2_SME_I8I32
#define HWCAP2_SME_I8I32                (1 << 26)
#endif
#ifndef HWCAP2_SME_F16F32
#define HWCAP2_SME_F16F32               (1 << 27)
#endif
#ifndef HWCAP2_SME_B16F32
#define HWCAP2_SME_B16F32               (1 << 28)
#endif
#ifndef HWCAP2_SME_F32F32
#define HWCAP2_SME_F32F32               (1 << 29)
#endif
#ifndef HWCAP2_SME_FA64
#define HWCAP2_SME_FA64                 (1 << 30)
#endif
#ifndef HWCAP2_WFXT
#define HWCAP2_WFXT                     (1UL << 31)
#endif
#ifndef HWCAP2_EBF16
#define HWCAP2_EBF16                    (1UL << 32)
#endif
#ifndef HWCAP2_SVE_EBF16
#define HWCAP2_SVE_EBF16                (1UL << 33)
#endif
#ifndef HWCAP2_CSSC
#define HWCAP2_CSSC                     (1UL << 34)
#endif
#ifndef HWCAP2_RPRFM
#define HWCAP2_RPRFM                    (1UL << 35)
#endif
#ifndef HWCAP2_SVE2P1
#define HWCAP2_SVE2P1                   (1UL << 36)
#endif
#ifndef HWCAP2_SME2
#define HWCAP2_SME2                     (1UL << 37)
#endif
#ifndef HWCAP2_SME2P1
#define HWCAP2_SME2P1                   (1UL << 38)
#endif
#ifndef HWCAP2_SME_I16I32
#define HWCAP2_SME_I16I32               (1UL << 39)
#endif
#ifndef HWCAP2_SME_BI32I32
#define HWCAP2_SME_BI32I32              (1UL << 40)
#endif
#ifndef HWCAP2_SME_B16B16
#define HWCAP2_SME_B16B16               (1UL << 41)
#endif
#ifndef HWCAP2_SME_F16F16
#define HWCAP2_SME_F16F16               (1UL << 42)
#endif
#ifndef HWCAP2_MOPS
#define HWCAP2_MOPS                     (1UL << 43)
#endif
#ifndef HWCAP2_HBC
#define HWCAP2_HBC                      (1UL << 44)
#endif
#ifndef HWCAP2_SVE_B16B16
#define HWCAP2_SVE_B16B16               (1UL << 45)
#endif
#ifndef HWCAP2_LRCPC3
#define HWCAP2_LRCPC3                   (1UL << 46)
#endif
#ifndef HWCAP2_LSE128
#define HWCAP2_LSE128                   (1UL << 47)
#endif
#ifndef HWCAP2_FPMR
#define HWCAP2_FPMR                     (1UL << 48)
#endif
#ifndef HWCAP2_LUT
#define HWCAP2_LUT                      (1UL << 49)
#endif
#ifndef HWCAP2_FAMINMAX
#define HWCAP2_FAMINMAX                 (1UL << 50)
#endif
#ifndef HWCAP2_F8CVT
#define HWCAP2_F8CVT                    (1UL << 51)
#endif
#ifndef HWCAP2_F8FMA
#define HWCAP2_F8FMA                    (1UL << 52)
#endif
#ifndef HWCAP2_F8DP4
#define HWCAP2_F8DP4                    (1UL << 53)
#endif
#ifndef HWCAP2_F8DP2
#define HWCAP2_F8DP2                    (1UL << 54)
#endif
#ifndef HWCAP2_F8E4M3
#define HWCAP2_F8E4M3                   (1UL << 55)
#endif
#ifndef HWCAP2_F8E5M2
#define HWCAP2_F8E5M2                   (1UL << 56)
#endif
#ifndef HWCAP2_SME_LUTV2
#define HWCAP2_SME_LUTV2                (1UL << 57)
#endif
#ifndef HWCAP2_SME_F8F16
#define HWCAP2_SME_F8F16                (1UL << 58)
#endif
#ifndef HWCAP2_SME_F8F32
#define HWCAP2_SME_F8F32                (1UL << 59)
#endif
#ifndef HWCAP2_SME_SF8FMA
#define HWCAP2_SME_SF8FMA               (1UL << 60)
#endif
#ifndef HWCAP2_SME_SF8DP4
#define HWCAP2_SME_SF8DP4               (1UL << 61)
#endif
#ifndef HWCAP2_SME_SF8DP2
#define HWCAP2_SME_SF8DP2               (1UL << 62)
#endif
#ifndef HWCAP2_POE
#define HWCAP2_POE                      (1UL << 63)
#endif

#ifndef HWCAP3_MTE_FAR
#define HWCAP3_MTE_FAR                  (1UL << 0)
#endif
#ifndef HWCAP3_MTE_STORE_ONLY
#define HWCAP3_MTE_STORE_ONLY           (1UL << 1)
#endif
#ifndef HWCAP3_LSFE
#define HWCAP3_LSFE                     (1UL << 2)
#endif
#ifndef HWCAP3_LS64
#define HWCAP3_LS64                     (1UL << 3)
#endif
#ifndef HWCAP3_SVE_B16MM
#define HWCAP3_SVE_B16MM                (1UL << 4)
#endif
#ifndef HWCAP3_SVE2P3
#define HWCAP3_SVE2P3                   (1UL << 5)
#endif
#ifndef HWCAP3_SME_LUT6
#define HWCAP3_SME_LUT6                 (1UL << 6)
#endif
#ifndef HWCAP3_SME2P3
#define HWCAP3_SME2P3                   (1UL << 7)
#endif
#ifndef HWCAP3_F16MM
#define HWCAP3_F16MM                    (1UL << 8)
#endif
#ifndef HWCAP3_F16F32DOT
#define HWCAP3_F16F32DOT                (1UL << 9)
#endif
#ifndef HWCAP3_F16F32MM
#define HWCAP3_F16F32MM                 (1UL << 10)
#endif
#ifndef HWCAP3_SVE_LUT6
#define HWCAP3_SVE_LUT6                 (1UL << 11)
#endif
#endif
