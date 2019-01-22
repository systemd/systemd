/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <endian.h>

#include "sd-id128.h"

/* We only support root disk discovery for x86, x86-64, Itanium and ARM for
 * now, since EFI for anything else doesn't really exist, and we only
 * care for root partitions on the same disk as the EFI ESP. */

#define GPT_ROOT_X86    SD_ID128_MAKE(44,47,95,40,f2,97,41,b2,9a,f7,d1,31,d5,f0,45,8a)
#define GPT_ROOT_X86_64 SD_ID128_MAKE(4f,68,bc,e3,e8,cd,4d,b1,96,e7,fb,ca,f9,84,b7,09)
#define GPT_ROOT_ARM    SD_ID128_MAKE(69,da,d7,10,2c,e4,4e,3c,b1,6c,21,a1,d4,9a,be,d3)
#define GPT_ROOT_ARM_64 SD_ID128_MAKE(b9,21,b0,45,1d,f0,41,c3,af,44,4c,6f,28,0d,3f,ae)
#define GPT_ROOT_IA64   SD_ID128_MAKE(99,3d,8d,3d,f8,0e,42,25,85,5a,9d,af,8e,d7,ea,97)
#define GPT_ESP         SD_ID128_MAKE(c1,2a,73,28,f8,1f,11,d2,ba,4b,00,a0,c9,3e,c9,3b)
#define GPT_XBOOTLDR    SD_ID128_MAKE(bc,13,c2,ff,59,e6,42,62,a3,52,b2,75,fd,6f,71,72)
#define GPT_SWAP        SD_ID128_MAKE(06,57,fd,6d,a4,ab,43,c4,84,e5,09,33,c8,4b,4f,4f)
#define GPT_HOME        SD_ID128_MAKE(93,3a,c7,e1,2e,b4,4f,13,b8,44,0e,14,e2,ae,f9,15)
#define GPT_SRV         SD_ID128_MAKE(3b,8f,84,25,20,e0,4f,3b,90,7f,1a,25,a7,6f,98,e8)

/* Verity partitions for the root partitions above (we only define them for the root partitions, because only they are
 * are commonly read-only and hence suitable for verity). */
#define GPT_ROOT_X86_VERITY    SD_ID128_MAKE(d1,3c,5d,3b,b5,d1,42,2a,b2,9f,94,54,fd,c8,9d,76)
#define GPT_ROOT_X86_64_VERITY SD_ID128_MAKE(2c,73,57,ed,eb,d2,46,d9,ae,c1,23,d4,37,ec,2b,f5)
#define GPT_ROOT_ARM_VERITY    SD_ID128_MAKE(73,86,cd,f2,20,3c,47,a9,a4,98,f2,ec,ce,45,a2,d6)
#define GPT_ROOT_ARM_64_VERITY SD_ID128_MAKE(df,33,00,ce,d6,9f,4c,92,97,8c,9b,fb,0f,38,d8,20)
#define GPT_ROOT_IA64_VERITY   SD_ID128_MAKE(86,ed,10,d5,b6,07,45,bb,89,57,d3,50,f2,3d,05,71)

#if defined(__x86_64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_X86
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_X86_64_VERITY
#  define GPT_ROOT_SECONDARY_VERITY GPT_ROOT_X86_VERITY
#elif defined(__i386__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_X86_VERITY
#endif

#if defined(__ia64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_IA64
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_IA64_VERITY
#endif

#if defined(__aarch64__) && (__BYTE_ORDER != __BIG_ENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_ARM
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_ARM_64_VERITY
#  define GPT_ROOT_SECONDARY_VERITY GPT_ROOT_ARM_VERITY
#elif defined(__arm__) && (__BYTE_ORDER != __BIG_ENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_ARM_VERITY
#endif

#define GPT_FLAG_NO_BLOCK_IO_PROTOCOL (1ULL << 1)

/* Flags we recognize on the root, swap, home and srv partitions when
 * doing auto-discovery. These happen to be identical to what
 * Microsoft defines for its own Basic Data Partitions, but that's
 * just because we saw no point in defining any other values here. */
#define GPT_FLAG_READ_ONLY (1ULL << 60)
#define GPT_FLAG_NO_AUTO (1ULL << 63)

#define GPT_LINUX_GENERIC SD_ID128_MAKE(0f,c6,3d,af,84,83,47,72,8e,79,3d,69,d8,47,7d,e4)
