/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <endian.h>

#include "sd-id128.h"

#include "id128-util.h"

/* We only support root disk discovery for x86, x86-64, Itanium and ARM for now, since EFI for anything else
 * doesn't really exist, and we only care for root partitions on the same disk as the EFI ESP. */

#define GPT_ROOT_X86      SD_ID128_MAKE(44,47,95,40,f2,97,41,b2,9a,f7,d1,31,d5,f0,45,8a)
#define GPT_ROOT_X86_64   SD_ID128_MAKE(4f,68,bc,e3,e8,cd,4d,b1,96,e7,fb,ca,f9,84,b7,09)
#define GPT_ROOT_ARM      SD_ID128_MAKE(69,da,d7,10,2c,e4,4e,3c,b1,6c,21,a1,d4,9a,be,d3)
#define GPT_ROOT_ARM_64   SD_ID128_MAKE(b9,21,b0,45,1d,f0,41,c3,af,44,4c,6f,28,0d,3f,ae)
#define GPT_ROOT_IA64     SD_ID128_MAKE(99,3d,8d,3d,f8,0e,42,25,85,5a,9d,af,8e,d7,ea,97)
#define GPT_ROOT_RISCV32  SD_ID128_MAKE(60,d5,a7,fe,8e,7d,43,5c,b7,14,3d,d8,16,21,44,e1)
#define GPT_ROOT_RISCV64  SD_ID128_MAKE(72,ec,70,a6,cf,74,40,e6,bd,49,4b,da,08,e8,f2,24)
#define GPT_USR_X86       SD_ID128_MAKE(75,25,0d,76,8c,c6,45,8e,bd,66,bd,47,cc,81,a8,12)
#define GPT_USR_X86_64    SD_ID128_MAKE(84,84,68,0c,95,21,48,c6,9c,11,b0,72,06,56,f6,9e)
#define GPT_USR_ARM       SD_ID128_MAKE(7d,03,59,a3,02,b3,4f,0a,86,5c,65,44,03,e7,06,25)
#define GPT_USR_ARM_64    SD_ID128_MAKE(b0,e0,10,50,ee,5f,43,90,94,9a,91,01,b1,71,04,e9)
#define GPT_USR_IA64      SD_ID128_MAKE(43,01,d2,a6,4e,3b,4b,2a,bb,94,9e,0b,2c,42,25,ea)
#define GPT_USR_RISCV32   SD_ID128_MAKE(b9,33,fb,22,5c,3f,4f,91,af,90,e2,bb,0f,a5,07,02)
#define GPT_USR_RISCV64   SD_ID128_MAKE(be,ae,c3,4b,84,42,43,9b,a4,0b,98,43,81,ed,09,7d)
#define GPT_ESP           SD_ID128_MAKE(c1,2a,73,28,f8,1f,11,d2,ba,4b,00,a0,c9,3e,c9,3b)
#define GPT_XBOOTLDR      SD_ID128_MAKE(bc,13,c2,ff,59,e6,42,62,a3,52,b2,75,fd,6f,71,72)
#define GPT_SWAP          SD_ID128_MAKE(06,57,fd,6d,a4,ab,43,c4,84,e5,09,33,c8,4b,4f,4f)
#define GPT_HOME          SD_ID128_MAKE(93,3a,c7,e1,2e,b4,4f,13,b8,44,0e,14,e2,ae,f9,15)
#define GPT_SRV           SD_ID128_MAKE(3b,8f,84,25,20,e0,4f,3b,90,7f,1a,25,a7,6f,98,e8)
#define GPT_VAR           SD_ID128_MAKE(4d,21,b0,16,b5,34,45,c2,a9,fb,5c,16,e0,91,fd,2d)
#define GPT_TMP           SD_ID128_MAKE(7e,c6,f5,57,3b,c5,4a,ca,b2,93,16,ef,5d,f6,39,d1)
#define GPT_USER_HOME     SD_ID128_MAKE(77,3f,91,ef,66,d4,49,b5,bd,83,d6,83,bf,40,ad,16)
#define GPT_LINUX_GENERIC SD_ID128_MAKE(0f,c6,3d,af,84,83,47,72,8e,79,3d,69,d8,47,7d,e4)

/* Verity partitions for the root partitions above (we only define them for the root and /usr partitions,
 * because only they are commonly read-only and hence suitable for verity). */
#define GPT_ROOT_X86_VERITY    SD_ID128_MAKE(d1,3c,5d,3b,b5,d1,42,2a,b2,9f,94,54,fd,c8,9d,76)
#define GPT_ROOT_X86_64_VERITY SD_ID128_MAKE(2c,73,57,ed,eb,d2,46,d9,ae,c1,23,d4,37,ec,2b,f5)
#define GPT_ROOT_ARM_VERITY    SD_ID128_MAKE(73,86,cd,f2,20,3c,47,a9,a4,98,f2,ec,ce,45,a2,d6)
#define GPT_ROOT_ARM_64_VERITY SD_ID128_MAKE(df,33,00,ce,d6,9f,4c,92,97,8c,9b,fb,0f,38,d8,20)
#define GPT_ROOT_IA64_VERITY   SD_ID128_MAKE(86,ed,10,d5,b6,07,45,bb,89,57,d3,50,f2,3d,05,71)
#define GPT_ROOT_RISCV32_VERITY SD_ID128_MAKE(ae,02,53,be,11,67,40,07,ac,68,43,92,6c,14,c5,de)
#define GPT_ROOT_RISCV64_VERITY SD_ID128_MAKE(b6,ed,55,82,44,0b,42,09,b8,da,5f,f7,c4,19,ea,3d)
#define GPT_USR_X86_VERITY     SD_ID128_MAKE(8f,46,1b,0d,14,ee,4e,81,9a,a9,04,9b,6f,b9,7a,bd)
#define GPT_USR_X86_64_VERITY  SD_ID128_MAKE(77,ff,5f,63,e7,b6,46,33,ac,f4,15,65,b8,64,c0,e6)
#define GPT_USR_ARM_VERITY     SD_ID128_MAKE(c2,15,d7,51,7b,cd,46,49,be,90,66,27,49,0a,4c,05)
#define GPT_USR_ARM_64_VERITY  SD_ID128_MAKE(6e,11,a4,e7,fb,ca,4d,ed,b9,e9,e1,a5,12,bb,66,4e)
#define GPT_USR_IA64_VERITY    SD_ID128_MAKE(6a,49,1e,03,3b,e7,45,45,8e,38,83,32,0e,0e,a8,80)
#define GPT_USR_RISCV32_VERITY SD_ID128_MAKE(cb,1e,e4,e3,8c,d0,41,36,a0,a4,aa,61,a3,2e,87,30)
#define GPT_USR_RISCV64_VERITY SD_ID128_MAKE(8f,10,56,be,9b,05,47,c4,81,d6,be,53,12,8e,5b,54)

#if defined(__x86_64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_X86
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_X86_64_VERITY
#  define GPT_ROOT_SECONDARY_VERITY GPT_ROOT_X86_VERITY
#  define GPT_USR_NATIVE GPT_USR_X86_64
#  define GPT_USR_SECONDARY GPT_USR_X86
#  define GPT_USR_NATIVE_VERITY GPT_USR_X86_64_VERITY
#  define GPT_USR_SECONDARY_VERITY GPT_USR_X86_VERITY
#elif defined(__i386__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_X86_VERITY
#  define GPT_USR_NATIVE GPT_USR_X86
#  define GPT_USR_NATIVE_VERITY GPT_USR_X86_VERITY
#endif

#if defined(__ia64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_IA64
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_IA64_VERITY
#  define GPT_USR_NATIVE GPT_USR_IA64
#  define GPT_USR_NATIVE_VERITY GPT_USR_IA64_VERITY
#endif

#if defined(__aarch64__) && (__BYTE_ORDER != __BIG_ENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_ARM
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_ARM_64_VERITY
#  define GPT_ROOT_SECONDARY_VERITY GPT_ROOT_ARM_VERITY
#  define GPT_USR_NATIVE GPT_USR_ARM_64
#  define GPT_USR_SECONDARY GPT_USR_ARM
#  define GPT_USR_NATIVE_VERITY GPT_USR_ARM_64_VERITY
#  define GPT_USR_SECONDARY_VERITY GPT_USR_ARM_VERITY
#elif defined(__arm__) && (__BYTE_ORDER != __BIG_ENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_ARM_VERITY
#  define GPT_USR_NATIVE GPT_USR_ARM
#  define GPT_USR_NATIVE_VERITY GPT_USR_ARM_VERITY
#endif

#if defined(__riscv)
#if (__riscv_xlen == 32)
#  define GPT_ROOT_NATIVE GPT_ROOT_RISCV32
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_RISCV32_VERITY
#  define GPT_USR_NATIVE GPT_USR_RISCV32
#  define GPT_USR_NATIVE_VERITY GPT_USR_RISCV32_VERITY
#elif (__riscv_xlen == 64)
#  define GPT_ROOT_NATIVE GPT_ROOT_RISCV64
#  define GPT_ROOT_NATIVE_VERITY GPT_ROOT_RISCV64_VERITY
#  define GPT_USR_NATIVE GPT_USR_RISCV64
#  define GPT_USR_NATIVE_VERITY GPT_USR_RISCV64_VERITY
#endif
#endif

#define GPT_FLAG_REQUIRED_PARTITION (1ULL << 0)
#define GPT_FLAG_NO_BLOCK_IO_PROTOCOL (1ULL << 1)
#define GPT_FLAG_LEGACY_BIOS_BOOTABLE (1ULL << 2)

/* Flags we recognize on the root, usr, xbootldr, swap, home, srv, var, tmp partitions when doing
 * auto-discovery. These happen to be identical to what Microsoft defines for its own Basic Data Partitions,
 * but that's just because we saw no point in defining any other values here. */
#define GPT_FLAG_READ_ONLY (1ULL << 60)
#define GPT_FLAG_NO_AUTO (1ULL << 63)

const char *gpt_partition_type_uuid_to_string(sd_id128_t id);
const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static ID128_UUID_STRING_MAX]);
int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret);

typedef struct GptPartitionType {
        sd_id128_t uuid;
        const char *name;
} GptPartitionType;

extern const GptPartitionType gpt_partition_type_table[];

int gpt_partition_label_valid(const char *s);
