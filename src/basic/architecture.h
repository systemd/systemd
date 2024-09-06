/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <endian.h>

#include "macro.h"

/* A cleaned up architecture definition. We don't want to get lost in
 * processor features, models, generations or even ABIs. Hence we
 * focus on general family, and distinguish word width and endianness. */

typedef enum {
        ARCHITECTURE_ALPHA,
        ARCHITECTURE_ARC,
        ARCHITECTURE_ARC_BE,
        ARCHITECTURE_ARM,
        ARCHITECTURE_ARM64,
        ARCHITECTURE_ARM64_BE,
        ARCHITECTURE_ARM_BE,
        ARCHITECTURE_CRIS,
        ARCHITECTURE_IA64,
        ARCHITECTURE_LOONGARCH64,
        ARCHITECTURE_M68K,
        ARCHITECTURE_MIPS,
        ARCHITECTURE_MIPS64,
        ARCHITECTURE_MIPS64_LE,
        ARCHITECTURE_MIPS_LE,
        ARCHITECTURE_NIOS2,
        ARCHITECTURE_PARISC,
        ARCHITECTURE_PARISC64,
        ARCHITECTURE_PPC,
        ARCHITECTURE_PPC64,
        ARCHITECTURE_PPC64_LE,
        ARCHITECTURE_PPC_LE,
        ARCHITECTURE_RISCV32,
        ARCHITECTURE_RISCV64,
        ARCHITECTURE_S390,
        ARCHITECTURE_S390X,
        ARCHITECTURE_SH,
        ARCHITECTURE_SH64,
        ARCHITECTURE_SPARC,
        ARCHITECTURE_SPARC64,
        ARCHITECTURE_TILEGX,
        ARCHITECTURE_X86,
        ARCHITECTURE_X86_64,
        _ARCHITECTURE_MAX,
        _ARCHITECTURE_INVALID = -EINVAL,
} Architecture;

Architecture uname_architecture(void);

/*
 * LIB_ARCH_TUPLE should resolve to the local library path
 * architecture tuple systemd is built for, according to the Debian
 * tuple list:
 *
 * https://wiki.debian.org/Multiarch/Tuples
 *
 * This is used in library search paths that should understand
 * Debian's paths on all distributions.
 */

#if defined(__x86_64__)
#  define native_architecture() ARCHITECTURE_X86_64
#  if defined(__ILP32__)
#    define LIB_ARCH_TUPLE "x86_64-linux-gnux32"
#  else
#    define LIB_ARCH_TUPLE "x86_64-linux-gnu"
#  endif
#  define ARCHITECTURE_SECONDARY ARCHITECTURE_X86
#elif defined(__i386__)
#  define native_architecture() ARCHITECTURE_X86
#  define LIB_ARCH_TUPLE "i386-linux-gnu"
#elif defined(__powerpc64__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_PPC64
#    define LIB_ARCH_TUPLE "ppc64-linux-gnu"
#    define ARCHITECTURE_SECONDARY ARCHITECTURE_PPC
#  else
#    define native_architecture() ARCHITECTURE_PPC64_LE
#    define LIB_ARCH_TUPLE  "powerpc64le-linux-gnu"
#    define ARCHITECTURE_SECONDARY ARCHITECTURE_PPC_LE
#  endif
#elif defined(__powerpc__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_PPC
#    if defined(__NO_FPRS__)
#      define LIB_ARCH_TUPLE "powerpc-linux-gnuspe"
#    else
#      define LIB_ARCH_TUPLE "powerpc-linux-gnu"
#    endif
#  else
#    define native_architecture() ARCHITECTURE_PPC_LE
#    error "Missing LIB_ARCH_TUPLE for PPCLE"
#  endif
#elif defined(__ia64__)
#  define native_architecture() ARCHITECTURE_IA64
#  define LIB_ARCH_TUPLE "ia64-linux-gnu"
#elif defined(__hppa64__)
#  define native_architecture() ARCHITECTURE_PARISC64
#  error "Missing LIB_ARCH_TUPLE for HPPA64"
#elif defined(__hppa__)
#  define native_architecture() ARCHITECTURE_PARISC
#  define LIB_ARCH_TUPLE "hppa‑linux‑gnu"
#elif defined(__s390x__)
#  define native_architecture() ARCHITECTURE_S390X
#  define LIB_ARCH_TUPLE "s390x-linux-gnu"
#  define ARCHITECTURE_SECONDARY ARCHITECTURE_S390
#elif defined(__s390__)
#  define native_architecture() ARCHITECTURE_S390
#  define LIB_ARCH_TUPLE "s390-linux-gnu"
#elif defined(__sparc__) && defined (__arch64__)
#  define native_architecture() ARCHITECTURE_SPARC64
#  define LIB_ARCH_TUPLE "sparc64-linux-gnu"
#elif defined(__sparc__)
#  define native_architecture() ARCHITECTURE_SPARC
#  define LIB_ARCH_TUPLE "sparc-linux-gnu"
#elif defined(__mips64) && defined(__LP64__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_MIPS64
#    define LIB_ARCH_TUPLE "mips64-linux-gnuabi64"
#  else
#    define native_architecture() ARCHITECTURE_MIPS64_LE
#    define LIB_ARCH_TUPLE "mips64el-linux-gnuabi64"
#  endif
#elif defined(__mips64)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_MIPS64
#    define LIB_ARCH_TUPLE "mips64-linux-gnuabin32"
#  else
#    define native_architecture() ARCHITECTURE_MIPS64_LE
#    define LIB_ARCH_TUPLE "mips64el-linux-gnuabin32"
#  endif
#elif defined(__mips__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_MIPS
#    define LIB_ARCH_TUPLE "mips-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_MIPS_LE
#    define LIB_ARCH_TUPLE "mipsel-linux-gnu"
#  endif
#elif defined(__alpha__)
#  define native_architecture() ARCHITECTURE_ALPHA
#  define LIB_ARCH_TUPLE "alpha-linux-gnu"
#elif defined(__aarch64__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_ARM64_BE
#    define LIB_ARCH_TUPLE "aarch64_be-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_ARM64
#    define LIB_ARCH_TUPLE "aarch64-linux-gnu"
#    define ARCHITECTURE_SECONDARY ARCHITECTURE_ARM
#  endif
#elif defined(__arm__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_ARM_BE
#    if defined(__ARM_EABI__)
#      if defined(__ARM_PCS_VFP)
#        define LIB_ARCH_TUPLE "armeb-linux-gnueabihf"
#      else
#        define LIB_ARCH_TUPLE "armeb-linux-gnueabi"
#      endif
#    else
#      define LIB_ARCH_TUPLE "armeb-linux-gnu"
#    endif
#  else
#    define native_architecture() ARCHITECTURE_ARM
#    if defined(__ARM_EABI__)
#      if defined(__ARM_PCS_VFP)
#        define LIB_ARCH_TUPLE "arm-linux-gnueabihf"
#      else
#        define LIB_ARCH_TUPLE "arm-linux-gnueabi"
#      endif
#    else
#      define LIB_ARCH_TUPLE "arm-linux-gnu"
#    endif
#  endif
#elif defined(__sh64__)
#  define native_architecture() ARCHITECTURE_SH64
#  error "Missing LIB_ARCH_TUPLE for SH64"
#elif defined(__sh__)
#  define native_architecture() ARCHITECTURE_SH
#  if defined(__SH1__)
#    define LIB_ARCH_TUPLE "sh1-linux-gnu"
#  elif defined(__SH2__)
#    define LIB_ARCH_TUPLE "sh2-linux-gnu"
#  elif defined(__SH2A__)
#    define LIB_ARCH_TUPLE "sh2a-linux-gnu"
#  elif defined(__SH2E__)
#    define LIB_ARCH_TUPLE "sh2e-linux-gnu"
#  elif defined(__SH3__)
#    define LIB_ARCH_TUPLE "sh3-linux-gnu"
#  elif defined(__SH3E__)
#    define LIB_ARCH_TUPLE "sh3e-linux-gnu"
#  elif defined(__SH4__) && !defined(__SH4A__)
#    define LIB_ARCH_TUPLE "sh4-linux-gnu"
#  elif defined(__SH4A__)
#    define LIB_ARCH_TUPLE "sh4a-linux-gnu"
#  endif
#elif defined(__loongarch_lp64)
#  define native_architecture() ARCHITECTURE_LOONGARCH64
#  if defined(__loongarch_double_float)
#    define LIB_ARCH_TUPLE "loongarch64-linux-gnu"
#  elif defined(__loongarch_single_float)
#    define LIB_ARCH_TUPLE "loongarch64-linux-gnuf32"
#  elif defined(__loongarch_soft_float)
#    define LIB_ARCH_TUPLE "loongarch64-linux-gnusf"
#  else
#    error "Unrecognized loongarch architecture variant"
#  endif
#elif defined(__m68k__)
#  define native_architecture() ARCHITECTURE_M68K
#  define LIB_ARCH_TUPLE "m68k-linux-gnu"
#elif defined(__tilegx__)
#  define native_architecture() ARCHITECTURE_TILEGX
#  define LIB_ARCH_TUPLE "tilegx-linux-gnu"
#elif defined(__cris__)
#  define native_architecture() ARCHITECTURE_CRIS
#  error "Missing LIB_ARCH_TUPLE for CRIS"
#elif defined(__nios2__)
#  define native_architecture() ARCHITECTURE_NIOS2
#  define LIB_ARCH_TUPLE "nios2-linux-gnu"
#elif defined(__riscv)
#  if __SIZEOF_POINTER__ == 4
#    define native_architecture() ARCHITECTURE_RISCV32
#    define LIB_ARCH_TUPLE "riscv32-linux-gnu"
#  elif __SIZEOF_POINTER__ == 8
#    define native_architecture() ARCHITECTURE_RISCV64
#    define LIB_ARCH_TUPLE "riscv64-linux-gnu"
#  else
#    error "Unrecognized riscv architecture variant"
#  endif
#elif defined(__arc__)
#  if __BYTE_ORDER == __BIG_ENDIAN
#    define native_architecture() ARCHITECTURE_ARC_BE
#    define LIB_ARCH_TUPLE "arceb-linux"
#  else
#    define native_architecture() ARCHITECTURE_ARC
#    define LIB_ARCH_TUPLE "arc-linux"
#  endif
#else
#  error "Please register your architecture here!"
#endif

const char* architecture_to_string(Architecture a) _const_;
Architecture architecture_from_string(const char *s) _pure_;
