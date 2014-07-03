/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"

/* A cleaned up architecture definition */

typedef enum Architecture {
        ARCHITECTURE_X86 = 0,
        ARCHITECTURE_X86_64,
        ARCHITECTURE_PPC,
        ARCHITECTURE_PPC_LE,
        ARCHITECTURE_PPC64,
        ARCHITECTURE_PPC64_LE,
        ARCHITECTURE_IA64,
        ARCHITECTURE_PARISC,
        ARCHITECTURE_PARISC64,
        ARCHITECTURE_S390,
        ARCHITECTURE_S390X,
        ARCHITECTURE_SPARC,
        ARCHITECTURE_SPARC64,
        ARCHITECTURE_MIPS,
        ARCHITECTURE_MIPS_LE,
        ARCHITECTURE_MIPS64,
        ARCHITECTURE_MIPS64_LE,
        ARCHITECTURE_ALPHA,
        ARCHITECTURE_ARM,
        ARCHITECTURE_ARM_BE,
        ARCHITECTURE_ARM64,
        ARCHITECTURE_ARM64_BE,
        ARCHITECTURE_SH,
        ARCHITECTURE_SH64,
        ARCHITECTURE_M68K,
        ARCHITECTURE_TILEGX,
        ARCHITECTURE_CRIS,
        _ARCHITECTURE_MAX,
        _ARCHITECTURE_INVALID = -1
} Architecture;

Architecture uname_architecture(void);

/*
 * ARCH_TUPLE should resolve to the local architecture systemd is
 * built for, according to the Debian tuple list:
 *
 * https://wiki.debian.org/Multiarch/Tuples
 *
 */

#if defined(__x86_64__)
#  define native_architecture() ARCHITECTURE_X86_64
#  define ARCH_TUPLE "x86_64-linux-gnu"
#elif defined(__i386__)
#  define native_architecture() ARCHITECTURE_X86
#  define ARCH_TUPLE "i386-linux-gnu"
#elif defined(__powerpc64__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_PPC64
#    define ARCH_TUPLE "ppc64-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_PPC64_LE
#    error "Missing ARCH_TUPLE for PPC64LE"
#  endif
#elif defined(__powerpc__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_PPC
#    define ARCH_TUPLE "powerpc-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_PPC_LE
#    error "Missing ARCH_TUPLE for PPCLE"
#  endif
#elif defined(__ia64__)
#  define native_architecture() ARCHITECTURE_IA64
#  define ARCH_TUPLE "ia64-linux-gnu"
#elif defined(__hppa64__)
#  define native_architecture() ARCHITECTURE_PARISC64
#  error "Missing ARCH_TUPLE for HPPA64"
#elif defined(__hppa__)
#  define native_architecture() ARCHITECTURE_PARISC
#  define ARCH_TUPLE "hppa‑linux‑gnu"
#elif defined(__s390x__)
#  define native_architecture() ARCHITECTURE_S390X
#  define ARCH_TUPLE "s390x-linux-gnu"
#elif defined(__s390__)
#  define native_architecture() ARCHITECTURE_S390
#  define ARCH_TUPLE "s390-linux-gnu"
#elif defined(__sparc64__)
#  define native_architecture() ARCHITECTURE_SPARC64
#  define ARCH_TUPLE "sparc64-linux-gnu"
#elif defined(__sparc__)
#  define native_architecture() ARCHITECTURE_SPARC
#  define ARCH_TUPLE "sparc-linux-gnu"
#elif defined(__mips64__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_MIPS64
#    error "Missing ARCH_TUPLE for MIPS64"
#  else
#    define native_architecture() ARCHITECTURE_MIPS64_LE
#    error "Missing ARCH_TUPLE for MIPS64_LE"
#  endif
#elif defined(__mips__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_MIPS
#    define ARCH_TUPLE "mips-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_MIPS_LE
#    define ARCH_TUPLE "mipsel-linux-gnu"
#endif
#elif defined(__alpha__)
#  define native_architecture() ARCHITECTURE_ALPHA
#  define ARCH_TUPLE "alpha-linux-gnu"
#elif defined(__aarch64__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_ARM64_BE
#    define ARCH_TUPLE "aarch64_be-linux-gnu"
#  else
#    define native_architecture() ARCHITECTURE_ARM64
#    define ARCH_TUPLE "aarch64-linux-gnu"
#  endif
#elif defined(__arm__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_ARM_BE
#    error "Missing ARCH_TUPLE for ARM_BE"
#  else
#    if defined(__ARM_PCS_VFP)
#      define native_architecture() ARCHITECTURE_ARM
#      define ARCH_TUPLE "arm-linux-gnueabihf"
#    else
#      define native_architecture() ARCHITECTURE_ARM
#      define ARCH_TUPLE "arm-linux-gnueabi"
#    endif
#  endif
#elif defined(__sh64__)
#  define native_architecture() ARCHITECTURE_SH64
#  error "Missing ARCH_TUPLE for SH64"
#elif defined(__sh__)
#  define native_architecture() ARCHITECTURE_SH
#  define ARCH_TUPLE "sh4-linux-gnu"
#elif defined(__m68k__)
#  define native_architecture() ARCHITECTURE_M68K
#  define ARCH_TUPLE "m68k-linux-gnu"
#elif defined(__tilegx__)
#  define native_architecture() ARCHITECTURE_TILEGX
#  error "Missing ARCH_TUPLE for TILEGX"
#elif defined(__cris__)
#  define native_architecture() ARCHITECTURE_CRIS
#  error "Missing ARCH_TUPLE for CRIS"
#else
#error "Please register your architecture here!"
#endif

const char *architecture_to_string(Architecture a) _const_;
Architecture architecture_from_string(const char *s) _pure_;
