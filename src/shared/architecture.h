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
        ARCHITECTURE_MIPS64,
        ARCHITECTURE_ALPHA,
        ARCHITECTURE_ARM,
        ARCHITECTURE_ARM_BE,
        ARCHITECTURE_ARM64,
        ARCHITECTURE_ARM64_BE,
        ARCHITECTURE_SH,
        ARCHITECTURE_SH64,
        ARCHITECTURE_M68K,
        _ARCHITECTURE_MAX,
        _ARCHITECTURE_INVALID = -1
} Architecture;

Architecture uname_architecture(void);

#if defined(__x86_64__)
#  define native_architecture() ARCHITECTURE_X86_64
#elif defined(__i386__)
#  define native_architecture() ARCHITECTURE_X86
#elif defined(__powerpc64__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_PPC64
#  else
#    define native_architecture() ARCHITECTURE_PPC64_LE
#  endif
#elif defined(__powerpc__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_PPC
#  else
#    define native_architecture() ARCHITECTURE_PPC_LE
#  endif
#elif defined(__ia64__)
#  define native_architecture() ARCHITECTURE_IA64
#elif defined(__hppa64__)
#  define native_architecture() ARCHITECTURE_PARISC64
#elif defined(__hppa__)
#  define native_architecture() ARCHITECTURE_PARISC
#elif defined(__s390x__)
#  define native_architecture() ARCHITECTURE_S390X
#elif defined(__s390__)
#  define native_architecture() ARCHITECTURE_S390
#elif defined(__sparc64__)
#  define native_architecture() ARCHITECTURE_SPARC64
#elif defined(__sparc__)
#  define native_architecture() ARCHITECTURE_SPARC
#elif defined(__mips64__)
#  define native_architecture() ARCHITECTURE_MIPS64
#elif defined(__mips__)
#  define native_architecture() ARCHITECTURE_MIPS
#elif defined(__alpha__)
#  define native_architecture() ARCHITECTURE_ALPHA
#elif defined(__aarch64__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_ARM64_BE
#  else
#    define native_architecture() ARCHITECTURE_ARM64
#  endif
#elif defined(__arm__)
#  if defined(WORDS_BIGENDIAN)
#    define native_architecture() ARCHITECTURE_ARM_BE
#  else
#    define native_architecture() ARCHITECTURE_ARM
#  endif
#elif defined(__sh64__)
#  define native_architecture() ARCHITECTURE_SH64
#elif defined(__sh__)
#  define native_architecture() ARCHITECTURE_SH
#elif defined(__m68k__)
#  define native_architecture() ARCHITECTURE_M68K
#else
#error "Please register your architecture here!"
#endif

const char *architecture_to_string(Architecture a) _const_;
Architecture architecture_from_string(const char *s) _pure_;
