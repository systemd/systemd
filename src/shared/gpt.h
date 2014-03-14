/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "sd-id128.h"

/* We only support root disk discovery for x86, x86-64 and ARM for
 * now, since EFI for anything else doesn't really exist, and we only
 * care for root partitions on the same disk as the EFI ESP. */

#define GPT_ROOT_X86    SD_ID128_MAKE(44,47,95,40,f2,97,41,b2,9a,f7,d1,31,d5,f0,45,8a)
#define GPT_ROOT_X86_64 SD_ID128_MAKE(4f,68,bc,e3,e8,cd,4d,b1,96,e7,fb,ca,f9,84,b7,09)
#define GPT_ROOT_ARM    SD_ID128_MAKE(69,da,d7,10,2c,e4,4e,3c,b1,6c,21,a1,d4,9a,be,d3)
#define GPT_ROOT_ARM_64 SD_ID128_MAKE(b9,21,b0,45,1d,f0,41,c3,af,44,4c,6f,28,0d,3f,ae)

#define GPT_ESP         SD_ID128_MAKE(c1,2a,73,28,f8,1f,11,d2,ba,4b,00,a0,c9,3e,c9,3b)
#define GPT_SWAP        SD_ID128_MAKE(06,57,fd,6d,a4,ab,43,c4,84,e5,09,33,c8,4b,4f,4f)
#define GPT_HOME        SD_ID128_MAKE(93,3a,c7,e1,2e,b4,4f,13,b8,44,0e,14,e2,ae,f9,15)
#define GPT_SRV         SD_ID128_MAKE(3b,8f,84,25,20,e0,4f,3b,90,7f,1a,25,a7,6f,98,e8)

#if defined(__x86_64__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_X86
#elif defined(__i386__)
#  define GPT_ROOT_NATIVE GPT_ROOT_X86
#endif

#if defined(__aarch64__) && !defined(WORDS_BIGENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM_64
#  define GPT_ROOT_SECONDARY GPT_ROOT_ARM
#elif defined(__arm__) && !defined(WORDS_BIGENDIAN)
#  define GPT_ROOT_NATIVE GPT_ROOT_ARM
#endif

/* Flags we recognize on the root, swap, home and srv partitions when
 * doing auto-discovery. These happen to be identical to what
 * Microsoft defines for its own Basic Data Partitions, but that's
 * just because we saw no point in defining any other values here. */
#define GPT_FLAG_READ_ONLY (1ULL << 60)
#define GPT_FLAG_NO_AUTO (1ULL << 63)
