/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/securebits.h>

/* 746bf6d64275be0c65b0631d8a72b16f1454cfa1 (4.3) */
#ifndef SECURE_NO_CAP_AMBIENT_RAISE
#define SECURE_NO_CAP_AMBIENT_RAISE        6
#define SECURE_NO_CAP_AMBIENT_RAISE_LOCKED 7  /* make bit-6 immutable */
#define SECBIT_NO_CAP_AMBIENT_RAISE        (issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
#define SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED (issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE_LOCKED))

#undef  SECURE_ALL_BITS
#define SECURE_ALL_BITS (issecure_mask(SECURE_NOROOT) |                 \
                         issecure_mask(SECURE_NO_SETUID_FIXUP) |        \
                         issecure_mask(SECURE_KEEP_CAPS) |              \
                         issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
#endif
