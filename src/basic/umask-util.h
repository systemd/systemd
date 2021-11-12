/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"

static inline void umaskp(mode_t *u) {
        umask(*u & 0777);
}

#define _cleanup_umask_ _cleanup_(umaskp)

/* We make use of the fact here that the umask() concept is using only the lower 9 bits of mode_t, although
 * mode_t has space for the file type in the bits further up. We simply OR in the file type mask S_IFMT to
 * distinguish the first and the second iteration of the RUN_WITH_UMASK() loop, so that we can run the first
 * one, and exit on the second. */

assert_cc((S_IFMT & 0777) == 0);

#define RUN_WITH_UMASK(mask)                                            \
        for (_cleanup_umask_ mode_t _saved_umask_ = umask(mask) | S_IFMT; \
             FLAGS_SET(_saved_umask_, S_IFMT);                          \
             _saved_umask_ &= 0777)

#define BLOCK_WITH_UMASK(mask) \
        _unused_ _cleanup_umask_ mode_t _saved_umask_ = umask(mask);
