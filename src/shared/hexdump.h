/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void hexdump(FILE *f, const void *p, size_t s) _nonnull_if_nonzero_(2, 3);

/* Returns a hexdump(3)-like side-by-side dump of two memory regions, marking the differing bytes. Returns
 * NULL on OOM. Meant for assertion failure messages, see ASSERT_MEMEQ() and friends. */
char* hexdump_memcmp(const void *m1, size_t l1, const void *m2, size_t l2);
