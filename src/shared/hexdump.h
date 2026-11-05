/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void hexdump(FILE *f, const void *p, size_t s) _nonnull_if_nonzero_(2, 3);

/* Returns a hexdump(3)-like side-by-side dump of two memory regions, marking the differing bytes. Returns
 * NULL on OOM. Meant for assertion failure messages, see ASSERT_MEMEQ() and friends. */
char* hexdump_memcmp(const void *m1, size_t l1, const void *m2, size_t l2);

/* Like hexdump_memcmp(), but compares against a region of the same length filled with 'byte'. */
char* hexdump_memcmp_byte(uint8_t byte, const void *data, size_t length);

/* Dumps the differing elements of two iovec wrappers, element by element. Used by ASSERT_IOVW_EQ(). */
char* hexdump_iovw_compare(const struct iovec_wrapper *a, const struct iovec_wrapper *b);
