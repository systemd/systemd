/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <malloc.h>

#if HAVE_MALLINFO2 /* since glibc-2.33 */
typedef struct mallinfo2 generic_mallinfo;
static inline generic_mallinfo generic_mallinfo_get(void) {
        return mallinfo2();
}
#else
typedef struct mallinfo generic_mallinfo;
static inline generic_mallinfo generic_mallinfo_get(void) {
        return mallinfo();
}
#endif
