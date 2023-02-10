/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <malloc.h>

#if HAVE_MALLINFO2
#  define HAVE_GENERIC_MALLINFO 1
typedef struct mallinfo2 generic_mallinfo;
static inline generic_mallinfo generic_mallinfo_get(void) {
        return mallinfo2();
}
#elif HAVE_MALLINFO
#  define HAVE_GENERIC_MALLINFO 1
typedef struct mallinfo generic_mallinfo;
static inline generic_mallinfo generic_mallinfo_get(void) {
        /* glibc has deprecated mallinfo(), let's suppress the deprecation warning if mallinfo2() doesn't
         * exist yet. */
DISABLE_WARNING_DEPRECATED_DECLARATIONS
        return mallinfo();
REENABLE_WARNING
}
#else
#  define HAVE_GENERIC_MALLINFO 0
#endif
