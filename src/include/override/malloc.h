/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <malloc.h>

#if !HAVE_MALLINFO2
struct mallinfo2 {
        size_t arena;    /* non-mmapped space allocated from system */
        size_t ordblks;  /* number of free chunks */
        size_t smblks;   /* number of fastbin blocks */
        size_t hblks;    /* number of mmapped regions */
        size_t hblkhd;   /* space in mmapped regions */
        size_t usmblks;  /* always 0, preserved for backwards compatibility */
        size_t fsmblks;  /* space available in freed fastbin blocks */
        size_t uordblks; /* total allocated space */
        size_t fordblks; /* total free space */
        size_t keepcost; /* top-most, releasable (via malloc_trim) space */
};

static inline struct mallinfo2 mallinfo2(void) {
        _Pragma("GCC diagnostic push");
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"");
        struct mallinfo m = mallinfo();
        _Pragma("GCC diagnostic pop");

        return (struct mallinfo2) {
                .arena = m.arena,
                .ordblks = m.ordblks,
                .smblks = m.smblks,
                .hblks = m.hblks,
                .hblkhd = m.hblkhd,
                .usmblks = 0,
                .fsmblks = m.fsmblks,
                .uordblks = m.uordblks,
                .fordblks = m.fordblks,
                .keepcost = m.keepcost,
        };
}
#endif
