/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdio.h>

/* struct mallinfo2 will be defined and struct mallinfo is converted to struct mallinfo2 in
 * override/malloc.h. Hence, here we define struct mallinfo. */

struct mallinfo {
        int arena;    /* non-mmapped space allocated from system */
        int ordblks;  /* number of free chunks */
        int smblks;   /* number of fastbin blocks */
        int hblks;    /* number of mmapped regions */
        int hblkhd;   /* space in mmapped regions */
        int usmblks;  /* always 0, preserved for backwards compatibility */
        int fsmblks;  /* space available in freed fastbin blocks */
        int uordblks; /* total allocated space */
        int fordblks; /* total free space */
        int keepcost; /* top-most, releasable (via malloc_trim) space */
};

static inline struct mallinfo mallinfo(void) {
        return (struct mallinfo) {};
}

static inline int malloc_info(int options, FILE *stream) {
        if (options != 0)
                errno = EINVAL;
        else
                errno = EOPNOTSUPP;
        return -1;
}

static inline int malloc_trim(size_t pad) {
        return 0;
}

#include_next <malloc.h>
