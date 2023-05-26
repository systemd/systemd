/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "memstream-util.h"

typedef struct MemStream {
        FILE *f;
        char *buf;
        size_t sz;
} MemStream;

MemStream* memstream_free(MemStream *m) {
        if (!m)
                return NULL;

        /* First, close file stream, as the buffer may be reallocated on close. */
        safe_fclose(m->f);

        /* Then, free buffer. */
        free(m->buf);

        return mfree(m);
}

FILE* memstream_open(MemStream **ret) {
        _cleanup_(memstream_freep) MemStream *m = NULL;

        assert(ret);

        m = new0(MemStream, 1);
        if (!m)
                return NULL;

        m->f = open_memstream_unlocked(&m->buf, &m->sz);
        if (!m->f)
                return NULL;

        *ret = TAKE_PTR(m);
        return (*ret)->f;
}

int memstream_finalize(MemStream *m, char **ret_buf, size_t *ret_size) {
        int r;

        assert(m);
        assert(m->f);
        assert(ret_buf);

        /* Add terminating NUL, so that the output buffer is a valid string. */
        fputc('\0', m->f);

        r = fflush_and_check(m->f);
        if (r < 0)
                return r;

        m->f = safe_fclose(m->f);

        /* On fclose(), the buffer may be reallocated, and may trigger OOM. */
        if (!m->buf)
                return -ENOMEM;

        *ret_buf = TAKE_PTR(m->buf);
        if (ret_size)
                *ret_size = m->sz - 1;

        return 0;
}
