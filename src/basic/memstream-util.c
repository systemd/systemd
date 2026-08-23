/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "memstream-util.h"

void memstream_done(MemStream *m) {
        assert(m);

        /* First, close file stream, as the buffer may be reallocated on close. */
        safe_fclose(m->f);

        /* Then, free buffer. */
        free(m->buf);
}

FILE* memstream_init(MemStream *m) {
        assert(m);
        assert(!m->f);

        m->f = open_memstream_unlocked(&m->buf, &m->sz);
        return m->f;
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

        assert(m->sz > 0);

        *ret_buf = TAKE_PTR(m->buf);
        if (ret_size)
                *ret_size = m->sz - 1;

        m->sz = 0; /* For safety when the MemStream object will be reused later. */
        return 0;
}

int memstream_dump_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                MemStream *m) {

        _cleanup_free_ char *buf = NULL;
        int r;

        assert(m);

        r = memstream_finalize(m, &buf, NULL);
        if (r < 0)
                return log_full_errno(level, r, "Failed to flush memstream: %m");

        return log_dump_internal(level, error, file, line, func, buf);
}
