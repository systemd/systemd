/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "memstream-util.h"

void memstream_done(MemStream *m) {
        assert(m);

        /* First, close file stream, as the buffer may be reallocated on close. */
        safe_fclose(m->f);

        /* Then, free buffer. */
        free(m->buf);
}

int memstream_open(MemStream *m, FILE **ret) {
        assert(m);

        m->f = open_memstream_unlocked(&m->buf, &m->sz);
        if (!m->f)
                return -ENOMEM;

        if (ret)
                *ret = m->f;
        return 0;
}

int memstream_close(MemStream *m, char **ret_buf, size_t *ret_size) {
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

        /* On fclose(), the buffer may be reallocated, and may trigger OOM.
         * Unfortunately, even if that happens, fclose() returns 0. */
        if (!m->buf)
                return -ENOMEM;

        *ret_buf = TAKE_PTR(m->buf);
        if (ret_size)
                *ret_size = m->sz - 1;

        return 0;
}
