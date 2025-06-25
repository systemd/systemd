/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "journal-file.h"
#include "journal-importer.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"

enum {
        IMPORTER_STATE_LINE = 0,    /* waiting to read, or reading line */
        IMPORTER_STATE_DATA_START,  /* reading binary data header */
        IMPORTER_STATE_DATA,        /* reading binary data */
        IMPORTER_STATE_DATA_FINISH, /* expecting newline */
        IMPORTER_STATE_EOF,         /* done */
};

void journal_importer_cleanup(JournalImporter *imp) {
        if (imp->fd >= 0 && !imp->passive_fd) {
                log_debug("Closing %s (fd=%d)", imp->name ?: "importer", imp->fd);
                safe_close(imp->fd);
        }

        free(imp->name);
        free(imp->buf);
        iovw_done(&imp->iovw);
}

static char* realloc_buffer(JournalImporter *imp, size_t size) {
        char *b, *old = ASSERT_PTR(imp)->buf;

        b = GREEDY_REALLOC(imp->buf, size);
        if (!b)
                return NULL;

        iovw_rebase(&imp->iovw, old, imp->buf);

        return b;
}

static int get_line(JournalImporter *imp, char **line, size_t *size) {
        ssize_t n;
        char *c = NULL;

        assert(imp);
        assert(imp->state == IMPORTER_STATE_LINE);
        assert(imp->offset <= imp->filled);
        assert(imp->filled <= MALLOC_SIZEOF_SAFE(imp->buf));
        assert(imp->fd >= 0);

        for (;;) {
                if (imp->buf) {
                        size_t start = MAX(imp->scanned, imp->offset);

                        c = memchr(imp->buf + start, '\n',
                                   imp->filled - start);
                        if (c)
                                break;
                }

                imp->scanned = imp->filled;
                if (imp->scanned >= DATA_SIZE_MAX)
                        return log_warning_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                                 "Entry is bigger than %u bytes.",
                                                 DATA_SIZE_MAX);

                if (imp->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                /* We know that imp->filled is at most DATA_SIZE_MAX, so if
                   we reallocate it, we'll increase the size at least a bit. */
                assert_cc(DATA_SIZE_MAX < ENTRY_SIZE_MAX);
                if (MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled < LINE_CHUNK &&
                    !realloc_buffer(imp, MIN(imp->filled + LINE_CHUNK, ENTRY_SIZE_MAX)))
                                return log_oom();

                assert(imp->buf);
                assert(MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled >= LINE_CHUNK ||
                       MALLOC_SIZEOF_SAFE(imp->buf) >= ENTRY_SIZE_MAX);

                n = read(imp->fd,
                         imp->buf + imp->filled,
                         MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled);
                if (n < 0) {
                        if (ERRNO_IS_DISCONNECT(errno)) {
                                log_debug_errno(errno, "Got disconnect for importer %s.", strna(imp->name));
                                return 0;
                        }

                        if (!ERRNO_IS_TRANSIENT(errno))
                                log_error_errno(errno, "read(%d, ..., %zu): %m",
                                                imp->fd,
                                                MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled);
                        return -errno;
                } else if (n == 0)
                        return 0;

                imp->filled += n;
        }

        *line = imp->buf + imp->offset;
        *size = c + 1 - imp->buf - imp->offset;
        imp->offset += *size;

        return 1;
}

static int fill_fixed_size(JournalImporter *imp, void **data, size_t size) {

        assert(imp);
        assert(IN_SET(imp->state, IMPORTER_STATE_DATA_START, IMPORTER_STATE_DATA, IMPORTER_STATE_DATA_FINISH));
        assert(size <= DATA_SIZE_MAX);
        assert(imp->offset <= imp->filled);
        assert(imp->filled <= MALLOC_SIZEOF_SAFE(imp->buf));
        assert(imp->fd >= 0);
        assert(data);

        while (imp->filled - imp->offset < size) {
                ssize_t n;

                if (imp->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                if (!realloc_buffer(imp, imp->offset + size))
                        return log_oom();

                n = read(imp->fd, imp->buf + imp->filled,
                         MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled);
                if (n < 0) {
                        if (ERRNO_IS_DISCONNECT(errno)) {
                                log_debug_errno(errno, "Got disconnect for importer %s.", strna(imp->name));
                                return 0;
                        }

                        if (!ERRNO_IS_TRANSIENT(errno))
                                log_error_errno(errno, "read(%d, ..., %zu): %m", imp->fd,
                                                MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled);
                        return -errno;
                } else if (n == 0)
                        return 0;

                imp->filled += n;
        }

        *data = imp->buf + imp->offset;
        imp->offset += size;

        return 1;
}

static int get_data_size(JournalImporter *imp) {
        int r;
        void *data;

        assert(imp);
        assert(imp->state == IMPORTER_STATE_DATA_START);
        assert(imp->data_size == 0);

        r = fill_fixed_size(imp, &data, sizeof(uint64_t));
        if (r <= 0)
                return r;

        imp->data_size = unaligned_read_le64(data);
        if (imp->data_size > DATA_SIZE_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Stream declares field with size %zu > DATA_SIZE_MAX = %u",
                                         imp->data_size, DATA_SIZE_MAX);
        if (imp->data_size == 0)
                log_warning("Binary field with zero length");

        return 1;
}

static int get_data_data(JournalImporter *imp, void **data) {
        int r;

        assert(imp);
        assert(data);
        assert(imp->state == IMPORTER_STATE_DATA);

        r = fill_fixed_size(imp, data, imp->data_size);
        if (r <= 0)
                return r;

        return 1;
}

static int get_data_newline(JournalImporter *imp) {
        int r;
        char *data;

        assert(imp);
        assert(imp->state == IMPORTER_STATE_DATA_FINISH);

        r = fill_fixed_size(imp, (void**) &data, 1);
        if (r <= 0)
                return r;

        assert(data);
        if (*data != '\n') {
                char buf[4];
                int l;

                l = cescape_char(*data, buf);
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Expected newline, got '%.*s'", l, buf);
        }

        return 1;
}

static int process_special_field(JournalImporter *imp, char *line) {
        const char *value;
        char buf[CELLESCAPE_DEFAULT_LENGTH];
        int r;

        assert(line);

        if (STARTSWITH_SET(line, "__CURSOR=", "__SEQNUM=", "__SEQNUM_ID="))
                /* ignore __CURSOR=, __SEQNUM=, __SEQNUM_ID= which we cannot replicate */
                return 1;

        value = startswith(line, "__REALTIME_TIMESTAMP=");
        if (value) {
                uint64_t x;

                r = safe_atou64(value, &x);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse __REALTIME_TIMESTAMP '%s': %m",
                                                 cellescape(buf, sizeof buf, value));
                else if (!VALID_REALTIME(x)) {
                        log_warning("__REALTIME_TIMESTAMP out of range, ignoring: %"PRIu64, x);
                        return -ERANGE;
                }

                imp->ts.realtime = x;
                return 1;
        }

        value = startswith(line, "__MONOTONIC_TIMESTAMP=");
        if (value) {
                uint64_t x;

                r = safe_atou64(value, &x);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse __MONOTONIC_TIMESTAMP '%s': %m",
                                                 cellescape(buf, sizeof buf, value));
                else if (!VALID_MONOTONIC(x)) {
                        log_warning("__MONOTONIC_TIMESTAMP out of range, ignoring: %"PRIu64, x);
                        return -ERANGE;
                }

                imp->ts.monotonic = x;
                return 1;
        }

        /* Just a single underline, but it needs special treatment too. */
        value = startswith(line, "_BOOT_ID=");
        if (value) {
                r = sd_id128_from_string(value, &imp->boot_id);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse _BOOT_ID '%s': %m",
                                                 cellescape(buf, sizeof buf, value));

                /* store the field in the usual fashion too */
                return 0;
        }

        value = startswith(line, "__");
        if (value) {
                log_notice("Unknown dunder line __%s, ignoring.", cellescape(buf, sizeof buf, value));
                return 1;
        }

        /* no dunder */
        return 0;
}

int journal_importer_process_data(JournalImporter *imp) {
        int r;

        switch (imp->state) {
        case IMPORTER_STATE_LINE: {
                char *line, *sep;
                size_t n = 0;

                assert(imp->data_size == 0);

                r = get_line(imp, &line, &n);
                if (r < 0)
                        return r;
                if (r == 0) {
                        imp->state = IMPORTER_STATE_EOF;
                        return 0;
                }
                assert(n > 0);
                assert(line[n-1] == '\n');

                if (n == 1) {
                        log_trace("Received empty line, event is ready");
                        return 1;
                }

                /* MESSAGE=xxx\n
                   or
                   COREDUMP\n
                   LLLLLLLL0011223344...\n
                */
                sep = memchr(line, '=', n);
                if (sep) {
                        /* chomp newline */
                        n--;

                        if (!journal_field_valid(line, sep - line, true)) {
                                char buf[64], *t;

                                t = strndupa_safe(line, sep - line);
                                log_debug("Ignoring invalid field: \"%s\"",
                                          cellescape(buf, sizeof buf, t));

                                return 0;
                        }

                        line[n] = '\0';
                        r = process_special_field(imp, line);
                        if (r != 0)
                                return r < 0 ? r : 0;

                        r = iovw_put(&imp->iovw, line, n);
                        if (r < 0)
                                return r;
                } else {
                        if (!journal_field_valid(line, n - 1, true)) {
                                char buf[64], *t;

                                t = strndupa_safe(line, n - 1);
                                log_debug("Ignoring invalid field: \"%s\"",
                                          cellescape(buf, sizeof buf, t));

                                return 0;
                        }

                        /* replace \n with = */
                        line[n-1] = '=';

                        imp->field_len = n;
                        imp->state = IMPORTER_STATE_DATA_START;

                        /* we cannot put the field in iovec until we have all data */
                }

                log_trace("Received: %.*s (%s)", (int) n, line, sep ? "text" : "binary");

                return 0; /* continue */
        }

        case IMPORTER_STATE_DATA_START:
                assert(imp->data_size == 0);

                r = get_data_size(imp);
                // log_debug("get_data_size() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        imp->state = IMPORTER_STATE_EOF;
                        return 0;
                }

                imp->state = imp->data_size > 0 ?
                        IMPORTER_STATE_DATA : IMPORTER_STATE_DATA_FINISH;

                return 0; /* continue */

        case IMPORTER_STATE_DATA: {
                void *data;
                char *field;

                assert(imp->data_size > 0);

                r = get_data_data(imp, &data);
                // log_debug("get_data_data() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        imp->state = IMPORTER_STATE_EOF;
                        return 0;
                }

                assert(data);

                field = (char*) data - sizeof(uint64_t) - imp->field_len;
                memmove(field + sizeof(uint64_t), field, imp->field_len);

                r = iovw_put(&imp->iovw, field + sizeof(uint64_t), imp->field_len + imp->data_size);
                if (r < 0)
                        return r;

                imp->state = IMPORTER_STATE_DATA_FINISH;

                return 0; /* continue */
        }

        case IMPORTER_STATE_DATA_FINISH:
                r = get_data_newline(imp);
                // log_debug("get_data_newline() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        imp->state = IMPORTER_STATE_EOF;
                        return 0;
                }

                imp->data_size = 0;
                imp->state = IMPORTER_STATE_LINE;

                return 0; /* continue */
        default:
                assert_not_reached();
        }
}

int journal_importer_push_data(JournalImporter *imp, const char *data, size_t size) {
        assert(imp);
        assert(imp->state != IMPORTER_STATE_EOF);

        if (!realloc_buffer(imp, imp->filled + size))
                return log_error_errno(ENOMEM,
                                       "Failed to store received data of size %zu "
                                       "(in addition to existing %zu bytes with %zu filled): %m",
                                       size, MALLOC_SIZEOF_SAFE(imp->buf), imp->filled);

        memcpy(imp->buf + imp->filled, data, size);
        imp->filled += size;

        return 0;
}

void journal_importer_drop_iovw(JournalImporter *imp) {
        size_t remain, target;

        /* This function drops processed data that along with the iovw that points at it */

        iovw_done(&imp->iovw);

        /* possibly reset buffer position */
        remain = imp->filled - imp->offset;

        if (remain == 0) /* no brainer */
                imp->offset = imp->scanned = imp->filled = 0;
        else if (imp->offset > MALLOC_SIZEOF_SAFE(imp->buf) - imp->filled &&
                 imp->offset > remain) {
                memcpy(imp->buf, imp->buf + imp->offset, remain);
                imp->offset = imp->scanned = 0;
                imp->filled = remain;
        }

        target = MALLOC_SIZEOF_SAFE(imp->buf);
        while (target > 16 * LINE_CHUNK && imp->filled < target / 2)
                target /= 2;
        if (target < MALLOC_SIZEOF_SAFE(imp->buf)) {
                char *tmp;
                size_t old_size;

                old_size = MALLOC_SIZEOF_SAFE(imp->buf);

                tmp = realloc(imp->buf, target);
                if (!tmp)
                        log_warning("Failed to reallocate buffer to (smaller) size %zu",
                                    target);
                else {
                        log_debug("Reallocated buffer from %zu to %zu bytes",
                                  old_size, target);
                        imp->buf = tmp;
                }
        }
}

bool journal_importer_eof(const JournalImporter *imp) {
        return imp->state == IMPORTER_STATE_EOF;
}
