/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>

#include "alloc-util.h"
#include "journal-importer.h"
#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "unaligned.h"

enum {
        IMPORTER_STATE_LINE = 0,    /* waiting to read, or reading line */
        IMPORTER_STATE_DATA_START,  /* reading binary data header */
        IMPORTER_STATE_DATA,        /* reading binary data */
        IMPORTER_STATE_DATA_FINISH, /* expecting newline */
        IMPORTER_STATE_EOF,         /* done */
};

static int iovw_put(struct iovec_wrapper *iovw, void* data, size_t len) {
        if (!GREEDY_REALLOC(iovw->iovec, iovw->size_bytes, iovw->count + 1))
                return log_oom();

        iovw->iovec[iovw->count++] = (struct iovec) {data, len};
        return 0;
}

static void iovw_free_contents(struct iovec_wrapper *iovw) {
        iovw->iovec = mfree(iovw->iovec);
        iovw->size_bytes = iovw->count = 0;
}

static void iovw_rebase(struct iovec_wrapper *iovw, char *old, char *new) {
        size_t i;

        for (i = 0; i < iovw->count; i++)
                iovw->iovec[i].iov_base = (char*) iovw->iovec[i].iov_base - old + new;
}

size_t iovw_size(struct iovec_wrapper *iovw) {
        size_t n = 0, i;

        for (i = 0; i < iovw->count; i++)
                n += iovw->iovec[i].iov_len;

        return n;
}

void journal_importer_cleanup(JournalImporter *imp) {
        if (imp->fd >= 0 && !imp->passive_fd) {
                log_debug("Closing %s (fd=%d)", imp->name ?: "importer", imp->fd);
                safe_close(imp->fd);
        }

        free(imp->name);
        free(imp->buf);
        iovw_free_contents(&imp->iovw);
}

static char* realloc_buffer(JournalImporter *imp, size_t size) {
        char *b, *old = imp->buf;

        b = GREEDY_REALLOC(imp->buf, imp->size, size);
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
        assert(imp->filled <= imp->size);
        assert(imp->buf == NULL || imp->size > 0);
        assert(imp->fd >= 0);

        for (;;) {
                if (imp->buf) {
                        size_t start = MAX(imp->scanned, imp->offset);

                        c = memchr(imp->buf + start, '\n',
                                   imp->filled - start);
                        if (c != NULL)
                                break;
                }

                imp->scanned = imp->filled;
                if (imp->scanned >= DATA_SIZE_MAX) {
                        log_error("Entry is bigger than %u bytes.", DATA_SIZE_MAX);
                        return -E2BIG;
                }

                if (imp->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                /* We know that imp->filled is at most DATA_SIZE_MAX, so if
                   we reallocate it, we'll increase the size at least a bit. */
                assert_cc(DATA_SIZE_MAX < ENTRY_SIZE_MAX);
                if (imp->size - imp->filled < LINE_CHUNK &&
                    !realloc_buffer(imp, MIN(imp->filled + LINE_CHUNK, ENTRY_SIZE_MAX)))
                                return log_oom();

                assert(imp->buf);
                assert(imp->size - imp->filled >= LINE_CHUNK ||
                       imp->size == ENTRY_SIZE_MAX);

                n = read(imp->fd,
                         imp->buf + imp->filled,
                         imp->size - imp->filled);
                if (n < 0) {
                        if (errno != EAGAIN)
                                log_error_errno(errno, "read(%d, ..., %zu): %m",
                                                imp->fd,
                                                imp->size - imp->filled);
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
        assert(imp->state == IMPORTER_STATE_DATA_START ||
               imp->state == IMPORTER_STATE_DATA ||
               imp->state == IMPORTER_STATE_DATA_FINISH);
        assert(size <= DATA_SIZE_MAX);
        assert(imp->offset <= imp->filled);
        assert(imp->filled <= imp->size);
        assert(imp->buf != NULL || imp->size == 0);
        assert(imp->buf == NULL || imp->size > 0);
        assert(imp->fd >= 0);
        assert(data);

        while (imp->filled - imp->offset < size) {
                int n;

                if (imp->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                if (!realloc_buffer(imp, imp->offset + size))
                        return log_oom();

                n = read(imp->fd, imp->buf + imp->filled,
                         imp->size - imp->filled);
                if (n < 0) {
                        if (errno != EAGAIN)
                                log_error_errno(errno, "read(%d, ..., %zu): %m", imp->fd,
                                                imp->size - imp->filled);
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
        if (imp->data_size > DATA_SIZE_MAX) {
                log_error("Stream declares field with size %zu > DATA_SIZE_MAX = %u",
                          imp->data_size, DATA_SIZE_MAX);
                return -EINVAL;
        }
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
                log_error("expected newline, got '%c'", *data);
                return -EINVAL;
        }

        return 1;
}

static int process_dunder(JournalImporter *imp, char *line, size_t n) {
        const char *timestamp;
        int r;

        assert(line);
        assert(n > 0);
        assert(line[n-1] == '\n');

        /* XXX: is it worth to support timestamps in extended format?
         * We don't produce them, but who knows... */

        timestamp = startswith(line, "__CURSOR=");
        if (timestamp)
                /* ignore __CURSOR */
                return 1;

        timestamp = startswith(line, "__REALTIME_TIMESTAMP=");
        if (timestamp) {
                long long unsigned x;
                line[n-1] = '\0';
                r = safe_atollu(timestamp, &x);
                if (r < 0)
                        log_warning("Failed to parse __REALTIME_TIMESTAMP: '%s'", timestamp);
                else
                        imp->ts.realtime = x;
                return r < 0 ? r : 1;
        }

        timestamp = startswith(line, "__MONOTONIC_TIMESTAMP=");
        if (timestamp) {
                long long unsigned x;
                line[n-1] = '\0';
                r = safe_atollu(timestamp, &x);
                if (r < 0)
                        log_warning("Failed to parse __MONOTONIC_TIMESTAMP: '%s'", timestamp);
                else
                        imp->ts.monotonic = x;
                return r < 0 ? r : 1;
        }

        timestamp = startswith(line, "__");
        if (timestamp) {
                log_notice("Unknown dunder line %s", line);
                return 1;
        }

        /* no dunder */
        return 0;
}

int journal_importer_process_data(JournalImporter *imp) {
        int r;

        switch(imp->state) {
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

                r = process_dunder(imp, line, n);
                if (r != 0)
                        return r < 0 ? r : 0;

                /* MESSAGE=xxx\n
                   or
                   COREDUMP\n
                   LLLLLLLL0011223344...\n
                */
                sep = memchr(line, '=', n);
                if (sep) {
                        /* chomp newline */
                        n--;

                        r = iovw_put(&imp->iovw, line, n);
                        if (r < 0)
                                return r;
                } else {
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
                assert_not_reached("wtf?");
        }
}

int journal_importer_push_data(JournalImporter *imp, const char *data, size_t size) {
        assert(imp);
        assert(imp->state != IMPORTER_STATE_EOF);

        if (!realloc_buffer(imp, imp->filled + size)) {
                log_error("Failed to store received data of size %zu "
                          "(in addition to existing %zu bytes with %zu filled): %s",
                          size, imp->size, imp->filled, strerror(ENOMEM));
                return -ENOMEM;
        }

        memcpy(imp->buf + imp->filled, data, size);
        imp->filled += size;

        return 0;
}

void journal_importer_drop_iovw(JournalImporter *imp) {
        size_t remain, target;

        /* This function drops processed data that along with the iovw that points at it */

        iovw_free_contents(&imp->iovw);

        /* possibly reset buffer position */
        remain = imp->filled - imp->offset;

        if (remain == 0) /* no brainer */
                imp->offset = imp->scanned = imp->filled = 0;
        else if (imp->offset > imp->size - imp->filled &&
                 imp->offset > remain) {
                memcpy(imp->buf, imp->buf + imp->offset, remain);
                imp->offset = imp->scanned = 0;
                imp->filled = remain;
        }

        target = imp->size;
        while (target > 16 * LINE_CHUNK && imp->filled < target / 2)
                target /= 2;
        if (target < imp->size) {
                char *tmp;

                tmp = realloc(imp->buf, target);
                if (!tmp)
                        log_warning("Failed to reallocate buffer to (smaller) size %zu",
                                    target);
                else {
                        log_debug("Reallocated buffer from %zu to %zu bytes",
                                  imp->size, target);
                        imp->buf = tmp;
                        imp->size = target;
                }
        }
}

bool journal_importer_eof(const JournalImporter *imp) {
        return imp->state == IMPORTER_STATE_EOF;
}
