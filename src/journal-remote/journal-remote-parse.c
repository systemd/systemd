/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "journal-remote-parse.h"
#include "journald-native.h"

#define LINE_CHUNK 8*1024u

void source_free(RemoteSource *source) {
        if (!source)
                return;

        if (source->fd >= 0 && !source->passive_fd) {
                log_debug("Closing fd:%d (%s)", source->fd, source->name);
                safe_close(source->fd);
        }

        free(source->name);
        free(source->buf);
        iovw_free_contents(&source->iovw);

        log_debug("Writer ref count %i", source->writer->n_ref);
        writer_unref(source->writer);

        sd_event_source_unref(source->event);
        sd_event_source_unref(source->buffer_event);

        free(source);
}

/**
 * Initialize zero-filled source with given values. On success, takes
 * ownerhship of fd and writer, otherwise does not touch them.
 */
RemoteSource* source_new(int fd, bool passive_fd, char *name, Writer *writer) {

        RemoteSource *source;

        log_debug("Creating source for %sfd:%d (%s)",
                  passive_fd ? "passive " : "", fd, name);

        assert(fd >= 0);

        source = new0(RemoteSource, 1);
        if (!source)
                return NULL;

        source->fd = fd;
        source->passive_fd = passive_fd;
        source->name = name;
        source->writer = writer;

        return source;
}

static char* realloc_buffer(RemoteSource *source, size_t size) {
        char *b, *old = source->buf;

        b = GREEDY_REALLOC(source->buf, source->size, size);
        if (!b)
                return NULL;

        iovw_rebase(&source->iovw, old, source->buf);

        return b;
}

static int get_line(RemoteSource *source, char **line, size_t *size) {
        ssize_t n;
        char *c = NULL;

        assert(source);
        assert(source->state == STATE_LINE);
        assert(source->offset <= source->filled);
        assert(source->filled <= source->size);
        assert(source->buf == NULL || source->size > 0);
        assert(source->fd >= 0);

        for (;;) {
                if (source->buf) {
                        size_t start = MAX(source->scanned, source->offset);

                        c = memchr(source->buf + start, '\n',
                                   source->filled - start);
                        if (c != NULL)
                                break;
                }

                source->scanned = source->filled;
                if (source->scanned >= DATA_SIZE_MAX) {
                        log_error("Entry is bigger than %u bytes.", DATA_SIZE_MAX);
                        return -E2BIG;
                }

                if (source->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                /* We know that source->filled is at most DATA_SIZE_MAX, so if
                   we reallocate it, we'll increase the size at least a bit. */
                assert_cc(DATA_SIZE_MAX < ENTRY_SIZE_MAX);
                if (source->size - source->filled < LINE_CHUNK &&
                    !realloc_buffer(source, MIN(source->filled + LINE_CHUNK, ENTRY_SIZE_MAX)))
                                return log_oom();

                assert(source->buf);
                assert(source->size - source->filled >= LINE_CHUNK ||
                       source->size == ENTRY_SIZE_MAX);

                n = read(source->fd,
                         source->buf + source->filled,
                         source->size - source->filled);
                if (n < 0) {
                        if (errno != EAGAIN)
                                log_error_errno(errno, "read(%d, ..., %zu): %m",
                                                source->fd,
                                                source->size - source->filled);
                        return -errno;
                } else if (n == 0)
                        return 0;

                source->filled += n;
        }

        *line = source->buf + source->offset;
        *size = c + 1 - source->buf - source->offset;
        source->offset += *size;

        return 1;
}

int push_data(RemoteSource *source, const char *data, size_t size) {
        assert(source);
        assert(source->state != STATE_EOF);

        if (!realloc_buffer(source, source->filled + size)) {
                log_error("Failed to store received data of size %zu "
                          "(in addition to existing %zu bytes with %zu filled): %s",
                          size, source->size, source->filled, strerror(ENOMEM));
                return -ENOMEM;
        }

        memcpy(source->buf + source->filled, data, size);
        source->filled += size;

        return 0;
}

static int fill_fixed_size(RemoteSource *source, void **data, size_t size) {

        assert(source);
        assert(source->state == STATE_DATA_START ||
               source->state == STATE_DATA ||
               source->state == STATE_DATA_FINISH);
        assert(size <= DATA_SIZE_MAX);
        assert(source->offset <= source->filled);
        assert(source->filled <= source->size);
        assert(source->buf != NULL || source->size == 0);
        assert(source->buf == NULL || source->size > 0);
        assert(source->fd >= 0);
        assert(data);

        while (source->filled - source->offset < size) {
                int n;

                if (source->passive_fd)
                        /* we have to wait for some data to come to us */
                        return -EAGAIN;

                if (!realloc_buffer(source, source->offset + size))
                        return log_oom();

                n = read(source->fd, source->buf + source->filled,
                         source->size - source->filled);
                if (n < 0) {
                        if (errno != EAGAIN)
                                log_error_errno(errno, "read(%d, ..., %zu): %m", source->fd,
                                                source->size - source->filled);
                        return -errno;
                } else if (n == 0)
                        return 0;

                source->filled += n;
        }

        *data = source->buf + source->offset;
        source->offset += size;

        return 1;
}

static int get_data_size(RemoteSource *source) {
        int r;
        void *data;

        assert(source);
        assert(source->state == STATE_DATA_START);
        assert(source->data_size == 0);

        r = fill_fixed_size(source, &data, sizeof(uint64_t));
        if (r <= 0)
                return r;

        source->data_size = le64toh( *(uint64_t *) data );
        if (source->data_size > DATA_SIZE_MAX) {
                log_error("Stream declares field with size %zu > DATA_SIZE_MAX = %u",
                          source->data_size, DATA_SIZE_MAX);
                return -EINVAL;
        }
        if (source->data_size == 0)
                log_warning("Binary field with zero length");

        return 1;
}

static int get_data_data(RemoteSource *source, void **data) {
        int r;

        assert(source);
        assert(data);
        assert(source->state == STATE_DATA);

        r = fill_fixed_size(source, data, source->data_size);
        if (r <= 0)
                return r;

        return 1;
}

static int get_data_newline(RemoteSource *source) {
        int r;
        char *data;

        assert(source);
        assert(source->state == STATE_DATA_FINISH);

        r = fill_fixed_size(source, (void**) &data, 1);
        if (r <= 0)
                return r;

        assert(data);
        if (*data != '\n') {
                log_error("expected newline, got '%c'", *data);
                return -EINVAL;
        }

        return 1;
}

static int process_dunder(RemoteSource *source, char *line, size_t n) {
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
                        source->ts.realtime = x;
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
                        source->ts.monotonic = x;
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

static int process_data(RemoteSource *source) {
        int r;

        switch(source->state) {
        case STATE_LINE: {
                char *line, *sep;
                size_t n = 0;

                assert(source->data_size == 0);

                r = get_line(source, &line, &n);
                if (r < 0)
                        return r;
                if (r == 0) {
                        source->state = STATE_EOF;
                        return r;
                }
                assert(n > 0);
                assert(line[n-1] == '\n');

                if (n == 1) {
                        log_trace("Received empty line, event is ready");
                        return 1;
                }

                r = process_dunder(source, line, n);
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

                        r = iovw_put(&source->iovw, line, n);
                        if (r < 0)
                                return r;
                } else {
                        /* replace \n with = */
                        line[n-1] = '=';

                        source->field_len = n;
                        source->state = STATE_DATA_START;

                        /* we cannot put the field in iovec until we have all data */
                }

                log_trace("Received: %.*s (%s)", (int) n, line, sep ? "text" : "binary");

                return 0; /* continue */
        }

        case STATE_DATA_START:
                assert(source->data_size == 0);

                r = get_data_size(source);
                // log_debug("get_data_size() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        source->state = STATE_EOF;
                        return 0;
                }

                source->state = source->data_size > 0 ?
                        STATE_DATA : STATE_DATA_FINISH;

                return 0; /* continue */

        case STATE_DATA: {
                void *data;
                char *field;

                assert(source->data_size > 0);

                r = get_data_data(source, &data);
                // log_debug("get_data_data() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        source->state = STATE_EOF;
                        return 0;
                }

                assert(data);

                field = (char*) data - sizeof(uint64_t) - source->field_len;
                memmove(field + sizeof(uint64_t), field, source->field_len);

                r = iovw_put(&source->iovw, field + sizeof(uint64_t), source->field_len + source->data_size);
                if (r < 0)
                        return r;

                source->state = STATE_DATA_FINISH;

                return 0; /* continue */
        }

        case STATE_DATA_FINISH:
                r = get_data_newline(source);
                // log_debug("get_data_newline() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        source->state = STATE_EOF;
                        return 0;
                }

                source->data_size = 0;
                source->state = STATE_LINE;

                return 0; /* continue */
        default:
                assert_not_reached("wtf?");
        }
}

int process_source(RemoteSource *source, bool compress, bool seal) {
        size_t remain, target;
        int r;

        assert(source);
        assert(source->writer);

        r = process_data(source);
        if (r <= 0)
                return r;

        /* We have a full event */
        log_trace("Received full event from source@%p fd:%d (%s)",
                  source, source->fd, source->name);

        if (!source->iovw.count) {
                log_warning("Entry with no payload, skipping");
                goto freeing;
        }

        assert(source->iovw.iovec);
        assert(source->iovw.count);

        r = writer_write(source->writer, &source->iovw, &source->ts, compress, seal);
        if (r < 0)
                log_error_errno(r, "Failed to write entry of %zu bytes: %m",
                                iovw_size(&source->iovw));
        else
                r = 1;

 freeing:
        iovw_free_contents(&source->iovw);

        /* possibly reset buffer position */
        remain = source->filled - source->offset;

        if (remain == 0) /* no brainer */
                source->offset = source->scanned = source->filled = 0;
        else if (source->offset > source->size - source->filled &&
                 source->offset > remain) {
                memcpy(source->buf, source->buf + source->offset, remain);
                source->offset = source->scanned = 0;
                source->filled = remain;
        }

        target = source->size;
        while (target > 16 * LINE_CHUNK && remain < target / 2)
                target /= 2;
        if (target < source->size) {
                char *tmp;

                tmp = realloc(source->buf, target);
                if (!tmp)
                        log_warning("Failed to reallocate buffer to (smaller) size %zu",
                                    target);
                else {
                        log_debug("Reallocated buffer from %zu to %zu bytes",
                                  source->size, target);
                        source->buf = tmp;
                        source->size = target;
                }
        }

        return r;
}
