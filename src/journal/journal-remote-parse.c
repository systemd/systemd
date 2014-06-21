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

#define LINE_CHUNK 1024u

void source_free(RemoteSource *source) {
        if (!source)
                return;

        if (source->fd >= 0) {
                log_debug("Closing fd:%d (%s)", source->fd, source->name);
                close(source->fd);
        }
        free(source->name);
        free(source->buf);
        iovw_free_contents(&source->iovw);
        free(source);
}

static int get_line(RemoteSource *source, char **line, size_t *size) {
        ssize_t n, remain;
        char *c = NULL;
        char *newbuf = NULL;
        size_t newsize = 0;

        assert(source);
        assert(source->state == STATE_LINE);
        assert(source->filled <= source->size);
        assert(source->buf == NULL || source->size > 0);

        if (source->buf)
                c = memchr(source->buf, '\n', source->filled);

        if (c != NULL)
                goto docopy;

 resize:
        if (source->fd < 0)
                /* we have to wait for some data to come to us */
                return -EWOULDBLOCK;

        if (source->size - source->filled < LINE_CHUNK) {
                // XXX: add check for maximum line length

                if (!GREEDY_REALLOC(source->buf, source->size,
                                    source->filled + LINE_CHUNK))
                        return log_oom();
        }
        assert(source->size - source->filled >= LINE_CHUNK);

        n = read(source->fd, source->buf + source->filled,
                 source->size - source->filled);
        if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                        log_error("read(%d, ..., %zd): %m", source->fd,
                                  source->size - source->filled);
                return -errno;
        } else if (n == 0)
                return 0;

        c = memchr(source->buf + source->filled, '\n', n);
        source->filled += n;

        if (c == NULL)
                goto resize;

 docopy:
        *line = source->buf;
        *size = c + 1 - source->buf;

        /* Check if something remains */
        remain = source->buf + source->filled - c - 1;
        assert(remain >= 0);
        if (remain) {
                newsize = MAX(remain, LINE_CHUNK);
                newbuf = malloc(newsize);
                if (!newbuf)
                        return log_oom();
                memcpy(newbuf, c + 1, remain);
        }
        source->buf = newbuf;
        source->size = newsize;
        source->filled = remain;

        return 1;
}

int push_data(RemoteSource *source, const char *data, size_t size) {
        assert(source);
        assert(source->state != STATE_EOF);

        if (!GREEDY_REALLOC(source->buf, source->size,
                            source->filled + size))
                return log_oom();

        memcpy(source->buf + source->filled, data, size);
        source->filled += size;

        return 0;
}

static int fill_fixed_size(RemoteSource *source, void **data, size_t size) {
        int n;
        char *newbuf = NULL;
        size_t newsize = 0, remain;

        assert(source);
        assert(source->state == STATE_DATA_START ||
               source->state == STATE_DATA ||
               source->state == STATE_DATA_FINISH);
        assert(size <= DATA_SIZE_MAX);
        assert(source->filled <= source->size);
        assert(source->buf != NULL || source->size == 0);
        assert(source->buf == NULL || source->size > 0);
        assert(data);

        while(source->filled < size) {
                if (source->fd < 0)
                        /* we have to wait for some data to come to us */
                        return -EWOULDBLOCK;

                if (!GREEDY_REALLOC(source->buf, source->size, size))
                        return log_oom();

                n = read(source->fd, source->buf + source->filled,
                         source->size - source->filled);
                if (n < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                                log_error("read(%d, ..., %zd): %m", source->fd,
                                          source->size - source->filled);
                        return -errno;
                } else if (n == 0)
                        return 0;

                source->filled += n;
        }

        *data = source->buf;

        /* Check if something remains */
        assert(size <= source->filled);
        remain = source->filled - size;
        if (remain) {
                newsize = MAX(remain, LINE_CHUNK);
                newbuf = malloc(newsize);
                if (!newbuf)
                        return log_oom();
                memcpy(newbuf, source->buf + size, remain);
        }
        source->buf = newbuf;
        source->size = newsize;
        source->filled = remain;

        return 1;
}

static int get_data_size(RemoteSource *source) {
        int r;
        _cleanup_free_ void *data = NULL;

        assert(source);
        assert(source->state == STATE_DATA_START);
        assert(source->data_size == 0);

        r = fill_fixed_size(source, &data, sizeof(uint64_t));
        if (r <= 0)
                return r;

        source->data_size = le64toh( *(uint64_t *) data );
        if (source->data_size > DATA_SIZE_MAX) {
                log_error("Stream declares field with size %zu > %u == DATA_SIZE_MAX",
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
        _cleanup_free_ char *data = NULL;

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

int process_data(RemoteSource *source) {
        int r;

        switch(source->state) {
        case STATE_LINE: {
                char *line, *sep;
                size_t n;

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
                        log_debug("Received empty line, event is ready");
                        free(line);
                        return 1;
                }

                r = process_dunder(source, line, n);
                if (r != 0) {
                        free(line);
                        return r < 0 ? r : 0;
                }

                /* MESSAGE=xxx\n
                   or
                   COREDUMP\n
                   LLLLLLLL0011223344...\n
                */
                sep = memchr(line, '=', n);
                if (sep)
                        /* chomp newline */
                        n--;
                else
                        /* replace \n with = */
                        line[n-1] = '=';
                log_debug("Received: %.*s", (int) n, line);

                r = iovw_put(&source->iovw, line, n);
                if (r < 0) {
                        log_error("Failed to put line in iovect");
                        free(line);
                        return r;
                }

                if (!sep)
                        source->state = STATE_DATA_START;
                return 0; /* continue */
        }

        case STATE_DATA_START:
                assert(source->data_size == 0);

                r = get_data_size(source);
                log_debug("get_data_size() -> %d", r);
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

                assert(source->data_size > 0);

                r = get_data_data(source, &data);
                log_debug("get_data_data() -> %d", r);
                if (r < 0)
                        return r;
                if (r == 0) {
                        source->state = STATE_EOF;
                        return 0;
                }

                assert(data);

                r = iovw_put(&source->iovw, data, source->data_size);
                if (r < 0) {
                        log_error("failed to put binary buffer in iovect");
                        return r;
                }

                source->state = STATE_DATA_FINISH;

                return 0; /* continue */
        }

        case STATE_DATA_FINISH:
                r = get_data_newline(source);
                log_debug("get_data_newline() -> %d", r);
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

int process_source(RemoteSource *source, Writer *writer, bool compress, bool seal) {
        int r;

        assert(source);
        assert(writer);

        r = process_data(source);
        if (r <= 0)
                return r;

        /* We have a full event */
        log_info("Received a full event from source@%p fd:%d (%s)",
                 source, source->fd, source->name);

        if (!source->iovw.count) {
                log_warning("Entry with no payload, skipping");
                goto freeing;
        }

        assert(source->iovw.iovec);
        assert(source->iovw.count);

        r = writer_write(writer, &source->iovw, &source->ts, compress, seal);
        if (r < 0)
                log_error("Failed to write entry of %zu bytes: %s",
                          iovw_size(&source->iovw), strerror(-r));
        else
                r = 1;

 freeing:
        iovw_free_contents(&source->iovw);
        return r;
}
