/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/inotify.h>

#include "log.h"

#define INOTIFY_EVENT_MAX (offsetof(struct inotify_event, name) + NAME_MAX + 1)

/* This evaluates arguments multiple times */
#define FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, log_level)            \
        for (struct inotify_event *e = NULL;                            \
             inotify_event_next(&buffer, sz, &e, log_level); )

#define FOREACH_INOTIFY_EVENT(e, buffer, sz)                    \
        FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, LOG_DEBUG)

#define FOREACH_INOTIFY_EVENT_WARN(e, buffer, sz)               \
        FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, LOG_WARNING)

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

static inline bool inotify_event_next(
                union inotify_event_buffer *buffer,
                size_t size,
                struct inotify_event **iterator,
                int log_level) {

        struct inotify_event *e;
        size_t offset = 0;

        assert(buffer);
        assert(iterator);

        if (*iterator) {
                assert((uint8_t*) *iterator >= buffer->raw);
                offset = (uint8_t*) *iterator - buffer->raw;
                offset += offsetof(struct inotify_event, name) + (*iterator)->len;
        }

        if (size == offset)
                return false;

        if (size < offset ||
            size - offset < offsetof(struct inotify_event, name)) {
                log_full(log_level, "Received invalid inotify event, ignoring.");
                return false;
        }

        e = (struct inotify_event*) (buffer->raw + offset);
        if (size - offset - offsetof(struct inotify_event, name) < e->len) {
                log_full(log_level, "Received invalid inotify event, ignoring.");
                return false;
        }

        *iterator = e;
        return true;
}

int inotify_add_watch_fd(int fd, int what, uint32_t mask);
int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask);
