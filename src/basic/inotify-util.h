/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/inotify.h>

#include "log.h"

#define INOTIFY_EVENT_MAX (offsetof(struct inotify_event, name) + NAME_MAX + 1)

#define _FOREACH_INOTIFY_EVENT(e, buffer, sz, log_level, start, end)    \
        for (struct inotify_event                                       \
                     *start = &((buffer).ev),                           \
                     *end = (struct inotify_event*) ((uint8_t*) start + (sz)), \
                     *e = start;                                        \
             (size_t) ((uint8_t*) end - (uint8_t*) e) >= sizeof(struct inotify_event) && \
             ((size_t) ((uint8_t*) end - (uint8_t*) e) >= sizeof(struct inotify_event) + e->len || \
              (log_full(log_level, "Received invalid inotify event, ignoring."), false)); \
             e = (struct inotify_event*) ((uint8_t*) e + sizeof(struct inotify_event) + e->len))

#define _FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, log_level)           \
        _FOREACH_INOTIFY_EVENT(e, buffer, sz, log_level, UNIQ_T(start, UNIQ), UNIQ_T(end, UNIQ))

#define FOREACH_INOTIFY_EVENT(e, buffer, sz)                    \
        _FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, LOG_DEBUG)

#define FOREACH_INOTIFY_EVENT_WARN(e, buffer, sz)               \
        _FOREACH_INOTIFY_EVENT_FULL(e, buffer, sz, LOG_WARNING)

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

int inotify_add_watch_fd(int fd, int what, uint32_t mask);
int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask);
