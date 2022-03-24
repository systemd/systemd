/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/inotify.h>

#define INOTIFY_EVENT_MAX (offsetof(struct inotify_event, name) + NAME_MAX + 1)

#define _FOREACH_INOTIFY_EVENT(e, buffer, sz, start, end)               \
        for (struct inotify_event                                       \
                     *start = &((buffer).ev),                           \
                     *end = (struct inotify_event*) ((uint8_t*) start + (sz)), \
                     *e = start;                                        \
             (uint8_t*) e + sizeof(struct inotify_event) <= (uint8_t*) end && \
             (uint8_t*) e + sizeof(struct inotify_event) + e->len <= (uint8_t*) end; \
             e = (struct inotify_event*) ((uint8_t*) e + sizeof(struct inotify_event) + e->len))
#define FOREACH_INOTIFY_EVENT(e, buffer, sz)                            \
        _FOREACH_INOTIFY_EVENT(e, buffer, sz, UNIQ_T(start, UNIQ), UNIQ_T(end, UNIQ))

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

int inotify_add_watch_fd(int fd, int what, uint32_t mask);
int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask);
