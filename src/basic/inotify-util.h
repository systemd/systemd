/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/inotify.h>

#define INOTIFY_EVENT_MAX (offsetof(struct inotify_event, name) + NAME_MAX + 1)

#define FOREACH_INOTIFY_EVENT(e, buffer, sz) \
        for ((e) = &buffer.ev;                                \
             (uint8_t*) (e) < (uint8_t*) (buffer.raw) + (sz); \
             (e) = (struct inotify_event*) ((uint8_t*) (e) + sizeof(struct inotify_event) + (e)->len))

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

int inotify_add_watch_fd(int fd, int what, uint32_t mask);
int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask);
