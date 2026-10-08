/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/fanotify.h>       /* IWYU pragma: export */
#include <sys/vfs.h>            /* IWYU pragma: export */

#include "forward.h"

union fanotify_event_buffer {
        struct fanotify_event_metadata em;
        uint8_t raw[4096];
};

/* This evaluates arguments multiple times */
#define FOREACH_FANOTIFY_EVENT(e, buffer, sz)                      \
        for (const struct fanotify_event_metadata *e = &buffer.em; \
             FAN_EVENT_OK(e, sz);                                  \
             e = FAN_EVENT_NEXT(e, sz))

static inline const struct fanotify_event_info_header* fanotify_event_info_header_first(const struct fanotify_event_metadata *e) {
        assert(e);
        return (const struct fanotify_event_info_header*) ((const uint8_t*) e + e->metadata_len);
}

static inline bool fanotify_event_info_header_is_valid(
                const struct fanotify_event_info_header *h,
                const struct fanotify_event_metadata *e) {

        assert(h);
        assert(e);

        return (const uint8_t*) h + sizeof(*h) <= (const uint8_t*) e + e->event_len &&
                h->len >= sizeof(*h) &&
                (const uint8_t*) h + h->len <= (const uint8_t*) e + e->event_len;
}

static inline const struct fanotify_event_info_header* fanotify_event_info_header_next(const struct fanotify_event_info_header *h) {
        assert(h);
        return (const struct fanotify_event_info_header*) ((const uint8_t*) h + h->len);
}

/* This evaluates arguments multiple times */
#define FOREACH_FANOTIFY_EVENT_INFO(h, e)                               \
        for (const struct fanotify_event_info_header *h = fanotify_event_info_header_first(e); \
             fanotify_event_info_header_is_valid(h, e);                 \
             h = fanotify_event_info_header_next(h))

int fanotify_event_get_fd(
                const struct fanotify_event_metadata *e,
                int mount_fd,             /* O_PATH fd cannot be used */
                const struct statfs *sfs, /* can be NULL */
                int *ret_fd_close);

int fanotify_mark_fd(int fanotify_fd, unsigned flags, uint64_t mask, int fd);
