/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/fanotify.h>       /* IWYU pragma: export */
#include <sys/vfs.h>            /* IWYU pragma: export */

#include "forward.h"

union fanotify_event_buffer {
        struct fanotify_event_metadata em;
        uint8_t raw[4096];
};

typedef struct FanotifyEventIterator {
        const uint8_t *ptr;                  /* cursor into the raw read buffer */
        size_t left;                         /* remaining bytes */
        union fanotify_event_buffer aligned; /* 8-byte aligned scratch for one event */
} FanotifyEventIterator;

bool fanotify_event_iterator_next(FanotifyEventIterator *i, const struct fanotify_event_metadata **ret);

/* Iterates over the events in a buffer filled by read() on an fanotify fd. Each event is copied into an
 * 8-byte aligned scratch buffer first, so 'e' is always suitably aligned. 'buffer' must be a
 * union fanotify_event_buffer, 'sz' the number of bytes read (must be >= 0). FAN_EVENT_OK()/
 * FAN_EVENT_NEXT() can't be used, as they dereference the metadata in place while possibly unaligned. */
#define _FOREACH_FANOTIFY_EVENT(e, buffer, sz, i)               \
        for (FanotifyEventIterator i =                          \
                     { .ptr = (buffer).raw, .left = (sz), };    \
             i.ptr;                                             \
             i.ptr = NULL)                                      \
                for (const struct fanotify_event_metadata *e;   \
                     fanotify_event_iterator_next(&i, &e); )
#define FOREACH_FANOTIFY_EVENT(e, buffer, sz)                   \
        _FOREACH_FANOTIFY_EVENT(e, buffer, sz, UNIQ_T(i, UNIQ))

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

int fanotify_event_open_by_fid(
                const struct fanotify_event_metadata *e,
                int mount_fd,              /* O_PATH fd cannot be used */
                const struct statfs *sfs); /* can be NULL */

int fanotify_mark_fd(int fanotify_fd, unsigned flags, uint64_t mask, int fd);
