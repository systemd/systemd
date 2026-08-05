/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"
#include "cleanup-util.h"

typedef struct Ringbuf Ringbuf;

typedef enum RingbufSide {
        RINGBUF_SIDE_READER,
        RINGBUF_SIDE_WRITER,
} RingbufSide;

typedef int (*ringbuf_data_t)(Ringbuf *rb, uint8_t *data, size_t size, void *userdata);
typedef void (*ringbuf_grow_t)(Ringbuf *rb, void *userdata);
typedef void (*ringbuf_shutdown_t)(Ringbuf *rb, void *userdata);

int ringbuf_new(Ringbuf **ret, RingbufSide side);

void* ringbuf_set_userdata(Ringbuf *rb, void *userdata);
void* ringbuf_get_userdata(Ringbuf *rb);

int ringbuf_bind_data(Ringbuf *rb, ringbuf_data_t data);
int ringbuf_bind_grow(Ringbuf *rb, ringbuf_grow_t grow);
int ringbuf_bind_shutdown(Ringbuf *rb, ringbuf_shutdown_t shutdown);

int ringbuf_attach_event(Ringbuf *rb, sd_event *e, int64_t priority);
int ringbuf_detach_event(Ringbuf *rb);
sd_event* ringbuf_get_event(Ringbuf *rb);

int ringbuf_create_memfd(Ringbuf *rb, uint64_t size);
int ringbuf_set_memfd(Ringbuf *rb, int memfd);
int ringbuf_get_memfd(Ringbuf *rb);

int ringbuf_create_eventfds(Ringbuf *rb);
int ringbuf_set_eventfds(Ringbuf *rb, int reader_eventfd, int writer_eventfd);
int ringbuf_get_eventfds(Ringbuf *rb, int *reader_eventfd, int *writer_eventfd);

int ringbuf_write(Ringbuf *rb, uint8_t *data, size_t size);
int ringbuf_flush(Ringbuf *rb);

DECLARE_TRIVIAL_REF_UNREF_FUNC(Ringbuf, ringbuf);
DEFINE_TRIVIAL_CLEANUP_FUNC(Ringbuf*, ringbuf_unref);
