/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/eventfd.h>

#include "log.h"
#include "fd-util.h"
#include "alloc-util.h"
#include "sd-event.h"
#include "memfd-util.h"

#include "ringbuf.h"

typedef struct Ringbuf {
        unsigned n_ref;
        RingbufSide side;
        bool shutdown;

        sd_event *event;
        int64_t event_priority;
        int memfd;
        int read_eventfd;
        sd_event_source *event_source_read_io;
        int write_eventfd;
        sd_event_source *event_source_write_io;

        void *userdata;
        ringbuf_data_t data_cb;
        ringbuf_grow_t grow_cb;
        ringbuf_shutdown_t shutdown_cb;

        void *address;
        uint64_t size;
        uint64_t reader;
        uint64_t reader_advanced;
        uint64_t writer;
        uint64_t writer_advanced;
} Ringbuf;

static void ringbuf_shutdown(Ringbuf *rb);

int ringbuf_new(Ringbuf **ret, RingbufSide side) {
        _cleanup_(ringbuf_unrefp) Ringbuf *rb = NULL;

        rb = new(Ringbuf, 1);
        if (!rb)
                return log_oom_debug();

        *rb = (Ringbuf) {
                .n_ref = 1,
                .side = side,
                .memfd = -EBADFD,
                .read_eventfd = -EBADFD,
                .write_eventfd = -EBADFD,
        };

        *ret = TAKE_PTR(rb);
        return 0;
}

static Ringbuf* ringbuf_destroy(Ringbuf *rb) {
        if (!rb)
                return NULL;

        ringbuf_shutdown(rb);

        safe_close(rb->memfd);
        safe_close(rb->read_eventfd);
        sd_event_source_unref(rb->event_source_read_io);
        safe_close(rb->write_eventfd);
        sd_event_source_unref(rb->event_source_write_io);

        if (rb->address) {
                if (munmap(rb->address, rb->size * 2) < 0)
                        log_debug_errno(errno, "Failed to unmap ring buffer: %m");
                rb->address = NULL;
        }

        return mfree(rb);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Ringbuf, ringbuf, ringbuf_destroy);

static uint8_t* reader_address(Ringbuf *rb) {
        return ((uint8_t *) rb->address) + (rb->reader % rb->size);
}

static uint8_t* writer_address(Ringbuf *rb) {
        return ((uint8_t *) rb->address) + (rb->writer % rb->size);
}

static uint64_t get_used_size(Ringbuf *rb) {
        return rb->writer - rb->reader;
}

static uint64_t get_free_size(Ringbuf *rb) {
        return rb->size - get_used_size(rb);
}

static int on_read_eventfd_io(sd_event_source *s, int fd, uint32_t events, void *userdata) {
        Ringbuf *rb = ASSERT_PTR(userdata);
        uint64_t u;
        int r;

        assert_return(rb->side == RINGBUF_SIDE_WRITER, -EINVAL);
        assert_return((events & (EPOLLIN|EPOLLHUP|EPOLLERR)) != 0, -EINVAL);

        if (events & (EPOLLHUP|EPOLLERR)) {
                ringbuf_shutdown(rb);
                return -EPIPE;
        }

        r = eventfd_read(rb->read_eventfd, &u);
        if (r < 0) {
                log_debug_errno(errno, "Failed to read from ring buffer eventfd: %m");
                return 0;
        }

        if (rb->reader + u > rb->writer) {
                /* reader advanced past writer */
                ringbuf_shutdown(rb);
                return -EPIPE;
        }

        rb->reader += u;

        if (rb->grow_cb)
                rb->grow_cb(rb, rb->userdata);

        return 0;
}

static int dispatch_reading(Ringbuf *rb) {
        uint64_t u;
        int r;

        u = get_used_size(rb);

        if (!rb->address || !rb->data_cb || u == 0)
                return 0;

        r = rb->data_cb(rb, reader_address(rb), u, rb->userdata);
        if (r < 0)
                return 0;

        rb->reader += u;
        rb->reader_advanced += u;

        r = eventfd_write(rb->read_eventfd, rb->reader_advanced);
        if (r < 0) {
                log_debug_errno(errno, "Failed to write to ring buffer eventfd: %m");
                return 0;
        }

        rb->reader_advanced = 0;

        return 0;
}

static int on_write_eventfd_io(sd_event_source *s, int fd, uint32_t events, void *userdata) {
        Ringbuf *rb = ASSERT_PTR(userdata);
        uint64_t u;
        int r;

        assert_return(rb->side == RINGBUF_SIDE_READER, -EINVAL);
        assert_return((events & (EPOLLIN|EPOLLHUP|EPOLLERR)) != 0, -EINVAL);

        if (events & (EPOLLHUP|EPOLLERR)) {
                ringbuf_shutdown(rb);
                return -EPIPE;
        }

        r = eventfd_read(rb->write_eventfd, &u);
        if (r < 0) {
                log_debug_errno(errno, "Failed to read from ring buffer eventfd: %m");
                return 0;
        }

        if (rb->writer + u > rb->reader + rb->size) {
                ringbuf_shutdown(rb);
                return -EPIPE;
        }

        rb->writer += u;

        dispatch_reading(rb);

        return 0;
}

static void ringbuf_detach_sources(Ringbuf *rb) {
        rb->event_source_read_io = sd_event_source_unref(rb->event_source_read_io);
        rb->event_source_write_io = sd_event_source_unref(rb->event_source_write_io);
}

static int ringbuf_attach_sources(Ringbuf *rb) {
        int r;

        if (!rb->event)
                return 0;

        if (rb->side == RINGBUF_SIDE_WRITER && rb->read_eventfd != -EBADFD && !rb->event_source_read_io) {
                r = sd_event_add_io(rb->event, &rb->event_source_read_io, rb->read_eventfd,
                                    EPOLLIN|EPOLLHUP|EPOLLERR, on_read_eventfd_io, rb);
                if (r < 0)
                        return r;
                sd_event_source_set_priority(rb->event_source_read_io, rb->event_priority);
        }

        if (rb->side == RINGBUF_SIDE_READER && rb->write_eventfd != -EBADFD && !rb->event_source_write_io) {
                r = sd_event_add_io(rb->event, &rb->event_source_write_io, rb->write_eventfd,
                                    EPOLLIN|EPOLLHUP|EPOLLERR, on_write_eventfd_io, rb);
                if (r < 0)
                        return r;
                sd_event_source_set_priority(rb->event_source_write_io, rb->event_priority);
        }

        return 0;
}

static void ringbuf_shutdown(Ringbuf *rb) {
        if (rb->shutdown)
                return;

        ringbuf_detach_sources(rb);

        rb->write_eventfd = safe_close(rb->write_eventfd);
        rb->read_eventfd = safe_close(rb->read_eventfd);

        if (rb->shutdown_cb)
                rb->shutdown_cb(rb, rb->userdata);

        rb->shutdown = true;
}

void* ringbuf_set_userdata(Ringbuf *rb, void *userdata) {
        void *ret;

        assert_return(rb, NULL);

        ret = rb->userdata;
        rb->userdata = userdata;

        return ret;
}

void* ringbuf_get_userdata(Ringbuf *rb) {
        assert_return(rb, NULL);

        return rb->userdata;
}

int ringbuf_bind_data(Ringbuf *rb, ringbuf_data_t data) {
        int r;

        assert_return(rb, -EINVAL);
        assert_return(rb->side == RINGBUF_SIDE_READER, -EINVAL);
        assert_return((data && !rb->data_cb) || !data, -EBUSY);

        rb->data_cb = data;

        r = ringbuf_attach_sources(rb);
        if (r < 0)
                return r;

        dispatch_reading(rb);

        return 0;
}

int ringbuf_bind_grow(Ringbuf *rb, ringbuf_grow_t grow) {
        int r;

        assert_return(rb, -EINVAL);
        assert_return(rb->side == RINGBUF_SIDE_WRITER, -EINVAL);
        assert_return((grow && !rb->grow_cb) || !grow, -EBUSY);

        rb->grow_cb = grow;

        r = ringbuf_attach_sources(rb);
        if (r < 0)
                return r;

        return 0;
}

int ringbuf_bind_shutdown(Ringbuf *rb, ringbuf_shutdown_t shutdown) {
        assert_return(rb, -EINVAL);
        assert_return((shutdown && !rb->shutdown_cb) || !shutdown, -EBUSY);

        rb->shutdown_cb = shutdown;

        return 0;
}

int ringbuf_attach_event(Ringbuf *rb, sd_event *e, int64_t priority) {
        int r;

        assert_return(rb, -EINVAL);
        assert_return(!rb->event, -EBUSY);

        if (e)
                rb->event = sd_event_ref(e);
        else {
                r = sd_event_default(&rb->event);
                if (r < 0)
                        goto fail;
        }

        rb->event_priority = priority;

        r = ringbuf_attach_sources(rb);
        if (r < 0)
                goto fail;

        return 0;

fail:
        rb->event = sd_event_unref(rb->event);
        return r;
}

int ringbuf_detach_event(Ringbuf *rb) {
        assert_return(rb, -EINVAL);

        ringbuf_detach_sources(rb);

        rb->event = sd_event_unref(rb->event);
        return 0;
}

sd_event* ringbuf_get_event(Ringbuf *rb) {
        assert_return(rb, NULL);

        return rb->event;
}

int ringbuf_create_memfd(Ringbuf *rb, uint64_t size) {
        _cleanup_close_ int memfd = -EBADF;
        int r;

        assert_return(rb, -EINVAL);
        assert_return(rb->memfd == -EBADFD, -EINVAL);

        memfd = memfd_new_full("Ringbuf", MFD_ALLOW_SEALING);
        if (memfd < 0)
                return memfd;

        r = memfd_set_size(memfd, size);
        if (r < 0)
                return r;

        return ringbuf_set_memfd(rb, TAKE_FD(memfd));
}

int ringbuf_set_memfd(Ringbuf *rb, int memfd) {
        _cleanup_close_ int fd = memfd;
        uint64_t size;
        int r;

        assert_return(rb, -EINVAL);
        assert_return(memfd != -EBADFD, -EINVAL);

        r = memfd_set_fixed_size(fd);
        if (r < 0)
                return r;

        r = memfd_get_size(fd, &size);
        if (r < 0)
                return r;

        size = ALIGN_TO_U64(size, page_size());
        if (size == 0)
                return -ENODATA;

        void *address, *lower, *upper;
        address = mmap(NULL, size * 2, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if (address == MAP_FAILED)
                return -errno;

        lower = mmap(address, size, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, fd, 0);
        if (lower != address) {
                munmap(address, size * 2);
                return -errno;
        }

        upper = mmap((uint8_t *)address + size, size, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, fd, 0);
        if (upper != (uint8_t *)address + size) {
                munmap(address, size * 2);
                return -errno;
        }

        rb->memfd = TAKE_FD(fd);
        rb->size = size;
        rb->address = address;

        return 0;
}

int ringbuf_get_memfd(Ringbuf *rb) {
        assert_return(rb, -EINVAL);

        return rb->memfd;
}

int ringbuf_create_eventfds(Ringbuf *rb) {
        _cleanup_close_ int read_eventfd = -EBADF;
        _cleanup_close_ int write_eventfd = -EBADF;

        assert_return(rb, -EINVAL);
        assert_return(!rb->shutdown, -ECONNABORTED);
        assert_return(rb->read_eventfd == -EBADFD, -EINVAL);
        assert_return(rb->write_eventfd == -EBADFD, -EINVAL);

        read_eventfd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
        if (read_eventfd < 0)
                return -errno;

        write_eventfd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
        if (write_eventfd < 0)
                return -errno;

        rb->read_eventfd = TAKE_FD(read_eventfd);
        rb->write_eventfd = TAKE_FD(write_eventfd);

        return ringbuf_attach_sources(rb);
}

int ringbuf_set_eventfds(Ringbuf *rb, int reader_eventfd, int writer_eventfd) {
        assert_return(rb, -EINVAL);
        assert_return(!rb->shutdown, -ECONNABORTED);
        assert_return(rb->read_eventfd == -EBADFD, -EINVAL);
        assert_return(rb->write_eventfd == -EBADFD, -EINVAL);

        rb->read_eventfd = TAKE_FD(reader_eventfd);
        rb->write_eventfd = TAKE_FD(writer_eventfd);

        return ringbuf_attach_sources(rb);
}

int ringbuf_get_eventfds(Ringbuf *rb, int *reader_eventfd, int *writer_eventfd) {
        assert_return(rb, -EINVAL);

        if (reader_eventfd)
                *reader_eventfd = rb->read_eventfd;
        if (writer_eventfd)
                *writer_eventfd = rb->write_eventfd;

        return 0;
}

int ringbuf_write(Ringbuf *rb, uint8_t *data, size_t size) {
        assert_return(rb, -EINVAL);
        assert_return(rb->side == RINGBUF_SIDE_WRITER, -EINVAL);
        assert_return(rb->address != NULL, -EINVAL);
        assert_return(rb->size > 0, -EINVAL);
        /* passing in anything larger than rb->size is a programmer error */
        assert_return(size <= rb->size, -EINVAL);

        /* ensure we have enough free space to write size */
        if (get_free_size(rb) < size)
                return -EBUSY;

        /* write the data */
        memcpy(writer_address(rb), data, size);

        /* update writer */
        rb->writer += size;
        rb->writer_advanced += size;

        return 0;
}

int ringbuf_flush(Ringbuf *rb) {
        int r;

        assert_return(rb, -EINVAL);
        assert_return(!rb->shutdown, -ECONNABORTED);
        assert_return(rb->side == RINGBUF_SIDE_WRITER, -EINVAL);
        assert_return(rb->write_eventfd != -EBADFD, -EINVAL);

        r = eventfd_write(rb->write_eventfd, rb->writer_advanced);
        if (r < 0)
                return r;

        rb->writer_advanced = 0;
        return 0;
}
