/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "socket-forward.h"

#define SOCKET_FORWARD_BUFFER_SIZE (256 * 1024)

/* Unidirectional forwarder: splices data from read_fd to write_fd via a kernel pipe buffer.
 * Each direction of a full-duplex SocketForward is handled by one of these. */
typedef struct SimplexForward {
        sd_event *event;

        int read_fd, write_fd;

        int buffer[2]; /* a pipe */

        size_t buffer_full, buffer_size;

        sd_event_source *read_event_source, *write_event_source;

        int (*on_done)(struct SimplexForward *fwd, int error, void *userdata);
        void *userdata;
} SimplexForward;

static SimplexForward* simplex_forward_free(SimplexForward *fwd) {
        if (!fwd)
                return NULL;

        sd_event_source_unref(fwd->read_event_source);
        sd_event_source_unref(fwd->write_event_source);

        safe_close(fwd->read_fd);
        safe_close(fwd->write_fd);

        safe_close_pair(fwd->buffer);

        sd_event_unref(fwd->event);

        return mfree(fwd);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SimplexForward*, simplex_forward_free);

static int socket_forward_create_pipes(int buffer[static 2], size_t *ret_size) {
        int r;

        assert(buffer);
        assert(ret_size);

        if (buffer[0] >= 0)
                return 0;

        r = pipe2(buffer, O_CLOEXEC|O_NONBLOCK);
        if (r < 0)
                return log_debug_errno(errno, "Failed to allocate pipe buffer: %m");

        (void) fcntl(buffer[0], F_SETPIPE_SZ, SOCKET_FORWARD_BUFFER_SIZE);

        r = fcntl(buffer[0], F_GETPIPE_SZ);
        if (r < 0)
                return log_debug_errno(errno, "Failed to get pipe buffer size: %m");

        assert(r > 0);
        *ret_size = r;

        return 0;
}

static int simplex_forward_shovel(
                int *from, int buffer[2], int *to,
                size_t *full, size_t *sz,
                sd_event_source **from_source, sd_event_source **to_source) {

        bool shoveled;

        assert(from);
        assert(buffer);
        assert(buffer[0] >= 0);
        assert(buffer[1] >= 0);
        assert(to);
        assert(full);
        assert(sz);
        assert(from_source);
        assert(to_source);

        do {
                ssize_t z;

                shoveled = false;

                if (*full < *sz && *from >= 0 && *to >= 0) {
                        z = splice(*from, NULL, buffer[1], NULL, *sz - *full, SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
                        if (z > 0) {
                                *full += z;
                                shoveled = true;
                        } else if (z == 0 || ERRNO_IS_DISCONNECT(errno)) {
                                *from_source = sd_event_source_unref(*from_source);
                                *from = safe_close(*from);
                        } else if (!ERRNO_IS_TRANSIENT(errno))
                                return log_debug_errno(errno, "Failed to splice: %m");
                }

                if (*full > 0 && *to >= 0) {
                        z = splice(buffer[0], NULL, *to, NULL, *full, SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
                        if (z > 0) {
                                *full -= z;
                                shoveled = true;
                        } else if (z == 0 || ERRNO_IS_DISCONNECT(errno)) {
                                *to_source = sd_event_source_unref(*to_source);
                                *to = safe_close(*to);
                        } else if (!ERRNO_IS_TRANSIENT(errno))
                                return log_debug_errno(errno, "Failed to splice: %m");
                }
        } while (shoveled);

        return 0;
}

static int simplex_forward_enable_event_sources(SimplexForward *fwd);

static int simplex_forward_traffic(SimplexForward *fwd) {
        int r;

        r = simplex_forward_shovel(
                        &fwd->read_fd, fwd->buffer, &fwd->write_fd,
                        &fwd->buffer_full, &fwd->buffer_size,
                        &fwd->read_event_source, &fwd->write_event_source);
        if (r < 0)
                goto quit;

        /* Read side closed and all buffered data written? */
        if (fwd->read_fd < 0 && fwd->buffer_full <= 0)
                goto quit;

        /* Write side closed? */
        if (fwd->write_fd < 0)
                goto quit;

        r = simplex_forward_enable_event_sources(fwd);
        if (r < 0)
                goto quit;

        return 1;

quit:
        fwd->read_event_source = sd_event_source_disable_unref(fwd->read_event_source);
        fwd->write_event_source = sd_event_source_disable_unref(fwd->write_event_source);
        return fwd->on_done(fwd, r, fwd->userdata);
}

static int simplex_forward_io_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        SimplexForward *fwd = ASSERT_PTR(userdata);

        return simplex_forward_traffic(fwd);
}

static int simplex_forward_defer_cb(sd_event_source *s, void *userdata) {
        SimplexForward *fwd = ASSERT_PTR(userdata);

        return simplex_forward_traffic(fwd);
}

static int simplex_forward_enable_event_sources(SimplexForward *fwd) {
        bool can_read, can_write;
        int r;

        assert(fwd);

        can_read = fwd->buffer_full < fwd->buffer_size;
        can_write = fwd->buffer_full > 0;

        /* Event sources may have been unref'd by the shovel on EOF/disconnect */
        if (fwd->read_event_source) {
                r = sd_event_source_set_enabled(fwd->read_event_source, can_read ? SD_EVENT_ONESHOT : SD_EVENT_OFF);
                if (r < 0)
                        return log_debug_errno(r, "Failed to update read event source: %m");
        }

        if (fwd->write_event_source) {
                r = sd_event_source_set_enabled(fwd->write_event_source, can_write ? SD_EVENT_ONESHOT : SD_EVENT_OFF);
                if (r < 0)
                        return log_debug_errno(r, "Failed to update write event source: %m");
        }

        return 0;
}

static int simplex_forward_create_event_source(
                SimplexForward *fwd,
                sd_event_source **ret,
                int fd,
                uint32_t events) {

        int r;

        r = sd_event_add_io(fwd->event, ret, fd, events, simplex_forward_io_cb, fwd);
        if (r == -EPERM)
                /* fd is not pollable (e.g. regular file). Fall back to a defer event source
                 * which fires on each event loop iteration. This works because regular
                 * file are always ready for I/O so we don't need to poll. */
                r = sd_event_add_defer(fwd->event, ret, simplex_forward_defer_cb, fwd);

        return r;
}

static int simplex_forward_new(
                sd_event *event,
                int read_fd,
                int write_fd,
                int (*on_done)(SimplexForward *fwd, int error, void *userdata),
                void *userdata,
                SimplexForward **ret) {

        _cleanup_(simplex_forward_freep) SimplexForward *fwd = NULL;
        int r;

        assert(event);
        assert(read_fd >= 0);
        assert(write_fd >= 0);
        assert(read_fd != write_fd);
        assert(on_done);
        assert(ret);

        fwd = new(SimplexForward, 1);
        if (!fwd) {
                safe_close(read_fd);
                safe_close(write_fd);
                return log_oom_debug();
        }

        *fwd = (SimplexForward) {
                .event = sd_event_ref(event),
                .read_fd = read_fd,
                .write_fd = write_fd,
                .buffer = EBADF_PAIR,
                .on_done = on_done,
                .userdata = userdata,
        };

        r = socket_forward_create_pipes(fwd->buffer, &fwd->buffer_size);
        if (r < 0)
                return r;

        r = simplex_forward_create_event_source(fwd, &fwd->read_event_source, fwd->read_fd, EPOLLIN);
        if (r < 0)
                return r;

        r = simplex_forward_create_event_source(fwd, &fwd->write_event_source, fwd->write_fd, EPOLLOUT);
        if (r < 0)
                return r;

        r = simplex_forward_enable_event_sources(fwd);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(fwd);
        return 0;
}

/* Full-duplex forwarder from two SimplexForward instances */
struct SocketForward {
        SimplexForward *server_to_client;
        SimplexForward *client_to_server;

        socket_forward_done_t on_done;
        void *userdata;

        int first_error;
        unsigned directions_done;
};

SocketForward* socket_forward_free(SocketForward *sf) {
        if (!sf)
                return NULL;

        simplex_forward_free(sf->server_to_client);
        simplex_forward_free(sf->client_to_server);

        return mfree(sf);
}

static int socket_forward_direction_done(SimplexForward *fwd, int error, void *userdata) {
        SocketForward *sf = ASSERT_PTR(userdata);

        /* Half-close the write side so the remote end sees EOF. For sockets,
         * shutdown(SHUT_WR) sends FIN while keeping the fd open for the read side
         * (which belongs to the other direction's dup'd fd). For pipes/FIFOs,
         * shutdown() fails with ENOTSOCK - close the fd instead, which is the
         * only way to signal EOF on a pipe. */
        if (fwd->write_fd >= 0 && shutdown(fwd->write_fd, SHUT_WR) < 0) {
                if (errno == ENOTSOCK)
                        fwd->write_fd = safe_close(fwd->write_fd);
                else
                        log_debug_errno(errno, "Failed to shutdown write side of fd %d: %m, ignoring",
                                        fwd->write_fd);
        }

        if (error < 0 && sf->first_error >= 0)
                sf->first_error = error;

        sf->directions_done++;

        if (sf->directions_done >= 2)
                return sf->on_done(sf, sf->first_error, sf->userdata);

        return 0;
}

int socket_forward_new_pair(
                sd_event *event,
                int server_read_fd,
                int server_write_fd,
                int client_read_fd,
                int client_write_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret) {

        _cleanup_close_ int server_read_fd_close = server_read_fd,
                            server_write_fd_close = server_write_fd,
                            client_read_fd_close = client_read_fd,
                            client_write_fd_close = client_write_fd;
        _cleanup_(socket_forward_freep) SocketForward *sf = NULL;
        int r;

        assert(event);
        assert(server_read_fd >= 0);
        assert(server_write_fd >= 0);
        assert(client_read_fd >= 0);
        assert(client_write_fd >= 0);
        assert(server_read_fd != server_write_fd);
        assert(client_read_fd != client_write_fd);
        assert(server_read_fd != client_read_fd);
        assert(server_read_fd != client_write_fd);
        assert(server_write_fd != client_read_fd);
        assert(server_write_fd != client_write_fd);
        assert(on_done);
        assert(ret);

        sf = new(SocketForward, 1);
        if (!sf)
                return log_oom_debug();

        *sf = (SocketForward) {
                .on_done = on_done,
                .userdata = userdata,
        };

        r = simplex_forward_new(event,
                                TAKE_FD(server_read_fd_close), TAKE_FD(client_write_fd_close),
                                socket_forward_direction_done, sf,
                                &sf->server_to_client);
        if (r < 0)
                return r;

        r = simplex_forward_new(event,
                                TAKE_FD(client_read_fd_close), TAKE_FD(server_write_fd_close),
                                socket_forward_direction_done, sf,
                                &sf->client_to_server);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(sf);
        return 0;
}

int socket_forward_new(
                sd_event *event,
                int server_fd,
                int client_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret) {

        _cleanup_close_ int server_fd_close = server_fd, client_fd_close = client_fd,
                            server_write_fd = -EBADF, client_write_fd = -EBADF;

        assert(event);
        assert(server_fd >= 0);
        assert(client_fd >= 0);
        assert(on_done);
        assert(ret);

        server_write_fd = fcntl(server_fd, F_DUPFD_CLOEXEC, 3);
        if (server_write_fd < 0)
                return -errno;

        client_write_fd = fcntl(client_fd, F_DUPFD_CLOEXEC, 3);
        if (client_write_fd < 0)
                return -errno;

        return socket_forward_new_pair(
                        event,
                        TAKE_FD(server_fd_close), TAKE_FD(server_write_fd),
                        TAKE_FD(client_fd_close), TAKE_FD(client_write_fd),
                        on_done, userdata, ret);
}
