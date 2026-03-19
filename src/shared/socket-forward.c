/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "socket-forward.h"

#define SOCKET_FORWARD_BUFFER_SIZE (256 * 1024)

struct SocketForward {
        sd_event *event;

        int server_fd, client_fd;

        int server_to_client_buffer[2]; /* a pipe */
        int client_to_server_buffer[2]; /* a pipe */

        size_t server_to_client_buffer_full, client_to_server_buffer_full;
        size_t server_to_client_buffer_size, client_to_server_buffer_size;

        sd_event_source *server_event_source, *client_event_source;

        socket_forward_done_t on_done;
        void *userdata;
};

SocketForward* socket_forward_free(SocketForward *sf) {
        if (!sf)
                return NULL;

        sd_event_source_unref(sf->server_event_source);
        sd_event_source_unref(sf->client_event_source);

        safe_close(sf->server_fd);
        safe_close(sf->client_fd);

        safe_close_pair(sf->server_to_client_buffer);
        safe_close_pair(sf->client_to_server_buffer);

        sd_event_unref(sf->event);

        return mfree(sf);
}

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

static int socket_forward_shovel(
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

static int socket_forward_enable_event_sources(SocketForward *sf);

static int socket_forward_traffic_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        SocketForward *sf = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        r = socket_forward_shovel(
                        &sf->server_fd, sf->server_to_client_buffer, &sf->client_fd,
                        &sf->server_to_client_buffer_full, &sf->server_to_client_buffer_size,
                        &sf->server_event_source, &sf->client_event_source);
        if (r < 0)
                goto quit;

        r = socket_forward_shovel(
                        &sf->client_fd, sf->client_to_server_buffer, &sf->server_fd,
                        &sf->client_to_server_buffer_full, &sf->client_to_server_buffer_size,
                        &sf->client_event_source, &sf->server_event_source);
        if (r < 0)
                goto quit;

        /* EOF on both sides? */
        if (sf->server_fd < 0 && sf->client_fd < 0)
                goto quit;

        /* Server closed, and all data written to client? */
        if (sf->server_fd < 0 && sf->server_to_client_buffer_full <= 0)
                goto quit;

        /* Client closed, and all data written to server? */
        if (sf->client_fd < 0 && sf->client_to_server_buffer_full <= 0)
                goto quit;

        r = socket_forward_enable_event_sources(sf);
        if (r < 0)
                goto quit;

        return 1;

quit:
        if (sf->on_done)
                return sf->on_done(sf, r, sf->userdata);

        return 0;
}

static int socket_forward_enable_event_sources(SocketForward *sf) {
        uint32_t a = 0, b = 0;
        int r;

        assert(sf);

        if (sf->server_to_client_buffer_full > 0)
                b |= EPOLLOUT;
        if (sf->server_to_client_buffer_full < sf->server_to_client_buffer_size)
                a |= EPOLLIN;

        if (sf->client_to_server_buffer_full > 0)
                a |= EPOLLOUT;
        if (sf->client_to_server_buffer_full < sf->client_to_server_buffer_size)
                b |= EPOLLIN;

        if (sf->server_event_source)
                r = sd_event_source_set_io_events(sf->server_event_source, a);
        else if (sf->server_fd >= 0)
                r = sd_event_add_io(sf->event, &sf->server_event_source, sf->server_fd, a, socket_forward_traffic_cb, sf);
        else
                r = 0;
        if (r < 0)
                return r;

        if (sf->client_event_source)
                r = sd_event_source_set_io_events(sf->client_event_source, b);
        else if (sf->client_fd >= 0)
                r = sd_event_add_io(sf->event, &sf->client_event_source, sf->client_fd, b, socket_forward_traffic_cb, sf);
        else
                r = 0;
        if (r < 0)
                return r;

        return 0;
}

int socket_forward_new(
                sd_event *event,
                int server_fd,
                int client_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret) {

        _cleanup_(socket_forward_freep) SocketForward *sf = NULL;
        int r;

        assert(event);
        assert(server_fd >= 0);
        assert(client_fd >= 0);
        assert(ret);

        sf = new(SocketForward, 1);
        if (!sf) {
                safe_close(server_fd);
                safe_close(client_fd);
                return -ENOMEM;
        }

        *sf = (SocketForward) {
                .event = sd_event_ref(event),
                .server_fd = server_fd,
                .client_fd = client_fd,
                .server_to_client_buffer = EBADF_PAIR,
                .client_to_server_buffer = EBADF_PAIR,
                .on_done = on_done,
                .userdata = userdata,
        };

        r = socket_forward_create_pipes(sf->server_to_client_buffer, &sf->server_to_client_buffer_size);
        if (r < 0)
                return r;

        r = socket_forward_create_pipes(sf->client_to_server_buffer, &sf->client_to_server_buffer_size);
        if (r < 0)
                return r;

        r = socket_forward_enable_event_sources(sf);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(sf);
        return 0;
}
