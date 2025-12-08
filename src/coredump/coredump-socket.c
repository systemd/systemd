/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/coredump.h>

#include "sd-event.h"

#include "coredump-context.h"   /* IWYU pragma: keep */
#include "coredump-socket.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "socket-util.h"

#define COREDUMP_REQ_SIZE_MAX 4096u

typedef enum SocketState {
        SOCKET_WAITING_REQUEST,
        SOCKET_SENDING_ACK,
        SOCKET_WAITING_MARKER,
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -EINVAL,
} SocketState;

typedef struct SocketContext {
        SocketState state;
        struct coredump_req req;
} SocketContext;

static int socket_process_request(SocketContext *socket, int fd, uint32_t revents) {
        assert(socket);
        assert(socket->state == SOCKET_WAITING_REQUEST);
        assert(fd >= 0);

        ssize_t n = next_datagram_size_fd(fd);
        if (n < 0) {
                if (ERRNO_IS_NEG_TRANSIENT(n))
                        return 0;
                return log_debug_errno(n, "Failed to determine coredump request size: %m");
        }

        /* Verify the acquired request size. */
        if (n < COREDUMP_REQ_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Acquired coredump request size is too small (%zi < %i).",
                                       n, COREDUMP_REQ_SIZE_VER0);
        if ((size_t) n > COREDUMP_REQ_SIZE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Acquired coredump request size is too large (%zi > %u).",
                                       n, COREDUMP_REQ_SIZE_MAX);

        union coredump_req_union {
                struct coredump_req req;
                uint8_t buf[COREDUMP_REQ_SIZE_MAX];
        } req = {};

        n = recv(fd, &req, n, /* flags= */ 0);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to receive coredump request: %m");
        }

        /* Verify the received coredump request. */
        if (n < COREDUMP_REQ_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request size is too small (%zi < %i).",
                                       n, COREDUMP_REQ_SIZE_VER0);
        if ((size_t) n != req.req.size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request size does not match with the size specified in the request (%zi != %"PRIu32").",
                                       n, req.req.size);
        if (req.req.size_ack < COREDUMP_ACK_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request with too small ack size (%"PRIu32" < %i).",
                                       req.req.size_ack, COREDUMP_ACK_SIZE_VER0);
        if (!FLAGS_SET(req.req.mask, COREDUMP_KERNEL | COREDUMP_USERSPACE | COREDUMP_REJECT | COREDUMP_WAIT))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request with insufficient flags (%"PRIx64").",
                                       (uint64_t) req.req.mask);

        socket->req = req.req;

        log_debug("Received coredump request, sending coredump ack.");
        socket->state = SOCKET_SENDING_ACK;
        return 0;
}

static int socket_send_ack(SocketContext *socket, int fd, uint32_t revents) {
        assert(socket);
        assert(socket->state == SOCKET_SENDING_ACK);
        assert(fd >= 0);

        struct coredump_ack ack = {
                .size = MIN(sizeof(struct coredump_ack), socket->req.size_ack),
                .mask = COREDUMP_KERNEL | COREDUMP_WAIT,
        };

        ssize_t n = send(fd, &ack, ack.size, MSG_NOSIGNAL);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to send coredump ack: %m");
        }
        if ((size_t) n != ack.size)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE),
                                       "Sent size does not match with the size of coredump ack (%zi != %"PRIu32"): %m",
                                       n, ack.size);

        log_debug("Sent coredump ack, waiting for marker.");
        socket->state = SOCKET_WAITING_MARKER;
        return 0;
}

static int socket_process_marker(SocketContext *socket, int fd, uint32_t revents) {
        assert(socket);
        assert(socket->state == SOCKET_WAITING_MARKER);
        assert(fd >= 0);

        enum coredump_mark mark;
        ssize_t n = recv(fd, &mark, sizeof(mark), /* flags= */ 0);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to receive marker: %m");
        }
        if ((size_t) n != sizeof(mark))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Received marker with invalid size (%zi).", n);

        switch (mark) {
        case COREDUMP_MARK_REQACK:
                log_debug("Sent coredump ack message is accepted, reading coredump data.");
                return 1;
        case COREDUMP_MARK_MINSIZE:
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "Sent coredump ack message is refused as its size is too small.");
        case COREDUMP_MARK_MAXSIZE:
                return log_debug_errno(SYNTHETIC_ERRNO(EMSGSIZE),
                                       "Sent coredump ack message is refused as its size is too large.");
        case COREDUMP_MARK_UNSUPPORTED:
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Sent coredump ack message is refused as it contains unsupported flags.");
        case COREDUMP_MARK_CONFLICTING:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Sent coredump ack message is refused as it contains conflicting flags.");
        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Sent coredump ack message is refused with unknown reason (%u).", mark);
        }
}

static int on_coredump_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        SocketContext *socket = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        switch (socket->state) {
        case SOCKET_WAITING_REQUEST:
                r = socket_process_request(socket, fd, revents);
                break;
        case SOCKET_SENDING_ACK:
                r = socket_send_ack(socket, fd, revents);
                break;
        case SOCKET_WAITING_MARKER:
                r = socket_process_marker(socket, fd, revents);
                break;
        default:
                assert_not_reached();
        }
        if (r != 0)
                return sd_event_exit(sd_event_source_get_event(s), r < 0 ? r : 0);

        return 0;
}

static int coredump_process_request(int fd) {
        int r;

        assert(fd >= 0);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        r = sd_event_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate sd-event object: %m");

        SocketContext socket = {};
        r = sd_event_add_io(e, NULL, fd, EPOLLIN | EPOLLOUT, on_coredump_io, &socket);
        if (r < 0)
                return log_error_errno(r, "Failed to add IO event source for kernel coredump socket: %m");

        r = sd_event_set_signal_exit(e, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable signal event sources: %m");

        log_debug("Processing coredump request.");

        r = sd_event_loop(e);
        if (r < 0)
                return log_error_errno(r, "Failed to process coredump request: %m");

        return 0;
}

int coredump_process_socket(CoredumpContext *context) {
        int r;

        assert(context);
        assert(context->input_fd >= 0);

        if (context->requested)
                return 0;

        /* Avoid processing request again later in the case that we fail to send. */
        context->requested = true;

        (void) fd_nonblock(context->input_fd, true);
        r = coredump_process_request(context->input_fd);
        (void) fd_nonblock(context->input_fd, false);

        return r;
}
