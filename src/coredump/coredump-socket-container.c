/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-event.h"

#include "coredump-socket.h"
#include "coredump-socket-container.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

typedef struct ContainerContext {
        int fd;
        int coredump_fd;
        usec_t timestamp;
        bool request_mode;
} ContainerContext;

static void container_done(ContainerContext *cc) {
        assert(cc);

        safe_close(cc->fd);
        safe_close(cc->coredump_fd);
}

static int process_message(ContainerContext *cc) {
        int r;

        assert(cc);
        assert(cc->fd >= 0);

        ssize_t l = next_datagram_size_fd(cc->fd);
        if (l < 0)
                return log_error_errno(l, "Failed to determine datagram size to read: %m");

        _cleanup_(iovec_done) struct iovec iovec = {
                .iov_len = l,
                .iov_base = malloc(l + 1),
        };
        if (!iovec.iov_base)
                return log_oom();

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int))) control;
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = &iovec,
                .msg_iovlen = 1,
        };

        ssize_t n = recvmsg_safe(cc->fd, &mh, MSG_CMSG_CLOEXEC);
        if (n < 0)
                return log_error_errno(n, "Failed to receive datagram: %m");

        /* The final zero-length datagram ("sentinel") carry file descriptor. */
        if (n == 0) {
                int *fd = CMSG_FIND_DATA(&mh, SOL_SOCKET, SCM_RIGHTS, int);
                if (!fd)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Received zero-length datagram without or multiple file descriptrs.");
                if (*fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Received zero-length datagram with an invalid file descriptr.");

                r = sd_is_socket_unix(*fd, SOCK_STREAM, /* listening= */ false, /* path= */ NULL, /* length= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if received file descriptor is a valid unix socket: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Received invalid coredump socket.");

                assert(cc->coredump_fd < 0);
                cc->coredump_fd = *fd;
                return 1;
        }

        cmsg_close_all(&mh);

        /* Payload messages should not carry fds */
        if (cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received payload message with file descriptor(s), expected none.");

        /* Add trailing NUL byte, for safety. */
        char *str = iovec.iov_base;
        str[n] = '\0';

        const char *val;
        if ((val = startswith(str, "TIMESTAMP="))) {
                usec_t t;

                r = safe_atou64(val, &t);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse received message, ignoring: %s", str);
                        return 0;
                }

                r = namespace_is_init(NAMESPACE_TIME);
                if (r < 0) {
                        log_warning_errno(r, "Failed to check if we are in the initial time namespace, ignoring: %m");
                        return 0;
                }
                if (r == 0) {
                        log_debug("We are in a non-initial time namespace, ignoring received timestamp.");
                        return 0;
                }

                cc->timestamp = t;
                return 0;
        }

        if ((val = startswith(str, "REQUEST="))) {
                r = parse_boolean(val);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse received message, ignoring: %s", str);
                        return 0;
                }

                cc->request_mode = r;
                return 0;
        }

        log_debug("Received unknown message, ignoring: %s", str);
        return 0;
}

static int on_receive(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        ContainerContext *cc = ASSERT_PTR(userdata);
        int r;

        r = process_message(cc);
        if (r != 0)
                return sd_event_exit(sd_event_source_get_event(s), r < 0 ? r : 0);

        return 0;
}

static int container_parse_message(ContainerContext *cc) {
        int r;

        assert(cc);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        r = sd_event_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate sd-event object: %m");

        r = sd_event_set_signal_exit(e, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable signal event sources: %m");

        r = sd_event_add_io(e, NULL, cc->fd, EPOLLIN, on_receive, cc);
        if (r < 0)
                return log_error_errno(r, "Failed to add IO event source for socket: %m");

        r = sd_event_loop(e);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

static int container_listen_fds(ContainerContext *cc) {
        int r;

        assert(cc);

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");
        if (r != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Received unexpected number (%i) of file descriptors.", r);

        _cleanup_close_ int fd = SD_LISTEN_FDS_START;

        r = sd_is_socket_unix(fd, SOCK_SEQPACKET, /* listening= */ false, /* path= */ NULL, /* length= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to check if received file descriptor is a valid unix socket: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Received invalid file descriptor.");

        cc->fd = TAKE_FD(fd);
        return 0;
}

int coredump_process_container_socket(int argc, char *argv[]) {
        int r;

        _cleanup_(container_done) ContainerContext cc = {
                .fd = -EBADF,
                .coredump_fd = -EBADF,
                .timestamp = now(CLOCK_REALTIME),
        };

        r = container_listen_fds(&cc);
        if (r < 0)
                return r;

        r = container_parse_message(&cc);
        if (r < 0)
                return r;

        return coredump_process_socket(cc.coredump_fd, cc.request_mode, cc.timestamp);
}
