/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "coredump-context.h"
#include "coredump-receive.h"
#include "coredump-submit.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "fd-util.h"
#include "log.h"
#include "socket-util.h"

int coredump_receive(int fd) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_close_ int input_fd = -EBADF;
        enum {
                STATE_PAYLOAD,
                STATE_INPUT_FD_DONE,
                STATE_PID_FD_DONE,
        } state = STATE_PAYLOAD;
        int r;

        assert(fd >= 0);

        log_setup();

        log_debug("Processing coredump received via socket...");

        for (;;) {
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int))) control;
                struct msghdr mh = {
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                        .msg_iovlen = 1,
                };
                ssize_t n, l;

                l = next_datagram_size_fd(fd);
                if (l < 0)
                        return log_error_errno(l, "Failed to determine datagram size to read: %m");

                _cleanup_(iovec_done) struct iovec iovec = {
                        .iov_len = l,
                        .iov_base = malloc(l + 1),
                };
                if (!iovec.iov_base)
                        return log_oom();

                mh.msg_iov = &iovec;

                n = recvmsg_safe(fd, &mh, MSG_CMSG_CLOEXEC);
                if (n < 0)
                        return log_error_errno(n, "Failed to receive datagram: %m");

                /* The final zero-length datagrams ("sentinels") carry file descriptors and tell us that
                 * we're done. There are three sentinels: one with just the coredump fd, followed by one with
                 * the pidfd, and finally one with the mount tree fd. The latter two or the last one may be
                 * omitted (which is supported for compatibility with older systemd version, in particular to
                 * facilitate cross-container coredumping). */
                if (n == 0) {
                        struct cmsghdr *found;

                        found = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN(sizeof(int)));
                        if (!found) {
                                /* This is zero length message but it either doesn't carry a single
                                 * descriptor, or it has more than one. This is a protocol violation so let's
                                 * bail out.
                                 *
                                 * Well, not quite! In practice there's one more complication: EOF on
                                 * SOCK_SEQPACKET is not distinguishable from a zero length datagram. Hence
                                 * if we get a zero length datagram without fds we consider it EOF, and
                                 * that's permissible for the final two fds. Hence let's be strict on the
                                 * first fd, but lenient on the other two. */

                                if (!cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1) && state != STATE_PAYLOAD)
                                        /* No fds, and already got the first fd → we are done. */
                                        break;

                                cmsg_close_all(&mh);
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Received zero length message with zero or more than one file descriptor(s), expected one.");
                        }

                        switch (state) {

                        case STATE_PAYLOAD:
                                assert(input_fd < 0);
                                input_fd = *CMSG_TYPED_DATA(found, int);
                                state = STATE_INPUT_FD_DONE;
                                continue;

                        case STATE_INPUT_FD_DONE:
                                assert(!pidref_is_set(&context.pidref));

                                r = pidref_set_pidfd_consume(&context.pidref, *CMSG_TYPED_DATA(found, int));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to initialize pidref: %m");

                                state = STATE_PID_FD_DONE;
                                continue;

                        case STATE_PID_FD_DONE:
                                assert(context.mount_tree_fd < 0);
                                context.mount_tree_fd = *CMSG_TYPED_DATA(found, int);
                                /* We have all FDs we need so we are done. */
                                break;
                        }

                        break;
                }

                cmsg_close_all(&mh);

                /* Only zero length messages are allowed after the first message that carried a file descriptor. */
                if (state != STATE_PAYLOAD)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received unexpected message with non-zero length.");

                /* Payload messages should not carry fds */
                if (cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Received payload message with file descriptor(s), expected none.");

                /* Add trailing NUL byte, in case these are strings */
                ((char*) iovec.iov_base)[n] = 0;
                iovec.iov_len = (size_t) n;

                if (iovw_put(&iovw, iovec.iov_base, iovec.iov_len) < 0)
                        return log_oom();

                TAKE_STRUCT(iovec);
        }

        /* Make sure we got all data we really need */
        assert(input_fd >= 0);

        r = context_parse_iovw(&context, &iovw);
        if (r < 0)
                return r;

        /* Make sure we received all the expected fields. We support being called by an *older*
         * systemd-coredump from the outside, so we require only the basic set of fields that
         * was being sent when the support for sending to containers over a socket was added
         * in a108c43e36d3ceb6e34efe37c014fc2cda856000. */
        meta_argv_t i;
        FOREACH_ARGUMENT(i,
                         META_ARGV_PID,
                         META_ARGV_UID,
                         META_ARGV_GID,
                         META_ARGV_SIGNAL,
                         META_ARGV_TIMESTAMP,
                         META_ARGV_RLIMIT,
                         META_ARGV_HOSTNAME,
                         META_COMM)
                if (!context.meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Mandatory argument %s not received on socket, aborting.",
                                               meta_field_names[i]);

        return coredump_submit(&context, &iovw, input_fd);
}
