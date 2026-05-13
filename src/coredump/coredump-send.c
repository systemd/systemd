/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "coredump-context.h"
#include "coredump-send.h"
#include "coredump-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "namespace-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"

int coredump_send(CoredumpContext *context) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(context);
        assert(context->input_fd >= 0);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create coredump socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, "/run/systemd/coredump");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to coredump service: %m");

        FOREACH_ARRAY(iovec, context->iovw.iovec, context->iovw.count) {
                struct msghdr mh = {
                        .msg_iov = iovec,
                        .msg_iovlen = 1,
                };
                struct iovec copy[2];

                for (;;) {
                        if (sendmsg(fd, &mh, MSG_NOSIGNAL) >= 0)
                                break;

                        if (IN_SET(errno, EMSGSIZE, ENOBUFS) && mh.msg_iov[0].iov_len > 0) {
                                /* This field didn't fit? That's a pity. Given that this is
                                 * just metadata, let's truncate the field at half, and try
                                 * again. We append three dots, in order to show that this is
                                 * truncated. */

                                if (mh.msg_iov != copy) {
                                        /* We don't want to modify the caller's iovec, hence
                                         * let's create our own array, consisting of two new
                                         * iovecs, where the first is a (truncated) copy of
                                         * what we want to send, and the second one contains
                                         * the trailing dots. */
                                        copy[0] = *iovec;
                                        copy[1] = IOVEC_MAKE(((const char[]){'.', '.', '.'}), 3);

                                        mh.msg_iov = copy;
                                        mh.msg_iovlen = 2;
                                }

                                copy[0].iov_len /= 2; /* halve it, and try again */
                                continue;
                        }

                        return log_error_errno(errno, "Failed to send coredump datagram: %m");
                }
        }

        /* First sentinel: the coredump fd */
        r = send_one_fd(fd, context->input_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send coredump fd: %m");

        /* The optional second sentinel: the pidfd */
        if (!pidref_is_set(&context->pidref) || context->pidref.fd < 0) /* If we have no pidfd, stop now */
                return 0;

        r = send_one_fd(fd, context->pidref.fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send pidfd: %m");

        /* The optional third sentinel: the mount tree fd */
        if (context->mount_tree_fd < 0) /* If we have no mount tree, stop now */
                return 0;

        r = send_one_fd(fd, context->mount_tree_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send mount tree fd: %m");

        return 0;
}

static int can_forward_coredump(PidRef *pidref, PidRef *leader) {
        int r;

        assert(pidref_is_set(pidref));
        assert(pidref_is_set(leader));

        if (pidref_equal(pidref, leader)) {
                log_debug("The system service manager crashed.");
                return false;
        }

        /* Check if the PID1 in the namespace is still running. */
        r = pidref_kill(leader, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send kill(0) to the service manager, maybe it is crashed, ignoring: %m");

        if (leader->fd >= 0) {
                struct pidfd_info info = {
                        .mask = PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP,
                };

                r = pidfd_get_info(leader->fd, &info);
                if (r >= 0) {
                        if (FLAGS_SET(info.mask, PIDFD_INFO_EXIT)) {
                                log_debug("PID1 has already exited.");
                                return false;
                        }

                        if (FLAGS_SET(info.mask, PIDFD_INFO_COREDUMP) && FLAGS_SET(info.coredump_mask, PIDFD_COREDUMPED)) {
                                log_debug("PID1 has already dumped core.");
                                return false;
                        }
                } else if (r != -EOPNOTSUPP)
                        return log_debug_errno(r, "ioctl(PIDFD_GET_INFO) for the service manager failed, maybe crashed, ignoring: %m");
        }

        _cleanup_free_ char *cgroup = NULL;
        r = cg_pidref_get_path(leader, &cgroup);
        if (r < 0)
                return log_debug_errno(r, "Failed to get cgroup of the leader process, ignoring: %m");

        _cleanup_free_ char *path = NULL;
        r = path_extract_directory(cgroup, &path);
        if (r < 0)
                return log_debug_errno(r, "Failed to get the parent directory of \"%s\", ignoring: %m", cgroup);

        _cleanup_free_ char *unit = NULL;
        r = cg_path_get_unit_path(path, &unit);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r == -ENXIO)
                /* No valid units in this path. */
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to get unit path from cgroup \"%s\", ignoring: %m", path);

        /* We require that this process belongs to a delegated cgroup
         * (i.e. Delegate=yes), with CoredumpReceive=yes also. */
        r = cg_is_delegated(unit);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if cgroup \"%s\" is delegated, ignoring: %m", unit);
        if (r == 0)
                return false;

        r = cg_has_coredump_receive(unit);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if cgroup \"%s\" can receive coredump, ignoring: %m", unit);
        if (r == 0)
                return false;

        return true;
}

static int send_ucred(int transport_fd, const struct ucred *ucred) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        assert(transport_fd >= 0);
        assert(ucred);

        cmsg = CMSG_FIRSTHDR(&mh);
        *cmsg = (struct cmsghdr) {
                .cmsg_level = SOL_SOCKET,
                .cmsg_type = SCM_CREDENTIALS,
                .cmsg_len = CMSG_LEN(sizeof(struct ucred)),
        };
        memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));

        return RET_NERRNO(sendmsg(transport_fd, &mh, MSG_NOSIGNAL));
}

static int receive_ucred(int transport_fd, struct ucred *ret_ucred) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg = NULL;
        struct ucred *ucred = NULL;
        ssize_t n;

        assert(transport_fd >= 0);
        assert(ret_ucred);

        n = recvmsg_safe(transport_fd, &mh, 0);
        if (n < 0)
                return n;

        CMSG_FOREACH(cmsg, &mh)
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        assert(!ucred);
                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                }

        if (!ucred)
                return -EIO;

        *ret_ucred = *ucred;
        return 0;
}

int coredump_send_to_container(CoredumpContext *context) {
        int r;

        assert(context);

        if (context->same_pidns)
                return 0;

        /* We need to avoid a situation where the attacker crashes a SUID process or a root daemon and
         * quickly replaces it with a namespaced process and we forward the coredump to the attacker, into
         * the namespace. With %F/pidfd we can reliably check the namespace of the original process, hence we
         * can allow forwarding. */
        if (!context->got_pidfd && context->dumpable != SUID_DUMP_USER)
                return 0;

        _cleanup_(pidref_done) PidRef leader_pid = PIDREF_NULL;
        r = namespace_get_leader(&context->pidref, NAMESPACE_PID, &leader_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to get namespace leader: %m");

        r = can_forward_coredump(&context->pidref, &leader_pid);
        if (r <= 0)
                return r;

        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, netnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        struct ucred ucred = {
                .pid = context->pidref.pid,
                .uid = context->uid,
                .gid = context->gid,
        };

        r = RET_NERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair));
        if (r < 0)
                return log_error_errno(r, "Failed to create socket pair: %m");

        r = setsockopt_int(pair[1], SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set SO_PASSCRED: %m");

        r = pidref_namespace_open(&leader_pid, &pidnsfd, &mntnsfd, &netnsfd, &usernsfd, &rootfd);
        if (r < 0)
                return log_error_errno(r, "Failed to open namespaces of PID " PID_FMT ": %m", leader_pid.pid);

        r = namespace_fork("(sd-coredumpns)", "(sd-coredump)",
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM,
                           pidnsfd, mntnsfd, netnsfd, usernsfd, rootfd, &child);
        if (r < 0)
                return log_error_errno(r, "Failed to fork into namespaces of PID " PID_FMT ": %m", leader_pid.pid);
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                r = access_nofollow("/run/systemd/coredump", W_OK);
                if (r < 0) {
                        log_error_errno(r, "Cannot find coredump socket, exiting: %m");
                        _exit(EXIT_FAILURE);
                }

                r = receive_ucred(pair[1], &ucred);
                if (r < 0) {
                        log_error_errno(r, "Failed to receive ucred and fd: %m");
                        _exit(EXIT_FAILURE);
                }

                PidRef pidref;
                r = pidref_set_pid(&pidref, ucred.pid);
                if (r < 0) {
                        log_error_errno(r, "Failed to set pid to pidref: %m");
                        _exit(EXIT_FAILURE);
                }

                pidref_done(&context->pidref);
                context->pidref = TAKE_PIDREF(pidref);

                context->uid = ucred.uid;
                context->gid = ucred.gid;

                r = coredump_context_build_iovw(context);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                (void) iovw_put_string_field(&context->iovw, "COREDUMP_FORWARDED=", "1");

                r = coredump_send(context);
                if (r < 0) {
                        log_error_errno(r, "Failed to send iovec to coredump socket: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        /* We need to translate the PID, UID, and GID of the crashing process
         * to the container's namespaces. Do this by sending an SCM_CREDENTIALS
         * message on a socket pair, and read the result when we join the
         * container. The kernel will perform the translation for us. */
        r = send_ucred(pair[0], &ucred);
        if (r < 0)
                return log_error_errno(r, "Failed to send metadata to container: %m");

        r = pidref_wait_for_terminate_and_check("(sd-coredumpns)", &child, WAIT_LOG);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EPROTO;

        return 1; /* sent */
}
