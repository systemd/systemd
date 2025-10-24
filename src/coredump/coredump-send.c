/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-messages.h"

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
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"

int coredump_send(const struct iovec_wrapper *iovw, int input_fd, PidRef *pidref, int mount_tree_fd) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(iovw);
        assert(input_fd >= 0);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create coredump socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, "/run/systemd/coredump");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to coredump service: %m");

        for (size_t i = 0; i < iovw->count; i++) {
                struct msghdr mh = {
                        .msg_iov = iovw->iovec + i,
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
                                        copy[0] = iovw->iovec[i];
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
        r = send_one_fd(fd, input_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send coredump fd: %m");

        /* The optional second sentinel: the pidfd */
        if (!pidref_is_set(pidref) || pidref->fd < 0) /* If we have no pidfd, stop now */
                return 0;

        r = send_one_fd(fd, pidref->fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send pidfd: %m");

        /* The optional third sentinel: the mount tree fd */
        if (mount_tree_fd < 0) /* If we have no mount tree, stop now */
                return 0;

        r = send_one_fd(fd, mount_tree_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send mount tree fd: %m");

        return 0;
}

static int can_forward_coredump(Context *context, const PidRef *pid) {
        _cleanup_free_ char *cgroup = NULL, *path = NULL, *unit = NULL;
        int r;

        assert(context);
        assert(pidref_is_set(pid));
        assert(!pidref_is_remote(pid));

        /* We need to avoid a situation where the attacker crashes a SUID process or a root daemon and
         * quickly replaces it with a namespaced process and we forward the coredump to the attacker, into
         * the namespace. With %F/pidfd we can reliably check the namespace of the original process, hence we
         * can allow forwarding. */
        if (!context->got_pidfd && context->dumpable != SUID_DUMP_USER)
                return false;

        r = cg_pidref_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup);
        if (r < 0)
                return r;

        r = path_extract_directory(cgroup, &path);
        if (r < 0)
                return r;

        r = cg_path_get_unit_path(path, &unit);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -ENXIO)
                /* No valid units in this path. */
                return false;
        if (r < 0)
                return r;

        /* We require that this process belongs to a delegated cgroup
         * (i.e. Delegate=yes), with CoredumpReceive=yes also. */
        r = cg_is_delegated(unit);
        if (r <= 0)
                return r;

        return cg_has_coredump_receive(unit);
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

int coredump_send_to_container(Context *context) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, netnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        pid_t child;
        struct ucred ucred = {
                .pid = context->pidref.pid,
                .uid = context->uid,
                .gid = context->gid,
        };
        int r;

        assert(context);

        _cleanup_(pidref_done) PidRef leader_pid = PIDREF_NULL;
        r = namespace_get_leader(&context->pidref, NAMESPACE_PID, &leader_pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get namespace leader: %m");

        r = can_forward_coredump(context, &leader_pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if coredump can be forwarded: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Coredump will not be forwarded because no target cgroup was found.");

        r = RET_NERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair));
        if (r < 0)
                return log_debug_errno(r, "Failed to create socket pair: %m");

        r = setsockopt_int(pair[1], SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to set SO_PASSCRED: %m");

        r = pidref_namespace_open(&leader_pid, &pidnsfd, &mntnsfd, &netnsfd, &usernsfd, &rootfd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open namespaces of PID " PID_FMT ": %m", leader_pid.pid);

        r = namespace_fork("(sd-coredumpns)", "(sd-coredump)", NULL, 0,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM,
                           pidnsfd, mntnsfd, netnsfd, usernsfd, rootfd, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork into namespaces of PID " PID_FMT ": %m", leader_pid.pid);
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                r = access_nofollow("/run/systemd/coredump", W_OK);
                if (r < 0) {
                        log_debug_errno(r, "Cannot find coredump socket, exiting: %m");
                        _exit(EXIT_FAILURE);
                }

                r = receive_ucred(pair[1], &ucred);
                if (r < 0) {
                        log_debug_errno(r, "Failed to receive ucred and fd: %m");
                        _exit(EXIT_FAILURE);
                }

                _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = iovw_new();
                if (!iovw) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
                (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));
                (void) iovw_put_string_field(iovw, "COREDUMP_FORWARDED=", "1");

                for (int i = 0; i < _META_ARGV_MAX; i++) {
                        char buf[DECIMAL_STR_MAX(pid_t)];
                        const char *t = context->meta[i];

                        /* Patch some of the fields with the translated ucred data */
                        switch (i) {

                        case META_ARGV_PID:
                                xsprintf(buf, PID_FMT, ucred.pid);
                                t = buf;
                                break;

                        case META_ARGV_UID:
                                xsprintf(buf, UID_FMT, ucred.uid);
                                t = buf;
                                break;

                        case META_ARGV_GID:
                                xsprintf(buf, GID_FMT, ucred.gid);
                                t = buf;
                                break;

                        default:
                                ;
                        }

                        r = iovw_put_string_field(iovw, meta_field_names[i], t);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to construct iovec: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                _cleanup_(context_done) Context child_context = CONTEXT_NULL;
                r = context_parse_iovw(&child_context, iovw);
                if (r < 0) {
                        log_debug_errno(r, "Failed to save context: %m");
                        _exit(EXIT_FAILURE);
                }

                r = gather_pid_metadata_from_procfs(iovw, &child_context);
                if (r < 0) {
                        log_debug_errno(r, "Failed to gather metadata from procfs: %m");
                        _exit(EXIT_FAILURE);
                }

                r = coredump_send(iovw, STDIN_FILENO, &context->pidref, /* mount_tree_fd= */ -EBADF);
                if (r < 0) {
                        log_debug_errno(r, "Failed to send iovec to coredump socket: %m");
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
                return log_debug_errno(r, "Failed to send metadata to container: %m");

        r = wait_for_terminate_and_check("(sd-coredumpns)", child, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for child to terminate: %m");
        if (r != EXIT_SUCCESS)
                return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Failed to process coredump in container.");

        return 0;
}
