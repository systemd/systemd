/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-json.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "coredump-backtrace.h"
#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-receive.h"
#include "coredump-submit.h"
#include "coredump-util.h"
#include "coredump-vacuum.h"
#include "dirent-util.h"
#include "elf-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-importer.h"
#include "journal-send.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "mkdir-label.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "user-util.h"

static int send_iovec(const struct iovec_wrapper *iovw, int input_fd, PidRef *pidref, int mount_tree_fd) {
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

                        if (errno == EMSGSIZE && mh.msg_iov[0].iov_len > 0) {
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

static int forward_coredump_to_container(Context *context) {
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

                r = send_iovec(iovw, STDIN_FILENO, &context->pidref, /* mount_tree_fd= */ -EBADF);
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

static int process_kernel(int argc, char *argv[]) {
        _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = NULL;
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        /* When we're invoked by the kernel, stdout/stderr are closed which is dangerous because the fds
         * could get reallocated. To avoid hard to debug issues, let's instead bind stdout/stderr to
         * /dev/null. */
        r = rearrange_stdio(STDIN_FILENO, -EBADF, -EBADF);
        if (r < 0)
                return log_error_errno(r, "Failed to connect stdout/stderr to /dev/null: %m");

        log_debug("Processing coredump received from the kernel...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        /* Collect all process metadata passed by the kernel through argv[] */
        r = gather_pid_metadata_from_argv(iovw, &context, argc - 1, argv + 1);
        if (r < 0)
                return r;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata_from_procfs(iovw, &context);
        if (r < 0)
                return r;

        if (!context.is_journald)
                /* OK, now we know it's not the journal, hence we can make use of it now. */
                log_set_target_and_open(LOG_TARGET_JOURNAL_OR_KMSG);

        /* Log minimal metadata now, so it is not lost if the system is about to shut down. */
        log_info("Process %s (%s) of user %s terminated abnormally with signal %s/%s, processing...",
                 context.meta[META_ARGV_PID], context.meta[META_COMM],
                 context.meta[META_ARGV_UID], context.meta[META_ARGV_SIGNAL],
                 signal_to_string(context.signo));

        r = pidref_in_same_namespace(/* pid1 = */ NULL, &context.pidref, NAMESPACE_PID);
        if (r < 0)
                log_debug_errno(r, "Failed to check pidns of crashing process, ignoring: %m");
        if (r == 0) {
                /* If this fails, fallback to the old behavior so that
                 * there is still some record of the crash. */
                r = forward_coredump_to_container(&context);
                if (r >= 0)
                        return 0;

                r = acquire_pid_mount_tree_fd(&context, &context.mount_tree_fd);
                if (r < 0)
                        log_warning_errno(r, "Failed to access the mount tree of a container, ignoring: %m");
        }

        /* If this is PID 1, disable coredump collection, we'll unlikely be able to process
         * it later on.
         *
         * FIXME: maybe we should disable coredumps generation from the beginning and
         * re-enable it only when we know it's either safe (i.e. we're not running OOM) or
         * it's not PID 1 ? */
        if (context.is_pid1) {
                log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                disable_coredumps();
        }

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        if (context.is_journald || context.is_pid1)
                return coredump_submit(&context, iovw, STDIN_FILENO);

        return send_iovec(iovw, STDIN_FILENO, &context.pidref, context.mount_tree_fd);
}

static int run(int argc, char *argv[]) {
        int r;

        /* First, log to a safe place, since we don't know what crashed and it might
         * be journald which we'd rather not log to then. */

        log_set_target_and_open(LOG_TARGET_KMSG);

        /* Make sure we never enter a loop */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        /* Ignore all parse errors */
        (void) coredump_parse_config();

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we
         * are invoked from the kernel as coredump handler. */
        if (r == 0) {
                if (streq_ptr(argv[1], "--backtrace"))
                        return coredump_backtrace(argc, argv);
                else
                        return process_kernel(argc, argv);
        } else if (r == 1)
                return coredump_receive_and_submit(SD_LISTEN_FDS_START);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Received unexpected number of file descriptors.");
}

DEFINE_MAIN_FUNCTION(run);
