/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "coredump.h"
#include "coredump-vacuum.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "journal-importer.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "memory-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stacktrace.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

/* Joins /proc/[pid]/fd/ and /proc/[pid]/fdinfo/ into the following lines:
 * 0:/dev/pts/23
 * pos:    0
 * flags:  0100002
 *
 * 1:/dev/pts/23
 * pos:    0
 * flags:  0100002
 *
 * 2:/dev/pts/23
 * pos:    0
 * flags:  0100002
 * EOF
 */
static int compose_open_fds(pid_t pid, char **open_fds) {
        _cleanup_closedir_ DIR *proc_fd_dir = NULL;
        _cleanup_close_ int proc_fdinfo_fd = -1;
        _cleanup_free_ char *buffer = NULL;
        _cleanup_fclose_ FILE *stream = NULL;
        const char *fddelim = "", *path;
        struct dirent *dent = NULL;
        size_t size = 0;
        int r;

        assert(pid >= 0);
        assert(open_fds != NULL);

        path = procfs_file_alloca(pid, "fd");
        proc_fd_dir = opendir(path);
        if (!proc_fd_dir)
                return -errno;

        proc_fdinfo_fd = openat(dirfd(proc_fd_dir), "../fdinfo", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (proc_fdinfo_fd < 0)
                return -errno;

        stream = open_memstream_unlocked(&buffer, &size);
        if (!stream)
                return -ENOMEM;

        FOREACH_DIRENT(dent, proc_fd_dir, return -errno) {
                _cleanup_fclose_ FILE *fdinfo = NULL;
                _cleanup_free_ char *fdname = NULL;
                int fd;

                r = readlinkat_malloc(dirfd(proc_fd_dir), dent->d_name, &fdname);
                if (r < 0)
                        return r;

                fprintf(stream, "%s%s:%s\n", fddelim, dent->d_name, fdname);
                fddelim = "\n";

                /* Use the directory entry from /proc/[pid]/fd with /proc/[pid]/fdinfo */
                fd = openat(proc_fdinfo_fd, dent->d_name, O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        continue;

                fdinfo = fdopen(fd, "r");
                if (!fdinfo) {
                        safe_close(fd);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(fdinfo, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        fputs(line, stream);
                        fputc('\n', stream);
                }
        }

        errno = 0;
        stream = safe_fclose(stream);

        if (errno > 0)
                return -errno;

        *open_fds = TAKE_PTR(buffer);

        return 0;
}

static int get_process_ns(pid_t pid, const char *namespace, ino_t *ns) {
        const char *p;
        struct stat stbuf;
        _cleanup_close_ int proc_ns_dir_fd;

        p = procfs_file_alloca(pid, "ns");

        proc_ns_dir_fd = open(p, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
        if (proc_ns_dir_fd < 0)
                return -errno;

        if (fstatat(proc_ns_dir_fd, namespace, &stbuf, /* flags */0) < 0)
                return -errno;

        *ns = stbuf.st_ino;
        return 0;
}

static int get_mount_namespace_leader(pid_t pid, pid_t *container_pid) {
        pid_t cpid = pid, ppid = 0;
        ino_t proc_mntns;
        int r = 0;

        r = get_process_ns(pid, "mnt", &proc_mntns);
        if (r < 0)
                return r;

        for (;;) {
                ino_t parent_mntns;

                r = get_process_ppid(cpid, &ppid);
                if (r < 0)
                        return r;

                r = get_process_ns(ppid, "mnt", &parent_mntns);
                if (r < 0)
                        return r;

                if (proc_mntns != parent_mntns)
                        break;

                if (ppid == 1)
                        return -ENOENT;

                cpid = ppid;
        }

        *container_pid = ppid;
        return 0;
}

/* Returns 1 if the parent was found.
 * Returns 0 if there is not a process we can call the pid's
 * container parent (the pid's process isn't 'containerized').
 * Returns a negative number on errors.
 */
static int get_process_container_parent_cmdline(pid_t pid, char** cmdline) {
        int r = 0;
        pid_t container_pid;
        const char *proc_root_path;
        struct stat root_stat, proc_root_stat;

        /* To compare inodes of / and /proc/[pid]/root */
        if (stat("/", &root_stat) < 0)
                return -errno;

        proc_root_path = procfs_file_alloca(pid, "root");
        if (stat(proc_root_path, &proc_root_stat) < 0)
                return -errno;

        /* The process uses system root. */
        if (proc_root_stat.st_ino == root_stat.st_ino) {
                *cmdline = NULL;
                return 0;
        }

        r = get_mount_namespace_leader(pid, &container_pid);
        if (r < 0)
                return r;

        r = get_process_cmdline(container_pid, SIZE_MAX, 0, cmdline);
        if (r < 0)
                return r;

        return 1;
}

static int send_iovec(const struct iovec_wrapper *iovw, int input_fd) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/coredump",
        };
        _cleanup_close_ int fd = -1;
        size_t i;
        int r;

        assert(iovw);
        assert(input_fd >= 0);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create coredump socket: %m");

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return log_error_errno(errno, "Failed to connect to coredump service: %m");

        for (i = 0; i < iovw->count; i++) {
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
                                        copy[1] = IOVEC_MAKE(((char[]){'.', '.', '.'}), 3);

                                        mh.msg_iov = copy;
                                        mh.msg_iovlen = 2;
                                }

                                copy[0].iov_len /= 2; /* halve it, and try again */
                                continue;
                        }

                        return log_error_errno(errno, "Failed to send coredump datagram: %m");
                }
        }

        r = send_one_fd(fd, input_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send coredump fd: %m");

        return 0;
}

static int gather_pid_metadata_from_strv(struct iovec_wrapper *iovw, Context *context, char **strv) {
        char **s;
        int r;

        /* We gather all metadata that were passed via argv[] into an array of iovecs that
         * we'll forward to the socket unit */

        STRV_FOREACH(s, strv) {
                char *p, *v;

                p = *s;
                v = strchr(p, '=');
                if (!v || v[1] == '\0')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Badly formatted parameter '%s'", p);

                if (startswith(p, "_SIGNAL=")) {
                        int signo;

                        /* For signal, record its pretty name too */
                        if (safe_atoi(v, &signo) >= 0 && SIGNAL_VALID(signo))
                                (void) iovw_put_string_field(iovw, "COREDUMP_SIGNAL_NAME=SIG",
                                                             signal_to_string(signo));

                } else if (startswith(p, "_TIMESTAMP="))
                        /* The journal fields contain the timestamp padded with six
                         * zeroes, so that the kernel-supplied 1s granularity timestamps
                         * becomes 1µs granularity, i.e. the granularity systemd usually
                         * operates in. */
                        p = strjoina(p, "000000");

                p = (p[0] == '_') ? strjoin("COREDUMP", p) : strdup(p);
                if (!p)
                        return log_oom();

                r = iovw_put(iovw, p, strlen(p));
                if (r < 0) {
                        free(p);
                        return r;
                }
        }

        /* Cache some of the process metadata we collected so far and that we'll need to
         * access soon. */
        return coredump_save_context(context, iovw);
}

static int gather_pid_metadata(struct iovec_wrapper *iovw, Context *context) {
        uid_t uid, owner_uid;
        gid_t gid;
        pid_t pid;
        char *t;
        const char *p;
        int r;

        /* Note that if we fail on oom later on, we do not roll-back changes to the iovec
         * structure. (It remains valid, with the first iovec fields initialized.) */

        pid = context->pid;

        /* The following are mandatory */
        r = get_process_comm(pid, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to get COMM: %m");

        r = iovw_put_string_field_free(iovw, "COREDUMP_COMM=", t);
        if (r < 0)
                return r;

        r = get_process_uid(pid, &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to get UID: %m");

        r = asprintf(&t, UID_FMT, uid);
        if (r < 0)
                 return -ENOMEM;

        r = iovw_put_string_field_free(iovw, "COREDUMP_UID=", t);
        if (r < 0)
                return r;

        r = get_process_gid(pid, &gid);
        if (r < 0)
                return log_error_errno(r, "Failed to get GID: %m");

        r = asprintf(&t, GID_FMT, gid);
        if (r < 0)
                 return -ENOMEM;

        r = iovw_put_string_field_free(iovw, "COREDUMP_GID=", t);
        if (r < 0)
                return r;

        /* The following are optional but we used them if present */
        r = get_process_exe(pid, &t);
        if (r >= 0)
                r = iovw_put_string_field_free(iovw, "COREDUMP_EXE=", t);
        if (r < 0)
                log_warning_errno(r, "Failed to get EXE, ignoring: %m");

        if (cg_pid_get_unit(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_UNIT=", t);

        /* The next are optional */
        if (cg_pid_get_user_unit(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_USER_UNIT=", t);

        if (sd_pid_get_session(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SESSION=", t);

        if (sd_pid_get_owner_uid(pid, &owner_uid) >= 0) {
                r = asprintf(&t, UID_FMT, owner_uid);
                if (r > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_OWNER_UID=", t);
        }

        if (sd_pid_get_slice(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SLICE=", t);

        if (get_process_cmdline(pid, SIZE_MAX, 0, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CMDLINE=", t);

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CGROUP=", t);

        if (compose_open_fds(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_OPEN_FDS=", t);

        p = procfs_file_alloca(pid, "status");
        if (read_full_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_STATUS=", t);

        p = procfs_file_alloca(pid, "maps");
        if (read_full_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MAPS=", t);

        p = procfs_file_alloca(pid, "limits");
        if (read_full_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_LIMITS=", t);

        p = procfs_file_alloca(pid, "cgroup");
        if (read_full_file(p, &t, NULL) >=0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_CGROUP=", t);

        p = procfs_file_alloca(pid, "mountinfo");
        if (read_full_file(p, &t, NULL) >=0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MOUNTINFO=", t);

        if (get_process_cwd(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CWD=", t);

        if (get_process_root(pid, &t) >= 0) {
                bool proc_self_root_is_slash;

                proc_self_root_is_slash = strcmp(t, "/") == 0;

                (void) iovw_put_string_field_free(iovw, "COREDUMP_ROOT=", t);

                /* If the process' root is "/", then there is a chance it has
                 * mounted own root and hence being containerized. */
                if (proc_self_root_is_slash && get_process_container_parent_cmdline(pid, &t) > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_CONTAINER_CMDLINE=", t);
        }

        if (get_process_environ(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_ENVIRON=", t);

        /* we successfully acquired all metadata */
        return coredump_save_context(context, iovw);
}

static int process_kernel(char* argv[]) {
        Context context = {};
        struct iovec_wrapper *iovw;
        int r;

        log_debug("Processing coredump received from the kernel...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        /* Collect all process metadata passed by the kernel through argv[] */
        r = gather_pid_metadata_from_strv(iovw, &context, argv);
        if (r < 0)
                goto finish;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata(iovw, &context);
        if (r < 0)
                goto finish;

        if (!context.is_journald) {
                /* OK, now we know it's not the journal, hence we can make use of it now. */
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_open();
        }

        /* If this is PID 1 disable coredump collection, we'll unlikely be able to process
         * it later on.
         *
         * FIXME: instead of turning coredump collection off completely, shouldn't we restore the
         * default value and let the kernel take over ? */
        if (context.is_pid1) {
                log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                disable_coredumps();
        }

        if (context.is_journald || context.is_pid1 || context.is_coredumpd)
                r = coredump_submit(&context, iovw, STDIN_FILENO);
        else
                r = send_iovec(iovw, STDIN_FILENO);

 finish:
        iovw = iovw_free_free(iovw);
        return r;
}

static int process_backtrace(char *argv[]) {
        Context context = {};
        struct iovec_wrapper *iovw;
        char *message;
        size_t i;
        int r;
         _cleanup_(journal_importer_cleanup) JournalImporter importer = JOURNAL_IMPORTER_INIT(STDIN_FILENO);

        log_debug("Processing backtrace on stdin...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_BACKTRACE_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        /* Collect all process metadata passed via argv[] */
        r = gather_pid_metadata_from_strv(iovw, &context, argv);
        if (r < 0)
                goto finish;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata(iovw, &context);
        if (r < 0)
                goto finish;

        for (;;) {
                r = journal_importer_process_data(&importer);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse journal entry on stdin: %m");
                        goto finish;
                }
                if (r == 1 ||                        /* complete entry */
                    journal_importer_eof(&importer)) /* end of data */
                        break;
        }

        if (journal_importer_eof(&importer)) {
                log_warning("Did not receive a full journal entry on stdin, ignoring message sent by reporter");

                message = strjoina("Process ", context.meta[META_PID],
                                  " (", context.meta[META_COMM], ")"
                                  " of user ", context.meta[META_UID],
                                  " failed with ", context.meta[META_SIGNAL]);

                r = iovw_put_string_field(iovw, "MESSAGE=", message);
                if (r < 0)
                        return r;
        } else {
                /* The imported iovecs are not supposed to be freed by us so let's store
                 * them at the end of the array so we can skip them while freeing the
                 * rest. */
                for (i = 0; i < importer.iovw.count; i++) {
                        struct iovec *iovec = importer.iovw.iovec + i;

                        iovw_put(iovw, iovec->iov_base, iovec->iov_len);
                }
        }

        r = sd_journal_sendv(iovw->iovec, iovw->count);
        if (r < 0)
                log_error_errno(r, "Failed to log backtrace: %m");

 finish:
        iovw->count -= importer.iovw.count;
        iovw = iovw_free_free(iovw);
        return r;
}

static int run(int argc, char *argv[]) {

        /* First, log to a safe place, since we don't know what crashed and it might
         * be journald which we'd rather not log to then. */

        log_set_target(LOG_TARGET_KMSG);
        log_open();

        /* Make sure we never enter a loop */
        (void) prctl(PR_SET_DUMPABLE, 0);

        if (streq_ptr(argv[1], "--backtrace"))
                /* Skip --backtrace from the argument list */
                return process_backtrace(argv + 2);

        return process_kernel(argv + 1);
}

DEFINE_MAIN_FUNCTION(run);
