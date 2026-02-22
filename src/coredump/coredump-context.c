/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-login.h"
#include "sd-messages.h"

#include "coredump-context.h"
#include "coredump-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "memstream-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"

static const char * const metadata_field_table[_META_MAX] = {
        [META_ARGV_PID]       = "COREDUMP_PID=",
        [META_ARGV_UID]       = "COREDUMP_UID=",
        [META_ARGV_GID]       = "COREDUMP_GID=",
        [META_ARGV_SIGNAL]    = "COREDUMP_SIGNAL=",
        [META_ARGV_TIMESTAMP] = "COREDUMP_TIMESTAMP=",
        [META_ARGV_RLIMIT]    = "COREDUMP_RLIMIT=",
        [META_ARGV_HOSTNAME]  = "COREDUMP_HOSTNAME=",
        [META_ARGV_DUMPABLE]  = "COREDUMP_DUMPABLE=",
        [META_ARGV_PIDFD]     = "COREDUMP_BY_PIDFD=",
        [META_COMM]           = "COREDUMP_COMM=",
        [META_EXE]            = "COREDUMP_EXE=",
        [META_UNIT]           = "COREDUMP_UNIT=",
        [META_PROC_AUXV]      = "COREDUMP_PROC_AUXV=",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(metadata_field, MetadataField);

void coredump_context_done(CoredumpContext *context) {
        assert(context);

        pidref_done(&context->pidref);
        free(context->hostname);
        free(context->comm);
        free(context->exe);
        free(context->unit);
        free(context->auxv);
        safe_close(context->mount_tree_fd);
        iovw_done_free(&context->iovw);
        safe_close(context->input_fd);
}

bool coredump_context_is_pid1(CoredumpContext *context) {
        assert(context);
        return context->pidref.pid == 1 || streq_ptr(context->unit, SPECIAL_INIT_SCOPE);
}

bool coredump_context_is_journald(CoredumpContext *context) {
        assert(context);
        return streq_ptr(context->unit, SPECIAL_JOURNALD_SERVICE);
}

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
static int compose_open_fds(pid_t pid, char **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_closedir_ DIR *proc_fd_dir = NULL;
        _cleanup_close_ int proc_fdinfo_fd = -EBADF;
        const char *fddelim = "", *path;
        FILE *stream;
        int r;

        assert(pid >= 0);
        assert(ret);

        path = procfs_file_alloca(pid, "fd");
        proc_fd_dir = opendir(path);
        if (!proc_fd_dir)
                return -errno;

        proc_fdinfo_fd = openat(dirfd(proc_fd_dir), "../fdinfo", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (proc_fdinfo_fd < 0)
                return -errno;

        stream = memstream_init(&m);
        if (!stream)
                return -ENOMEM;

        FOREACH_DIRENT(de, proc_fd_dir, return -errno) {
                _cleanup_fclose_ FILE *fdinfo = NULL;
                _cleanup_free_ char *fdname = NULL;
                _cleanup_close_ int fd = -EBADF;

                r = readlinkat_malloc(dirfd(proc_fd_dir), de->d_name, &fdname);
                if (r < 0)
                        return r;

                fprintf(stream, "%s%s:%s\n", fddelim, de->d_name, fdname);
                fddelim = "\n";

                /* Use the directory entry from /proc/[pid]/fd with /proc/[pid]/fdinfo */
                fd = openat(proc_fdinfo_fd, de->d_name, O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        continue;

                fdinfo = take_fdopen(&fd, "r");
                if (!fdinfo)
                        continue;

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

        return memstream_finalize(&m, ret, NULL);
}

/* Returns 1 if the parent was found.
 * Returns 0 if there is not a process we can call the pid's
 * container parent (the pid's process isn't 'containerized').
 * Returns a negative number on errors.
 */
static int get_process_container_parent_cmdline(PidRef *pid, char** ret_cmdline) {
        int r;

        assert(pidref_is_set(pid));
        assert(!pidref_is_remote(pid));

        r = pidref_from_same_root_fs(pid, &PIDREF_MAKE_FROM_PID(1));
        if (r < 0)
                return r;
        if (r > 0) {
                /* The process uses system root. */
                *ret_cmdline = NULL;
                return 0;
        }

        _cleanup_(pidref_done) PidRef container_pid = PIDREF_NULL;
        r = namespace_get_leader(pid, NAMESPACE_MOUNT, &container_pid);
        if (r < 0)
                return r;

        r = pidref_get_cmdline(&container_pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, ret_cmdline);
        if (r < 0)
                return r;

        return 1;
}

int coredump_context_build_iovw(CoredumpContext *context) {
        char *t;
        int r;

        assert(context);
        assert(pidref_is_set(&context->pidref));

        if (!iovw_isempty(&context->iovw))
                return 0;

        pid_t pid = context->pidref.pid;

        r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_PID=", PID_FMT, context->pidref.pid);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_PID= field: %m");

        if (context->got_pidfd) {
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_BY_PIDFD=", "1");

                if (pidref_acquire_pidfd_id(&context->pidref) >= 0)
                        (void) iovw_put_string_fieldf(&context->iovw, "COREDUMP_PIDFDID=", "%"PRIu64, context->pidref.fd_id);
        }

        r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_UID=", UID_FMT, context->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_UID= field: %m");

        r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_GID=", UID_FMT, context->gid);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_GID= field: %m");

        if (SIGNAL_VALID(context->signo)) {
                r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_SIGNAL=", "%i", context->signo);
                if (r < 0)
                        return log_error_errno(r, "Failed to add COREDUMP_SIGNAL= field: %m");

                (void) iovw_put_string_field(&context->iovw, "COREDUMP_SIGNAL_NAME=SIG", signal_to_string(context->signo));
        }

        r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_TIMESTAMP=", USEC_FMT, context->timestamp);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_TIMESTAMP= field: %m");

        r = iovw_put_string_fieldf(&context->iovw, "COREDUMP_RLIMIT=", "%"PRIu64, context->rlimit);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_RLIMIT= field: %m");

        if (context->hostname)
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_HOSTNAME=", context->hostname);

        (void) iovw_put_string_fieldf(&context->iovw, "COREDUMP_DUMPABLE=", "%u", context->dumpable);

        r = iovw_put_string_field(&context->iovw, "COREDUMP_COMM=", context->comm);
        if (r < 0)
                return log_error_errno(r, "Failed to add COREDUMP_COMM= field: %m");

        if (context->exe)
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_EXE=", context->exe);

        (void) iovw_put_string_field(&context->iovw, "COREDUMP_UNIT=", context->unit);

        if (cg_pidref_get_user_unit(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_USER_UNIT=", t);

        if (cg_pidref_get_session(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_SESSION=", t);

        uid_t owner_uid;
        if (cg_pidref_get_owner_uid(&context->pidref, &owner_uid) >= 0)
                (void) iovw_put_string_fieldf(&context->iovw, "COREDUMP_OWNER_UID=", UID_FMT, owner_uid);

        if (sd_pid_get_slice(pid, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_SLICE=", t);

        if (pidref_get_cmdline(&context->pidref, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_CMDLINE=", t);

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_CGROUP=", t);

        if (compose_open_fds(pid, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_OPEN_FDS=", t);

        if (read_full_file(procfs_file_alloca(pid, "status"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_PROC_STATUS=", t);

        if (read_full_file(procfs_file_alloca(pid, "maps"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_PROC_MAPS=", t);

        if (read_full_file(procfs_file_alloca(pid, "limits"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_PROC_LIMITS=", t);

        if (read_full_file(procfs_file_alloca(pid, "cgroup"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_PROC_CGROUP=", t);

        if (read_full_file(procfs_file_alloca(pid, "mountinfo"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_PROC_MOUNTINFO=", t);

        /* We attach /proc/auxv here. ELF coredumps also contain a note for this (NT_AUXV), see elf(5). */
        if (context->auxv) {
                size_t sz = STRLEN("COREDUMP_PROC_AUXV=") + context->auxv_size;
                char *buf = malloc(sz + 1);
                if (buf) {
                        /* Add a dummy terminator to make coredump_context_parse_iovw() happy. */
                        *mempcpy_typesafe(stpcpy(buf, "COREDUMP_PROC_AUXV="), context->auxv, context->auxv_size) = '\0';
                        (void) iovw_consume(&context->iovw, buf, sz);
                }
        }

        if (get_process_cwd(pid, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_CWD=", t);

        if (get_process_root(pid, &t) >= 0) {
                bool proc_self_root_is_slash;

                proc_self_root_is_slash = strcmp(t, "/") == 0;

                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_ROOT=", t);

                /* If the process' root is "/", then there is a chance it has
                 * mounted own root and hence being containerized. */
                if (proc_self_root_is_slash && get_process_container_parent_cmdline(&context->pidref, &t) > 0)
                        (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_CONTAINER_CMDLINE=", t);
        }

        if (get_process_environ(pid, &t) >= 0)
                (void) iovw_put_string_field_free(&context->iovw, "COREDUMP_ENVIRON=", t);

        if (context->forwarded)
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_FORWARDED=", "1");

        (void) iovw_put_string_field(&context->iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));
        (void) iovw_put_string_field(&context->iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);

        /* Now that we have parsed info from /proc/ ensure the pidfd is still valid before continuing. */
        r = pidref_verify(&context->pidref);
        if (r < 0)
                return log_error_errno(r, "PIDFD validation failed: %m");

        return 0;
}

static void coredump_context_check_pidns(CoredumpContext *context) {
        int r;

        assert(context);
        assert(pidref_is_set(&context->pidref));

        r = pidref_in_same_namespace(/* pid1= */ NULL, &context->pidref, NAMESPACE_PID);
        if (r < 0)
                log_debug_errno(r, "Failed to check pidns of crashing process, ignoring: %m");

        context->same_pidns = r != 0;
}

static int coredump_context_parse_from_procfs(CoredumpContext *context) {
        int r;

        assert(context);
        assert(pidref_is_set(&context->pidref));

        pid_t pid = context->pidref.pid;

        r = pidref_get_comm(&context->pidref, &context->comm);
        if (r < 0)
                return log_error_errno(r, "Failed to get COMM: %m");

        r = get_process_exe(pid, &context->exe);
        if (r < 0)
                log_warning_errno(r, "Failed to get EXE, ignoring: %m");

        r = cg_pidref_get_unit(&context->pidref, &context->unit);
        if (r < 0)
                log_warning_errno(r, "Failed to get unit, ignoring: %m");

        r = read_full_file(procfs_file_alloca(pid, "auxv"), &context->auxv, &context->auxv_size);
        if (r < 0)
                log_warning_errno(r, "Failed to get auxv, ignoring: %m");

        r = pidref_verify(&context->pidref);
        if (r < 0)
                return log_error_errno(r, "PIDFD validation failed: %m");

        return 0;
}

static int context_parse_one(CoredumpContext *context, MetadataField meta, bool from_argv, const char *s, size_t size) {
        int r;

        assert(context);
        assert(s);

        switch (meta) {
        case META_ARGV_PID: {
                /* Store this so that we can check whether the core will be forwarded to a container
                 * even when the kernel doesn't provide a pidfd. Can be dropped once baseline is
                 * >= v6.16. */
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = pidref_set_pidstr(&pidref, s);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize pidref from pid %s: %m", s);

                if (pidref_is_set(&context->pidref)) {
                        if (!pidref_equal(&context->pidref, &pidref))
                                return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "Received conflicting pid: %s", s);
                } else
                        context->pidref = TAKE_PIDREF(pidref);
                return 0;
        }
        case META_ARGV_UID:
                r = parse_uid(s, &context->uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse UID \"%s\": %m", s);
                return 0;

        case META_ARGV_GID:
                r = parse_gid(s, &context->gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse GID \"%s\": %m", s);
                return 0;

        case META_ARGV_SIGNAL:
                r = parse_signo(s, &context->signo);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse signal number \"%s\", ignoring: %m", s);
                return 0;

        case META_ARGV_TIMESTAMP:
                /* The kernel provides 1 sec granularity timestamps, while we forward it with 1 μsec granularity. */
                r = parse_time(s, &context->timestamp, from_argv ? USEC_PER_SEC : 1);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse timestamp \"%s\", ignoring: %m", s);
                return 0;

        case META_ARGV_RLIMIT:
                r = safe_atou64(s, &context->rlimit);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse resource limit \"%s\", ignoring: %m", s);
                return 0;

        case META_ARGV_HOSTNAME:
                if (!hostname_is_valid(s, /* flags= */ 0)) {
                        log_warning("Received coredump with an invalid hostname, ignoring: %s", s);
                        return 0;
                }

                return free_and_strdup_warn(&context->hostname, s);

        case META_ARGV_DUMPABLE:
                /* The value is set to contents of /proc/sys/fs/suid_dumpable, which we set to SUID_DUMP_SAFE (2),
                 * if the process is marked as not dumpable, see PR_SET_DUMPABLE(2const). */
                r = safe_atou(s, &context->dumpable);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse dumpable field \"%s\": %m", s);
                if (context->dumpable > SUID_DUMP_SAFE)
                        log_notice("Got unexpected %%d/dumpable value %u.", context->dumpable);
                return 0;

        case META_ARGV_PIDFD: {
                /* We do not forward the index of the file descriptor, as it is meaningless, and always set to 1. */
                if (!from_argv) {
                        if (!streq(s, "1"))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received unexpected pidfd field: %s", s);
                        if (!pidref_is_set(&context->pidref) || !context->got_pidfd)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received unexpected pidfd field without pidfd.");
                        return 0;
                }

                /* If the current kernel doesn't support the %F specifier (which resolves to a pidfd), but we
                 * included it in the core_pattern expression, we'll receive an empty string here. Deal with
                 * that gracefully. */
                if (isempty(s))
                        return 0;

                r = parse_fd(s);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse pidfd \"%s\": %m", s);

                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = pidref_set_pidfd_consume(&pidref, r);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize pidref from pidfd \"%s\": %m", s);

                if (pidref_is_set(&context->pidref) && !pidref_equal(&context->pidref, &pidref))
                        return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "Received conflicting pidfd: %s", s);

                /* pidref by pidfd has higher preference over one by pid. */
                pidref_done(&context->pidref);
                context->pidref = TAKE_PIDREF(pidref);

                context->got_pidfd = 1;
                return 0;
        }
        case META_COMM:
                return free_and_strdup_warn(&context->comm, s);

        case META_EXE:
                return free_and_strdup_warn(&context->exe, s);

        case META_UNIT:
                return free_and_strdup_warn(&context->unit, s);

        case META_PROC_AUXV: {
                char *t = memdup_suffix0(s, size);
                if (!t)
                        return log_oom();

                context->auxv_size = size;
                return free_and_replace(context->auxv, t);
        }

        default:
                assert_not_reached();
        }
}

int coredump_context_parse_iovw(CoredumpContext *context) {
        int r;

        assert(context);

        /* Parse the data in the iovec array iovw into separate fields. */

        bool have[_META_MAX] = {};
        FOREACH_ARRAY(iovec, context->iovw.iovec, context->iovw.count) {
                /* Note that these strings are NUL-terminated, because we made sure that a trailing NUL byte
                 * is in the buffer, though not included in the iov_len count. See coredump_receive() and
                 * coredump_context_parse_from_*(). */
                assert(((char*) iovec->iov_base)[iovec->iov_len] == 0);

                for (MetadataField i = 0; i < _META_MAX; i++) {
                        const char *s = metadata_field_to_string(i);
                        const char *p = memory_startswith(iovec->iov_base, iovec->iov_len, s);
                        if (!p)
                                continue;

                        size_t size = iovec->iov_len - strlen(s);
                        if (i != META_PROC_AUXV && strlen(p) != size)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "%s= field contains NUL character.", s);

                        if (have[i])
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Message contains duplicated field: %s", s);

                        have[i] = true;

                        r = context_parse_one(context, i, /* from_argv= */ false, p, size);
                        if (r < 0)
                                return r;

                        break;
                }
        }

        /* Make sure we received all the expected fields. We support being called by an *older* systemd-coredump
         * from the outside, so we require only the basic set of fields that was being sent when the support for
         * sending to containers over a socket was added in a108c43e36d3ceb6e34efe37c014fc2cda856000. */
        MetadataField i;
        FOREACH_ARGUMENT(i,
                         META_ARGV_PID,
                         META_ARGV_UID,
                         META_ARGV_GID,
                         META_ARGV_SIGNAL,
                         META_ARGV_TIMESTAMP,
                         META_ARGV_RLIMIT,
                         META_ARGV_HOSTNAME,
                         META_COMM)
                if (!have[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Mandatory argument %s not received on socket.",
                                               metadata_field_to_string(i));

        coredump_context_check_pidns(context);
        return 0;
}

int coredump_context_parse_from_argv(CoredumpContext *context, int argc, char **argv) {
        int r;

        assert(context);

        /* We gather all metadata that were passed via argv[] into an array of iovecs that
         * we'll forward to the socket unit.
         *
         * We require at least _META_ARGV_REQUIRED args, but will accept more.
         * We know how to parse _META_ARGV_MAX args. The rest will be ignored. */

        if (argc < _META_ARGV_REQUIRED)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough arguments passed by the kernel (%i, expected between %i and %i).",
                                       argc, _META_ARGV_REQUIRED, _META_ARGV_MAX);

        for (MetadataField i = 0; i < MIN(argc, _META_ARGV_MAX); i++) {
                r = context_parse_one(context, i, /* from_argv= */ true, argv[i], SIZE_MAX);
                if (r < 0)
                        return r;
        }

        coredump_context_check_pidns(context);
        return coredump_context_parse_from_procfs(context);
}
