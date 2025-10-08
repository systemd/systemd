/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-login.h"

#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "memstream-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "special.h"
#include "string-util.h"
#include "user-util.h"

const char * const meta_field_names[_META_MAX] = {
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

void context_done(Context *c) {
        assert(c);

        pidref_done(&c->pidref);
        c->mount_tree_fd = safe_close(c->mount_tree_fd);
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

int gather_pid_metadata_from_procfs(struct iovec_wrapper *iovw, Context *context) {
        char *t;
        size_t size;
        int r;

        assert(iovw);
        assert(context);

        /* Note that if we fail on oom later on, we do not roll-back changes to the iovec
         * structure. (It remains valid, with the first iovec fields initialized.) */

        pid_t pid = context->pidref.pid;

        /* The following is mandatory */
        r = pidref_get_comm(&context->pidref, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to get COMM: %m");

        r = iovw_put_string_field_free(iovw, "COREDUMP_COMM=", t);
        if (r < 0)
                return r;

        /* The following are optional, but we use them if present. */
        r = get_process_exe(pid, &t);
        if (r >= 0)
                r = iovw_put_string_field_free(iovw, "COREDUMP_EXE=", t);
        if (r < 0)
                log_warning_errno(r, "Failed to get EXE, ignoring: %m");

        if (cg_pidref_get_unit(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_UNIT=", t);

        if (cg_pidref_get_user_unit(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_USER_UNIT=", t);

        if (cg_pidref_get_session(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SESSION=", t);

        uid_t owner_uid;
        if (cg_pidref_get_owner_uid(&context->pidref, &owner_uid) >= 0) {
                r = asprintf(&t, UID_FMT, owner_uid);
                if (r > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_OWNER_UID=", t);
        }

        if (sd_pid_get_slice(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SLICE=", t);

        if (pidref_get_cmdline(&context->pidref, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CMDLINE=", t);

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CGROUP=", t);

        if (compose_open_fds(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_OPEN_FDS=", t);

        if (read_full_file(procfs_file_alloca(pid, "status"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_STATUS=", t);

        if (read_full_file(procfs_file_alloca(pid, "maps"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MAPS=", t);

        if (read_full_file(procfs_file_alloca(pid, "limits"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_LIMITS=", t);

        if (read_full_file(procfs_file_alloca(pid, "cgroup"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_CGROUP=", t);

        if (read_full_file(procfs_file_alloca(pid, "mountinfo"), &t, /* ret_size= */ NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MOUNTINFO=", t);

        /* We attach /proc/auxv here. ELF coredumps also contain a note for this (NT_AUXV), see elf(5). */
        if (read_full_file(procfs_file_alloca(pid, "auxv"), &t, &size) >= 0) {
                char *buf = malloc(strlen("COREDUMP_PROC_AUXV=") + size + 1);
                if (buf) {
                        /* Add a dummy terminator to make context_parse_iovw() happy. */
                        *mempcpy_typesafe(stpcpy(buf, "COREDUMP_PROC_AUXV="), t, size) = '\0';
                        (void) iovw_consume(iovw, buf, size + strlen("COREDUMP_PROC_AUXV="));
                }

                free(t);
        }

        if (get_process_cwd(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CWD=", t);

        if (get_process_root(pid, &t) >= 0) {
                bool proc_self_root_is_slash;

                proc_self_root_is_slash = strcmp(t, "/") == 0;

                (void) iovw_put_string_field_free(iovw, "COREDUMP_ROOT=", t);

                /* If the process' root is "/", then there is a chance it has
                 * mounted own root and hence being containerized. */
                if (proc_self_root_is_slash && get_process_container_parent_cmdline(&context->pidref, &t) > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_CONTAINER_CMDLINE=", t);
        }

        if (get_process_environ(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_ENVIRON=", t);

        /* Now that we have parsed info from /proc/ ensure the pidfd is still valid before continuing. */
        r = pidref_verify(&context->pidref);
        if (r < 0)
                return log_error_errno(r, "PIDFD validation failed: %m");

        /* We successfully acquired all metadata. */
        return context_parse_iovw(context, iovw);
}

int context_parse_iovw(Context *context, struct iovec_wrapper *iovw) {
        const char *unit;
        int r;

        assert(context);
        assert(iovw);

        /* Converts the data in the iovec array iovw into separate fields. Fills in context->meta[] (for
         * which no memory is allocated, it just contains direct pointers into the iovec array memory). */

        bool have_signal_name = false;
        FOREACH_ARRAY(iovec, iovw->iovec, iovw->count) {
                /* Note that these strings are NUL-terminated, because we made sure that a trailing NUL byte
                 * is in the buffer, though not included in the iov_len count. See coredump_receive() and
                 * gather_pid_metadata_*(). */
                assert(((char*) iovec->iov_base)[iovec->iov_len] == 0);

                for (size_t i = 0; i < ELEMENTSOF(meta_field_names); i++) {
                        const char *p = memory_startswith(iovec->iov_base, iovec->iov_len, meta_field_names[i]);
                        if (p) {
                                context->meta[i] = p;
                                context->meta_size[i] = iovec->iov_len - strlen(meta_field_names[i]);
                                break;
                        }
                }

                have_signal_name = have_signal_name ||
                        memory_startswith(iovec->iov_base, iovec->iov_len, "COREDUMP_SIGNAL_NAME=");
        }

        /* The basic fields from argv[] should always be there, refuse early if not. */
        for (int i = 0; i < _META_ARGV_REQUIRED; i++)
                if (!context->meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "A required (%s) has not been sent, aborting.", meta_field_names[i]);

        pid_t parsed_pid;
        r = parse_pid(context->meta[META_ARGV_PID], &parsed_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PID \"%s\": %m", context->meta[META_ARGV_PID]);
        if (pidref_is_set(&context->pidref)) {
                if (context->pidref.pid != parsed_pid)
                        return log_error_errno(r, "Passed PID " PID_FMT " does not match passed " PID_FMT ": %m",
                                               parsed_pid, context->pidref.pid);
        } else {
                r = pidref_set_pid(&context->pidref, parsed_pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize pidref from pid " PID_FMT ": %m", parsed_pid);
        }

        r = parse_uid(context->meta[META_ARGV_UID], &context->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID \"%s\": %m", context->meta[META_ARGV_UID]);

        r = parse_gid(context->meta[META_ARGV_GID], &context->gid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse GID \"%s\": %m", context->meta[META_ARGV_GID]);

        r = parse_signo(context->meta[META_ARGV_SIGNAL], &context->signo);
        if (r < 0)
                log_warning_errno(r, "Failed to parse signal number \"%s\", ignoring: %m", context->meta[META_ARGV_SIGNAL]);

        r = safe_atou64(context->meta[META_ARGV_RLIMIT], &context->rlimit);
        if (r < 0)
                log_warning_errno(r, "Failed to parse resource limit \"%s\", ignoring: %m", context->meta[META_ARGV_RLIMIT]);

        /* The value is set to contents of /proc/sys/fs/suid_dumpable, which we set to SUID_DUMP_SAFE (2),
         * if the process is marked as not dumpable, see PR_SET_DUMPABLE(2const). */
        if (context->meta[META_ARGV_DUMPABLE]) {
                r = safe_atou(context->meta[META_ARGV_DUMPABLE], &context->dumpable);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse dumpable field \"%s\": %m", context->meta[META_ARGV_DUMPABLE]);
                if (context->dumpable > SUID_DUMP_SAFE)
                        log_notice("Got unexpected %%d/dumpable value %u.", context->dumpable);
        }

        unit = context->meta[META_UNIT];
        context->is_pid1 = streq(context->meta[META_ARGV_PID], "1") || streq_ptr(unit, SPECIAL_INIT_SCOPE);
        context->is_journald = streq_ptr(unit, SPECIAL_JOURNALD_SERVICE);

        /* After parsing everything, let's also synthesize a new iovw field for the textual signal name if it
         * isn't already set. */
        if (SIGNAL_VALID(context->signo) && !have_signal_name)
                (void) iovw_put_string_field(iovw, "COREDUMP_SIGNAL_NAME=SIG", signal_to_string(context->signo));

        return 0;
}

int gather_pid_metadata_from_argv(
                struct iovec_wrapper *iovw,
                Context *context,
                int argc, char **argv) {

        _cleanup_(pidref_done) PidRef local_pidref = PIDREF_NULL;
        int r, kernel_fd = -EBADF;

        assert(iovw);
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

        for (int i = 0; i < MIN(argc, _META_ARGV_MAX); i++) {
                _cleanup_free_ char *buf = NULL;
                const char *t = argv[i];

                if (i == META_ARGV_TIMESTAMP) {
                        /* The journal fields contain the timestamp padded with six
                         * zeroes, so that the kernel-supplied 1s granularity timestamps
                         * becomes 1μs granularity, i.e. the granularity systemd usually
                         * operates in. */
                        buf = strjoin(argv[i], "000000");
                        if (!buf)
                                return log_oom();

                        t = buf;
                }

                if (i == META_ARGV_PID) {
                        /* Store this so that we can check whether the core will be forwarded to a container
                         * even when the kernel doesn't provide a pidfd. Can be dropped once baseline is
                         * >= v6.16. */
                        r = pidref_set_pidstr(&local_pidref, t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to initialize pidref from pid %s: %m", t);
                }

                if (i == META_ARGV_PIDFD) {
                        /* If the current kernel doesn't support the %F specifier (which resolves to a
                         * pidfd), but we included it in the core_pattern expression, we'll receive an empty
                         * string here. Deal with that gracefully. */
                        if (isempty(t))
                                continue;

                        assert(!pidref_is_set(&context->pidref));
                        assert(kernel_fd < 0);

                        kernel_fd = parse_fd(t);
                        if (kernel_fd < 0)
                                return log_error_errno(kernel_fd, "Failed to parse pidfd \"%s\": %m", t);

                        r = pidref_set_pidfd(&context->pidref, kernel_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to initialize pidref from pidfd %d: %m", kernel_fd);

                        context->got_pidfd = 1;

                        /* If there are containers involved with different versions of the code they might
                         * not be using pidfds, so it would be wrong to set the metadata, skip it. */
                        r = pidref_in_same_namespace(/* pid1 = */ NULL, &context->pidref, NAMESPACE_PID);
                        if (r < 0)
                                log_debug_errno(r, "Failed to check pidns of crashing process, ignoring: %m");
                        if (r <= 0)
                                continue;

                        /* We don't print the fd number in the journal as it's meaningless, but we still
                         * record that the parsing was done with a kernel-provided fd as it means it's safe
                         * from races, which is valuable information to provide in the journal record. */
                        t = "1";
                }

                r = iovw_put_string_field(iovw, meta_field_names[i], t);
                if (r < 0)
                        return r;
        }

        /* Cache some of the process metadata we collected so far and that we'll need to
         * access soon. */
        r = context_parse_iovw(context, iovw);
        if (r < 0)
                return r;

        /* If the kernel didn't give us a PIDFD, then use the one derived from the
         * PID immediately, given we have it. */
        if (!pidref_is_set(&context->pidref))
                context->pidref = TAKE_PIDREF(local_pidref);

        /* Close the kernel-provided FD as the last thing after everything else succeeded. */
        kernel_fd = safe_close(kernel_fd);

        return 0;
}
