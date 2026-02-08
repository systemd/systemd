/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/ioprio.h>
#include <sys/keyctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "sd-messages.h"

#include "apparmor-util.h"      /* IWYU pragma: keep */
#include "argv-util.h"
#include "ask-password-api.h"
#include "barrier.h"
#include "bitfield.h"
#include "bpf-dlopen.h"
#include "bpf-restrict-fs.h"
#include "btrfs-util.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "cgroup.h"
#include "chase.h"
#include "chattr-util.h"
#include "chown-recursive.h"
#include "constants.h"
#include "copy.h"
#include "coredump-util.h"
#include "cryptsetup-util.h"
#include "dissect-image.h"
#include "dynamic-user.h"
#include "env-util.h"
#include "escape.h"
#include "exec-credential.h"
#include "exec-invoke.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "image-policy.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-send.h"
#include "libmount-util.h"
#include "manager.h"
#include "memfd-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "nsflags.h"
#include "open-file.h"
#include "osc-context.h"
#include "pam-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "psi-util.h"
#include "quota-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "selinux-util.h"
#include "set.h"
#include "signal-util.h"
#include "siphash24.h"
#include "smack-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utmp-wtmp.h"
#include "vpick.h"

#define IDLE_TIMEOUT_USEC (5*USEC_PER_SEC)
#define IDLE_TIMEOUT2_USEC (1*USEC_PER_SEC)

#define SNDBUF_SIZE (8*1024*1024)

/* Project id range for disk quotas */
#define PROJ_ID_MIN UINT32_C(2147483648)
#define PROJ_ID_MAX UINT32_C(4294967294)
#define PROJ_ID_CLAMP_INTO_QUOTA_RANGE(id) ((uint32_t) ((id) % (PROJ_ID_MAX - PROJ_ID_MIN + 1)) + PROJ_ID_MIN)

static int flag_fds(
                const int fds[],
                size_t n_socket_fds,
                size_t n_fds,
                bool nonblock) {

        int r;

        assert(fds || n_fds == 0);

        /* Drops/Sets O_NONBLOCK and FD_CLOEXEC from the file flags.
         * O_NONBLOCK only applies to socket activation though. */

        for (size_t i = 0; i < n_fds; i++) {

                if (i < n_socket_fds) {
                        r = fd_nonblock(fds[i], nonblock);
                        if (r < 0)
                                return r;
                }

                /* We unconditionally drop FD_CLOEXEC from the fds,
                 * since after all we want to pass these fds to our
                 * children */

                r = fd_cloexec(fds[i], false);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int open_null_as(int flags, int nfd) {
        int fd;

        assert(nfd >= 0);

        fd = open("/dev/null", flags|O_NOCTTY);
        if (fd < 0)
                return -errno;

        return move_fd(fd, nfd, false);
}

static int connect_journal_socket(
                int fd,
                const char *log_namespace,
                uid_t uid,
                gid_t gid) {

        uid_t olduid = UID_INVALID;
        gid_t oldgid = GID_INVALID;
        const char *j;
        int r;

        assert(fd >= 0);

        j = journal_stream_path(log_namespace);
        if (!j)
                return -EINVAL;

        if (gid_is_valid(gid)) {
                oldgid = getgid();

                if (setegid(gid) < 0)
                        return -errno;
        }

        if (uid_is_valid(uid)) {
                olduid = getuid();

                if (seteuid(uid) < 0) {
                        r = -errno;
                        goto restore_gid;
                }
        }

        r = connect_unix_path(fd, AT_FDCWD, j);

        /* If we fail to restore the uid or gid, things will likely fail later on. This should only happen if
           an LSM interferes. */

        if (uid_is_valid(uid))
                (void) seteuid(olduid);

 restore_gid:
        if (gid_is_valid(gid))
                (void) setegid(oldgid);

        return r;
}

static bool exec_output_forward_to_console(ExecOutput o) {
        return IN_SET(o,
                      EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
                      EXEC_OUTPUT_KMSG_AND_CONSOLE);
}

static bool exec_output_forward_to_kmsg(ExecOutput o) {
        return IN_SET(o,
                      EXEC_OUTPUT_KMSG,
                      EXEC_OUTPUT_KMSG_AND_CONSOLE);
}

static int connect_logger_as(
                const ExecContext *context,
                const ExecParameters *params,
                ExecOutput output,
                const char *ident,
                int nfd,
                uid_t uid,
                gid_t gid) {

        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(context);
        assert(params);
        assert(output < _EXEC_OUTPUT_MAX);
        assert(ident);
        assert(nfd >= 0);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return -errno;

        r = connect_journal_socket(fd, context->log_namespace, uid, gid);
        if (r < 0)
                return r;

        if (shutdown(fd, SHUT_RD) < 0)
                return -errno;

        (void) fd_inc_sndbuf(fd, SNDBUF_SIZE);

        if (dprintf(fd,
                    "%s\n"
                    "%s\n"
                    "%i\n"
                    "%i\n"
                    "%i\n"
                    "%i\n"
                    "%i\n",
                    context->syslog_identifier ?: ident,
                    params->flags & EXEC_PASS_LOG_UNIT ? params->unit_id : "",
                    context->syslog_priority,
                    !!context->syslog_level_prefix,
                    false,
                    exec_output_forward_to_kmsg(output),
                    exec_output_forward_to_console(output)) < 0)
                return -errno;

        return move_fd(TAKE_FD(fd), nfd, false);
}

static int open_terminal_as(const char *path, int flags, int nfd) {
        int fd;

        assert(path);
        assert(nfd >= 0);

        fd = open_terminal(path, flags | O_NOCTTY);
        if (fd < 0)
                return fd;

        return move_fd(fd, nfd, false);
}

static int acquire_path(const char *path, int flags, mode_t mode) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(path);

        if (IN_SET(flags & O_ACCMODE_STRICT, O_WRONLY, O_RDWR))
                flags |= O_CREAT;

        fd = open(path, flags|O_NOCTTY, mode);
        if (fd >= 0)
                return TAKE_FD(fd);

        if (errno != ENXIO) /* ENXIO is returned when we try to open() an AF_UNIX file system socket on Linux */
                return -errno;

        /* So, it appears the specified path could be an AF_UNIX socket. Let's see if we can connect to it. */

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return -errno;

        r = connect_unix_path(fd, AT_FDCWD, path);
        if (IN_SET(r, -ENOTSOCK, -EINVAL))
                /* Propagate initial error if we get ENOTSOCK or EINVAL, i.e. we have indication that this
                 * wasn't an AF_UNIX socket after all */
                return -ENXIO;
        if (r < 0)
                return r;

        if ((flags & O_ACCMODE_STRICT) == O_RDONLY)
                r = shutdown(fd, SHUT_WR);
        else if ((flags & O_ACCMODE_STRICT) == O_WRONLY)
                r = shutdown(fd, SHUT_RD);
        else
                r = 0;
        if (r < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int fixup_input(
                const ExecContext *context,
                bool apply_tty_stdin) {

        ExecInput std_input;

        assert(context);

        std_input = context->std_input;

        if (exec_input_is_terminal(std_input) && !apply_tty_stdin)
                return EXEC_INPUT_NULL;

        if (std_input == EXEC_INPUT_DATA && context->stdin_data_size == 0)
                return EXEC_INPUT_NULL;

        return std_input;
}

static int setup_input(
                const ExecContext *context,
                const ExecParameters *params,
                int socket_fd,
                const int named_iofds[static 3]) {

        ExecInput i;
        int r;

        assert(context);
        assert(params);
        assert(named_iofds);

        if (params->stdin_fd >= 0) {
                if (dup2(params->stdin_fd, STDIN_FILENO) < 0)
                        return -errno;

                /* Try to make this our controlling tty, if it is a tty */
                if (isatty_safe(STDIN_FILENO) && ioctl(STDIN_FILENO, TIOCSCTTY, context->std_input == EXEC_INPUT_TTY_FORCE) < 0)
                        log_debug_errno(errno, "Failed to make standard input TTY our controlling terminal: %m");

                return STDIN_FILENO;
        }

        i = fixup_input(context, params->flags & EXEC_APPLY_TTY_STDIN);

        switch (i) {

        case EXEC_INPUT_NULL:
                return open_null_as(O_RDONLY, STDIN_FILENO);

        case EXEC_INPUT_TTY:
        case EXEC_INPUT_TTY_FORCE:
        case EXEC_INPUT_TTY_FAIL: {
                _cleanup_close_ int tty_fd = -EBADF;
                _cleanup_free_ char *resolved = NULL;
                const char *tty_path;

                tty_path = ASSERT_PTR(exec_context_tty_path(context));

                if (tty_is_console(tty_path)) {
                        r = resolve_dev_console(&resolved);
                        if (r < 0)
                                log_debug_errno(r, "Failed to resolve /dev/console, ignoring: %m");
                        else {
                                log_debug("Resolved /dev/console to %s", resolved);
                                tty_path = resolved;
                        }
                }

                tty_fd = acquire_terminal(tty_path,
                                          i == EXEC_INPUT_TTY_FAIL  ? ACQUIRE_TERMINAL_TRY :
                                          i == EXEC_INPUT_TTY_FORCE ? ACQUIRE_TERMINAL_FORCE :
                                                                      ACQUIRE_TERMINAL_WAIT,
                                          USEC_INFINITY);
                if (tty_fd < 0)
                        return tty_fd;

                r = move_fd(tty_fd, STDIN_FILENO, /* cloexec= */ false);
                if (r < 0)
                        return r;

                TAKE_FD(tty_fd);
                return r;
        }

        case EXEC_INPUT_SOCKET:
                assert(socket_fd >= 0);

                return RET_NERRNO(dup2(socket_fd, STDIN_FILENO));

        case EXEC_INPUT_NAMED_FD:
                assert(named_iofds[STDIN_FILENO] >= 0);

                (void) fd_nonblock(named_iofds[STDIN_FILENO], false);
                return RET_NERRNO(dup2(named_iofds[STDIN_FILENO], STDIN_FILENO));

        case EXEC_INPUT_DATA: {
                int fd;

                fd = memfd_new_and_seal("exec-input", context->stdin_data, context->stdin_data_size);
                if (fd < 0)
                        return fd;

                return move_fd(fd, STDIN_FILENO, false);
        }

        case EXEC_INPUT_FILE: {
                bool rw;
                int fd;

                assert(context->stdio_file[STDIN_FILENO]);

                rw = (context->std_output == EXEC_OUTPUT_FILE && path_equal(context->stdio_file[STDIN_FILENO], context->stdio_file[STDOUT_FILENO])) ||
                        (context->std_error == EXEC_OUTPUT_FILE && path_equal(context->stdio_file[STDIN_FILENO], context->stdio_file[STDERR_FILENO]));

                fd = acquire_path(context->stdio_file[STDIN_FILENO], rw ? O_RDWR : O_RDONLY, 0666 & ~context->umask);
                if (fd < 0)
                        return fd;

                return move_fd(fd, STDIN_FILENO, false);
        }

        default:
                assert_not_reached();
        }
}

static bool can_inherit_stderr_from_stdout(const ExecContext *context) {
        ExecOutput o, e;

        assert(context);

        /* Returns true, if given the specified STDERR and STDOUT output we can directly dup() the stdout fd to the
         * stderr fd */

        o = context->std_output;
        e = context->std_error;

        if (e == EXEC_OUTPUT_INHERIT)
                return true;
        if (e != o)
                return false;

        /* Let's not shortcut named fds here, even though we in theory can by comparing fd names, since
         * we have the named_iofds array readily available, and the inherit practice would simply be duplicative. */
        if (e == EXEC_OUTPUT_NAMED_FD)
                return false;

        if (IN_SET(e, EXEC_OUTPUT_FILE, EXEC_OUTPUT_FILE_APPEND, EXEC_OUTPUT_FILE_TRUNCATE))
                return path_equal(context->stdio_file[STDOUT_FILENO], context->stdio_file[STDERR_FILENO]);

        return true;
}

static int maybe_inherit_stdout_from_stdin(const ExecContext *context, ExecInput i) {
        int r;

        assert(context);

        if (context->std_output != EXEC_OUTPUT_INHERIT)
                return 0;

        /* If input got downgraded, inherit the original value */
        if (i == EXEC_INPUT_NULL && exec_input_is_terminal(context->std_input))
                return open_terminal_as(exec_context_tty_path(context), O_WRONLY, STDOUT_FILENO);

        if (!exec_input_is_inheritable(i))
                goto fallback;

        r = fd_is_writable(STDIN_FILENO);
        if (r <= 0) {
                if (r < 0)
                        log_warning_errno(r, "Failed to check if inherited stdin is writable for stdout, using fallback: %m");
                else
                        log_warning("Inherited stdin is not writable for stdout, using fallback: %m");
                goto fallback;
        }

        return RET_NERRNO(dup2(STDIN_FILENO, STDOUT_FILENO));

fallback:
        /* If we are not started from PID 1 we just inherit STDOUT from our parent process. */
        if (getppid() != 1)
                return STDOUT_FILENO;

        /* We need to open /dev/null here anew, to get the right access mode. */
        return open_null_as(O_WRONLY, STDOUT_FILENO);
}

static int setup_output(
                const ExecContext *context,
                const ExecParameters *params,
                int fileno,
                int socket_fd,
                const int named_iofds[static 3],
                const char *ident,
                uid_t uid,
                gid_t gid,
                dev_t *journal_stream_dev,
                ino_t *journal_stream_ino) {

        ExecOutput o;
        ExecInput i;
        int r;

        assert(context);
        assert(params);
        assert(ident);
        assert(journal_stream_dev);
        assert(journal_stream_ino);

        if (fileno == STDOUT_FILENO && params->stdout_fd >= 0) {

                if (dup2(params->stdout_fd, STDOUT_FILENO) < 0)
                        return -errno;

                return STDOUT_FILENO;
        }

        if (fileno == STDERR_FILENO && params->stderr_fd >= 0) {
                if (dup2(params->stderr_fd, STDERR_FILENO) < 0)
                        return -errno;

                return STDERR_FILENO;
        }

        i = fixup_input(context, params->flags & EXEC_APPLY_TTY_STDIN);

        if (fileno == STDERR_FILENO) {
                /* This expects the input and output are already set up */

                /* Don't change the stderr file descriptor if we inherit all
                 * the way and are not on a tty */
                if (context->std_error == EXEC_OUTPUT_INHERIT &&
                    context->std_output == EXEC_OUTPUT_INHERIT &&
                    i == EXEC_INPUT_NULL && !exec_input_is_terminal(context->std_input) &&
                    getppid() != 1)
                        return fileno;

                /* Duplicate from stdout if possible */
                if (can_inherit_stderr_from_stdout(context))
                        return RET_NERRNO(dup2(STDOUT_FILENO, fileno));

                o = context->std_error;

        } else {
                assert(fileno == STDOUT_FILENO);

                r = maybe_inherit_stdout_from_stdin(context, i);
                if (r != 0)
                        return r;

                o = context->std_output;
        }

        switch (o) {

        case EXEC_OUTPUT_NULL:
                return open_null_as(O_WRONLY, fileno);

        case EXEC_OUTPUT_TTY:
                if (exec_input_is_terminal(i)) {
                        r = fd_is_writable(STDIN_FILENO);
                        if (r <= 0) {
                                if (r < 0)
                                        log_warning_errno(r, "Failed to check if inherited stdin is writable for TTY's %s, falling back to opening terminal.",
                                                          fileno == STDOUT_FILENO ? "stdout" : "stderr");
                                else
                                        log_warning("Inherited stdin is not writable for TTY's %s, falling back to opening terminal.",
                                                    fileno == STDOUT_FILENO ? "stdout" : "stderr");
                                return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);
                        }
                        return RET_NERRNO(dup2(STDIN_FILENO, fileno));
                }

                return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);

        case EXEC_OUTPUT_KMSG:
        case EXEC_OUTPUT_KMSG_AND_CONSOLE:
        case EXEC_OUTPUT_JOURNAL:
        case EXEC_OUTPUT_JOURNAL_AND_CONSOLE:
                r = connect_logger_as(context, params, o, ident, fileno, uid, gid);
                if (r < 0) {
                        log_warning_errno(r, "Failed to connect %s to the journal socket, ignoring: %m",
                                          fileno == STDOUT_FILENO ? "stdout" : "stderr");
                        r = open_null_as(O_WRONLY, fileno);
                } else {
                        struct stat st;

                        /* If we connected this fd to the journal via a stream, patch the device/inode into the passed
                         * parameters, but only then. This is useful so that we can set $JOURNAL_STREAM that permits
                         * services to detect whether they are connected to the journal or not.
                         *
                         * If both stdout and stderr are connected to a stream then let's make sure to store the data
                         * about STDERR as that's usually the best way to do logging. */

                        if (fstat(fileno, &st) >= 0 &&
                            (*journal_stream_ino == 0 || fileno == STDERR_FILENO)) {
                                *journal_stream_dev = st.st_dev;
                                *journal_stream_ino = st.st_ino;
                        }
                }
                return r;

        case EXEC_OUTPUT_SOCKET:
                assert(socket_fd >= 0);

                return RET_NERRNO(dup2(socket_fd, fileno));

        case EXEC_OUTPUT_NAMED_FD:
                assert(named_iofds[fileno] >= 0);

                (void) fd_nonblock(named_iofds[fileno], false);
                return RET_NERRNO(dup2(named_iofds[fileno], fileno));

        case EXEC_OUTPUT_FILE:
        case EXEC_OUTPUT_FILE_APPEND:
        case EXEC_OUTPUT_FILE_TRUNCATE: {
                int fd, flags;

                assert(context->stdio_file[fileno]);

                /* stdin points to the same file hence setup_input() opened it as rw already?
                 * Then just duplicate it. */
                if (context->std_input == EXEC_INPUT_FILE &&
                    path_equal(context->stdio_file[fileno], context->stdio_file[STDIN_FILENO]))
                        return RET_NERRNO(dup2(STDIN_FILENO, fileno));

                flags = O_WRONLY;
                if (o == EXEC_OUTPUT_FILE_APPEND)
                        flags |= O_APPEND;
                else if (o == EXEC_OUTPUT_FILE_TRUNCATE)
                        flags |= O_TRUNC;

                fd = acquire_path(context->stdio_file[fileno], flags, 0666 & ~context->umask);
                if (fd < 0)
                        return fd;

                return move_fd(fd, fileno, 0);
        }

        default:
                assert_not_reached();
        }
}

static int chown_terminal(int fd, uid_t uid) {
        int r;

        assert(fd >= 0);

        /* Before we chown/chmod the TTY, let's ensure this is actually a tty */
        if (!isatty_safe(fd))
                return 0;

        /* This might fail. What matters are the results. */
        r = fchmod_and_chown(fd, TTY_MODE, uid, GID_INVALID);
        if (r < 0)
                return r;

        return 1;
}

static int setup_confirm_stdio(
                const ExecContext *context,
                const char *vc,
                int *ret_saved_stdin,
                int *ret_saved_stdout) {

        _cleanup_close_ int fd = -EBADF, saved_stdin = -EBADF, saved_stdout = -EBADF;
        int r;

        assert(context);
        assert(ret_saved_stdin);
        assert(ret_saved_stdout);

        saved_stdin = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
        if (saved_stdin < 0)
                return -errno;

        saved_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        if (saved_stdout < 0)
                return -errno;

        fd = acquire_terminal(vc, ACQUIRE_TERMINAL_WAIT, DEFAULT_CONFIRM_USEC);
        if (fd < 0)
                return fd;

        _cleanup_close_ int lock_fd = lock_dev_console();
        if (lock_fd < 0)
                log_debug_errno(lock_fd, "Failed to lock /dev/console, ignoring: %m");

        r = chown_terminal(fd, getuid());
        if (r < 0)
                return r;

        r = terminal_reset_defensive(fd, TERMINAL_RESET_SWITCH_TO_TEXT);
        if (r < 0)
                return r;

        r = exec_context_apply_tty_size(context, fd, fd, vc);
        if (r < 0)
                return r;

        r = rearrange_stdio(fd, fd, STDERR_FILENO); /* Invalidates 'fd' also on failure */
        TAKE_FD(fd);
        if (r < 0)
                return r;

        *ret_saved_stdin = TAKE_FD(saved_stdin);
        *ret_saved_stdout = TAKE_FD(saved_stdout);
        return 0;
}

static void write_confirm_error_fd(int err, int fd, const char *unit_id) {
        assert(err != 0);
        assert(fd >= 0);
        assert(unit_id);

        errno = abs(err);

        if (errno == ETIMEDOUT)
                dprintf(fd, "Confirmation question timed out for %s, assuming positive response.\n", unit_id);
        else
                dprintf(fd, "Couldn't ask confirmation for %s, assuming positive response: %m\n", unit_id);
}

static void write_confirm_error(int err, const char *vc, const char *unit_id) {
        _cleanup_close_ int fd = -EBADF;

        assert(vc);

        fd = open_terminal(vc, O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return;

        write_confirm_error_fd(err, fd, unit_id);
}

static int restore_confirm_stdio(int *saved_stdin, int *saved_stdout) {
        int r = 0;

        assert(saved_stdin);
        assert(saved_stdout);

        release_terminal();

        if (*saved_stdin >= 0)
                if (dup2(*saved_stdin, STDIN_FILENO) < 0)
                        r = -errno;

        if (*saved_stdout >= 0)
                if (dup2(*saved_stdout, STDOUT_FILENO) < 0)
                        r = -errno;

        *saved_stdin = safe_close(*saved_stdin);
        *saved_stdout = safe_close(*saved_stdout);

        return r;
}

enum {
        CONFIRM_PRETEND_FAILURE = -1,
        CONFIRM_PRETEND_SUCCESS =  0,
        CONFIRM_EXECUTE = 1,
};

static bool confirm_spawn_disabled(void) {
        return access("/run/systemd/confirm_spawn_disabled", F_OK) >= 0;
}

static int ask_for_confirmation(const ExecContext *context, const ExecParameters *params, const char *cmdline) {
        int saved_stdout = -EBADF, saved_stdin = -EBADF, r;
        _cleanup_free_ char *e = NULL;
        char c;

        assert(context);
        assert(params);

        /* For any internal errors, assume a positive response. */
        r = setup_confirm_stdio(context, params->confirm_spawn, &saved_stdin, &saved_stdout);
        if (r < 0) {
                write_confirm_error(r, params->confirm_spawn, params->unit_id);
                return CONFIRM_EXECUTE;
        }

        /* confirm_spawn might have been disabled while we were sleeping. */
        if (!params->confirm_spawn || confirm_spawn_disabled()) {
                r = 1;
                goto restore_stdio;
        }

        e = ellipsize(cmdline, 60, 100);
        if (!e) {
                log_oom();
                r = CONFIRM_EXECUTE;
                goto restore_stdio;
        }

        for (;;) {
                r = ask_char(&c, "yfshiDjcn", "Execute %s? [y, f, s – h for help] ", e);
                if (r < 0) {
                        write_confirm_error_fd(r, STDOUT_FILENO, params->unit_id);
                        r = CONFIRM_EXECUTE;
                        goto restore_stdio;
                }

                switch (c) {
                case 'c':
                        printf("Resuming normal execution.\n");
                        manager_disable_confirm_spawn();
                        r = 1;
                        break;
                case 'D':
                        printf("  Unit: %s\n",
                               params->unit_id);
                        exec_context_dump(context, stdout, "  ");
                        exec_params_dump(params, stdout, "  ");
                        continue; /* ask again */
                case 'f':
                        printf("Failing execution.\n");
                        r = CONFIRM_PRETEND_FAILURE;
                        break;
                case 'h':
                        printf("  c - continue, proceed without asking anymore\n"
                               "  D - dump, show the state of the unit\n"
                               "  f - fail, don't execute the command and pretend it failed\n"
                               "  h - help\n"
                               "  i - info, show a short summary of the unit\n"
                               "  j - jobs, show jobs that are in progress\n"
                               "  s - skip, don't execute the command and pretend it succeeded\n"
                               "  y - yes, execute the command\n");
                        continue; /* ask again */
                case 'i':
                        printf("  Unit:        %s\n"
                               "  Command:     %s\n",
                               params->unit_id, cmdline);
                        continue; /* ask again */
                case 'j':
                        if (sigqueue(getppid(),
                                     SIGRTMIN+18,
                                     (const union sigval) { .sival_int = MANAGER_SIGNAL_COMMAND_DUMP_JOBS }) < 0)
                                return -errno;

                        continue; /* ask again */
                case 'n':
                        /* 'n' was removed in favor of 'f'. */
                        printf("Didn't understand 'n', did you mean 'f'?\n");
                        continue; /* ask again */
                case 's':
                        printf("Skipping execution.\n");
                        r = CONFIRM_PRETEND_SUCCESS;
                        break;
                case 'y':
                        r = CONFIRM_EXECUTE;
                        break;
                default:
                        assert_not_reached();
                }
                break;
        }

restore_stdio:
        restore_confirm_stdio(&saved_stdin, &saved_stdout);
        return r;
}

static int get_fixed_user(
                const char *user_or_uid,
                bool prefer_nss,
                const char **ret_username,
                uid_t *ret_uid,
                gid_t *ret_gid,
                const char **ret_home,
                const char **ret_shell) {

        int r;

        assert(user_or_uid);
        assert(ret_username);

        r = get_user_creds(&user_or_uid, ret_uid, ret_gid, ret_home, ret_shell,
                           USER_CREDS_CLEAN|(prefer_nss ? USER_CREDS_PREFER_NSS : 0));
        if (r < 0)
                return r;

        /* user_or_uid is normalized by get_user_creds to username */
        *ret_username = user_or_uid;

        return 0;
}

static int get_fixed_group(
                const char *group_or_gid,
                const char **ret_groupname,
                gid_t *ret_gid) {

        int r;

        assert(group_or_gid);
        assert(ret_groupname);

        r = get_group_creds(&group_or_gid, ret_gid, /* flags= */ 0);
        if (r < 0)
                return r;

        /* group_or_gid is normalized by get_group_creds to groupname */
        *ret_groupname = group_or_gid;

        return 0;
}

static int get_supplementary_groups(
                const ExecContext *c,
                const char *user,
                gid_t gid,
                gid_t **ret_gids) {

        int r;

        assert(c);
        assert(ret_gids);

        /*
         * If user is given, then lookup GID and supplementary groups list.
         * We avoid NSS lookups for gid=0. Also we have to initialize groups
         * here and as early as possible so we keep the list of supplementary
         * groups of the caller.
         */
        bool keep_groups = false;
        if (user && gid_is_valid(gid) && gid != 0) {
                /* First step, initialize groups from /etc/groups */
                if (initgroups(user, gid) < 0) {
                        /* If our primary gid is already the one specified in Group= (i.e. we're running in
                         * user mode), gracefully handle the case where we have no privilege to re-initgroups().
                         *
                         * Note that group memberships of the current user might have been modified, but
                         * the change will only take effect after re-login. It's better to continue on with
                         * existing credentials rather than erroring out. */
                        if (!ERRNO_IS_PRIVILEGE(errno) || gid != getgid())
                                return -errno;
                }

                keep_groups = true;
        }

        if (strv_isempty(c->supplementary_groups)) {
                *ret_gids = NULL;
                return 0;
        }

        /*
         * If SupplementaryGroups= was passed then NGROUPS_MAX has to
         * be positive, otherwise fail.
         */
        errno = 0;
        int ngroups_max = (int) sysconf(_SC_NGROUPS_MAX);
        if (ngroups_max <= 0)
                return errno_or_else(EOPNOTSUPP);

        _cleanup_free_ gid_t *l_gids = new(gid_t, ngroups_max);
        if (!l_gids)
                return -ENOMEM;

        int k = 0;
        if (keep_groups) {
                /*
                 * Lookup the list of groups that the user belongs to, we
                 * avoid NSS lookups here too for gid=0.
                 */
                k = ngroups_max;
                if (getgrouplist(user, gid, l_gids, &k) < 0)
                        return -EINVAL;
        }

        STRV_FOREACH(i, c->supplementary_groups) {
                if (k >= ngroups_max)
                        return -E2BIG;

                const char *g = *i;
                r = get_group_creds(&g, l_gids + k, /* flags= */ 0);
                if (r < 0)
                        return r;

                k++;
        }

        if (k == 0) {
                *ret_gids = NULL;
                return 0;
        }

        /* Otherwise get the final list of supplementary groups */
        gid_t *groups = newdup(gid_t, l_gids, k);
        if (!groups)
                return -ENOMEM;

        *ret_gids = groups;
        return k;
}

static int enforce_groups(gid_t gid, const gid_t *supplementary_gids, int ngids) {
        int r;

        /* Handle SupplementaryGroups= if it is not empty */
        if (ngids > 0) {
                r = maybe_setgroups(ngids, supplementary_gids);
                if (r < 0)
                        return r;
        }

        if (gid_is_valid(gid)) {
                /* Then set our gids */
                if (setresgid(gid, gid, gid) < 0)
                        return -errno;
        }

        return 0;
}

static int set_securebits(unsigned bits, unsigned mask) {
        unsigned applied;
        int current;

        current = prctl(PR_GET_SECUREBITS);
        if (current < 0)
                return -errno;

        /* Clear all securebits defined in mask and set bits */
        applied = ((unsigned) current & ~mask) | bits;
        if ((unsigned) current == applied)
                return 0;

        if (prctl(PR_SET_SECUREBITS, applied) < 0)
                return -errno;

        return 1;
}

static int enforce_user(
                const ExecContext *context,
                uid_t uid,
                uint64_t capability_ambient_set) {

        int r;

        assert(context);

        if (!uid_is_valid(uid))
                return 0;

        /* Sets (but doesn't look up) the UIS and makes sure we keep the capabilities while doing so. For
         * setting secure bits the capability CAP_SETPCAP is required, so we also need keep-caps in this
         * case. */

        if ((capability_ambient_set != 0 || context->secure_bits != 0) && uid != 0) {

                /* First step: If we need to keep capabilities but drop privileges we need to make sure we
                 * keep our caps, while we drop privileges. Add KEEP_CAPS to the securebits */
                r = set_securebits(1U << SECURE_KEEP_CAPS, 0);
                if (r < 0)
                        return r;
        }

        /* Second step: actually set the uids */
        if (setresuid(uid, uid, uid) < 0)
                return -errno;

        /* At this point we should have all necessary capabilities but are otherwise a normal user. However,
         * the caps might got corrupted due to the setresuid() so we need clean them up later. This is done
         * outside of this call. */
        return 0;
}

#if HAVE_PAM

static void pam_response_free_array(struct pam_response *responses, size_t n_responses) {
        assert(responses || n_responses == 0);

        FOREACH_ARRAY(resp, responses, n_responses)
                erase_and_free(resp->resp);

        free(responses);
}

typedef struct AskPasswordConvData {
        const ExecContext *context;
        const ExecParameters *params;
} AskPasswordConvData;

static int ask_password_conv(
                int num_msg,
                const struct pam_message *msg[],
                struct pam_response **ret,
                void *userdata) {

        AskPasswordConvData *data = ASSERT_PTR(userdata);
        bool set_credential_env_var = false;
        int r;

        assert(num_msg >= 0);
        assert(msg);
        assert(data->context);
        assert(data->params);

        size_t n = num_msg;
        struct pam_response *responses = new0(struct pam_response, n);
        if (!responses)
                return PAM_BUF_ERR;
        CLEANUP_ARRAY(responses, n, pam_response_free_array);

        for (size_t i = 0; i < n; i++) {
                const struct pam_message *mi = *msg + i;

                switch (mi->msg_style) {

                case PAM_PROMPT_ECHO_ON:
                case PAM_PROMPT_ECHO_OFF: {

                        /* Locally set the $CREDENTIALS_DIRECTORY to the credentials directory we just populated */
                        if (!set_credential_env_var) {
                                _cleanup_free_ char *creds_dir = NULL;
                                r = exec_context_get_credential_directory(data->context, data->params, data->params->unit_id, &creds_dir);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine credentials directory: %m");

                                if (creds_dir) {
                                        if (setenv("CREDENTIALS_DIRECTORY", creds_dir, /* overwrite= */ true) < 0)
                                                return log_error_errno(r, "Failed to set $CREDENTIALS_DIRECTORY: %m");
                                } else
                                        (void) unsetenv("CREDENTIALS_DIRECTORY");

                                set_credential_env_var = true;
                        }

                        _cleanup_free_ char *credential_name = strjoin("pam.authtok.", data->context->pam_name);
                        if (!credential_name)
                                return log_oom();

                        AskPasswordRequest req = {
                                .message = mi->msg,
                                .credential = credential_name,
                                .tty_fd = -EBADF,
                                .hup_fd = -EBADF,
                                .until = usec_add(now(CLOCK_MONOTONIC), 15 * USEC_PER_SEC),
                        };

                        _cleanup_strv_free_erase_ char **acquired = NULL;
                        r = ask_password_auto(
                                        &req,
                                        ASK_PASSWORD_ACCEPT_CACHED|
                                        ASK_PASSWORD_NO_TTY|
                                        (mi->msg_style == PAM_PROMPT_ECHO_ON ? ASK_PASSWORD_ECHO : 0),
                                        &acquired);
                        if (r < 0) {
                                log_error_errno(r, "Failed to query for password: %m");
                                return PAM_CONV_ERR;
                        }

                        responses[i].resp = strdup(ASSERT_PTR(acquired[0]));
                        if (!responses[i].resp) {
                                log_oom();
                                return PAM_BUF_ERR;
                        }
                        break;
                }

                case PAM_ERROR_MSG:
                        log_error("PAM: %s", mi->msg);
                        break;

                case PAM_TEXT_INFO:
                        log_info("PAM: %s", mi->msg);
                        break;

                default:
                        return PAM_CONV_ERR;
                }
        }

        *ret = TAKE_PTR(responses);
        n = 0;

        return PAM_SUCCESS;
}

static int pam_close_session_and_delete_credentials(pam_handle_t *pamh, int flags) {
        int r, s;

        assert(pamh);

        r = sym_pam_close_session(pamh, flags);
        if (r != PAM_SUCCESS)
                pam_syslog_pam_error(pamh, LOG_DEBUG, r, "pam_close_session() failed: @PAMERR@");

        s = sym_pam_setcred(pamh, PAM_DELETE_CRED | flags);
        if (s != PAM_SUCCESS)
                pam_syslog_pam_error(pamh, LOG_DEBUG, r, "pam_setcred(PAM_DELETE_CRED) failed: @PAMERR@");

        return r != PAM_SUCCESS ? r : s;
}
#endif

static int attach_to_subcgroup(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                const ExecParameters *params,
                const char *prefix) {

        _cleanup_free_ char *subgroup = NULL;
        int r;

        assert(context);
        assert(cgroup_context);
        assert(params);

        /* If we're a control process that needs a subgroup, we've already been spawned into it as otherwise
         * we'd violate the "no inner processes" rule, so no need to do anything. */
        if (exec_params_needs_control_subcgroup(params))
                return 0;

        r = exec_params_get_cgroup_path(params, cgroup_context, prefix, &subgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire cgroup path: %m");
        /* No subgroup required? Then there's nothing to do. */
        if (r == 0)
                return 0;

        r = cg_attach(subgroup, 0);
        if (r == -EUCLEAN)
                return log_error_errno(r,
                                "Failed to attach process " PID_FMT " to cgroup '%s', "
                                "because the cgroup or one of its parents or "
                                "siblings is in the threaded mode.",
                                getpid_cached(), subgroup);
        if (r < 0)
                return log_error_errno(r,
                                "Failed to attach process " PID_FMT " to cgroup %s: %m",
                                getpid_cached(), subgroup);

        return 0;
}

#if HAVE_PAM
static int exec_context_get_tty_for_pam(const ExecContext *context, char **ret) {
        _cleanup_free_ char *tty = NULL;
        int r;

        assert(context);
        assert(ret);

        /* First, let's get TTY from STDIN. We may already set STDIN in setup_output(). */
        r = getttyname_malloc(STDIN_FILENO, &tty);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r >= 0) {
                _cleanup_free_ char *q = path_join("/dev/", tty);
                if (!q)
                        return log_oom_debug();

                log_debug("Got TTY '%s' from STDIN.", q);
                *ret = TAKE_PTR(q);
                return 1;
        }

        /* Do not implicitly configure TTY unless TTYPath= or StandardInput=tty is specified. See issue
         * #39334. Note, exec_context_tty_path() returns "/dev/console" when TTYPath= is unspecified, hence
         * explicitly check context->tty_path here. */
        if (!context->tty_path && !exec_input_is_terminal(context->std_input)) {
                *ret = NULL;
                return 0;
        }

        /* Next, let's try to use the TTY specified in TTYPath=. */
        const char *t = exec_context_tty_path(context);
        if (!t) {
                *ret = NULL;
                return 0;
        }

        /* If /dev/console is specified, resolve it. */
        if (tty_is_console(t)) {
                r = resolve_dev_console(&tty);
                if (r < 0) {
                        log_debug_errno(r, "Failed to resolve /dev/console, ignoring: %m");
                        *ret = NULL;
                        return 0;
                }

                log_debug("Got TTY '%s' from /dev/console.", tty);
                *ret = TAKE_PTR(tty);
                return 1;
        }

        /* Otherwise, use the specified TTY as is. */
        if (path_startswith(t, "/dev/"))
                tty = strdup(t);
        else
                tty = path_join("/dev/", t);
        if (!tty)
                return log_oom_debug();

        log_debug("Got TTY '%s' from TTYPath= setting.", tty);
        *ret = TAKE_PTR(tty);
        return 1;
}
#endif

static int setup_pam(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                ExecParameters *params,
                const char *user,
                uid_t uid,
                gid_t gid,
                char ***env, /* updated on success */
                bool needs_sandboxing,
                int exec_fd) {

#if HAVE_PAM
        AskPasswordConvData conv_data = {
                .context = context,
                .params = params,
        };

        const struct pam_conv conv = {
                .conv = ask_password_conv,
                .appdata_ptr = &conv_data,
        };

        _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
        _cleanup_strv_free_ char **e = NULL;
        _cleanup_free_ char *tty = NULL;
        pam_handle_t *pamh = NULL;
        sigset_t old_ss;
        int pam_code = PAM_SUCCESS, r;
        bool close_session = false;
        pid_t parent_pid;
        int flags = 0;

        assert(context);
        assert(params);
        assert(user);
        assert(uid_is_valid(uid));
        assert(gid_is_valid(gid));
        assert(env);

        /* We set up PAM in the parent process, then fork. The child will then stay around until killed via
         * PR_GET_PDEATHSIG or systemd via the cgroup logic. It will then remove the PAM session again. The
         * parent process will exec() the actual daemon. We do things this way to ensure that the main PID of
         * the daemon is the one we initially fork()ed. */

        r = dlopen_libpam();
        if (r < 0)
                return log_error_errno(r, "PAM support not available: %m");

        r = barrier_create(&barrier);
        if (r < 0)
                goto fail;

        if (log_get_max_level() < LOG_DEBUG)
                flags |= PAM_SILENT;

        pam_code = sym_pam_start(context->pam_name, user, &conv, &pamh);
        if (pam_code != PAM_SUCCESS) {
                pamh = NULL;
                goto fail;
        }

        r = exec_context_get_tty_for_pam(context, &tty);
        if (r < 0)
                goto fail;
        if (r > 0) {
                pam_code = sym_pam_set_item(pamh, PAM_TTY, tty);
                if (pam_code != PAM_SUCCESS)
                        goto fail;
        }

        STRV_FOREACH(nv, *env) {
                pam_code = sym_pam_putenv(pamh, *nv);
                if (pam_code != PAM_SUCCESS)
                        goto fail;
        }

        pam_code = sym_pam_acct_mgmt(pamh, flags);
        if (pam_code != PAM_SUCCESS)
                goto fail;

        pam_code = sym_pam_setcred(pamh, PAM_ESTABLISH_CRED | flags);
        if (pam_code != PAM_SUCCESS)
                pam_syslog_pam_error(pamh, LOG_DEBUG, pam_code, "pam_setcred(PAM_ESTABLISH_CRED) failed, ignoring: @PAMERR@");

        pam_code = sym_pam_open_session(pamh, flags);
        if (pam_code != PAM_SUCCESS)
                goto fail;

        close_session = true;

        e = sym_pam_getenvlist(pamh);
        if (!e) {
                pam_code = PAM_BUF_ERR;
                goto fail;
        }

        /* Block SIGTERM, so that we know that it won't get lost in the child */

        assert_se(sigprocmask_many(SIG_BLOCK, &old_ss, SIGTERM) >= 0);

        parent_pid = getpid_cached();

        r = pidref_safe_fork("(sd-pam)", /* flags= */ 0, /* ret= */ NULL);
        if (r < 0)
                goto fail;
        if (r == 0) {
                int ret = EXIT_PAM;

                if (needs_sandboxing && exec_needs_cgroup_namespace(context) && params->cgroup_path) {
                        /* Move PAM process into subgroup immediately if the main process hasn't been moved
                         * into the subgroup yet (when cgroup namespacing is enabled) and a subgroup is
                         * configured. */
                        r = attach_to_subcgroup(context, cgroup_context, params, params->cgroup_path);
                        if (r < 0)
                                return r;
                }

                /* The child's job is to reset the PAM session on termination */
                barrier_set_role(&barrier, BARRIER_CHILD);

                /* Make sure we don't keep open the passed fds in this child. We assume that otherwise only
                 * those fds are open here that have been opened by PAM. */
                close_many(params->fds, params->n_socket_fds + params->n_stashed_fds);

                /* Also close the 'exec_fd' in the child, since the service manager waits for the EOF induced
                 * by the execve() to wait for completion, and if we'd keep the fd open here in the child
                 * we'd never signal completion. */
                exec_fd = safe_close(exec_fd);

                /* Drop privileges - we don't need any to pam_close_session and this will make
                 * PR_SET_PDEATHSIG work in most cases.  If this fails, ignore the error - but expect sd-pam
                 * threads to fail to exit normally */

                r = fully_set_uid_gid(uid, gid, /* supplementary_gids= */ NULL, /* n_supplementary_gids= */ 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to drop privileges in sd-pam: %m");

                (void) ignore_signals(SIGPIPE);

                /* Wait until our parent died. This will only work if the above setresuid() succeeds,
                 * otherwise the kernel will not allow unprivileged parents kill their privileged children
                 * this way. We rely on the control groups kill logic to do the rest for us. */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        goto child_finish;

                /* Tell the parent that our setup is done. This is especially important regarding dropping
                 * privileges. Otherwise, unit setup might race against our setresuid(2) call.
                 *
                 * If the parent aborted, we'll detect this below, hence ignore return failure here. */
                (void) barrier_place(&barrier);

                /* Check if our parent process might already have died? */
                if (getppid() == parent_pid) {
                        sigset_t ss;
                        int sig;

                        assert_se(sigemptyset(&ss) >= 0);
                        assert_se(sigaddset(&ss, SIGTERM) >= 0);

                        assert_se(sigwait(&ss, &sig) == 0);
                        assert(sig == SIGTERM);
                }

                /* If our parent died we'll end the session */
                if (getppid() != parent_pid) {
                        pam_code = pam_close_session_and_delete_credentials(pamh, flags);
                        if (pam_code != PAM_SUCCESS)
                                goto child_finish;
                }

                ret = 0;

        child_finish:
                /* NB: pam_end() when called in child processes should set PAM_DATA_SILENT to let the module
                 * know about this. See pam_end(3) */
                (void) sym_pam_end(pamh, pam_code | flags | PAM_DATA_SILENT);
                _exit(ret);
        }

        barrier_set_role(&barrier, BARRIER_PARENT);

        /* If the child was forked off successfully it will do all the cleanups, so forget about the handle
         * here. */
        pamh = NULL;

        /* Unblock SIGTERM again in the parent */
        assert_se(sigprocmask(SIG_SETMASK, &old_ss, NULL) >= 0);

        /* We close the log explicitly here, since the PAM modules might have opened it, but we don't want
         * this fd around. */
        closelog();

        /* Synchronously wait for the child to initialize. We don't care for errors as we cannot
         * recover. However, warn loudly if it happens. */
        if (!barrier_place_and_sync(&barrier))
                log_error("PAM initialization failed");

        return strv_free_and_replace(*env, e);

fail:
        if (pam_code != PAM_SUCCESS) {
                pam_syslog_pam_error(pamh, LOG_ERR, pam_code, "PAM failed: @PAMERR@");
                r = -EPERM;  /* PAM errors do not map to errno */
        } else
                log_error_errno(r, "PAM failed: %m");

        if (pamh) {
                if (close_session)
                        pam_code = pam_close_session_and_delete_credentials(pamh, flags);

                (void) sym_pam_end(pamh, pam_code | flags);
        }

        closelog();
        return r;
#else
        return 0;
#endif
}

static void rename_process_from_path(const char *path) {
        int r;

        assert(path);

        _cleanup_free_ char *buf = NULL;
        r = path_extract_filename(path, &buf);
        if (r < 0) {
                log_debug_errno(r, "Failed to extract file name from '%s', ignoring: %m", path);
                return (void) rename_process("(...)");
        }

        size_t len = strlen(buf);
        char comm[TASK_COMM_LEN], *p = comm;
        *p++ = '(';
        strnpcpy(&p, TASK_COMM_LEN - 2, buf, len); /* strnpcpy() accounts for NUL byte internally */
        *p++ = ')';
        *p = '\0';

        size_t len_invocation = program_invocation_name ? strlen(program_invocation_name) : SIZE_MAX;
        _cleanup_free_ char *invocation = strjoin("(", buf + LESS_BY(len, len_invocation - 2), ")");
        if (!invocation)
                log_oom_debug();

        (void) rename_process_full(comm, invocation ?: comm);
}

static bool context_has_address_families(const ExecContext *c) {
        assert(c);

        return c->address_families_allow_list ||
                !set_isempty(c->address_families);
}

static bool context_has_syscall_filters(const ExecContext *c) {
        assert(c);

        return c->syscall_allow_list ||
                !hashmap_isempty(c->syscall_filter);
}

static bool context_has_syscall_logs(const ExecContext *c) {
        assert(c);

        return c->syscall_log_allow_list ||
                !hashmap_isempty(c->syscall_log);
}

static bool context_has_seccomp(const ExecContext *c) {
        assert(c);

        /* We need NNP if we have any form of seccomp and are unprivileged */
        return c->lock_personality ||
                c->memory_deny_write_execute ||
                c->private_devices ||
                c->protect_clock ||
                c->protect_hostname == PROTECT_HOSTNAME_YES ||
                c->protect_kernel_tunables ||
                c->protect_kernel_modules ||
                c->protect_kernel_logs ||
                context_has_address_families(c) ||
                exec_context_restrict_namespaces_set(c) ||
                c->restrict_realtime ||
                c->restrict_suid_sgid ||
                !set_isempty(c->syscall_archs) ||
                context_has_syscall_filters(c) ||
                context_has_syscall_logs(c);
}

static bool context_has_no_new_privileges(const ExecContext *c) {
        assert(c);

        if (c->no_new_privileges)
                return true;

        if (have_effective_cap(CAP_SYS_ADMIN) > 0) /* if we are privileged, we don't need NNP */
                return false;

        return context_has_seccomp(c);
}

#if HAVE_SECCOMP

static bool seccomp_allows_drop_privileges(const ExecContext *c) {
        void *id, *val;
        bool have_capget = false, have_capset = false, have_prctl = false;

        assert(c);

        /* No libseccomp, all is fine */
        if (dlopen_libseccomp() < 0)
                return true;

        /* No syscall filter, we are allowed to drop privileges */
        if (hashmap_isempty(c->syscall_filter))
                return true;

        HASHMAP_FOREACH_KEY(val, id, c->syscall_filter) {
                _cleanup_free_ char *name = NULL;

                name = sym_seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);

                if (streq(name, "capget"))
                        have_capget = true;
                else if (streq(name, "capset"))
                        have_capset = true;
                else if (streq(name, "prctl"))
                        have_prctl = true;
        }

        if (c->syscall_allow_list)
                return have_capget && have_capset && have_prctl;
        else
                return !(have_capget || have_capset || have_prctl);
}

static bool skip_seccomp_unavailable(const char *msg) {
        assert(msg);

        if (is_seccomp_available())
                return false;

        log_debug("SECCOMP features not detected in the kernel, skipping %s", msg);
        return true;
}

static int apply_syscall_filter(const ExecContext *c, const ExecParameters *p) {
        uint32_t negative_action, default_action, action;
        int r;

        assert(c);
        assert(p);

        if (!context_has_syscall_filters(c))
                return 0;

        if (skip_seccomp_unavailable("SystemCallFilter="))
                return 0;

        negative_action = c->syscall_errno == SECCOMP_ERROR_NUMBER_KILL ? SCMP_ACT_KILL_PROCESS : SCMP_ACT_ERRNO(c->syscall_errno);

        if (c->syscall_allow_list) {
                default_action = negative_action;
                action = SCMP_ACT_ALLOW;
        } else {
                default_action = SCMP_ACT_ALLOW;
                action = negative_action;
        }

        /* Sending over exec_fd or handoff_timestamp_fd requires write() syscall. */
        if (p->exec_fd >= 0 || p->handoff_timestamp_fd >= 0) {
                r = seccomp_filter_set_add_by_name(c->syscall_filter, c->syscall_allow_list, "write");
                if (r < 0)
                        return r;
        }

        return seccomp_load_syscall_filter_set_raw(default_action, c->syscall_filter, action, false);
}

static int apply_syscall_log(const ExecContext *c, const ExecParameters *p) {
        uint32_t default_action, action;

        assert(c);
        assert(p);

        if (!context_has_syscall_logs(c))
                return 0;

        if (skip_seccomp_unavailable("SystemCallLog="))
                return 0;

        if (c->syscall_log_allow_list) {
                /* Log nothing but the ones listed */
                default_action = SCMP_ACT_ALLOW;
                action = SCMP_ACT_LOG;
        } else {
                /* Log everything but the ones listed */
                default_action = SCMP_ACT_LOG;
                action = SCMP_ACT_ALLOW;
        }

        return seccomp_load_syscall_filter_set_raw(default_action, c->syscall_log, action, false);
}

static int apply_syscall_archs(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (set_isempty(c->syscall_archs))
                return 0;

        if (skip_seccomp_unavailable("SystemCallArchitectures="))
                return 0;

        return seccomp_restrict_archs(c->syscall_archs);
}

static int apply_address_families(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!context_has_address_families(c))
                return 0;

        if (skip_seccomp_unavailable("RestrictAddressFamilies="))
                return 0;

        return seccomp_restrict_address_families(c->address_families, c->address_families_allow_list);
}

static int apply_memory_deny_write_execute(const ExecContext *c, const ExecParameters *p) {
        int r;

        assert(c);
        assert(p);

        if (!c->memory_deny_write_execute)
                return 0;

        /* use prctl() if kernel supports it (6.3) */
        r = prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0);
        if (r == 0) {
                log_debug("Enabled MemoryDenyWriteExecute= with PR_SET_MDWE");
                return 0;
        }
        if (r < 0 && errno != EINVAL)
                return log_debug_errno(errno, "Failed to enable MemoryDenyWriteExecute= with PR_SET_MDWE: %m");
        /* else use seccomp */
        log_debug("Kernel doesn't support PR_SET_MDWE: falling back to seccomp");

        if (skip_seccomp_unavailable("MemoryDenyWriteExecute="))
                return 0;

        return seccomp_memory_deny_write_execute();
}

static int apply_restrict_realtime(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->restrict_realtime)
                return 0;

        if (skip_seccomp_unavailable("RestrictRealtime="))
                return 0;

        return seccomp_restrict_realtime();
}

static int apply_restrict_suid_sgid(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->restrict_suid_sgid)
                return 0;

        if (skip_seccomp_unavailable("RestrictSUIDSGID="))
                return 0;

        return seccomp_restrict_suid_sgid();
}

static int apply_protect_sysctl(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        /* Turn off the legacy sysctl() system call. Many distributions turn this off while building the kernel, but
         * let's protect even those systems where this is left on in the kernel. */

        if (!c->protect_kernel_tunables)
                return 0;

        if (skip_seccomp_unavailable("ProtectKernelTunables="))
                return 0;

        return seccomp_protect_sysctl();
}

static int apply_protect_kernel_modules(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        /* Turn off module syscalls on ProtectKernelModules=yes */

        if (!c->protect_kernel_modules)
                return 0;

        if (skip_seccomp_unavailable("ProtectKernelModules="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_MODULE, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_protect_kernel_logs(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->protect_kernel_logs)
                return 0;

        if (skip_seccomp_unavailable("ProtectKernelLogs="))
                return 0;

        return seccomp_protect_syslog();
}

static int apply_protect_clock(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->protect_clock)
                return 0;

        if (skip_seccomp_unavailable("ProtectClock="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_CLOCK, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_private_devices(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        /* If PrivateDevices= is set, also turn off iopl and all @raw-io syscalls. */

        if (!c->private_devices)
                return 0;

        if (skip_seccomp_unavailable("PrivateDevices="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_RAW_IO, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_restrict_namespaces(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!exec_context_restrict_namespaces_set(c))
                return 0;

        if (skip_seccomp_unavailable("RestrictNamespaces="))
                return 0;

        return seccomp_restrict_namespaces(c->restrict_namespaces);
}

static int apply_lock_personality(const ExecContext *c, const ExecParameters *p) {
        unsigned long personality;
        int r;

        assert(c);
        assert(p);

        if (!c->lock_personality)
                return 0;

        if (skip_seccomp_unavailable("LockPersonality="))
                return 0;

        personality = c->personality;

        /* If personality is not specified, use either PER_LINUX or PER_LINUX32 depending on what is currently set. */
        if (personality == PERSONALITY_INVALID) {

                r = opinionated_personality(&personality);
                if (r < 0)
                        return r;
        }

        return seccomp_lock_personality(personality);
}

#endif

#if HAVE_LIBBPF
static int apply_restrict_filesystems(const ExecContext *c, const ExecParameters *p) {
        int r;

        assert(c);
        assert(p);

        if (!exec_context_restrict_filesystems_set(c))
                return 0;

        if (p->bpf_restrict_fs_map_fd < 0) {
                /* LSM BPF is unsupported or lsm_bpf_setup failed */
                log_debug("LSM BPF not supported, skipping RestrictFileSystems=");
                return 0;
        }

        /* We are in a new binary, so dl-open again */
        r = dlopen_bpf();
        if (r < 0)
                return r;

        return bpf_restrict_fs_update(c->restrict_filesystems, p->cgroup_id, p->bpf_restrict_fs_map_fd, c->restrict_filesystems_allow_list);
}
#endif

static int apply_protect_hostname(const ExecContext *c, const ExecParameters *p, int *ret_exit_status) {
        int r;

        assert(c);
        assert(p);
        assert(ret_exit_status);

        if (c->protect_hostname == PROTECT_HOSTNAME_NO)
                return 0;

        if (namespace_type_supported(NAMESPACE_UTS)) {
                if (unshare(CLONE_NEWUTS) < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno)) {
                                *ret_exit_status = EXIT_NAMESPACE;
                                return log_error_errno(errno, "Failed to set up UTS namespacing: %m");
                        }

                        log_warning("ProtectHostname=%s is configured, but UTS namespace setup is prohibited (container manager?), ignoring namespace setup.",
                                    protect_hostname_to_string(c->protect_hostname));

                } else if (c->private_hostname) {
                        r = sethostname_idempotent(c->private_hostname);
                        if (r < 0) {
                                *ret_exit_status = EXIT_NAMESPACE;
                                return log_error_errno(r, "Failed to set private hostname '%s': %m", c->private_hostname);
                        }
                }
        } else
                log_warning("ProtectHostname=%s is configured, but the kernel does not support UTS namespaces, ignoring namespace setup.",
                            protect_hostname_to_string(c->protect_hostname));

#if HAVE_SECCOMP
        if (c->protect_hostname == PROTECT_HOSTNAME_YES) {
                if (skip_seccomp_unavailable("ProtectHostname="))
                        return 0;

                r = seccomp_protect_hostname();
                if (r < 0) {
                        *ret_exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply hostname restrictions: %m");
                }
        }
#endif

        return 1;
}

static void do_idle_pipe_dance(int idle_pipe[static 4]) {
        assert(idle_pipe);

        idle_pipe[1] = safe_close(idle_pipe[1]);
        idle_pipe[2] = safe_close(idle_pipe[2]);

        if (idle_pipe[0] >= 0) {
                int r;

                r = fd_wait_for_event(idle_pipe[0], POLLHUP, IDLE_TIMEOUT_USEC);

                if (idle_pipe[3] >= 0 && r == 0 /* timeout */) {
                        ssize_t n;

                        /* Signal systemd that we are bored and want to continue. */
                        n = write(idle_pipe[3], "x", 1);
                        if (n > 0)
                                /* Wait for systemd to react to the signal above. */
                                (void) fd_wait_for_event(idle_pipe[0], POLLHUP, IDLE_TIMEOUT2_USEC);
                }

                idle_pipe[0] = safe_close(idle_pipe[0]);

        }

        idle_pipe[3] = safe_close(idle_pipe[3]);
}

/* And this table also maps ExecDirectoryType, to the environment variable we pass the selected directory to
 * the service payload in. */
static const char* const exec_directory_env_name_table[_EXEC_DIRECTORY_TYPE_MAX] = {
        [EXEC_DIRECTORY_RUNTIME]       = "RUNTIME_DIRECTORY",
        [EXEC_DIRECTORY_STATE]         = "STATE_DIRECTORY",
        [EXEC_DIRECTORY_CACHE]         = "CACHE_DIRECTORY",
        [EXEC_DIRECTORY_LOGS]          = "LOGS_DIRECTORY",
        [EXEC_DIRECTORY_CONFIGURATION] = "CONFIGURATION_DIRECTORY",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(exec_directory_env_name, ExecDirectoryType);

static int build_environment(
                const ExecContext *c,
                const ExecParameters *p,
                const CGroupContext *cgroup_context,
                const char *home,
                const char *username,
                const char *shell,
                dev_t journal_stream_dev,
                ino_t journal_stream_ino,
                const char *memory_pressure_path,
                bool needs_sandboxing,
                char ***ret) {

        _cleanup_strv_free_ char **e = NULL;
        size_t n = 0;
        pid_t exec_pid;
        int r;

        assert(c);
        assert(p);
        assert(cgroup_context);
        assert(ret);

        exec_pid = needs_sandboxing && exec_needs_pid_namespace(c, p) ? 1 : getpid_cached();

        if (p->n_socket_fds + p->n_stashed_fds > 0) {
                _cleanup_free_ char *joined = NULL;

                r = strv_extendf_with_size(&e, &n, "LISTEN_PID="PID_FMT, exec_pid);
                if (r < 0)
                        return r;

                uint64_t pidfdid;
                if (pidfd_get_inode_id_self_cached(&pidfdid) >= 0) {
                        r = strv_extendf_with_size(&e, &n, "LISTEN_PIDFDID=%"PRIu64, pidfdid);
                        if (r < 0)
                                return r;
                }

                r = strv_extendf_with_size(&e, &n, "LISTEN_FDS=%zu", p->n_socket_fds + p->n_stashed_fds);
                if (r < 0)
                        return r;

                joined = strv_join(p->fd_names, ":");
                if (!joined)
                        return -ENOMEM;

                r = strv_extend_joined_with_size(&e, &n, "LISTEN_FDNAMES=", joined);
                if (r < 0)
                        return r;
        }

        if ((p->flags & EXEC_SET_WATCHDOG) && p->watchdog_usec > 0) {
                r = strv_extendf_with_size(&e, &n, "WATCHDOG_PID="PID_FMT, exec_pid);
                if (r < 0)
                        return r;

                r = strv_extendf_with_size(&e, &n, "WATCHDOG_USEC="USEC_FMT, p->watchdog_usec);
                if (r < 0)
                        return r;
        }

        /* If this is D-Bus, tell the nss-systemd module, since it relies on being able to use blocking
         * Varlink calls back to us for look up dynamic users in PID 1. Break the deadlock between D-Bus and
         * PID 1 by disabling use of PID1' NSS interface for looking up dynamic users. */
        if (p->flags & EXEC_NSS_DYNAMIC_BYPASS) {
                r = strv_extend_with_size(&e, &n, "SYSTEMD_NSS_DYNAMIC_BYPASS=1");
                if (r < 0)
                        return r;
        }

        /* We query "root" if this is a system unit and User= is not specified. $USER is always set. $HOME
         * could cause problem for e.g. getty, since login doesn't override $HOME, and $LOGNAME and $SHELL don't
         * really make much sense since we're not logged in. Hence we conditionalize the three based on
         * SetLoginEnvironment= switch. */
        if (!username && !c->dynamic_user && p->runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                assert(!c->user);

                r = get_fixed_user("root", /* prefer_nss= */ false, &username, NULL, NULL, &home, &shell);
                if (r < 0) {
                        log_debug_errno(r, "Failed to determine credentials for user root: %s",
                                        STRERROR_USER(r));
                        return ERRNO_IS_NEG_BAD_ACCOUNT(r) ? -EINVAL : r;  /* Suppress confusing errno */
                }
        }

        bool set_user_login_env = exec_context_get_set_login_environment(c);

        if (username) {
                r = strv_extend_joined_with_size(&e, &n, "USER=", username);
                if (r < 0)
                        return r;

                if (set_user_login_env) {
                        r = strv_extend_joined_with_size(&e, &n, "LOGNAME=", username);
                        if (r < 0)
                                return r;
                }
        }

        /* Note that we don't set $HOME or $SHELL if they are not particularly enlightening anyway
         * (i.e. are "/" or "/bin/nologin"). */

        if (home && set_user_login_env && !empty_or_root(home)) {
                _cleanup_free_ char *x = NULL;

                r = path_simplify_alloc(home, &x);
                if (r < 0)
                        return r;

                r = strv_extend_joined_with_size(&e, &n, "HOME=", x);
                if (r < 0)
                        return r;
        }

        if (shell && set_user_login_env && !shell_is_placeholder(shell)) {
                _cleanup_free_ char *x = NULL;

                r = path_simplify_alloc(shell, &x);
                if (r < 0)
                        return r;

                r = strv_extend_joined_with_size(&e, &n, "SHELL=", x);
                if (r < 0)
                        return r;
        }

        if (!sd_id128_is_null(p->invocation_id)) {
                assert(!isempty(p->invocation_id_string));

                r = strv_extend_joined_with_size(&e, &n, "INVOCATION_ID=", p->invocation_id_string);
                if (r < 0)
                        return r;
        }

        if (journal_stream_dev != 0 && journal_stream_ino != 0) {
                r = strv_extendf_with_size(&e, &n, "JOURNAL_STREAM=" DEV_FMT ":" INO_FMT, journal_stream_dev, journal_stream_ino);
                if (r < 0)
                        return r;
        }

        if (c->log_namespace) {
                r = strv_extend_joined_with_size(&e, &n, "LOG_NAMESPACE=", c->log_namespace);
                if (r < 0)
                        return r;
        }

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                _cleanup_free_ char *joined = NULL;

                if (!p->prefix[t])
                        continue;

                if (c->directories[t].n_items == 0)
                        continue;

                const char *name = exec_directory_env_name_to_string(t);
                if (!name)
                        continue;

                for (size_t i = 0; i < c->directories[t].n_items; i++) {
                        _cleanup_free_ char *prefixed = NULL;

                        prefixed = path_join(p->prefix[t], c->directories[t].items[i].path);
                        if (!prefixed)
                                return -ENOMEM;

                        if (!strextend_with_separator(&joined, ":", prefixed))
                                return -ENOMEM;
                }

                r = strv_extend_joined_with_size(&e, &n, name, "=", joined);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *creds_dir = NULL;
        r = exec_context_get_credential_directory(c, p, p->unit_id, &creds_dir);
        if (r < 0)
                return r;
        if (r > 0) {
                r = strv_extend_joined_with_size(&e, &n, "CREDENTIALS_DIRECTORY=", creds_dir);
                if (r < 0)
                        return r;
        }

        r = strv_extendf_with_size(&e, &n, "SYSTEMD_EXEC_PID=" PID_FMT, exec_pid);
        if (r < 0)
                return r;

        if (memory_pressure_path) {
                r = strv_extend_joined_with_size(&e, &n, "MEMORY_PRESSURE_WATCH=", memory_pressure_path);
                if (r < 0)
                        return r;

                if (!path_equal(memory_pressure_path, "/dev/null")) {
                        _cleanup_free_ char *b = NULL, *x = NULL;

                        if (asprintf(&b, "%s " USEC_FMT " " USEC_FMT,
                                     MEMORY_PRESSURE_DEFAULT_TYPE,
                                     cgroup_context->memory_pressure_threshold_usec == USEC_INFINITY ? MEMORY_PRESSURE_DEFAULT_THRESHOLD_USEC :
                                     CLAMP(cgroup_context->memory_pressure_threshold_usec, 1U, MEMORY_PRESSURE_DEFAULT_WINDOW_USEC),
                                     MEMORY_PRESSURE_DEFAULT_WINDOW_USEC) < 0)
                                return -ENOMEM;

                        if (base64mem(b, strlen(b) + 1, &x) < 0)
                                return -ENOMEM;

                        r = strv_extend_joined_with_size(&e, &n, "MEMORY_PRESSURE_WRITE=", x);
                        if (r < 0)
                                return r;
                }
        }

        if (p->notify_socket) {
                r = strv_extend_joined_with_size(
                                &e, &n, "NOTIFY_SOCKET=",
                                exec_get_private_notify_socket_path(c, p, needs_sandboxing) ?: p->notify_socket);
                if (r < 0)
                        return r;
        }

        assert(c->private_var_tmp >= 0 && c->private_var_tmp < _PRIVATE_TMP_MAX);
        if (needs_sandboxing && c->private_tmp != c->private_var_tmp) {
                assert(c->private_tmp == PRIVATE_TMP_DISCONNECTED);
                assert(c->private_var_tmp == PRIVATE_TMP_NO);

                /* When private tmpfs is enabled only on /tmp/, then explicitly set $TMPDIR to suggest the
                 * service to use /tmp/. */

                r = strv_extend_with_size(&e, &n, "TMPDIR=/tmp");
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(e);
        return 0;
}

static int build_pass_environment(const ExecContext *c, char ***ret) {
        _cleanup_strv_free_ char **pass_env = NULL;
        size_t n_env = 0;

        assert(c);
        assert(ret);

        STRV_FOREACH(i, c->pass_environment) {
                _cleanup_free_ char *x = NULL;
                char *v;

                v = getenv(*i);
                if (!v)
                        continue;
                x = strjoin(*i, "=", v);
                if (!x)
                        return -ENOMEM;

                if (!GREEDY_REALLOC(pass_env, n_env + 2))
                        return -ENOMEM;

                pass_env[n_env++] = TAKE_PTR(x);
                pass_env[n_env] = NULL;
        }

        *ret = TAKE_PTR(pass_env);
        return 0;
}

static int bpffs_helper(const ExecContext *c, int socket_fd) {
        assert(c);
        assert(socket_fd >= 0);

        _cleanup_close_ int fs_fd = receive_one_fd(socket_fd, /* flags= */ 0);
        if (fs_fd < 0)
                return log_debug_errno(fs_fd, "Failed to receive file descriptor from parent: %m");

        char number[STRLEN("0x") + sizeof(c->bpf_delegate_commands) * 2 + 1];
        xsprintf(number, "0x%"PRIx64, c->bpf_delegate_commands);
        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, "delegate_cmds", number, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to FSCONFIG_SET_STRING: %m");

        xsprintf(number, "0x%"PRIx64, c->bpf_delegate_maps);
        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, "delegate_maps", number, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to FSCONFIG_SET_STRING: %m");

        xsprintf(number, "0x%"PRIx64, c->bpf_delegate_programs);
        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, "delegate_progs", number, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to FSCONFIG_SET_STRING: %m");

        xsprintf(number, "0x%"PRIx64, c->bpf_delegate_attachments);
        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, "delegate_attachs", number, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to FSCONFIG_SET_STRING: %m");

        if (fsconfig(fs_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to create bpffs superblock: %m");

        return 0;
}

static int bpffs_prepare(
                const ExecContext *c,
                PidRef *ret_pid,
                int *ret_sock_fd,
                int *ret_errno_pipe) {

        _cleanup_close_pair_ int socket_fds[2] = EBADF_PAIR, errno_pipe[2] = EBADF_PAIR;
        int r;

        assert(ret_sock_fd);
        assert(ret_pid);
        assert(ret_errno_pipe);

        r = pipe2(errno_pipe, O_CLOEXEC|O_NONBLOCK);
        if (r < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, socket_fds);
        if (r < 0)
                return log_debug_errno(errno, "Failed to create socket pair: %m");

        r = pidref_safe_fork("(sd-bpffs)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, ret_pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork bpffs privileged helper: %m");
        if (r == 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);
                socket_fds[0] = safe_close(socket_fds[0]);
                report_errno_and_exit(errno_pipe[1], bpffs_helper(c, socket_fds[1]));
        }

        *ret_sock_fd = TAKE_FD(socket_fds[0]);
        *ret_errno_pipe = TAKE_FD(errno_pipe[0]);
        return 0;
}

static int setup_private_users_child(int unshare_ready_fd, const char *uid_map, const char *gid_map, bool allow_setgroups) {
        int r;

        /* Child process, running in the original user namespace. Let's update the parent's UID/GID map from
         * here, after the parent opened its own user namespace. */

        pid_t ppid = getppid();

        /* Wait until the parent unshared the user namespace */
        uint64_t c;
        ssize_t n = read(unshare_ready_fd, &c, sizeof(c));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read from signaling eventfd: %m");
        if (n != sizeof(c))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short read from signaling eventfd.");

        /* Disable the setgroups() system call in the child user namespace, for good, unless PrivateUsers=full
         * and using the system service manager. */
        const char *a = procfs_file_alloca(ppid, "setgroups");
        const char *setgroups = allow_setgroups ? "allow" : "deny";
        r = write_string_file(a, setgroups, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write '%s' to %s: %m", setgroups, a);

        /* First write the GID map */
        a = procfs_file_alloca(ppid, "gid_map");
        r = write_string_file(a, gid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write GID map to %s: %m", a);

        /* Then write the UID map */
        a = procfs_file_alloca(ppid, "uid_map");
        r = write_string_file(a, uid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write UID map to %s: %m", a);

        return 0;
}

static int setup_private_users(
                PrivateUsers private_users,
                uid_t ouid,
                gid_t ogid,
                uid_t uid,
                gid_t gid,
                bool allow_setgroups) {

        _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        _cleanup_close_ int unshare_ready_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        uint64_t c = 1;
        ssize_t n;
        int r;

        /* Set up a user namespace and map the original UID/GID (IDs from before any user or group changes, i.e.
         * the IDs from the user or system manager(s)) to itself, the selected UID/GID to itself, and everything else to
         * nobody. In order to be able to write this mapping we need CAP_SETUID in the original user namespace, which
         * we however lack after opening the user namespace. To work around this we fork() a temporary child process,
         * which waits for the parent to create the new user namespace while staying in the original namespace. The
         * child then writes the UID mapping, under full privileges. The parent waits for the child to finish and
         * continues execution normally.
         * For unprivileged users (i.e. without capabilities), the root to root mapping is excluded. As such, it
         * does not need CAP_SETUID to write the single line mapping to itself. */

        switch (private_users) { /* Prepare the UID mappings */

        case PRIVATE_USERS_NO:
                return 0; /* Early exit */

        case PRIVATE_USERS_IDENTITY:
                uid_map = strdup("0 0 65536\n");
                if (!uid_map)
                        return -ENOMEM;
                break;

        case PRIVATE_USERS_FULL:
                /* Map all UID/GID from original to new user namespace.
                 *
                 * Note the kernel defines the UID range between 0 and UINT32_MAX so we map all UIDs even though
                 * the UID range beyond INT32_MAX (e.g. i.e. the range above the signed 32-bit range) is
                 * icky. For example, setfsuid() returns the old UID as signed integer. But units can decide to
                 * use these UIDs/GIDs so we need to map them. */
                if (asprintf(&uid_map, "0 0 " UID_FMT "\n", (uid_t) UINT32_MAX) < 0)
                        return -ENOMEM;

                break;

        case PRIVATE_USERS_SELF:
                /* Can only set up multiple mappings with CAP_SETUID. */
                if (uid_is_valid(uid) && uid != ouid && have_effective_cap(CAP_SETUID) > 0)
                        r = asprintf(&uid_map,
                                     UID_FMT " " UID_FMT " 1\n"     /* Map $OUID → $OUID */
                                     UID_FMT " " UID_FMT " 1\n",    /* Map $UID → $UID */
                                     ouid, ouid, uid, uid);
                else
                        r = asprintf(&uid_map,
                                     UID_FMT " " UID_FMT " 1\n",    /* Map $OUID → $OUID */
                                     ouid, ouid);
                if (r < 0)
                        return -ENOMEM;

                break;

        default:
                assert_not_reached();
        }

        switch (private_users) { /* Prepare the GID mappings */

        case PRIVATE_USERS_IDENTITY:
                gid_map = strdup("0 0 65536\n");
                if (!gid_map)
                        return -ENOMEM;
                break;

        case PRIVATE_USERS_FULL:
                if (asprintf(&gid_map, "0 0 " GID_FMT "\n", (gid_t) UINT32_MAX) < 0)
                        return -ENOMEM;

                break;

        case PRIVATE_USERS_SELF:
                /* Can only set up multiple mappings with CAP_SETGID. */
                if (gid_is_valid(gid) && gid != ogid && have_effective_cap(CAP_SETGID) > 0)
                        r = asprintf(&gid_map,
                                     GID_FMT " " GID_FMT " 1\n"     /* Map $OGID → $OGID */
                                     GID_FMT " " GID_FMT " 1\n",    /* Map $GID → $GID */
                                     ogid, ogid, gid, gid);
                else
                        r = asprintf(&gid_map,
                                     GID_FMT " " GID_FMT " 1\n",    /* Map $OGID -> $OGID */
                                     ogid, ogid);
                if (r < 0)
                        return -ENOMEM;
                break;

        default:
                assert_not_reached();
        }

        /* Create a communication channel so that the parent can tell the child when it finished creating the user
         * namespace. */
        unshare_ready_fd = eventfd(0, EFD_CLOEXEC);
        if (unshare_ready_fd < 0)
                return -errno;

        /* Create a communication channel so that the child can tell the parent a proper error code in case it
         * failed. */
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return -errno;

        r = pidref_safe_fork("(sd-userns)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);
                r = setup_private_users_child(unshare_ready_fd, uid_map, gid_map, allow_setgroups);
                if (r < 0)
                        report_errno_and_exit(errno_pipe[1], r);
                _exit(EXIT_SUCCESS);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);

        if (unshare(CLONE_NEWUSER) < 0)
                return log_debug_errno(errno, "Failed to unshare user namespace: %m");

        /* Let the child know that the namespace is ready now */
        if (write(unshare_ready_fd, &c, sizeof(c)) < 0)
                return -errno;

        /* Try to read an error code from the child */
        n = read(errno_pipe[0], &r, sizeof(r));
        if (n < 0)
                return -errno;
        if (n == sizeof(r)) { /* an error code was sent to us */
                if (r < 0)
                        return r;
                return -EIO;
        }
        if (n != 0) /* on success we should have read 0 bytes */
                return -EIO;

        r = pidref_wait_for_terminate_and_check("(sd-userns)", &pidref, 0);
        if (r < 0)
                return r;
        pidref_done(&pidref);
        if (r != EXIT_SUCCESS) /* If something strange happened with the child, let's consider this fatal, too */
                return -EIO;

        return 1;
}

static int can_mount_proc(void) {
        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        ssize_t n;
        int r;

        /* If running via unprivileged user manager and /proc/ is masked (e.g. /proc/kmsg is over-mounted with tmpfs
         * like systemd-nspawn does), then mounting /proc/ will fail with EPERM. This is due to a kernel restriction
         * where unprivileged user namespaces cannot mount a less restrictive instance of /proc. */

        /* Create a communication channel so that the child can tell the parent a proper error code in case it
         * failed. */
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to create pipe for communicating with child process (sd-proc-check): %m");

        /* Fork a child process into its own mount and PID namespace. Note safe_fork() already remounts / as SLAVE
         * with FORK_MOUNTNS_SLAVE. */
        r = pidref_safe_fork(
                        "(sd-proc-check)",
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE|FORK_NEW_PIDNS,
                        &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork child process (sd-proc-check): %m");
        if (r == 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* Try mounting /proc on /dev/shm/. No need to clean up the mount since the mount
                 * namespace will be cleaned up once the process exits. */
                r = mount_follow_verbose(LOG_DEBUG, "proc", "/dev/shm/", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
                if (r < 0) {
                        (void) write(errno_pipe[1], &r, sizeof(r));
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);

        /* Try to read an error code from the child */
        n = read(errno_pipe[0], &r, sizeof(r));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read errno from pipe with child process (sd-proc-check): %m");
        if (n == sizeof(r)) { /* an error code was sent to us */
                /* This is the expected case where proc cannot be mounted due to permissions. */
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        return 0;
                if (r < 0)
                        return r;

                return -EIO;
        }
        if (n != 0) /* on success we should have read 0 bytes */
                return -EIO;

        r = pidref_wait_for_terminate_and_check("(sd-proc-check)", &pidref, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for (sd-proc-check) child process to terminate: %m");
        pidref_done(&pidref);
        if (r != EXIT_SUCCESS) /* If something strange happened with the child, let's consider this fatal, too */
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Child process (sd-proc-check) exited with unexpected exit status '%d'.", r);

        return 1;
}

static int setup_private_pids(const ExecContext *c, ExecParameters *p) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        ssize_t n;
        int r, q;

        assert(c);
        assert(p);
        assert(p->pidref_transport_fd >= 0);

        /* The first process created after unsharing a pid namespace becomes PID 1 in the pid namespace, so
         * we have to fork after unsharing the pid namespace to become PID 1. The parent sends the child
         * pidref to the manager and exits while the child process continues with the rest of exec_invoke()
         * and finally executes the actual payload. */

        /* Create a communication channel so that the parent can tell the child a proper error code in case it
         * failed to send child pidref to the manager. */
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to create pipe for communicating with parent process: %m");

        /* Set FORK_DETACH to immediately re-parent the child process to the invoking manager process. */
        r = pidref_safe_fork("(sd-pidns-child)", FORK_NEW_PIDNS|FORK_DETACH, &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork child into new pid namespace: %m");
        if (r > 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* In the parent process, we send the child pidref to the manager and exit.
                 * If PIDFD is not supported, only the child PID is sent. The server then
                 * uses the child PID to set the new exec main process. */
                q = send_one_fd_iov(
                                p->pidref_transport_fd,
                                pidref.fd,
                                &IOVEC_MAKE(&pidref.pid, sizeof(pidref.pid)),
                                /* iovlen= */ 1,
                                /* flags= */ 0);
                /* Send error code to child process. */
                (void) write(errno_pipe[1], &q, sizeof(q));
                /* Exit here so we only go through the destructors in exec_invoke only once - in the child - as
                 * some destructors have external effects. The main codepaths continue in the child process. */
                _exit(q < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);
        p->pidref_transport_fd = safe_close(p->pidref_transport_fd);

        /* Try to read an error code from the parent. Note a child process cannot wait for the parent so we always
         * receive an errno even on success. */
        n = read(errno_pipe[0], &r, sizeof(r));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read errno from pipe with parent process: %m");
        if (n != sizeof(r))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to read enough bytes from pipe with parent process");
        if (r < 0)
                return log_debug_errno(r, "Failed to send child pidref to manager: %m");

        /* NOTE! This function returns in the child process only. */
        return r;
}

static int create_many_symlinks(const char *root, const char *source, char **symlinks) {
        _cleanup_free_ char *src_abs = NULL;
        int r;

        assert(source);

        src_abs = path_join(root, source);
        if (!src_abs)
                return -ENOMEM;

        STRV_FOREACH(dst, symlinks) {
                _cleanup_free_ char *dst_abs = NULL;

                dst_abs = path_join(root, *dst);
                if (!dst_abs)
                        return -ENOMEM;

                r = mkdir_parents_label(dst_abs, 0755);
                if (r < 0)
                        return r;

                r = symlink_idempotent(src_abs, dst_abs, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int set_exec_storage_quota(int fd, uint32_t proj_id, const QuotaLimit *ql) {
        int r;
        uint64_t block_limit = 0, inode_limit = 0;

        assert(fd >= 0);
        assert(ql);

        if (ql->quota_absolute == 0 || ql->quota_scale == 0)
                /* Limit of 0 means no usage is allowed. For quotactl, use 1 as the limit, since 0 means that
                 * hard limits are disabled */
                block_limit = inode_limit = 1;
        else if (ql->quota_absolute == UINT64_MAX) {
                _cleanup_close_ int fd_parent = -EBADF;

                /* Use target_dir's parent when setting quotas. If a FD for target_dir has been previously
                 * used for quotactl_fd(SET) and is passed again for fstatvfs(), the total number of blocks is not
                 * reported accurately (instead, the block limit is reported as total blocks). Thus, use the FD
                 * associated with the parent, so that total blocks is accurate */
                fd_parent = openat(fd, "..", O_PATH|O_CLOEXEC|O_DIRECTORY);
                if (fd_parent < 0)
                        return -errno;

                uint32_t xattr_flags = 0;
                r = read_fs_xattr_fd(fd_parent, &xattr_flags, /* ret_projid= */ NULL);
                if (r < 0)
                        return r;
                /* Refuse if parent has FS_XFLAG_PROJINHERIT since this will mean the total number of blocks will not
                 * be reported accurately */
                if (FLAGS_SET(xattr_flags, FS_XFLAG_PROJINHERIT))
                        return -ENOMEDIUM;

                struct statvfs disk_st;
                if (fstatvfs(fd_parent, &disk_st) < 0)
                        return -errno;

                block_limit = (uint64_t) DIV_ROUND_UP((uint64_t)((double) (disk_st.f_frsize * disk_st.f_blocks) / UINT32_MAX * ql->quota_scale), QIF_DQBLKSIZE);
                inode_limit = (uint64_t) ((double) disk_st.f_files / UINT32_MAX * ql->quota_scale);
        } else
                block_limit = (uint64_t) DIV_ROUND_UP(ql->quota_absolute, QIF_DQBLKSIZE);

        struct dqblk req = {
                .dqb_bhardlimit = block_limit,
                .dqb_ihardlimit = inode_limit,
                .dqb_valid = QIF_LIMITS,
        };

        r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_SETQUOTA, PRJQUOTA), proj_id, &req);
        if (r < 0)
                return r;

        log_debug("Storage quotas set for project id %" PRIu32 ". Block limit = %" PRIu64 ", inode limit = %" PRIu64, proj_id, block_limit, inode_limit);

        return 0;
}

static int unset_exec_storage_quota(int fd, uint32_t proj_id, bool quota_accounting) {
        int r, quota_supported;
        struct dqblk req;

        assert(fd >= 0);

        quota_supported = quota_query_proj_id(fd, proj_id, &req);
        if (quota_supported < 0)
                return log_debug_errno(quota_supported, "Failed to query disk quota for project ID %" PRIu32 ": %m", proj_id);

        /* Do not enforce quotas anymore */
        if (quota_supported && FLAGS_SET(req.dqb_valid, QIF_BLIMITS) && (req.dqb_bhardlimit > 0 || req.dqb_ihardlimit > 0)) {
                req.dqb_bhardlimit = 0, req.dqb_ihardlimit = 0;

                r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_SETQUOTA, PRJQUOTA), proj_id, &req);
                if (r < 0)
                        return log_debug_errno(r, "Failed to disable project quotas for project ID %" PRIu32 ": %m", proj_id);

                log_debug("Storage quotas for project ID %" PRIu32 " were disabled", proj_id);
        }

        /* Release project ID if no accounting needed */
        if (!quota_accounting) {
                r = set_proj_id_recursive(fd, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to release project ID %" PRIu32 ", ignoring: %m", proj_id);
        }

        return 0;
}

static int apply_exec_quotas(
                const char *target_dir,
                const char *cgroup_path,
                ExecDirectoryType type,
                const QuotaLimit *ql,
                uint32_t *exec_dt_proj_id, /* in/out */
                bool *already_enforced) {  /* in/out */

        _cleanup_close_ int fd = -EBADF;
        int r, quota_supported = 0;

        assert(target_dir);
        assert(cgroup_path);
        assert(ql);
        assert(exec_dt_proj_id);
        assert(already_enforced);

        /* Do not apply to the Runtime directory since tmpfs does not support project IDs yet */
        if (!IN_SET(type, EXEC_DIRECTORY_STATE, EXEC_DIRECTORY_CACHE, EXEC_DIRECTORY_LOGS))
                return 0;

        fd = open(target_dir, O_PATH|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s: %m", target_dir);

        /* Get the project ID of the current directory */
        uint32_t proj_id;
        r = read_fs_xattr_fd(fd, /* ret_xflags= */ NULL, &proj_id);
        if (ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(r)) {
                log_debug_errno(r, "Not applying storage quotas. FS_IOC_FSGETXATTR not supported for %s: %m", target_dir);
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to retrieve project ID for %s: %m", target_dir);

        /* If the first directory of this ExecType already has a project ID, adopt it as the project ID for all dirs of this ExecType */
        bool proj_id_exists = PROJ_ID_MIN <= proj_id && proj_id <= PROJ_ID_MAX;
        if (proj_id_exists && *exec_dt_proj_id == 0)
                *exec_dt_proj_id = proj_id;

        /* Check if enforcement should be disabled. Do not release project ID if accounting is enabled */
        if (!ql->quota_enforce) {
                if (proj_id_exists) {
                        r = unset_exec_storage_quota(fd, proj_id, ql->quota_accounting);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to unset project quotas for %s: %m", target_dir);
                }

                if (!ql->quota_accounting)
                        return 0;
        }

        if (*exec_dt_proj_id > 0 && *exec_dt_proj_id != proj_id) {
                /* Set the existing project ID only if the current directory's ID does not exist or does not match */
                proj_id = *exec_dt_proj_id;
                r = quota_proj_id_set_recursive(fd, proj_id, false);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set project ID for %s: %m", target_dir);
        } else if (*exec_dt_proj_id == 0) {
                /* Only generate a new project ID if it's the first directory of this ExecType to be processed and does not have an existing ID */
                static const sd_id128_t k = SD_ID128_ARRAY(e1,4a,79,9b,64,40,41,4a,a8,46,c2,f3,f9,19,4f,01);
                _cleanup_free_ char *proj_id_plain = NULL;

                /* Generate candidate project id */
                proj_id_plain = strjoin(cgroup_path, "|", exec_directory_type_to_string(type));
                if (!proj_id_plain)
                        return log_oom_debug();

                struct siphash state;
                siphash24_init(&state, k.bytes);
                siphash24_compress_string(proj_id_plain, &state);
                proj_id = PROJ_ID_CLAMP_INTO_QUOTA_RANGE(siphash24_finalize(&state));

#define MAX_PROJ_ID_RETRIES 10
                for (unsigned attempt = 0;; attempt++) {
                        if (attempt >= MAX_PROJ_ID_RETRIES)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Failed to generate unique project ID for '%s'.", target_dir);

                        /* Check if project quotas are supported */
                        struct dqblk req;
                        quota_supported = quota_query_proj_id(fd, proj_id, &req);
                        if (quota_supported < 0)
                                return log_debug_errno(quota_supported, "Failed to query disk quota for project ID %" PRIu32 ": %m", proj_id);
                        if (!quota_supported) {
                                log_debug("Not applying storage quotas. Project quotas are not supported for %s", target_dir);
                                return 0;
                        }

                        if (!quota_dqblk_is_populated(&req)) {
                                int proj_id_was_set = quota_proj_id_set_recursive(fd, proj_id, true);
                                if (proj_id_was_set < 0)
                                        return log_debug_errno(proj_id_was_set, "Failed to set project ID for %s: %m", target_dir);
                                if (proj_id_was_set) {
                                        *exec_dt_proj_id = proj_id;
                                        log_debug("Project ID %u generated for %s", proj_id, target_dir);
                                        break;
                                }
                        }

                        proj_id = (uint32_t) (random_u64_range(PROJ_ID_MAX - PROJ_ID_MIN + 1) + PROJ_ID_MIN);
                }
        }

        if (ql->quota_enforce && !*already_enforced) {
                if (!quota_supported) {
                        struct dqblk req;
                        quota_supported = quota_query_proj_id(fd, proj_id, &req);
                        if (quota_supported < 0)
                                return log_debug_errno(quota_supported, "Failed to query disk quota for project ID %" PRIu32 ": %m", proj_id);
                        if (!quota_supported) {
                                log_debug("Not applying storage quotas. Project quotas are not supported for %s", target_dir);
                                return 0;
                        }
                }

                r = set_exec_storage_quota(fd, proj_id, ql);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set storage quotas for %s: %m", target_dir);

                *already_enforced = true;
        }

        return r;
}

static int setup_exec_directory(
                const ExecContext *context,
                const ExecParameters *params,
                uid_t uid,
                gid_t gid,
                ExecDirectoryType type,
                bool needs_mount_namespace,
                int *exit_status) {

        static const int exit_status_table[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME]       = EXIT_RUNTIME_DIRECTORY,
                [EXEC_DIRECTORY_STATE]         = EXIT_STATE_DIRECTORY,
                [EXEC_DIRECTORY_CACHE]         = EXIT_CACHE_DIRECTORY,
                [EXEC_DIRECTORY_LOGS]          = EXIT_LOGS_DIRECTORY,
                [EXEC_DIRECTORY_CONFIGURATION] = EXIT_CONFIGURATION_DIRECTORY,
        };
        int r;

        assert(context);
        assert(params);
        assert(type >= 0 && type < _EXEC_DIRECTORY_TYPE_MAX);
        assert(exit_status);

        if (!params->prefix[type])
                return 0;

        if (params->flags & EXEC_CHOWN_DIRECTORIES) {
                if (!uid_is_valid(uid))
                        uid = 0;
                if (!gid_is_valid(gid))
                        gid = 0;
        }

        uint32_t exec_dt_proj_id = 0;
        bool quota_already_enforced = false;

        FOREACH_ARRAY(i, context->directories[type].items, context->directories[type].n_items) {
                _cleanup_free_ char *p = NULL, *pp = NULL;

                p = path_join(params->prefix[type], i->path);
                if (!p) {
                        r = -ENOMEM;
                        goto fail;
                }

                r = mkdir_parents_label(p, 0755);
                if (r < 0)
                        goto fail;

                if (IN_SET(type, EXEC_DIRECTORY_STATE, EXEC_DIRECTORY_LOGS) && params->runtime_scope == RUNTIME_SCOPE_USER) {

                        /* If we are in user mode, and a configuration directory exists but a state directory
                         * doesn't exist, then we likely are upgrading from an older systemd version that
                         * didn't know the more recent addition to the xdg-basedir spec: the $XDG_STATE_HOME
                         * directory. In older systemd versions EXEC_DIRECTORY_STATE was aliased to
                         * EXEC_DIRECTORY_CONFIGURATION, with the advent of $XDG_STATE_HOME it is now
                         * separated. If a service has both dirs configured but only the configuration dir
                         * exists and the state dir does not, we assume we are looking at an update
                         * situation. Hence, create a compatibility symlink, so that all expectations are
                         * met.
                         *
                         * (We also do something similar with the log directory, which still doesn't exist in
                         * the xdg basedir spec. We'll make it a subdir of the state dir.) */

                        /* this assumes the state dir is always created before the configuration dir */
                        assert_cc(EXEC_DIRECTORY_STATE < EXEC_DIRECTORY_LOGS);
                        assert_cc(EXEC_DIRECTORY_LOGS < EXEC_DIRECTORY_CONFIGURATION);

                        r = access_nofollow(p, F_OK);
                        if (r == -ENOENT) {
                                _cleanup_free_ char *q = NULL;

                                /* OK, we know that the state dir does not exist. Let's see if the dir exists
                                 * under the configuration hierarchy. */

                                if (type == EXEC_DIRECTORY_STATE)
                                        q = path_join(params->prefix[EXEC_DIRECTORY_CONFIGURATION], i->path);
                                else if (type == EXEC_DIRECTORY_LOGS)
                                        q = path_join(params->prefix[EXEC_DIRECTORY_CONFIGURATION], "log", i->path);
                                else
                                        assert_not_reached();
                                if (!q) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                r = access_nofollow(q, F_OK);
                                if (r >= 0) {
                                        /* It does exist! This hence looks like an update. Symlink the
                                         * configuration directory into the state directory. */

                                        r = symlink_idempotent(q, p, /* make_relative= */ true);
                                        if (r < 0)
                                                goto fail;

                                        log_notice("Unit state directory %s missing but matching configuration directory %s exists, assuming update from systemd 253 or older, creating compatibility symlink.", p, q);
                                        continue;
                                } else if (r != -ENOENT)
                                        log_warning_errno(r, "Unable to detect whether unit configuration directory '%s' exists, assuming not: %m", q);

                        } else if (r < 0)
                                log_warning_errno(r, "Unable to detect whether unit state directory '%s' is missing, assuming it is: %m", p);
                }

                if (exec_directory_is_private(context, type)) {
                        /* So, here's one extra complication when dealing with DynamicUser=1 units. In that
                         * case we want to avoid leaving a directory around fully accessible that is owned by
                         * a dynamic user whose UID is later on reused. To lock this down we use the same
                         * trick used by container managers to prohibit host users to get access to files of
                         * the same UID in containers: we place everything inside a directory that has an
                         * access mode of 0700 and is owned root:root, so that it acts as security boundary
                         * for unprivileged host code. We then use fs namespacing to make this directory
                         * permeable for the service itself.
                         *
                         * Specifically: for a service which wants a special directory "foo/" we first create
                         * a directory "private/" with access mode 0700 owned by root:root. Then we place
                         * "foo" inside of that directory (i.e. "private/foo/"), and make "foo" a symlink to
                         * "private/foo". This way, privileged host users can access "foo/" as usual, but
                         * unprivileged host users can't look into it. Inside of the namespace of the unit
                         * "private/" is replaced by a more liberally accessible tmpfs, into which the host's
                         * "private/foo/" is mounted under the same name, thus disabling the access boundary
                         * for the service and making sure it only gets access to the dirs it needs but no
                         * others. Tricky? Yes, absolutely, but it works!
                         *
                         * Note that we don't do this for EXEC_DIRECTORY_CONFIGURATION as that's assumed not
                         * to be owned by the service itself.
                         *
                         * Also, note that we don't do this for EXEC_DIRECTORY_RUNTIME as that's often used
                         * for sharing files or sockets with other services. */

                        pp = path_join(params->prefix[type], "private");
                        if (!pp) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        /* First set up private root if it doesn't exist yet, with access mode 0700 and owned by root:root */
                        r = mkdir_safe_label(pp, 0700, 0, 0, MKDIR_WARN_MODE);
                        if (r < 0)
                                goto fail;

                        if (!path_extend(&pp, i->path)) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        /* Create all directories between the configured directory and this private root, and mark them 0755 */
                        r = mkdir_parents_label(pp, 0755);
                        if (r < 0)
                                goto fail;

                        if (is_dir(p, false) > 0 &&
                            (access_nofollow(pp, F_OK) == -ENOENT)) {

                                /* Hmm, the private directory doesn't exist yet, but the normal one exists? If so, move
                                 * it over. Most likely the service has been upgraded from one that didn't use
                                 * DynamicUser=1, to one that does. */

                                log_info("Found pre-existing public %s= directory %s, migrating to %s.\n"
                                         "Apparently, service previously had DynamicUser= turned off, and has now turned it on.",
                                         exec_directory_type_to_string(type), p, pp);

                                r = RET_NERRNO(rename(p, pp));
                                if (r < 0)
                                        goto fail;
                        } else {
                                /* Otherwise, create the actual directory for the service */

                                r = mkdir_label(pp, context->directories[type].mode);
                                if (r < 0 && r != -EEXIST)
                                        goto fail;
                        }

                        if (!FLAGS_SET(i->flags, EXEC_DIRECTORY_ONLY_CREATE)) {
                                /* And link it up from the original place.
                                 * Notes
                                 * 1) If a mount namespace is going to be used, then this symlink remains on
                                 *    the host, and a new one for the child namespace will be created later.
                                 * 2) It is not necessary to create this symlink when one of its parent
                                 *    directories is specified and already created. E.g.
                                 *        StateDirectory=foo foo/bar
                                 *    In that case, the inode points to pp and p for "foo/bar" are the same:
                                 *        pp = "/var/lib/private/foo/bar"
                                 *        p = "/var/lib/foo/bar"
                                 *    and, /var/lib/foo is a symlink to /var/lib/private/foo. So, not only
                                 *    we do not need to create the symlink, but we cannot create the symlink.
                                 *    See issue #24783. */
                                r = symlink_idempotent(pp, p, true);
                                if (r < 0)
                                        goto fail;
                        }

                } else {
                        _cleanup_free_ char *target = NULL;

                        if (EXEC_DIRECTORY_TYPE_SHALL_CHOWN(type) &&
                            readlink_and_make_absolute(p, &target) >= 0) {
                                _cleanup_free_ char *q = NULL, *q_resolved = NULL, *target_resolved = NULL;

                                /* This already exists and is a symlink? Interesting. Maybe it's one created
                                 * by DynamicUser=1 (see above)?
                                 *
                                 * We do this for all directory types except for ConfigurationDirectory=,
                                 * since they all support the private/ symlink logic at least in some
                                 * configurations, see above. */

                                r = chase(target, NULL, 0, &target_resolved, NULL);
                                if (r < 0)
                                        goto fail;

                                q = path_join(params->prefix[type], "private", i->path);
                                if (!q) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                /* /var/lib or friends may be symlinks. So, let's chase them also. */
                                r = chase(q, NULL, CHASE_NONEXISTENT, &q_resolved, NULL);
                                if (r < 0)
                                        goto fail;

                                if (path_equal(q_resolved, target_resolved)) {

                                        /* Hmm, apparently DynamicUser= was once turned on for this service,
                                         * but is no longer. Let's move the directory back up. */

                                        log_info("Found pre-existing private %s= directory %s, migrating to %s.\n"
                                                 "Apparently, service previously had DynamicUser= turned on, and has now turned it off.",
                                                 exec_directory_type_to_string(type), q, p);

                                        r = RET_NERRNO(unlink(p));
                                        if (r < 0)
                                                goto fail;

                                        r = RET_NERRNO(rename(q, p));
                                        if (r < 0)
                                                goto fail;
                                }
                        }

                        r = mkdir_label(p, context->directories[type].mode);
                        if (r < 0) {
                                if (r != -EEXIST)
                                        goto fail;

                                if (!EXEC_DIRECTORY_TYPE_SHALL_CHOWN(type)) {
                                        struct stat st;

                                        /* Don't change the owner/access mode of the configuration directory,
                                         * as in the common case it is not written to by a service, and shall
                                         * not be writable. */

                                        r = RET_NERRNO(stat(p, &st));
                                        if (r < 0)
                                                goto fail;

                                        /* Still complain if the access mode doesn't match */
                                        if (((st.st_mode ^ context->directories[type].mode) & 07777) != 0)
                                                log_warning("%s \'%s\' already exists but the mode is different. "
                                                            "(File system: %o %sMode: %o)",
                                                            exec_directory_type_to_string(type), i->path,
                                                            st.st_mode & 07777, exec_directory_type_to_string(type), context->directories[type].mode & 07777);

                                        continue;
                                }
                        }
                }

                /* Lock down the access mode (we use chmod_and_chown() to make this idempotent. We don't
                 * specify UID/GID here, so that path_chown_recursive() can optimize things depending on the
                 * current UID/GID ownership.) */
                const char *target_dir = pp ?: p;
                r = chmod_and_chown(target_dir, context->directories[type].mode, UID_INVALID, GID_INVALID);
                if (r < 0)
                        goto fail;

                /* Skip the rest (which deals with ownership) in user mode, since ownership changes are not
                 * available to user code anyway */
                if (params->runtime_scope != RUNTIME_SCOPE_SYSTEM)
                        continue;

                int idmapping_supported = is_idmapping_supported(target_dir);
                if (idmapping_supported < 0) {
                        r = log_debug_errno(idmapping_supported, "Unable to determine if ID mapping is supported on mount '%s': %m", target_dir);
                        goto fail;
                }

                log_debug("ID-mapping is%ssupported for exec directory %s", idmapping_supported ? " " : " not ", target_dir);

                /* Change the ownership of the whole tree, if necessary. When dynamic users are used we
                 * drop the suid/sgid bits, since we really don't want SUID/SGID files for dynamic UID/GID
                 * assignments to exist. */
                uid_t chown_uid = uid;
                gid_t chown_gid = gid;
                bool do_chown = false;

                if (uid == 0 || gid == 0 || !idmapping_supported) {
                        do_chown = true;
                        i->idmapped = false;
                } else {
                        /* Use 'nobody' uid/gid for exec directories if ID-mapping is supported. For backward compatibility,
                         * continue doing chmod/chown if the directory was chmod/chowned before (if uid/gid is not 'nobody') */
                        struct stat st;
                        r = RET_NERRNO(stat(target_dir, &st));
                        if (r < 0)
                                goto fail;

                        if (st.st_uid == UID_NOBODY && st.st_gid == GID_NOBODY) {
                                do_chown = false;
                                i->idmapped = true;
                       } else if (exec_directory_is_private(context, type) && st.st_uid == 0 && st.st_gid == 0) {
                                chown_uid = UID_NOBODY;
                                chown_gid = GID_NOBODY;
                                do_chown = true;
                                i->idmapped = true;
                        } else {
                                do_chown = true;
                                i->idmapped = false;
                        }
                }

                if (do_chown) {
                        r = path_chown_recursive(target_dir, chown_uid, chown_gid, context->dynamic_user ? 01777 : 07777, AT_SYMLINK_FOLLOW);
                        if (r < 0)
                                goto fail;
                }

                /* Apply storage quotas and accounting */
                r = apply_exec_quotas(target_dir, params->cgroup_path, type, &context->directories[type].exec_quota, &exec_dt_proj_id, &quota_already_enforced);
                if (r < 0)
                        goto fail;
        }

        /* If we are not going to run in a namespace, set up the symlinks - otherwise
         * they are set up later, to allow configuring empty var/run/etc. */
        if (!needs_mount_namespace)
                FOREACH_ARRAY(i, context->directories[type].items, context->directories[type].n_items) {
                        r = create_many_symlinks(params->prefix[type], i->path, i->symlinks);
                        if (r < 0)
                                goto fail;
                }

        return 0;

fail:
        *exit_status = exit_status_table[type];
        return r;
}

#if ENABLE_SMACK
static int setup_smack(
                const ExecContext *context,
                const ExecParameters *params,
                int executable_fd) {
        int r;

        assert(context);
        assert(params);
        assert(executable_fd >= 0);

        if (context->smack_process_label) {
                r = mac_smack_apply_pid(0, context->smack_process_label);
                if (r < 0)
                        return r;
        } else if (params->fallback_smack_process_label) {
                _cleanup_free_ char *exec_label = NULL;

                r = mac_smack_read_fd(executable_fd, SMACK_ATTR_EXEC, &exec_label);
                if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                        return r;

                r = mac_smack_apply_pid(0, exec_label ?: params->fallback_smack_process_label);
                if (r < 0)
                        return r;
        }

        return 0;
}
#endif

static int compile_bind_mounts(
                const ExecContext *context,
                const ExecParameters *params,
                uid_t exec_directory_uid, /* only used for id-mapped mounts Exec directories */
                gid_t exec_directory_gid, /* only used for id-mapped mounts Exec directories */
                BindMount **ret_bind_mounts,
                size_t *ret_n_bind_mounts,
                char ***ret_empty_directories) {

        _cleanup_strv_free_ char **empty_directories = NULL;
        BindMount *bind_mounts = NULL;
        size_t n, h = 0;
        int r;

        assert(context);
        assert(params);
        assert(ret_bind_mounts);
        assert(ret_n_bind_mounts);
        assert(ret_empty_directories);

        CLEANUP_ARRAY(bind_mounts, h, bind_mount_free_many);

        n = context->n_bind_mounts;
        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!params->prefix[t])
                        continue;

                FOREACH_ARRAY(i, context->directories[t].items, context->directories[t].n_items)
                        n += !FLAGS_SET(i->flags, EXEC_DIRECTORY_ONLY_CREATE) || FLAGS_SET(i->flags, EXEC_DIRECTORY_READ_ONLY);
        }

        if (n <= 0) {
                *ret_bind_mounts = NULL;
                *ret_n_bind_mounts = 0;
                *ret_empty_directories = NULL;
                return 0;
        }

        bind_mounts = new(BindMount, n);
        if (!bind_mounts)
                return -ENOMEM;

        FOREACH_ARRAY(item, context->bind_mounts, context->n_bind_mounts) {
                r = bind_mount_add(&bind_mounts, &h, item);
                if (r < 0)
                        return r;
        }

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!params->prefix[t])
                        continue;

                if (context->directories[t].n_items == 0)
                        continue;

                if (exec_directory_is_private(context, t) &&
                    !exec_context_with_rootfs(context)) {
                        char *private_root;

                        /* So this is for a dynamic user, and we need to make sure the process can access its own
                         * directory. For that we overmount the usually inaccessible "private" subdirectory with a
                         * tmpfs that makes it accessible and is empty except for the submounts we do this for. */

                        private_root = path_join(params->prefix[t], "private");
                        if (!private_root)
                                return -ENOMEM;

                        r = strv_consume(&empty_directories, private_root);
                        if (r < 0)
                                return r;
                }

                FOREACH_ARRAY(i, context->directories[t].items, context->directories[t].n_items) {
                        _cleanup_free_ char *s = NULL, *d = NULL;

                        /* When one of the parent directories is in the list, we cannot create the symlink
                         * for the child directory. See also the comments in setup_exec_directory().
                         * But if it needs to be read only, then we have to create a bind mount anyway to
                         * make it so. */
                        if (FLAGS_SET(i->flags, EXEC_DIRECTORY_ONLY_CREATE) && !FLAGS_SET(i->flags, EXEC_DIRECTORY_READ_ONLY))
                                continue;

                        if (exec_directory_is_private(context, t))
                                s = path_join(params->prefix[t], "private", i->path);
                        else
                                s = path_join(params->prefix[t], i->path);
                        if (!s)
                                return -ENOMEM;

                        if (exec_directory_is_private(context, t) &&
                            exec_context_with_rootfs(context))
                                /* When RootDirectory= or RootImage= are set, then the symbolic link to the private
                                 * directory is not created on the root directory. So, let's bind-mount the directory
                                 * on the 'non-private' place. */
                                d = path_join(params->prefix[t], i->path);
                        else
                                d = strdup(s);
                        if (!d)
                                return -ENOMEM;

                        bind_mounts[h++] = (BindMount) {
                                .source = TAKE_PTR(s),
                                .destination = TAKE_PTR(d),
                                .nosuid = context->dynamic_user, /* don't allow suid/sgid when DynamicUser= is on */
                                .recursive = true,
                                .read_only = FLAGS_SET(i->flags, EXEC_DIRECTORY_READ_ONLY),
                                .idmapped = i->idmapped,
                                .uid = exec_directory_uid,
                                .gid = exec_directory_gid,
                        };
                }
        }

        assert(h == n);

        *ret_bind_mounts = TAKE_PTR(bind_mounts);
        *ret_n_bind_mounts = n;
        *ret_empty_directories = TAKE_PTR(empty_directories);

        return (int) n;
}

/* ret_symlinks will contain a list of pairs src:dest that describes
 * the symlinks to create later on. For example, the symlinks needed
 * to safely give private directories to DynamicUser=1 users. */
static int compile_symlinks(
                const ExecContext *context,
                const ExecParameters *params,
                bool setup_os_release_symlink,
                char ***ret_symlinks) {

        _cleanup_strv_free_ char **symlinks = NULL;
        int r;

        assert(context);
        assert(params);
        assert(ret_symlinks);

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++)
                FOREACH_ARRAY(i, context->directories[dt].items, context->directories[dt].n_items) {
                        _cleanup_free_ char *private_path = NULL, *path = NULL;

                        STRV_FOREACH(symlink, i->symlinks) {
                                _cleanup_free_ char *src_abs = NULL, *dst_abs = NULL;

                                src_abs = path_join(params->prefix[dt], i->path);
                                dst_abs = path_join(params->prefix[dt], *symlink);
                                if (!src_abs || !dst_abs)
                                        return -ENOMEM;

                                r = strv_consume_pair(&symlinks, TAKE_PTR(src_abs), TAKE_PTR(dst_abs));
                                if (r < 0)
                                        return r;
                        }

                        if (!exec_directory_is_private(context, dt) ||
                            exec_context_with_rootfs(context) ||
                            FLAGS_SET(i->flags, EXEC_DIRECTORY_ONLY_CREATE))
                                continue;

                        private_path = path_join(params->prefix[dt], "private", i->path);
                        if (!private_path)
                                return -ENOMEM;

                        path = path_join(params->prefix[dt], i->path);
                        if (!path)
                                return -ENOMEM;

                        r = strv_consume_pair(&symlinks, TAKE_PTR(private_path), TAKE_PTR(path));
                        if (r < 0)
                                return r;
                }

        /* We make the host's os-release available via a symlink, so that we can copy it atomically
         * and readers will never get a half-written version. Note that, while the paths specified here are
         * absolute, when they are processed in namespace.c they will be made relative automatically, i.e.:
         * 'os-release -> .os-release-stage/os-release' is what will be created. */
        if (setup_os_release_symlink) {
                r = strv_extend_many(
                                &symlinks,
                                "/run/host/.os-release-stage/os-release",
                                "/run/host/os-release");
                if (r < 0)
                        return r;
        }

        *ret_symlinks = TAKE_PTR(symlinks);

        return 0;
}

static bool insist_on_sandboxing(
                const ExecContext *context,
                const char *root_dir,
                const char *root_image,
                const BindMount *bind_mounts,
                size_t n_bind_mounts) {

        assert(context);
        assert(n_bind_mounts == 0 || bind_mounts);

        /* Checks whether we need to insist on fs namespacing. i.e. whether we have settings configured that
         * would alter the view on the file system beyond making things read-only or invisible, i.e. would
         * rearrange stuff in a way we cannot ignore gracefully. */

        if (context->n_temporary_filesystems > 0)
                return true;

        if (root_dir || root_image || context->root_directory_as_fd)
                return true;

        if (context->n_mount_images > 0)
                return true;

        if (context->dynamic_user)
                return true;

        if (context->n_extension_images > 0 || !strv_isempty(context->extension_directories))
                return true;

        /* If there are any bind mounts set that don't map back onto themselves, fs namespacing becomes
         * essential. */
        FOREACH_ARRAY(i, bind_mounts, n_bind_mounts)
                if (!path_equal(i->source, i->destination))
                        return true;

        if (context->log_namespace)
                return true;

        return false;
}

static int setup_ephemeral(
                const ExecContext *context,
                ExecRuntime *runtime,
                char **root_image,            /* both input and output! modified if ephemeral logic enabled */
                char **root_directory,        /* ditto */
                char **reterr_path) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *new_root = NULL;
        int r;

        assert(context);
        assert(!context->root_directory_as_fd);
        assert(runtime);
        assert(root_image);
        assert(root_directory);

        if (!*root_image && !*root_directory)
                return 0;

        if (!runtime->ephemeral_copy)
                return 0;

        assert(runtime->ephemeral_storage_socket[0] >= 0);
        assert(runtime->ephemeral_storage_socket[1] >= 0);

        new_root = strdup(runtime->ephemeral_copy);
        if (!new_root)
                return log_oom_debug();

        r = posix_lock(runtime->ephemeral_storage_socket[0], LOCK_EX);
        if (r < 0)
                return log_debug_errno(r, "Failed to lock ephemeral storage socket: %m");

        CLEANUP_POSIX_UNLOCK(runtime->ephemeral_storage_socket[0]);

        fd = receive_one_fd(runtime->ephemeral_storage_socket[0], MSG_PEEK|MSG_DONTWAIT);
        if (fd >= 0)
                /* We got an fd! That means ephemeral has already been set up, so nothing to do here. */
                return 0;
        if (fd != -EAGAIN)
                return log_debug_errno(fd, "Failed to receive file descriptor queued on ephemeral storage socket: %m");

        if (*root_image) {
                log_debug("Making ephemeral copy of %s to %s", *root_image, new_root);

                fd = copy_file(*root_image, new_root, O_EXCL, 0600,
                               COPY_LOCK_BSD|COPY_REFLINK|COPY_CRTIME|COPY_NOCOW_AFTER);
                if (fd < 0) {
                        *reterr_path = strdup(*root_image);
                        return log_debug_errno(fd, "Failed to copy image %s to %s: %m",
                                               *root_image, new_root);
                }
        } else {
                assert(*root_directory);

                log_debug("Making ephemeral snapshot of %s to %s", *root_directory, new_root);

                fd = btrfs_subvol_snapshot_at(
                                AT_FDCWD, *root_directory,
                                AT_FDCWD, new_root,
                                BTRFS_SNAPSHOT_FALLBACK_COPY |
                                BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                BTRFS_SNAPSHOT_RECURSIVE |
                                BTRFS_SNAPSHOT_LOCK_BSD);
                if (fd < 0) {
                        *reterr_path = strdup(*root_directory);
                        return log_debug_errno(fd, "Failed to snapshot directory %s to %s: %m",
                                               *root_directory, new_root);
                }
        }

        r = send_one_fd(runtime->ephemeral_storage_socket[1], fd, MSG_DONTWAIT);
        if (r < 0)
                return log_debug_errno(r, "Failed to queue file descriptor on ephemeral storage socket: %m");

        if (*root_image)
                free_and_replace(*root_image, new_root);
        else {
                assert(*root_directory);
                free_and_replace(*root_directory, new_root);
        }

        return 1;
}

static int verity_settings_prepare(
                VeritySettings *verity,
                const char *root_image,
                const struct iovec *root_hash,
                const char *root_hash_path,
                const struct iovec *root_hash_sig,
                const char *root_hash_sig_path,
                const char *verity_data_path) {

        int r;

        assert(verity);

        if (root_hash) {
                iovec_done(&verity->root_hash);

                if (!iovec_memdup(root_hash, &verity->root_hash))
                        return -ENOMEM;

                verity->designator = PARTITION_ROOT;
        }

        if (root_hash_sig) {
                iovec_done(&verity->root_hash_sig);

                if (!iovec_memdup(root_hash_sig, &verity->root_hash_sig))
                        return -ENOMEM;

                verity->designator = PARTITION_ROOT;
        }

        if (verity_data_path) {
                r = free_and_strdup(&verity->data_path, verity_data_path);
                if (r < 0)
                        return r;
        }

        r = verity_settings_load(
                        verity,
                        root_image,
                        root_hash_path,
                        root_hash_sig_path);
        if (r < 0)
                return log_debug_errno(r, "Failed to load root hash: %m");

        return 0;
}

static int pick_versions(
                const ExecContext *context,
                const ExecParameters *params,
                char **ret_root_image,
                char **ret_root_directory,
                char **reterr_path) {

        int r;

        assert(context);
        assert(!context->root_directory_as_fd);
        assert(params);
        assert(ret_root_image);
        assert(ret_root_directory);

        if (context->root_image) {
                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              context->root_image,
                              pick_filter_image_raw,
                              ELEMENTSOF(pick_filter_image_raw),
                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                              &result);
                if (r < 0) {
                        *reterr_path = strdup(context->root_image);
                        return r;
                }

                if (!result.path) {
                        *reterr_path = strdup(context->root_image);
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "No matching entry in .v/ directory %s found.", context->root_image);
                }

                *ret_root_image = TAKE_PTR(result.path);
                *ret_root_directory = NULL;
                return r;
        }

        if (context->root_directory) {
                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              context->root_directory,
                              pick_filter_image_dir,
                              ELEMENTSOF(pick_filter_image_dir),
                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                              &result);
                if (r < 0) {
                        *reterr_path = strdup(context->root_directory);
                        return r;
                }

                if (!result.path) {
                        *reterr_path = strdup(context->root_directory);
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "No matching entry in .v/ directory %s found.", context->root_directory);
                }

                *ret_root_image = NULL;
                *ret_root_directory = TAKE_PTR(result.path);
                return r;
        }

        *ret_root_image = *ret_root_directory = NULL;
        return 0;
}

static int apply_mount_namespace(
                ExecCommandFlags command_flags,
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                const char *memory_pressure_path,
                bool needs_sandboxing,
                uid_t exec_directory_uid,
                gid_t exec_directory_gid,
                PidRef *bpffs_pidref,
                int bpffs_socket_fd,
                int bpffs_errno_pipe,
                char **reterr_path) {

        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        _cleanup_strv_free_ char **empty_directories = NULL, **symlinks = NULL,
                        **read_write_paths_cleanup = NULL;
        _cleanup_free_ char *creds_path = NULL, *incoming_dir = NULL, *propagate_dir = NULL,
                *private_namespace_dir = NULL, *host_os_release_stage = NULL, *root_image = NULL, *root_dir = NULL;
        const char *tmp_dir = NULL, *var_tmp_dir = NULL;
        char **read_write_paths;
        bool setup_os_release_symlink;
        BindMount *bind_mounts = NULL;
        size_t n_bind_mounts = 0;
        int r;

        assert(context);
        assert(params);
        assert(runtime);

        CLEANUP_ARRAY(bind_mounts, n_bind_mounts, bind_mount_free_many);

        if (params->flags & EXEC_APPLY_CHROOT && !context->root_directory_as_fd) {
                r = pick_versions(
                                context,
                                params,
                                &root_image,
                                &root_dir,
                                reterr_path);
                if (r < 0)
                        return r;

                r = setup_ephemeral(
                                context,
                                runtime,
                                &root_image,
                                &root_dir,
                                reterr_path);
                if (r < 0)
                        return r;
        }

        r = compile_bind_mounts(context, params, exec_directory_uid, exec_directory_gid, &bind_mounts, &n_bind_mounts, &empty_directories);
        if (r < 0)
                return r;

        /* We need to make the pressure path writable even if /sys/fs/cgroups is made read-only, as the
         * service will need to write to it in order to start the notifications. */
        if (exec_is_cgroup_mount_read_only(context) && memory_pressure_path && !streq(memory_pressure_path, "/dev/null")) {
                read_write_paths_cleanup = strv_copy(context->read_write_paths);
                if (!read_write_paths_cleanup)
                        return -ENOMEM;

                r = strv_extend(&read_write_paths_cleanup, memory_pressure_path);
                if (r < 0)
                        return r;

                read_write_paths = read_write_paths_cleanup;
        } else
                read_write_paths = context->read_write_paths;

        if (needs_sandboxing) {
                /* The runtime struct only contains the parent of the private /tmp, which is non-accessible
                 * to world users. Inside of it there's a /tmp that is sticky, and that's the one we want to
                 * use here.  This does not apply when we are using /run/systemd/empty as fallback. */

                if (context->private_tmp == PRIVATE_TMP_CONNECTED && runtime->shared) {
                        if (streq_ptr(runtime->shared->tmp_dir, RUN_SYSTEMD_EMPTY))
                                tmp_dir = runtime->shared->tmp_dir;
                        else if (runtime->shared->tmp_dir)
                                tmp_dir = strjoina(runtime->shared->tmp_dir, "/tmp");

                        if (streq_ptr(runtime->shared->var_tmp_dir, RUN_SYSTEMD_EMPTY))
                                var_tmp_dir = runtime->shared->var_tmp_dir;
                        else if (runtime->shared->var_tmp_dir)
                                var_tmp_dir = strjoina(runtime->shared->var_tmp_dir, "/tmp");
                }
        }

        /* Symlinks (exec dirs, os-release) are set up after other mounts, before they are made read-only. */
        setup_os_release_symlink = needs_sandboxing && exec_context_get_effective_mount_apivfs(context) && (root_dir || root_image);
        r = compile_symlinks(context, params, setup_os_release_symlink, &symlinks);
        if (r < 0)
                return r;

        if (context->mount_propagation_flag == MS_SHARED)
                log_debug("shared mount propagation hidden by other fs namespacing unit settings: ignoring");

        r = exec_context_get_credential_directory(context, params, params->unit_id, &creds_path);
        if (r < 0)
                return r;

        if (params->runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                if (!mount_new_api_supported()) {
                        propagate_dir = path_join("/run/systemd/propagate/", params->unit_id);
                        if (!propagate_dir)
                                return -ENOMEM;

                        incoming_dir = strdup("/run/systemd/incoming");
                        if (!incoming_dir)
                                return -ENOMEM;
                }

                private_namespace_dir = strdup("/run/systemd");
                if (!private_namespace_dir)
                        return -ENOMEM;

                /* If running under a different root filesystem, propagate the host's os-release. We make a
                 * copy rather than just bind mounting it, so that it can be updated on soft-reboot. */
                if (setup_os_release_symlink) {
                        host_os_release_stage = strdup("/run/systemd/propagate/.os-release-stage");
                        if (!host_os_release_stage)
                                return -ENOMEM;
                }
        } else {
                assert(params->runtime_scope == RUNTIME_SCOPE_USER);

                if (asprintf(&private_namespace_dir, "/run/user/" UID_FMT "/systemd", geteuid()) < 0)
                        return -ENOMEM;

                if (setup_os_release_symlink &&
                    asprintf(&host_os_release_stage,
                             "/run/user/" UID_FMT "/systemd/propagate/.os-release-stage",
                             geteuid()) < 0)
                        return -ENOMEM;
        }

        if (root_image) {
                r = verity_settings_prepare(
                        &verity,
                        root_image,
                        &context->root_hash, context->root_hash_path,
                        &context->root_hash_sig, context->root_hash_sig_path,
                        context->root_verity);
                if (r < 0)
                        return r;
        }

        NamespaceParameters parameters = {
                .runtime_scope = params->runtime_scope,

                .root_directory = root_dir,
                .root_image = root_image,
                .root_directory_fd = params->flags & EXEC_APPLY_CHROOT ? params->root_directory_fd : -EBADF,
                .root_image_options = context->root_image_options,
                .root_image_policy = context->root_image_policy ?: &image_policy_service,

                .read_write_paths = read_write_paths,
                .read_only_paths = needs_sandboxing ? context->read_only_paths : NULL,
                .inaccessible_paths = needs_sandboxing ? context->inaccessible_paths : NULL,

                .exec_paths = needs_sandboxing ? context->exec_paths : NULL,
                .no_exec_paths = needs_sandboxing ? context->no_exec_paths : NULL,

                .empty_directories = empty_directories,
                .symlinks = symlinks,

                .bind_mounts = bind_mounts,
                .n_bind_mounts = n_bind_mounts,

                .temporary_filesystems = context->temporary_filesystems,
                .n_temporary_filesystems = context->n_temporary_filesystems,

                .mount_images = context->mount_images,
                .n_mount_images = context->n_mount_images,
                .mount_image_policy = context->mount_image_policy ?: &image_policy_service,

                .tmp_dir = tmp_dir,
                .var_tmp_dir = var_tmp_dir,

                .creds_path = creds_path,
                .log_namespace = context->log_namespace,
                .mount_propagation_flag = context->mount_propagation_flag,

                .verity = &verity,

                .extension_images = context->extension_images,
                .n_extension_images = context->n_extension_images,
                .extension_image_policy = context->extension_image_policy ?: &image_policy_sysext,
                .extension_directories = context->extension_directories,

                .propagate_dir = propagate_dir,
                .incoming_dir = incoming_dir,
                .private_namespace_dir = private_namespace_dir,
                .host_notify_socket = params->notify_socket,
                .notify_socket_path = exec_get_private_notify_socket_path(context, params, needs_sandboxing),
                .host_os_release_stage = host_os_release_stage,

                /* If DynamicUser=no and RootDirectory= is set then lets pass a relaxed sandbox info,
                 * otherwise enforce it, don't ignore protected paths and fail if we are enable to apply the
                 * sandbox inside the mount namespace. */
                .ignore_protect_paths = !needs_sandboxing && !context->dynamic_user && root_dir,

                .protect_control_groups = needs_sandboxing ? exec_get_protect_control_groups(context) : PROTECT_CONTROL_GROUPS_NO,
                .protect_kernel_tunables = needs_sandboxing && context->protect_kernel_tunables,
                .protect_kernel_modules = needs_sandboxing && context->protect_kernel_modules,
                .protect_kernel_logs = needs_sandboxing && context->protect_kernel_logs,

                .private_dev = needs_sandboxing && context->private_devices,
                .private_network = needs_sandboxing && exec_needs_network_namespace(context),
                .private_ipc = needs_sandboxing && exec_needs_ipc_namespace(context),
                .private_pids = needs_sandboxing && exec_needs_pid_namespace(context, params) ? context->private_pids : PRIVATE_PIDS_NO,
                .private_tmp = needs_sandboxing ? context->private_tmp : PRIVATE_TMP_NO,
                .private_var_tmp = needs_sandboxing ? context->private_var_tmp : PRIVATE_TMP_NO,

                .mount_apivfs = needs_sandboxing && exec_context_get_effective_mount_apivfs(context),
                .bind_log_sockets = needs_sandboxing && exec_context_get_effective_bind_log_sockets(context),

                /* If NNP is on, we can turn on MS_NOSUID, since it won't have any effect anymore. */
                .mount_nosuid = needs_sandboxing && context->no_new_privileges && !mac_selinux_use(),

                .protect_home = needs_sandboxing ? context->protect_home : PROTECT_HOME_NO,
                .protect_hostname = needs_sandboxing ? context->protect_hostname : PROTECT_HOSTNAME_NO,
                .protect_system = needs_sandboxing ? context->protect_system : PROTECT_SYSTEM_NO,
                .protect_proc = needs_sandboxing ? context->protect_proc : PROTECT_PROC_DEFAULT,
                .proc_subset = needs_sandboxing ? context->proc_subset : PROC_SUBSET_ALL,
                .private_bpf = needs_sandboxing ? context->private_bpf : PRIVATE_BPF_NO,

                .bpffs_pidref = bpffs_pidref,
                .bpffs_socket_fd = bpffs_socket_fd,
                .bpffs_errno_pipe = bpffs_errno_pipe,
        };

        r = setup_namespace(&parameters, reterr_path);
        /* If we couldn't set up the namespace this is probably due to a missing capability. setup_namespace() reports
         * that with a special, recognizable error ENOANO. In this case, silently proceed, but only if exclusively
         * sandboxing options were used, i.e. nothing such as RootDirectory= or BindMount= that would result in a
         * completely different execution environment. */
        if (r == -ENOANO) {
                if (insist_on_sandboxing(
                                    context,
                                    root_dir, root_image,
                                    bind_mounts,
                                    n_bind_mounts))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Failed to set up namespace, and refusing to continue since "
                                               "the selected namespacing options alter mount environment non-trivially.\n"
                                               "Bind mounts: %zu, temporary filesystems: %zu, root directory: %s, root image: %s, dynamic user: %s",
                                               n_bind_mounts,
                                               context->n_temporary_filesystems,
                                               yes_no(root_dir),
                                               yes_no(root_image),
                                               yes_no(context->dynamic_user));

                log_debug("Failed to set up namespace, assuming containerized execution and ignoring.");
                return 0;
        }

        return r;
}

static int apply_working_directory(
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                const char *pwent_home,
                char * const *env) {

        const char *wd;
        int r;

        assert(context);
        assert(params);
        assert(runtime);

        if (context->working_directory_home) {
                /* Preferably use the data from $HOME, in case it was updated by a PAM module */
                wd = strv_env_get(env, "HOME");
                if (!wd) {
                        /* If that's not available, use the data from the struct passwd entry: */
                        if (!pwent_home)
                                return -ENXIO;

                        wd = pwent_home;
                }
        } else
                wd = empty_to_root(context->working_directory);

        if (params->flags & EXEC_APPLY_CHROOT)
                r = RET_NERRNO(chdir(wd));
        else {
                _cleanup_close_ int dfd = -EBADF;

                r = chase(wd,
                          runtime->ephemeral_copy ?: context->root_directory,
                          CHASE_PREFIX_ROOT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS,
                          /* ret_path= */ NULL,
                          &dfd);
                if (r >= 0)
                        r = RET_NERRNO(fchdir(dfd));
        }
        return context->working_directory_missing_ok ? 0 : r;
}

static int apply_root_directory(
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                const bool needs_mount_ns,
                int *exit_status) {

        assert(context);
        assert(params);
        assert(runtime);
        assert(exit_status);

        if (params->flags & EXEC_APPLY_CHROOT)
                if (!needs_mount_ns && context->root_directory)
                        if (chroot(runtime->ephemeral_copy ?: context->root_directory) < 0) {
                                *exit_status = EXIT_CHROOT;
                                return -errno;
                        }

        return 0;
}

static int setup_keyring(
                const ExecContext *context,
                const ExecParameters *p,
                uid_t uid,
                gid_t gid) {

        key_serial_t keyring;
        int r = 0;
        uid_t saved_uid;
        gid_t saved_gid;

        assert(context);
        assert(p);

        /* Let's set up a new per-service "session" kernel keyring for each system service. This has the benefit that
         * each service runs with its own keyring shared among all processes of the service, but with no hook-up beyond
         * that scope, and in particular no link to the per-UID keyring. If we don't do this the keyring will be
         * automatically created on-demand and then linked to the per-UID keyring, by the kernel. The kernel's built-in
         * on-demand behaviour is very appropriate for login users, but probably not so much for system services, where
         * UIDs are not necessarily specific to a service but reused (at least in the case of UID 0). */

        if (context->keyring_mode == EXEC_KEYRING_INHERIT)
                return 0;

        /* Acquiring a reference to the user keyring is nasty. We briefly change identity in order to get things set up
         * properly by the kernel. If we don't do that then we can't create it atomically, and that sucks for parallel
         * execution. This mimics what pam_keyinit does, too. Setting up session keyring, to be owned by the right user
         * & group is just as nasty as acquiring a reference to the user keyring. */

        saved_uid = getuid();
        saved_gid = getgid();

        if (gid_is_valid(gid) && gid != saved_gid) {
                if (setregid(gid, -1) < 0)
                        return log_error_errno(errno, "Failed to change GID for user keyring: %m");
        }

        if (uid_is_valid(uid) && uid != saved_uid) {
                if (setreuid(uid, -1) < 0) {
                        r = log_error_errno(errno, "Failed to change UID for user keyring: %m");
                        goto out;
                }
        }

        keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
        if (keyring == -1) {
                if (errno == ENOSYS)
                        log_debug_errno(errno, "Kernel keyring not supported, ignoring.");
                else if (ERRNO_IS_PRIVILEGE(errno))
                        log_debug_errno(errno, "Kernel keyring access prohibited, ignoring.");
                else if (errno == EDQUOT)
                        log_debug_errno(errno, "Out of kernel keyrings to allocate, ignoring.");
                else
                        r = log_error_errno(errno, "Setting up kernel keyring failed: %m");

                goto out;
        }

        /* When requested link the user keyring into the session keyring. */
        if (context->keyring_mode == EXEC_KEYRING_SHARED) {

                if (keyctl(KEYCTL_LINK,
                           KEY_SPEC_USER_KEYRING,
                           KEY_SPEC_SESSION_KEYRING, 0, 0) < 0) {
                        r = log_error_errno(errno, "Failed to link user keyring into session keyring: %m");
                        goto out;
                }
        }

        /* Restore uid/gid back */
        if (uid_is_valid(uid) && uid != saved_uid) {
                if (setreuid(saved_uid, -1) < 0) {
                        r = log_error_errno(errno, "Failed to change UID back for user keyring: %m");
                        goto out;
                }
        }

        if (gid_is_valid(gid) && gid != saved_gid) {
                if (setregid(saved_gid, -1) < 0)
                        return log_error_errno(errno, "Failed to change GID back for user keyring: %m");
        }

        /* Populate the keyring with the invocation ID by default, as original saved_uid. */
        if (!sd_id128_is_null(p->invocation_id)) {
                key_serial_t key;

                key = add_key("user",
                              "invocation_id",
                              &p->invocation_id,
                              sizeof(p->invocation_id),
                              KEY_SPEC_SESSION_KEYRING);
                if (key == -1)
                        log_debug_errno(errno, "Failed to add invocation ID to keyring, ignoring: %m");
                else {
                        if (keyctl(KEYCTL_SETPERM, key,
                                   KEY_POS_VIEW|KEY_POS_READ|KEY_POS_SEARCH|
                                   KEY_USR_VIEW|KEY_USR_READ|KEY_USR_SEARCH, 0, 0) < 0)
                                r = log_error_errno(errno, "Failed to restrict invocation ID permission: %m");
                }
        }

out:
        /* Revert back uid & gid for the last time, and exit */
        /* no extra logging, as only the first already reported error matters */
        if (getuid() != saved_uid)
                (void) setreuid(saved_uid, -1);

        if (getgid() != saved_gid)
                (void) setregid(saved_gid, -1);

        return r;
}

static void append_socket_pair(int *array, size_t *n, const int pair[static 2]) {
        assert(array);
        assert(n);
        assert(pair);

        if (pair[0] >= 0)
                array[(*n)++] = pair[0];
        if (pair[1] >= 0)
                array[(*n)++] = pair[1];
}

static int close_remaining_fds(
                const ExecParameters *params,
                const ExecRuntime *runtime,
                int socket_fd,
                const int *fds,
                size_t n_fds) {

        size_t n_dont_close = 0;
        int dont_close[n_fds + 17];

        assert(params);
        assert(runtime);

        if (params->stdin_fd >= 0)
                dont_close[n_dont_close++] = params->stdin_fd;
        if (params->stdout_fd >= 0)
                dont_close[n_dont_close++] = params->stdout_fd;
        if (params->stderr_fd >= 0)
                dont_close[n_dont_close++] = params->stderr_fd;

        if (socket_fd >= 0)
                dont_close[n_dont_close++] = socket_fd;
        if (n_fds > 0) {
                memcpy(dont_close + n_dont_close, fds, sizeof(int) * n_fds);
                n_dont_close += n_fds;
        }

        append_socket_pair(dont_close, &n_dont_close, runtime->ephemeral_storage_socket);

        if (runtime->shared) {
                append_socket_pair(dont_close, &n_dont_close, runtime->shared->userns_storage_socket);
                append_socket_pair(dont_close, &n_dont_close, runtime->shared->netns_storage_socket);
                append_socket_pair(dont_close, &n_dont_close, runtime->shared->ipcns_storage_socket);
        }

        if (runtime->dynamic_creds) {
                if (runtime->dynamic_creds->user)
                        append_socket_pair(dont_close, &n_dont_close, runtime->dynamic_creds->user->storage_socket);
                if (runtime->dynamic_creds->group)
                        append_socket_pair(dont_close, &n_dont_close, runtime->dynamic_creds->group->storage_socket);
        }

        if (params->user_lookup_fd >= 0)
                dont_close[n_dont_close++] = params->user_lookup_fd;

        if (params->handoff_timestamp_fd >= 0)
                dont_close[n_dont_close++] = params->handoff_timestamp_fd;

        if (params->pidref_transport_fd >= 0)
                dont_close[n_dont_close++] = params->pidref_transport_fd;

        assert(n_dont_close <= ELEMENTSOF(dont_close));

        return close_all_fds(dont_close, n_dont_close);
}

static int send_user_lookup(
                const char *unit_id,
                int user_lookup_fd,
                uid_t uid,
                gid_t gid) {

        assert(unit_id);

        /* Send the resolved UID/GID to PID 1 after we learnt it. We send a single datagram, containing the UID/GID
         * data as well as the unit name. Note that we suppress sending this if no user/group to resolve was
         * specified. */

        if (user_lookup_fd < 0)
                return 0;

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        if (writev(user_lookup_fd,
               (struct iovec[]) {
                           IOVEC_MAKE(&uid, sizeof(uid)),
                           IOVEC_MAKE(&gid, sizeof(gid)),
                           IOVEC_MAKE_STRING(unit_id) }, 3) < 0)
                return -errno;

        return 0;
}

static int acquire_home(const ExecContext *c, const char **home, char **ret_buf) {
        int r;

        assert(c);
        assert(home);
        assert(ret_buf);

        /* If WorkingDirectory=~ is set, try to acquire a usable home directory. */

        if (*home) /* Already acquired from get_fixed_user()? */
                return 0;

        if (!c->working_directory_home)
                return 0;

        if (c->dynamic_user || (c->user && is_this_me(c->user) <= 0))
                return -EADDRNOTAVAIL;

        r = get_home_dir(ret_buf);
        if (r < 0)
                return r;

        *home = *ret_buf;
        return 1;
}

static int compile_suggested_paths(const ExecContext *c, const ExecParameters *p, char ***ret) {
        _cleanup_strv_free_ char ** list = NULL;
        int r;

        assert(c);
        assert(p);
        assert(ret);

        assert(c->dynamic_user);

        /* Compile a list of paths that it might make sense to read the owning UID from to use as initial candidate for
         * dynamic UID allocation, in order to save us from doing costly recursive chown()s of the special
         * directories. */

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {

                if (!EXEC_DIRECTORY_TYPE_SHALL_CHOWN(t))
                        continue;

                if (!p->prefix[t])
                        continue;

                for (size_t i = 0; i < c->directories[t].n_items; i++) {
                        char *e;

                        if (exec_directory_is_private(c, t))
                                e = path_join(p->prefix[t], "private", c->directories[t].items[i].path);
                        else
                                e = path_join(p->prefix[t], c->directories[t].items[i].path);
                        if (!e)
                                return -ENOMEM;

                        r = strv_consume(&list, e);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(list);

        return 0;
}

static int exec_context_cpu_affinity_from_numa(const ExecContext *c, CPUSet *ret) {
        int r;

        assert(c);
        assert(ret);

        if (!c->numa_policy.nodes.set) {
                log_debug("Can't derive CPU affinity mask from NUMA mask because NUMA mask is not set, ignoring");
                *ret = (CPUSet) {};
                return 0;
        }

        _cleanup_(cpu_set_done) CPUSet s = {};
        r = numa_to_cpu_set(&c->numa_policy, &s);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(s);
        return 0;
}

static int add_shifted_fd(int **fds, size_t *n_fds, int *fd) {
        int r;

        assert(fds);
        assert(n_fds);
        assert(fd);

        if (*fd < 0)
               return 0;

        if (*fd < 3 + (int) *n_fds) {
                /* Let's move the fd up, so that it's outside of the fd range we will use to store
                 * the fds we pass to the process (or which are closed only during execve). */

                r = fcntl(*fd, F_DUPFD_CLOEXEC, 3 + (int) *n_fds);
                if (r < 0)
                        return -errno;

                close_and_replace(*fd, r);
        }

        if (!GREEDY_REALLOC(*fds, *n_fds + 1))
                return -ENOMEM;

        (*fds)[(*n_fds)++] = *fd;
        return 1;
}

static int connect_unix_harder(const OpenFile *of, int ofd) {
        static const int socket_types[] = { SOCK_DGRAM, SOCK_STREAM, SOCK_SEQPACKET };

        union sockaddr_union addr = {
                .un.sun_family = AF_UNIX,
        };
        socklen_t sa_len;
        int r;

        assert(of);
        assert(ofd >= 0);

        r = sockaddr_un_set_path(&addr.un, FORMAT_PROC_FD_PATH(ofd));
        if (r < 0)
                return log_debug_errno(r, "Failed to set sockaddr for '%s': %m", of->path);
        sa_len = r;

        FOREACH_ELEMENT(i, socket_types) {
                _cleanup_close_ int fd = -EBADF;

                fd = socket(AF_UNIX, *i|SOCK_CLOEXEC, 0);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to create socket for '%s': %m", of->path);

                r = RET_NERRNO(connect(fd, &addr.sa, sa_len));
                if (r >= 0)
                        return TAKE_FD(fd);
                if (r != -EPROTOTYPE)
                        return log_debug_errno(r, "Failed to connect to socket for '%s': %m", of->path);
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EPROTOTYPE), "No suitable socket type to connect to socket '%s'.", of->path);
}

static int get_open_file_fd(const OpenFile *of) {
        _cleanup_close_ int fd = -EBADF, ofd = -EBADF;
        struct stat st;

        assert(of);

        ofd = open(of->path, O_PATH | O_CLOEXEC);
        if (ofd < 0)
                return log_debug_errno(errno, "Failed to open '%s' as O_PATH: %m", of->path);

        if (fstat(ofd, &st) < 0)
                return log_debug_errno( errno, "Failed to stat '%s': %m", of->path);

        if (S_ISSOCK(st.st_mode)) {
                fd = connect_unix_harder(of, ofd);
                if (fd < 0)
                        return fd;

                if (FLAGS_SET(of->flags, OPENFILE_READ_ONLY) && shutdown(fd, SHUT_WR) < 0)
                        return log_debug_errno(errno, "Failed to shutdown send for socket '%s': %m", of->path);

                log_debug("Opened socket '%s' as fd %d.", of->path, fd);
        } else {
                int flags = FLAGS_SET(of->flags, OPENFILE_READ_ONLY) ? O_RDONLY : O_RDWR;
                if (FLAGS_SET(of->flags, OPENFILE_APPEND))
                        flags |= O_APPEND;
                else if (FLAGS_SET(of->flags, OPENFILE_TRUNCATE))
                        flags |= O_TRUNC;

                fd = fd_reopen(ofd, flags|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return log_debug_errno(fd, "Failed to reopen file '%s': %m", of->path);

                log_debug("Opened file '%s' as fd %d.", of->path, fd);
        }

        return TAKE_FD(fd);
}

static int collect_open_file_fds(ExecParameters *p) {
        assert(p);

        LIST_FOREACH(open_files, of, p->open_files) {
                _cleanup_close_ int fd = -EBADF;

                fd = get_open_file_fd(of);
                if (fd < 0) {
                        if (FLAGS_SET(of->flags, OPENFILE_GRACEFUL)) {
                                log_full_errno(fd == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(fd) ? LOG_DEBUG : LOG_WARNING,
                                               fd,
                                               "Failed to get OpenFile= file descriptor for '%s', ignoring: %m",
                                               of->path);
                                continue;
                        }

                        return log_error_errno(fd, "Failed to get OpenFile= file descriptor for '%s': %m", of->path);
                }

                if (!GREEDY_REALLOC(p->fds, p->n_socket_fds + p->n_stashed_fds + 1))
                        return log_oom();

                if (strv_extend(&p->fd_names, of->fdname) < 0)
                        return log_oom();

                p->fds[p->n_socket_fds + p->n_stashed_fds++] = TAKE_FD(fd);
        }

        return 0;
}

static void log_command_line(
                const ExecContext *context,
                const ExecParameters *params,
                const char *msg,
                const char *executable,
                char **argv) {

        assert(context);
        assert(params);
        assert(msg);
        assert(executable);

        if (!DEBUG_LOGGING)
                return;

        _cleanup_free_ char *cmdline = quote_command_line(argv, SHELL_ESCAPE_EMPTY);

        log_struct(LOG_DEBUG,
                   LOG_ITEM("EXECUTABLE=%s", executable),
                   LOG_EXEC_MESSAGE(params, "%s: %s", msg, strnull(cmdline)),
                   LOG_EXEC_INVOCATION_ID(params));
}

static bool exec_needs_cap_sys_admin(const ExecContext *context, const ExecParameters *params) {
        assert(context);
        assert(params);

        /* We only want to ever imply PrivateUsers= for user managers, as they're not expected to setuid() to
         * other users, unlike the system manager which needs all users to be around. */
        if (params->runtime_scope != RUNTIME_SCOPE_USER)
                return false;

        return context->private_users != PRIVATE_USERS_NO ||
               context->private_tmp != PRIVATE_TMP_NO ||
               context->private_devices ||
               context->private_network ||
               context->user_namespace_path ||
               context->network_namespace_path ||
               context->private_ipc ||
               context->ipc_namespace_path ||
               context->private_mounts > 0 ||
               context->mount_apivfs > 0 ||
               context->bind_log_sockets > 0 ||
               context->n_bind_mounts > 0 ||
               context->n_temporary_filesystems > 0 ||
               context->root_directory ||
               context->root_directory_as_fd ||
               !strv_isempty(context->extension_directories) ||
               context->root_image ||
               context->n_mount_images > 0 ||
               context->n_extension_images > 0 ||
               context->protect_system != PROTECT_SYSTEM_NO ||
               context->protect_home != PROTECT_HOME_NO ||
               exec_needs_pid_namespace(context, params) ||
               context->protect_kernel_tunables ||
               context->protect_kernel_modules ||
               context->protect_kernel_logs ||
               exec_needs_cgroup_mount(context) ||
               context->protect_clock ||
               context->protect_hostname != PROTECT_HOSTNAME_NO ||
               !strv_isempty(context->read_write_paths) ||
               !strv_isempty(context->read_only_paths) ||
               !strv_isempty(context->inaccessible_paths) ||
               !strv_isempty(context->exec_paths) ||
               !strv_isempty(context->no_exec_paths) ||
               context->delegate_namespaces != NAMESPACE_FLAGS_INITIAL;
}

static PrivateUsers exec_context_get_effective_private_users(
                const ExecContext *context,
                const ExecParameters *params) {

        assert(context);
        assert(params);

        if (context->private_users != PRIVATE_USERS_NO)
                return context->private_users;

        /* If any namespace is delegated with DelegateNamespaces=, always set up a user namespace. */
        if (context->delegate_namespaces != NAMESPACE_FLAGS_INITIAL)
                return PRIVATE_USERS_SELF;

        return PRIVATE_USERS_NO;
}

static bool exec_namespace_is_delegated(
                const ExecContext *context,
                const ExecParameters *params,
                bool have_cap_sys_admin,
                unsigned long namespace) {

        assert(context);
        assert(params);
        assert(namespace != CLONE_NEWUSER);

        /* If we need unprivileged private users, we've already unshared a user namespace by the time we call
         * setup_delegated_namespaces() for the first time so let's make sure we do all other namespace
         * unsharing in the first call to setup_delegated_namespaces() by returning false here. */
        if (!have_cap_sys_admin && exec_needs_cap_sys_admin(context, params))
                return false;

        if (context->delegate_namespaces == NAMESPACE_FLAGS_INITIAL)
                return params->runtime_scope == RUNTIME_SCOPE_USER;

        if (FLAGS_SET(context->delegate_namespaces, namespace))
                return true;

        /* Various namespaces imply mountns for private procfs/sysfs/cgroupfs instances, which means when
         * those are delegated mountns must be deferred too.
         *
         * The list should stay in sync with exec_needs_mount_namespace(). */
        if (namespace == CLONE_NEWNS)
                return context->delegate_namespaces & (CLONE_NEWPID|CLONE_NEWCGROUP|CLONE_NEWNET);

        return false;
}

static int setup_delegated_namespaces(
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                bool delegate,
                const char *memory_pressure_path,
                uid_t uid,
                gid_t gid,
                const ExecCommand *command,
                bool needs_sandboxing,
                bool have_cap_sys_admin,
                PidRef *bpffs_pidref,
                int bpffs_socket_fd,
                int bpffs_errno_pipe,
                int *reterr_exit_status) {

        int r;

        /* This function is called twice, once before unsharing the user namespace, and once after unsharing
         * the user namespace. When called before unsharing the user namespace, "delegate" is set to "false".
         * When called after unsharing the user namespace, "delegate" is set to "true". The net effect is
         * that all namespaces that should not be delegated are unshared when this function is called the
         * first time and all namespaces that should be delegated are unshared when this function is called
         * the second time. */

        assert(context);
        assert(params);
        assert(runtime);
        assert(reterr_exit_status);

        if (exec_needs_network_namespace(context) &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWNET) == delegate &&
            runtime->shared && runtime->shared->netns_storage_socket[0] >= 0) {

                /* Try to enable network namespacing if network namespacing is available and we have
                 * CAP_NET_ADMIN in the current user namespace (either the system manager one or the unit's
                 * own user namespace). We need CAP_NET_ADMIN to be able to configure the loopback device in
                 * the new network namespace. And if we don't have that, then we could only create a network
                 * namespace without the ability to set up "lo". Hence gracefully skip things then. */
                if (namespace_type_supported(NAMESPACE_NET) && have_effective_cap(CAP_NET_ADMIN) > 0) {
                        r = setup_shareable_ns(runtime->shared->netns_storage_socket, CLONE_NEWNET);
                        if (ERRNO_IS_NEG_PRIVILEGE(r))
                                log_notice_errno(r, "PrivateNetwork=yes is configured, but network namespace setup not permitted, proceeding without: %m");
                        else if (r < 0) {
                                *reterr_exit_status = EXIT_NETWORK;
                                return log_error_errno(r, "Failed to set up network namespacing: %m");
                        } else
                                log_debug("Set up %snetwork namespace", delegate ? "delegated " : "");
                } else if (context->network_namespace_path) {
                        *reterr_exit_status = EXIT_NETWORK;
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "NetworkNamespacePath= is not supported, refusing.");
                } else
                        log_notice("PrivateNetwork=yes is configured, but the kernel does not support or we lack privileges for network namespace, proceeding without.");
        }

        if (exec_needs_ipc_namespace(context) &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWIPC) == delegate &&
            runtime->shared && runtime->shared->ipcns_storage_socket[0] >= 0) {

                if (namespace_type_supported(NAMESPACE_IPC)) {
                        r = setup_shareable_ns(runtime->shared->ipcns_storage_socket, CLONE_NEWIPC);
                        if (ERRNO_IS_NEG_PRIVILEGE(r))
                                log_warning_errno(r, "PrivateIPC=yes is configured, but IPC namespace setup failed, ignoring: %m");
                        else if (r < 0) {
                                *reterr_exit_status = EXIT_NAMESPACE;
                                return log_error_errno(r, "Failed to set up IPC namespacing: %m");
                        } else
                                log_debug("Set up %sIPC namespace", delegate ? "delegated " : "");
                } else if (context->ipc_namespace_path) {
                        *reterr_exit_status = EXIT_NAMESPACE;
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "IPCNamespacePath= is not supported, refusing.");
                } else
                        log_warning("PrivateIPC=yes is configured, but the kernel does not support IPC namespaces, ignoring.");
        }

        if (needs_sandboxing && exec_needs_cgroup_namespace(context) &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWCGROUP) == delegate) {
                if (unshare(CLONE_NEWCGROUP) < 0) {
                        *reterr_exit_status = EXIT_NAMESPACE;
                        return log_error_errno(errno, "Failed to set up cgroup namespacing: %m");
                }

                log_debug("Set up %scgroup namespace", delegate ? "delegated " : "");
        }

        /* Unshare a new PID namespace before setting up mounts to ensure /proc/ is mounted with only processes in PID namespace visible.
         * Note PrivatePIDs=yes implies MountAPIVFS=yes so we'll always ensure procfs is remounted. */
        if (needs_sandboxing && exec_needs_pid_namespace(context, params) &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWPID) == delegate) {
                if (params->pidref_transport_fd < 0) {
                        *reterr_exit_status = EXIT_NAMESPACE;
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTCONN), "PidRef socket is not set up.");
                }

                /* If we had CAP_SYS_ADMIN prior to joining the user namespace, then we are privileged and don't need
                 * to check if we can mount /proc/.
                 *
                 * We need to check prior to entering the user namespace because if we're running unprivileged or in a
                 * system without CAP_SYS_ADMIN, then we can have CAP_SYS_ADMIN in the current user namespace but not
                 * once we unshare a mount namespace. */
                if (!have_cap_sys_admin || delegate) {
                        r = can_mount_proc();
                        if (r < 0) {
                                *reterr_exit_status = EXIT_NAMESPACE;
                                return log_error_errno(r, "Failed to detect if /proc/ can be remounted: %m");
                        }
                        if (r == 0) {
                                *reterr_exit_status = EXIT_NAMESPACE;
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "PrivatePIDs=yes is configured, but /proc/ cannot be re-mounted due to lack of privileges, refusing.");
                        }
                }

                r = setup_private_pids(context, params);
                if (r < 0) {
                        *reterr_exit_status = EXIT_NAMESPACE;
                        return log_error_errno(r, "Failed to set up pid namespace: %m");
                }

                log_debug("Set up %spid namespace", delegate ? "delegated " : "");
        }

        /* If PrivatePIDs= yes is configured, we're now running as pid 1 in a pid namespace! */

        if (exec_needs_mount_namespace(context, params, runtime) &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWNS) == delegate) {
                _cleanup_free_ char *error_path = NULL;

                r = apply_mount_namespace(command->flags,
                                          context,
                                          params,
                                          runtime,
                                          memory_pressure_path,
                                          needs_sandboxing,
                                          uid,
                                          gid,
                                          bpffs_pidref,
                                          bpffs_socket_fd,
                                          bpffs_errno_pipe,
                                          &error_path);
                if (r < 0) {
                        *reterr_exit_status = EXIT_NAMESPACE;
                        return log_error_errno(r, "Failed to set up mount namespacing%s%s: %m",
                                               error_path ? ": " : "", strempty(error_path));
                }

                log_debug("Set up %smount namespace", delegate ? "delegated " : "");
        }

        if (needs_sandboxing &&
            exec_namespace_is_delegated(context, params, have_cap_sys_admin, CLONE_NEWUTS) == delegate) {
                r = apply_protect_hostname(context, params, reterr_exit_status);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_debug("Set up %sUTS namespace", delegate ? "delegated " : "");
        }

        return 0;
}

static int set_memory_thp(MemoryTHP thp) {
        int r;

        switch (thp) {

        case MEMORY_THP_INHERIT:
                return 0;

        case MEMORY_THP_DISABLE:
                r = RET_NERRNO(prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0));
                break;

        case MEMORY_THP_MADVISE:
                r = RET_NERRNO(prctl(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0));
                break;

        case MEMORY_THP_SYSTEM:
                r = RET_NERRNO(prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0));
                break;

        default:
                assert_not_reached();
        }

        return r == -EINVAL ? -EOPNOTSUPP : r;
}

static bool exec_context_shall_confirm_spawn(const ExecContext *context) {
        assert(context);

        if (confirm_spawn_disabled())
                return false;

        /* For some reasons units remaining in the same process group
         * as PID 1 fail to acquire the console even if it's not used
         * by any process. So skip the confirmation question for them. */
        return !context->same_pgrp;
}

static int exec_context_named_iofds(
                const ExecContext *c,
                const ExecParameters *p,
                int named_iofds[static 3]) {

        const char *stdio_fdname[3];
        size_t targets;

        assert(c);
        assert(p);
        assert(named_iofds);

        targets = (c->std_input == EXEC_INPUT_NAMED_FD) +
                  (c->std_output == EXEC_OUTPUT_NAMED_FD) +
                  (c->std_error == EXEC_OUTPUT_NAMED_FD);

        for (size_t i = 0; i < 3; i++)
                stdio_fdname[i] = exec_context_fdname(c, i);

        /* Note that socket fds are always placed at the beginning of the fds array, no need for extra
         * manipulation. */
        for (size_t i = 0; i < p->n_socket_fds && targets > 0; i++) {
                if (named_iofds[STDIN_FILENO] < 0 &&
                    c->std_input == EXEC_INPUT_NAMED_FD &&
                    streq(p->fd_names[i], stdio_fdname[STDIN_FILENO])) {

                        named_iofds[STDIN_FILENO] = p->fds[i];
                        targets--;
                        continue;
                }

                /* Allow stdout and stderr to use the same named fd */

                if (named_iofds[STDOUT_FILENO] < 0 &&
                    c->std_output == EXEC_OUTPUT_NAMED_FD &&
                    streq(p->fd_names[i], stdio_fdname[STDOUT_FILENO])) {

                        named_iofds[STDOUT_FILENO] = p->fds[i];
                        targets--;
                }

                if (named_iofds[STDERR_FILENO] < 0 &&
                    c->std_error == EXEC_OUTPUT_NAMED_FD &&
                    streq(p->fd_names[i], stdio_fdname[STDERR_FILENO])) {

                        named_iofds[STDERR_FILENO] = p->fds[i];
                        targets--;
                }
        }

        return targets == 0 ? 0 : -ENOENT;
}

static void exec_shared_runtime_close(ExecSharedRuntime *shared) {
        if (!shared)
                return;

        safe_close_pair(shared->userns_storage_socket);
        safe_close_pair(shared->netns_storage_socket);
        safe_close_pair(shared->ipcns_storage_socket);
}

static void exec_runtime_close(ExecRuntime *rt) {
        if (!rt)
                return;

        safe_close_pair(rt->ephemeral_storage_socket);

        exec_shared_runtime_close(rt->shared);
        dynamic_creds_close(rt->dynamic_creds);
}

static void exec_params_close(ExecParameters *p) {
        if (!p)
                return;

        p->stdin_fd = safe_close(p->stdin_fd);
        p->stdout_fd = safe_close(p->stdout_fd);
        p->stderr_fd = safe_close(p->stderr_fd);
}

static int exec_fd_mark_hot(
                const ExecContext *c,
                ExecParameters *p,
                bool hot,
                int *reterr_exit_status) {

        assert(c);
        assert(p);

        if (p->exec_fd < 0)
                return 0;

        uint8_t x = hot;

        if (write(p->exec_fd, &x, sizeof(x)) < 0) {
                if (reterr_exit_status)
                        *reterr_exit_status = EXIT_EXEC;
                return log_error_errno(errno, "Failed to mark exec_fd as %s: %m", hot ? "hot" : "cold");
        }

        return 1;
}

static int send_handoff_timestamp(
                const ExecContext *c,
                ExecParameters *p,
                int *reterr_exit_status) {

        assert(c);
        assert(p);

        if (p->handoff_timestamp_fd < 0)
                return 0;

        dual_timestamp dt;
        dual_timestamp_now(&dt);

        if (write(p->handoff_timestamp_fd, (const usec_t[2]) { dt.realtime, dt.monotonic }, sizeof(usec_t) * 2) < 0) {
                if (reterr_exit_status)
                        *reterr_exit_status = EXIT_EXEC;
                return log_error_errno(errno, "Failed to send handoff timestamp: %m");
        }

        return 1;
}

static void prepare_terminal(
                const ExecContext *context,
                ExecParameters *p) {

        _cleanup_close_ int lock_fd = -EBADF;

        /* This is the "constructive" reset, i.e. is about preparing things for our invocation rather than
         * cleaning up things from older invocations. */

        assert(context);
        assert(p);

        /* We only try to reset things if we there's the chance our stdout points to a TTY */
        if (!(context->std_output == EXEC_OUTPUT_TTY ||
              (context->std_output == EXEC_OUTPUT_INHERIT && exec_input_is_terminal(context->std_input)) ||
              context->std_output == EXEC_OUTPUT_NAMED_FD ||
              p->stdout_fd >= 0))
                return;

        /* Let's explicitly determine whether to reset via ANSI sequences or not, taking our ExecContext
         * information into account */
        bool use_ansi = exec_context_shall_ansi_seq_reset(context);

        if (context->tty_reset) {
                /* When we are resetting the TTY, then let's create a lock first, to synchronize access. This
                 * in particular matters as concurrent resets and the TTY size ANSI DSR logic done by the
                 * exec_context_apply_tty_size() below might interfere */
                lock_fd = lock_dev_console();
                if (lock_fd < 0)
                        log_debug_errno(lock_fd, "Failed to lock /dev/console, ignoring: %m");

                /* We explicitly control whether to send ansi sequences or not here, since we want to consult
                 * the env vars explicitly configured in the ExecContext, rather than our own environment
                 * block. */
                (void) terminal_reset_defensive(STDOUT_FILENO, use_ansi ? TERMINAL_RESET_FORCE_ANSI_SEQ : TERMINAL_RESET_AVOID_ANSI_SEQ);
        }

        (void) exec_context_apply_tty_size(context, STDIN_FILENO, STDOUT_FILENO, /* tty_path= */ NULL);

        if (use_ansi)
                (void) osc_context_open_service(p->unit_id, p->invocation_id, /* ret_seq= */ NULL);
}

static int setup_term_environment(const ExecContext *context, char ***env) {
        int r;

        assert(context);
        assert(env);

        /* Already specified by user? */
        if (strv_env_get(*env, "TERM"))
                return 0;

        /* Do we need $TERM at all? */
        if (!exec_context_has_tty(context))
                return 0;

        const char *tty_path = exec_context_tty_path(context);
        if (tty_path) {
                /* If we are forked off PID 1 and we are supposed to operate on /dev/console, then let's try
                 * to inherit the $TERM set for PID 1. This is useful for containers so that the $TERM the
                 * container manager passes to PID 1 ends up all the way in the console login shown.
                 *
                 * Note that if this doesn't work out we won't bother with querying systemd.tty.term.console
                 * kernel cmdline option or DCS anymore either, because pid1 also imports $TERM based on those
                 * and it should have showed up as our $TERM if there were anything. */
                if (tty_is_console(tty_path) && getppid() == 1) {
                        const char *term = strv_find_prefix(environ, "TERM=");
                        if (term) {
                                r = strv_env_replace_strdup(env, term);
                                if (r < 0)
                                        return r;

                                FOREACH_STRING(i, "COLORTERM=", "NO_COLOR=") {
                                        const char *s = strv_find_prefix(environ, i);
                                        if (!s)
                                                continue;

                                        r = strv_env_replace_strdup(env, s);
                                        if (r < 0)
                                                return r;
                                }

                                return 1;
                        }

                } else {
                        if (in_charset(skip_dev_prefix(tty_path), ALPHANUMERICAL)) {
                                _cleanup_free_ char *key = NULL, *cmdline = NULL;

                                key = strjoin("systemd.tty.term.", skip_dev_prefix(tty_path));
                                if (!key)
                                        return -ENOMEM;

                                r = proc_cmdline_get_key(key, /* flags= */ 0, &cmdline);
                                if (r > 0)
                                        return strv_env_assign(env, "TERM", cmdline);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to read '%s' from kernel cmdline, ignoring: %m", key);
                        }

                        /* This handles real virtual terminals (returning "linux") and
                         * any terminals which support the DCS +q query sequence. */
                        _cleanup_free_ char *dcs_term = NULL;
                        r = query_term_for_tty(tty_path, &dcs_term);
                        if (r >= 0)
                                return strv_env_assign(env, "TERM", dcs_term);
                }
        }

        /* If $TERM is not known and we pick a fallback default, then let's also set
         * $COLORTERM=truecolor. That's because our fallback default is vt220, which is
         * generally a safe bet (as it supports PageUp/PageDown unlike vt100, and is quite
         * universally available in terminfo/termcap), except for the fact that real DEC
         * vt220 gear never actually supported color. Most tools these days generate color on
         * vt220 anyway, ignoring the physical capabilities of the real hardware, but some
         * tools actually believe in the historical truth. Which is unfortunate since *we*
         * *don't* care about the historical truth, we just want sane defaults if nothing
         * better is explicitly configured. It's 2025 after all, at the time of writing,
         * pretty much all terminal emulators actually *do* support color, hence if we don't
         * know any better let's explicitly claim color support via $COLORTERM. Or in other
         * words: we now explicitly claim to be connected to a franken-vt220 with true color
         * support. */
        r = strv_env_replace_strdup(env, "COLORTERM=truecolor");
        if (r < 0)
                return r;

        return strv_env_replace_strdup(env, "TERM=" FALLBACK_TERM);
}

int exec_invoke(
                const ExecCommand *command,
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                int *exit_status) {

        _cleanup_strv_free_ char **our_env = NULL, **pass_env = NULL, **joined_exec_search_path = NULL, **accum_env = NULL;
        int r;
        const char *username = NULL, *groupname = NULL;
        _cleanup_free_ char *home_buffer = NULL, *memory_pressure_path = NULL, *own_user = NULL;
        const char *pwent_home = NULL, *shell = NULL;
        dev_t journal_stream_dev = 0;
        ino_t journal_stream_ino = 0;
        bool needs_sandboxing,          /* Do we need to set up full sandboxing? (i.e. all namespacing, all MAC stuff, caps, yadda yadda */
                needs_setuid,           /* Do we need to do the actual setresuid()/setresgid() calls? */
                needs_mount_namespace,  /* Do we need to set up a mount namespace for this kernel? */
                have_cap_sys_admin,
                userns_set_up = false,
                keep_seccomp_privileges = false;
#if HAVE_SELINUX
        _cleanup_free_ char *mac_selinux_context_net = NULL;
        bool use_selinux = false;
#endif
#if ENABLE_SMACK
        bool use_smack = false;
#endif
#if HAVE_APPARMOR
        bool use_apparmor = false;
#endif
#if HAVE_SECCOMP
        uint64_t saved_bset = 0;
#endif
        uid_t saved_uid = getuid();
        gid_t saved_gid = getgid();
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        int secure_bits;
        _cleanup_free_ gid_t *gids = NULL, *gids_after_pam = NULL;
        int ngids = 0, ngids_after_pam = 0;
        int named_iofds[3] = EBADF_TRIPLET;
        _cleanup_close_ int socket_fd = -EBADF, bpffs_socket_fd = -EBADF, bpffs_errno_pipe = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef bpffs_pidref = PIDREF_NULL;

        assert(command);
        assert(context);
        assert(params);
        assert(runtime);
        assert(cgroup_context);
        assert(exit_status);

        LOG_CONTEXT_PUSH_EXEC(context, params);

        /* Explicitly test for CVE-2021-4034 inspired invocations */
        if (!command->path || strv_isempty(command->argv)) {
                *exit_status = EXIT_EXEC;
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid command line arguments.");
        }

        rename_process_from_path(command->path);

        if (context->std_input == EXEC_INPUT_SOCKET ||
            context->std_output == EXEC_OUTPUT_SOCKET ||
            context->std_error == EXEC_OUTPUT_SOCKET) {

                if (params->n_socket_fds != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected exactly one socket, got %zu.",
                                               params->n_socket_fds);

                socket_fd = TAKE_FD(params->fds[0]);
                free(params->fd_names[0]);
                params->n_socket_fds = 0;

                memmove(params->fds, params->fds + 1, params->n_stashed_fds * sizeof(int));
                memmove(params->fd_names, params->fd_names + 1, params->n_stashed_fds * sizeof(char*));
                params->fd_names[params->n_stashed_fds] = NULL;
        }

        r = exec_context_named_iofds(context, params, named_iofds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to load a named file descriptor: %m");
        }

        /* We reset exactly these signals, since they are the only ones we set to SIG_IGN in the main
         * daemon. All others we leave untouched because we set them to SIG_DFL or a valid handler initially,
         * both of which will be demoted to SIG_DFL. */
        (void) default_signals(SIGNALS_CRASH_HANDLER,
                               SIGNALS_IGNORE);

        if (context->ignore_sigpipe)
                (void) ignore_signals(SIGPIPE);

        r = reset_signal_mask();
        if (r < 0) {
                *exit_status = EXIT_SIGNAL_MASK;
                return log_error_errno(r, "Failed to set process signal mask: %m");
        }

        if (params->idle_pipe)
                do_idle_pipe_dance(params->idle_pipe);

        /* Close fds we don't need very early to make sure we don't block init reexecution because it cannot bind its
         * sockets. Among the fds we close are the logging fds, and we want to keep them closed, so that we don't have
         * any fds open we don't really want open during the transition. In order to make logging work, we switch the
         * log subsystem into open_when_needed mode, so that it reopens the logs on every single log call. */

        log_forget_fds();
        log_set_open_when_needed(true);
        log_settle_target();

        /* In case anything used libc syslog(), close this here, too */
        closelog();

        r = collect_open_file_fds(params);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to get OpenFile= file descriptors: %m");
        }

        size_t n_keep_fds = params->n_socket_fds + params->n_stashed_fds;
        _cleanup_free_ int *keep_fds = newdup(int, params->fds, n_keep_fds);
        if (!keep_fds) {
                *exit_status = EXIT_MEMORY;
                return log_oom();
        }

        r = add_shifted_fd(&keep_fds, &n_keep_fds, &params->exec_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to collect shifted fd: %m");
        }

        r = add_shifted_fd(&keep_fds, &n_keep_fds, &params->handoff_timestamp_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to collect shifted fd: %m");
        }

#if HAVE_LIBBPF
        r = add_shifted_fd(&keep_fds, &n_keep_fds, &params->bpf_restrict_fs_map_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to collect shifted fd: %m");
        }
#endif

        r = add_shifted_fd(&keep_fds, &n_keep_fds, &params->root_directory_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to collect shifted fd: %m");
        }

        r = close_remaining_fds(params, runtime, socket_fd, keep_fds, n_keep_fds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to close unwanted file descriptors: %m");
        }

        if (!context->same_pgrp &&
            setsid() < 0) {
                *exit_status = EXIT_SETSID;
                return log_error_errno(errno, "Failed to create new process session: %m");
        }

        /* Now, reset the TTY associated to this service "destructively" (i.e. possibly even hang up or
         * disallocate the VT), to get rid of any prior uses of the device. Note that we do not keep any fd
         * open here, hence some of the settings made here might vanish again, depending on the TTY driver
         * used. A 2nd ("constructive") initialization after we opened the input/output fds we actually want
         * will fix this. Note that we pass a NULL invocation ID here – as exec_context_tty_reset() expects
         * the invocation ID associated with the OSC 3008 context ID to close. But we don't want to close any
         * OSC 3008 context here, and opening a fresh OSC 3008 context happens a bit further down. */
        exec_context_tty_reset(context, params, /* invocation_id= */ SD_ID128_NULL);

        if (params->shall_confirm_spawn && exec_context_shall_confirm_spawn(context)) {
                _cleanup_free_ char *cmdline = NULL;

                cmdline = quote_command_line(command->argv, SHELL_ESCAPE_EMPTY);
                if (!cmdline) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }

                r = ask_for_confirmation(context, params, cmdline);
                if (r != CONFIRM_EXECUTE) {
                        if (r == CONFIRM_PRETEND_SUCCESS) {
                                *exit_status = EXIT_SUCCESS;
                                return 0;
                        }

                        *exit_status = EXIT_CONFIRM;
                        return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Execution cancelled by the user.");
                }
        }

        /* We are about to invoke NSS and PAM modules. Let's tell them what we are doing here, maybe they care. This is
         * used by nss-resolve to disable itself when we are about to start systemd-resolved, to avoid deadlocks. Note
         * that these env vars do not survive the execve(), which means they really only apply to the PAM and NSS
         * invocations themselves. Also note that while we'll only invoke NSS modules involved in user management they
         * might internally call into other NSS modules that are involved in hostname resolution, we never know. */
        if (setenv("SYSTEMD_ACTIVATION_UNIT", params->unit_id, true) != 0 ||
            setenv("SYSTEMD_ACTIVATION_SCOPE", runtime_scope_to_string(params->runtime_scope), true) != 0) {
                *exit_status = EXIT_MEMORY;
                return log_error_errno(errno, "Failed to update environment: %m");
        }

        if (context->dynamic_user && runtime->dynamic_creds) {
                _cleanup_strv_free_ char **suggested_paths = NULL;

                /* On top of that, make sure we bypass our own NSS module nss-systemd comprehensively for any NSS
                 * checks, if DynamicUser=1 is used, as we shouldn't create a feedback loop with ourselves here. */
                if (putenv((char*) "SYSTEMD_NSS_DYNAMIC_BYPASS=1") != 0) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(errno, "Failed to update environment: %m");
                }

                r = compile_suggested_paths(context, params, &suggested_paths);
                if (r < 0) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }

                r = dynamic_creds_realize(runtime->dynamic_creds, suggested_paths, &uid, &gid);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        if (r == -EILSEQ)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Failed to update dynamic user credentials: User or group with specified name already exists.");
                        return log_error_errno(r, "Failed to update dynamic user credentials: %m");
                }

                if (!uid_is_valid(uid)) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "UID validation failed for \""UID_FMT"\".", uid);
                }

                if (!gid_is_valid(gid)) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "GID validation failed for \""GID_FMT"\".", gid);
                }

                if (runtime->dynamic_creds->user)
                        username = runtime->dynamic_creds->user->name;

        } else {
                const char *u;

                if (context->user)
                        u = context->user;
                else if (context->pam_name || FLAGS_SET(command->flags, EXEC_COMMAND_VIA_SHELL)) {
                        /* If PAM is enabled but no user name is explicitly selected, then use our own one. */
                        own_user = getusername_malloc();
                        if (!own_user) {
                                *exit_status = EXIT_USER;
                                return log_error_errno(r, "Failed to determine my own user ID: %m");
                        }
                        u = own_user;
                } else
                        u = NULL;

                if (u) {
                        /* We can't use nss unconditionally for root without risking deadlocks if some IPC services
                         * will be started by pid1 and are ordered after us. But if SetLoginEnvironment= is
                         * enabled *explicitly* (i.e. no exec_context_get_set_login_environment() here),
                         * or PAM shall be invoked, let's consult NSS even for root, so that the user
                         * gets accurate $SHELL in session(-like) contexts. */
                        r = get_fixed_user(u,
                                           /* prefer_nss= */ context->set_login_environment > 0 || context->pam_name,
                                           &username, &uid, &gid, &pwent_home, &shell);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                log_error_errno(r, "Failed to determine credentials for user '%s': %s",
                                                u, STRERROR_USER(r));
                                return ERRNO_IS_NEG_BAD_ACCOUNT(r) ? -EINVAL : r;  /* Suppress confusing errno */
                        }
                }

                if (context->group) {
                        r = get_fixed_group(context->group, &groupname, &gid);
                        if (r < 0) {
                                *exit_status = EXIT_GROUP;
                                log_error_errno(r, "Failed to determine credentials for group '%s': %s",
                                                u, STRERROR_GROUP(r));
                                return ERRNO_IS_NEG_BAD_ACCOUNT(r) ? -EINVAL : r;  /* Suppress confusing errno */
                        }
                }
        }

        /* Initialize user supplementary groups and get SupplementaryGroups= ones */
        ngids = get_supplementary_groups(context, username, gid, &gids);
        if (ngids < 0) {
                *exit_status = EXIT_GROUP;
                return log_error_errno(ngids, "Failed to determine supplementary groups: %m");
        }

        r = send_user_lookup(params->unit_id, params->user_lookup_fd, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_USER;
                return log_error_errno(r, "Failed to send user credentials to PID1: %m");
        }

        params->user_lookup_fd = safe_close(params->user_lookup_fd);

        r = acquire_home(context, &pwent_home, &home_buffer);
        if (r < 0) {
                *exit_status = EXIT_CHDIR;
                return log_error_errno(r, "Failed to determine $HOME for the invoking user: %m");
        }

        /* If a socket is connected to STDIN/STDOUT/STDERR, we must drop O_NONBLOCK */
        if (socket_fd >= 0)
                (void) fd_nonblock(socket_fd, false);

        /* We need sandboxing if the caller asked us to apply it and the command isn't explicitly excepted
         * from it. */
        needs_sandboxing = (params->flags & EXEC_APPLY_SANDBOXING) && !(command->flags & EXEC_COMMAND_FULLY_PRIVILEGED);

        /* Journald will try to look-up our cgroup in order to populate _SYSTEMD_CGROUP and _SYSTEMD_UNIT fields.
         * Hence we need to migrate to the target cgroup from init.scope before connecting to journald */
        if (params->cgroup_path) {
                _cleanup_free_ char *subcgroup = NULL;

                r = exec_params_get_cgroup_path(params, cgroup_context, params->cgroup_path, &subcgroup);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return log_error_errno(r, "Failed to acquire cgroup path: %m");
                }
                if (r > 0) {
                        /* If there is a subcgroup required, let's make sure to create it now. */
                        r = cg_create(subcgroup);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create subcgroup '%s': %m", subcgroup);
                }

                /* If we need a cgroup namespace, we cannot yet move the service to its configured subgroup,
                 * as unsharing the cgroup namespace later on makes the current cgroup the root of the
                 * namespace and we want the root of the namespace to be the main service cgroup and not the
                 * subgroup. One edge case is if we're a control process that needs to be spawned in a
                 * subgroup, in this case, we have no choice as moving into the main service cgroup might
                 * violate the no inner processes rule of cgroupv2. */
                const char *cgtarget = needs_sandboxing && exec_needs_cgroup_namespace(context) &&
                                                           !exec_params_needs_control_subcgroup(params)
                                                           ? params->cgroup_path : subcgroup;

                r = cg_attach(cgtarget, 0);
                if (r == -EUCLEAN) {
                        *exit_status = EXIT_CGROUP;
                        return log_error_errno(r,
                                               "Failed to attach process to cgroup '%s', "
                                               "because the cgroup or one of its parents or "
                                               "siblings is in the threaded mode.", cgtarget);
                }
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return log_error_errno(r, "Failed to attach to cgroup %s: %m", cgtarget);
                }
        }

        if (context->user_namespace_path && runtime->shared && runtime->shared->userns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(runtime->shared->userns_storage_socket, context->user_namespace_path, CLONE_NEWUSER);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_error_errno(r, "Failed to open user namespace path %s: %m", context->user_namespace_path);
                }
        }

        if (context->network_namespace_path && runtime->shared && runtime->shared->netns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(runtime->shared->netns_storage_socket, context->network_namespace_path, CLONE_NEWNET);
                if (r < 0) {
                        *exit_status = EXIT_NETWORK;
                        return log_error_errno(r, "Failed to open network namespace path %s: %m", context->network_namespace_path);
                }
        }

        if (context->ipc_namespace_path && runtime->shared && runtime->shared->ipcns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(runtime->shared->ipcns_storage_socket, context->ipc_namespace_path, CLONE_NEWIPC);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_error_errno(r, "Failed to open IPC namespace path %s: %m", context->ipc_namespace_path);
                }
        }

        r = setup_input(context, params, socket_fd, named_iofds);
        if (r < 0) {
                *exit_status = EXIT_STDIN;
                return log_error_errno(r, "Failed to set up standard input: %m");
        }

        _cleanup_free_ char *fname = NULL;
        r = path_extract_filename(command->path, &fname);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                return log_error_errno(r, "Failed to extract filename from path %s: %m", command->path);
        }

        r = setup_output(context, params, STDOUT_FILENO, socket_fd, named_iofds, fname, uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                return log_error_errno(r, "Failed to set up standard output: %m");
        }

        r = setup_output(context, params, STDERR_FILENO, socket_fd, named_iofds, fname, uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDERR;
                return log_error_errno(r, "Failed to set up standard error output: %m");
        }

        /* Now that stdin/stdout are definiely opened, properly initialize it with our desired
         * settings. Note: this is a "constructive" reset, it prepares things for us to use. This is
         * different from the "destructive" TTY reset further up. Also note: we apply this on stdin/stdout in
         * case this is a tty, regardless if we opened it ourselves or got it passed in pre-opened. */
        prepare_terminal(context, params);

        if (context->oom_score_adjust_set) {
                /* When we can't make this change due to EPERM, then let's silently skip over it. User
                 * namespaces prohibit write access to this file, and we shouldn't trip up over that. */
                r = set_oom_score_adjust(context->oom_score_adjust);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        log_debug_errno(r, "Failed to adjust OOM setting, assuming containerized execution, ignoring: %m");
                else if (r < 0) {
                        *exit_status = EXIT_OOM_ADJUST;
                        return log_error_errno(r, "Failed to adjust OOM setting: %m");
                }
        }

        if (context->coredump_filter_set) {
                r = set_coredump_filter(context->coredump_filter);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        log_debug_errno(r, "Failed to adjust coredump_filter, ignoring: %m");
                else if (r < 0) {
                        *exit_status = EXIT_LIMITS;
                        return log_error_errno(r, "Failed to adjust coredump_filter: %m");
                }
        }

        if (context->cpu_sched_set) {
                struct sched_attr attr = {
                        .size = sizeof(attr),
                        .sched_policy = context->cpu_sched_policy,
                        .sched_priority = context->cpu_sched_priority,
                        .sched_flags = context->cpu_sched_reset_on_fork ? SCHED_FLAG_RESET_ON_FORK : 0,
                };

                r = RET_NERRNO(sched_setattr(/* pid= */ 0, &attr, /* flags= */ 0));
                if (r == -EINVAL && !sched_policy_supported(context->cpu_sched_policy)) {
                        _cleanup_free_ char *s = NULL;
                        (void) sched_policy_to_string_alloc(context->cpu_sched_policy, &s);
                        log_warning_errno(r, "CPU scheduling policy %s is not supported, proceeding without.", strna(s));
                } else if (r < 0) {
                        *exit_status = EXIT_SETSCHEDULER;
                        return log_error_errno(r, "Failed to set up CPU scheduling: %m");
                }
        }

        /*
         * Set nice value _after_ the call to sched_setattr() because struct sched_attr includes sched_nice
         * which we do not set, thus it will clobber any previously set nice value. Scheduling policy might
         * be reasonably set together with nice value e.g. in case of SCHED_BATCH (see sched(7)).
         * It would be ideal to set both with the same call, but we cannot easily do so because of all the
         * extra logic in setpriority_closest().
         */
        if (context->nice_set) {
                r = setpriority_closest(context->nice);
                if (r < 0) {
                        *exit_status = EXIT_NICE;
                        return log_error_errno(r, "Failed to set up process scheduling priority (nice level): %m");
                }
        }

        if (context->cpu_affinity_from_numa || context->cpu_set.set) {
                _cleanup_(cpu_set_done) CPUSet converted_cpu_set = {};
                const CPUSet *cpu_set;

                if (context->cpu_affinity_from_numa) {
                        r = exec_context_cpu_affinity_from_numa(context, &converted_cpu_set);
                        if (r < 0) {
                                *exit_status = EXIT_CPUAFFINITY;
                                return log_error_errno(r, "Failed to derive CPU affinity mask from NUMA mask: %m");
                        }

                        cpu_set = &converted_cpu_set;
                } else
                        cpu_set = &context->cpu_set;

                if (sched_setaffinity(0, cpu_set->allocated, cpu_set->set) < 0) {
                        *exit_status = EXIT_CPUAFFINITY;
                        return log_error_errno(errno, "Failed to set up CPU affinity: %m");
                }
        }

        if (mpol_is_valid(numa_policy_get_type(&context->numa_policy))) {
                r = apply_numa_policy(&context->numa_policy);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "NUMA support not available, ignoring.");
                else if (r < 0) {
                        *exit_status = EXIT_NUMA_POLICY;
                        return log_error_errno(r, "Failed to set NUMA memory policy: %m");
                }
        }

        if (context->ioprio_is_set)
                if (ioprio_set(IOPRIO_WHO_PROCESS, 0, context->ioprio) < 0) {
                        *exit_status = EXIT_IOPRIO;
                        return log_error_errno(errno, "Failed to set up IO scheduling priority: %m");
                }

        if (context->timer_slack_nsec != NSEC_INFINITY)
                if (prctl(PR_SET_TIMERSLACK, context->timer_slack_nsec) < 0) {
                        *exit_status = EXIT_TIMERSLACK;
                        return log_error_errno(errno, "Failed to set up timer slack: %m");
                }

        if (context->personality != PERSONALITY_INVALID) {
                r = safe_personality(context->personality);
                if (r < 0) {
                        *exit_status = EXIT_PERSONALITY;
                        return log_error_errno(r, "Failed to set up execution domain (personality): %m");
                }
        }

        if (context->memory_ksm >= 0)
                if (prctl(PR_SET_MEMORY_MERGE, context->memory_ksm, 0, 0, 0) < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno))
                                log_debug_errno(errno, "KSM support not available, ignoring.");
                        else {
                                *exit_status = EXIT_KSM;
                                return log_error_errno(errno, "Failed to set KSM: %m");
                        }
                }

        r = set_memory_thp(context->memory_thp);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "Setting MemoryTHP=%s is not supported, ignoring.",
                                memory_thp_to_string(context->memory_thp));
        else if (r < 0) {
                *exit_status = EXIT_MEMORY_THP;
                return log_error_errno(r, "Failed to set MemoryTHP=%s: %m",
                                       memory_thp_to_string(context->memory_thp));
        }

#if ENABLE_UTMP
        if (context->utmp_id) {
                _cleanup_free_ char *username_alloc = NULL;

                if (!username && context->utmp_mode == EXEC_UTMP_USER) {
                        username_alloc = uid_to_name(uid_is_valid(uid) ? uid : saved_uid);
                        if (!username_alloc) {
                                *exit_status = EXIT_USER;
                                return log_oom();
                        }
                }

                const char *line = context->tty_path ?
                        (path_startswith(context->tty_path, "/dev/") ?: context->tty_path) :
                        NULL;
                utmp_put_init_process(context->utmp_id, getpid_cached(), getsid(0),
                                      line,
                                      context->utmp_mode == EXEC_UTMP_INIT  ? INIT_PROCESS :
                                      context->utmp_mode == EXEC_UTMP_LOGIN ? LOGIN_PROCESS :
                                      USER_PROCESS,
                                      username ?: username_alloc);
        }
#endif

        if (uid_is_valid(uid)) {
                r = chown_terminal(STDIN_FILENO, uid);
                if (r < 0) {
                        *exit_status = EXIT_STDIN;
                        return log_error_errno(r, "Failed to change ownership of terminal: %m");
                }
        }

        if (params->cgroup_path) {
                /* If delegation is enabled we'll pass ownership of the cgroup to the user of the new process. On cgroup v1
                 * this is only about systemd's own hierarchy, i.e. not the controller hierarchies, simply because that's not
                 * safe. On cgroup v2 there's only one hierarchy anyway, and delegation is safe there, hence in that case only
                 * touch a single hierarchy too. */

                if (params->flags & EXEC_CGROUP_DELEGATE) {
                        _cleanup_free_ char *p = NULL;

                        r = cg_set_access(params->cgroup_path, uid, gid);
                        if (r < 0) {
                                *exit_status = EXIT_CGROUP;
                                return log_error_errno(r, "Failed to adjust control group access: %m");
                        }

                        r = exec_params_get_cgroup_path(params, cgroup_context, params->cgroup_path, &p);
                        if (r < 0) {
                                *exit_status = EXIT_CGROUP;
                                return log_error_errno(r, "Failed to acquire cgroup path: %m");
                        }
                        if (r > 0) {
                                r = cg_set_access_recursive(p, uid, gid);
                                if (r < 0) {
                                        *exit_status = EXIT_CGROUP;
                                        return log_error_errno(r, "Failed to adjust control subgroup access: %m");
                                }
                        }
                }

                if (is_pressure_supported() > 0) {
                        if (cgroup_context_want_memory_pressure(cgroup_context)) {
                                r = cg_get_path(params->cgroup_path, "memory.pressure", &memory_pressure_path);
                                if (r < 0) {
                                        *exit_status = EXIT_MEMORY;
                                        return log_oom();
                                }

                                r = chmod_and_chown(memory_pressure_path, 0644, uid, gid);
                                if (r < 0) {
                                        log_full_errno(r == -ENOENT || ERRNO_IS_PRIVILEGE(r) ? LOG_DEBUG : LOG_WARNING, r,
                                                       "Failed to adjust ownership of '%s', ignoring: %m", memory_pressure_path);
                                        memory_pressure_path = mfree(memory_pressure_path);
                                }
                                /* First we use the current cgroup path to chmod and chown the memory pressure path, then pass the path relative
                                 * to the cgroup namespace to environment variables and mounts. If chown/chmod fails, we should not pass memory
                                 * pressure path environment variable or read-write mount to the unit. This is why we check if
                                 * memory_pressure_path != NULL in the conditional below. */
                                if (memory_pressure_path && needs_sandboxing && exec_needs_cgroup_namespace(context)) {
                                        memory_pressure_path = mfree(memory_pressure_path);
                                        r = cg_get_path("/", "memory.pressure", &memory_pressure_path);
                                        if (r < 0) {
                                                *exit_status = EXIT_MEMORY;
                                                return log_oom();
                                        }
                                }
                        } else if (cgroup_context->memory_pressure_watch == CGROUP_PRESSURE_WATCH_NO) {
                                memory_pressure_path = strdup("/dev/null"); /* /dev/null is explicit indicator for turning of memory pressure watch */
                                if (!memory_pressure_path) {
                                        *exit_status = EXIT_MEMORY;
                                        return log_oom();
                                }
                        }
                }
        }

        needs_mount_namespace = exec_needs_mount_namespace(context, params, runtime);

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                r = setup_exec_directory(context, params, uid, gid, dt, needs_mount_namespace, exit_status);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up special execution directory in %s: %m", params->prefix[dt]);
        }

        r = exec_setup_credentials(context, cgroup_context, params, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_CREDENTIALS;
                return log_error_errno(r, "Failed to set up credentials: %m");
        }

        r = build_environment(
                        context,
                        params,
                        cgroup_context,
                        pwent_home,
                        username,
                        shell,
                        journal_stream_dev,
                        journal_stream_ino,
                        memory_pressure_path,
                        needs_sandboxing,
                        &our_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return log_oom();
        }

        r = build_pass_environment(context, &pass_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return log_oom();
        }

        /* The $PATH variable is set to the default path in params->environment. However, this is overridden
         * if user-specified fields have $PATH set. The intention is to also override $PATH if the unit does
         * not specify PATH but the unit has ExecSearchPath. */
        if (!strv_isempty(context->exec_search_path)) {
                _cleanup_free_ char *joined = NULL;

                joined = strv_join(context->exec_search_path, ":");
                if (!joined) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }

                r = strv_env_assign(&joined_exec_search_path, "PATH", joined);
                if (r < 0) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }
        }

        accum_env = strv_env_merge(params->environment,
                                   our_env,
                                   joined_exec_search_path,
                                   pass_env,
                                   context->environment,
                                   params->files_env);
        if (!accum_env) {
                *exit_status = EXIT_MEMORY;
                return log_oom();
        }
        strv_env_clean(accum_env);

        (void) umask(context->umask);

        r = setup_term_environment(context, &accum_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return log_error_errno(r, "Failed to construct $TERM: %m");
        }

        r = setup_keyring(context, params, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_KEYRING;
                return log_error_errno(r, "Failed to set up kernel keyring: %m");
        }

        /* We need setresuid() if the caller asked us to apply sandboxing and the command isn't explicitly
         * excepted from either whole sandboxing or just setresuid() itself. */
        needs_setuid = needs_sandboxing && !FLAGS_SET(command->flags, EXEC_COMMAND_NO_SETUID);

        uint64_t capability_ambient_set = context->capability_ambient_set;

        /* Check CAP_SYS_ADMIN before we enter user namespace to see if we can mount /proc even though its masked. */
        have_cap_sys_admin = have_effective_cap(CAP_SYS_ADMIN) > 0;

        if (needs_sandboxing) {
                /* MAC enablement checks need to be done before a new mount ns is created, as they rely on
                 * /sys being present. The actual MAC context application will happen later, as late as
                 * possible, to avoid impacting our own code paths. */

#if HAVE_SELINUX
                use_selinux = mac_selinux_use();
#endif
#if ENABLE_SMACK
                use_smack = mac_smack_use();
#endif
#if HAVE_APPARMOR
                use_apparmor = mac_apparmor_use();
#endif
        }

        if (needs_sandboxing) {
                int which_failed;

                /* Let's set the resource limits before we call into PAM, so that pam_limits wins over what
                 * is set here. (See below.) */

                r = setrlimit_closest_all((const struct rlimit* const *) context->rlimit, &which_failed);
                if (r < 0) {
                        *exit_status = EXIT_LIMITS;
                        return log_error_errno(r, "Failed to adjust resource limit RLIMIT_%s: %m", rlimit_to_string(which_failed));
                }
        }

        if (needs_setuid && context->pam_name && username) {
                /* Let's call into PAM after we set up our own idea of resource limits so that pam_limits
                 * wins here. (See above.) */

                /* All fds passed in the fds array will be closed in the pam child process. */
                r = setup_pam(context, cgroup_context, params, username, uid, gid, &accum_env,
                              needs_sandboxing, params->exec_fd);
                if (r < 0) {
                        *exit_status = EXIT_PAM;
                        return log_error_errno(r, "Failed to set up PAM session: %m");
                }

                /* PAM modules might have set some ambient caps. Query them here and merge them into
                 * the caps we want to set in the end, so that we don't end up unsetting them. */
                uint64_t ambient_after_pam;
                r = capability_get_ambient(&ambient_after_pam);
                if (r < 0) {
                        *exit_status = EXIT_CAPABILITIES;
                        return log_error_errno(r, "Failed to query ambient caps: %m");
                }

                capability_ambient_set |= ambient_after_pam;

                ngids_after_pam = getgroups_alloc(&gids_after_pam);
                if (ngids_after_pam < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_error_errno(ngids_after_pam, "Failed to obtain groups after setting up PAM: %m");
                }
        }

        if (context->private_bpf != PRIVATE_BPF_NO) {
                /* To create a BPF token, the bpffs has to be mounted with the fsopen()/fsmount() API.
                 * More specifically, fsopen() must be called within the user namespace, then all the
                 * fsconfig() as privileged user, and finally and fsmount() and move_mount() in
                 * the user namespace.
                 * To do this, we split the code into a bpffs_prepare() and mount_bpffs() functions,
                 * the first runs as privileged user the second as unprivileged one, and they coordinate
                 * by sending messages and file descriptors via a socket pair.
                 * The user and mount namespaces need to be unshared in this exact order and before
                 * the fsopen() call for the fsopen() API to work as unprivileged.
                 * This is the kernel sample doing this:
                 * https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/token.c
                 */
                r = bpffs_prepare(context, &bpffs_pidref, &bpffs_socket_fd, &bpffs_errno_pipe);
                if (r < 0) {
                        *exit_status = EXIT_BPF;
                        return log_error_errno(r, "Failed to mount bpffs in bpffs_prepare(): %m");
                }
        }

        /* Load a bunch of libraries we'll possibly need later, before we turn off dlopen() */
        (void) dlopen_bpf();
        (void) dlopen_cryptsetup();
        (void) dlopen_libmount();
        (void) dlopen_libseccomp();

        /* Let's now disable further dlopen()ing of libraries, since we are about to do namespace
         * shenanigans, and do not want to mix resources from host and namespace */
        block_dlopen();

        if (needs_sandboxing && !have_cap_sys_admin && exec_needs_cap_sys_admin(context, params)) {
                /* If we're unprivileged, set up the user namespace first to enable use of the other namespaces.
                 * Users with CAP_SYS_ADMIN can set up user namespaces last because they will be able to
                 * set up all of the other namespaces (i.e. network, mount, UTS) without a user namespace. */

                if (context->user_namespace_path && runtime->shared->userns_storage_socket[0] >= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "UserNamespacePath= is configured, but user namespace setup not permitted");

                PrivateUsers pu = exec_context_get_effective_private_users(context, params);
                if (pu == PRIVATE_USERS_NO)
                        pu = PRIVATE_USERS_SELF;

                /* The kernel requires /proc/pid/setgroups be set to "deny" prior to writing /proc/pid/gid_map in
                 * unprivileged user namespaces. */
                r = setup_private_users(pu, saved_uid, saved_gid, uid, gid, /* allow_setgroups= */ false);
                /* If it was requested explicitly and we can't set it up, fail early. Otherwise, continue and let
                 * the actual requested operations fail (or silently continue). */
                if (r < 0 && context->private_users != PRIVATE_USERS_NO) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(r, "Failed to set up user namespacing for unprivileged user: %m");
                }
                if (r < 0)
                        log_info_errno(r, "Failed to set up user namespacing for unprivileged user, ignoring: %m");
                else {
                        assert(r > 0);
                        userns_set_up = true;
                        log_debug("Set up unprivileged user namespace");
                }
        }

        /* Call setup_delegated_namespaces() the first time to unshare all non-delegated namespaces. */
        r = setup_delegated_namespaces(
                        context,
                        params,
                        runtime,
                        /* delegate= */ false,
                        memory_pressure_path,
                        uid,
                        gid,
                        command,
                        needs_sandboxing,
                        have_cap_sys_admin,
                        &bpffs_pidref,
                        bpffs_socket_fd,
                        bpffs_errno_pipe,
                        exit_status);
        if (r < 0)
                return r;

        /* Drop groups as early as possible.
         * This needs to be done after PrivateDevices=yes setup as device nodes should be owned by the host's root.
         * For non-root in a userns, devices will be owned by the user/group before the group change, and nobody. */
        if (needs_setuid) {
                _cleanup_free_ gid_t *gids_to_enforce = NULL;
                int ngids_to_enforce;

                ngids_to_enforce = merge_gid_lists(gids,
                                                   ngids,
                                                   gids_after_pam,
                                                   ngids_after_pam,
                                                   &gids_to_enforce);
                if (ngids_to_enforce < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_error_errno(ngids_to_enforce, "Failed to merge group lists. Group membership might be incorrect: %m");
                }

                r = enforce_groups(gid, gids_to_enforce, ngids_to_enforce);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_error_errno(r, "Changing group credentials failed: %m");
                }
        }

        /* If the user namespace was not set up above, try to do it now.
         * It's preferred to set up the user namespace later (after all other namespaces) so as not to be
         * restricted by rules pertaining to combining user namespaces with other namespaces (e.g. in the
         * case of mount namespaces being less privileged when the mount point list is copied from a
         * different user namespace). */
        if (needs_sandboxing && context->user_namespace_path && runtime->shared && runtime->shared->userns_storage_socket[0] >= 0) {
                if (!namespace_type_supported(NAMESPACE_USER))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "UserNamespacePath= is not supported, refusing.");

                r = setup_shareable_ns(runtime->shared->userns_storage_socket, CLONE_NEWUSER);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        return log_notice_errno(r, "PrivateUsers= is configured, but user namespace setup not permitted, refusing.");
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(r, "Failed to set up user namespacing: %m");
                }

                log_debug("Set up existing user namespace");
        } else if (needs_sandboxing && !userns_set_up) {
                PrivateUsers pu = exec_context_get_effective_private_users(context, params);

                r = setup_private_users(pu, saved_uid, saved_gid, uid, gid,
                                        /* allow_setgroups= */ pu == PRIVATE_USERS_FULL);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        return log_error_errno(r, "Failed to set up user namespacing: %m");
                }
                if (r > 0)
                        log_debug("Set up privileged user namespace");
        }

        /* Call setup_delegated_namespaces() the second time to unshare all delegated namespaces. */
        r = setup_delegated_namespaces(
                        context,
                        params,
                        runtime,
                        /* delegate= */ true,
                        memory_pressure_path,
                        uid,
                        gid,
                        command,
                        needs_sandboxing,
                        have_cap_sys_admin,
                        &bpffs_pidref,
                        bpffs_socket_fd,
                        bpffs_errno_pipe,
                        exit_status);
        if (r < 0)
                return r;

        /* Kill unnecessary process, for the case that e.g. when the bpffs mount point is hidden. */
        pidref_done_sigkill_wait(&bpffs_pidref);

        if (needs_sandboxing && exec_needs_cgroup_namespace(context) && params->cgroup_path) {
                /* Move ourselves into the subcgroup now *after* we've unshared the cgroup namespace, which
                 * ensures the root of the cgroup namespace is the top level service cgroup and not the
                 * subcgroup. Adjust the prefix accordingly since we're in a cgroup namespace now. */
                r = attach_to_subcgroup(context, cgroup_context, params, /* prefix= */ NULL);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return r;
                }
        }

        /* Now that the mount namespace has been set up and privileges adjusted, let's look for the thing we
         * shall execute. */

        const char *path = command->path;

        if (FLAGS_SET(command->flags, EXEC_COMMAND_VIA_SHELL)) {
                if (shell_is_placeholder(shell)) {
                        log_debug("Shell prefixing requested for user without default shell, using /bin/sh: %s",
                                  strna(username));
                        assert(streq(path, _PATH_BSHELL));
                } else
                        path = shell;
        }

        _cleanup_free_ char *executable = NULL;
        _cleanup_close_ int executable_fd = -EBADF;
        r = find_executable_full(path, /* root= */ NULL, context->exec_search_path, false, &executable, &executable_fd);
        if (r < 0) {
                *exit_status = EXIT_EXEC;
                log_struct_errno(LOG_NOTICE, r,
                                 LOG_MESSAGE_ID(SD_MESSAGE_SPAWN_FAILED_STR),
                                 LOG_EXEC_MESSAGE(params, "Unable to locate executable '%s': %m", path),
                                 LOG_ITEM("EXECUTABLE=%s", path));
                /* If the error will be ignored by manager, tune down the log level here. Missing executable
                 * is very much expected in this case. */
                return r != -ENOMEM && FLAGS_SET(command->flags, EXEC_COMMAND_IGNORE_FAILURE) ? 1 : r;
        }

        r = add_shifted_fd(&keep_fds, &n_keep_fds, &executable_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to collect shifted fd: %m");
        }

#if HAVE_SELINUX
        if (needs_sandboxing && use_selinux && params->selinux_context_net) {
                int fd = -EBADF;

                if (socket_fd >= 0)
                        fd = socket_fd;
                else if (params->n_socket_fds == 1)
                        /* If stdin is not connected to a socket but we are triggered by exactly one socket unit then we
                         * use context from that fd to compute the label. */
                        fd = params->fds[0];

                if (fd >= 0) {
                        r = mac_selinux_get_child_mls_label(fd, executable, context->selinux_context, &mac_selinux_context_net);
                        if (r < 0) {
                                if (!context->selinux_context_ignore) {
                                        *exit_status = EXIT_SELINUX_CONTEXT;
                                        return log_error_errno(r, "Failed to determine SELinux context: %m");
                                }
                                log_debug_errno(r, "Failed to determine SELinux context, ignoring: %m");
                        }
                }
        }
#endif

        /* We repeat the fd closing here, to make sure that nothing is leaked from the PAM modules. Note that
         * we are more aggressive this time, since we don't need socket_fd and the netns and ipcns fds any
         * more. We do keep exec_fd and handoff_timestamp_fd however, if we have it, since we need to keep
         * them open until the final execve(). But first, close the remaining sockets in the context
         * objects. */

        exec_runtime_close(runtime);
        exec_params_close(params);

        r = close_all_fds(keep_fds, n_keep_fds);
        if (r >= 0)
                r = pack_fds(params->fds, params->n_socket_fds + params->n_stashed_fds);
        if (r >= 0)
                r = flag_fds(params->fds, params->n_socket_fds, params->n_socket_fds + params->n_stashed_fds,
                             context->non_blocking);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_error_errno(r, "Failed to adjust passed file descriptors: %m");
        }

        /* At this point, the fds we want to pass to the program are all ready and set up, with O_CLOEXEC turned off
         * and at the right fd numbers. The are no other fds open, with one exception: the exec_fd if it is defined,
         * and it has O_CLOEXEC set, after all we want it to be closed by the execve(), so that our parent knows we
         * came this far. */

        secure_bits = context->secure_bits;

        if (needs_sandboxing) {
                uint64_t bset;

                /* Set the RTPRIO resource limit to 0, but only if nothing else was explicitly requested.
                 * (Note this is placed after the general resource limit initialization, see above, in order
                 * to take precedence.) */
                if (context->restrict_realtime && !context->rlimit[RLIMIT_RTPRIO]) {
                        if (setrlimit(RLIMIT_RTPRIO, &RLIMIT_MAKE_CONST(0)) < 0) {
                                *exit_status = EXIT_LIMITS;
                                return log_error_errno(errno, "Failed to adjust RLIMIT_RTPRIO resource limit: %m");
                        }
                }

#if ENABLE_SMACK
                /* LSM Smack needs the capability CAP_MAC_ADMIN to change the current execution security context of the
                 * process. This is the latest place before dropping capabilities. Other MAC context are set later. */
                if (use_smack) {
                        r = setup_smack(context, params, executable_fd);
                        if (r < 0 && !context->smack_process_label_ignore) {
                                *exit_status = EXIT_SMACK_PROCESS_LABEL;
                                return log_error_errno(r, "Failed to set SMACK process label: %m");
                        }
                }
#endif

                bset = context->capability_bounding_set;

#if HAVE_SECCOMP
                /* If the service has any form of a seccomp filter and it allows dropping privileges, we'll
                 * keep the needed privileges to apply it even if we're not root. */
                if (needs_setuid &&
                    uid_is_valid(uid) &&
                    context_has_seccomp(context) &&
                    seccomp_allows_drop_privileges(context)) {
                        keep_seccomp_privileges = true;

                        if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
                                *exit_status = EXIT_USER;
                                return log_error_errno(errno, "Failed to enable keep capabilities flag: %m");
                        }

                        /* Save the current bounding set so we can restore it after applying the seccomp
                         * filter */
                        saved_bset = bset;
                        bset |= (UINT64_C(1) << CAP_SYS_ADMIN) |
                                (UINT64_C(1) << CAP_SETPCAP);
                }
#endif

                if (!cap_test_all(bset)) {
                        r = capability_bounding_set_drop(bset, /* right_now= */ false);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return log_error_errno(r, "Failed to drop capabilities: %m");
                        }
                }

                /* Ambient capabilities are cleared during setresuid() (in enforce_user()) even with
                 * keep-caps set.
                 *
                 * To be able to raise the ambient capabilities after setresuid() they have to be added to
                 * the inherited set and keep caps has to be set (done in enforce_user()).  After setresuid()
                 * the ambient capabilities can be raised as they are present in the permitted and
                 * inhertiable set. However it is possible that someone wants to set ambient capabilities
                 * without changing the user, so we also set the ambient capabilities here.
                 *
                 * The requested ambient capabilities are raised in the inheritable set if the second
                 * argument is true. */
                if (capability_ambient_set != 0) {
                        r = capability_ambient_set_apply(capability_ambient_set, /* also_inherit= */ true);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return log_error_errno(r, "Failed to apply ambient capabilities (before UID change): %m");
                        }
                }
        }

        /* chroot to root directory first, before we lose the ability to chroot */
        r = apply_root_directory(context, params, runtime, needs_mount_namespace, exit_status);
        if (r < 0)
                return log_error_errno(r, "Chrooting to the requested root directory failed: %m");

        if (needs_setuid) {
                if (uid_is_valid(uid)) {
                        r = enforce_user(context, uid, capability_ambient_set);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                return log_error_errno(r, "Failed to change UID to " UID_FMT ": %m", uid);
                        }

                        if (keep_seccomp_privileges) {
                                if (!BIT_SET(capability_ambient_set, CAP_SETUID)) {
                                        r = drop_capability(CAP_SETUID);
                                        if (r < 0) {
                                                *exit_status = EXIT_USER;
                                                return log_error_errno(r, "Failed to drop CAP_SETUID: %m");
                                        }
                                }

                                r = keep_capability(CAP_SYS_ADMIN);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_error_errno(r, "Failed to keep CAP_SYS_ADMIN: %m");
                                }

                                r = keep_capability(CAP_SETPCAP);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_error_errno(r, "Failed to keep CAP_SETPCAP: %m");
                                }
                        }

                        if (capability_ambient_set != 0) {

                                /* Raise the ambient capabilities after user change. */
                                r = capability_ambient_set_apply(capability_ambient_set, /* also_inherit= */ false);
                                if (r < 0) {
                                        *exit_status = EXIT_CAPABILITIES;
                                        return log_error_errno(r, "Failed to apply ambient capabilities (after UID change): %m");
                                }
                        }
                }
        }

        /* Apply working directory here, because the working directory might be on NFS and only the user
         * running this service might have the correct privilege to change to the working directory. Also, it
         * is absolutely 💣 crucial 💣 we applied all mount namespacing rearrangements before this, so that
         * the cwd cannot be used to pin directories outside of the sandbox. */
        r = apply_working_directory(context, params, runtime, pwent_home, accum_env);
        if (r < 0) {
                *exit_status = EXIT_CHDIR;
                return log_error_errno(r, "Changing to the requested working directory failed: %m");
        }

        if (needs_sandboxing) {
                /* Apply other MAC contexts late, but before seccomp syscall filtering, as those should really be last to
                 * influence our own codepaths as little as possible. Moreover, applying MAC contexts usually requires
                 * syscalls that are subject to seccomp filtering, hence should probably be applied before the syscalls
                 * are restricted. */

#if HAVE_SELINUX
                if (use_selinux) {
                        char *exec_context = mac_selinux_context_net ?: context->selinux_context;

                        if (exec_context) {
                                r = sym_setexeccon_raw(exec_context);
                                if (r < 0) {
                                        if (!context->selinux_context_ignore) {
                                                *exit_status = EXIT_SELINUX_CONTEXT;
                                                return log_error_errno(r, "Failed to change SELinux context to %s: %m", exec_context);
                                        }
                                        log_debug_errno(r, "Failed to change SELinux context to %s, ignoring: %m", exec_context);
                                }
                        }
                }
#endif

#if HAVE_APPARMOR
                if (use_apparmor && context->apparmor_profile) {
                        r = ASSERT_PTR(sym_aa_change_onexec)(context->apparmor_profile);
                        if (r < 0 && !context->apparmor_profile_ignore) {
                                *exit_status = EXIT_APPARMOR_PROFILE;
                                return log_error_errno(errno, "Failed to prepare AppArmor profile change to %s: %m",
                                                       context->apparmor_profile);
                        }
                }
#endif

                /* PR_GET_SECUREBITS is not privileged, while PR_SET_SECUREBITS is. So to suppress potential
                 * EPERMs we'll try not to call PR_SET_SECUREBITS unless necessary. Setting securebits
                 * requires CAP_SETPCAP. */
                if (prctl(PR_GET_SECUREBITS) != secure_bits) {
                        /* CAP_SETPCAP is required to set securebits. This capability is raised into the
                         * effective set here.
                         *
                         * The effective set is overwritten during execve() with the following values:
                         *
                         * - ambient set (for non-root processes)
                         *
                         * - (inheritable | bounding) set for root processes)
                         *
                         * Hence there is no security impact to raise it in the effective set before execve
                         */
                        r = capability_gain_cap_setpcap();
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return log_error_errno(r, "Failed to gain CAP_SETPCAP for setting secure bits");
                        }
                        if (prctl(PR_SET_SECUREBITS, secure_bits) < 0) {
                                *exit_status = EXIT_SECUREBITS;
                                return log_error_errno(errno, "Failed to set process secure bits: %m");
                        }
                }

                if (context_has_no_new_privileges(context))
                        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                                *exit_status = EXIT_NO_NEW_PRIVILEGES;
                                return log_error_errno(errno, "Failed to disable new privileges: %m");
                        }

#if HAVE_SECCOMP
                r = apply_address_families(context, params);
                if (r < 0) {
                        *exit_status = EXIT_ADDRESS_FAMILIES;
                        return log_error_errno(r, "Failed to restrict address families: %m");
                }

                r = apply_memory_deny_write_execute(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to disable writing to executable memory: %m");
                }

                r = apply_restrict_realtime(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply realtime restrictions: %m");
                }

                r = apply_restrict_suid_sgid(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply SUID/SGID restrictions: %m");
                }

                r = apply_restrict_namespaces(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply namespace restrictions: %m");
                }

                r = apply_protect_sysctl(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply sysctl restrictions: %m");
                }

                r = apply_protect_kernel_modules(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply module loading restrictions: %m");
                }

                r = apply_protect_kernel_logs(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply kernel log restrictions: %m");
                }

                r = apply_protect_clock(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply clock restrictions: %m");
                }

                r = apply_private_devices(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to set up private devices: %m");
                }

                r = apply_syscall_archs(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply syscall architecture restrictions: %m");
                }

                r = apply_lock_personality(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to lock personalities: %m");
                }

                r = apply_syscall_log(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply system call log filters: %m");
                }
#endif

#if HAVE_LIBBPF
                r = apply_restrict_filesystems(context, params);
                if (r < 0) {
                        *exit_status = EXIT_BPF;
                        return log_error_errno(r, "Failed to restrict filesystems: %m");
                }
#endif

#if HAVE_SECCOMP
                /* This really should remain as close to the execve() as possible, to make sure our own code is affected
                 * by the filter as little as possible. */
                r = apply_syscall_filter(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_error_errno(r, "Failed to apply system call filters: %m");
                }

                if (keep_seccomp_privileges) {
                        /* Restore the capability bounding set with what's expected from the service + the
                         * ambient capabilities hack */
                        if (!cap_test_all(saved_bset)) {
                                r = capability_bounding_set_drop(saved_bset, /* right_now= */ false);
                                if (r < 0) {
                                        *exit_status = EXIT_CAPABILITIES;
                                        return log_error_errno(r, "Failed to drop bset capabilities: %m");
                                }
                        }

                        /* Only drop CAP_SYS_ADMIN if it's not in the bounding set, otherwise we'll break
                         * applications that use it. */
                        if (!BIT_SET(saved_bset, CAP_SYS_ADMIN)) {
                                r = drop_capability(CAP_SYS_ADMIN);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_error_errno(r, "Failed to drop CAP_SYS_ADMIN: %m");
                                }
                        }

                        /* Only drop CAP_SETPCAP if it's not in the bounding set, otherwise we'll break
                         * applications that use it. */
                        if (!BIT_SET(saved_bset, CAP_SETPCAP)) {
                                r = drop_capability(CAP_SETPCAP);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_error_errno(r, "Failed to drop CAP_SETPCAP: %m");
                                }
                        }

                        if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                                *exit_status = EXIT_USER;
                                return log_error_errno(errno, "Failed to drop keep capabilities flag: %m");
                        }
                }
#endif

        }

        if (!strv_isempty(context->unset_environment)) {
                char **ee = NULL;

                ee = strv_env_delete(accum_env, 1, context->unset_environment);
                if (!ee) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }

                strv_free_and_replace(accum_env, ee);
        }

        _cleanup_strv_free_ char **replaced_argv = NULL, **argv_via_shell = NULL;
        char **final_argv = FLAGS_SET(command->flags, EXEC_COMMAND_VIA_SHELL) ? strv_skip(command->argv, 1) : command->argv;

        if (final_argv && !FLAGS_SET(command->flags, EXEC_COMMAND_NO_ENV_EXPAND)) {
                _cleanup_strv_free_ char **unset_variables = NULL, **bad_variables = NULL;

                r = replace_env_argv(final_argv, accum_env, &replaced_argv, &unset_variables, &bad_variables);
                if (r < 0) {
                        *exit_status = EXIT_MEMORY;
                        return log_error_errno(r, "Failed to replace environment variables: %m");
                }
                final_argv = replaced_argv;

                if (!strv_isempty(unset_variables)) {
                        _cleanup_free_ char *ju = strv_join(unset_variables, ", ");
                        log_warning("Referenced but unset environment variable evaluates to an empty string: %s", strna(ju));
                }

                if (!strv_isempty(bad_variables)) {
                        _cleanup_free_ char *jb = strv_join(bad_variables, ", ");
                        log_warning("Invalid environment variable name evaluates to an empty string: %s", strna(jb));
                }
        }

        if (FLAGS_SET(command->flags, EXEC_COMMAND_VIA_SHELL)) {
                r = strv_extendf(&argv_via_shell, "%s%s", command->argv[0][0] == '-' ? "-" : "", path);
                if (r < 0) {
                        *exit_status = EXIT_MEMORY;
                        return log_oom();
                }

                if (!strv_isempty(final_argv)) {
                        _cleanup_free_ char *cmdline_joined = NULL;

                        cmdline_joined = strv_join(final_argv, " ");
                        if (!cmdline_joined) {
                                *exit_status = EXIT_MEMORY;
                                return log_oom();
                        }

                        r = strv_extend_many(&argv_via_shell, "-c", cmdline_joined);
                        if (r < 0) {
                                *exit_status = EXIT_MEMORY;
                                return log_oom();
                        }
                }

                final_argv = argv_via_shell;
        }

        log_command_line(context, params, "Executing", executable, final_argv);

        /* We have finished with all our initializations. Let's now let the manager know that. From this
         * point on, if the manager sees POLLHUP on the exec_fd, then execve() was successful. */

        r = exec_fd_mark_hot(context, params, /* hot= */ true, exit_status);
        if (r < 0)
                return r;

        /* As last thing before the execve(), let's send the handoff timestamp */
        r = send_handoff_timestamp(context, params, exit_status);
        if (r < 0) {
                /* If this handoff timestamp failed, let's undo the marking as hot */
                (void) exec_fd_mark_hot(context, params, /* hot= */ false, /* reterr_exit_status= */ NULL);
                return r;
        }

        /* NB: we leave executable_fd, exec_fd, handoff_timestamp_fd open here. This is safe, because they
         * have O_CLOEXEC set, and the execve() below will thus automatically close them. In fact, for
         * exec_fd this is pretty much the whole raison d'etre. */

        r = fexecve_or_execve(executable_fd, executable, final_argv, accum_env);

        /* The execve() failed, let's undo the marking as hot */
        (void) exec_fd_mark_hot(context, params, /* hot= */ false, /* reterr_exit_status= */ NULL);

        *exit_status = EXIT_EXEC;
        return log_error_errno(r, "Failed to execute %s: %m", executable);
}
