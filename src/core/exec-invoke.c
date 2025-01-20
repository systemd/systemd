/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sched.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>

#if HAVE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#endif

#if HAVE_APPARMOR
#include <sys/apparmor.h>
#endif

#include "sd-messages.h"

#if HAVE_APPARMOR
#include "apparmor-util.h"
#endif
#include "argv-util.h"
#include "ask-password-api.h"
#include "barrier.h"
#include "bitfield.h"
#include "bpf-dlopen.h"
#include "bpf-restrict-fs.h"
#include "btrfs-util.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "chase.h"
#include "chattr-util.h"
#include "chown-recursive.h"
#include "copy.h"
#include "env-util.h"
#include "escape.h"
#include "exec-credential.h"
#include "exec-invoke.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-send.h"
#include "memfd-util.h"
#include "missing_ioprio.h"
#include "missing_prctl.h"
#include "missing_sched.h"
#include "missing_securebits.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "psi-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "smack-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "utmp-wtmp.h"
#include "vpick.h"

#define IDLE_TIMEOUT_USEC (5*USEC_PER_SEC)
#define IDLE_TIMEOUT2_USEC (1*USEC_PER_SEC)

#define SNDBUF_SIZE (8*1024*1024)

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

static bool is_terminal_input(ExecInput i) {
        return IN_SET(i,
                      EXEC_INPUT_TTY,
                      EXEC_INPUT_TTY_FORCE,
                      EXEC_INPUT_TTY_FAIL);
}

static bool is_terminal_output(ExecOutput o) {
        return IN_SET(o,
                      EXEC_OUTPUT_TTY,
                      EXEC_OUTPUT_KMSG_AND_CONSOLE,
                      EXEC_OUTPUT_JOURNAL_AND_CONSOLE);
}

static bool is_kmsg_output(ExecOutput o) {
        return IN_SET(o,
                      EXEC_OUTPUT_KMSG,
                      EXEC_OUTPUT_KMSG_AND_CONSOLE);
}

static bool exec_context_needs_term(const ExecContext *c) {
        assert(c);

        /* Return true if the execution context suggests we should set $TERM to something useful. */

        if (is_terminal_input(c->std_input))
                return true;

        if (is_terminal_output(c->std_output))
                return true;

        if (is_terminal_output(c->std_error))
                return true;

        return !!c->tty_path;
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
                is_kmsg_output(output),
                is_terminal_output(output)) < 0)
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

        if (IN_SET(flags & O_ACCMODE, O_WRONLY, O_RDWR))
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

        if ((flags & O_ACCMODE) == O_RDONLY)
                r = shutdown(fd, SHUT_WR);
        else if ((flags & O_ACCMODE) == O_WRONLY)
                r = shutdown(fd, SHUT_RD);
        else
                r = 0;
        if (r < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int fixup_input(
                const ExecContext *context,
                int socket_fd,
                bool apply_tty_stdin) {

        ExecInput std_input;

        assert(context);

        std_input = context->std_input;

        if (is_terminal_input(std_input) && !apply_tty_stdin)
                return EXEC_INPUT_NULL;

        if (std_input == EXEC_INPUT_SOCKET && socket_fd < 0)
                return EXEC_INPUT_NULL;

        if (std_input == EXEC_INPUT_DATA && context->stdin_data_size == 0)
                return EXEC_INPUT_NULL;

        return std_input;
}

static int fixup_output(ExecOutput output, int socket_fd) {

        if (output == EXEC_OUTPUT_SOCKET && socket_fd < 0)
                return EXEC_OUTPUT_INHERIT;

        return output;
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

                /* Try to make this the controlling tty, if it is a tty */
                if (isatty_safe(STDIN_FILENO))
                        (void) ioctl(STDIN_FILENO, TIOCSCTTY, context->std_input == EXEC_INPUT_TTY_FORCE);

                return STDIN_FILENO;
        }

        i = fixup_input(context, socket_fd, params->flags & EXEC_APPLY_TTY_STDIN);

        switch (i) {

        case EXEC_INPUT_NULL:
                return open_null_as(O_RDONLY, STDIN_FILENO);

        case EXEC_INPUT_TTY:
        case EXEC_INPUT_TTY_FORCE:
        case EXEC_INPUT_TTY_FAIL: {
                _cleanup_close_ int tty_fd = -EBADF;
                const char *tty_path;

                tty_path = ASSERT_PTR(exec_context_tty_path(context));

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

                rw = (context->std_output == EXEC_OUTPUT_FILE && streq_ptr(context->stdio_file[STDIN_FILENO], context->stdio_file[STDOUT_FILENO])) ||
                        (context->std_error == EXEC_OUTPUT_FILE && streq_ptr(context->stdio_file[STDIN_FILENO], context->stdio_file[STDERR_FILENO]));

                fd = acquire_path(context->stdio_file[STDIN_FILENO], rw ? O_RDWR : O_RDONLY, 0666 & ~context->umask);
                if (fd < 0)
                        return fd;

                return move_fd(fd, STDIN_FILENO, false);
        }

        default:
                assert_not_reached();
        }
}

static bool can_inherit_stderr_from_stdout(
                const ExecContext *context,
                ExecOutput o,
                ExecOutput e) {

        assert(context);

        /* Returns true, if given the specified STDERR and STDOUT output we can directly dup() the stdout fd to the
         * stderr fd */

        if (e == EXEC_OUTPUT_INHERIT)
                return true;
        if (e != o)
                return false;

        if (e == EXEC_OUTPUT_NAMED_FD)
                return streq_ptr(context->stdio_fdname[STDOUT_FILENO], context->stdio_fdname[STDERR_FILENO]);

        if (IN_SET(e, EXEC_OUTPUT_FILE, EXEC_OUTPUT_FILE_APPEND, EXEC_OUTPUT_FILE_TRUNCATE))
                return streq_ptr(context->stdio_file[STDOUT_FILENO], context->stdio_file[STDERR_FILENO]);

        return true;
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

        i = fixup_input(context, socket_fd, params->flags & EXEC_APPLY_TTY_STDIN);
        o = fixup_output(context->std_output, socket_fd);

        // FIXME: we probably should spend some time here to verify that if we inherit an fd from stdin
        // (possibly indirect via inheritance from stdout) it is actually opened for write!

        if (fileno == STDERR_FILENO) {
                ExecOutput e;
                e = fixup_output(context->std_error, socket_fd);

                /* This expects the input and output are already set up */

                /* Don't change the stderr file descriptor if we inherit all
                 * the way and are not on a tty */
                if (e == EXEC_OUTPUT_INHERIT &&
                    o == EXEC_OUTPUT_INHERIT &&
                    i == EXEC_INPUT_NULL &&
                    !is_terminal_input(context->std_input) &&
                    getppid() != 1)
                        return fileno;

                /* Duplicate from stdout if possible */
                if (can_inherit_stderr_from_stdout(context, o, e))
                        return RET_NERRNO(dup2(STDOUT_FILENO, fileno));

                o = e;

        } else if (o == EXEC_OUTPUT_INHERIT) {
                /* If input got downgraded, inherit the original value */
                if (i == EXEC_INPUT_NULL && is_terminal_input(context->std_input))
                        return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);

                /* If the input is connected to anything that's not a /dev/null or a data fd, inherit that... */
                if (!IN_SET(i, EXEC_INPUT_NULL, EXEC_INPUT_DATA))
                        return RET_NERRNO(dup2(STDIN_FILENO, fileno));

                /* If we are not started from PID 1 we just inherit STDOUT from our parent process. */
                if (getppid() != 1)
                        return fileno;

                /* We need to open /dev/null here anew, to get the right access mode. */
                return open_null_as(O_WRONLY, fileno);
        }

        switch (o) {

        case EXEC_OUTPUT_NULL:
                return open_null_as(O_WRONLY, fileno);

        case EXEC_OUTPUT_TTY:
                if (is_terminal_input(i))
                        return RET_NERRNO(dup2(STDIN_FILENO, fileno));

                return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);

        case EXEC_OUTPUT_KMSG:
        case EXEC_OUTPUT_KMSG_AND_CONSOLE:
        case EXEC_OUTPUT_JOURNAL:
        case EXEC_OUTPUT_JOURNAL_AND_CONSOLE:
                r = connect_logger_as(context, params, o, ident, fileno, uid, gid);
                if (r < 0) {
                        log_exec_warning_errno(context,
                                               params,
                                               r,
                                               "Failed to connect %s to the journal socket, ignoring: %m",
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
                bool rw;
                int fd, flags;

                assert(context->stdio_file[fileno]);

                rw = context->std_input == EXEC_INPUT_FILE &&
                        streq_ptr(context->stdio_file[fileno], context->stdio_file[STDIN_FILENO]);

                if (rw)
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

        r = terminal_reset_defensive(fd, /* switch_to_text= */ true);
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
                const char **ret_username,
                uid_t *ret_uid,
                gid_t *ret_gid,
                const char **ret_home,
                const char **ret_shell) {

        int r;

        assert(user_or_uid);
        assert(ret_username);

        r = get_user_creds(&user_or_uid, ret_uid, ret_gid, ret_home, ret_shell, USER_CREDS_CLEAN);
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

        r = get_group_creds(&group_or_gid, ret_gid, /* flags = */ 0);
        if (r < 0)
                return r;

        /* group_or_gid is normalized by get_group_creds to groupname */
        *ret_groupname = group_or_gid;

        return 0;
}

static int get_supplementary_groups(const ExecContext *c, const char *user,
                                    const char *group, gid_t gid,
                                    gid_t **supplementary_gids, int *ngids) {
        int r, k = 0;
        int ngroups_max;
        bool keep_groups = false;
        gid_t *groups = NULL;
        _cleanup_free_ gid_t *l_gids = NULL;

        assert(c);

        /*
         * If user is given, then lookup GID and supplementary groups list.
         * We avoid NSS lookups for gid=0. Also we have to initialize groups
         * here and as early as possible so we keep the list of supplementary
         * groups of the caller.
         */
        if (user && gid_is_valid(gid) && gid != 0) {
                /* First step, initialize groups from /etc/groups */
                if (initgroups(user, gid) < 0)
                        return -errno;

                keep_groups = true;
        }

        if (strv_isempty(c->supplementary_groups))
                return 0;

        /*
         * If SupplementaryGroups= was passed then NGROUPS_MAX has to
         * be positive, otherwise fail.
         */
        errno = 0;
        ngroups_max = (int) sysconf(_SC_NGROUPS_MAX);
        if (ngroups_max <= 0)
                return errno_or_else(EOPNOTSUPP);

        l_gids = new(gid_t, ngroups_max);
        if (!l_gids)
                return -ENOMEM;

        if (keep_groups) {
                /*
                 * Lookup the list of groups that the user belongs to, we
                 * avoid NSS lookups here too for gid=0.
                 */
                k = ngroups_max;
                if (getgrouplist(user, gid, l_gids, &k) < 0)
                        return -EINVAL;
        } else
                k = 0;

        STRV_FOREACH(i, c->supplementary_groups) {
                const char *g;

                if (k >= ngroups_max)
                        return -E2BIG;

                g = *i;
                r = get_group_creds(&g, l_gids+k, 0);
                if (r < 0)
                        return r;

                k++;
        }

        /*
         * Sets ngids to zero to drop all supplementary groups, happens
         * when we are under root and SupplementaryGroups= is empty.
         */
        if (k == 0) {
                *ngids = 0;
                return 0;
        }

        /* Otherwise get the final list of supplementary groups */
        groups = memdup(l_gids, sizeof(gid_t) * k);
        if (!groups)
                return -ENOMEM;

        *supplementary_gids = groups;
        *ngids = k;

        groups = NULL;

        return 0;
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
        assert(context);
        int r;

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
                                        return log_exec_error_errno(data->context, data->params, r, "Failed to determine credentials directory: %m");

                                if (creds_dir) {
                                        if (setenv("CREDENTIALS_DIRECTORY", creds_dir, /* overwrite= */ true) < 0)
                                                return log_exec_error_errno(data->context, data->params, r, "Failed to set $CREDENTIALS_DIRECTORY: %m");
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
                                log_exec_error_errno(data->context, data->params, r, "Failed to query for password: %m");
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
                        log_exec_error(data->context, data->params, "PAM: %s", mi->msg);
                        break;

                case PAM_TEXT_INFO:
                        log_exec_info(data->context, data->params, "PAM: %s", mi->msg);
                        break;

                default:
                        return PAM_CONV_ERR;
                }
        }

        *ret = TAKE_PTR(responses);
        n = 0;

        return PAM_SUCCESS;
}

static int pam_close_session_and_delete_credentials(pam_handle_t *handle, int flags) {
        int r, s;

        assert(handle);

        r = pam_close_session(handle, flags);
        if (r != PAM_SUCCESS)
                log_debug("pam_close_session() failed: %s", pam_strerror(handle, r));

        s = pam_setcred(handle, PAM_DELETE_CRED | flags);
        if (s != PAM_SUCCESS)
                log_debug("pam_setcred(PAM_DELETE_CRED) failed: %s", pam_strerror(handle, s));

        return r != PAM_SUCCESS ? r : s;
}
#endif

static int setup_pam(
                const ExecContext *context,
                ExecParameters *params,
                const char *user,
                uid_t uid,
                gid_t gid,
                char ***env, /* updated on success */
                const int fds[], size_t n_fds,
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
        pam_handle_t *handle = NULL;
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
        assert(fds || n_fds == 0);
        assert(env);

        /* We set up PAM in the parent process, then fork. The child
         * will then stay around until killed via PR_GET_PDEATHSIG or
         * systemd via the cgroup logic. It will then remove the PAM
         * session again. The parent process will exec() the actual
         * daemon. We do things this way to ensure that the main PID
         * of the daemon is the one we initially fork()ed. */

        r = barrier_create(&barrier);
        if (r < 0)
                goto fail;

        if (log_get_max_level() < LOG_DEBUG)
                flags |= PAM_SILENT;

        pam_code = pam_start(context->pam_name, user, &conv, &handle);
        if (pam_code != PAM_SUCCESS) {
                handle = NULL;
                goto fail;
        }

        const char *tty = context->tty_path;
        if (!tty) {
                _cleanup_free_ char *q = NULL;

                /* Hmm, so no TTY was explicitly passed, but an fd passed to us directly might be a TTY. Let's figure
                 * out if that's the case, and read the TTY off it. */

                if (getttyname_malloc(STDIN_FILENO, &q) >= 0)
                        tty = strjoina("/dev/", q);
        }

        if (tty) {
                pam_code = pam_set_item(handle, PAM_TTY, tty);
                if (pam_code != PAM_SUCCESS)
                        goto fail;
        }

        STRV_FOREACH(nv, *env) {
                pam_code = pam_putenv(handle, *nv);
                if (pam_code != PAM_SUCCESS)
                        goto fail;
        }

        pam_code = pam_acct_mgmt(handle, flags);
        if (pam_code != PAM_SUCCESS)
                goto fail;

        pam_code = pam_setcred(handle, PAM_ESTABLISH_CRED | flags);
        if (pam_code != PAM_SUCCESS)
                log_debug("pam_setcred(PAM_ESTABLISH_CRED) failed, ignoring: %s", pam_strerror(handle, pam_code));

        pam_code = pam_open_session(handle, flags);
        if (pam_code != PAM_SUCCESS)
                goto fail;

        close_session = true;

        e = pam_getenvlist(handle);
        if (!e) {
                pam_code = PAM_BUF_ERR;
                goto fail;
        }

        /* Block SIGTERM, so that we know that it won't get lost in the child */

        assert_se(sigprocmask_many(SIG_BLOCK, &old_ss, SIGTERM) >= 0);

        parent_pid = getpid_cached();

        r = safe_fork("(sd-pam)", 0, NULL);
        if (r < 0)
                goto fail;
        if (r == 0) {
                int ret = EXIT_PAM;

                /* The child's job is to reset the PAM session on termination */
                barrier_set_role(&barrier, BARRIER_CHILD);

                /* Make sure we don't keep open the passed fds in this child. We assume that otherwise only
                 * those fds are open here that have been opened by PAM. */
                (void) close_many(fds, n_fds);

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
                        pam_code = pam_close_session_and_delete_credentials(handle, flags);
                        if (pam_code != PAM_SUCCESS)
                                goto child_finish;
                }

                ret = 0;

        child_finish:
                /* NB: pam_end() when called in child processes should set PAM_DATA_SILENT to let the module
                 * know about this. See pam_end(3) */
                (void) pam_end(handle, pam_code | flags | PAM_DATA_SILENT);
                _exit(ret);
        }

        barrier_set_role(&barrier, BARRIER_PARENT);

        /* If the child was forked off successfully it will do all the cleanups, so forget about the handle
         * here. */
        handle = NULL;

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
                log_error("PAM failed: %s", pam_strerror(handle, pam_code));
                r = -EPERM;  /* PAM errors do not map to errno */
        } else
                log_error_errno(r, "PAM failed: %m");

        if (handle) {
                if (close_session)
                        pam_code = pam_close_session_and_delete_credentials(handle, flags);

                (void) pam_end(handle, pam_code | flags);
        }

        closelog();
        return r;
#else
        return 0;
#endif
}

static void rename_process_from_path(const char *path) {
        _cleanup_free_ char *buf = NULL;
        const char *p;

        assert(path);

        /* This resulting string must fit in 10 chars (i.e. the length of "/sbin/init") to look pretty in
         * /bin/ps */

        if (path_extract_filename(path, &buf) < 0) {
                rename_process("(...)");
                return;
        }

        size_t l = strlen(buf);
        if (l > 8) {
                /* The end of the process name is usually more interesting, since the first bit might just be
                 * "systemd-" */
                p = buf + l - 8;
                l = 8;
        } else
                p = buf;

        char process_name[11];
        process_name[0] = '(';
        memcpy(process_name+1, p, l);
        process_name[1+l] = ')';
        process_name[1+l+1] = 0;

        (void) rename_process(process_name);
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
        bool has_capget = false, has_capset = false, has_prctl = false;

        assert(c);

        /* No syscall filter, we are allowed to drop privileges */
        if (hashmap_isempty(c->syscall_filter))
                return true;

        HASHMAP_FOREACH_KEY(val, id, c->syscall_filter) {
                _cleanup_free_ char *name = NULL;

                name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);

                if (streq(name, "capget"))
                        has_capget = true;
                else if (streq(name, "capset"))
                        has_capset = true;
                else if (streq(name, "prctl"))
                        has_prctl = true;
        }

        if (c->syscall_allow_list)
                return has_capget && has_capset && has_prctl;
        else
                return !(has_capget || has_capset || has_prctl);
}

static bool skip_seccomp_unavailable(const ExecContext *c, const ExecParameters *p, const char* msg) {

        if (is_seccomp_available())
                return false;

        log_exec_debug(c, p, "SECCOMP features not detected in the kernel, skipping %s", msg);
        return true;
}

static int apply_syscall_filter(const ExecContext *c, const ExecParameters *p) {
        uint32_t negative_action, default_action, action;
        int r;

        assert(c);
        assert(p);

        if (!context_has_syscall_filters(c))
                return 0;

        if (skip_seccomp_unavailable(c, p, "SystemCallFilter="))
                return 0;

        negative_action = c->syscall_errno == SECCOMP_ERROR_NUMBER_KILL ? scmp_act_kill_process() : SCMP_ACT_ERRNO(c->syscall_errno);

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
#ifdef SCMP_ACT_LOG
        uint32_t default_action, action;
#endif

        assert(c);
        assert(p);

        if (!context_has_syscall_logs(c))
                return 0;

#ifdef SCMP_ACT_LOG
        if (skip_seccomp_unavailable(c, p, "SystemCallLog="))
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
#else
        /* old libseccomp */
        log_exec_debug(c, p, "SECCOMP feature SCMP_ACT_LOG not available, skipping SystemCallLog=");
        return 0;
#endif
}

static int apply_syscall_archs(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (set_isempty(c->syscall_archs))
                return 0;

        if (skip_seccomp_unavailable(c, p, "SystemCallArchitectures="))
                return 0;

        return seccomp_restrict_archs(c->syscall_archs);
}

static int apply_address_families(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!context_has_address_families(c))
                return 0;

        if (skip_seccomp_unavailable(c, p, "RestrictAddressFamilies="))
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
                log_exec_debug(c, p, "Enabled MemoryDenyWriteExecute= with PR_SET_MDWE");
                return 0;
        }
        if (r < 0 && errno != EINVAL)
                return log_exec_debug_errno(c,
                                            p,
                                            errno,
                                            "Failed to enable MemoryDenyWriteExecute= with PR_SET_MDWE: %m");
        /* else use seccomp */
        log_exec_debug(c, p, "Kernel doesn't support PR_SET_MDWE: falling back to seccomp");

        if (skip_seccomp_unavailable(c, p, "MemoryDenyWriteExecute="))
                return 0;

        return seccomp_memory_deny_write_execute();
}

static int apply_restrict_realtime(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->restrict_realtime)
                return 0;

        if (skip_seccomp_unavailable(c, p, "RestrictRealtime="))
                return 0;

        return seccomp_restrict_realtime();
}

static int apply_restrict_suid_sgid(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->restrict_suid_sgid)
                return 0;

        if (skip_seccomp_unavailable(c, p, "RestrictSUIDSGID="))
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

        if (skip_seccomp_unavailable(c, p, "ProtectKernelTunables="))
                return 0;

        return seccomp_protect_sysctl();
}

static int apply_protect_kernel_modules(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        /* Turn off module syscalls on ProtectKernelModules=yes */

        if (!c->protect_kernel_modules)
                return 0;

        if (skip_seccomp_unavailable(c, p, "ProtectKernelModules="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_MODULE, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_protect_kernel_logs(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->protect_kernel_logs)
                return 0;

        if (skip_seccomp_unavailable(c, p, "ProtectKernelLogs="))
                return 0;

        return seccomp_protect_syslog();
}

static int apply_protect_clock(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!c->protect_clock)
                return 0;

        if (skip_seccomp_unavailable(c, p, "ProtectClock="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_CLOCK, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_private_devices(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        /* If PrivateDevices= is set, also turn off iopl and all @raw-io syscalls. */

        if (!c->private_devices)
                return 0;

        if (skip_seccomp_unavailable(c, p, "PrivateDevices="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_RAW_IO, SCMP_ACT_ERRNO(EPERM), false);
}

static int apply_restrict_namespaces(const ExecContext *c, const ExecParameters *p) {
        assert(c);
        assert(p);

        if (!exec_context_restrict_namespaces_set(c))
                return 0;

        if (skip_seccomp_unavailable(c, p, "RestrictNamespaces="))
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

        if (skip_seccomp_unavailable(c, p, "LockPersonality="))
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
                log_exec_debug(c, p, "LSM BPF not supported, skipping RestrictFileSystems=");
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

        if (c->protect_hostname == PROTECT_HOSTNAME_NO)
                return 0;

        if (ns_type_supported(NAMESPACE_UTS)) {
                if (unshare(CLONE_NEWUTS) < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno)) {
                                *ret_exit_status = EXIT_NAMESPACE;
                                return log_exec_error_errno(c, p, errno, "Failed to set up UTS namespacing: %m");
                        }

                        log_exec_warning(c, p,
                                         "ProtectHostname=%s is configured, but UTS namespace setup is prohibited (container manager?), ignoring namespace setup.",
                                         protect_hostname_to_string(c->protect_hostname));

                } else if (c->private_hostname) {
                        r = sethostname_idempotent(c->private_hostname);
                        if (r < 0) {
                                *ret_exit_status = EXIT_NAMESPACE;
                                return log_exec_error_errno(c, p, r, "Failed to set private hostname '%s': %m", c->private_hostname);
                        }
                }
        } else
                log_exec_warning(c, p,
                                 "ProtectHostname=%s is configured, but the kernel does not support UTS namespaces, ignoring namespace setup.",
                                 protect_hostname_to_string(c->protect_hostname));

#if HAVE_SECCOMP
        if (c->protect_hostname == PROTECT_HOSTNAME_YES) {
                if (skip_seccomp_unavailable(c, p, "ProtectHostname="))
                        return 0;

                r = seccomp_protect_hostname();
                if (r < 0) {
                        *ret_exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(c, p, r, "Failed to apply hostname restrictions: %m");
                }
        }
#endif

        return 0;
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

static const char *exec_directory_env_name_to_string(ExecDirectoryType t);

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
                size_t n_fds,
                const char *home,
                const char *username,
                const char *shell,
                dev_t journal_stream_dev,
                ino_t journal_stream_ino,
                const char *memory_pressure_path,
                bool needs_sandboxing,
                char ***ret) {

        _cleanup_strv_free_ char **our_env = NULL;
        size_t n_env = 0;
        char *x;
        int r;

        assert(c);
        assert(p);
        assert(ret);

#define N_ENV_VARS 20
        our_env = new0(char*, N_ENV_VARS + _EXEC_DIRECTORY_TYPE_MAX);
        if (!our_env)
                return -ENOMEM;

        if (n_fds > 0) {
                _cleanup_free_ char *joined = NULL;

                if (asprintf(&x, "LISTEN_PID="PID_FMT, getpid_cached()) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (asprintf(&x, "LISTEN_FDS=%zu", n_fds) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                joined = strv_join(p->fd_names, ":");
                if (!joined)
                        return -ENOMEM;

                x = strjoin("LISTEN_FDNAMES=", joined);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if ((p->flags & EXEC_SET_WATCHDOG) && p->watchdog_usec > 0) {
                if (asprintf(&x, "WATCHDOG_PID="PID_FMT, getpid_cached()) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (asprintf(&x, "WATCHDOG_USEC="USEC_FMT, p->watchdog_usec) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        /* If this is D-Bus, tell the nss-systemd module, since it relies on being able to use blocking
         * Varlink calls back to us for look up dynamic users in PID 1. Break the deadlock between D-Bus and
         * PID 1 by disabling use of PID1' NSS interface for looking up dynamic users. */
        if (p->flags & EXEC_NSS_DYNAMIC_BYPASS) {
                x = strdup("SYSTEMD_NSS_DYNAMIC_BYPASS=1");
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        /* We query "root" if this is a system unit and User= is not specified. $USER is always set. $HOME
         * could cause problem for e.g. getty, since login doesn't override $HOME, and $LOGNAME and $SHELL don't
         * really make much sense since we're not logged in. Hence we conditionalize the three based on
         * SetLoginEnvironment= switch. */
        if (!c->user && !c->dynamic_user && p->runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                r = get_fixed_user("root", &username, NULL, NULL, &home, &shell);
                if (r < 0)
                        return log_exec_debug_errno(c,
                                                    p,
                                                    r,
                                                    "Failed to determine user credentials for root: %m");
        }

        bool set_user_login_env = exec_context_get_set_login_environment(c);

        if (username) {
                x = strjoin("USER=", username);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (set_user_login_env) {
                        x = strjoin("LOGNAME=", username);
                        if (!x)
                                return -ENOMEM;
                        our_env[n_env++] = x;
                }
        }

        /* Note that we don't set $HOME or $SHELL if they are not particularly enlightening anyway
         * (i.e. are "/" or "/bin/nologin"). */

        if (home && set_user_login_env && !empty_or_root(home)) {
                x = strjoin("HOME=", home);
                if (!x)
                        return -ENOMEM;

                path_simplify(x + 5);
                our_env[n_env++] = x;
        }

        if (shell && set_user_login_env && !shell_is_placeholder(shell)) {
                x = strjoin("SHELL=", shell);
                if (!x)
                        return -ENOMEM;

                path_simplify(x + 6);
                our_env[n_env++] = x;
        }

        if (!sd_id128_is_null(p->invocation_id)) {
                assert(p->invocation_id_string);

                x = strjoin("INVOCATION_ID=", p->invocation_id_string);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        if (exec_context_needs_term(c)) {
                _cleanup_free_ char *cmdline = NULL;
                const char *tty_path, *term = NULL;

                tty_path = exec_context_tty_path(c);

                /* If we are forked off PID 1 and we are supposed to operate on /dev/console, then let's try
                 * to inherit the $TERM set for PID 1. This is useful for containers so that the $TERM the
                 * container manager passes to PID 1 ends up all the way in the console login shown. */

                if (path_equal(tty_path, "/dev/console") && getppid() == 1)
                        term = getenv("TERM");
                else if (tty_path && in_charset(skip_dev_prefix(tty_path), ALPHANUMERICAL)) {
                        _cleanup_free_ char *key = NULL;

                        key = strjoin("systemd.tty.term.", skip_dev_prefix(tty_path));
                        if (!key)
                                return -ENOMEM;

                        r = proc_cmdline_get_key(key, 0, &cmdline);
                        if (r < 0)
                                log_exec_debug_errno(c,
                                                     p,
                                                     r,
                                                     "Failed to read %s from kernel cmdline, ignoring: %m",
                                                     key);
                        else if (r > 0)
                                term = cmdline;
                }

                if (!term)
                        term = default_term_for_tty(tty_path);

                x = strjoin("TERM=", term);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (journal_stream_dev != 0 && journal_stream_ino != 0) {
                if (asprintf(&x, "JOURNAL_STREAM=" DEV_FMT ":" INO_FMT, journal_stream_dev, journal_stream_ino) < 0)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        if (c->log_namespace) {
                x = strjoin("LOG_NAMESPACE=", c->log_namespace);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                _cleanup_free_ char *joined = NULL;
                const char *n;

                if (!p->prefix[t])
                        continue;

                if (c->directories[t].n_items == 0)
                        continue;

                n = exec_directory_env_name_to_string(t);
                if (!n)
                        continue;

                for (size_t i = 0; i < c->directories[t].n_items; i++) {
                        _cleanup_free_ char *prefixed = NULL;

                        prefixed = path_join(p->prefix[t], c->directories[t].items[i].path);
                        if (!prefixed)
                                return -ENOMEM;

                        if (!strextend_with_separator(&joined, ":", prefixed))
                                return -ENOMEM;
                }

                x = strjoin(n, "=", joined);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        _cleanup_free_ char *creds_dir = NULL;
        r = exec_context_get_credential_directory(c, p, p->unit_id, &creds_dir);
        if (r < 0)
                return r;
        if (r > 0) {
                x = strjoin("CREDENTIALS_DIRECTORY=", creds_dir);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        if (asprintf(&x, "SYSTEMD_EXEC_PID=" PID_FMT, getpid_cached()) < 0)
                return -ENOMEM;

        our_env[n_env++] = x;

        if (memory_pressure_path) {
                x = strjoin("MEMORY_PRESSURE_WATCH=", memory_pressure_path);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;

                if (cgroup_context && !path_equal(memory_pressure_path, "/dev/null")) {
                        _cleanup_free_ char *b = NULL, *e = NULL;

                        if (asprintf(&b, "%s " USEC_FMT " " USEC_FMT,
                                     MEMORY_PRESSURE_DEFAULT_TYPE,
                                     cgroup_context->memory_pressure_threshold_usec == USEC_INFINITY ? MEMORY_PRESSURE_DEFAULT_THRESHOLD_USEC :
                                     CLAMP(cgroup_context->memory_pressure_threshold_usec, 1U, MEMORY_PRESSURE_DEFAULT_WINDOW_USEC),
                                     MEMORY_PRESSURE_DEFAULT_WINDOW_USEC) < 0)
                                return -ENOMEM;

                        if (base64mem(b, strlen(b) + 1, &e) < 0)
                                return -ENOMEM;

                        x = strjoin("MEMORY_PRESSURE_WRITE=", e);
                        if (!x)
                                return -ENOMEM;

                        our_env[n_env++] = x;
                }
        }

        if (p->notify_socket) {
                x = strjoin("NOTIFY_SOCKET=", exec_get_private_notify_socket_path(c, p, needs_sandboxing) ?: p->notify_socket);
                if (!x)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        assert(n_env < N_ENV_VARS + _EXEC_DIRECTORY_TYPE_MAX);
#undef N_ENV_VARS

        *ret = TAKE_PTR(our_env);

        return 0;
}

static int build_pass_environment(const ExecContext *c, char ***ret) {
        _cleanup_strv_free_ char **pass_env = NULL;
        size_t n_env = 0;

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

static int setup_private_users(PrivateUsers private_users, uid_t ouid, gid_t ogid, uid_t uid, gid_t gid, bool allow_setgroups) {
        _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        _cleanup_close_ int unshare_ready_fd = -EBADF;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
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

        if (private_users == PRIVATE_USERS_NO)
                return 0;

        if (private_users == PRIVATE_USERS_IDENTITY) {
                uid_map = strdup("0 0 65536\n");
                if (!uid_map)
                        return -ENOMEM;
        } else if (private_users == PRIVATE_USERS_FULL) {
                /* Map all UID/GID from original to new user namespace. We can't use `0 0 UINT32_MAX` because
                 * this is the same UID/GID map as the init user namespace and systemd's running_in_userns()
                 * checks whether its in a user namespace by comparing uid_map/gid_map to `0 0 UINT32_MAX`.
                 * Thus, we still map all UIDs/GIDs but do it using two extents to differentiate the new user
                 * namespace from the init namespace:
                 *   0 0 1
                 *   1 1 UINT32_MAX - 1
                 *
                 * systemd will remove the heuristic in running_in_userns() and use namespace inodes in version 258
                 * (PR #35382). But some users may be running a container image with older systemd < 258 so we keep
                 * this uid_map/gid_map hack until version 259 for version N-1 compatibility.
                 *
                 * TODO: Switch to `0 0 UINT32_MAX` in systemd v259.
                 *
                 * Note the kernel defines the UID range between 0 and UINT32_MAX so we map all UIDs even though
                 * the UID range beyond INT32_MAX (e.g. i.e. the range above the signed 32-bit range) is
                 * icky. For example, setfsuid() returns the old UID as signed integer. But units can decide to
                 * use these UIDs/GIDs so we need to map them. */
                r = asprintf(&uid_map, "0 0 1\n"
                                       "1 1 " UID_FMT "\n", (uid_t) (UINT32_MAX - 1));
                if (r < 0)
                        return -ENOMEM;
        /* Can only set up multiple mappings with CAP_SETUID. */
        } else if (have_effective_cap(CAP_SETUID) > 0 && uid != ouid && uid_is_valid(uid)) {
                r = asprintf(&uid_map,
                             UID_FMT " " UID_FMT " 1\n"     /* Map $OUID → $OUID */
                             UID_FMT " " UID_FMT " 1\n",    /* Map $UID → $UID */
                             ouid, ouid, uid, uid);
                if (r < 0)
                        return -ENOMEM;
        } else {
                r = asprintf(&uid_map,
                             UID_FMT " " UID_FMT " 1\n",    /* Map $OUID → $OUID */
                             ouid, ouid);
                if (r < 0)
                        return -ENOMEM;
        }

        if (private_users == PRIVATE_USERS_IDENTITY) {
                gid_map = strdup("0 0 65536\n");
                if (!gid_map)
                        return -ENOMEM;
        } else if (private_users == PRIVATE_USERS_FULL) {
                r = asprintf(&gid_map, "0 0 1\n"
                                       "1 1 " GID_FMT "\n", (gid_t) (UINT32_MAX - 1));
                if (r < 0)
                        return -ENOMEM;
        /* Can only set up multiple mappings with CAP_SETGID. */
        } else if (have_effective_cap(CAP_SETGID) > 0 && gid != ogid && gid_is_valid(gid)) {
                r = asprintf(&gid_map,
                             GID_FMT " " GID_FMT " 1\n"     /* Map $OGID → $OGID */
                             GID_FMT " " GID_FMT " 1\n",    /* Map $GID → $GID */
                             ogid, ogid, gid, gid);
                if (r < 0)
                        return -ENOMEM;
        } else {
                r = asprintf(&gid_map,
                             GID_FMT " " GID_FMT " 1\n",    /* Map $OGID -> $OGID */
                             ogid, ogid);
                if (r < 0)
                        return -ENOMEM;
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

        r = safe_fork("(sd-userns)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                _cleanup_close_ int fd = -EBADF;
                const char *a;
                pid_t ppid;

                /* Child process, running in the original user namespace. Let's update the parent's UID/GID map from
                 * here, after the parent opened its own user namespace. */

                ppid = getppid();
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* Wait until the parent unshared the user namespace */
                if (read(unshare_ready_fd, &c, sizeof(c)) < 0)
                        report_errno_and_exit(errno_pipe[1], -errno);

                /* Disable the setgroups() system call in the child user namespace, for good, unless PrivateUsers=full
                 * and using the system service manager. */
                a = procfs_file_alloca(ppid, "setgroups");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        if (errno != ENOENT) {
                                r = log_debug_errno(errno, "Failed to open %s: %m", a);
                                report_errno_and_exit(errno_pipe[1], r);
                        }

                        /* If the file is missing the kernel is too old, let's continue anyway. */
                } else {
                        const char *setgroups = allow_setgroups ? "allow\n" : "deny\n";
                        if (write(fd, setgroups, strlen(setgroups)) < 0) {
                                r = log_debug_errno(errno, "Failed to write '%s' to %s: %m", setgroups, a);
                                report_errno_and_exit(errno_pipe[1], r);
                        }

                        fd = safe_close(fd);
                }

                /* First write the GID map */
                a = procfs_file_alloca(ppid, "gid_map");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        r = log_debug_errno(errno, "Failed to open %s: %m", a);
                        report_errno_and_exit(errno_pipe[1], r);
                }

                if (write(fd, gid_map, strlen(gid_map)) < 0) {
                        r = log_debug_errno(errno, "Failed to write GID map to %s: %m", a);
                        report_errno_and_exit(errno_pipe[1], r);
                }

                fd = safe_close(fd);

                /* The write the UID map */
                a = procfs_file_alloca(ppid, "uid_map");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        r = log_debug_errno(errno, "Failed to open %s: %m", a);
                        report_errno_and_exit(errno_pipe[1], r);
                }

                if (write(fd, uid_map, strlen(uid_map)) < 0) {
                        r = log_debug_errno(errno, "Failed to write UID map to %s: %m", a);
                        report_errno_and_exit(errno_pipe[1], r);
                }

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

        r = wait_for_terminate_and_check("(sd-userns)", TAKE_PID(pid), 0);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS) /* If something strange happened with the child, let's consider this fatal, too */
                return -EIO;

        return 1;
}

static int can_mount_proc(const ExecContext *c, ExecParameters *p) {
        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        ssize_t n;
        int r;

        assert(c);
        assert(p);

        /* If running via unprivileged user manager and /proc/ is masked (e.g. /proc/kmsg is over-mounted with tmpfs
         * like systemd-nspawn does), then mounting /proc/ will fail with EPERM. This is due to a kernel restriction
         * where unprivileged user namespaces cannot mount a less restrictive instance of /proc. */

        /* Create a communication channel so that the child can tell the parent a proper error code in case it
         * failed. */
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return log_exec_debug_errno(c, p, errno, "Failed to create pipe for communicating with child process (sd-proc-check): %m");

        /* Fork a child process into its own mount and PID namespace. Note safe_fork() already remounts / as SLAVE
         * with FORK_MOUNTNS_SLAVE. */
        r = safe_fork("(sd-proc-check)",
                      FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE|FORK_NEW_PIDNS, &pid);
        if (r < 0)
                return log_exec_debug_errno(c, p, r, "Failed to fork child process (sd-proc-check): %m");
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
                return log_exec_debug_errno(c, p, errno, "Failed to read errno from pipe with child process (sd-proc-check): %m");
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

        r = wait_for_terminate_and_check("(sd-proc-check)", TAKE_PID(pid), 0 /* flags= */);
        if (r < 0)
                return log_exec_debug_errno(c, p, r, "Failed to wait for (sd-proc-check) child process to terminate: %m");
        if (r != EXIT_SUCCESS) /* If something strange happened with the child, let's consider this fatal, too */
                return log_exec_debug_errno(c, p, SYNTHETIC_ERRNO(EIO), "Child process (sd-proc-check) exited with unexpected exit status '%d'.", r);

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
                return log_exec_debug_errno(c, p, errno, "Failed to create pipe for communicating with parent process: %m");

        r = pidref_safe_fork("(sd-pidns-child)", FORK_NEW_PIDNS, &pidref);
        if (r < 0)
                return log_exec_debug_errno(c, p, r, "Failed to fork child into new pid namespace: %m");
        if (r > 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* In the parent process, we send the child pidref to the manager and exit.
                 * If PIDFD is not supported, only the child PID is sent. The server then
                 * uses the child PID to set the new exec main process. */
                q = send_one_fd_iov(
                                p->pidref_transport_fd,
                                pidref.fd,
                                &IOVEC_MAKE(&pidref.pid, sizeof(pidref.pid)),
                                /*iovlen=*/ 1,
                                /*flags=*/ 0);
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
                return log_exec_debug_errno(c, p, errno, "Failed to read errno from pipe with parent process: %m");
        if (n != sizeof(r))
                return log_exec_debug_errno(c, p, SYNTHETIC_ERRNO(EIO), "Failed to read enough bytes from pipe with parent process");
        if (r < 0)
                return log_exec_debug_errno(c, p, r, "Failed to send child pidref to manager: %m");

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

                                        log_exec_notice(context, params, "Unit state directory %s missing but matching configuration directory %s exists, assuming update from systemd 253 or older, creating compatibility symlink.", p, q);
                                        continue;
                                } else if (r != -ENOENT)
                                        log_exec_warning_errno(context, params, r, "Unable to detect whether unit configuration directory '%s' exists, assuming not: %m", q);

                        } else if (r < 0)
                                log_exec_warning_errno(context, params, r, "Unable to detect whether unit state directory '%s' is missing, assuming it is: %m", p);
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

                                log_exec_info(context,
                                              params,
                                              "Found pre-existing public %s= directory %s, migrating to %s.\n"
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

                                        log_exec_info(context,
                                                      params,
                                                      "Found pre-existing private %s= directory %s, migrating to %s.\n"
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
                                                log_exec_warning(context,
                                                                 params,
                                                                 "%s \'%s\' already exists but the mode is different. "
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
                const ExecParameters *params,
                const ExecContext *context,
                int executable_fd) {
        int r;

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

        if (root_dir || root_image)
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
        assert(root_image);
        assert(root_directory);

        if (!*root_image && !*root_directory)
                return 0;

        if (!runtime || !runtime->ephemeral_copy)
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
                const void *root_hash,
                size_t root_hash_size,
                const char *root_hash_path,
                const void *root_hash_sig,
                size_t root_hash_sig_size,
                const char *root_hash_sig_path,
                const char *verity_data_path) {

        int r;

        assert(verity);

        if (root_hash) {
                void *d;

                d = memdup(root_hash, root_hash_size);
                if (!d)
                        return -ENOMEM;

                free_and_replace(verity->root_hash, d);
                verity->root_hash_size = root_hash_size;
                verity->designator = PARTITION_ROOT;
        }

        if (root_hash_sig) {
                void *d;

                d = memdup(root_hash_sig, root_hash_sig_size);
                if (!d)
                        return -ENOMEM;

                free_and_replace(verity->root_hash_sig, d);
                verity->root_hash_sig_size = root_hash_sig_size;
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
        assert(params);
        assert(ret_root_image);
        assert(ret_root_directory);

        if (context->root_image) {
                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              context->root_image,
                              &pick_filter_image_raw,
                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                              &result);
                if (r < 0) {
                        *reterr_path = strdup(context->root_image);
                        return r;
                }

                if (!result.path) {
                        *reterr_path = strdup(context->root_image);
                        return log_exec_debug_errno(context, params, SYNTHETIC_ERRNO(ENOENT), "No matching entry in .v/ directory %s found.", context->root_image);
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
                              &pick_filter_image_dir,
                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                              &result);
                if (r < 0) {
                        *reterr_path = strdup(context->root_directory);
                        return r;
                }

                if (!result.path) {
                        *reterr_path = strdup(context->root_directory);
                        return log_exec_debug_errno(context, params, SYNTHETIC_ERRNO(ENOENT), "No matching entry in .v/ directory %s found.", context->root_directory);
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
                char **reterr_path,
                uid_t exec_directory_uid,
                gid_t exec_directory_gid) {

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

        CLEANUP_ARRAY(bind_mounts, n_bind_mounts, bind_mount_free_many);

        if (params->flags & EXEC_APPLY_CHROOT) {
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
        if (exec_is_cgroup_mount_read_only(context, params) && memory_pressure_path && !streq(memory_pressure_path, "/dev/null")) {
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

                if (context->private_tmp == PRIVATE_TMP_CONNECTED && runtime && runtime->shared) {
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
                log_exec_debug(context,
                               params,
                               "shared mount propagation hidden by other fs namespacing unit settings: ignoring");

        r = exec_context_get_credential_directory(context, params, params->unit_id, &creds_path);
        if (r < 0)
                return r;

        if (params->runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                propagate_dir = path_join("/run/systemd/propagate/", params->unit_id);
                if (!propagate_dir)
                        return -ENOMEM;

                incoming_dir = strdup("/run/systemd/incoming");
                if (!incoming_dir)
                        return -ENOMEM;

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

                if (setup_os_release_symlink) {
                        if (asprintf(&host_os_release_stage,
                                     "/run/user/" UID_FMT "/systemd/propagate/.os-release-stage",
                                     geteuid()) < 0)
                                return -ENOMEM;
                }
        }

        if (root_image) {
                r = verity_settings_prepare(
                        &verity,
                        root_image,
                        context->root_hash, context->root_hash_size, context->root_hash_path,
                        context->root_hash_sig, context->root_hash_sig_size, context->root_hash_sig_path,
                        context->root_verity);
                if (r < 0)
                        return r;
        }

        NamespaceParameters parameters = {
                .runtime_scope = params->runtime_scope,

                .root_directory = root_dir,
                .root_image = root_image,
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

                .protect_control_groups = needs_sandboxing ? exec_get_protect_control_groups(context, params) : PROTECT_CONTROL_GROUPS_NO,
                .protect_kernel_tunables = needs_sandboxing && context->protect_kernel_tunables,
                .protect_kernel_modules = needs_sandboxing && context->protect_kernel_modules,
                .protect_kernel_logs = needs_sandboxing && context->protect_kernel_logs,

                .private_dev = needs_sandboxing && context->private_devices,
                .private_network = needs_sandboxing && exec_needs_network_namespace(context),
                .private_ipc = needs_sandboxing && exec_needs_ipc_namespace(context),
                .private_pids = needs_sandboxing && exec_needs_pid_namespace(context) ? context->private_pids : PRIVATE_PIDS_NO,
                .private_tmp = needs_sandboxing ? context->private_tmp : PRIVATE_TMP_NO,

                .mount_apivfs = needs_sandboxing && exec_context_get_effective_mount_apivfs(context),
                .bind_log_sockets = needs_sandboxing && exec_context_get_effective_bind_log_sockets(context),

                /* If NNP is on, we can turn on MS_NOSUID, since it won't have any effect anymore. */
                .mount_nosuid = needs_sandboxing && context->no_new_privileges && !mac_selinux_use(),

                .protect_home = needs_sandboxing ? context->protect_home : PROTECT_HOME_NO,
                .protect_hostname = needs_sandboxing ? context->protect_hostname : PROTECT_HOSTNAME_NO,
                .protect_system = needs_sandboxing ? context->protect_system : PROTECT_SYSTEM_NO,
                .protect_proc = needs_sandboxing ? context->protect_proc : PROTECT_PROC_DEFAULT,
                .proc_subset = needs_sandboxing ? context->proc_subset : PROC_SUBSET_ALL,
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
                        return log_exec_debug_errno(context,
                                                    params,
                                                    SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                    "Failed to set up namespace, and refusing to continue since "
                                                    "the selected namespacing options alter mount environment non-trivially.\n"
                                                    "Bind mounts: %zu, temporary filesystems: %zu, root directory: %s, root image: %s, dynamic user: %s",
                                                    n_bind_mounts,
                                                    context->n_temporary_filesystems,
                                                    yes_no(root_dir),
                                                    yes_no(root_image),
                                                    yes_no(context->dynamic_user));

                log_exec_debug(context, params, "Failed to set up namespace, assuming containerized execution and ignoring.");
                return 0;
        }

        return r;
}

static int apply_working_directory(
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                const char *home) {

        const char *wd;
        int r;

        assert(context);

        if (context->working_directory_home) {
                if (!home)
                        return -ENXIO;

                wd = home;
        } else
                wd = empty_to_root(context->working_directory);

        if (params->flags & EXEC_APPLY_CHROOT)
                r = RET_NERRNO(chdir(wd));
        else {
                _cleanup_close_ int dfd = -EBADF;

                r = chase(wd,
                          (runtime ? runtime->ephemeral_copy : NULL) ?: context->root_directory,
                          CHASE_PREFIX_ROOT|CHASE_AT_RESOLVE_IN_ROOT,
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
        assert(exit_status);

        if (params->flags & EXEC_APPLY_CHROOT)
                if (!needs_mount_ns && context->root_directory)
                        if (chroot((runtime ? runtime->ephemeral_copy : NULL) ?: context->root_directory) < 0) {
                                *exit_status = EXIT_CHROOT;
                                return -errno;
                        }

        return 0;
}

static int setup_keyring(
                const ExecContext *context,
                const ExecParameters *p,
                uid_t uid, gid_t gid) {

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
                        return log_exec_error_errno(context,
                                                    p,
                                                    errno,
                                                    "Failed to change GID for user keyring: %m");
        }

        if (uid_is_valid(uid) && uid != saved_uid) {
                if (setreuid(uid, -1) < 0) {
                        r = log_exec_error_errno(context,
                                                 p,
                                                 errno,
                                                 "Failed to change UID for user keyring: %m");
                        goto out;
                }
        }

        keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
        if (keyring == -1) {
                if (errno == ENOSYS)
                        log_exec_debug_errno(context,
                                             p,
                                             errno,
                                             "Kernel keyring not supported, ignoring.");
                else if (ERRNO_IS_PRIVILEGE(errno))
                        log_exec_debug_errno(context,
                                             p,
                                             errno,
                                             "Kernel keyring access prohibited, ignoring.");
                else if (errno == EDQUOT)
                        log_exec_debug_errno(context,
                                             p,
                                             errno,
                                             "Out of kernel keyrings to allocate, ignoring.");
                else
                        r = log_exec_error_errno(context,
                                                 p,
                                                 errno,
                                                 "Setting up kernel keyring failed: %m");

                goto out;
        }

        /* When requested link the user keyring into the session keyring. */
        if (context->keyring_mode == EXEC_KEYRING_SHARED) {

                if (keyctl(KEYCTL_LINK,
                           KEY_SPEC_USER_KEYRING,
                           KEY_SPEC_SESSION_KEYRING, 0, 0) < 0) {
                        r = log_exec_error_errno(context,
                                                 p,
                                                 errno,
                                                 "Failed to link user keyring into session keyring: %m");
                        goto out;
                }
        }

        /* Restore uid/gid back */
        if (uid_is_valid(uid) && uid != saved_uid) {
                if (setreuid(saved_uid, -1) < 0) {
                        r = log_exec_error_errno(context,
                                                 p,
                                                 errno,
                                                 "Failed to change UID back for user keyring: %m");
                        goto out;
                }
        }

        if (gid_is_valid(gid) && gid != saved_gid) {
                if (setregid(saved_gid, -1) < 0)
                        return log_exec_error_errno(context,
                                                    p,
                                                    errno,
                                                    "Failed to change GID back for user keyring: %m");
        }

        /* Populate they keyring with the invocation ID by default, as original saved_uid. */
        if (!sd_id128_is_null(p->invocation_id)) {
                key_serial_t key;

                key = add_key("user",
                              "invocation_id",
                              &p->invocation_id,
                              sizeof(p->invocation_id),
                              KEY_SPEC_SESSION_KEYRING);
                if (key == -1)
                        log_exec_debug_errno(context,
                                             p,
                                             errno,
                                             "Failed to add invocation ID to keyring, ignoring: %m");
                else {
                        if (keyctl(KEYCTL_SETPERM, key,
                                   KEY_POS_VIEW|KEY_POS_READ|KEY_POS_SEARCH|
                                   KEY_USR_VIEW|KEY_USR_READ|KEY_USR_SEARCH, 0, 0) < 0)
                                r = log_exec_error_errno(context,
                                                         p,
                                                         errno,
                                                         "Failed to restrict invocation ID permission: %m");
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
                const int *fds, size_t n_fds) {

        size_t n_dont_close = 0;
        int dont_close[n_fds + 17];

        assert(params);

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

        if (runtime)
                append_socket_pair(dont_close, &n_dont_close, runtime->ephemeral_storage_socket);

        if (runtime && runtime->shared) {
                append_socket_pair(dont_close, &n_dont_close, runtime->shared->netns_storage_socket);
                append_socket_pair(dont_close, &n_dont_close, runtime->shared->ipcns_storage_socket);
        }

        if (runtime && runtime->dynamic_creds) {
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
        _cleanup_(cpu_set_reset) CPUSet s = {};
        int r;

        assert(c);
        assert(ret);

        if (!c->numa_policy.nodes.set) {
                log_debug("Can't derive CPU affinity mask from NUMA mask because NUMA mask is not set, ignoring");
                return 0;
        }

        r = numa_to_cpu_set(&c->numa_policy, &s);
        if (r < 0)
                return r;

        cpu_set_reset(ret);

        return cpu_set_add_all(ret, &s);
}

static int add_shifted_fd(int *fds, size_t fds_size, size_t *n_fds, int *fd) {
        int r;

        assert(fds);
        assert(n_fds);
        assert(*n_fds < fds_size);
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

        fds[(*n_fds)++] = *fd;
        return 1;
}

static int connect_unix_harder(const ExecContext *c, const ExecParameters *p, const OpenFile *of, int ofd) {
        static const int socket_types[] = { SOCK_DGRAM, SOCK_STREAM, SOCK_SEQPACKET };

        union sockaddr_union addr = {
                .un.sun_family = AF_UNIX,
        };
        socklen_t sa_len;
        int r;

        assert(c);
        assert(p);
        assert(of);
        assert(ofd >= 0);

        r = sockaddr_un_set_path(&addr.un, FORMAT_PROC_FD_PATH(ofd));
        if (r < 0)
                return log_exec_debug_errno(c, p, r, "Failed to set sockaddr for '%s': %m", of->path);
        sa_len = r;

        FOREACH_ELEMENT(i, socket_types) {
                _cleanup_close_ int fd = -EBADF;

                fd = socket(AF_UNIX, *i|SOCK_CLOEXEC, 0);
                if (fd < 0)
                        return log_exec_debug_errno(c, p,
                                                    errno, "Failed to create socket for '%s': %m",
                                                    of->path);

                r = RET_NERRNO(connect(fd, &addr.sa, sa_len));
                if (r >= 0)
                        return TAKE_FD(fd);
                if (r != -EPROTOTYPE)
                        return log_exec_debug_errno(c, p,
                                                    r, "Failed to connect to socket for '%s': %m",
                                                    of->path);
        }

        return log_exec_debug_errno(c, p,
                                    SYNTHETIC_ERRNO(EPROTOTYPE), "No suitable socket type to connect to socket '%s'.",
                                    of->path);
}

static int get_open_file_fd(const ExecContext *c, const ExecParameters *p, const OpenFile *of) {
        _cleanup_close_ int fd = -EBADF, ofd = -EBADF;
        struct stat st;

        assert(c);
        assert(p);
        assert(of);

        ofd = open(of->path, O_PATH | O_CLOEXEC);
        if (ofd < 0)
                return log_exec_debug_errno(c, p, errno, "Failed to open '%s' as O_PATH: %m", of->path);

        if (fstat(ofd, &st) < 0)
                return log_exec_debug_errno(c, p, errno, "Failed to stat '%s': %m", of->path);

        if (S_ISSOCK(st.st_mode)) {
                fd = connect_unix_harder(c, p, of, ofd);
                if (fd < 0)
                        return fd;

                if (FLAGS_SET(of->flags, OPENFILE_READ_ONLY) && shutdown(fd, SHUT_WR) < 0)
                        return log_exec_debug_errno(c, p,
                                                    errno, "Failed to shutdown send for socket '%s': %m",
                                                    of->path);

                log_exec_debug(c, p, "Opened socket '%s' as fd %d.", of->path, fd);
        } else {
                int flags = FLAGS_SET(of->flags, OPENFILE_READ_ONLY) ? O_RDONLY : O_RDWR;
                if (FLAGS_SET(of->flags, OPENFILE_APPEND))
                        flags |= O_APPEND;
                else if (FLAGS_SET(of->flags, OPENFILE_TRUNCATE))
                        flags |= O_TRUNC;

                fd = fd_reopen(ofd, flags|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return log_exec_debug_errno(c, p, fd, "Failed to reopen file '%s': %m", of->path);

                log_exec_debug(c, p, "Opened file '%s' as fd %d.", of->path, fd);
        }

        return TAKE_FD(fd);
}

static int collect_open_file_fds(const ExecContext *c, ExecParameters *p, size_t *n_fds) {
        assert(c);
        assert(p);
        assert(n_fds);

        LIST_FOREACH(open_files, of, p->open_files) {
                _cleanup_close_ int fd = -EBADF;

                fd = get_open_file_fd(c, p, of);
                if (fd < 0) {
                        if (FLAGS_SET(of->flags, OPENFILE_GRACEFUL)) {
                                log_exec_full_errno(c, p,
                                                    fd == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(fd) ? LOG_DEBUG : LOG_WARNING,
                                                    fd,
                                                    "Failed to get OpenFile= file descriptor for '%s', ignoring: %m",
                                                    of->path);
                                continue;
                        }

                        return log_exec_error_errno(c, p, fd,
                                                    "Failed to get OpenFile= file descriptor for '%s': %m",
                                                    of->path);
                }

                if (!GREEDY_REALLOC(p->fds, *n_fds + 1))
                        return log_oom();

                if (strv_extend(&p->fd_names, of->fdname) < 0)
                        return log_oom();

                p->fds[(*n_fds)++] = TAKE_FD(fd);
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

        log_exec_struct(context, params, LOG_DEBUG,
                        "EXECUTABLE=%s", executable,
                        LOG_EXEC_MESSAGE(params, "%s: %s", msg, strnull(cmdline)),
                        LOG_EXEC_INVOCATION_ID(params));
}

static bool exec_context_need_unprivileged_private_users(
                const ExecContext *context,
                const ExecParameters *params) {

        assert(context);
        assert(params);

        /* These options require PrivateUsers= when used in user units, as we need to be in a user namespace
         * to have permission to enable them when not running as root. If we have effective CAP_SYS_ADMIN
         * (system manager) then we have privileges and don't need this. */
        if (params->runtime_scope != RUNTIME_SCOPE_USER)
                return false;

        return context->private_users != PRIVATE_USERS_NO ||
               context->private_tmp != PRIVATE_TMP_NO ||
               context->private_devices ||
               context->private_network ||
               context->network_namespace_path ||
               context->private_ipc ||
               context->ipc_namespace_path ||
               context->private_mounts > 0 ||
               context->mount_apivfs > 0 ||
               context->bind_log_sockets > 0 ||
               context->n_bind_mounts > 0 ||
               context->n_temporary_filesystems > 0 ||
               context->root_directory ||
               !strv_isempty(context->extension_directories) ||
               context->protect_system != PROTECT_SYSTEM_NO ||
               context->protect_home != PROTECT_HOME_NO ||
               exec_needs_pid_namespace(context) ||
               context->protect_kernel_tunables ||
               context->protect_kernel_modules ||
               context->protect_kernel_logs ||
               exec_needs_cgroup_mount(context, params) ||
               context->protect_clock ||
               context->protect_hostname != PROTECT_HOSTNAME_NO ||
               !strv_isempty(context->read_write_paths) ||
               !strv_isempty(context->read_only_paths) ||
               !strv_isempty(context->inaccessible_paths) ||
               !strv_isempty(context->exec_paths) ||
               !strv_isempty(context->no_exec_paths);
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

        size_t targets;
        const char* stdio_fdname[3];
        size_t n_fds;

        assert(c);
        assert(p);
        assert(named_iofds);

        targets = (c->std_input == EXEC_INPUT_NAMED_FD) +
                  (c->std_output == EXEC_OUTPUT_NAMED_FD) +
                  (c->std_error == EXEC_OUTPUT_NAMED_FD);

        for (size_t i = 0; i < 3; i++)
                stdio_fdname[i] = exec_context_fdname(c, i);

        n_fds = p->n_storage_fds + p->n_socket_fds + p->n_extra_fds;

        for (size_t i = 0; i < n_fds  && targets > 0; i++)
                if (named_iofds[STDIN_FILENO] < 0 &&
                    c->std_input == EXEC_INPUT_NAMED_FD &&
                    stdio_fdname[STDIN_FILENO] &&
                    streq(p->fd_names[i], stdio_fdname[STDIN_FILENO])) {

                        named_iofds[STDIN_FILENO] = p->fds[i];
                        targets--;

                } else if (named_iofds[STDOUT_FILENO] < 0 &&
                           c->std_output == EXEC_OUTPUT_NAMED_FD &&
                           stdio_fdname[STDOUT_FILENO] &&
                           streq(p->fd_names[i], stdio_fdname[STDOUT_FILENO])) {

                        named_iofds[STDOUT_FILENO] = p->fds[i];
                        targets--;

                } else if (named_iofds[STDERR_FILENO] < 0 &&
                           c->std_error == EXEC_OUTPUT_NAMED_FD &&
                           stdio_fdname[STDERR_FILENO] &&
                           streq(p->fd_names[i], stdio_fdname[STDERR_FILENO])) {

                        named_iofds[STDERR_FILENO] = p->fds[i];
                        targets--;
                }

        return targets == 0 ? 0 : -ENOENT;
}

static void exec_shared_runtime_close(ExecSharedRuntime *shared) {
        if (!shared)
                return;

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
                return log_exec_error_errno(c, p, errno, "Failed to mark exec_fd as %s: %m", hot ? "hot" : "cold");
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
                return log_exec_error_errno(c, p, errno, "Failed to send handoff timestamp: %m");
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
        if (!(is_terminal_output(context->std_output) ||
              (context->std_output == EXEC_OUTPUT_INHERIT && is_terminal_input(context->std_input)) ||
              context->std_output == EXEC_OUTPUT_NAMED_FD ||
              p->stdout_fd >= 0))
                return;

        if (context->tty_reset) {
                /* When we are resetting the TTY, then let's create a lock first, to synchronize access. This
                 * in particular matters as concurrent resets and the TTY size ANSI DSR logic done by the
                 * exec_context_apply_tty_size() below might interfere */
                lock_fd = lock_dev_console();
                if (lock_fd < 0)
                        log_exec_debug_errno(context, p, lock_fd, "Failed to lock /dev/console, ignoring: %m");

                (void) terminal_reset_defensive(STDOUT_FILENO, /* switch_to_text= */ false);
        }

        (void) exec_context_apply_tty_size(context, STDIN_FILENO, STDOUT_FILENO, /* tty_path= */ NULL);
}

int exec_invoke(
                const ExecCommand *command,
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                int *exit_status) {

        _cleanup_strv_free_ char **our_env = NULL, **pass_env = NULL, **joined_exec_search_path = NULL, **accum_env = NULL, **replaced_argv = NULL;
        int r, ngids = 0;
        _cleanup_free_ gid_t *supplementary_gids = NULL;
        const char *username = NULL, *groupname = NULL;
        _cleanup_free_ char *home_buffer = NULL, *memory_pressure_path = NULL, *own_user = NULL;
        const char *home = NULL, *shell = NULL;
        char **final_argv = NULL;
        dev_t journal_stream_dev = 0;
        ino_t journal_stream_ino = 0;
        bool userns_set_up = false;
        bool needs_sandboxing,          /* Do we need to set up full sandboxing? (i.e. all namespacing, all MAC stuff, caps, yadda yadda */
                needs_setuid,           /* Do we need to do the actual setresuid()/setresgid() calls? */
                needs_mount_namespace;  /* Do we need to set up a mount namespace for this kernel? */
        bool keep_seccomp_privileges = false;
        bool has_cap_sys_admin = false;
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
        size_t n_fds, /* fds to pass to the child */
               n_keep_fds; /* total number of fds not to close */
        int secure_bits;
        _cleanup_free_ gid_t *gids_after_pam = NULL;
        int ngids_after_pam = 0;

        int socket_fd = -EBADF, named_iofds[3] = EBADF_TRIPLET;
        size_t n_storage_fds, n_socket_fds, n_extra_fds;

        assert(command);
        assert(context);
        assert(params);
        assert(exit_status);

        /* This should be mostly redundant, as the log level is also passed as an argument of the executor,
         * and is already applied earlier. Just for safety. */
        if (params->debug_invocation)
                log_set_max_level(LOG_PRI(LOG_DEBUG));
        else if (context->log_level_max >= 0)
                log_set_max_level(context->log_level_max);

        /* Explicitly test for CVE-2021-4034 inspired invocations */
        if (!command->path || strv_isempty(command->argv)) {
                *exit_status = EXIT_EXEC;
                return log_exec_error_errno(
                                context,
                                params,
                                SYNTHETIC_ERRNO(EINVAL),
                                "Invalid command line arguments.");
        }

        LOG_CONTEXT_PUSH_EXEC(context, params);

        if (context->std_input == EXEC_INPUT_SOCKET ||
            context->std_output == EXEC_OUTPUT_SOCKET ||
            context->std_error == EXEC_OUTPUT_SOCKET) {

                if (params->n_socket_fds > 1)
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EINVAL), "Got more than one socket.");

                if (params->n_socket_fds == 0)
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EINVAL), "Got no socket.");

                socket_fd = params->fds[0];
                n_storage_fds = n_socket_fds = n_extra_fds = 0;
        } else {
                n_socket_fds = params->n_socket_fds;
                n_storage_fds = params->n_storage_fds;
                n_extra_fds = params->n_extra_fds;
        }
        n_fds = n_socket_fds + n_storage_fds + n_extra_fds;

        r = exec_context_named_iofds(context, params, named_iofds);
        if (r < 0)
                return log_exec_error_errno(context, params, r, "Failed to load a named file descriptor: %m");

        rename_process_from_path(command->path);

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
                return log_exec_error_errno(context, params, r, "Failed to set process signal mask: %m");
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

        r = collect_open_file_fds(context, params, &n_fds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to get OpenFile= file descriptors: %m");
        }

        int keep_fds[n_fds + 4];
        memcpy_safe(keep_fds, params->fds, n_fds * sizeof(int));
        n_keep_fds = n_fds;

        r = add_shifted_fd(keep_fds, ELEMENTSOF(keep_fds), &n_keep_fds, &params->exec_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to collect shifted fd: %m");
        }

        r = add_shifted_fd(keep_fds, ELEMENTSOF(keep_fds), &n_keep_fds, &params->handoff_timestamp_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to collect shifted fd: %m");
        }

#if HAVE_LIBBPF
        r = add_shifted_fd(keep_fds, ELEMENTSOF(keep_fds), &n_keep_fds, &params->bpf_restrict_fs_map_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to collect shifted fd: %m");
        }
#endif

        r = close_remaining_fds(params, runtime, socket_fd, keep_fds, n_keep_fds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to close unwanted file descriptors: %m");
        }

        if (!context->same_pgrp &&
            setsid() < 0) {
                *exit_status = EXIT_SETSID;
                return log_exec_error_errno(context, params, errno, "Failed to create new process session: %m");
        }

        /* Now, reset the TTY associated to this service "destructively" (i.e. possibly even hang up or
         * disallocate the VT), to get rid of any prior uses of the device. Note that we do not keep any fd
         * open here, hence some of the settings made here might vanish again, depending on the TTY driver
         * used. A 2nd ("constructive") initialization after we opened the input/output fds we actually want
         * will fix this. */
        exec_context_tty_reset(context, params);

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
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(ECANCELED),
                                                    "Execution cancelled by the user.");
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
                return log_exec_error_errno(context, params, errno, "Failed to update environment: %m");
        }

        if (context->dynamic_user && runtime && runtime->dynamic_creds) {
                _cleanup_strv_free_ char **suggested_paths = NULL;

                /* On top of that, make sure we bypass our own NSS module nss-systemd comprehensively for any NSS
                 * checks, if DynamicUser=1 is used, as we shouldn't create a feedback loop with ourselves here. */
                if (putenv((char*) "SYSTEMD_NSS_DYNAMIC_BYPASS=1") != 0) {
                        *exit_status = EXIT_USER;
                        return log_exec_error_errno(context, params, errno, "Failed to update environment: %m");
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
                                return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                            "Failed to update dynamic user credentials: User or group with specified name already exists.");
                        return log_exec_error_errno(context, params, r, "Failed to update dynamic user credentials: %m");
                }

                if (!uid_is_valid(uid)) {
                        *exit_status = EXIT_USER;
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(ESRCH), "UID validation failed for \""UID_FMT"\".", uid);
                }

                if (!gid_is_valid(gid)) {
                        *exit_status = EXIT_USER;
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(ESRCH), "GID validation failed for \""GID_FMT"\".", gid);
                }

                if (runtime->dynamic_creds->user)
                        username = runtime->dynamic_creds->user->name;

        } else {
                const char *u;

                if (context->user)
                        u = context->user;
                else if (context->pam_name) {
                        /* If PAM is enabled but no user name is explicitly selected, then use our own one. */
                        own_user = getusername_malloc();
                        if (!own_user) {
                                *exit_status = EXIT_USER;
                                return log_exec_error_errno(context, params, r, "Failed to determine my own user ID: %m");
                        }
                        u = own_user;
                } else
                        u = NULL;

                if (u) {
                        r = get_fixed_user(u, &username, &uid, &gid, &home, &shell);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                return log_exec_error_errno(context, params, r, "Failed to determine user credentials: %m");
                        }
                }

                if (context->group) {
                        r = get_fixed_group(context->group, &groupname, &gid);
                        if (r < 0) {
                                *exit_status = EXIT_GROUP;
                                return log_exec_error_errno(context, params, r, "Failed to determine group credentials: %m");
                        }
                }
        }

        /* Initialize user supplementary groups and get SupplementaryGroups= ones */
        r = get_supplementary_groups(context, username, groupname, gid,
                                     &supplementary_gids, &ngids);
        if (r < 0) {
                *exit_status = EXIT_GROUP;
                return log_exec_error_errno(context, params, r, "Failed to determine supplementary groups: %m");
        }

        r = send_user_lookup(params->unit_id, params->user_lookup_fd, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_USER;
                return log_exec_error_errno(context, params, r, "Failed to send user credentials to PID1: %m");
        }

        params->user_lookup_fd = safe_close(params->user_lookup_fd);

        r = acquire_home(context, &home, &home_buffer);
        if (r < 0) {
                *exit_status = EXIT_CHDIR;
                return log_exec_error_errno(context, params, r, "Failed to determine $HOME for the invoking user: %m");
        }

        /* If a socket is connected to STDIN/STDOUT/STDERR, we must drop O_NONBLOCK */
        if (socket_fd >= 0)
                (void) fd_nonblock(socket_fd, false);

        /* Journald will try to look-up our cgroup in order to populate _SYSTEMD_CGROUP and _SYSTEMD_UNIT fields.
         * Hence we need to migrate to the target cgroup from init.scope before connecting to journald */
        if (params->cgroup_path) {
                _cleanup_free_ char *p = NULL;

                r = exec_params_get_cgroup_path(params, cgroup_context, &p);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return log_exec_error_errno(context, params, r, "Failed to acquire cgroup path: %m");
                }

                r = cg_attach_everywhere(params->cgroup_supported, p, 0);
                if (r == -EUCLEAN) {
                        *exit_status = EXIT_CGROUP;
                        return log_exec_error_errno(context, params, r,
                                                    "Failed to attach process to cgroup '%s', "
                                                    "because the cgroup or one of its parents or "
                                                    "siblings is in the threaded mode.", p);
                }
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return log_exec_error_errno(context, params, r, "Failed to attach to cgroup %s: %m", p);
                }
        }

        if (context->network_namespace_path && runtime && runtime->shared && runtime->shared->netns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(runtime->shared->netns_storage_socket, context->network_namespace_path, CLONE_NEWNET);
                if (r < 0) {
                        *exit_status = EXIT_NETWORK;
                        return log_exec_error_errno(context, params, r, "Failed to open network namespace path %s: %m", context->network_namespace_path);
                }
        }

        if (context->ipc_namespace_path && runtime && runtime->shared && runtime->shared->ipcns_storage_socket[0] >= 0) {
                r = open_shareable_ns_path(runtime->shared->ipcns_storage_socket, context->ipc_namespace_path, CLONE_NEWIPC);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "Failed to open IPC namespace path %s: %m", context->ipc_namespace_path);
                }
        }

        r = setup_input(context, params, socket_fd, named_iofds);
        if (r < 0) {
                *exit_status = EXIT_STDIN;
                return log_exec_error_errno(context, params, r, "Failed to set up standard input: %m");
        }

        _cleanup_free_ char *fname = NULL;
        r = path_extract_filename(command->path, &fname);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                return log_exec_error_errno(context, params, r, "Failed to extract filename from path %s: %m", command->path);
        }

        r = setup_output(context, params, STDOUT_FILENO, socket_fd, named_iofds, fname, uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                return log_exec_error_errno(context, params, r, "Failed to set up standard output: %m");
        }

        r = setup_output(context, params, STDERR_FILENO, socket_fd, named_iofds, fname, uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDERR;
                return log_exec_error_errno(context, params, r, "Failed to set up standard error output: %m");
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
                        log_exec_debug_errno(context, params, r,
                                             "Failed to adjust OOM setting, assuming containerized execution, ignoring: %m");
                else if (r < 0) {
                        *exit_status = EXIT_OOM_ADJUST;
                        return log_exec_error_errno(context, params, r, "Failed to adjust OOM setting: %m");
                }
        }

        if (context->coredump_filter_set) {
                r = set_coredump_filter(context->coredump_filter);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        log_exec_debug_errno(context, params, r, "Failed to adjust coredump_filter, ignoring: %m");
                else if (r < 0) {
                        *exit_status = EXIT_LIMITS;
                        return log_exec_error_errno(context, params, r, "Failed to adjust coredump_filter: %m");
                }
        }

        if (context->cpu_sched_set) {
                struct sched_attr attr = {
                        .size = sizeof(attr),
                        .sched_policy = context->cpu_sched_policy,
                        .sched_priority = context->cpu_sched_priority,
                        .sched_flags = context->cpu_sched_reset_on_fork ? SCHED_FLAG_RESET_ON_FORK : 0,
                };

                r = sched_setattr(/* pid= */ 0, &attr, /* flags= */ 0);
                if (r < 0) {
                        *exit_status = EXIT_SETSCHEDULER;
                        return log_exec_error_errno(context, params, errno, "Failed to set up CPU scheduling: %m");
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
                        return log_exec_error_errno(context, params, r, "Failed to set up process scheduling priority (nice level): %m");
                }
        }

        if (context->cpu_affinity_from_numa || context->cpu_set.set) {
                _cleanup_(cpu_set_reset) CPUSet converted_cpu_set = {};
                const CPUSet *cpu_set;

                if (context->cpu_affinity_from_numa) {
                        r = exec_context_cpu_affinity_from_numa(context, &converted_cpu_set);
                        if (r < 0) {
                                *exit_status = EXIT_CPUAFFINITY;
                                return log_exec_error_errno(context, params, r, "Failed to derive CPU affinity mask from NUMA mask: %m");
                        }

                        cpu_set = &converted_cpu_set;
                } else
                        cpu_set = &context->cpu_set;

                if (sched_setaffinity(0, cpu_set->allocated, cpu_set->set) < 0) {
                        *exit_status = EXIT_CPUAFFINITY;
                        return log_exec_error_errno(context, params, errno, "Failed to set up CPU affinity: %m");
                }
        }

        if (mpol_is_valid(numa_policy_get_type(&context->numa_policy))) {
                r = apply_numa_policy(&context->numa_policy);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_exec_debug_errno(context, params, r, "NUMA support not available, ignoring.");
                else if (r < 0) {
                        *exit_status = EXIT_NUMA_POLICY;
                        return log_exec_error_errno(context, params, r, "Failed to set NUMA memory policy: %m");
                }
        }

        if (context->ioprio_set)
                if (ioprio_set(IOPRIO_WHO_PROCESS, 0, context->ioprio) < 0) {
                        *exit_status = EXIT_IOPRIO;
                        return log_exec_error_errno(context, params, errno, "Failed to set up IO scheduling priority: %m");
                }

        if (context->timer_slack_nsec != NSEC_INFINITY)
                if (prctl(PR_SET_TIMERSLACK, context->timer_slack_nsec) < 0) {
                        *exit_status = EXIT_TIMERSLACK;
                        return log_exec_error_errno(context, params, errno, "Failed to set up timer slack: %m");
                }

        if (context->personality != PERSONALITY_INVALID) {
                r = safe_personality(context->personality);
                if (r < 0) {
                        *exit_status = EXIT_PERSONALITY;
                        return log_exec_error_errno(context, params, r, "Failed to set up execution domain (personality): %m");
                }
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
                        return log_exec_error_errno(context, params, r, "Failed to change ownership of terminal: %m");
                }
        }

        /* We need sandboxing if the caller asked us to apply it and the command isn't explicitly excepted
         * from it. */
        needs_sandboxing = (params->flags & EXEC_APPLY_SANDBOXING) && !(command->flags & EXEC_COMMAND_FULLY_PRIVILEGED);

        if (params->cgroup_path) {
                /* If delegation is enabled we'll pass ownership of the cgroup to the user of the new process. On cgroup v1
                 * this is only about systemd's own hierarchy, i.e. not the controller hierarchies, simply because that's not
                 * safe. On cgroup v2 there's only one hierarchy anyway, and delegation is safe there, hence in that case only
                 * touch a single hierarchy too. */

                if (params->flags & EXEC_CGROUP_DELEGATE) {
                        _cleanup_free_ char *p = NULL;

                        r = cg_set_access(SYSTEMD_CGROUP_CONTROLLER, params->cgroup_path, uid, gid);
                        if (r < 0) {
                                *exit_status = EXIT_CGROUP;
                                return log_exec_error_errno(context, params, r, "Failed to adjust control group access: %m");
                        }

                        r = exec_params_get_cgroup_path(params, cgroup_context, &p);
                        if (r < 0) {
                                *exit_status = EXIT_CGROUP;
                                return log_exec_error_errno(context, params, r, "Failed to acquire cgroup path: %m");
                        }
                        if (r > 0) {
                                r = cg_set_access_recursive(SYSTEMD_CGROUP_CONTROLLER, p, uid, gid);
                                if (r < 0) {
                                        *exit_status = EXIT_CGROUP;
                                        return log_exec_error_errno(context, params, r, "Failed to adjust control subgroup access: %m");
                                }
                        }
                }

                if (cgroup_context && cg_unified() > 0 && is_pressure_supported() > 0) {
                        if (cgroup_context_want_memory_pressure(cgroup_context)) {
                                r = cg_get_path("memory", params->cgroup_path, "memory.pressure", &memory_pressure_path);
                                if (r < 0) {
                                        *exit_status = EXIT_MEMORY;
                                        return log_oom();
                                }

                                r = chmod_and_chown(memory_pressure_path, 0644, uid, gid);
                                if (r < 0) {
                                        log_exec_full_errno(context, params, r == -ENOENT || ERRNO_IS_PRIVILEGE(r) ? LOG_DEBUG : LOG_WARNING, r,
                                                            "Failed to adjust ownership of '%s', ignoring: %m", memory_pressure_path);
                                        memory_pressure_path = mfree(memory_pressure_path);
                                }
                                /* First we use the current cgroup path to chmod and chown the memory pressure path, then pass the path relative
                                 * to the cgroup namespace to environment variables and mounts. If chown/chmod fails, we should not pass memory
                                 * pressure path environment variable or read-write mount to the unit. This is why we check if
                                 * memory_pressure_path != NULL in the conditional below. */
                                if (memory_pressure_path && needs_sandboxing && exec_needs_cgroup_namespace(context, params)) {
                                        memory_pressure_path = mfree(memory_pressure_path);
                                        r = cg_get_path("memory", "", "memory.pressure", &memory_pressure_path);
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
                        return log_exec_error_errno(context, params, r, "Failed to set up special execution directory in %s: %m", params->prefix[dt]);
        }

        r = exec_setup_credentials(context, params, params->unit_id, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_CREDENTIALS;
                return log_exec_error_errno(context, params, r, "Failed to set up credentials: %m");
        }

        r = build_environment(
                        context,
                        params,
                        cgroup_context,
                        n_fds,
                        home,
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
        accum_env = strv_env_clean(accum_env);

        (void) umask(context->umask);

        r = setup_keyring(context, params, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_KEYRING;
                return log_exec_error_errno(context, params, r, "Failed to set up kernel keyring: %m");
        }

        /* We need setresuid() if the caller asked us to apply sandboxing and the command isn't explicitly
         * excepted from either whole sandboxing or just setresuid() itself. */
        needs_setuid = (params->flags & EXEC_APPLY_SANDBOXING) && !(command->flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID));

        uint64_t capability_ambient_set = context->capability_ambient_set;

        /* Check CAP_SYS_ADMIN before we enter user namespace to see if we can mount /proc even though its masked. */
        has_cap_sys_admin = have_effective_cap(CAP_SYS_ADMIN) > 0;

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
                        return log_exec_error_errno(context, params, r, "Failed to adjust resource limit RLIMIT_%s: %m", rlimit_to_string(which_failed));
                }
        }

        if (needs_setuid && context->pam_name && username) {
                /* Let's call into PAM after we set up our own idea of resource limits so that pam_limits
                 * wins here. (See above.) */

                /* All fds passed in the fds array will be closed in the pam child process. */
                r = setup_pam(context, params, username, uid, gid, &accum_env, params->fds, n_fds, params->exec_fd);
                if (r < 0) {
                        *exit_status = EXIT_PAM;
                        return log_exec_error_errno(context, params, r, "Failed to set up PAM session: %m");
                }

                /* PAM modules might have set some ambient caps. Query them here and merge them into
                 * the caps we want to set in the end, so that we don't end up unsetting them. */
                uint64_t ambient_after_pam;
                r = capability_get_ambient(&ambient_after_pam);
                if (r < 0) {
                        *exit_status = EXIT_CAPABILITIES;
                        return log_exec_error_errno(context, params, r, "Failed to query ambient caps: %m");
                }

                capability_ambient_set |= ambient_after_pam;

                ngids_after_pam = getgroups_alloc(&gids_after_pam);
                if (ngids_after_pam < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_exec_error_errno(context, params, ngids_after_pam, "Failed to obtain groups after setting up PAM: %m");
                }
        }

        if (needs_sandboxing && exec_context_need_unprivileged_private_users(context, params)) {
                /* If we're unprivileged, set up the user namespace first to enable use of the other namespaces.
                 * Users with CAP_SYS_ADMIN can set up user namespaces last because they will be able to
                 * set up all of the other namespaces (i.e. network, mount, UTS) without a user namespace. */
                PrivateUsers pu = context->private_users;
                if (pu == PRIVATE_USERS_NO)
                        pu = PRIVATE_USERS_SELF;

                /* The kernel requires /proc/pid/setgroups be set to "deny" prior to writing /proc/pid/gid_map in
                 * unprivileged user namespaces. */
                r = setup_private_users(pu, saved_uid, saved_gid, uid, gid, /* allow_setgroups= */ false);
                /* If it was requested explicitly and we can't set it up, fail early. Otherwise, continue and let
                 * the actual requested operations fail (or silently continue). */
                if (r < 0 && context->private_users != PRIVATE_USERS_NO) {
                        *exit_status = EXIT_USER;
                        return log_exec_error_errno(context, params, r, "Failed to set up user namespacing for unprivileged user: %m");
                }
                if (r < 0)
                        log_exec_info_errno(context, params, r, "Failed to set up user namespacing for unprivileged user, ignoring: %m");
                else {
                        assert(r > 0);
                        userns_set_up = true;
                }
        }

        if (exec_needs_network_namespace(context) && runtime && runtime->shared && runtime->shared->netns_storage_socket[0] >= 0) {

                /* Try to enable network namespacing if network namespacing is available and we have
                 * CAP_NET_ADMIN. We need CAP_NET_ADMIN to be able to configure the loopback device in the
                 * new network namespace. And if we don't have that, then we could only create a network
                 * namespace without the ability to set up "lo". Hence gracefully skip things then. */
                if (ns_type_supported(NAMESPACE_NET) && have_effective_cap(CAP_NET_ADMIN) > 0) {
                        r = setup_shareable_ns(runtime->shared->netns_storage_socket, CLONE_NEWNET);
                        if (ERRNO_IS_NEG_PRIVILEGE(r))
                                log_exec_notice_errno(context, params, r,
                                                      "PrivateNetwork=yes is configured, but network namespace setup not permitted, proceeding without: %m");
                        else if (r < 0) {
                                *exit_status = EXIT_NETWORK;
                                return log_exec_error_errno(context, params, r, "Failed to set up network namespacing: %m");
                        }
                } else if (context->network_namespace_path) {
                        *exit_status = EXIT_NETWORK;
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                    "NetworkNamespacePath= is not supported, refusing.");
                } else
                        log_exec_notice(context, params, "PrivateNetwork=yes is configured, but the kernel does not support or we lack privileges for network namespace, proceeding without.");
        }

        if (exec_needs_ipc_namespace(context) && runtime && runtime->shared && runtime->shared->ipcns_storage_socket[0] >= 0) {

                if (ns_type_supported(NAMESPACE_IPC)) {
                        r = setup_shareable_ns(runtime->shared->ipcns_storage_socket, CLONE_NEWIPC);
                        if (ERRNO_IS_NEG_PRIVILEGE(r))
                                log_exec_warning_errno(context, params, r,
                                                       "PrivateIPC=yes is configured, but IPC namespace setup failed, ignoring: %m");
                        else if (r < 0) {
                                *exit_status = EXIT_NAMESPACE;
                                return log_exec_error_errno(context, params, r, "Failed to set up IPC namespacing: %m");
                        }
                } else if (context->ipc_namespace_path) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                    "IPCNamespacePath= is not supported, refusing.");
                } else
                        log_exec_warning(context, params, "PrivateIPC=yes is configured, but the kernel does not support IPC namespaces, ignoring.");
        }

        if (needs_sandboxing && exec_needs_cgroup_namespace(context, params)) {
                r = unshare(CLONE_NEWCGROUP);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "Failed to set up cgroup namespacing: %m");
                }
        }

        /* Unshare a new PID namespace before setting up mounts to ensure /proc/ is mounted with only processes in PID namespace visible.
         * Note PrivatePIDs=yes implies MountAPIVFS=yes so we'll always ensure procfs is remounted. */
        if (needs_sandboxing && exec_needs_pid_namespace(context)) {
                if (params->pidref_transport_fd < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "PidRef socket is not set up: %m");
                }

                /* If we had CAP_SYS_ADMIN prior to joining the user namespace, then we are privileged and don't need
                 * to check if we can mount /proc/.
                 *
                 * We need to check prior to entering the user namespace because if we're running unprivileged or in a
                 * system without CAP_SYS_ADMIN, then we can have CAP_SYS_ADMIN in the current user namespace but not
                 * once we unshare a mount namespace. */
                r = has_cap_sys_admin ? 1 : can_mount_proc(context, params);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "Failed to detect if /proc/ can be remounted: %m");
                }
                if (r == 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, SYNTHETIC_ERRNO(EPERM),
                                                    "PrivatePIDs=yes is configured, but /proc/ cannot be re-mounted due to lack of privileges, refusing.");
                }

                r = setup_private_pids(context, params);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "Failed to set up pid namespace: %m");
                }
        }

        /* If PrivatePIDs= yes is configured, we're now running as pid 1 in a pid namespace! */

        if (needs_mount_namespace) {
                _cleanup_free_ char *error_path = NULL;

                r = apply_mount_namespace(command->flags,
                                          context,
                                          params,
                                          runtime,
                                          memory_pressure_path,
                                          needs_sandboxing,
                                          &error_path,
                                          uid,
                                          gid);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return log_exec_error_errno(context, params, r, "Failed to set up mount namespacing%s%s: %m",
                                                    error_path ? ": " : "", strempty(error_path));
                }
        }

        if (needs_sandboxing) {
                r = apply_protect_hostname(context, params, exit_status);
                if (r < 0)
                        return r;
        }

        if (context->memory_ksm >= 0)
                if (prctl(PR_SET_MEMORY_MERGE, context->memory_ksm, 0, 0, 0) < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno))
                                log_exec_debug_errno(context,
                                                     params,
                                                     errno,
                                                     "KSM support not available, ignoring.");
                        else {
                                *exit_status = EXIT_KSM;
                                return log_exec_error_errno(context, params, errno, "Failed to set KSM: %m");
                        }
                }

        /* Drop groups as early as possible.
         * This needs to be done after PrivateDevices=yes setup as device nodes should be owned by the host's root.
         * For non-root in a userns, devices will be owned by the user/group before the group change, and nobody. */
        if (needs_setuid) {
                _cleanup_free_ gid_t *gids_to_enforce = NULL;
                int ngids_to_enforce = 0;

                ngids_to_enforce = merge_gid_lists(supplementary_gids,
                                                   ngids,
                                                   gids_after_pam,
                                                   ngids_after_pam,
                                                   &gids_to_enforce);
                if (ngids_to_enforce < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_exec_error_errno(context, params,
                                                    ngids_to_enforce,
                                                    "Failed to merge group lists. Group membership might be incorrect: %m");
                }

                r = enforce_groups(gid, gids_to_enforce, ngids_to_enforce);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        return log_exec_error_errno(context, params, r, "Changing group credentials failed: %m");
                }
        }

        /* If the user namespace was not set up above, try to do it now.
         * It's preferred to set up the user namespace later (after all other namespaces) so as not to be
         * restricted by rules pertaining to combining user namespaces with other namespaces (e.g. in the
         * case of mount namespaces being less privileged when the mount point list is copied from a
         * different user namespace). */

        if (needs_sandboxing && !userns_set_up) {
                r = setup_private_users(context->private_users, saved_uid, saved_gid, uid, gid,
                                        /* allow_setgroups= */ context->private_users == PRIVATE_USERS_FULL);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        return log_exec_error_errno(context, params, r, "Failed to set up user namespacing: %m");
                }
        }

        /* Now that the mount namespace has been set up and privileges adjusted, let's look for the thing we
         * shall execute. */

        _cleanup_free_ char *executable = NULL;
        _cleanup_close_ int executable_fd = -EBADF;
        r = find_executable_full(command->path, /* root= */ NULL, context->exec_search_path, false, &executable, &executable_fd);
        if (r < 0) {
                *exit_status = EXIT_EXEC;
                log_exec_struct_errno(context, params, LOG_NOTICE, r,
                                      "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                      LOG_EXEC_MESSAGE(params,
                                                       "Unable to locate executable '%s': %m",
                                                       command->path),
                                      "EXECUTABLE=%s", command->path);
                /* If the error will be ignored by manager, tune down the log level here. Missing executable
                 * is very much expected in this case. */
                return r != -ENOMEM && FLAGS_SET(command->flags, EXEC_COMMAND_IGNORE_FAILURE) ? 1 : r;
        }

        r = add_shifted_fd(keep_fds, ELEMENTSOF(keep_fds), &n_keep_fds, &executable_fd);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to collect shifted fd: %m");
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
                                        return log_exec_error_errno(context,
                                                                    params,
                                                                    r,
                                                                    "Failed to determine SELinux context: %m");
                                }
                                log_exec_debug_errno(context,
                                                     params,
                                                     r,
                                                     "Failed to determine SELinux context, ignoring: %m");
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
                r = pack_fds(params->fds, n_fds);
        if (r >= 0)
                r = flag_fds(params->fds, n_socket_fds, n_fds, context->non_blocking);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return log_exec_error_errno(context, params, r, "Failed to adjust passed file descriptors: %m");
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
                                return log_exec_error_errno(context, params, errno, "Failed to adjust RLIMIT_RTPRIO resource limit: %m");
                        }
                }

#if ENABLE_SMACK
                /* LSM Smack needs the capability CAP_MAC_ADMIN to change the current execution security context of the
                 * process. This is the latest place before dropping capabilities. Other MAC context are set later. */
                if (use_smack) {
                        r = setup_smack(params, context, executable_fd);
                        if (r < 0 && !context->smack_process_label_ignore) {
                                *exit_status = EXIT_SMACK_PROCESS_LABEL;
                                return log_exec_error_errno(context, params, r, "Failed to set SMACK process label: %m");
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
                                return log_exec_error_errno(context, params, errno, "Failed to enable keep capabilities flag: %m");
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
                                return log_exec_error_errno(context, params, r, "Failed to drop capabilities: %m");
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
                                return log_exec_error_errno(context, params, r, "Failed to apply ambient capabilities (before UID change): %m");
                        }
                }
        }

        /* chroot to root directory first, before we lose the ability to chroot */
        r = apply_root_directory(context, params, runtime, needs_mount_namespace, exit_status);
        if (r < 0)
                return log_exec_error_errno(context, params, r, "Chrooting to the requested root directory failed: %m");

        if (needs_setuid) {
                if (uid_is_valid(uid)) {
                        r = enforce_user(context, uid, capability_ambient_set);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                return log_exec_error_errno(context, params, r, "Failed to change UID to " UID_FMT ": %m", uid);
                        }

                        if (keep_seccomp_privileges) {
                                if (!BIT_SET(capability_ambient_set, CAP_SETUID)) {
                                        r = drop_capability(CAP_SETUID);
                                        if (r < 0) {
                                                *exit_status = EXIT_USER;
                                                return log_exec_error_errno(context, params, r, "Failed to drop CAP_SETUID: %m");
                                        }
                                }

                                r = keep_capability(CAP_SYS_ADMIN);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_exec_error_errno(context, params, r, "Failed to keep CAP_SYS_ADMIN: %m");
                                }

                                r = keep_capability(CAP_SETPCAP);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_exec_error_errno(context, params, r, "Failed to keep CAP_SETPCAP: %m");
                                }
                        }

                        if (capability_ambient_set != 0) {

                                /* Raise the ambient capabilities after user change. */
                                r = capability_ambient_set_apply(capability_ambient_set, /* also_inherit= */ false);
                                if (r < 0) {
                                        *exit_status = EXIT_CAPABILITIES;
                                        return log_exec_error_errno(context, params, r, "Failed to apply ambient capabilities (after UID change): %m");
                                }
                        }
                }
        }

        /* Apply working directory here, because the working directory might be on NFS and only the user
         * running this service might have the correct privilege to change to the working directory. Also, it
         * is absolutely 💣 crucial 💣 we applied all mount namespacing rearrangements before this, so that
         * the cwd cannot be used to pin directories outside of the sandbox. */
        r = apply_working_directory(context, params, runtime, home);
        if (r < 0) {
                *exit_status = EXIT_CHDIR;
                return log_exec_error_errno(context, params, r, "Changing to the requested working directory failed: %m");
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
                                r = setexeccon(exec_context);
                                if (r < 0) {
                                        if (!context->selinux_context_ignore) {
                                                *exit_status = EXIT_SELINUX_CONTEXT;
                                                return log_exec_error_errno(context, params, r, "Failed to change SELinux context to %s: %m", exec_context);
                                        }
                                        log_exec_debug_errno(context,
                                                             params,
                                                             r,
                                                             "Failed to change SELinux context to %s, ignoring: %m",
                                                             exec_context);
                                }
                        }
                }
#endif

#if HAVE_APPARMOR
                if (use_apparmor && context->apparmor_profile) {
                        r = aa_change_onexec(context->apparmor_profile);
                        if (r < 0 && !context->apparmor_profile_ignore) {
                                *exit_status = EXIT_APPARMOR_PROFILE;
                                return log_exec_error_errno(context,
                                                            params,
                                                            errno,
                                                            "Failed to prepare AppArmor profile change to %s: %m",
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
                        r = capability_gain_cap_setpcap(/* ret_before_caps = */ NULL);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return log_exec_error_errno(context, params, r, "Failed to gain CAP_SETPCAP for setting secure bits");
                        }
                        if (prctl(PR_SET_SECUREBITS, secure_bits) < 0) {
                                *exit_status = EXIT_SECUREBITS;
                                return log_exec_error_errno(context, params, errno, "Failed to set process secure bits: %m");
                        }
                }

                if (context_has_no_new_privileges(context))
                        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                                *exit_status = EXIT_NO_NEW_PRIVILEGES;
                                return log_exec_error_errno(context, params, errno, "Failed to disable new privileges: %m");
                        }

#if HAVE_SECCOMP
                r = apply_address_families(context, params);
                if (r < 0) {
                        *exit_status = EXIT_ADDRESS_FAMILIES;
                        return log_exec_error_errno(context, params, r, "Failed to restrict address families: %m");
                }

                r = apply_memory_deny_write_execute(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to disable writing to executable memory: %m");
                }

                r = apply_restrict_realtime(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply realtime restrictions: %m");
                }

                r = apply_restrict_suid_sgid(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply SUID/SGID restrictions: %m");
                }

                r = apply_restrict_namespaces(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply namespace restrictions: %m");
                }

                r = apply_protect_sysctl(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply sysctl restrictions: %m");
                }

                r = apply_protect_kernel_modules(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply module loading restrictions: %m");
                }

                r = apply_protect_kernel_logs(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply kernel log restrictions: %m");
                }

                r = apply_protect_clock(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply clock restrictions: %m");
                }

                r = apply_private_devices(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to set up private devices: %m");
                }

                r = apply_syscall_archs(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply syscall architecture restrictions: %m");
                }

                r = apply_lock_personality(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to lock personalities: %m");
                }

                r = apply_syscall_log(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply system call log filters: %m");
                }
#endif

#if HAVE_LIBBPF
                r = apply_restrict_filesystems(context, params);
                if (r < 0) {
                        *exit_status = EXIT_BPF;
                        return log_exec_error_errno(context, params, r, "Failed to restrict filesystems: %m");
                }
#endif

#if HAVE_SECCOMP
                /* This really should remain as close to the execve() as possible, to make sure our own code is affected
                 * by the filter as little as possible. */
                r = apply_syscall_filter(context, params);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        return log_exec_error_errno(context, params, r, "Failed to apply system call filters: %m");
                }

                if (keep_seccomp_privileges) {
                        /* Restore the capability bounding set with what's expected from the service + the
                         * ambient capabilities hack */
                        if (!cap_test_all(saved_bset)) {
                                r = capability_bounding_set_drop(saved_bset, /* right_now= */ false);
                                if (r < 0) {
                                        *exit_status = EXIT_CAPABILITIES;
                                        return log_exec_error_errno(context, params, r, "Failed to drop bset capabilities: %m");
                                }
                        }

                        /* Only drop CAP_SYS_ADMIN if it's not in the bounding set, otherwise we'll break
                         * applications that use it. */
                        if (!BIT_SET(saved_bset, CAP_SYS_ADMIN)) {
                                r = drop_capability(CAP_SYS_ADMIN);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_exec_error_errno(context, params, r, "Failed to drop CAP_SYS_ADMIN: %m");
                                }
                        }

                        /* Only drop CAP_SETPCAP if it's not in the bounding set, otherwise we'll break
                         * applications that use it. */
                        if (!BIT_SET(saved_bset, CAP_SETPCAP)) {
                                r = drop_capability(CAP_SETPCAP);
                                if (r < 0) {
                                        *exit_status = EXIT_USER;
                                        return log_exec_error_errno(context, params, r, "Failed to drop CAP_SETPCAP: %m");
                                }
                        }

                        if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                                *exit_status = EXIT_USER;
                                return log_exec_error_errno(context, params, errno, "Failed to drop keep capabilities flag: %m");
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

        if (!FLAGS_SET(command->flags, EXEC_COMMAND_NO_ENV_EXPAND)) {
                _cleanup_strv_free_ char **unset_variables = NULL, **bad_variables = NULL;

                r = replace_env_argv(command->argv, accum_env, &replaced_argv, &unset_variables, &bad_variables);
                if (r < 0) {
                        *exit_status = EXIT_MEMORY;
                        return log_exec_error_errno(context,
                                                    params,
                                                    r,
                                                    "Failed to replace environment variables: %m");
                }
                final_argv = replaced_argv;

                if (!strv_isempty(unset_variables)) {
                        _cleanup_free_ char *ju = strv_join(unset_variables, ", ");
                        log_exec_warning(context,
                                         params,
                                         "Referenced but unset environment variable evaluates to an empty string: %s",
                                         strna(ju));
                }

                if (!strv_isempty(bad_variables)) {
                        _cleanup_free_ char *jb = strv_join(bad_variables, ", ");
                        log_exec_warning(context,
                                         params,
                                         "Invalid environment variable name evaluates to an empty string: %s",
                                         strna(jb));
                }
        } else
                final_argv = command->argv;

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
        return log_exec_error_errno(context, params, r, "Failed to execute %s: %m", executable);
}
