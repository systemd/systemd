/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <utmpx.h>

#ifdef HAVE_PAM
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#ifdef HAVE_APPARMOR
#include <sys/apparmor.h>
#endif

#include "sd-messages.h"

#include "af-list.h"
#include "alloc-util.h"
#ifdef HAVE_APPARMOR
#include "apparmor-util.h"
#endif
#include "async.h"
#include "barrier.h"
#include "cap-list.h"
#include "capability-util.h"
#include "def.h"
#include "env-util.h"
#include "errno-list.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "io-util.h"
#include "ioprio.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "namespace.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "securebits.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "smack-util.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "unit.h"
#include "user-util.h"
#include "util.h"
#include "utmp-wtmp.h"

#define IDLE_TIMEOUT_USEC (5*USEC_PER_SEC)
#define IDLE_TIMEOUT2_USEC (1*USEC_PER_SEC)

/* This assumes there is a 'tty' group */
#define TTY_MODE 0620

#define SNDBUF_SIZE (8*1024*1024)

static int shift_fds(int fds[], unsigned n_fds) {
        int start, restart_from;

        if (n_fds <= 0)
                return 0;

        /* Modifies the fds array! (sorts it) */

        assert(fds);

        start = 0;
        for (;;) {
                int i;

                restart_from = -1;

                for (i = start; i < (int) n_fds; i++) {
                        int nfd;

                        /* Already at right index? */
                        if (fds[i] == i+3)
                                continue;

                        nfd = fcntl(fds[i], F_DUPFD, i + 3);
                        if (nfd < 0)
                                return -errno;

                        safe_close(fds[i]);
                        fds[i] = nfd;

                        /* Hmm, the fd we wanted isn't free? Then
                         * let's remember that and try again from here */
                        if (nfd != i+3 && restart_from < 0)
                                restart_from = i;
                }

                if (restart_from < 0)
                        break;

                start = restart_from;
        }

        return 0;
}

static int flags_fds(const int fds[], unsigned n_storage_fds, unsigned n_socket_fds, bool nonblock) {
        unsigned i, n_fds;
        int r;

        n_fds = n_storage_fds + n_socket_fds;
        if (n_fds <= 0)
                return 0;

        assert(fds);

        /* Drops/Sets O_NONBLOCK and FD_CLOEXEC from the file flags.
         * O_NONBLOCK only applies to socket activation though. */

        for (i = 0; i < n_fds; i++) {

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

static const char *exec_context_tty_path(const ExecContext *context) {
        assert(context);

        if (context->stdio_as_fds)
                return NULL;

        if (context->tty_path)
                return context->tty_path;

        return "/dev/console";
}

static void exec_context_tty_reset(const ExecContext *context, const ExecParameters *p) {
        const char *path;

        assert(context);

        path = exec_context_tty_path(context);

        if (context->tty_vhangup) {
                if (p && p->stdin_fd >= 0)
                        (void) terminal_vhangup_fd(p->stdin_fd);
                else if (path)
                        (void) terminal_vhangup(path);
        }

        if (context->tty_reset) {
                if (p && p->stdin_fd >= 0)
                        (void) reset_terminal_fd(p->stdin_fd, true);
                else if (path)
                        (void) reset_terminal(path);
        }

        if (context->tty_vt_disallocate && path)
                (void) vt_disallocate(path);
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
                      EXEC_OUTPUT_SYSLOG_AND_CONSOLE,
                      EXEC_OUTPUT_KMSG_AND_CONSOLE,
                      EXEC_OUTPUT_JOURNAL_AND_CONSOLE);
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
        int fd, r;

        assert(nfd >= 0);

        fd = open("/dev/null", flags|O_NOCTTY);
        if (fd < 0)
                return -errno;

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                safe_close(fd);
        } else
                r = nfd;

        return r;
}

static int connect_journal_socket(int fd, uid_t uid, gid_t gid) {
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/stdout",
        };
        uid_t olduid = UID_INVALID;
        gid_t oldgid = GID_INVALID;
        int r;

        if (gid != GID_INVALID) {
                oldgid = getgid();

                r = setegid(gid);
                if (r < 0)
                        return -errno;
        }

        if (uid != UID_INVALID) {
                olduid = getuid();

                r = seteuid(uid);
                if (r < 0) {
                        r = -errno;
                        goto restore_gid;
                }
        }

        r = connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0)
                r = -errno;

        /* If we fail to restore the uid or gid, things will likely
           fail later on. This should only happen if an LSM interferes. */

        if (uid != UID_INVALID)
                (void) seteuid(olduid);

 restore_gid:
        if (gid != GID_INVALID)
                (void) setegid(oldgid);

        return r;
}

static int connect_logger_as(
                Unit *unit,
                const ExecContext *context,
                ExecOutput output,
                const char *ident,
                int nfd,
                uid_t uid,
                gid_t gid) {

        int fd, r;

        assert(context);
        assert(output < _EXEC_OUTPUT_MAX);
        assert(ident);
        assert(nfd >= 0);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return -errno;

        r = connect_journal_socket(fd, uid, gid);
        if (r < 0)
                return r;

        if (shutdown(fd, SHUT_RD) < 0) {
                safe_close(fd);
                return -errno;
        }

        (void) fd_inc_sndbuf(fd, SNDBUF_SIZE);

        dprintf(fd,
                "%s\n"
                "%s\n"
                "%i\n"
                "%i\n"
                "%i\n"
                "%i\n"
                "%i\n",
                context->syslog_identifier ? context->syslog_identifier : ident,
                unit->id,
                context->syslog_priority,
                !!context->syslog_level_prefix,
                output == EXEC_OUTPUT_SYSLOG || output == EXEC_OUTPUT_SYSLOG_AND_CONSOLE,
                output == EXEC_OUTPUT_KMSG || output == EXEC_OUTPUT_KMSG_AND_CONSOLE,
                is_terminal_output(output));

        if (fd == nfd)
                return nfd;

        r = dup2(fd, nfd) < 0 ? -errno : nfd;
        safe_close(fd);

        return r;
}
static int open_terminal_as(const char *path, mode_t mode, int nfd) {
        int fd, r;

        assert(path);
        assert(nfd >= 0);

        fd = open_terminal(path, mode | O_NOCTTY);
        if (fd < 0)
                return fd;

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                safe_close(fd);
        } else
                r = nfd;

        return r;
}

static int fixup_input(ExecInput std_input, int socket_fd, bool apply_tty_stdin) {

        if (is_terminal_input(std_input) && !apply_tty_stdin)
                return EXEC_INPUT_NULL;

        if (std_input == EXEC_INPUT_SOCKET && socket_fd < 0)
                return EXEC_INPUT_NULL;

        return std_input;
}

static int fixup_output(ExecOutput std_output, int socket_fd) {

        if (std_output == EXEC_OUTPUT_SOCKET && socket_fd < 0)
                return EXEC_OUTPUT_INHERIT;

        return std_output;
}

static int setup_input(
                const ExecContext *context,
                const ExecParameters *params,
                int socket_fd,
                int named_iofds[3]) {

        ExecInput i;

        assert(context);
        assert(params);

        if (params->stdin_fd >= 0) {
                if (dup2(params->stdin_fd, STDIN_FILENO) < 0)
                        return -errno;

                /* Try to make this the controlling tty, if it is a tty, and reset it */
                (void) ioctl(STDIN_FILENO, TIOCSCTTY, context->std_input == EXEC_INPUT_TTY_FORCE);
                (void) reset_terminal_fd(STDIN_FILENO, true);

                return STDIN_FILENO;
        }

        i = fixup_input(context->std_input, socket_fd, params->flags & EXEC_APPLY_TTY_STDIN);

        switch (i) {

        case EXEC_INPUT_NULL:
                return open_null_as(O_RDONLY, STDIN_FILENO);

        case EXEC_INPUT_TTY:
        case EXEC_INPUT_TTY_FORCE:
        case EXEC_INPUT_TTY_FAIL: {
                int fd, r;

                fd = acquire_terminal(exec_context_tty_path(context),
                                      i == EXEC_INPUT_TTY_FAIL,
                                      i == EXEC_INPUT_TTY_FORCE,
                                      false,
                                      USEC_INFINITY);
                if (fd < 0)
                        return fd;

                if (fd != STDIN_FILENO) {
                        r = dup2(fd, STDIN_FILENO) < 0 ? -errno : STDIN_FILENO;
                        safe_close(fd);
                } else
                        r = STDIN_FILENO;

                return r;
        }

        case EXEC_INPUT_SOCKET:
                return dup2(socket_fd, STDIN_FILENO) < 0 ? -errno : STDIN_FILENO;

        case EXEC_INPUT_NAMED_FD:
                (void) fd_nonblock(named_iofds[STDIN_FILENO], false);
                return dup2(named_iofds[STDIN_FILENO], STDIN_FILENO) < 0 ? -errno : STDIN_FILENO;

        default:
                assert_not_reached("Unknown input type");
        }
}

static int setup_output(
                Unit *unit,
                const ExecContext *context,
                const ExecParameters *params,
                int fileno,
                int socket_fd,
                int named_iofds[3],
                const char *ident,
                uid_t uid,
                gid_t gid,
                dev_t *journal_stream_dev,
                ino_t *journal_stream_ino) {

        ExecOutput o;
        ExecInput i;
        int r;

        assert(unit);
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

        i = fixup_input(context->std_input, socket_fd, params->flags & EXEC_APPLY_TTY_STDIN);
        o = fixup_output(context->std_output, socket_fd);

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
                    getppid () != 1)
                        return fileno;

                /* Duplicate from stdout if possible */
                if ((e == o && e != EXEC_OUTPUT_NAMED_FD) || e == EXEC_OUTPUT_INHERIT)
                        return dup2(STDOUT_FILENO, fileno) < 0 ? -errno : fileno;

                o = e;

        } else if (o == EXEC_OUTPUT_INHERIT) {
                /* If input got downgraded, inherit the original value */
                if (i == EXEC_INPUT_NULL && is_terminal_input(context->std_input))
                        return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);

                /* If the input is connected to anything that's not a /dev/null, inherit that... */
                if (i != EXEC_INPUT_NULL)
                        return dup2(STDIN_FILENO, fileno) < 0 ? -errno : fileno;

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
                        return dup2(STDIN_FILENO, fileno) < 0 ? -errno : fileno;

                /* We don't reset the terminal if this is just about output */
                return open_terminal_as(exec_context_tty_path(context), O_WRONLY, fileno);

        case EXEC_OUTPUT_SYSLOG:
        case EXEC_OUTPUT_SYSLOG_AND_CONSOLE:
        case EXEC_OUTPUT_KMSG:
        case EXEC_OUTPUT_KMSG_AND_CONSOLE:
        case EXEC_OUTPUT_JOURNAL:
        case EXEC_OUTPUT_JOURNAL_AND_CONSOLE:
                r = connect_logger_as(unit, context, o, ident, fileno, uid, gid);
                if (r < 0) {
                        log_unit_error_errno(unit, r, "Failed to connect %s to the journal socket, ignoring: %m", fileno == STDOUT_FILENO ? "stdout" : "stderr");
                        r = open_null_as(O_WRONLY, fileno);
                } else {
                        struct stat st;

                        /* If we connected this fd to the journal via a stream, patch the device/inode into the passed
                         * parameters, but only then. This is useful so that we can set $JOURNAL_STREAM that permits
                         * services to detect whether they are connected to the journal or not. */

                        if (fstat(fileno, &st) >= 0) {
                                *journal_stream_dev = st.st_dev;
                                *journal_stream_ino = st.st_ino;
                        }
                }
                return r;

        case EXEC_OUTPUT_SOCKET:
                assert(socket_fd >= 0);
                return dup2(socket_fd, fileno) < 0 ? -errno : fileno;

        case EXEC_OUTPUT_NAMED_FD:
                (void) fd_nonblock(named_iofds[fileno], false);
                return dup2(named_iofds[fileno], fileno) < 0 ? -errno : fileno;

        default:
                assert_not_reached("Unknown error type");
        }
}

static int chown_terminal(int fd, uid_t uid) {
        struct stat st;

        assert(fd >= 0);

        /* Before we chown/chmod the TTY, let's ensure this is actually a tty */
        if (isatty(fd) < 1)
                return 0;

        /* This might fail. What matters are the results. */
        (void) fchown(fd, uid, -1);
        (void) fchmod(fd, TTY_MODE);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_uid != uid || (st.st_mode & 0777) != TTY_MODE)
                return -EPERM;

        return 0;
}

static int setup_confirm_stdio(const char *vc, int *_saved_stdin, int *_saved_stdout) {
        _cleanup_close_ int fd = -1, saved_stdin = -1, saved_stdout = -1;
        int r;

        assert(_saved_stdin);
        assert(_saved_stdout);

        saved_stdin = fcntl(STDIN_FILENO, F_DUPFD, 3);
        if (saved_stdin < 0)
                return -errno;

        saved_stdout = fcntl(STDOUT_FILENO, F_DUPFD, 3);
        if (saved_stdout < 0)
                return -errno;

        fd = acquire_terminal(vc, false, false, false, DEFAULT_CONFIRM_USEC);
        if (fd < 0)
                return fd;

        r = chown_terminal(fd, getuid());
        if (r < 0)
                return r;

        r = reset_terminal_fd(fd, true);
        if (r < 0)
                return r;

        if (dup2(fd, STDIN_FILENO) < 0)
                return -errno;

        if (dup2(fd, STDOUT_FILENO) < 0)
                return -errno;

        if (fd >= 2)
                safe_close(fd);
        fd = -1;

        *_saved_stdin = saved_stdin;
        *_saved_stdout = saved_stdout;

        saved_stdin = saved_stdout = -1;

        return 0;
}

static void write_confirm_error_fd(int err, int fd, const Unit *u) {
        assert(err < 0);

        if (err == -ETIMEDOUT)
                dprintf(fd, "Confirmation question timed out for %s, assuming positive response.\n", u->id);
        else {
                errno = -err;
                dprintf(fd, "Couldn't ask confirmation for %s: %m, assuming positive response.\n", u->id);
        }
}

static void write_confirm_error(int err, const char *vc, const Unit *u) {
        _cleanup_close_ int fd = -1;

        assert(vc);

        fd = open_terminal(vc, O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return;

        write_confirm_error_fd(err, fd, u);
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

static int ask_for_confirmation(const char *vc, Unit *u, const char *cmdline) {
        int saved_stdout = -1, saved_stdin = -1, r;
        _cleanup_free_ char *e = NULL;
        char c;

        /* For any internal errors, assume a positive response. */
        r = setup_confirm_stdio(vc, &saved_stdin, &saved_stdout);
        if (r < 0) {
                write_confirm_error(r, vc, u);
                return CONFIRM_EXECUTE;
        }

        /* confirm_spawn might have been disabled while we were sleeping. */
        if (manager_is_confirm_spawn_disabled(u->manager)) {
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
                        write_confirm_error_fd(r, STDOUT_FILENO, u);
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
                        unit_dump(u, stdout, "  ");
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
                        printf("  Description: %s\n"
                               "  Unit:        %s\n"
                               "  Command:     %s\n",
                               u->id, u->description, cmdline);
                        continue; /* ask again */
                case 'j':
                        manager_dump_jobs(u->manager, stdout, "  ");
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
                        assert_not_reached("Unhandled choice");
                }
                break;
        }

restore_stdio:
        restore_confirm_stdio(&saved_stdin, &saved_stdout);
        return r;
}

static int get_fixed_user(const ExecContext *c, const char **user,
                          uid_t *uid, gid_t *gid,
                          const char **home, const char **shell) {
        int r;
        const char *name;

        assert(c);

        if (!c->user)
                return 0;

        /* Note that we don't set $HOME or $SHELL if they are not particularly enlightening anyway
         * (i.e. are "/" or "/bin/nologin"). */

        name = c->user;
        r = get_user_creds_clean(&name, uid, gid, home, shell);
        if (r < 0)
                return r;

        *user = name;
        return 0;
}

static int get_fixed_group(const ExecContext *c, const char **group, gid_t *gid) {
        int r;
        const char *name;

        assert(c);

        if (!c->group)
                return 0;

        name = c->group;
        r = get_group_creds(&name, gid);
        if (r < 0)
                return r;

        *group = name;
        return 0;
}

static int get_supplementary_groups(const ExecContext *c, const char *user,
                                    const char *group, gid_t gid,
                                    gid_t **supplementary_gids, int *ngids) {
        char **i;
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

        if (!c->supplementary_groups)
                return 0;

        /*
         * If SupplementaryGroups= was passed then NGROUPS_MAX has to
         * be positive, otherwise fail.
         */
        errno = 0;
        ngroups_max = (int) sysconf(_SC_NGROUPS_MAX);
        if (ngroups_max <= 0) {
                if (errno > 0)
                        return -errno;
                else
                        return -EOPNOTSUPP; /* For all other values */
        }

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
                r = get_group_creds(&g, l_gids+k);
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

static int enforce_groups(const ExecContext *context, gid_t gid,
                          gid_t *supplementary_gids, int ngids) {
        int r;

        assert(context);

        /* Handle SupplementaryGroups= even if it is empty */
        if (context->supplementary_groups) {
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

static int enforce_user(const ExecContext *context, uid_t uid) {
        assert(context);

        if (!uid_is_valid(uid))
                return 0;

        /* Sets (but doesn't look up) the uid and make sure we keep the
         * capabilities while doing so. */

        if (context->capability_ambient_set != 0) {

                /* First step: If we need to keep capabilities but
                 * drop privileges we need to make sure we keep our
                 * caps, while we drop privileges. */
                if (uid != 0) {
                        int sb = context->secure_bits | 1<<SECURE_KEEP_CAPS;

                        if (prctl(PR_GET_SECUREBITS) != sb)
                                if (prctl(PR_SET_SECUREBITS, sb) < 0)
                                        return -errno;
                }
        }

        /* Second step: actually set the uids */
        if (setresuid(uid, uid, uid) < 0)
                return -errno;

        /* At this point we should have all necessary capabilities but
           are otherwise a normal user. However, the caps might got
           corrupted due to the setresuid() so we need clean them up
           later. This is done outside of this call. */

        return 0;
}

#ifdef HAVE_PAM

static int null_conv(
                int num_msg,
                const struct pam_message **msg,
                struct pam_response **resp,
                void *appdata_ptr) {

        /* We don't support conversations */

        return PAM_CONV_ERR;
}

#endif

static int setup_pam(
                const char *name,
                const char *user,
                uid_t uid,
                gid_t gid,
                const char *tty,
                char ***env,
                int fds[], unsigned n_fds) {

#ifdef HAVE_PAM

        static const struct pam_conv conv = {
                .conv = null_conv,
                .appdata_ptr = NULL
        };

        _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
        pam_handle_t *handle = NULL;
        sigset_t old_ss;
        int pam_code = PAM_SUCCESS, r;
        char **nv, **e = NULL;
        bool close_session = false;
        pid_t pam_pid = 0, parent_pid;
        int flags = 0;

        assert(name);
        assert(user);
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

        pam_code = pam_start(name, user, &conv, &handle);
        if (pam_code != PAM_SUCCESS) {
                handle = NULL;
                goto fail;
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

        pam_code = pam_open_session(handle, flags);
        if (pam_code != PAM_SUCCESS)
                goto fail;

        close_session = true;

        e = pam_getenvlist(handle);
        if (!e) {
                pam_code = PAM_BUF_ERR;
                goto fail;
        }

        /* Block SIGTERM, so that we know that it won't get lost in
         * the child */

        assert_se(sigprocmask_many(SIG_BLOCK, &old_ss, SIGTERM, -1) >= 0);

        parent_pid = getpid();

        pam_pid = fork();
        if (pam_pid < 0) {
                r = -errno;
                goto fail;
        }

        if (pam_pid == 0) {
                int sig, ret = EXIT_PAM;

                /* The child's job is to reset the PAM session on
                 * termination */
                barrier_set_role(&barrier, BARRIER_CHILD);

                /* This string must fit in 10 chars (i.e. the length
                 * of "/sbin/init"), to look pretty in /bin/ps */
                rename_process("(sd-pam)");

                /* Make sure we don't keep open the passed fds in this
                child. We assume that otherwise only those fds are
                open here that have been opened by PAM. */
                close_many(fds, n_fds);

                /* Drop privileges - we don't need any to pam_close_session
                 * and this will make PR_SET_PDEATHSIG work in most cases.
                 * If this fails, ignore the error - but expect sd-pam threads
                 * to fail to exit normally */

                r = maybe_setgroups(0, NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to setgroups() in sd-pam: %m");
                if (setresgid(gid, gid, gid) < 0)
                        log_warning_errno(errno, "Failed to setresgid() in sd-pam: %m");
                if (setresuid(uid, uid, uid) < 0)
                        log_warning_errno(errno, "Failed to setresuid() in sd-pam: %m");

                (void) ignore_signals(SIGPIPE, -1);

                /* Wait until our parent died. This will only work if
                 * the above setresuid() succeeds, otherwise the kernel
                 * will not allow unprivileged parents kill their privileged
                 * children this way. We rely on the control groups kill logic
                 * to do the rest for us. */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        goto child_finish;

                /* Tell the parent that our setup is done. This is especially
                 * important regarding dropping privileges. Otherwise, unit
                 * setup might race against our setresuid(2) call.
                 *
                 * If the parent aborted, we'll detect this below, hence ignore
                 * return failure here. */
                (void) barrier_place(&barrier);

                /* Check if our parent process might already have died? */
                if (getppid() == parent_pid) {
                        sigset_t ss;

                        assert_se(sigemptyset(&ss) >= 0);
                        assert_se(sigaddset(&ss, SIGTERM) >= 0);

                        for (;;) {
                                if (sigwait(&ss, &sig) < 0) {
                                        if (errno == EINTR)
                                                continue;

                                        goto child_finish;
                                }

                                assert(sig == SIGTERM);
                                break;
                        }
                }

                /* If our parent died we'll end the session */
                if (getppid() != parent_pid) {
                        pam_code = pam_close_session(handle, flags);
                        if (pam_code != PAM_SUCCESS)
                                goto child_finish;
                }

                ret = 0;

        child_finish:
                pam_end(handle, pam_code | flags);
                _exit(ret);
        }

        barrier_set_role(&barrier, BARRIER_PARENT);

        /* If the child was forked off successfully it will do all the
         * cleanups, so forget about the handle here. */
        handle = NULL;

        /* Unblock SIGTERM again in the parent */
        assert_se(sigprocmask(SIG_SETMASK, &old_ss, NULL) >= 0);

        /* We close the log explicitly here, since the PAM modules
         * might have opened it, but we don't want this fd around. */
        closelog();

        /* Synchronously wait for the child to initialize. We don't care for
         * errors as we cannot recover. However, warn loudly if it happens. */
        if (!barrier_place_and_sync(&barrier))
                log_error("PAM initialization failed");

        strv_free(*env);
        *env = e;

        return 0;

fail:
        if (pam_code != PAM_SUCCESS) {
                log_error("PAM failed: %s", pam_strerror(handle, pam_code));
                r = -EPERM;  /* PAM errors do not map to errno */
        } else
                log_error_errno(r, "PAM failed: %m");

        if (handle) {
                if (close_session)
                        pam_code = pam_close_session(handle, flags);

                pam_end(handle, pam_code | flags);
        }

        strv_free(e);
        closelog();

        return r;
#else
        return 0;
#endif
}

static void rename_process_from_path(const char *path) {
        char process_name[11];
        const char *p;
        size_t l;

        /* This resulting string must fit in 10 chars (i.e. the length
         * of "/sbin/init") to look pretty in /bin/ps */

        p = basename(path);
        if (isempty(p)) {
                rename_process("(...)");
                return;
        }

        l = strlen(p);
        if (l > 8) {
                /* The end of the process name is usually more
                 * interesting, since the first bit might just be
                 * "systemd-" */
                p = p + l - 8;
                l = 8;
        }

        process_name[0] = '(';
        memcpy(process_name+1, p, l);
        process_name[1+l] = ')';
        process_name[1+l+1] = 0;

        rename_process(process_name);
}

static bool context_has_address_families(const ExecContext *c) {
        assert(c);

        return c->address_families_whitelist ||
                !set_isempty(c->address_families);
}

static bool context_has_syscall_filters(const ExecContext *c) {
        assert(c);

        return c->syscall_whitelist ||
                !set_isempty(c->syscall_filter);
}

static bool context_has_no_new_privileges(const ExecContext *c) {
        assert(c);

        if (c->no_new_privileges)
                return true;

        if (have_effective_cap(CAP_SYS_ADMIN)) /* if we are privileged, we don't need NNP */
                return false;

        /* We need NNP if we have any form of seccomp and are unprivileged */
        return context_has_address_families(c) ||
                c->memory_deny_write_execute ||
                c->restrict_realtime ||
                exec_context_restrict_namespaces_set(c) ||
                c->protect_kernel_tunables ||
                c->protect_kernel_modules ||
                c->private_devices ||
                context_has_syscall_filters(c) ||
                !set_isempty(c->syscall_archs);
}

#ifdef HAVE_SECCOMP

static bool skip_seccomp_unavailable(const Unit* u, const char* msg) {

        if (is_seccomp_available())
                return false;

        log_open();
        log_unit_debug(u, "SECCOMP features not detected in the kernel, skipping %s", msg);
        log_close();
        return true;
}

static int apply_syscall_filter(const Unit* u, const ExecContext *c) {
        uint32_t negative_action, default_action, action;

        assert(u);
        assert(c);

        if (!context_has_syscall_filters(c))
                return 0;

        if (skip_seccomp_unavailable(u, "SystemCallFilter="))
                return 0;

        negative_action = c->syscall_errno == 0 ? SCMP_ACT_KILL : SCMP_ACT_ERRNO(c->syscall_errno);

        if (c->syscall_whitelist) {
                default_action = negative_action;
                action = SCMP_ACT_ALLOW;
        } else {
                default_action = SCMP_ACT_ALLOW;
                action = negative_action;
        }

        return seccomp_load_syscall_filter_set_raw(default_action, c->syscall_filter, action);
}

static int apply_syscall_archs(const Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);

        if (set_isempty(c->syscall_archs))
                return 0;

        if (skip_seccomp_unavailable(u, "SystemCallArchitectures="))
                return 0;

        return seccomp_restrict_archs(c->syscall_archs);
}

static int apply_address_families(const Unit* u, const ExecContext *c) {
        assert(u);
        assert(c);

        if (!context_has_address_families(c))
                return 0;

        if (skip_seccomp_unavailable(u, "RestrictAddressFamilies="))
                return 0;

        return seccomp_restrict_address_families(c->address_families, c->address_families_whitelist);
}

static int apply_memory_deny_write_execute(const Unit* u, const ExecContext *c) {
        assert(u);
        assert(c);

        if (!c->memory_deny_write_execute)
                return 0;

        if (skip_seccomp_unavailable(u, "MemoryDenyWriteExecute="))
                return 0;

        return seccomp_memory_deny_write_execute();
}

static int apply_restrict_realtime(const Unit* u, const ExecContext *c) {
        assert(u);
        assert(c);

        if (!c->restrict_realtime)
                return 0;

        if (skip_seccomp_unavailable(u, "RestrictRealtime="))
                return 0;

        return seccomp_restrict_realtime();
}

static int apply_protect_sysctl(const Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);

        /* Turn off the legacy sysctl() system call. Many distributions turn this off while building the kernel, but
         * let's protect even those systems where this is left on in the kernel. */

        if (!c->protect_kernel_tunables)
                return 0;

        if (skip_seccomp_unavailable(u, "ProtectKernelTunables="))
                return 0;

        return seccomp_protect_sysctl();
}

static int apply_protect_kernel_modules(const Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);

        /* Turn off module syscalls on ProtectKernelModules=yes */

        if (!c->protect_kernel_modules)
                return 0;

        if (skip_seccomp_unavailable(u, "ProtectKernelModules="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_MODULE, SCMP_ACT_ERRNO(EPERM));
}

static int apply_private_devices(const Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);

        /* If PrivateDevices= is set, also turn off iopl and all @raw-io syscalls. */

        if (!c->private_devices)
                return 0;

        if (skip_seccomp_unavailable(u, "PrivateDevices="))
                return 0;

        return seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + SYSCALL_FILTER_SET_RAW_IO, SCMP_ACT_ERRNO(EPERM));
}

static int apply_restrict_namespaces(Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);

        if (!exec_context_restrict_namespaces_set(c))
                return 0;

        if (skip_seccomp_unavailable(u, "RestrictNamespaces="))
                return 0;

        return seccomp_restrict_namespaces(c->restrict_namespaces);
}

#endif

static void do_idle_pipe_dance(int idle_pipe[4]) {
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
                                fd_wait_for_event(idle_pipe[0], POLLHUP, IDLE_TIMEOUT2_USEC);
                }

                idle_pipe[0] = safe_close(idle_pipe[0]);

        }

        idle_pipe[3] = safe_close(idle_pipe[3]);
}

static int build_environment(
                Unit *u,
                const ExecContext *c,
                const ExecParameters *p,
                unsigned n_fds,
                const char *home,
                const char *username,
                const char *shell,
                dev_t journal_stream_dev,
                ino_t journal_stream_ino,
                char ***ret) {

        _cleanup_strv_free_ char **our_env = NULL;
        unsigned n_env = 0;
        char *x;

        assert(u);
        assert(c);
        assert(ret);

        our_env = new0(char*, 14);
        if (!our_env)
                return -ENOMEM;

        if (n_fds > 0) {
                _cleanup_free_ char *joined = NULL;

                if (asprintf(&x, "LISTEN_PID="PID_FMT, getpid()) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (asprintf(&x, "LISTEN_FDS=%u", n_fds) < 0)
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
                if (asprintf(&x, "WATCHDOG_PID="PID_FMT, getpid()) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (asprintf(&x, "WATCHDOG_USEC="USEC_FMT, p->watchdog_usec) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        /* If this is D-Bus, tell the nss-systemd module, since it relies on being able to use D-Bus look up dynamic
         * users via PID 1, possibly dead-locking the dbus daemon. This way it will not use D-Bus to resolve names, but
         * check the database directly. */
        if (unit_has_name(u, SPECIAL_DBUS_SERVICE)) {
                x = strdup("SYSTEMD_NSS_BYPASS_BUS=1");
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (home) {
                x = strappend("HOME=", home);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (username) {
                x = strappend("LOGNAME=", username);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;

                x = strappend("USER=", username);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (shell) {
                x = strappend("SHELL=", shell);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (!sd_id128_is_null(u->invocation_id)) {
                if (asprintf(&x, "INVOCATION_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(u->invocation_id)) < 0)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        if (exec_context_needs_term(c)) {
                const char *tty_path, *term = NULL;

                tty_path = exec_context_tty_path(c);

                /* If we are forked off PID 1 and we are supposed to operate on /dev/console, then let's try to inherit
                 * the $TERM set for PID 1. This is useful for containers so that the $TERM the container manager
                 * passes to PID 1 ends up all the way in the console login shown. */

                if (path_equal(tty_path, "/dev/console") && getppid() == 1)
                        term = getenv("TERM");
                if (!term)
                        term = default_term_for_tty(tty_path);

                x = strappend("TERM=", term);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (journal_stream_dev != 0 && journal_stream_ino != 0) {
                if (asprintf(&x, "JOURNAL_STREAM=" DEV_FMT ":" INO_FMT, journal_stream_dev, journal_stream_ino) < 0)
                        return -ENOMEM;

                our_env[n_env++] = x;
        }

        our_env[n_env++] = NULL;
        assert(n_env <= 12);

        *ret = our_env;
        our_env = NULL;

        return 0;
}

static int build_pass_environment(const ExecContext *c, char ***ret) {
        _cleanup_strv_free_ char **pass_env = NULL;
        size_t n_env = 0, n_bufsize = 0;
        char **i;

        STRV_FOREACH(i, c->pass_environment) {
                _cleanup_free_ char *x = NULL;
                char *v;

                v = getenv(*i);
                if (!v)
                        continue;
                x = strjoin(*i, "=", v);
                if (!x)
                        return -ENOMEM;
                if (!GREEDY_REALLOC(pass_env, n_bufsize, n_env + 2))
                        return -ENOMEM;
                pass_env[n_env++] = x;
                pass_env[n_env] = NULL;
                x = NULL;
        }

        *ret = pass_env;
        pass_env = NULL;

        return 0;
}

static bool exec_needs_mount_namespace(
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime) {

        assert(context);
        assert(params);

        if (context->root_image)
                return true;

        if (!strv_isempty(context->read_write_paths) ||
            !strv_isempty(context->read_only_paths) ||
            !strv_isempty(context->inaccessible_paths))
                return true;

        if (context->n_bind_mounts > 0)
                return true;

        if (context->mount_flags != 0)
                return true;

        if (context->private_tmp && runtime && (runtime->tmp_dir || runtime->var_tmp_dir))
                return true;

        if (context->private_devices ||
            context->protect_system != PROTECT_SYSTEM_NO ||
            context->protect_home != PROTECT_HOME_NO ||
            context->protect_kernel_tunables ||
            context->protect_kernel_modules ||
            context->protect_control_groups)
                return true;

        if (context->mount_apivfs && (context->root_image || context->root_directory))
                return true;

        return false;
}

static int setup_private_users(uid_t uid, gid_t gid) {
        _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
        _cleanup_close_pair_ int errno_pipe[2] = { -1, -1 };
        _cleanup_close_ int unshare_ready_fd = -1;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        uint64_t c = 1;
        siginfo_t si;
        ssize_t n;
        int r;

        /* Set up a user namespace and map root to root, the selected UID/GID to itself, and everything else to
         * nobody. In order to be able to write this mapping we need CAP_SETUID in the original user namespace, which
         * we however lack after opening the user namespace. To work around this we fork() a temporary child process,
         * which waits for the parent to create the new user namespace while staying in the original namespace. The
         * child then writes the UID mapping, under full privileges. The parent waits for the child to finish and
         * continues execution normally. */

        if (uid != 0 && uid_is_valid(uid)) {
                r = asprintf(&uid_map,
                             "0 0 1\n"                      /* Map root → root */
                             UID_FMT " " UID_FMT " 1\n",    /* Map $UID → $UID */
                             uid, uid);
                if (r < 0)
                        return -ENOMEM;
        } else {
                uid_map = strdup("0 0 1\n");            /* The case where the above is the same */
                if (!uid_map)
                        return -ENOMEM;
        }

        if (gid != 0 && gid_is_valid(gid)) {
                r = asprintf(&gid_map,
                             "0 0 1\n"                      /* Map root → root */
                             GID_FMT " " GID_FMT " 1\n",    /* Map $GID → $GID */
                             gid, gid);
                if (r < 0)
                        return -ENOMEM;
        } else {
                gid_map = strdup("0 0 1\n");            /* The case where the above is the same */
                if (!gid_map)
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

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                _cleanup_close_ int fd = -1;
                const char *a;
                pid_t ppid;

                /* Child process, running in the original user namespace. Let's update the parent's UID/GID map from
                 * here, after the parent opened its own user namespace. */

                ppid = getppid();
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* Wait until the parent unshared the user namespace */
                if (read(unshare_ready_fd, &c, sizeof(c)) < 0) {
                        r = -errno;
                        goto child_fail;
                }

                /* Disable the setgroups() system call in the child user namespace, for good. */
                a = procfs_file_alloca(ppid, "setgroups");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        if (errno != ENOENT) {
                                r = -errno;
                                goto child_fail;
                        }

                        /* If the file is missing the kernel is too old, let's continue anyway. */
                } else {
                        if (write(fd, "deny\n", 5) < 0) {
                                r = -errno;
                                goto child_fail;
                        }

                        fd = safe_close(fd);
                }

                /* First write the GID map */
                a = procfs_file_alloca(ppid, "gid_map");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        r = -errno;
                        goto child_fail;
                }
                if (write(fd, gid_map, strlen(gid_map)) < 0) {
                        r = -errno;
                        goto child_fail;
                }
                fd = safe_close(fd);

                /* The write the UID map */
                a = procfs_file_alloca(ppid, "uid_map");
                fd = open(a, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        r = -errno;
                        goto child_fail;
                }
                if (write(fd, uid_map, strlen(uid_map)) < 0) {
                        r = -errno;
                        goto child_fail;
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe[1], &r, sizeof(r));
                _exit(EXIT_FAILURE);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);

        if (unshare(CLONE_NEWUSER) < 0)
                return -errno;

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

        r = wait_for_terminate(pid, &si);
        if (r < 0)
                return r;
        pid = 0;

        /* If something strange happened with the child, let's consider this fatal, too */
        if (si.si_code != CLD_EXITED || si.si_status != 0)
                return -EIO;

        return 0;
}

static int setup_runtime_directory(
                const ExecContext *context,
                const ExecParameters *params,
                uid_t uid,
                gid_t gid) {

        char **rt;
        int r;

        assert(context);
        assert(params);

        STRV_FOREACH(rt, context->runtime_directory) {
                _cleanup_free_ char *p;

                p = strjoin(params->runtime_prefix, "/", *rt);
                if (!p)
                        return -ENOMEM;

                r = mkdir_p_label(p, context->runtime_directory_mode);
                if (r < 0)
                        return r;

                r = chmod_and_chown(p, context->runtime_directory_mode, uid, gid);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int setup_smack(
                const ExecContext *context,
                const ExecCommand *command) {

#ifdef HAVE_SMACK
        int r;

        assert(context);
        assert(command);

        if (!mac_smack_use())
                return 0;

        if (context->smack_process_label) {
                r = mac_smack_apply_pid(0, context->smack_process_label);
                if (r < 0)
                        return r;
        }
#ifdef SMACK_DEFAULT_PROCESS_LABEL
        else {
                _cleanup_free_ char *exec_label = NULL;

                r = mac_smack_read(command->path, SMACK_ATTR_EXEC, &exec_label);
                if (r < 0 && r != -ENODATA && r != -EOPNOTSUPP)
                        return r;

                r = mac_smack_apply_pid(0, exec_label ? : SMACK_DEFAULT_PROCESS_LABEL);
                if (r < 0)
                        return r;
        }
#endif
#endif

        return 0;
}

static int compile_read_write_paths(
                const ExecContext *context,
                const ExecParameters *params,
                char ***ret) {

        _cleanup_strv_free_ char **l = NULL;
        char **rt;

        /* Compile the list of writable paths. This is the combination of
         * the explicitly configured paths, plus all runtime directories. */

        if (strv_isempty(context->read_write_paths) &&
            strv_isempty(context->runtime_directory)) {
                *ret = NULL; /* NOP if neither is set */
                return 0;
        }

        l = strv_copy(context->read_write_paths);
        if (!l)
                return -ENOMEM;

        STRV_FOREACH(rt, context->runtime_directory) {
                char *s;

                s = strjoin(params->runtime_prefix, "/", *rt);
                if (!s)
                        return -ENOMEM;

                if (strv_consume(&l, s) < 0)
                        return -ENOMEM;
        }

        *ret = l;
        l = NULL;

        return 0;
}

static int apply_mount_namespace(
                Unit *u,
                ExecCommand *command,
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime) {

        _cleanup_strv_free_ char **rw = NULL;
        char *tmp = NULL, *var = NULL;
        const char *root_dir = NULL, *root_image = NULL;
        NameSpaceInfo ns_info = {
                .ignore_protect_paths = false,
                .private_dev = context->private_devices,
                .protect_control_groups = context->protect_control_groups,
                .protect_kernel_tunables = context->protect_kernel_tunables,
                .protect_kernel_modules = context->protect_kernel_modules,
                .mount_apivfs = context->mount_apivfs,
        };
        bool apply_restrictions;
        int r;

        assert(context);

        /* The runtime struct only contains the parent of the private /tmp,
         * which is non-accessible to world users. Inside of it there's a /tmp
         * that is sticky, and that's the one we want to use here. */

        if (context->private_tmp && runtime) {
                if (runtime->tmp_dir)
                        tmp = strjoina(runtime->tmp_dir, "/tmp");
                if (runtime->var_tmp_dir)
                        var = strjoina(runtime->var_tmp_dir, "/tmp");
        }

        r = compile_read_write_paths(context, params, &rw);
        if (r < 0)
                return r;

        if (params->flags & EXEC_APPLY_CHROOT) {
                root_image = context->root_image;

                if (!root_image)
                        root_dir = context->root_directory;
        }

        /*
         * If DynamicUser=no and RootDirectory= is set then lets pass a relaxed
         * sandbox info, otherwise enforce it, don't ignore protected paths and
         * fail if we are enable to apply the sandbox inside the mount namespace.
         */
        if (!context->dynamic_user && root_dir)
                ns_info.ignore_protect_paths = true;

        apply_restrictions = (params->flags & EXEC_APPLY_PERMISSIONS) && !command->privileged;

        r = setup_namespace(root_dir, root_image,
                            &ns_info, rw,
                            apply_restrictions ? context->read_only_paths : NULL,
                            apply_restrictions ? context->inaccessible_paths : NULL,
                            context->bind_mounts,
                            context->n_bind_mounts,
                            tmp,
                            var,
                            apply_restrictions ? context->protect_home : PROTECT_HOME_NO,
                            apply_restrictions ? context->protect_system : PROTECT_SYSTEM_NO,
                            context->mount_flags,
                            DISSECT_IMAGE_DISCARD_ON_LOOP);

        /* If we couldn't set up the namespace this is probably due to a
         * missing capability. In this case, silently proceeed. */
        if (IN_SET(r, -EPERM, -EACCES)) {
                log_open();
                log_unit_debug_errno(u, r, "Failed to set up namespace, assuming containerized execution, ignoring: %m");
                log_close();
                r = 0;
        }

        return r;
}

static int apply_working_directory(
                const ExecContext *context,
                const ExecParameters *params,
                const char *home,
                const bool needs_mount_ns,
                int *exit_status) {

        const char *d, *wd;

        assert(context);
        assert(exit_status);

        if (context->working_directory_home) {

                if (!home) {
                        *exit_status = EXIT_CHDIR;
                        return -ENXIO;
                }

                wd = home;

        } else if (context->working_directory)
                wd = context->working_directory;
        else
                wd = "/";

        if (params->flags & EXEC_APPLY_CHROOT) {
                if (!needs_mount_ns && context->root_directory)
                        if (chroot(context->root_directory) < 0) {
                                *exit_status = EXIT_CHROOT;
                                return -errno;
                        }

                d = wd;
        } else
                d = prefix_roota(context->root_directory, wd);

        if (chdir(d) < 0 && !context->working_directory_missing_ok) {
                *exit_status = EXIT_CHDIR;
                return -errno;
        }

        return 0;
}

static int setup_keyring(Unit *u, const ExecParameters *p, uid_t uid, gid_t gid) {
        key_serial_t keyring;

        assert(u);
        assert(p);

        /* Let's set up a new per-service "session" kernel keyring for each system service. This has the benefit that
         * each service runs with its own keyring shared among all processes of the service, but with no hook-up beyond
         * that scope, and in particular no link to the per-UID keyring. If we don't do this the keyring will be
         * automatically created on-demand and then linked to the per-UID keyring, by the kernel. The kernel's built-in
         * on-demand behaviour is very appropriate for login users, but probably not so much for system services, where
         * UIDs are not necessarily specific to a service but reused (at least in the case of UID 0). */

        if (!(p->flags & EXEC_NEW_KEYRING))
                return 0;

        keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
        if (keyring == -1) {
                if (errno == ENOSYS)
                        log_debug_errno(errno, "Kernel keyring not supported, ignoring.");
                else if (IN_SET(errno, EACCES, EPERM))
                        log_debug_errno(errno, "Kernel keyring access prohibited, ignoring.");
                else if (errno == EDQUOT)
                        log_debug_errno(errno, "Out of kernel keyrings to allocate, ignoring.");
                else
                        return log_error_errno(errno, "Setting up kernel keyring failed: %m");

                return 0;
        }

        /* Populate they keyring with the invocation ID by default. */
        if (!sd_id128_is_null(u->invocation_id)) {
                key_serial_t key;

                key = add_key("user", "invocation_id", &u->invocation_id, sizeof(u->invocation_id), KEY_SPEC_SESSION_KEYRING);
                if (key == -1)
                        log_debug_errno(errno, "Failed to add invocation ID to keyring, ignoring: %m");
                else {
                        if (keyctl(KEYCTL_SETPERM, key,
                                   KEY_POS_VIEW|KEY_POS_READ|KEY_POS_SEARCH|
                                   KEY_USR_VIEW|KEY_USR_READ|KEY_USR_SEARCH, 0, 0) < 0)
                                return log_error_errno(errno, "Failed to restrict invocation ID permission: %m");
                }
        }

        /* And now, make the keyring owned by the service's user */
        if (uid_is_valid(uid) || gid_is_valid(gid))
                if (keyctl(KEYCTL_CHOWN, keyring, uid, gid, 0) < 0)
                        return log_error_errno(errno, "Failed to change ownership of session keyring: %m");

        return 0;
}

static void append_socket_pair(int *array, unsigned *n, int pair[2]) {
        assert(array);
        assert(n);

        if (!pair)
                return;

        if (pair[0] >= 0)
                array[(*n)++] = pair[0];
        if (pair[1] >= 0)
                array[(*n)++] = pair[1];
}

static int close_remaining_fds(
                const ExecParameters *params,
                ExecRuntime *runtime,
                DynamicCreds *dcreds,
                int user_lookup_fd,
                int socket_fd,
                int *fds, unsigned n_fds) {

        unsigned n_dont_close = 0;
        int dont_close[n_fds + 12];

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
                append_socket_pair(dont_close, &n_dont_close, runtime->netns_storage_socket);

        if (dcreds) {
                if (dcreds->user)
                        append_socket_pair(dont_close, &n_dont_close, dcreds->user->storage_socket);
                if (dcreds->group)
                        append_socket_pair(dont_close, &n_dont_close, dcreds->group->storage_socket);
        }

        if (user_lookup_fd >= 0)
                dont_close[n_dont_close++] = user_lookup_fd;

        return close_all_fds(dont_close, n_dont_close);
}

static int send_user_lookup(
                Unit *unit,
                int user_lookup_fd,
                uid_t uid,
                gid_t gid) {

        assert(unit);

        /* Send the resolved UID/GID to PID 1 after we learnt it. We send a single datagram, containing the UID/GID
         * data as well as the unit name. Note that we suppress sending this if no user/group to resolve was
         * specified. */

        if (user_lookup_fd < 0)
                return 0;

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        if (writev(user_lookup_fd,
               (struct iovec[]) {
                           { .iov_base = &uid, .iov_len = sizeof(uid) },
                           { .iov_base = &gid, .iov_len = sizeof(gid) },
                           { .iov_base = unit->id, .iov_len = strlen(unit->id) }}, 3) < 0)
                return -errno;

        return 0;
}

static int acquire_home(const ExecContext *c, uid_t uid, const char** home, char **buf) {
        int r;

        assert(c);
        assert(home);
        assert(buf);

        /* If WorkingDirectory=~ is set, try to acquire a usable home directory. */

        if (*home)
                return 0;

        if (!c->working_directory_home)
                return 0;

        if (uid == 0) {
                /* Hardcode /root as home directory for UID 0 */
                *home = "/root";
                return 1;
        }

        r = get_home_dir(buf);
        if (r < 0)
                return r;

        *home = *buf;
        return 1;
}

static int exec_child(
                Unit *unit,
                ExecCommand *command,
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                DynamicCreds *dcreds,
                char **argv,
                int socket_fd,
                int named_iofds[3],
                int *fds,
                unsigned n_storage_fds,
                unsigned n_socket_fds,
                char **files_env,
                int user_lookup_fd,
                int *exit_status,
                char **error_message) {

        _cleanup_strv_free_ char **our_env = NULL, **pass_env = NULL, **accum_env = NULL, **final_argv = NULL;
        _cleanup_free_ char *mac_selinux_context_net = NULL, *home_buffer = NULL;
        _cleanup_free_ gid_t *supplementary_gids = NULL;
        const char *username = NULL, *groupname = NULL;
        const char *home = NULL, *shell = NULL;
        dev_t journal_stream_dev = 0;
        ino_t journal_stream_ino = 0;
        bool needs_mount_namespace;
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        int i, r, ngids = 0;
        unsigned n_fds;

        assert(unit);
        assert(command);
        assert(context);
        assert(params);
        assert(exit_status);
        assert(error_message);
        /* We don't always set error_message, hence it must be initialized */
        assert(*error_message == NULL);

        rename_process_from_path(command->path);

        /* We reset exactly these signals, since they are the
         * only ones we set to SIG_IGN in the main daemon. All
         * others we leave untouched because we set them to
         * SIG_DFL or a valid handler initially, both of which
         * will be demoted to SIG_DFL. */
        (void) default_signals(SIGNALS_CRASH_HANDLER,
                               SIGNALS_IGNORE, -1);

        if (context->ignore_sigpipe)
                (void) ignore_signals(SIGPIPE, -1);

        r = reset_signal_mask();
        if (r < 0) {
                *exit_status = EXIT_SIGNAL_MASK;
                *error_message = strdup("Failed to reset signal mask");
                /* If strdup fails, here and below, we will just print the generic error message. */
                return r;
        }

        if (params->idle_pipe)
                do_idle_pipe_dance(params->idle_pipe);

        /* Close sockets very early to make sure we don't
         * block init reexecution because it cannot bind its
         * sockets */

        log_forget_fds();

        n_fds = n_storage_fds + n_socket_fds;
        r = close_remaining_fds(params, runtime, dcreds, user_lookup_fd, socket_fd, fds, n_fds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                *error_message = strdup("Failed to close remaining fds");
                return r;
        }

        if (!context->same_pgrp)
                if (setsid() < 0) {
                        *exit_status = EXIT_SETSID;
                        return -errno;
                }

        exec_context_tty_reset(context, params);

        if (unit_shall_confirm_spawn(unit)) {
                const char *vc = params->confirm_spawn;
                _cleanup_free_ char *cmdline = NULL;

                cmdline = exec_command_line(argv);
                if (!cmdline) {
                        *exit_status = EXIT_CONFIRM;
                        return -ENOMEM;
                }

                r = ask_for_confirmation(vc, unit, cmdline);
                if (r != CONFIRM_EXECUTE) {
                        if (r == CONFIRM_PRETEND_SUCCESS) {
                                *exit_status = EXIT_SUCCESS;
                                return 0;
                        }
                        *exit_status = EXIT_CONFIRM;
                        *error_message = strdup("Execution cancelled");
                        return -ECANCELED;
                }
        }

        if (context->dynamic_user && dcreds) {

                /* Make sure we bypass our own NSS module for any NSS checks */
                if (putenv((char*) "SYSTEMD_NSS_DYNAMIC_BYPASS=1") != 0) {
                        *exit_status = EXIT_USER;
                        *error_message = strdup("Failed to update environment");
                        return -errno;
                }

                r = dynamic_creds_realize(dcreds, &uid, &gid);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        *error_message = strdup("Failed to update dynamic user credentials");
                        return r;
                }

                if (!uid_is_valid(uid)) {
                        *exit_status = EXIT_USER;
                        (void) asprintf(error_message, "UID validation failed for \""UID_FMT"\"", uid);
                        /* If asprintf fails, here and below, we will just print the generic error message. */
                        return -ESRCH;
                }

                if (!gid_is_valid(gid)) {
                        *exit_status = EXIT_USER;
                        (void) asprintf(error_message, "GID validation failed for \""GID_FMT"\"", gid);
                        return -ESRCH;
                }

                if (dcreds->user)
                        username = dcreds->user->name;

        } else {
                r = get_fixed_user(context, &username, &uid, &gid, &home, &shell);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        *error_message = strdup("Failed to determine user credentials");
                        return r;
                }

                r = get_fixed_group(context, &groupname, &gid);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        *error_message = strdup("Failed to determine group credentials");
                        return r;
                }
        }

        /* Initialize user supplementary groups and get SupplementaryGroups= ones */
        r = get_supplementary_groups(context, username, groupname, gid,
                                     &supplementary_gids, &ngids);
        if (r < 0) {
                *exit_status = EXIT_GROUP;
                *error_message = strdup("Failed to determine supplementary groups");
                return r;
        }

        r = send_user_lookup(unit, user_lookup_fd, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_USER;
                *error_message = strdup("Failed to send user credentials to PID1");
                return r;
        }

        user_lookup_fd = safe_close(user_lookup_fd);

        r = acquire_home(context, uid, &home, &home_buffer);
        if (r < 0) {
                *exit_status = EXIT_CHDIR;
                *error_message = strdup("Failed to determine $HOME for user");
                return r;
        }

        /* If a socket is connected to STDIN/STDOUT/STDERR, we
         * must sure to drop O_NONBLOCK */
        if (socket_fd >= 0)
                (void) fd_nonblock(socket_fd, false);

        r = setup_input(context, params, socket_fd, named_iofds);
        if (r < 0) {
                *exit_status = EXIT_STDIN;
                *error_message = strdup("Failed to set up stdin");
                return r;
        }

        r = setup_output(unit, context, params, STDOUT_FILENO, socket_fd, named_iofds, basename(command->path), uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                *error_message = strdup("Failed to set up stdout");
                return r;
        }

        r = setup_output(unit, context, params, STDERR_FILENO, socket_fd, named_iofds, basename(command->path), uid, gid, &journal_stream_dev, &journal_stream_ino);
        if (r < 0) {
                *exit_status = EXIT_STDERR;
                *error_message = strdup("Failed to set up stderr");
                return r;
        }

        if (params->cgroup_path) {
                r = cg_attach_everywhere(params->cgroup_supported, params->cgroup_path, 0, NULL, NULL);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        (void) asprintf(error_message, "Failed to attach to cgroup %s", params->cgroup_path);
                        return r;
                }
        }

        if (context->oom_score_adjust_set) {
                char t[DECIMAL_STR_MAX(context->oom_score_adjust)];

                /* When we can't make this change due to EPERM, then
                 * let's silently skip over it. User namespaces
                 * prohibit write access to this file, and we
                 * shouldn't trip up over that. */

                sprintf(t, "%i", context->oom_score_adjust);
                r = write_string_file("/proc/self/oom_score_adj", t, 0);
                if (r == -EPERM || r == -EACCES) {
                        log_open();
                        log_unit_debug_errno(unit, r, "Failed to adjust OOM setting, assuming containerized execution, ignoring: %m");
                        log_close();
                } else if (r < 0) {
                        *exit_status = EXIT_OOM_ADJUST;
                        *error_message = strdup("Failed to write /proc/self/oom_score_adj");
                        return -errno;
                }
        }

        if (context->nice_set)
                if (setpriority(PRIO_PROCESS, 0, context->nice) < 0) {
                        *exit_status = EXIT_NICE;
                        return -errno;
                }

        if (context->cpu_sched_set) {
                struct sched_param param = {
                        .sched_priority = context->cpu_sched_priority,
                };

                r = sched_setscheduler(0,
                                       context->cpu_sched_policy |
                                       (context->cpu_sched_reset_on_fork ?
                                        SCHED_RESET_ON_FORK : 0),
                                       &param);
                if (r < 0) {
                        *exit_status = EXIT_SETSCHEDULER;
                        return -errno;
                }
        }

        if (context->cpuset)
                if (sched_setaffinity(0, CPU_ALLOC_SIZE(context->cpuset_ncpus), context->cpuset) < 0) {
                        *exit_status = EXIT_CPUAFFINITY;
                        return -errno;
                }

        if (context->ioprio_set)
                if (ioprio_set(IOPRIO_WHO_PROCESS, 0, context->ioprio) < 0) {
                        *exit_status = EXIT_IOPRIO;
                        return -errno;
                }

        if (context->timer_slack_nsec != NSEC_INFINITY)
                if (prctl(PR_SET_TIMERSLACK, context->timer_slack_nsec) < 0) {
                        *exit_status = EXIT_TIMERSLACK;
                        return -errno;
                }

        if (context->personality != PERSONALITY_INVALID)
                if (personality(context->personality) < 0) {
                        *exit_status = EXIT_PERSONALITY;
                        return -errno;
                }

        if (context->utmp_id)
                utmp_put_init_process(context->utmp_id, getpid(), getsid(0),
                                      context->tty_path,
                                      context->utmp_mode == EXEC_UTMP_INIT  ? INIT_PROCESS :
                                      context->utmp_mode == EXEC_UTMP_LOGIN ? LOGIN_PROCESS :
                                      USER_PROCESS,
                                      username);

        if (context->user) {
                r = chown_terminal(STDIN_FILENO, uid);
                if (r < 0) {
                        *exit_status = EXIT_STDIN;
                        return r;
                }
        }

        /* If delegation is enabled we'll pass ownership of the cgroup
         * (but only in systemd's own controller hierarchy!) to the
         * user of the new process. */
        if (params->cgroup_path && context->user && params->cgroup_delegate) {
                r = cg_set_task_access(SYSTEMD_CGROUP_CONTROLLER, params->cgroup_path, 0644, uid, gid);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return r;
                }


                r = cg_set_group_access(SYSTEMD_CGROUP_CONTROLLER, params->cgroup_path, 0755, uid, gid);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
                        return r;
                }
        }

        if (!strv_isempty(context->runtime_directory) && params->runtime_prefix) {
                r = setup_runtime_directory(context, params, uid, gid);
                if (r < 0) {
                        *exit_status = EXIT_RUNTIME_DIRECTORY;
                        return r;
                }
        }

        r = build_environment(
                        unit,
                        context,
                        params,
                        n_fds,
                        home,
                        username,
                        shell,
                        journal_stream_dev,
                        journal_stream_ino,
                        &our_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return r;
        }

        r = build_pass_environment(context, &pass_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return r;
        }

        accum_env = strv_env_merge(5,
                                   params->environment,
                                   our_env,
                                   pass_env,
                                   context->environment,
                                   files_env,
                                   NULL);
        if (!accum_env) {
                *exit_status = EXIT_MEMORY;
                return -ENOMEM;
        }
        accum_env = strv_env_clean(accum_env);

        (void) umask(context->umask);

        r = setup_keyring(unit, params, uid, gid);
        if (r < 0) {
                *exit_status = EXIT_KEYRING;
                return r;
        }

        if ((params->flags & EXEC_APPLY_PERMISSIONS) && !command->privileged) {
                if (context->pam_name && username) {
                        r = setup_pam(context->pam_name, username, uid, gid, context->tty_path, &accum_env, fds, n_fds);
                        if (r < 0) {
                                *exit_status = EXIT_PAM;
                                return r;
                        }
                }
        }

        if (context->private_network && runtime && runtime->netns_storage_socket[0] >= 0) {
                r = setup_netns(runtime->netns_storage_socket);
                if (r < 0) {
                        *exit_status = EXIT_NETWORK;
                        return r;
                }
        }

        needs_mount_namespace = exec_needs_mount_namespace(context, params, runtime);
        if (needs_mount_namespace) {
                r = apply_mount_namespace(unit, command, context, params, runtime);
                if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return r;
                }
        }

        /* Apply just after mount namespace setup */
        r = apply_working_directory(context, params, home, needs_mount_namespace, exit_status);
        if (r < 0)
                return r;

        /* Drop groups as early as possbile */
        if ((params->flags & EXEC_APPLY_PERMISSIONS) && !command->privileged) {
                r = enforce_groups(context, gid, supplementary_gids, ngids);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        return r;
                }
        }

#ifdef HAVE_SELINUX
        if ((params->flags & EXEC_APPLY_PERMISSIONS) &&
            mac_selinux_use() &&
            params->selinux_context_net &&
            socket_fd >= 0 &&
            !command->privileged) {

                r = mac_selinux_get_child_mls_label(socket_fd, command->path, context->selinux_context, &mac_selinux_context_net);
                if (r < 0) {
                        *exit_status = EXIT_SELINUX_CONTEXT;
                        return r;
                }
        }
#endif

        if ((params->flags & EXEC_APPLY_PERMISSIONS) && context->private_users) {
                r = setup_private_users(uid, gid);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        return r;
                }
        }

        /* We repeat the fd closing here, to make sure that
         * nothing is leaked from the PAM modules. Note that
         * we are more aggressive this time since socket_fd
         * and the netns fds we don't need anymore. The custom
         * endpoint fd was needed to upload the policy and can
         * now be closed as well. */
        r = close_all_fds(fds, n_fds);
        if (r >= 0)
                r = shift_fds(fds, n_fds);
        if (r >= 0)
                r = flags_fds(fds, n_storage_fds, n_socket_fds, context->non_blocking);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return r;
        }

        if ((params->flags & EXEC_APPLY_PERMISSIONS) && !command->privileged) {

                int secure_bits = context->secure_bits;

                for (i = 0; i < _RLIMIT_MAX; i++) {

                        if (!context->rlimit[i])
                                continue;

                        r = setrlimit_closest(i, context->rlimit[i]);
                        if (r < 0) {
                                *exit_status = EXIT_LIMITS;
                                return r;
                        }
                }

                /* Set the RTPRIO resource limit to 0, but only if nothing else was explicitly requested. */
                if (context->restrict_realtime && !context->rlimit[RLIMIT_RTPRIO]) {
                        if (setrlimit(RLIMIT_RTPRIO, &RLIMIT_MAKE_CONST(0)) < 0) {
                                *exit_status = EXIT_LIMITS;
                                return -errno;
                        }
                }

                if (!cap_test_all(context->capability_bounding_set)) {
                        r = capability_bounding_set_drop(context->capability_bounding_set, false);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                *error_message = strdup("Failed to drop capabilities");
                                return r;
                        }
                }

                /* This is done before enforce_user, but ambient set
                 * does not survive over setresuid() if keep_caps is not set. */
                if (context->capability_ambient_set != 0) {
                        r = capability_ambient_set_apply(context->capability_ambient_set, true);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                *error_message = strdup("Failed to apply ambient capabilities (before UID change)");
                                return r;
                        }
                }

                if (context->user) {
                        r = enforce_user(context, uid);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                (void) asprintf(error_message, "Failed to change UID to "UID_FMT, uid);
                                return r;
                        }
                        if (context->capability_ambient_set != 0) {

                                /* Fix the ambient capabilities after user change. */
                                r = capability_ambient_set_apply(context->capability_ambient_set, false);
                                if (r < 0) {
                                        *exit_status = EXIT_CAPABILITIES;
                                        *error_message = strdup("Failed to apply ambient capabilities (after UID change)");
                                        return r;
                                }

                                /* If we were asked to change user and ambient capabilities
                                 * were requested, we had to add keep-caps to the securebits
                                 * so that we would maintain the inherited capability set
                                 * through the setresuid(). Make sure that the bit is added
                                 * also to the context secure_bits so that we don't try to
                                 * drop the bit away next. */

                                secure_bits |= 1<<SECURE_KEEP_CAPS;
                        }
                }

                /* Apply the MAC contexts late, but before seccomp syscall filtering, as those should really be last to
                 * influence our own codepaths as little as possible. Moreover, applying MAC contexts usually requires
                 * syscalls that are subject to seccomp filtering, hence should probably be applied before the syscalls
                 * are restricted. */

#ifdef HAVE_SELINUX
                if (mac_selinux_use()) {
                        char *exec_context = mac_selinux_context_net ?: context->selinux_context;

                        if (exec_context) {
                                r = setexeccon(exec_context);
                                if (r < 0) {
                                        *exit_status = EXIT_SELINUX_CONTEXT;
                                        (void) asprintf(error_message, "Failed to set SELinux context to %s", exec_context);
                                        return r;
                                }
                        }
                }
#endif

                r = setup_smack(context, command);
                if (r < 0) {
                        *exit_status = EXIT_SMACK_PROCESS_LABEL;
                        *error_message = strdup("Failed to set SMACK process label");
                        return r;
                }

#ifdef HAVE_APPARMOR
                if (context->apparmor_profile && mac_apparmor_use()) {
                        r = aa_change_onexec(context->apparmor_profile);
                        if (r < 0 && !context->apparmor_profile_ignore) {
                                *exit_status = EXIT_APPARMOR_PROFILE;
                                (void) asprintf(error_message,
                                                "Failed to prepare AppArmor profile change to %s",
                                                context->apparmor_profile);
                                return -errno;
                        }
                }
#endif

                /* PR_GET_SECUREBITS is not privileged, while
                 * PR_SET_SECUREBITS is. So to suppress
                 * potential EPERMs we'll try not to call
                 * PR_SET_SECUREBITS unless necessary. */
                if (prctl(PR_GET_SECUREBITS) != secure_bits)
                        if (prctl(PR_SET_SECUREBITS, secure_bits) < 0) {
                                *exit_status = EXIT_SECUREBITS;
                                *error_message = strdup("Failed to set secure bits");
                                return -errno;
                        }

                if (context_has_no_new_privileges(context))
                        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                                *exit_status = EXIT_NO_NEW_PRIVILEGES;
                                *error_message = strdup("Failed to disable new privileges");
                                return -errno;
                        }

#ifdef HAVE_SECCOMP
                r = apply_address_families(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_ADDRESS_FAMILIES;
                        *error_message = strdup("Failed to restrict address families");
                        return r;
                }

                r = apply_memory_deny_write_execute(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to disable writing to executable memory");
                        return r;
                }

                r = apply_restrict_realtime(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply realtime restrictions");
                        return r;
                }

                r = apply_restrict_namespaces(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply namespace restrictions");
                        return r;
                }

                r = apply_protect_sysctl(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply sysctl restrictions");
                        return r;
                }

                r = apply_protect_kernel_modules(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply module loading restrictions");
                        return r;
                }

                r = apply_private_devices(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to set up private devices");
                        return r;
                }

                r = apply_syscall_archs(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply syscall architecture restrictions");
                        return r;
                }

                /* This really should remain the last step before the execve(), to make sure our own code is unaffected
                 * by the filter as little as possible. */
                r = apply_syscall_filter(unit, context);
                if (r < 0) {
                        *exit_status = EXIT_SECCOMP;
                        *error_message = strdup("Failed to apply syscall filters");
                        return r;
                }
#endif
        }

        final_argv = replace_env_argv(argv, accum_env);
        if (!final_argv) {
                *exit_status = EXIT_MEMORY;
                *error_message = strdup("Failed to prepare process arguments");
                return -ENOMEM;
        }

        if (_unlikely_(log_get_max_level() >= LOG_DEBUG)) {
                _cleanup_free_ char *line;

                line = exec_command_line(final_argv);
                if (line) {
                        log_open();
                        log_struct(LOG_DEBUG,
                                   "EXECUTABLE=%s", command->path,
                                   LOG_UNIT_MESSAGE(unit, "Executing: %s", line),
                                   LOG_UNIT_ID(unit),
                                   NULL);
                        log_close();
                }
        }

        execve(command->path, final_argv, accum_env);
        *exit_status = EXIT_EXEC;
        return -errno;
}

int exec_spawn(Unit *unit,
               ExecCommand *command,
               const ExecContext *context,
               const ExecParameters *params,
               ExecRuntime *runtime,
               DynamicCreds *dcreds,
               pid_t *ret) {

        _cleanup_strv_free_ char **files_env = NULL;
        int *fds = NULL;
        unsigned n_storage_fds = 0, n_socket_fds = 0;
        _cleanup_free_ char *line = NULL;
        int socket_fd, r;
        int named_iofds[3] = { -1, -1, -1 };
        char **argv;
        pid_t pid;

        assert(unit);
        assert(command);
        assert(context);
        assert(ret);
        assert(params);
        assert(params->fds || (params->n_storage_fds + params->n_socket_fds <= 0));

        if (context->std_input == EXEC_INPUT_SOCKET ||
            context->std_output == EXEC_OUTPUT_SOCKET ||
            context->std_error == EXEC_OUTPUT_SOCKET) {

                if (params->n_socket_fds > 1) {
                        log_unit_error(unit, "Got more than one socket.");
                        return -EINVAL;
                }

                if (params->n_socket_fds == 0) {
                        log_unit_error(unit, "Got no socket.");
                        return -EINVAL;
                }

                socket_fd = params->fds[0];
        } else {
                socket_fd = -1;
                fds = params->fds;
                n_storage_fds = params->n_storage_fds;
                n_socket_fds = params->n_socket_fds;
        }

        r = exec_context_named_iofds(unit, context, params, named_iofds);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to load a named file descriptor: %m");

        r = exec_context_load_environment(unit, context, &files_env);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to load environment files: %m");

        argv = params->argv ?: command->argv;
        line = exec_command_line(argv);
        if (!line)
                return log_oom();

        log_struct(LOG_DEBUG,
                   LOG_UNIT_MESSAGE(unit, "About to execute: %s", line),
                   "EXECUTABLE=%s", command->path,
                   LOG_UNIT_ID(unit),
                   NULL);
        pid = fork();
        if (pid < 0)
                return log_unit_error_errno(unit, errno, "Failed to fork: %m");

        if (pid == 0) {
                int exit_status;
                _cleanup_free_ char *error_message = NULL;

                r = exec_child(unit,
                               command,
                               context,
                               params,
                               runtime,
                               dcreds,
                               argv,
                               socket_fd,
                               named_iofds,
                               fds,
                               n_storage_fds,
                               n_socket_fds,
                               files_env,
                               unit->manager->user_lookup_fds[1],
                               &exit_status,
                               &error_message);
                if (r < 0) {
                        log_open();
                        if (error_message)
                                log_struct_errno(LOG_ERR, r,
                                                 "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                                 LOG_UNIT_ID(unit),
                                                 LOG_UNIT_MESSAGE(unit, "%s: %m",
                                                                  error_message),
                                                 "EXECUTABLE=%s", command->path,
                                                 NULL);
                        else if (r == -ENOENT && command->ignore)
                                log_struct_errno(LOG_INFO, r,
                                                 "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                                 LOG_UNIT_ID(unit),
                                                 LOG_UNIT_MESSAGE(unit, "Skipped spawning %s: %m",
                                                                  command->path),
                                                 "EXECUTABLE=%s", command->path,
                                                 NULL);
                        else
                                log_struct_errno(LOG_ERR, r,
                                                 "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                                 LOG_UNIT_ID(unit),
                                                 LOG_UNIT_MESSAGE(unit, "Failed at step %s spawning %s: %m",
                                                                  exit_status_to_string(exit_status, EXIT_STATUS_SYSTEMD),
                                                                  command->path),
                                                 "EXECUTABLE=%s", command->path,
                                                 NULL);
                }

                _exit(exit_status);
        }

        log_unit_debug(unit, "Forked %s as "PID_FMT, command->path, pid);

        /* We add the new process to the cgroup both in the child (so
         * that we can be sure that no user code is ever executed
         * outside of the cgroup) and in the parent (so that we can be
         * sure that when we kill the cgroup the process will be
         * killed too). */
        if (params->cgroup_path)
                (void) cg_attach(SYSTEMD_CGROUP_CONTROLLER, params->cgroup_path, pid);

        exec_status_start(&command->exec_status, pid);

        *ret = pid;
        return 0;
}

void exec_context_init(ExecContext *c) {
        assert(c);

        c->umask = 0022;
        c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0);
        c->cpu_sched_policy = SCHED_OTHER;
        c->syslog_priority = LOG_DAEMON|LOG_INFO;
        c->syslog_level_prefix = true;
        c->ignore_sigpipe = true;
        c->timer_slack_nsec = NSEC_INFINITY;
        c->personality = PERSONALITY_INVALID;
        c->runtime_directory_mode = 0755;
        c->capability_bounding_set = CAP_ALL;
        c->restrict_namespaces = NAMESPACE_FLAGS_ALL;
}

void exec_context_done(ExecContext *c) {
        unsigned l;

        assert(c);

        c->environment = strv_free(c->environment);
        c->environment_files = strv_free(c->environment_files);
        c->pass_environment = strv_free(c->pass_environment);

        for (l = 0; l < ELEMENTSOF(c->rlimit); l++)
                c->rlimit[l] = mfree(c->rlimit[l]);

        for (l = 0; l < 3; l++)
                c->stdio_fdname[l] = mfree(c->stdio_fdname[l]);

        c->working_directory = mfree(c->working_directory);
        c->root_directory = mfree(c->root_directory);
        c->root_image = mfree(c->root_image);
        c->tty_path = mfree(c->tty_path);
        c->syslog_identifier = mfree(c->syslog_identifier);
        c->user = mfree(c->user);
        c->group = mfree(c->group);

        c->supplementary_groups = strv_free(c->supplementary_groups);

        c->pam_name = mfree(c->pam_name);

        c->read_only_paths = strv_free(c->read_only_paths);
        c->read_write_paths = strv_free(c->read_write_paths);
        c->inaccessible_paths = strv_free(c->inaccessible_paths);

        bind_mount_free_many(c->bind_mounts, c->n_bind_mounts);

        if (c->cpuset)
                CPU_FREE(c->cpuset);

        c->utmp_id = mfree(c->utmp_id);
        c->selinux_context = mfree(c->selinux_context);
        c->apparmor_profile = mfree(c->apparmor_profile);

        c->syscall_filter = set_free(c->syscall_filter);
        c->syscall_archs = set_free(c->syscall_archs);
        c->address_families = set_free(c->address_families);

        c->runtime_directory = strv_free(c->runtime_directory);
}

int exec_context_destroy_runtime_directory(ExecContext *c, const char *runtime_prefix) {
        char **i;

        assert(c);

        if (!runtime_prefix)
                return 0;

        STRV_FOREACH(i, c->runtime_directory) {
                _cleanup_free_ char *p;

                p = strjoin(runtime_prefix, "/", *i);
                if (!p)
                        return -ENOMEM;

                /* We execute this synchronously, since we need to be
                 * sure this is gone when we start the service
                 * next. */
                (void) rm_rf(p, REMOVE_ROOT);
        }

        return 0;
}

void exec_command_done(ExecCommand *c) {
        assert(c);

        c->path = mfree(c->path);

        c->argv = strv_free(c->argv);
}

void exec_command_done_array(ExecCommand *c, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++)
                exec_command_done(c+i);
}

ExecCommand* exec_command_free_list(ExecCommand *c) {
        ExecCommand *i;

        while ((i = c)) {
                LIST_REMOVE(command, c, i);
                exec_command_done(i);
                free(i);
        }

        return NULL;
}

void exec_command_free_array(ExecCommand **c, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++)
                c[i] = exec_command_free_list(c[i]);
}

typedef struct InvalidEnvInfo {
        Unit *unit;
        const char *path;
} InvalidEnvInfo;

static void invalid_env(const char *p, void *userdata) {
        InvalidEnvInfo *info = userdata;

        log_unit_error(info->unit, "Ignoring invalid environment assignment '%s': %s", p, info->path);
}

const char* exec_context_fdname(const ExecContext *c, int fd_index) {
        assert(c);

        switch (fd_index) {
        case STDIN_FILENO:
                if (c->std_input != EXEC_INPUT_NAMED_FD)
                        return NULL;
                return c->stdio_fdname[STDIN_FILENO] ?: "stdin";
        case STDOUT_FILENO:
                if (c->std_output != EXEC_OUTPUT_NAMED_FD)
                        return NULL;
                return c->stdio_fdname[STDOUT_FILENO] ?: "stdout";
        case STDERR_FILENO:
                if (c->std_error != EXEC_OUTPUT_NAMED_FD)
                        return NULL;
                return c->stdio_fdname[STDERR_FILENO] ?: "stderr";
        default:
                return NULL;
        }
}

int exec_context_named_iofds(Unit *unit, const ExecContext *c, const ExecParameters *p, int named_iofds[3]) {
        unsigned i, targets;
        const char* stdio_fdname[3];
        unsigned n_fds;

        assert(c);
        assert(p);

        targets = (c->std_input == EXEC_INPUT_NAMED_FD) +
                  (c->std_output == EXEC_OUTPUT_NAMED_FD) +
                  (c->std_error == EXEC_OUTPUT_NAMED_FD);

        for (i = 0; i < 3; i++)
                stdio_fdname[i] = exec_context_fdname(c, i);

        n_fds = p->n_storage_fds + p->n_socket_fds;

        for (i = 0; i < n_fds  && targets > 0; i++)
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

int exec_context_load_environment(Unit *unit, const ExecContext *c, char ***l) {
        char **i, **r = NULL;

        assert(c);
        assert(l);

        STRV_FOREACH(i, c->environment_files) {
                char *fn;
                int k;
                unsigned n;
                bool ignore = false;
                char **p;
                _cleanup_globfree_ glob_t pglob = {};

                fn = *i;

                if (fn[0] == '-') {
                        ignore = true;
                        fn++;
                }

                if (!path_is_absolute(fn)) {
                        if (ignore)
                                continue;

                        strv_free(r);
                        return -EINVAL;
                }

                /* Filename supports globbing, take all matching files */
                k = safe_glob(fn, 0, &pglob);
                if (k < 0) {
                        if (ignore)
                                continue;

                        strv_free(r);
                        return k;
                }

                /* When we don't match anything, -ENOENT should be returned */
                assert(pglob.gl_pathc > 0);

                for (n = 0; n < pglob.gl_pathc; n++) {
                        k = load_env_file(NULL, pglob.gl_pathv[n], NULL, &p);
                        if (k < 0) {
                                if (ignore)
                                        continue;

                                strv_free(r);
                                return k;
                        }
                        /* Log invalid environment variables with filename */
                        if (p) {
                                InvalidEnvInfo info = {
                                        .unit = unit,
                                        .path = pglob.gl_pathv[n]
                                };

                                p = strv_env_clean_with_callback(p, invalid_env, &info);
                        }

                        if (r == NULL)
                                r = p;
                        else {
                                char **m;

                                m = strv_env_merge(2, r, p);
                                strv_free(r);
                                strv_free(p);
                                if (!m)
                                        return -ENOMEM;

                                r = m;
                        }
                }
        }

        *l = r;

        return 0;
}

static bool tty_may_match_dev_console(const char *tty) {
        _cleanup_free_ char *active = NULL;
        char *console;

        if (!tty)
                return true;

        if (startswith(tty, "/dev/"))
                tty += 5;

        /* trivial identity? */
        if (streq(tty, "console"))
                return true;

        console = resolve_dev_console(&active);
        /* if we could not resolve, assume it may */
        if (!console)
                return true;

        /* "tty0" means the active VC, so it may be the same sometimes */
        return streq(console, tty) || (streq(console, "tty0") && tty_is_vc(tty));
}

bool exec_context_may_touch_console(ExecContext *ec) {

        return (ec->tty_reset ||
                ec->tty_vhangup ||
                ec->tty_vt_disallocate ||
                is_terminal_input(ec->std_input) ||
                is_terminal_output(ec->std_output) ||
                is_terminal_output(ec->std_error)) &&
               tty_may_match_dev_console(exec_context_tty_path(ec));
}

static void strv_fprintf(FILE *f, char **l) {
        char **g;

        assert(f);

        STRV_FOREACH(g, l)
                fprintf(f, " %s", *g);
}

void exec_context_dump(ExecContext *c, FILE* f, const char *prefix) {
        char **e, **d;
        unsigned i;
        int r;

        assert(c);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%sUMask: %04o\n"
                "%sWorkingDirectory: %s\n"
                "%sRootDirectory: %s\n"
                "%sNonBlocking: %s\n"
                "%sPrivateTmp: %s\n"
                "%sPrivateDevices: %s\n"
                "%sProtectKernelTunables: %s\n"
                "%sProtectKernelModules: %s\n"
                "%sProtectControlGroups: %s\n"
                "%sPrivateNetwork: %s\n"
                "%sPrivateUsers: %s\n"
                "%sProtectHome: %s\n"
                "%sProtectSystem: %s\n"
                "%sMountAPIVFS: %s\n"
                "%sIgnoreSIGPIPE: %s\n"
                "%sMemoryDenyWriteExecute: %s\n"
                "%sRestrictRealtime: %s\n",
                prefix, c->umask,
                prefix, c->working_directory ? c->working_directory : "/",
                prefix, c->root_directory ? c->root_directory : "/",
                prefix, yes_no(c->non_blocking),
                prefix, yes_no(c->private_tmp),
                prefix, yes_no(c->private_devices),
                prefix, yes_no(c->protect_kernel_tunables),
                prefix, yes_no(c->protect_kernel_modules),
                prefix, yes_no(c->protect_control_groups),
                prefix, yes_no(c->private_network),
                prefix, yes_no(c->private_users),
                prefix, protect_home_to_string(c->protect_home),
                prefix, protect_system_to_string(c->protect_system),
                prefix, yes_no(c->mount_apivfs),
                prefix, yes_no(c->ignore_sigpipe),
                prefix, yes_no(c->memory_deny_write_execute),
                prefix, yes_no(c->restrict_realtime));

        if (c->root_image)
                fprintf(f, "%sRootImage: %s\n", prefix, c->root_image);

        STRV_FOREACH(e, c->environment)
                fprintf(f, "%sEnvironment: %s\n", prefix, *e);

        STRV_FOREACH(e, c->environment_files)
                fprintf(f, "%sEnvironmentFile: %s\n", prefix, *e);

        STRV_FOREACH(e, c->pass_environment)
                fprintf(f, "%sPassEnvironment: %s\n", prefix, *e);

        fprintf(f, "%sRuntimeDirectoryMode: %04o\n", prefix, c->runtime_directory_mode);

        STRV_FOREACH(d, c->runtime_directory)
                fprintf(f, "%sRuntimeDirectory: %s\n", prefix, *d);

        if (c->nice_set)
                fprintf(f,
                        "%sNice: %i\n",
                        prefix, c->nice);

        if (c->oom_score_adjust_set)
                fprintf(f,
                        "%sOOMScoreAdjust: %i\n",
                        prefix, c->oom_score_adjust);

        for (i = 0; i < RLIM_NLIMITS; i++)
                if (c->rlimit[i]) {
                        fprintf(f, "%s%s: " RLIM_FMT "\n",
                                prefix, rlimit_to_string(i), c->rlimit[i]->rlim_max);
                        fprintf(f, "%s%sSoft: " RLIM_FMT "\n",
                                prefix, rlimit_to_string(i), c->rlimit[i]->rlim_cur);
                }

        if (c->ioprio_set) {
                _cleanup_free_ char *class_str = NULL;

                ioprio_class_to_string_alloc(IOPRIO_PRIO_CLASS(c->ioprio), &class_str);
                fprintf(f,
                        "%sIOSchedulingClass: %s\n"
                        "%sIOPriority: %i\n",
                        prefix, strna(class_str),
                        prefix, (int) IOPRIO_PRIO_DATA(c->ioprio));
        }

        if (c->cpu_sched_set) {
                _cleanup_free_ char *policy_str = NULL;

                sched_policy_to_string_alloc(c->cpu_sched_policy, &policy_str);
                fprintf(f,
                        "%sCPUSchedulingPolicy: %s\n"
                        "%sCPUSchedulingPriority: %i\n"
                        "%sCPUSchedulingResetOnFork: %s\n",
                        prefix, strna(policy_str),
                        prefix, c->cpu_sched_priority,
                        prefix, yes_no(c->cpu_sched_reset_on_fork));
        }

        if (c->cpuset) {
                fprintf(f, "%sCPUAffinity:", prefix);
                for (i = 0; i < c->cpuset_ncpus; i++)
                        if (CPU_ISSET_S(i, CPU_ALLOC_SIZE(c->cpuset_ncpus), c->cpuset))
                                fprintf(f, " %u", i);
                fputs("\n", f);
        }

        if (c->timer_slack_nsec != NSEC_INFINITY)
                fprintf(f, "%sTimerSlackNSec: "NSEC_FMT "\n", prefix, c->timer_slack_nsec);

        fprintf(f,
                "%sStandardInput: %s\n"
                "%sStandardOutput: %s\n"
                "%sStandardError: %s\n",
                prefix, exec_input_to_string(c->std_input),
                prefix, exec_output_to_string(c->std_output),
                prefix, exec_output_to_string(c->std_error));

        if (c->tty_path)
                fprintf(f,
                        "%sTTYPath: %s\n"
                        "%sTTYReset: %s\n"
                        "%sTTYVHangup: %s\n"
                        "%sTTYVTDisallocate: %s\n",
                        prefix, c->tty_path,
                        prefix, yes_no(c->tty_reset),
                        prefix, yes_no(c->tty_vhangup),
                        prefix, yes_no(c->tty_vt_disallocate));

        if (c->std_output == EXEC_OUTPUT_SYSLOG ||
            c->std_output == EXEC_OUTPUT_KMSG ||
            c->std_output == EXEC_OUTPUT_JOURNAL ||
            c->std_output == EXEC_OUTPUT_SYSLOG_AND_CONSOLE ||
            c->std_output == EXEC_OUTPUT_KMSG_AND_CONSOLE ||
            c->std_output == EXEC_OUTPUT_JOURNAL_AND_CONSOLE ||
            c->std_error == EXEC_OUTPUT_SYSLOG ||
            c->std_error == EXEC_OUTPUT_KMSG ||
            c->std_error == EXEC_OUTPUT_JOURNAL ||
            c->std_error == EXEC_OUTPUT_SYSLOG_AND_CONSOLE ||
            c->std_error == EXEC_OUTPUT_KMSG_AND_CONSOLE ||
            c->std_error == EXEC_OUTPUT_JOURNAL_AND_CONSOLE) {

                _cleanup_free_ char *fac_str = NULL, *lvl_str = NULL;

                log_facility_unshifted_to_string_alloc(c->syslog_priority >> 3, &fac_str);
                log_level_to_string_alloc(LOG_PRI(c->syslog_priority), &lvl_str);

                fprintf(f,
                        "%sSyslogFacility: %s\n"
                        "%sSyslogLevel: %s\n",
                        prefix, strna(fac_str),
                        prefix, strna(lvl_str));
        }

        if (c->secure_bits)
                fprintf(f, "%sSecure Bits:%s%s%s%s%s%s\n",
                        prefix,
                        (c->secure_bits & 1<<SECURE_KEEP_CAPS) ? " keep-caps" : "",
                        (c->secure_bits & 1<<SECURE_KEEP_CAPS_LOCKED) ? " keep-caps-locked" : "",
                        (c->secure_bits & 1<<SECURE_NO_SETUID_FIXUP) ? " no-setuid-fixup" : "",
                        (c->secure_bits & 1<<SECURE_NO_SETUID_FIXUP_LOCKED) ? " no-setuid-fixup-locked" : "",
                        (c->secure_bits & 1<<SECURE_NOROOT) ? " noroot" : "",
                        (c->secure_bits & 1<<SECURE_NOROOT_LOCKED) ? "noroot-locked" : "");

        if (c->capability_bounding_set != CAP_ALL) {
                unsigned long l;
                fprintf(f, "%sCapabilityBoundingSet:", prefix);

                for (l = 0; l <= cap_last_cap(); l++)
                        if (c->capability_bounding_set & (UINT64_C(1) << l))
                                fprintf(f, " %s", strna(capability_to_name(l)));

                fputs("\n", f);
        }

        if (c->capability_ambient_set != 0) {
                unsigned long l;
                fprintf(f, "%sAmbientCapabilities:", prefix);

                for (l = 0; l <= cap_last_cap(); l++)
                        if (c->capability_ambient_set & (UINT64_C(1) << l))
                                fprintf(f, " %s", strna(capability_to_name(l)));

                fputs("\n", f);
        }

        if (c->user)
                fprintf(f, "%sUser: %s\n", prefix, c->user);
        if (c->group)
                fprintf(f, "%sGroup: %s\n", prefix, c->group);

        fprintf(f, "%sDynamicUser: %s\n", prefix, yes_no(c->dynamic_user));

        if (strv_length(c->supplementary_groups) > 0) {
                fprintf(f, "%sSupplementaryGroups:", prefix);
                strv_fprintf(f, c->supplementary_groups);
                fputs("\n", f);
        }

        if (c->pam_name)
                fprintf(f, "%sPAMName: %s\n", prefix, c->pam_name);

        if (strv_length(c->read_write_paths) > 0) {
                fprintf(f, "%sReadWritePaths:", prefix);
                strv_fprintf(f, c->read_write_paths);
                fputs("\n", f);
        }

        if (strv_length(c->read_only_paths) > 0) {
                fprintf(f, "%sReadOnlyPaths:", prefix);
                strv_fprintf(f, c->read_only_paths);
                fputs("\n", f);
        }

        if (strv_length(c->inaccessible_paths) > 0) {
                fprintf(f, "%sInaccessiblePaths:", prefix);
                strv_fprintf(f, c->inaccessible_paths);
                fputs("\n", f);
        }

        if (c->n_bind_mounts > 0)
                for (i = 0; i < c->n_bind_mounts; i++) {
                        fprintf(f, "%s%s: %s:%s:%s\n", prefix,
                                c->bind_mounts[i].read_only ? "BindReadOnlyPaths" : "BindPaths",
                                c->bind_mounts[i].source,
                                c->bind_mounts[i].destination,
                                c->bind_mounts[i].recursive ? "rbind" : "norbind");
                }

        if (c->utmp_id)
                fprintf(f,
                        "%sUtmpIdentifier: %s\n",
                        prefix, c->utmp_id);

        if (c->selinux_context)
                fprintf(f,
                        "%sSELinuxContext: %s%s\n",
                        prefix, c->selinux_context_ignore ? "-" : "", c->selinux_context);

        if (c->personality != PERSONALITY_INVALID)
                fprintf(f,
                        "%sPersonality: %s\n",
                        prefix, strna(personality_to_string(c->personality)));

        if (c->syscall_filter) {
#ifdef HAVE_SECCOMP
                Iterator j;
                void *id;
                bool first = true;
#endif

                fprintf(f,
                        "%sSystemCallFilter: ",
                        prefix);

                if (!c->syscall_whitelist)
                        fputc('~', f);

#ifdef HAVE_SECCOMP
                SET_FOREACH(id, c->syscall_filter, j) {
                        _cleanup_free_ char *name = NULL;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                        fputs(strna(name), f);
                }
#endif

                fputc('\n', f);
        }

        if (c->syscall_archs) {
#ifdef HAVE_SECCOMP
                Iterator j;
                void *id;
#endif

                fprintf(f,
                        "%sSystemCallArchitectures:",
                        prefix);

#ifdef HAVE_SECCOMP
                SET_FOREACH(id, c->syscall_archs, j)
                        fprintf(f, " %s", strna(seccomp_arch_to_string(PTR_TO_UINT32(id) - 1)));
#endif
                fputc('\n', f);
        }

        if (exec_context_restrict_namespaces_set(c)) {
                _cleanup_free_ char *s = NULL;

                r = namespace_flag_to_string_many(c->restrict_namespaces, &s);
                if (r >= 0)
                        fprintf(f, "%sRestrictNamespaces: %s\n",
                                prefix, s);
        }

        if (c->syscall_errno > 0)
                fprintf(f,
                        "%sSystemCallErrorNumber: %s\n",
                        prefix, strna(errno_to_name(c->syscall_errno)));

        if (c->apparmor_profile)
                fprintf(f,
                        "%sAppArmorProfile: %s%s\n",
                        prefix, c->apparmor_profile_ignore ? "-" : "", c->apparmor_profile);
}

bool exec_context_maintains_privileges(ExecContext *c) {
        assert(c);

        /* Returns true if the process forked off would run under
         * an unchanged UID or as root. */

        if (!c->user)
                return true;

        if (streq(c->user, "root") || streq(c->user, "0"))
                return true;

        return false;
}

int exec_context_get_effective_ioprio(ExecContext *c) {
        int p;

        assert(c);

        if (c->ioprio_set)
                return c->ioprio;

        p = ioprio_get(IOPRIO_WHO_PROCESS, 0);
        if (p < 0)
                return IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4);

        return p;
}

void exec_status_start(ExecStatus *s, pid_t pid) {
        assert(s);

        zero(*s);
        s->pid = pid;
        dual_timestamp_get(&s->start_timestamp);
}

void exec_status_exit(ExecStatus *s, ExecContext *context, pid_t pid, int code, int status) {
        assert(s);

        if (s->pid && s->pid != pid)
                zero(*s);

        s->pid = pid;
        dual_timestamp_get(&s->exit_timestamp);

        s->code = code;
        s->status = status;

        if (context) {
                if (context->utmp_id)
                        utmp_put_dead_process(context->utmp_id, pid, code, status);

                exec_context_tty_reset(context, NULL);
        }
}

void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix) {
        char buf[FORMAT_TIMESTAMP_MAX];

        assert(s);
        assert(f);

        if (s->pid <= 0)
                return;

        prefix = strempty(prefix);

        fprintf(f,
                "%sPID: "PID_FMT"\n",
                prefix, s->pid);

        if (dual_timestamp_is_set(&s->start_timestamp))
                fprintf(f,
                        "%sStart Timestamp: %s\n",
                        prefix, format_timestamp(buf, sizeof(buf), s->start_timestamp.realtime));

        if (dual_timestamp_is_set(&s->exit_timestamp))
                fprintf(f,
                        "%sExit Timestamp: %s\n"
                        "%sExit Code: %s\n"
                        "%sExit Status: %i\n",
                        prefix, format_timestamp(buf, sizeof(buf), s->exit_timestamp.realtime),
                        prefix, sigchld_code_to_string(s->code),
                        prefix, s->status);
}

char *exec_command_line(char **argv) {
        size_t k;
        char *n, *p, **a;
        bool first = true;

        assert(argv);

        k = 1;
        STRV_FOREACH(a, argv)
                k += strlen(*a)+3;

        n = new(char, k);
        if (!n)
                return NULL;

        p = n;
        STRV_FOREACH(a, argv) {

                if (!first)
                        *(p++) = ' ';
                else
                        first = false;

                if (strpbrk(*a, WHITESPACE)) {
                        *(p++) = '\'';
                        p = stpcpy(p, *a);
                        *(p++) = '\'';
                } else
                        p = stpcpy(p, *a);

        }

        *p = 0;

        /* FIXME: this doesn't really handle arguments that have
         * spaces and ticks in them */

        return n;
}

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix) {
        _cleanup_free_ char *cmd = NULL;
        const char *prefix2;

        assert(c);
        assert(f);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        cmd = exec_command_line(c->argv);
        fprintf(f,
                "%sCommand Line: %s\n",
                prefix, cmd ? cmd : strerror(ENOMEM));

        exec_status_dump(&c->exec_status, f, prefix2);
}

void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix) {
        assert(f);

        prefix = strempty(prefix);

        LIST_FOREACH(command, c, c)
                exec_command_dump(c, f, prefix);
}

void exec_command_append_list(ExecCommand **l, ExecCommand *e) {
        ExecCommand *end;

        assert(l);
        assert(e);

        if (*l) {
                /* It's kind of important, that we keep the order here */
                LIST_FIND_TAIL(command, *l, end);
                LIST_INSERT_AFTER(command, *l, end, e);
        } else
              *l = e;
}

int exec_command_set(ExecCommand *c, const char *path, ...) {
        va_list ap;
        char **l, *p;

        assert(c);
        assert(path);

        va_start(ap, path);
        l = strv_new_ap(path, ap);
        va_end(ap);

        if (!l)
                return -ENOMEM;

        p = strdup(path);
        if (!p) {
                strv_free(l);
                return -ENOMEM;
        }

        free(c->path);
        c->path = p;

        strv_free(c->argv);
        c->argv = l;

        return 0;
}

int exec_command_append(ExecCommand *c, const char *path, ...) {
        _cleanup_strv_free_ char **l = NULL;
        va_list ap;
        int r;

        assert(c);
        assert(path);

        va_start(ap, path);
        l = strv_new_ap(path, ap);
        va_end(ap);

        if (!l)
                return -ENOMEM;

        r = strv_extend_strv(&c->argv, l, false);
        if (r < 0)
                return r;

        return 0;
}


static int exec_runtime_allocate(ExecRuntime **rt) {

        if (*rt)
                return 0;

        *rt = new0(ExecRuntime, 1);
        if (!*rt)
                return -ENOMEM;

        (*rt)->n_ref = 1;
        (*rt)->netns_storage_socket[0] = (*rt)->netns_storage_socket[1] = -1;

        return 0;
}

int exec_runtime_make(ExecRuntime **rt, ExecContext *c, const char *id) {
        int r;

        assert(rt);
        assert(c);
        assert(id);

        if (*rt)
                return 1;

        if (!c->private_network && !c->private_tmp)
                return 0;

        r = exec_runtime_allocate(rt);
        if (r < 0)
                return r;

        if (c->private_network && (*rt)->netns_storage_socket[0] < 0) {
                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, (*rt)->netns_storage_socket) < 0)
                        return -errno;
        }

        if (c->private_tmp && !(*rt)->tmp_dir) {
                r = setup_tmp_dirs(id, &(*rt)->tmp_dir, &(*rt)->var_tmp_dir);
                if (r < 0)
                        return r;
        }

        return 1;
}

ExecRuntime *exec_runtime_ref(ExecRuntime *r) {
        assert(r);
        assert(r->n_ref > 0);

        r->n_ref++;
        return r;
}

ExecRuntime *exec_runtime_unref(ExecRuntime *r) {

        if (!r)
                return NULL;

        assert(r->n_ref > 0);

        r->n_ref--;
        if (r->n_ref > 0)
                return NULL;

        free(r->tmp_dir);
        free(r->var_tmp_dir);
        safe_close_pair(r->netns_storage_socket);
        return mfree(r);
}

int exec_runtime_serialize(Unit *u, ExecRuntime *rt, FILE *f, FDSet *fds) {
        assert(u);
        assert(f);
        assert(fds);

        if (!rt)
                return 0;

        if (rt->tmp_dir)
                unit_serialize_item(u, f, "tmp-dir", rt->tmp_dir);

        if (rt->var_tmp_dir)
                unit_serialize_item(u, f, "var-tmp-dir", rt->var_tmp_dir);

        if (rt->netns_storage_socket[0] >= 0) {
                int copy;

                copy = fdset_put_dup(fds, rt->netns_storage_socket[0]);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "netns-socket-0", "%i", copy);
        }

        if (rt->netns_storage_socket[1] >= 0) {
                int copy;

                copy = fdset_put_dup(fds, rt->netns_storage_socket[1]);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "netns-socket-1", "%i", copy);
        }

        return 0;
}

int exec_runtime_deserialize_item(Unit *u, ExecRuntime **rt, const char *key, const char *value, FDSet *fds) {
        int r;

        assert(rt);
        assert(key);
        assert(value);

        if (streq(key, "tmp-dir")) {
                char *copy;

                r = exec_runtime_allocate(rt);
                if (r < 0)
                        return log_oom();

                copy = strdup(value);
                if (!copy)
                        return log_oom();

                free((*rt)->tmp_dir);
                (*rt)->tmp_dir = copy;

        } else if (streq(key, "var-tmp-dir")) {
                char *copy;

                r = exec_runtime_allocate(rt);
                if (r < 0)
                        return log_oom();

                copy = strdup(value);
                if (!copy)
                        return log_oom();

                free((*rt)->var_tmp_dir);
                (*rt)->var_tmp_dir = copy;

        } else if (streq(key, "netns-socket-0")) {
                int fd;

                r = exec_runtime_allocate(rt);
                if (r < 0)
                        return log_oom();

                if (safe_atoi(value, &fd) < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse netns socket value: %s", value);
                else {
                        safe_close((*rt)->netns_storage_socket[0]);
                        (*rt)->netns_storage_socket[0] = fdset_remove(fds, fd);
                }
        } else if (streq(key, "netns-socket-1")) {
                int fd;

                r = exec_runtime_allocate(rt);
                if (r < 0)
                        return log_oom();

                if (safe_atoi(value, &fd) < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse netns socket value: %s", value);
                else {
                        safe_close((*rt)->netns_storage_socket[1]);
                        (*rt)->netns_storage_socket[1] = fdset_remove(fds, fd);
                }
        } else
                return 0;

        return 1;
}

static void *remove_tmpdir_thread(void *p) {
        _cleanup_free_ char *path = p;

        (void) rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
        return NULL;
}

void exec_runtime_destroy(ExecRuntime *rt) {
        int r;

        if (!rt)
                return;

        /* If there are multiple users of this, let's leave the stuff around */
        if (rt->n_ref > 1)
                return;

        if (rt->tmp_dir) {
                log_debug("Spawning thread to nuke %s", rt->tmp_dir);

                r = asynchronous_job(remove_tmpdir_thread, rt->tmp_dir);
                if (r < 0) {
                        log_warning_errno(r, "Failed to nuke %s: %m", rt->tmp_dir);
                        free(rt->tmp_dir);
                }

                rt->tmp_dir = NULL;
        }

        if (rt->var_tmp_dir) {
                log_debug("Spawning thread to nuke %s", rt->var_tmp_dir);

                r = asynchronous_job(remove_tmpdir_thread, rt->var_tmp_dir);
                if (r < 0) {
                        log_warning_errno(r, "Failed to nuke %s: %m", rt->var_tmp_dir);
                        free(rt->var_tmp_dir);
                }

                rt->var_tmp_dir = NULL;
        }

        safe_close_pair(rt->netns_storage_socket);
}

static const char* const exec_input_table[_EXEC_INPUT_MAX] = {
        [EXEC_INPUT_NULL] = "null",
        [EXEC_INPUT_TTY] = "tty",
        [EXEC_INPUT_TTY_FORCE] = "tty-force",
        [EXEC_INPUT_TTY_FAIL] = "tty-fail",
        [EXEC_INPUT_SOCKET] = "socket",
        [EXEC_INPUT_NAMED_FD] = "fd",
};

DEFINE_STRING_TABLE_LOOKUP(exec_input, ExecInput);

static const char* const exec_output_table[_EXEC_OUTPUT_MAX] = {
        [EXEC_OUTPUT_INHERIT] = "inherit",
        [EXEC_OUTPUT_NULL] = "null",
        [EXEC_OUTPUT_TTY] = "tty",
        [EXEC_OUTPUT_SYSLOG] = "syslog",
        [EXEC_OUTPUT_SYSLOG_AND_CONSOLE] = "syslog+console",
        [EXEC_OUTPUT_KMSG] = "kmsg",
        [EXEC_OUTPUT_KMSG_AND_CONSOLE] = "kmsg+console",
        [EXEC_OUTPUT_JOURNAL] = "journal",
        [EXEC_OUTPUT_JOURNAL_AND_CONSOLE] = "journal+console",
        [EXEC_OUTPUT_SOCKET] = "socket",
        [EXEC_OUTPUT_NAMED_FD] = "fd",
};

DEFINE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

static const char* const exec_utmp_mode_table[_EXEC_UTMP_MODE_MAX] = {
        [EXEC_UTMP_INIT] = "init",
        [EXEC_UTMP_LOGIN] = "login",
        [EXEC_UTMP_USER] = "user",
};

DEFINE_STRING_TABLE_LOOKUP(exec_utmp_mode, ExecUtmpMode);
