/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "bus-endpoint.h"
#include "cap-list.h"
#include "capability-util.h"
#include "def.h"
#include "env-util.h"
#include "errno-list.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
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

static int flags_fds(const int fds[], unsigned n_fds, bool nonblock) {
        unsigned i;
        int r;

        if (n_fds <= 0)
                return 0;

        assert(fds);

        /* Drops/Sets O_NONBLOCK and FD_CLOEXEC from the file flags */

        for (i = 0; i < n_fds; i++) {

                r = fd_nonblock(fds[i], nonblock);
                if (r < 0)
                        return r;

                /* We unconditionally drop FD_CLOEXEC from the fds,
                 * since after all we want to pass these fds to our
                 * children */

                r = fd_cloexec(fds[i], false);
                if (r < 0)
                        return r;
        }

        return 0;
}

_pure_ static const char *tty_path(const ExecContext *context) {
        assert(context);

        if (context->tty_path)
                return context->tty_path;

        return "/dev/console";
}

static void exec_context_tty_reset(const ExecContext *context) {
        assert(context);

        if (context->tty_vhangup)
                terminal_vhangup(tty_path(context));

        if (context->tty_reset)
                reset_terminal(tty_path(context));

        if (context->tty_vt_disallocate && context->tty_path)
                vt_disallocate(context->tty_path);
}

static bool is_terminal_output(ExecOutput o) {
        return
                o == EXEC_OUTPUT_TTY ||
                o == EXEC_OUTPUT_SYSLOG_AND_CONSOLE ||
                o == EXEC_OUTPUT_KMSG_AND_CONSOLE ||
                o == EXEC_OUTPUT_JOURNAL_AND_CONSOLE;
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

        r = connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path));
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

static int connect_logger_as(const ExecContext *context, ExecOutput output, const char *ident, const char *unit_id, int nfd, uid_t uid, gid_t gid) {
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

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        dprintf(fd,
                "%s\n"
                "%s\n"
                "%i\n"
                "%i\n"
                "%i\n"
                "%i\n"
                "%i\n",
                context->syslog_identifier ? context->syslog_identifier : ident,
                unit_id,
                context->syslog_priority,
                !!context->syslog_level_prefix,
                output == EXEC_OUTPUT_SYSLOG || output == EXEC_OUTPUT_SYSLOG_AND_CONSOLE,
                output == EXEC_OUTPUT_KMSG || output == EXEC_OUTPUT_KMSG_AND_CONSOLE,
                is_terminal_output(output));

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                safe_close(fd);
        } else
                r = nfd;

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

static bool is_terminal_input(ExecInput i) {
        return
                i == EXEC_INPUT_TTY ||
                i == EXEC_INPUT_TTY_FORCE ||
                i == EXEC_INPUT_TTY_FAIL;
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
                int socket_fd) {

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

        i = fixup_input(context->std_input, socket_fd, params->apply_tty_stdin);

        switch (i) {

        case EXEC_INPUT_NULL:
                return open_null_as(O_RDONLY, STDIN_FILENO);

        case EXEC_INPUT_TTY:
        case EXEC_INPUT_TTY_FORCE:
        case EXEC_INPUT_TTY_FAIL: {
                int fd, r;

                fd = acquire_terminal(tty_path(context),
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
                const char *ident,
                uid_t uid, gid_t gid) {

        ExecOutput o;
        ExecInput i;
        int r;

        assert(unit);
        assert(context);
        assert(params);
        assert(ident);

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

        i = fixup_input(context->std_input, socket_fd, params->apply_tty_stdin);
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
                if (e == o || e == EXEC_OUTPUT_INHERIT)
                        return dup2(STDOUT_FILENO, fileno) < 0 ? -errno : fileno;

                o = e;

        } else if (o == EXEC_OUTPUT_INHERIT) {
                /* If input got downgraded, inherit the original value */
                if (i == EXEC_INPUT_NULL && is_terminal_input(context->std_input))
                        return open_terminal_as(tty_path(context), O_WRONLY, fileno);

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
                return open_terminal_as(tty_path(context), O_WRONLY, fileno);

        case EXEC_OUTPUT_SYSLOG:
        case EXEC_OUTPUT_SYSLOG_AND_CONSOLE:
        case EXEC_OUTPUT_KMSG:
        case EXEC_OUTPUT_KMSG_AND_CONSOLE:
        case EXEC_OUTPUT_JOURNAL:
        case EXEC_OUTPUT_JOURNAL_AND_CONSOLE:
                r = connect_logger_as(context, o, ident, unit->id, fileno, uid, gid);
                if (r < 0) {
                        log_unit_error_errno(unit, r, "Failed to connect %s to the journal socket, ignoring: %m", fileno == STDOUT_FILENO ? "stdout" : "stderr");
                        r = open_null_as(O_WRONLY, fileno);
                }
                return r;

        case EXEC_OUTPUT_SOCKET:
                assert(socket_fd >= 0);
                return dup2(socket_fd, fileno) < 0 ? -errno : fileno;

        default:
                assert_not_reached("Unknown error type");
        }
}

static int chown_terminal(int fd, uid_t uid) {
        struct stat st;

        assert(fd >= 0);

        /* This might fail. What matters are the results. */
        (void) fchown(fd, uid, -1);
        (void) fchmod(fd, TTY_MODE);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_uid != uid || (st.st_mode & 0777) != TTY_MODE)
                return -EPERM;

        return 0;
}

static int setup_confirm_stdio(int *_saved_stdin, int *_saved_stdout) {
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

        fd = acquire_terminal(
                        "/dev/console",
                        false,
                        false,
                        false,
                        DEFAULT_CONFIRM_USEC);
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

_printf_(1, 2) static int write_confirm_message(const char *format, ...) {
        _cleanup_close_ int fd = -1;
        va_list ap;

        assert(format);

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        va_start(ap, format);
        vdprintf(fd, format, ap);
        va_end(ap);

        return 0;
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

static int ask_for_confirmation(char *response, char **argv) {
        int saved_stdout = -1, saved_stdin = -1, r;
        _cleanup_free_ char *line = NULL;

        r = setup_confirm_stdio(&saved_stdin, &saved_stdout);
        if (r < 0)
                return r;

        line = exec_command_line(argv);
        if (!line)
                return -ENOMEM;

        r = ask_char(response, "yns", "Execute %s? [Yes, No, Skip] ", line);

        restore_confirm_stdio(&saved_stdin, &saved_stdout);

        return r;
}

static int enforce_groups(const ExecContext *context, const char *username, gid_t gid) {
        bool keep_groups = false;
        int r;

        assert(context);

        /* Lookup and set GID and supplementary group list. Here too
         * we avoid NSS lookups for gid=0. */

        if (context->group || username) {
                /* First step, initialize groups from /etc/groups */
                if (username && gid != 0) {
                        if (initgroups(username, gid) < 0)
                                return -errno;

                        keep_groups = true;
                }

                /* Second step, set our gids */
                if (setresgid(gid, gid, gid) < 0)
                        return -errno;
        }

        if (context->supplementary_groups) {
                int ngroups_max, k;
                gid_t *gids;
                char **i;

                /* Final step, initialize any manually set supplementary groups */
                assert_se((ngroups_max = (int) sysconf(_SC_NGROUPS_MAX)) > 0);

                if (!(gids = new(gid_t, ngroups_max)))
                        return -ENOMEM;

                if (keep_groups) {
                        k = getgroups(ngroups_max, gids);
                        if (k < 0) {
                                free(gids);
                                return -errno;
                        }
                } else
                        k = 0;

                STRV_FOREACH(i, context->supplementary_groups) {
                        const char *g;

                        if (k >= ngroups_max) {
                                free(gids);
                                return -E2BIG;
                        }

                        g = *i;
                        r = get_group_creds(&g, gids+k);
                        if (r < 0) {
                                free(gids);
                                return r;
                        }

                        k++;
                }

                if (setgroups(k, gids) < 0) {
                        free(gids);
                        return -errno;
                }

                free(gids);
        }

        return 0;
}

static int enforce_user(const ExecContext *context, uid_t uid) {
        assert(context);

        /* Sets (but doesn't lookup) the uid and make sure we keep the
         * capabilities while doing so. */

        if (context->capabilities) {
                _cleanup_cap_free_ cap_t d = NULL;
                static const cap_value_t bits[] = {
                        CAP_SETUID,   /* Necessary so that we can run setresuid() below */
                        CAP_SETPCAP   /* Necessary so that we can set PR_SET_SECUREBITS later on */
                };

                /* First step: If we need to keep capabilities but
                 * drop privileges we need to make sure we keep our
                 * caps, while we drop privileges. */
                if (uid != 0) {
                        int sb = context->secure_bits | 1<<SECURE_KEEP_CAPS;

                        if (prctl(PR_GET_SECUREBITS) != sb)
                                if (prctl(PR_SET_SECUREBITS, sb) < 0)
                                        return -errno;
                }

                /* Second step: set the capabilities. This will reduce
                 * the capabilities to the minimum we need. */

                d = cap_dup(context->capabilities);
                if (!d)
                        return -errno;

                if (cap_set_flag(d, CAP_EFFECTIVE, ELEMENTSOF(bits), bits, CAP_SET) < 0 ||
                    cap_set_flag(d, CAP_PERMITTED, ELEMENTSOF(bits), bits, CAP_SET) < 0)
                        return -errno;

                if (cap_set_proc(d) < 0)
                        return -errno;
        }

        /* Third step: actually set the uids */
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

static int setup_pam(
                const char *name,
                const char *user,
                uid_t uid,
                const char *tty,
                char ***pam_env,
                int fds[], unsigned n_fds) {

        static const struct pam_conv conv = {
                .conv = null_conv,
                .appdata_ptr = NULL
        };

        _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
        pam_handle_t *handle = NULL;
        sigset_t old_ss;
        int pam_code = PAM_SUCCESS;
        int err = 0;
        char **e = NULL;
        bool close_session = false;
        pid_t pam_pid = 0, parent_pid;
        int flags = 0;

        assert(name);
        assert(user);
        assert(pam_env);

        /* We set up PAM in the parent process, then fork. The child
         * will then stay around until killed via PR_GET_PDEATHSIG or
         * systemd via the cgroup logic. It will then remove the PAM
         * session again. The parent process will exec() the actual
         * daemon. We do things this way to ensure that the main PID
         * of the daemon is the one we initially fork()ed. */

        err = barrier_create(&barrier);
        if (err < 0)
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
        if (pam_pid < 0)
                goto fail;

        if (pam_pid == 0) {
                int sig;
                int r = EXIT_PAM;

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
                if (setresuid(uid, uid, uid) < 0)
                        log_error_errno(r, "Error: Failed to setresuid() in sd-pam: %m");

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
                 * setup might race against our setresuid(2) call. */
                barrier_place(&barrier);

                /* Check if our parent process might already have
                 * died? */
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

                r = 0;

        child_finish:
                pam_end(handle, pam_code | flags);
                _exit(r);
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

        *pam_env = e;
        e = NULL;

        return 0;

fail:
        if (pam_code != PAM_SUCCESS) {
                log_error("PAM failed: %s", pam_strerror(handle, pam_code));
                err = -EPERM;  /* PAM errors do not map to errno */
        } else {
                err = log_error_errno(err < 0 ? err : errno, "PAM failed: %m");
        }

        if (handle) {
                if (close_session)
                        pam_code = pam_close_session(handle, flags);

                pam_end(handle, pam_code | flags);
        }

        strv_free(e);

        closelog();

        if (pam_pid > 1) {
                kill(pam_pid, SIGTERM);
                kill(pam_pid, SIGCONT);
        }

        return err;
}
#endif

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

#ifdef HAVE_SECCOMP

static int apply_seccomp(const ExecContext *c) {
        uint32_t negative_action, action;
        scmp_filter_ctx *seccomp;
        Iterator i;
        void *id;
        int r;

        assert(c);

        negative_action = c->syscall_errno == 0 ? SCMP_ACT_KILL : SCMP_ACT_ERRNO(c->syscall_errno);

        seccomp = seccomp_init(c->syscall_whitelist ? negative_action : SCMP_ACT_ALLOW);
        if (!seccomp)
                return -ENOMEM;

        if (c->syscall_archs) {

                SET_FOREACH(id, c->syscall_archs, i) {
                        r = seccomp_arch_add(seccomp, PTR_TO_UINT32(id) - 1);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                goto finish;
                }

        } else {
                r = seccomp_add_secondary_archs(seccomp);
                if (r < 0)
                        goto finish;
        }

        action = c->syscall_whitelist ? SCMP_ACT_ALLOW : negative_action;
        SET_FOREACH(id, c->syscall_filter, i) {
                r = seccomp_rule_add(seccomp, action, PTR_TO_INT(id) - 1, 0);
                if (r < 0)
                        goto finish;
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0)
                goto finish;

        r = seccomp_load(seccomp);

finish:
        seccomp_release(seccomp);
        return r;
}

static int apply_address_families(const ExecContext *c) {
        scmp_filter_ctx *seccomp;
        Iterator i;
        int r;

        assert(c);

        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return -ENOMEM;

        r = seccomp_add_secondary_archs(seccomp);
        if (r < 0)
                goto finish;

        if (c->address_families_whitelist) {
                int af, first = 0, last = 0;
                void *afp;

                /* If this is a whitelist, we first block the address
                 * families that are out of range and then everything
                 * that is not in the set. First, we find the lowest
                 * and highest address family in the set. */

                SET_FOREACH(afp, c->address_families, i) {
                        af = PTR_TO_INT(afp);

                        if (af <= 0 || af >= af_max())
                                continue;

                        if (first == 0 || af < first)
                                first = af;

                        if (last == 0 || af > last)
                                last = af;
                }

                assert((first == 0) == (last == 0));

                if (first == 0) {

                        /* No entries in the valid range, block everything */
                        r = seccomp_rule_add(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPROTONOSUPPORT),
                                        SCMP_SYS(socket),
                                        0);
                        if (r < 0)
                                goto finish;

                } else {

                        /* Block everything below the first entry */
                        r = seccomp_rule_add(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPROTONOSUPPORT),
                                        SCMP_SYS(socket),
                                        1,
                                        SCMP_A0(SCMP_CMP_LT, first));
                        if (r < 0)
                                goto finish;

                        /* Block everything above the last entry */
                        r = seccomp_rule_add(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPROTONOSUPPORT),
                                        SCMP_SYS(socket),
                                        1,
                                        SCMP_A0(SCMP_CMP_GT, last));
                        if (r < 0)
                                goto finish;

                        /* Block everything between the first and last
                         * entry */
                        for (af = 1; af < af_max(); af++) {

                                if (set_contains(c->address_families, INT_TO_PTR(af)))
                                        continue;

                                r = seccomp_rule_add(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EPROTONOSUPPORT),
                                                SCMP_SYS(socket),
                                                1,
                                                SCMP_A0(SCMP_CMP_EQ, af));
                                if (r < 0)
                                        goto finish;
                        }
                }

        } else {
                void *af;

                /* If this is a blacklist, then generate one rule for
                 * each address family that are then combined in OR
                 * checks. */

                SET_FOREACH(af, c->address_families, i) {

                        r = seccomp_rule_add(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPROTONOSUPPORT),
                                        SCMP_SYS(socket),
                                        1,
                                        SCMP_A0(SCMP_CMP_EQ, PTR_TO_INT(af)));
                        if (r < 0)
                                goto finish;
                }
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0)
                goto finish;

        r = seccomp_load(seccomp);

finish:
        seccomp_release(seccomp);
        return r;
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
                const ExecContext *c,
                unsigned n_fds,
                char ** fd_names,
                usec_t watchdog_usec,
                const char *home,
                const char *username,
                const char *shell,
                char ***ret) {

        _cleanup_strv_free_ char **our_env = NULL;
        unsigned n_env = 0;
        char *x;

        assert(c);
        assert(ret);

        our_env = new0(char*, 11);
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

                joined = strv_join(fd_names, ":");
                if (!joined)
                        return -ENOMEM;

                x = strjoin("LISTEN_FDNAMES=", joined, NULL);
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        if (watchdog_usec > 0) {
                if (asprintf(&x, "WATCHDOG_PID="PID_FMT, getpid()) < 0)
                        return -ENOMEM;
                our_env[n_env++] = x;

                if (asprintf(&x, "WATCHDOG_USEC="USEC_FMT, watchdog_usec) < 0)
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

        if (is_terminal_input(c->std_input) ||
            c->std_output == EXEC_OUTPUT_TTY ||
            c->std_error == EXEC_OUTPUT_TTY ||
            c->tty_path) {

                x = strdup(default_term_for_tty(tty_path(c)));
                if (!x)
                        return -ENOMEM;
                our_env[n_env++] = x;
        }

        our_env[n_env++] = NULL;
        assert(n_env <= 11);

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
                x = strjoin(*i, "=", v, NULL);
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

        if (!strv_isempty(context->read_write_dirs) ||
            !strv_isempty(context->read_only_dirs) ||
            !strv_isempty(context->inaccessible_dirs))
                return true;

        if (context->mount_flags != 0)
                return true;

        if (context->private_tmp && runtime && (runtime->tmp_dir || runtime->var_tmp_dir))
                return true;

        if (params->bus_endpoint_path)
                return true;

        if (context->private_devices ||
            context->protect_system != PROTECT_SYSTEM_NO ||
            context->protect_home != PROTECT_HOME_NO)
                return true;

        return false;
}

static int close_remaining_fds(
                const ExecParameters *params,
                ExecRuntime *runtime,
                int socket_fd,
                int *fds, unsigned n_fds) {

        unsigned n_dont_close = 0;
        int dont_close[n_fds + 7];

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

        if (params->bus_endpoint_fd >= 0)
                dont_close[n_dont_close++] = params->bus_endpoint_fd;

        if (runtime) {
                if (runtime->netns_storage_socket[0] >= 0)
                        dont_close[n_dont_close++] = runtime->netns_storage_socket[0];
                if (runtime->netns_storage_socket[1] >= 0)
                        dont_close[n_dont_close++] = runtime->netns_storage_socket[1];
        }

        return close_all_fds(dont_close, n_dont_close);
}

static int exec_child(
                Unit *unit,
                ExecCommand *command,
                const ExecContext *context,
                const ExecParameters *params,
                ExecRuntime *runtime,
                char **argv,
                int socket_fd,
                int *fds, unsigned n_fds,
                char **files_env,
                int *exit_status) {

        _cleanup_strv_free_ char **our_env = NULL, **pass_env = NULL, **pam_env = NULL, **final_env = NULL, **final_argv = NULL;
        _cleanup_free_ char *mac_selinux_context_net = NULL;
        const char *username = NULL, *home = NULL, *shell = NULL, *wd;
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        int i, r;
        bool needs_mount_namespace;

        assert(unit);
        assert(command);
        assert(context);
        assert(params);
        assert(exit_status);

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
                return r;
        }

        if (params->idle_pipe)
                do_idle_pipe_dance(params->idle_pipe);

        /* Close sockets very early to make sure we don't
         * block init reexecution because it cannot bind its
         * sockets */

        log_forget_fds();

        r = close_remaining_fds(params, runtime, socket_fd, fds, n_fds);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return r;
        }

        if (!context->same_pgrp)
                if (setsid() < 0) {
                        *exit_status = EXIT_SETSID;
                        return -errno;
                }

        exec_context_tty_reset(context);

        if (params->confirm_spawn) {
                char response;

                r = ask_for_confirmation(&response, argv);
                if (r == -ETIMEDOUT)
                        write_confirm_message("Confirmation question timed out, assuming positive response.\n");
                else if (r < 0)
                        write_confirm_message("Couldn't ask confirmation question, assuming positive response: %s\n", strerror(-r));
                else if (response == 's') {
                        write_confirm_message("Skipping execution.\n");
                        *exit_status = EXIT_CONFIRM;
                        return -ECANCELED;
                } else if (response == 'n') {
                        write_confirm_message("Failing execution.\n");
                        *exit_status = 0;
                        return 0;
                }
        }

        if (context->user) {
                username = context->user;
                r = get_user_creds(&username, &uid, &gid, &home, &shell);
                if (r < 0) {
                        *exit_status = EXIT_USER;
                        return r;
                }
        }

        if (context->group) {
                const char *g = context->group;

                r = get_group_creds(&g, &gid);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        return r;
                }
        }


        /* If a socket is connected to STDIN/STDOUT/STDERR, we
         * must sure to drop O_NONBLOCK */
        if (socket_fd >= 0)
                (void) fd_nonblock(socket_fd, false);

        r = setup_input(context, params, socket_fd);
        if (r < 0) {
                *exit_status = EXIT_STDIN;
                return r;
        }

        r = setup_output(unit, context, params, STDOUT_FILENO, socket_fd, basename(command->path), uid, gid);
        if (r < 0) {
                *exit_status = EXIT_STDOUT;
                return r;
        }

        r = setup_output(unit, context, params, STDERR_FILENO, socket_fd, basename(command->path), uid, gid);
        if (r < 0) {
                *exit_status = EXIT_STDERR;
                return r;
        }

        if (params->cgroup_path) {
                r = cg_attach_everywhere(params->cgroup_supported, params->cgroup_path, 0, NULL, NULL);
                if (r < 0) {
                        *exit_status = EXIT_CGROUP;
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
                utmp_put_init_process(context->utmp_id, getpid(), getsid(0), context->tty_path,
                                      context->utmp_mode == EXEC_UTMP_INIT  ? INIT_PROCESS :
                                      context->utmp_mode == EXEC_UTMP_LOGIN ? LOGIN_PROCESS :
                                      USER_PROCESS,
                                      username ? "root" : context->user);

        if (context->user && is_terminal_input(context->std_input)) {
                r = chown_terminal(STDIN_FILENO, uid);
                if (r < 0) {
                        *exit_status = EXIT_STDIN;
                        return r;
                }
        }

        if (params->bus_endpoint_fd >= 0 && context->bus_endpoint) {
                uid_t ep_uid = (uid == UID_INVALID) ? 0 : uid;

                r = bus_kernel_set_endpoint_policy(params->bus_endpoint_fd, ep_uid, context->bus_endpoint);
                if (r < 0) {
                        *exit_status = EXIT_BUS_ENDPOINT;
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
                char **rt;

                STRV_FOREACH(rt, context->runtime_directory) {
                        _cleanup_free_ char *p;

                        p = strjoin(params->runtime_prefix, "/", *rt, NULL);
                        if (!p) {
                                *exit_status = EXIT_RUNTIME_DIRECTORY;
                                return -ENOMEM;
                        }

                        r = mkdir_p_label(p, context->runtime_directory_mode);
                        if (r < 0) {
                                *exit_status = EXIT_RUNTIME_DIRECTORY;
                                return r;
                        }

                        r = chmod_and_chown(p, context->runtime_directory_mode, uid, gid);
                        if (r < 0) {
                                *exit_status = EXIT_RUNTIME_DIRECTORY;
                                return r;
                        }
                }
        }

        umask(context->umask);

        if (params->apply_permissions) {
                r = enforce_groups(context, username, gid);
                if (r < 0) {
                        *exit_status = EXIT_GROUP;
                        return r;
                }
#ifdef HAVE_SMACK
                if (context->smack_process_label) {
                        r = mac_smack_apply_pid(0, context->smack_process_label);
                        if (r < 0) {
                                *exit_status = EXIT_SMACK_PROCESS_LABEL;
                                return r;
                        }
                }
#ifdef SMACK_DEFAULT_PROCESS_LABEL
                else {
                        _cleanup_free_ char *exec_label = NULL;

                        r = mac_smack_read(command->path, SMACK_ATTR_EXEC, &exec_label);
                        if (r < 0 && r != -ENODATA && r != -EOPNOTSUPP) {
                                *exit_status = EXIT_SMACK_PROCESS_LABEL;
                                return r;
                        }

                        r = mac_smack_apply_pid(0, exec_label ? : SMACK_DEFAULT_PROCESS_LABEL);
                        if (r < 0) {
                                *exit_status = EXIT_SMACK_PROCESS_LABEL;
                                return r;
                        }
                }
#endif
#endif
#ifdef HAVE_PAM
                if (context->pam_name && username) {
                        r = setup_pam(context->pam_name, username, uid, context->tty_path, &pam_env, fds, n_fds);
                        if (r < 0) {
                                *exit_status = EXIT_PAM;
                                return r;
                        }
                }
#endif
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
                char *tmp = NULL, *var = NULL;

                /* The runtime struct only contains the parent
                 * of the private /tmp, which is
                 * non-accessible to world users. Inside of it
                 * there's a /tmp that is sticky, and that's
                 * the one we want to use here. */

                if (context->private_tmp && runtime) {
                        if (runtime->tmp_dir)
                                tmp = strjoina(runtime->tmp_dir, "/tmp");
                        if (runtime->var_tmp_dir)
                                var = strjoina(runtime->var_tmp_dir, "/tmp");
                }

                r = setup_namespace(
                                params->apply_chroot ? context->root_directory : NULL,
                                context->read_write_dirs,
                                context->read_only_dirs,
                                context->inaccessible_dirs,
                                tmp,
                                var,
                                params->bus_endpoint_path,
                                context->private_devices,
                                context->protect_home,
                                context->protect_system,
                                context->mount_flags);

                /* If we couldn't set up the namespace this is
                 * probably due to a missing capability. In this case,
                 * silently proceeed. */
                if (r == -EPERM || r == -EACCES) {
                        log_open();
                        log_unit_debug_errno(unit, r, "Failed to set up namespace, assuming containerized execution, ignoring: %m");
                        log_close();
                } else if (r < 0) {
                        *exit_status = EXIT_NAMESPACE;
                        return r;
                }
        }

        if (context->working_directory_home)
                wd = home;
        else if (context->working_directory)
                wd = context->working_directory;
        else
                wd = "/";

        if (params->apply_chroot) {
                if (!needs_mount_namespace && context->root_directory)
                        if (chroot(context->root_directory) < 0) {
                                *exit_status = EXIT_CHROOT;
                                return -errno;
                        }

                if (chdir(wd) < 0 &&
                    !context->working_directory_missing_ok) {
                        *exit_status = EXIT_CHDIR;
                        return -errno;
                }
        } else {
                const char *d;

                d = strjoina(strempty(context->root_directory), "/", strempty(wd));
                if (chdir(d) < 0 &&
                    !context->working_directory_missing_ok) {
                        *exit_status = EXIT_CHDIR;
                        return -errno;
                }
        }

#ifdef HAVE_SELINUX
        if (params->apply_permissions && mac_selinux_use() && params->selinux_context_net && socket_fd >= 0) {
                r = mac_selinux_get_child_mls_label(socket_fd, command->path, context->selinux_context, &mac_selinux_context_net);
                if (r < 0) {
                        *exit_status = EXIT_SELINUX_CONTEXT;
                        return r;
                }
        }
#endif

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
                r = flags_fds(fds, n_fds, context->non_blocking);
        if (r < 0) {
                *exit_status = EXIT_FDS;
                return r;
        }

        if (params->apply_permissions) {

                for (i = 0; i < _RLIMIT_MAX; i++) {
                        if (!context->rlimit[i])
                                continue;

                        if (setrlimit_closest(i, context->rlimit[i]) < 0) {
                                *exit_status = EXIT_LIMITS;
                                return -errno;
                        }
                }

                if (context->capability_bounding_set_drop) {
                        r = capability_bounding_set_drop(context->capability_bounding_set_drop, false);
                        if (r < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return r;
                        }
                }

                if (context->user) {
                        r = enforce_user(context, uid);
                        if (r < 0) {
                                *exit_status = EXIT_USER;
                                return r;
                        }
                }

                /* PR_GET_SECUREBITS is not privileged, while
                 * PR_SET_SECUREBITS is. So to suppress
                 * potential EPERMs we'll try not to call
                 * PR_SET_SECUREBITS unless necessary. */
                if (prctl(PR_GET_SECUREBITS) != context->secure_bits)
                        if (prctl(PR_SET_SECUREBITS, context->secure_bits) < 0) {
                                *exit_status = EXIT_SECUREBITS;
                                return -errno;
                        }

                if (context->capabilities)
                        if (cap_set_proc(context->capabilities) < 0) {
                                *exit_status = EXIT_CAPABILITIES;
                                return -errno;
                        }

                if (context->no_new_privileges)
                        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                                *exit_status = EXIT_NO_NEW_PRIVILEGES;
                                return -errno;
                        }

#ifdef HAVE_SECCOMP
                if (context->address_families_whitelist ||
                    !set_isempty(context->address_families)) {
                        r = apply_address_families(context);
                        if (r < 0) {
                                *exit_status = EXIT_ADDRESS_FAMILIES;
                                return r;
                        }
                }

                if (context->syscall_whitelist ||
                    !set_isempty(context->syscall_filter) ||
                    !set_isempty(context->syscall_archs)) {
                        r = apply_seccomp(context);
                        if (r < 0) {
                                *exit_status = EXIT_SECCOMP;
                                return r;
                        }
                }
#endif

#ifdef HAVE_SELINUX
                if (mac_selinux_use()) {
                        char *exec_context = mac_selinux_context_net ?: context->selinux_context;

                        if (exec_context) {
                                r = setexeccon(exec_context);
                                if (r < 0) {
                                        *exit_status = EXIT_SELINUX_CONTEXT;
                                        return r;
                                }
                        }
                }
#endif

#ifdef HAVE_APPARMOR
                if (context->apparmor_profile && mac_apparmor_use()) {
                        r = aa_change_onexec(context->apparmor_profile);
                        if (r < 0 && !context->apparmor_profile_ignore) {
                                *exit_status = EXIT_APPARMOR_PROFILE;
                                return -errno;
                        }
                }
#endif
        }

        r = build_environment(context, n_fds, params->fd_names, params->watchdog_usec, home, username, shell, &our_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return r;
        }

        r = build_pass_environment(context, &pass_env);
        if (r < 0) {
                *exit_status = EXIT_MEMORY;
                return r;
        }

        final_env = strv_env_merge(6,
                                   params->environment,
                                   our_env,
                                   pass_env,
                                   context->environment,
                                   files_env,
                                   pam_env,
                                   NULL);
        if (!final_env) {
                *exit_status = EXIT_MEMORY;
                return -ENOMEM;
        }

        final_argv = replace_env_argv(argv, final_env);
        if (!final_argv) {
                *exit_status = EXIT_MEMORY;
                return -ENOMEM;
        }

        final_env = strv_env_clean(final_env);

        if (_unlikely_(log_get_max_level() >= LOG_DEBUG)) {
                _cleanup_free_ char *line;

                line = exec_command_line(final_argv);
                if (line) {
                        log_open();
                        log_struct(LOG_DEBUG,
                                   LOG_UNIT_ID(unit),
                                   "EXECUTABLE=%s", command->path,
                                   LOG_UNIT_MESSAGE(unit, "Executing: %s", line),
                                   NULL);
                        log_close();
                }
        }

        execve(command->path, final_argv, final_env);
        *exit_status = EXIT_EXEC;
        return -errno;
}

int exec_spawn(Unit *unit,
               ExecCommand *command,
               const ExecContext *context,
               const ExecParameters *params,
               ExecRuntime *runtime,
               pid_t *ret) {

        _cleanup_strv_free_ char **files_env = NULL;
        int *fds = NULL; unsigned n_fds = 0;
        _cleanup_free_ char *line = NULL;
        int socket_fd, r;
        char **argv;
        pid_t pid;

        assert(unit);
        assert(command);
        assert(context);
        assert(ret);
        assert(params);
        assert(params->fds || params->n_fds <= 0);

        if (context->std_input == EXEC_INPUT_SOCKET ||
            context->std_output == EXEC_OUTPUT_SOCKET ||
            context->std_error == EXEC_OUTPUT_SOCKET) {

                if (params->n_fds != 1) {
                        log_unit_error(unit, "Got more than one socket.");
                        return -EINVAL;
                }

                socket_fd = params->fds[0];
        } else {
                socket_fd = -1;
                fds = params->fds;
                n_fds = params->n_fds;
        }

        r = exec_context_load_environment(unit, context, &files_env);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to load environment files: %m");

        argv = params->argv ?: command->argv;
        line = exec_command_line(argv);
        if (!line)
                return log_oom();

        log_struct(LOG_DEBUG,
                   LOG_UNIT_ID(unit),
                   LOG_UNIT_MESSAGE(unit, "About to execute: %s", line),
                   "EXECUTABLE=%s", command->path,
                   NULL);
        pid = fork();
        if (pid < 0)
                return log_unit_error_errno(unit, r, "Failed to fork: %m");

        if (pid == 0) {
                int exit_status;

                r = exec_child(unit,
                               command,
                               context,
                               params,
                               runtime,
                               argv,
                               socket_fd,
                               fds, n_fds,
                               files_env,
                               &exit_status);
                if (r < 0) {
                        log_open();
                        log_struct_errno(LOG_ERR, r,
                                         LOG_MESSAGE_ID(SD_MESSAGE_SPAWN_FAILED),
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
}

void exec_context_done(ExecContext *c) {
        unsigned l;

        assert(c);

        c->environment = strv_free(c->environment);
        c->environment_files = strv_free(c->environment_files);
        c->pass_environment = strv_free(c->pass_environment);

        for (l = 0; l < ELEMENTSOF(c->rlimit); l++)
                c->rlimit[l] = mfree(c->rlimit[l]);

        c->working_directory = mfree(c->working_directory);
        c->root_directory = mfree(c->root_directory);
        c->tty_path = mfree(c->tty_path);
        c->syslog_identifier = mfree(c->syslog_identifier);
        c->user = mfree(c->user);
        c->group = mfree(c->group);

        c->supplementary_groups = strv_free(c->supplementary_groups);

        c->pam_name = mfree(c->pam_name);

        if (c->capabilities) {
                cap_free(c->capabilities);
                c->capabilities = NULL;
        }

        c->read_only_dirs = strv_free(c->read_only_dirs);
        c->read_write_dirs = strv_free(c->read_write_dirs);
        c->inaccessible_dirs = strv_free(c->inaccessible_dirs);

        if (c->cpuset)
                CPU_FREE(c->cpuset);

        c->utmp_id = mfree(c->utmp_id);
        c->selinux_context = mfree(c->selinux_context);
        c->apparmor_profile = mfree(c->apparmor_profile);

        c->syscall_filter = set_free(c->syscall_filter);
        c->syscall_archs = set_free(c->syscall_archs);
        c->address_families = set_free(c->address_families);

        c->runtime_directory = strv_free(c->runtime_directory);

        bus_endpoint_free(c->bus_endpoint);
        c->bus_endpoint = NULL;
}

int exec_context_destroy_runtime_directory(ExecContext *c, const char *runtime_prefix) {
        char **i;

        assert(c);

        if (!runtime_prefix)
                return 0;

        STRV_FOREACH(i, c->runtime_directory) {
                _cleanup_free_ char *p;

                p = strjoin(runtime_prefix, "/", *i, NULL);
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

int exec_context_load_environment(Unit *unit, const ExecContext *c, char ***l) {
        char **i, **r = NULL;

        assert(c);
        assert(l);

        STRV_FOREACH(i, c->environment_files) {
                char *fn;
                int k;
                bool ignore = false;
                char **p;
                _cleanup_globfree_ glob_t pglob = {};
                int count, n;

                fn = *i;

                if (fn[0] == '-') {
                        ignore = true;
                        fn ++;
                }

                if (!path_is_absolute(fn)) {
                        if (ignore)
                                continue;

                        strv_free(r);
                        return -EINVAL;
                }

                /* Filename supports globbing, take all matching files */
                errno = 0;
                if (glob(fn, 0, NULL, &pglob) != 0) {
                        if (ignore)
                                continue;

                        strv_free(r);
                        return errno ? -errno : -EINVAL;
                }
                count = pglob.gl_pathc;
                if (count == 0) {
                        if (ignore)
                                continue;

                        strv_free(r);
                        return -EINVAL;
                }
                for (n = 0; n < count; n++) {
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
        return (ec->tty_reset || ec->tty_vhangup || ec->tty_vt_disallocate ||
                is_terminal_input(ec->std_input) ||
                is_terminal_output(ec->std_output) ||
                is_terminal_output(ec->std_error)) &&
               tty_may_match_dev_console(tty_path(ec));
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

        assert(c);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%sUMask: %04o\n"
                "%sWorkingDirectory: %s\n"
                "%sRootDirectory: %s\n"
                "%sNonBlocking: %s\n"
                "%sPrivateTmp: %s\n"
                "%sPrivateNetwork: %s\n"
                "%sPrivateDevices: %s\n"
                "%sProtectHome: %s\n"
                "%sProtectSystem: %s\n"
                "%sIgnoreSIGPIPE: %s\n",
                prefix, c->umask,
                prefix, c->working_directory ? c->working_directory : "/",
                prefix, c->root_directory ? c->root_directory : "/",
                prefix, yes_no(c->non_blocking),
                prefix, yes_no(c->private_tmp),
                prefix, yes_no(c->private_network),
                prefix, yes_no(c->private_devices),
                prefix, protect_home_to_string(c->protect_home),
                prefix, protect_system_to_string(c->protect_system),
                prefix, yes_no(c->ignore_sigpipe));

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
                if (c->rlimit[i])
                        fprintf(f, "%s%s: "RLIM_FMT"\n",
                                prefix, rlimit_to_string(i), c->rlimit[i]->rlim_max);

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

        if (c->capabilities) {
                _cleanup_cap_free_charp_ char *t;

                t = cap_to_text(c->capabilities, NULL);
                if (t)
                        fprintf(f, "%sCapabilities: %s\n", prefix, t);
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

        if (c->capability_bounding_set_drop) {
                unsigned long l;
                fprintf(f, "%sCapabilityBoundingSet:", prefix);

                for (l = 0; l <= cap_last_cap(); l++)
                        if (!(c->capability_bounding_set_drop & ((uint64_t) 1ULL << (uint64_t) l)))
                                fprintf(f, " %s", strna(capability_to_name(l)));

                fputs("\n", f);
        }

        if (c->user)
                fprintf(f, "%sUser: %s\n", prefix, c->user);
        if (c->group)
                fprintf(f, "%sGroup: %s\n", prefix, c->group);

        if (strv_length(c->supplementary_groups) > 0) {
                fprintf(f, "%sSupplementaryGroups:", prefix);
                strv_fprintf(f, c->supplementary_groups);
                fputs("\n", f);
        }

        if (c->pam_name)
                fprintf(f, "%sPAMName: %s\n", prefix, c->pam_name);

        if (strv_length(c->read_write_dirs) > 0) {
                fprintf(f, "%sReadWriteDirs:", prefix);
                strv_fprintf(f, c->read_write_dirs);
                fputs("\n", f);
        }

        if (strv_length(c->read_only_dirs) > 0) {
                fprintf(f, "%sReadOnlyDirs:", prefix);
                strv_fprintf(f, c->read_only_dirs);
                fputs("\n", f);
        }

        if (strv_length(c->inaccessible_dirs) > 0) {
                fprintf(f, "%sInaccessibleDirs:", prefix);
                strv_fprintf(f, c->inaccessible_dirs);
                fputs("\n", f);
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

        if (c->syscall_errno != 0)
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

        /* Returns true if the process forked off would run run under
         * an unchanged UID or as root. */

        if (!c->user)
                return true;

        if (streq(c->user, "root") || streq(c->user, "0"))
                return true;

        return false;
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

                exec_context_tty_reset(context);
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

        if (s->start_timestamp.realtime > 0)
                fprintf(f,
                        "%sStart Timestamp: %s\n",
                        prefix, format_timestamp(buf, sizeof(buf), s->start_timestamp.realtime));

        if (s->exit_timestamp.realtime > 0)
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

        if (!(n = new(char, k)))
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
                if (socketpair(AF_UNIX, SOCK_DGRAM, 0, (*rt)->netns_storage_socket) < 0)
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
        free(r);

        return NULL;
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
        [EXEC_INPUT_SOCKET] = "socket"
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
        [EXEC_OUTPUT_SOCKET] = "socket"
};

DEFINE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

static const char* const exec_utmp_mode_table[_EXEC_UTMP_MODE_MAX] = {
        [EXEC_UTMP_INIT] = "init",
        [EXEC_UTMP_LOGIN] = "login",
        [EXEC_UTMP_USER] = "user",
};

DEFINE_STRING_TABLE_LOOKUP(exec_utmp_mode, ExecUtmpMode);
