/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <sys/mount.h>
#include <linux/fs.h>

#ifdef HAVE_PAM
#include <security/pam_appl.h>
#endif

#include "execute.h"
#include "strv.h"
#include "macro.h"
#include "util.h"
#include "log.h"
#include "ioprio.h"
#include "securebits.h"
#include "cgroup.h"
#include "namespace.h"
#include "tcpwrap.h"

/* This assumes there is a 'tty' group */
#define TTY_MODE 0620

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

                        if ((nfd = fcntl(fds[i], F_DUPFD, i+3)) < 0)
                                return -errno;

                        close_nointr_nofail(fds[i]);
                        fds[i] = nfd;

                        /* Hmm, the fd we wanted isn't free? Then
                         * let's remember that and try again from here*/
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

                if ((r = fd_nonblock(fds[i], nonblock)) < 0)
                        return r;

                /* We unconditionally drop FD_CLOEXEC from the fds,
                 * since after all we want to pass these fds to our
                 * children */

                if ((r = fd_cloexec(fds[i], false)) < 0)
                        return r;
        }

        return 0;
}

static const char *tty_path(const ExecContext *context) {
        assert(context);

        if (context->tty_path)
                return context->tty_path;

        return "/dev/console";
}

static int open_null_as(int flags, int nfd) {
        int fd, r;

        assert(nfd >= 0);

        if ((fd = open("/dev/null", flags|O_NOCTTY)) < 0)
                return -errno;

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                close_nointr_nofail(fd);
        } else
                r = nfd;

        return r;
}

static int connect_logger_as(const ExecContext *context, ExecOutput output, const char *ident, int nfd) {
        int fd, r;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;

        assert(context);
        assert(output < _EXEC_OUTPUT_MAX);
        assert(ident);
        assert(nfd >= 0);

        if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
                return -errno;

        zero(sa);
        sa.sa.sa_family = AF_UNIX;
        strncpy(sa.un.sun_path+1, LOGGER_SOCKET, sizeof(sa.un.sun_path)-1);

        if (connect(fd, &sa.sa, sizeof(sa_family_t) + 1 + sizeof(LOGGER_SOCKET) - 1) < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        if (shutdown(fd, SHUT_RD) < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        /* We speak a very simple protocol between log server
         * and client: one line for the log destination (kmsg
         * or syslog), followed by the priority field,
         * followed by the process name. Since we replaced
         * stdin/stderr we simple use stdio to write to
         * it. Note that we use stderr, to minimize buffer
         * flushing issues. */

        dprintf(fd,
                "%s\n"
                "%i\n"
                "%s\n"
                "%i\n",
                output == EXEC_OUTPUT_KMSG ? "kmsg" : "syslog",
                context->syslog_priority,
                context->syslog_identifier ? context->syslog_identifier : ident,
                context->syslog_level_prefix);

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                close_nointr_nofail(fd);
        } else
                r = nfd;

        return r;
}
static int open_terminal_as(const char *path, mode_t mode, int nfd) {
        int fd, r;

        assert(path);
        assert(nfd >= 0);

        if ((fd = open_terminal(path, mode | O_NOCTTY)) < 0)
                return fd;

        if (fd != nfd) {
                r = dup2(fd, nfd) < 0 ? -errno : nfd;
                close_nointr_nofail(fd);
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

static int setup_input(const ExecContext *context, int socket_fd, bool apply_tty_stdin) {
        ExecInput i;

        assert(context);

        i = fixup_input(context->std_input, socket_fd, apply_tty_stdin);

        switch (i) {

        case EXEC_INPUT_NULL:
                return open_null_as(O_RDONLY, STDIN_FILENO);

        case EXEC_INPUT_TTY:
        case EXEC_INPUT_TTY_FORCE:
        case EXEC_INPUT_TTY_FAIL: {
                int fd, r;

                if ((fd = acquire_terminal(
                                     tty_path(context),
                                     i == EXEC_INPUT_TTY_FAIL,
                                     i == EXEC_INPUT_TTY_FORCE,
                                     false)) < 0)
                        return fd;

                if (fd != STDIN_FILENO) {
                        r = dup2(fd, STDIN_FILENO) < 0 ? -errno : STDIN_FILENO;
                        close_nointr_nofail(fd);
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

static int setup_output(const ExecContext *context, int socket_fd, const char *ident, bool apply_tty_stdin) {
        ExecOutput o;
        ExecInput i;

        assert(context);
        assert(ident);

        i = fixup_input(context->std_input, socket_fd, apply_tty_stdin);
        o = fixup_output(context->std_output, socket_fd);

        /* This expects the input is already set up */

        switch (o) {

        case EXEC_OUTPUT_INHERIT:

                /* If the input is connected to anything that's not a /dev/null, inherit that... */
                if (i != EXEC_INPUT_NULL)
                        return dup2(STDIN_FILENO, STDOUT_FILENO) < 0 ? -errno : STDOUT_FILENO;

                /* If we are not started from PID 1 we just inherit STDOUT from our parent process. */
                if (getppid() != 1)
                        return STDOUT_FILENO;

                /* We need to open /dev/null here anew, to get the
                 * right access mode. So we fall through */

        case EXEC_OUTPUT_NULL:
                return open_null_as(O_WRONLY, STDOUT_FILENO);

        case EXEC_OUTPUT_TTY:
                if (is_terminal_input(i))
                        return dup2(STDIN_FILENO, STDOUT_FILENO) < 0 ? -errno : STDOUT_FILENO;

                /* We don't reset the terminal if this is just about output */
                return open_terminal_as(tty_path(context), O_WRONLY, STDOUT_FILENO);

        case EXEC_OUTPUT_SYSLOG:
        case EXEC_OUTPUT_KMSG:
                return connect_logger_as(context, o, ident, STDOUT_FILENO);

        case EXEC_OUTPUT_SOCKET:
                assert(socket_fd >= 0);
                return dup2(socket_fd, STDOUT_FILENO) < 0 ? -errno : STDOUT_FILENO;

        default:
                assert_not_reached("Unknown output type");
        }
}

static int setup_error(const ExecContext *context, int socket_fd, const char *ident, bool apply_tty_stdin) {
        ExecOutput o, e;
        ExecInput i;

        assert(context);
        assert(ident);

        i = fixup_input(context->std_input, socket_fd, apply_tty_stdin);
        o = fixup_output(context->std_output, socket_fd);
        e = fixup_output(context->std_error, socket_fd);

        /* This expects the input and output are already set up */

        /* Don't change the stderr file descriptor if we inherit all
         * the way and are not on a tty */
        if (e == EXEC_OUTPUT_INHERIT &&
            o == EXEC_OUTPUT_INHERIT &&
            i == EXEC_INPUT_NULL &&
            getppid () != 1)
                return STDERR_FILENO;

        /* Duplicate form stdout if possible */
        if (e == o || e == EXEC_OUTPUT_INHERIT)
                return dup2(STDOUT_FILENO, STDERR_FILENO) < 0 ? -errno : STDERR_FILENO;

        switch (e) {

        case EXEC_OUTPUT_NULL:
                return open_null_as(O_WRONLY, STDERR_FILENO);

        case EXEC_OUTPUT_TTY:
                if (is_terminal_input(i))
                        return dup2(STDIN_FILENO, STDERR_FILENO) < 0 ? -errno : STDERR_FILENO;

                /* We don't reset the terminal if this is just about output */
                return open_terminal_as(tty_path(context), O_WRONLY, STDERR_FILENO);

        case EXEC_OUTPUT_SYSLOG:
        case EXEC_OUTPUT_KMSG:
                return connect_logger_as(context, e, ident, STDERR_FILENO);

        case EXEC_OUTPUT_SOCKET:
                assert(socket_fd >= 0);
                return dup2(socket_fd, STDERR_FILENO) < 0 ? -errno : STDERR_FILENO;

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

static int setup_confirm_stdio(const ExecContext *context,
                               int *_saved_stdin,
                               int *_saved_stdout) {
        int fd = -1, saved_stdin, saved_stdout = -1, r;

        assert(context);
        assert(_saved_stdin);
        assert(_saved_stdout);

        /* This returns positive EXIT_xxx return values instead of
         * negative errno style values! */

        if ((saved_stdin = fcntl(STDIN_FILENO, F_DUPFD, 3)) < 0)
                return EXIT_STDIN;

        if ((saved_stdout = fcntl(STDOUT_FILENO, F_DUPFD, 3)) < 0) {
                r = EXIT_STDOUT;
                goto fail;
        }

        if ((fd = acquire_terminal(
                             tty_path(context),
                             context->std_input == EXEC_INPUT_TTY_FAIL,
                             context->std_input == EXEC_INPUT_TTY_FORCE,
                             false)) < 0) {
                r = EXIT_STDIN;
                goto fail;
        }

        if (chown_terminal(fd, getuid()) < 0) {
                r = EXIT_STDIN;
                goto fail;
        }

        if (dup2(fd, STDIN_FILENO) < 0) {
                r = EXIT_STDIN;
                goto fail;
        }

        if (dup2(fd, STDOUT_FILENO) < 0) {
                r = EXIT_STDOUT;
                goto fail;
        }

        if (fd >= 2)
                close_nointr_nofail(fd);

        *_saved_stdin = saved_stdin;
        *_saved_stdout = saved_stdout;

        return 0;

fail:
        if (saved_stdout >= 0)
                close_nointr_nofail(saved_stdout);

        if (saved_stdin >= 0)
                close_nointr_nofail(saved_stdin);

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

static int restore_confirm_stdio(const ExecContext *context,
                                 int *saved_stdin,
                                 int *saved_stdout,
                                 bool *keep_stdin,
                                 bool *keep_stdout) {

        assert(context);
        assert(saved_stdin);
        assert(*saved_stdin >= 0);
        assert(saved_stdout);
        assert(*saved_stdout >= 0);

        /* This returns positive EXIT_xxx return values instead of
         * negative errno style values! */

        if (is_terminal_input(context->std_input)) {

                /* The service wants terminal input. */

                *keep_stdin = true;
                *keep_stdout =
                        context->std_output == EXEC_OUTPUT_INHERIT ||
                        context->std_output == EXEC_OUTPUT_TTY;

        } else {
                /* If the service doesn't want a controlling terminal,
                 * then we need to get rid entirely of what we have
                 * already. */

                if (release_terminal() < 0)
                        return EXIT_STDIN;

                if (dup2(*saved_stdin, STDIN_FILENO) < 0)
                        return EXIT_STDIN;

                if (dup2(*saved_stdout, STDOUT_FILENO) < 0)
                        return EXIT_STDOUT;

                *keep_stdout = *keep_stdin = false;
        }

        return 0;
}

static int get_group_creds(const char *groupname, gid_t *gid) {
        struct group *g;
        unsigned long lu;

        assert(groupname);
        assert(gid);

        /* We enforce some special rules for gid=0: in order to avoid
         * NSS lookups for root we hardcode its data. */

        if (streq(groupname, "root") || streq(groupname, "0")) {
                *gid = 0;
                return 0;
        }

        if (safe_atolu(groupname, &lu) >= 0) {
                errno = 0;
                g = getgrgid((gid_t) lu);
        } else {
                errno = 0;
                g = getgrnam(groupname);
        }

        if (!g)
                return errno != 0 ? -errno : -ESRCH;

        *gid = g->gr_gid;
        return 0;
}

static int get_user_creds(const char **username, uid_t *uid, gid_t *gid, const char **home) {
        struct passwd *p;
        unsigned long lu;

        assert(username);
        assert(*username);
        assert(uid);
        assert(gid);
        assert(home);

        /* We enforce some special rules for uid=0: in order to avoid
         * NSS lookups for root we hardcode its data. */

        if (streq(*username, "root") || streq(*username, "0")) {
                *username = "root";
                *uid = 0;
                *gid = 0;
                *home = "/root";
                return 0;
        }

        if (safe_atolu(*username, &lu) >= 0) {
                errno = 0;
                p = getpwuid((uid_t) lu);

                /* If there are multiple users with the same id, make
                 * sure to leave $USER to the configured value instead
                 * of the first occurence in the database. However if
                 * the uid was configured by a numeric uid, then let's
                 * pick the real username from /etc/passwd. */
                if (*username && p)
                        *username = p->pw_name;
        } else {
                errno = 0;
                p = getpwnam(*username);
        }

        if (!p)
                return errno != 0 ? -errno : -ESRCH;

        *uid = p->pw_uid;
        *gid = p->pw_gid;
        *home = p->pw_dir;
        return 0;
}

static int enforce_groups(const ExecContext *context, const char *username, gid_t gid) {
        bool keep_groups = false;
        int r;

        assert(context);

        /* Lookup and ser GID and supplementary group list. Here too
         * we avoid NSS lookups for gid=0. */

        if (context->group || username) {

                if (context->group)
                        if ((r = get_group_creds(context->group, &gid)) < 0)
                                return r;

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
                ngroups_max = (int) sysconf(_SC_NGROUPS_MAX);

                if (!(gids = new(gid_t, ngroups_max)))
                        return -ENOMEM;

                if (keep_groups) {
                        if ((k = getgroups(ngroups_max, gids)) < 0) {
                                free(gids);
                                return -errno;
                        }
                } else
                        k = 0;

                STRV_FOREACH(i, context->supplementary_groups) {

                        if (k >= ngroups_max) {
                                free(gids);
                                return -E2BIG;
                        }

                        if ((r = get_group_creds(*i, gids+k)) < 0) {
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
        int r;
        assert(context);

        /* Sets (but doesn't lookup) the uid and make sure we keep the
         * capabilities while doing so. */

        if (context->capabilities) {
                cap_t d;
                static const cap_value_t bits[] = {
                        CAP_SETUID,   /* Necessary so that we can run setresuid() below */
                        CAP_SETPCAP   /* Necessary so that we can set PR_SET_SECUREBITS later on */
                };

                /* First step: If we need to keep capabilities but
                 * drop privileges we need to make sure we keep our
                 * caps, whiel we drop priviliges. */
                if (uid != 0) {
                        int sb = context->secure_bits|SECURE_KEEP_CAPS;

                        if (prctl(PR_GET_SECUREBITS) != sb)
                                if (prctl(PR_SET_SECUREBITS, sb) < 0)
                                        return -errno;
                }

                /* Second step: set the capabilites. This will reduce
                 * the capabilities to the minimum we need. */

                if (!(d = cap_dup(context->capabilities)))
                        return -errno;

                if (cap_set_flag(d, CAP_EFFECTIVE, ELEMENTSOF(bits), bits, CAP_SET) < 0 ||
                    cap_set_flag(d, CAP_PERMITTED, ELEMENTSOF(bits), bits, CAP_SET) < 0) {
                        r = -errno;
                        cap_free(d);
                        return r;
                }

                if (cap_set_proc(d) < 0) {
                        r = -errno;
                        cap_free(d);
                        return r;
                }

                cap_free(d);
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
                const char *tty,
                char ***pam_env,
                int fds[], unsigned n_fds) {

        static const struct pam_conv conv = {
                .conv = null_conv,
                .appdata_ptr = NULL
        };

        pam_handle_t *handle = NULL;
        sigset_t ss, old_ss;
        int pam_code = PAM_SUCCESS;
        char **e = NULL;
        bool close_session = false;
        pid_t pam_pid = 0, parent_pid;

        assert(name);
        assert(user);
        assert(pam_env);

        /* We set up PAM in the parent process, then fork. The child
         * will then stay around untill killed via PR_GET_PDEATHSIG or
         * systemd via the cgroup logic. It will then remove the PAM
         * session again. The parent process will exec() the actual
         * daemon. We do things this way to ensure that the main PID
         * of the daemon is the one we initially fork()ed. */

        if ((pam_code = pam_start(name, user, &conv, &handle)) != PAM_SUCCESS) {
                handle = NULL;
                goto fail;
        }

        if (tty)
                if ((pam_code = pam_set_item(handle, PAM_TTY, tty)) != PAM_SUCCESS)
                        goto fail;

        if ((pam_code = pam_acct_mgmt(handle, PAM_SILENT)) != PAM_SUCCESS)
                goto fail;

        if ((pam_code = pam_open_session(handle, PAM_SILENT)) != PAM_SUCCESS)
                goto fail;

        close_session = true;

        if ((pam_code = pam_setcred(handle, PAM_ESTABLISH_CRED | PAM_SILENT)) != PAM_SUCCESS)
                goto fail;

        if ((!(e = pam_getenvlist(handle)))) {
                pam_code = PAM_BUF_ERR;
                goto fail;
        }

        /* Block SIGTERM, so that we know that it won't get lost in
         * the child */
        if (sigemptyset(&ss) < 0 ||
            sigaddset(&ss, SIGTERM) < 0 ||
            sigprocmask(SIG_BLOCK, &ss, &old_ss) < 0)
                goto fail;

        parent_pid = getpid();

        if ((pam_pid = fork()) < 0)
                goto fail;

        if (pam_pid == 0) {
                int sig;
                int r = EXIT_PAM;

                /* The child's job is to reset the PAM session on
                 * termination */

                /* This string must fit in 10 chars (i.e. the length
                 * of "/sbin/init") */
                rename_process("sd:pam");

                /* Make sure we don't keep open the passed fds in this
                child. We assume that otherwise only those fds are
                open here that have been opened by PAM. */
                close_many(fds, n_fds);

                /* Wait until our parent died. This will most likely
                 * not work since the kernel does not allow
                 * unpriviliged paretns kill their priviliged children
                 * this way. We rely on the control groups kill logic
                 * to do the rest for us. */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        goto child_finish;

                /* Check if our parent process might already have
                 * died? */
                if (getppid() == parent_pid) {
                        if (sigwait(&ss, &sig) < 0)
                                goto child_finish;

                        assert(sig == SIGTERM);
                }

                /* Only if our parent died we'll end the session */
                if (getppid() != parent_pid)
                        if ((pam_code = pam_close_session(handle, PAM_DATA_SILENT)) != PAM_SUCCESS)
                                goto child_finish;

                r = 0;

        child_finish:
                pam_end(handle, pam_code | PAM_DATA_SILENT);
                _exit(r);
        }

        /* If the child was forked off successfully it will do all the
         * cleanups, so forget about the handle here. */
        handle = NULL;

        /* Unblock SIGSUR1 again in the parent */
        if (sigprocmask(SIG_SETMASK, &old_ss, NULL) < 0)
                goto fail;

        /* We close the log explicitly here, since the PAM modules
         * might have opened it, but we don't want this fd around. */
        closelog();

        return 0;

fail:
        if (handle) {
                if (close_session)
                        pam_code = pam_close_session(handle, PAM_DATA_SILENT);

                pam_end(handle, pam_code | PAM_DATA_SILENT);
        }

        strv_free(e);

        closelog();

        if (pam_pid > 1)
                kill(pam_pid, SIGTERM);

        return EXIT_PAM;
}
#endif

int exec_spawn(ExecCommand *command,
               char **argv,
               const ExecContext *context,
               int fds[], unsigned n_fds,
               char **environment,
               bool apply_permissions,
               bool apply_chroot,
               bool apply_tty_stdin,
               bool confirm_spawn,
               CGroupBonding *cgroup_bondings,
               pid_t *ret) {

        pid_t pid;
        int r;
        char *line;
        int socket_fd;

        assert(command);
        assert(context);
        assert(ret);
        assert(fds || n_fds <= 0);

        if (context->std_input == EXEC_INPUT_SOCKET ||
            context->std_output == EXEC_OUTPUT_SOCKET ||
            context->std_error == EXEC_OUTPUT_SOCKET) {

                if (n_fds != 1)
                        return -EINVAL;

                socket_fd = fds[0];

                fds = NULL;
                n_fds = 0;
        } else
                socket_fd = -1;

        if (!argv)
                argv = command->argv;

        if (!(line = exec_command_line(argv)))
                return -ENOMEM;

        log_debug("About to execute: %s", line);
        free(line);

        if (cgroup_bondings)
                if ((r = cgroup_bonding_realize_list(cgroup_bondings)))
                        return r;

        if ((pid = fork()) < 0)
                return -errno;

        if (pid == 0) {
                int i;
                sigset_t ss;
                const char *username = NULL, *home = NULL;
                uid_t uid = (uid_t) -1;
                gid_t gid = (gid_t) -1;
                char **our_env = NULL, **pam_env = NULL, **final_env = NULL, **final_argv = NULL;
                unsigned n_env = 0;
                int saved_stdout = -1, saved_stdin = -1;
                bool keep_stdout = false, keep_stdin = false;

                /* child */

                /* This string must fit in 10 chars (i.e. the length
                 * of "/sbin/init") */
                rename_process("sd:exec");

                /* We reset exactly these signals, since they are the
                 * only ones we set to SIG_IGN in the main daemon. All
                 * others we leave untouched because we set them to
                 * SIG_DFL or a valid handler initially, both of which
                 * will be demoted to SIG_DFL. */
                default_signals(SIGNALS_CRASH_HANDLER,
                                SIGNALS_IGNORE, -1);

                if (sigemptyset(&ss) < 0 ||
                    sigprocmask(SIG_SETMASK, &ss, NULL) < 0) {
                        r = EXIT_SIGNAL_MASK;
                        goto fail;
                }

                /* Close sockets very early to make sure we don' block
                 * init reexecution because it cannot bind its sockets
                 * or so */
                if (close_all_fds(fds, n_fds) < 0) {
                        r = EXIT_FDS;
                        goto fail;
                }

                if (!context->same_pgrp)
                        if (setsid() < 0) {
                                r = EXIT_SETSID;
                                goto fail;
                        }

                if (context->tcpwrap_name) {
                        if (socket_fd >= 0)
                                if (!socket_tcpwrap(socket_fd, context->tcpwrap_name)) {
                                        r = EXIT_TCPWRAP;
                                        goto fail;
                                }

                        for (i = 0; i < (int) n_fds; i++) {
                                if (!socket_tcpwrap(fds[i], context->tcpwrap_name)) {
                                        r = EXIT_TCPWRAP;
                                        goto fail;
                                }
                        }
                }

                /* We skip the confirmation step if we shall not apply the TTY */
                if (confirm_spawn &&
                    (!is_terminal_input(context->std_input) || apply_tty_stdin)) {
                        char response;

                        /* Set up terminal for the question */
                        if ((r = setup_confirm_stdio(context,
                                                     &saved_stdin, &saved_stdout)))
                                goto fail;

                        /* Now ask the question. */
                        if (!(line = exec_command_line(argv))) {
                                r = EXIT_MEMORY;
                                goto fail;
                        }

                        r = ask(&response, "yns", "Execute %s? [Yes, No, Skip] ", line);
                        free(line);

                        if (r < 0 || response == 'n') {
                                r = EXIT_CONFIRM;
                                goto fail;
                        } else if (response == 's') {
                                r = 0;
                                goto fail;
                        }

                        /* Release terminal for the question */
                        if ((r = restore_confirm_stdio(context,
                                                       &saved_stdin, &saved_stdout,
                                                       &keep_stdin, &keep_stdout)))
                                goto fail;
                }

                if (!keep_stdin)
                        if (setup_input(context, socket_fd, apply_tty_stdin) < 0) {
                                r = EXIT_STDIN;
                                goto fail;
                        }

                if (!keep_stdout)
                        if (setup_output(context, socket_fd, file_name_from_path(command->path), apply_tty_stdin) < 0) {
                                r = EXIT_STDOUT;
                                goto fail;
                        }

                if (setup_error(context, socket_fd, file_name_from_path(command->path), apply_tty_stdin) < 0) {
                        r = EXIT_STDERR;
                        goto fail;
                }

                if (cgroup_bondings)
                        if ((r = cgroup_bonding_install_list(cgroup_bondings, 0)) < 0) {
                                r = EXIT_CGROUP;
                                goto fail;
                        }

                if (context->oom_adjust_set) {
                        char t[16];

                        snprintf(t, sizeof(t), "%i", context->oom_adjust);
                        char_array_0(t);

                        if (write_one_line_file("/proc/self/oom_adj", t) < 0) {
                                r = EXIT_OOM_ADJUST;
                                goto fail;
                        }
                }

                if (context->nice_set)
                        if (setpriority(PRIO_PROCESS, 0, context->nice) < 0) {
                                r = EXIT_NICE;
                                goto fail;
                        }

                if (context->cpu_sched_set) {
                        struct sched_param param;

                        zero(param);
                        param.sched_priority = context->cpu_sched_priority;

                        if (sched_setscheduler(0, context->cpu_sched_policy |
                                               (context->cpu_sched_reset_on_fork ? SCHED_RESET_ON_FORK : 0), &param) < 0) {
                                r = EXIT_SETSCHEDULER;
                                goto fail;
                        }
                }

                if (context->cpuset)
                        if (sched_setaffinity(0, CPU_ALLOC_SIZE(context->cpuset_ncpus), context->cpuset) < 0) {
                                r = EXIT_CPUAFFINITY;
                                goto fail;
                        }

                if (context->ioprio_set)
                        if (ioprio_set(IOPRIO_WHO_PROCESS, 0, context->ioprio) < 0) {
                                r = EXIT_IOPRIO;
                                goto fail;
                        }

                if (context->timer_slack_nsec_set)
                        if (prctl(PR_SET_TIMERSLACK, context->timer_slack_nsec) < 0) {
                                r = EXIT_TIMERSLACK;
                                goto fail;
                        }

                if (context->user) {
                        username = context->user;
                        if (get_user_creds(&username, &uid, &gid, &home) < 0) {
                                r = EXIT_USER;
                                goto fail;
                        }

                        if (is_terminal_input(context->std_input))
                                if (chown_terminal(STDIN_FILENO, uid) < 0) {
                                        r = EXIT_STDIN;
                                        goto fail;
                                }
                }

#ifdef HAVE_PAM
                if (context->pam_name && username) {
                        if (setup_pam(context->pam_name, username, context->tty_path, &pam_env, fds, n_fds) < 0) {
                                r = EXIT_PAM;
                                goto fail;
                        }
                }
#endif

                if (apply_permissions)
                        if (enforce_groups(context, username, uid) < 0) {
                                r = EXIT_GROUP;
                                goto fail;
                        }

                umask(context->umask);

                if (strv_length(context->read_write_dirs) > 0 ||
                    strv_length(context->read_only_dirs) > 0 ||
                    strv_length(context->inaccessible_dirs) > 0 ||
                    context->mount_flags != MS_SHARED ||
                    context->private_tmp)
                        if ((r = setup_namespace(
                                             context->read_write_dirs,
                                             context->read_only_dirs,
                                             context->inaccessible_dirs,
                                             context->private_tmp,
                                             context->mount_flags)) < 0)
                                goto fail;

                if (apply_chroot) {
                        if (context->root_directory)
                                if (chroot(context->root_directory) < 0) {
                                        r = EXIT_CHROOT;
                                        goto fail;
                                }

                        if (chdir(context->working_directory ? context->working_directory : "/") < 0) {
                                r = EXIT_CHDIR;
                                goto fail;
                        }
                } else {

                        char *d;

                        if (asprintf(&d, "%s/%s",
                                     context->root_directory ? context->root_directory : "",
                                     context->working_directory ? context->working_directory : "") < 0) {
                                r = EXIT_MEMORY;
                                goto fail;
                        }

                        if (chdir(d) < 0) {
                                free(d);
                                r = EXIT_CHDIR;
                                goto fail;
                        }

                        free(d);
                }

                /* We repeat the fd closing here, to make sure that
                 * nothing is leaked from the PAM modules */
                if (close_all_fds(fds, n_fds) < 0 ||
                    shift_fds(fds, n_fds) < 0 ||
                    flags_fds(fds, n_fds, context->non_blocking) < 0) {
                        r = EXIT_FDS;
                        goto fail;
                }

                if (apply_permissions) {

                        for (i = 0; i < RLIMIT_NLIMITS; i++) {
                                if (!context->rlimit[i])
                                        continue;

                                if (setrlimit(i, context->rlimit[i]) < 0) {
                                        r = EXIT_LIMITS;
                                        goto fail;
                                }
                        }

                        if (context->user)
                                if (enforce_user(context, uid) < 0) {
                                        r = EXIT_USER;
                                        goto fail;
                                }

                        /* PR_GET_SECUREBITS is not priviliged, while
                         * PR_SET_SECUREBITS is. So to suppress
                         * potential EPERMs we'll try not to call
                         * PR_SET_SECUREBITS unless necessary. */
                        if (prctl(PR_GET_SECUREBITS) != context->secure_bits)
                                if (prctl(PR_SET_SECUREBITS, context->secure_bits) < 0) {
                                        r = EXIT_SECUREBITS;
                                        goto fail;
                                }

                        if (context->capabilities)
                                if (cap_set_proc(context->capabilities) < 0) {
                                        r = EXIT_CAPABILITIES;
                                        goto fail;
                                }
                }

                if (!(our_env = new0(char*, 6))) {
                        r = EXIT_MEMORY;
                        goto fail;
                }

                if (n_fds > 0)
                        if (asprintf(our_env + n_env++, "LISTEN_PID=%lu", (unsigned long) getpid()) < 0 ||
                            asprintf(our_env + n_env++, "LISTEN_FDS=%u", n_fds) < 0) {
                                r = EXIT_MEMORY;
                                goto fail;
                        }

                if (home)
                        if (asprintf(our_env + n_env++, "HOME=%s", home) < 0) {
                                r = EXIT_MEMORY;
                                goto fail;
                        }

                if (username)
                        if (asprintf(our_env + n_env++, "LOGNAME=%s", username) < 0 ||
                            asprintf(our_env + n_env++, "USER=%s", username) < 0) {
                                r = EXIT_MEMORY;
                                goto fail;
                        }

                assert(n_env <= 6);

                if (!(final_env = strv_env_merge(
                                      4,
                                      environment,
                                      our_env,
                                      context->environment,
                                      pam_env,
                                      NULL))) {
                        r = EXIT_MEMORY;
                        goto fail;
                }

                if (!(final_argv = replace_env_argv(argv, final_env))) {
                        r = EXIT_MEMORY;
                        goto fail;
                }

                execve(command->path, final_argv, final_env);
                r = EXIT_EXEC;

        fail:
                strv_free(our_env);
                strv_free(final_env);
                strv_free(pam_env);
                strv_free(final_argv);

                if (saved_stdin >= 0)
                        close_nointr_nofail(saved_stdin);

                if (saved_stdout >= 0)
                        close_nointr_nofail(saved_stdout);

                _exit(r);
        }

        /* We add the new process to the cgroup both in the child (so
         * that we can be sure that no user code is ever executed
         * outside of the cgroup) and in the parent (so that we can be
         * sure that when we kill the cgroup the process will be
         * killed too). */
        if (cgroup_bondings)
                cgroup_bonding_install_list(cgroup_bondings, pid);

        log_debug("Forked %s as %lu", command->path, (unsigned long) pid);

        exec_status_start(&command->exec_status, pid);

        *ret = pid;
        return 0;
}

void exec_context_init(ExecContext *c) {
        assert(c);

        c->umask = 0002;
        c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0);
        c->cpu_sched_policy = SCHED_OTHER;
        c->syslog_priority = LOG_DAEMON|LOG_INFO;
        c->syslog_level_prefix = true;
        c->mount_flags = MS_SHARED;
        c->kill_signal = SIGTERM;
}

void exec_context_done(ExecContext *c) {
        unsigned l;

        assert(c);

        strv_free(c->environment);
        c->environment = NULL;

        for (l = 0; l < ELEMENTSOF(c->rlimit); l++) {
                free(c->rlimit[l]);
                c->rlimit[l] = NULL;
        }

        free(c->working_directory);
        c->working_directory = NULL;
        free(c->root_directory);
        c->root_directory = NULL;

        free(c->tty_path);
        c->tty_path = NULL;

        free(c->tcpwrap_name);
        c->tcpwrap_name = NULL;

        free(c->syslog_identifier);
        c->syslog_identifier = NULL;

        free(c->user);
        c->user = NULL;

        free(c->group);
        c->group = NULL;

        strv_free(c->supplementary_groups);
        c->supplementary_groups = NULL;

        free(c->pam_name);
        c->pam_name = NULL;

        if (c->capabilities) {
                cap_free(c->capabilities);
                c->capabilities = NULL;
        }

        strv_free(c->read_only_dirs);
        c->read_only_dirs = NULL;

        strv_free(c->read_write_dirs);
        c->read_write_dirs = NULL;

        strv_free(c->inaccessible_dirs);
        c->inaccessible_dirs = NULL;

        if (c->cpuset)
                CPU_FREE(c->cpuset);
}

void exec_command_done(ExecCommand *c) {
        assert(c);

        free(c->path);
        c->path = NULL;

        strv_free(c->argv);
        c->argv = NULL;
}

void exec_command_done_array(ExecCommand *c, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++)
                exec_command_done(c+i);
}

void exec_command_free_list(ExecCommand *c) {
        ExecCommand *i;

        while ((i = c)) {
                LIST_REMOVE(ExecCommand, command, c, i);
                exec_command_done(i);
                free(i);
        }
}

void exec_command_free_array(ExecCommand **c, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++) {
                exec_command_free_list(c[i]);
                c[i] = NULL;
        }
}

static void strv_fprintf(FILE *f, char **l) {
        char **g;

        assert(f);

        STRV_FOREACH(g, l)
                fprintf(f, " %s", *g);
}

void exec_context_dump(ExecContext *c, FILE* f, const char *prefix) {
        char ** e;
        unsigned i;

        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sUMask: %04o\n"
                "%sWorkingDirectory: %s\n"
                "%sRootDirectory: %s\n"
                "%sNonBlocking: %s\n"
                "%sPrivateTmp: %s\n",
                prefix, c->umask,
                prefix, c->working_directory ? c->working_directory : "/",
                prefix, c->root_directory ? c->root_directory : "/",
                prefix, yes_no(c->non_blocking),
                prefix, yes_no(c->private_tmp));

        if (c->environment)
                for (e = c->environment; *e; e++)
                        fprintf(f, "%sEnvironment: %s\n", prefix, *e);

        if (c->tcpwrap_name)
                fprintf(f,
                        "%sTCPWrapName: %s\n",
                        prefix, c->tcpwrap_name);

        if (c->nice_set)
                fprintf(f,
                        "%sNice: %i\n",
                        prefix, c->nice);

        if (c->oom_adjust_set)
                fprintf(f,
                        "%sOOMAdjust: %i\n",
                        prefix, c->oom_adjust);

        for (i = 0; i < RLIM_NLIMITS; i++)
                if (c->rlimit[i])
                        fprintf(f, "%s%s: %llu\n", prefix, rlimit_to_string(i), (unsigned long long) c->rlimit[i]->rlim_max);

        if (c->ioprio_set)
                fprintf(f,
                        "%sIOSchedulingClass: %s\n"
                        "%sIOPriority: %i\n",
                        prefix, ioprio_class_to_string(IOPRIO_PRIO_CLASS(c->ioprio)),
                        prefix, (int) IOPRIO_PRIO_DATA(c->ioprio));

        if (c->cpu_sched_set)
                fprintf(f,
                        "%sCPUSchedulingPolicy: %s\n"
                        "%sCPUSchedulingPriority: %i\n"
                        "%sCPUSchedulingResetOnFork: %s\n",
                        prefix, sched_policy_to_string(c->cpu_sched_policy),
                        prefix, c->cpu_sched_priority,
                        prefix, yes_no(c->cpu_sched_reset_on_fork));

        if (c->cpuset) {
                fprintf(f, "%sCPUAffinity:", prefix);
                for (i = 0; i < c->cpuset_ncpus; i++)
                        if (CPU_ISSET_S(i, CPU_ALLOC_SIZE(c->cpuset_ncpus), c->cpuset))
                                fprintf(f, " %i", i);
                fputs("\n", f);
        }

        if (c->timer_slack_nsec_set)
                fprintf(f, "%sTimerSlackNSec: %lu\n", prefix, c->timer_slack_nsec);

        fprintf(f,
                "%sStandardInput: %s\n"
                "%sStandardOutput: %s\n"
                "%sStandardError: %s\n",
                prefix, exec_input_to_string(c->std_input),
                prefix, exec_output_to_string(c->std_output),
                prefix, exec_output_to_string(c->std_error));

        if (c->tty_path)
                fprintf(f,
                        "%sTTYPath: %s\n",
                        prefix, c->tty_path);

        if (c->std_output == EXEC_OUTPUT_SYSLOG || c->std_output == EXEC_OUTPUT_KMSG ||
            c->std_error == EXEC_OUTPUT_SYSLOG || c->std_error == EXEC_OUTPUT_KMSG)
                fprintf(f,
                        "%sSyslogFacility: %s\n"
                        "%sSyslogLevel: %s\n",
                        prefix, log_facility_to_string(LOG_FAC(c->syslog_priority)),
                        prefix, log_level_to_string(LOG_PRI(c->syslog_priority)));

        if (c->capabilities) {
                char *t;
                if ((t = cap_to_text(c->capabilities, NULL))) {
                        fprintf(f, "%sCapabilities: %s\n",
                                prefix, t);
                        cap_free(t);
                }
        }

        if (c->secure_bits)
                fprintf(f, "%sSecure Bits:%s%s%s%s%s%s\n",
                        prefix,
                        (c->secure_bits & SECURE_KEEP_CAPS) ? " keep-caps" : "",
                        (c->secure_bits & SECURE_KEEP_CAPS_LOCKED) ? " keep-caps-locked" : "",
                        (c->secure_bits & SECURE_NO_SETUID_FIXUP) ? " no-setuid-fixup" : "",
                        (c->secure_bits & SECURE_NO_SETUID_FIXUP_LOCKED) ? " no-setuid-fixup-locked" : "",
                        (c->secure_bits & SECURE_NOROOT) ? " noroot" : "",
                        (c->secure_bits & SECURE_NOROOT_LOCKED) ? "noroot-locked" : "");

        if (c->capability_bounding_set_drop) {
                fprintf(f, "%sCapabilityBoundingSetDrop:", prefix);

                for (i = 0; i <= CAP_LAST_CAP; i++)
                        if (c->capability_bounding_set_drop & (1 << i)) {
                                char *t;

                                if ((t = cap_to_name(i))) {
                                        fprintf(f, " %s", t);
                                        free(t);
                                }
                        }

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

        fprintf(f,
                "%sKillMode: %s\n"
                "%sKillSignal: SIG%s\n",
                prefix, kill_mode_to_string(c->kill_mode),
                prefix, signal_to_string(c->kill_signal));
}

void exec_status_start(ExecStatus *s, pid_t pid) {
        assert(s);

        zero(*s);
        s->pid = pid;
        dual_timestamp_get(&s->start_timestamp);
}

void exec_status_exit(ExecStatus *s, pid_t pid, int code, int status) {
        assert(s);

        if ((s->pid && s->pid != pid) ||
            !s->start_timestamp.realtime <= 0)
                zero(*s);

        s->pid = pid;
        dual_timestamp_get(&s->exit_timestamp);

        s->code = code;
        s->status = status;
}

void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix) {
        char buf[FORMAT_TIMESTAMP_MAX];

        assert(s);
        assert(f);

        if (!prefix)
                prefix = "";

        if (s->pid <= 0)
                return;

        fprintf(f,
                "%sPID: %lu\n",
                prefix, (unsigned long) s->pid);

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
        char *p2;
        const char *prefix2;

        char *cmd;

        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";
        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        cmd = exec_command_line(c->argv);

        fprintf(f,
                "%sCommand Line: %s\n",
                prefix, cmd ? cmd : strerror(ENOMEM));

        free(cmd);

        exec_status_dump(&c->exec_status, f, prefix2);

        free(p2);
}

void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix) {
        assert(f);

        if (!prefix)
                prefix = "";

        LIST_FOREACH(command, c, c)
                exec_command_dump(c, f, prefix);
}

void exec_command_append_list(ExecCommand **l, ExecCommand *e) {
        ExecCommand *end;

        assert(l);
        assert(e);

        if (*l) {
                /* It's kinda important that we keep the order here */
                LIST_FIND_TAIL(ExecCommand, command, *l, end);
                LIST_INSERT_AFTER(ExecCommand, command, *l, end, e);
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

        if (!(p = strdup(path))) {
                strv_free(l);
                return -ENOMEM;
        }

        free(c->path);
        c->path = p;

        strv_free(c->argv);
        c->argv = l;

        return 0;
}

const char* exit_status_to_string(ExitStatus status) {

        /* We cast to int here, so that -Wenum doesn't complain that
         * EXIT_SUCCESS/EXIT_FAILURE aren't in the enum */

        switch ((int) status) {

        case EXIT_SUCCESS:
                return "SUCCESS";

        case EXIT_FAILURE:
                return "FAILURE";

        case EXIT_INVALIDARGUMENT:
                return "INVALIDARGUMENT";

        case EXIT_NOTIMPLEMENTED:
                return "NOTIMPLEMENTED";

        case EXIT_NOPERMISSION:
                return "NOPERMISSION";

        case EXIT_NOTINSTALLED:
                return "NOTINSSTALLED";

        case EXIT_NOTCONFIGURED:
                return "NOTCONFIGURED";

        case EXIT_NOTRUNNING:
                return "NOTRUNNING";

        case EXIT_CHDIR:
                return "CHDIR";

        case EXIT_NICE:
                return "NICE";

        case EXIT_FDS:
                return "FDS";

        case EXIT_EXEC:
                return "EXEC";

        case EXIT_MEMORY:
                return "MEMORY";

        case EXIT_LIMITS:
                return "LIMITS";

        case EXIT_OOM_ADJUST:
                return "OOM_ADJUST";

        case EXIT_SIGNAL_MASK:
                return "SIGNAL_MASK";

        case EXIT_STDIN:
                return "STDIN";

        case EXIT_STDOUT:
                return "STDOUT";

        case EXIT_CHROOT:
                return "CHROOT";

        case EXIT_IOPRIO:
                return "IOPRIO";

        case EXIT_TIMERSLACK:
                return "TIMERSLACK";

        case EXIT_SECUREBITS:
                return "SECUREBITS";

        case EXIT_SETSCHEDULER:
                return "SETSCHEDULER";

        case EXIT_CPUAFFINITY:
                return "CPUAFFINITY";

        case EXIT_GROUP:
                return "GROUP";

        case EXIT_USER:
                return "USER";

        case EXIT_CAPABILITIES:
                return "CAPABILITIES";

        case EXIT_CGROUP:
                return "CGROUP";

        case EXIT_SETSID:
                return "SETSID";

        case EXIT_CONFIRM:
                return "CONFIRM";

        case EXIT_STDERR:
                return "STDERR";

        case EXIT_TCPWRAP:
                return "TCPWRAP";

        case EXIT_PAM:
                return "PAM";

        default:
                return NULL;
        }
}

static const char* const exec_input_table[_EXEC_INPUT_MAX] = {
        [EXEC_INPUT_NULL] = "null",
        [EXEC_INPUT_TTY] = "tty",
        [EXEC_INPUT_TTY_FORCE] = "tty-force",
        [EXEC_INPUT_TTY_FAIL] = "tty-fail",
        [EXEC_INPUT_SOCKET] = "socket"
};

static const char* const exec_output_table[_EXEC_OUTPUT_MAX] = {
        [EXEC_OUTPUT_INHERIT] = "inherit",
        [EXEC_OUTPUT_NULL] = "null",
        [EXEC_OUTPUT_TTY] = "tty",
        [EXEC_OUTPUT_SYSLOG] = "syslog",
        [EXEC_OUTPUT_KMSG] = "kmsg",
        [EXEC_OUTPUT_SOCKET] = "socket"
};

DEFINE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

DEFINE_STRING_TABLE_LOOKUP(exec_input, ExecInput);
