/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static char **arg_listen = NULL;
static bool arg_accept = false;
static int arg_socket_type = SOCK_STREAM;
static char **arg_args = NULL;
static char **arg_setenv = NULL;
static char **arg_fdnames = NULL;
static bool arg_inetd = false;

static int add_epoll(int epoll_fd, int fd) {
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.fd = fd,
        };

        assert(epoll_fd >= 0);
        assert(fd >= 0);

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                return log_error_errno(errno, "Failed to add event on epoll fd:%d for fd:%d: %m", epoll_fd, fd);

        return 0;
}

static int open_sockets(int *ret_epoll_fd, bool accept) {
        _cleanup_close_ int epoll_fd = -EBADF;
        int n, r, count = 0;

        assert(ret_epoll_fd);

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");
        if (n > 0) {
                log_info("Received %i descriptors via the environment.", n);

                for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                        r = fd_cloexec(fd, arg_accept);
                        if (r < 0)
                                return r;

                        count++;
                }
        }

        /* Close logging and all other descriptors */
        if (arg_listen) {
                _cleanup_free_ int *except = new(int, n);
                if (!except)
                        return log_oom();

                for (int i = 0; i < n; i++)
                        except[i] = SD_LISTEN_FDS_START + i;

                log_close();
                log_set_open_when_needed(true);
                log_settle_target();

                r = close_all_fds(except, n);
                if (r < 0)
                        return log_error_errno(r, "Failed to close all file descriptors: %m");
        }

        /* Note: we leak some fd's on error here. It doesn't matter much, since the program will exit
         * immediately anyway, but would be a pain to fix. */

        STRV_FOREACH(address, arg_listen) {
                r = make_socket_fd(LOG_DEBUG, *address, arg_socket_type, (arg_accept * SOCK_CLOEXEC));
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", *address);

                assert(r == SD_LISTEN_FDS_START + count);
                count++;
        }

        if (arg_listen) {
                log_open();
                log_set_open_when_needed(false);
        }

        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd < 0)
                return log_error_errno(errno, "Failed to create epoll object: %m");

        for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + count; fd++) {
                _cleanup_free_ char *name = NULL;

                getsockname_pretty(fd, &name);
                log_info("Listening on %s as %i.", strna(name), fd);

                r = add_epoll(epoll_fd, fd);
                if (r < 0)
                        return r;
        }

        *ret_epoll_fd = TAKE_FD(epoll_fd);
        return count;
}

static int exec_process(const char *name, char **argv, int start_fd, size_t n_fds) {
        _cleanup_strv_free_ char **envp = NULL;
        int r;

        if (arg_inetd && n_fds != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--inetd only supported for single file descriptors.");

        FOREACH_STRING(var, "TERM", "PATH", "USER", "HOME") {
                const char *n;

                n = strv_find_prefix(environ, var);
                if (!n)
                        continue;

                r = strv_extend(&envp, n);
                if (r < 0)
                        return r;
        }

        if (arg_inetd) {
                assert(n_fds == 1);

                r = rearrange_stdio(start_fd, start_fd, STDERR_FILENO); /* invalidates start_fd on success + error */
                if (r < 0)
                        return log_error_errno(r, "Failed to move fd to stdin+stdout: %m");

        } else {
                if (start_fd != SD_LISTEN_FDS_START) {
                        assert(n_fds == 1);

                        if (dup2(start_fd, SD_LISTEN_FDS_START) < 0)
                                return log_error_errno(errno, "Failed to dup connection: %m");

                        safe_close(start_fd);
                }

                r = strv_extendf(&envp, "LISTEN_FDS=%zu", n_fds);
                if (r < 0)
                        return r;

                r = strv_extendf(&envp, "LISTEN_PID=" PID_FMT, getpid_cached());
                if (r < 0)
                        return r;

                if (arg_fdnames) {
                        _cleanup_free_ char *names = NULL;
                        size_t len;

                        len = strv_length(arg_fdnames);
                        if (len == 1)
                                for (size_t i = 1; i < n_fds; i++) {
                                        r = strv_extend(&arg_fdnames, arg_fdnames[0]);
                                        if (r < 0)
                                                return log_oom();
                                }
                        else if (len != n_fds)
                                log_warning("The number of fd names is different than number of fds: %zu vs %zu", len, n_fds);

                        names = strv_join(arg_fdnames, ":");
                        if (!names)
                                return log_oom();

                        char *t = strjoin("LISTEN_FDNAMES=", names);
                        if (!t)
                                return log_oom();

                        r = strv_consume(&envp, t);
                        if (r < 0)
                                return r;
                }
        }

        STRV_FOREACH(s, arg_setenv) {
                r = strv_env_replace_strdup(&envp, *s);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *joined = strv_join(argv, " ");
        if (!joined)
                return log_oom();

        log_info("Execing %s (%s)", name, joined);
        execvpe(name, argv, envp);

        return log_error_errno(errno, "Failed to execp %s (%s): %m", name, joined);
}

static int fork_and_exec_process(const char *child, char **argv, int fd) {
        _cleanup_free_ char *joined = NULL;
        pid_t child_pid;
        int r;

        joined = strv_join(argv, " ");
        if (!joined)
                return log_oom();

        r = safe_fork("(activate)",
                      FORK_RESET_SIGNALS | FORK_DEATHSIG_SIGTERM | FORK_RLIMIT_NOFILE_SAFE | FORK_LOG,
                      &child_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* In the child */
                exec_process(child, argv, fd, 1);
                _exit(EXIT_FAILURE);
        }

        log_info("Spawned %s (%s) as PID " PID_FMT ".", child, joined, child_pid);
        return 0;
}

static int do_accept(const char *name, char **argv, int fd) {
        _cleanup_free_ char *local = NULL, *peer = NULL;
        _cleanup_close_ int fd_accepted = -EBADF;

        fd_accepted = accept4(fd, NULL, NULL, 0);
        if (fd_accepted < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return log_error_errno(errno, "Failed to accept connection on fd:%d: %m", fd);
        }

        (void) getsockname_pretty(fd_accepted, &local);
        (void) getpeername_pretty(fd_accepted, true, &peer);
        log_info("Connection from %s to %s", strna(peer), strna(local));

        return fork_and_exec_process(name, argv, fd_accepted);
}

/* SIGCHLD handler. */
static void sigchld_hdl(int sig) {
        PROTECT_ERRNO;

        for (;;) {
                siginfo_t si;
                int r;

                si.si_pid = 0;
                r = waitid(P_ALL, 0, &si, WEXITED | WNOHANG);
                if (r < 0) {
                        if (errno != ECHILD)
                                log_error_errno(errno, "Failed to reap children: %m");
                        return;
                }
                if (si.si_pid == 0)
                        return;

                log_info("Child %d died with code %d", si.si_pid, si.si_status);
        }
}

static int install_chld_handler(void) {
        static const struct sigaction act = {
                .sa_flags = SA_NOCLDSTOP | SA_RESTART,
                .sa_handler = sigchld_hdl,
        };

        if (sigaction(SIGCHLD, &act, NULL) < 0)
                return log_error_errno(errno, "Failed to install SIGCHLD handler: %m");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-socket-activate", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n"
               "\n%sListen on sockets and launch child on connection.%s\n"
               "\nOptions:\n"
               "  -h --help                  Show this help and exit\n"
               "     --version               Print version string and exit\n"
               "  -l --listen=ADDR           Listen for raw connections at ADDR\n"
               "  -d --datagram              Listen on datagram instead of stream socket\n"
               "     --seqpacket             Listen on SOCK_SEQPACKET instead of stream socket\n"
               "  -a --accept                Spawn separate child for each connection\n"
               "  -E --setenv=NAME[=VALUE]   Pass an environment variable to children\n"
               "     --fdname=NAME[:NAME...] Specify names for file descriptors\n"
               "     --inetd                 Enable inetd file descriptor passing protocol\n"
               "\nNote: file descriptors from sd_listen_fds() will be passed through.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_FDNAME,
                ARG_SEQPACKET,
                ARG_INETD,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'           },
                { "version",     no_argument,       NULL, ARG_VERSION   },
                { "datagram",    no_argument,       NULL, 'd'           },
                { "seqpacket",   no_argument,       NULL, ARG_SEQPACKET },
                { "listen",      required_argument, NULL, 'l'           },
                { "accept",      no_argument,       NULL, 'a'           },
                { "setenv",      required_argument, NULL, 'E'           },
                { "environment", required_argument, NULL, 'E'           }, /* legacy alias */
                { "fdname",      required_argument, NULL, ARG_FDNAME    },
                { "inetd",       no_argument,       NULL, ARG_INETD     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "+hl:aE:d", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'l':
                        r = strv_extend(&arg_listen, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case 'd':
                        if (arg_socket_type == SOCK_SEQPACKET)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--datagram may not be combined with --seqpacket.");

                        arg_socket_type = SOCK_DGRAM;
                        break;

                case ARG_SEQPACKET:
                        if (arg_socket_type == SOCK_DGRAM)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--seqpacket may not be combined with --datagram.");

                        arg_socket_type = SOCK_SEQPACKET;
                        break;

                case 'a':
                        arg_accept = true;
                        break;

                case 'E':
                        r = strv_env_replace_strdup_passthrough(&arg_setenv, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);
                        break;

                case ARG_FDNAME: {
                        _cleanup_strv_free_ char **names = NULL;

                        names = strv_split(optarg, ":");
                        if (!names)
                                return log_oom();

                        STRV_FOREACH(s, names)
                                if (!fdname_is_valid(*s)) {
                                        _cleanup_free_ char *esc = NULL;

                                        esc = cescape(*s);
                                        log_warning("File descriptor name \"%s\" is not valid.", esc);
                                }

                        /* Empty optargs means one empty name */
                        r = strv_extend_strv(&arg_fdnames,
                                             strv_isempty(names) ? STRV_MAKE("") : names,
                                             false);
                        if (r < 0)
                                return log_error_errno(r, "strv_extend_strv: %m");
                        break;
                }

                case ARG_INETD:
                        arg_inetd = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind == argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: command to execute is missing.",
                                       program_invocation_short_name);

        if (arg_socket_type == SOCK_DGRAM && arg_accept)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Datagram sockets do not accept connections. "
                                       "The --datagram and --accept options may not be combined.");

        arg_args = argv + optind;

        return 1 /* work to do */;
}

static int run(int argc, char **argv) {
        _cleanup_close_ int epoll_fd = -EBADF;
        _cleanup_strv_free_ char **exec_argv = NULL;
        int r, n;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        exec_argv = strv_copy(arg_args);
        if (!exec_argv)
                return log_oom();

        assert(!strv_isempty(exec_argv));

        r = install_chld_handler();
        if (r < 0)
                return r;

        n = open_sockets(&epoll_fd, arg_accept);
        if (n < 0)
                return n;
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No sockets to listen on specified or passed in.");

        for (;;) {
                struct epoll_event event;

                if (epoll_wait(epoll_fd, &event, 1, -1) < 0) {
                        if (errno == EINTR)
                                continue;

                        return log_error_errno(errno, "epoll_wait() failed: %m");
                }

                log_info("Communication attempt on fd %i.", event.data.fd);
                if (arg_accept) {
                        r = do_accept(exec_argv[0], exec_argv, event.data.fd);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        return exec_process(exec_argv[0], exec_argv, SD_LISTEN_FDS_START, (size_t) n);
}

DEFINE_MAIN_FUNCTION(run);
