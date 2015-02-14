/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <getopt.h>

#include "systemd/sd-daemon.h"

#include "socket-util.h"
#include "build.h"
#include "log.h"
#include "strv.h"
#include "macro.h"

static char** arg_listen = NULL;
static bool arg_accept = false;
static char** arg_args = NULL;
static char** arg_setenv = NULL;

static int add_epoll(int epoll_fd, int fd) {
        struct epoll_event ev = {
                .events = EPOLLIN
        };
        int r;

        assert(epoll_fd >= 0);
        assert(fd >= 0);

        ev.data.fd = fd;
        r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0)
                return log_error_errno(errno, "Failed to add event on epoll fd:%d for fd:%d: %m", epoll_fd, fd);

        return 0;
}

static int open_sockets(int *epoll_fd, bool accept) {
        char **address;
        int n, fd, r;
        int count = 0;

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");
        if (n > 0) {
                log_info("Received %i descriptors via the environment.", n);

                for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                        r = fd_cloexec(fd, arg_accept);
                        if (r < 0)
                                return r;

                        count ++;
                }
        }

        /* Close logging and all other descriptors */
        if (arg_listen) {
                int except[3 + n];

                for (fd = 0; fd < SD_LISTEN_FDS_START + n; fd++)
                        except[fd] = fd;

                log_close();
                close_all_fds(except, 3 + n);
        }

        /** Note: we leak some fd's on error here. I doesn't matter
         *  much, since the program will exit immediately anyway, but
         *  would be a pain to fix.
         */

        STRV_FOREACH(address, arg_listen) {

                fd = make_socket_fd(LOG_DEBUG, *address, SOCK_STREAM | (arg_accept*SOCK_CLOEXEC));
                if (fd < 0) {
                        log_open();
                        return log_error_errno(fd, "Failed to open '%s': %m", *address);
                }

                assert(fd == SD_LISTEN_FDS_START + count);
                count ++;
        }

        if (arg_listen)
                log_open();

        *epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (*epoll_fd < 0)
                return log_error_errno(errno, "Failed to create epoll object: %m");

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + count; fd++) {
                _cleanup_free_ char *name = NULL;

                getsockname_pretty(fd, &name);
                log_info("Listening on %s as %i.", strna(name), fd);

                r = add_epoll(*epoll_fd, fd);
                if (r < 0)
                        return r;
        }

        return count;
}

static int launch(char* name, char **argv, char **env, int fds) {

        static const char* tocopy[] = {"TERM=", "PATH=", "USER=", "HOME="};
        _cleanup_strv_free_ char **envp = NULL;
        _cleanup_free_ char *tmp = NULL;
        unsigned n_env = 0, length;
        char **s;
        unsigned i;

        length = strv_length(arg_setenv);

        /* PATH, TERM, HOME, USER, LISTEN_FDS, LISTEN_PID, NULL */
        envp = new0(char *, length + 7);
        if (!envp)
                return log_oom();

        STRV_FOREACH(s, arg_setenv) {
                if (strchr(*s, '='))
                        envp[n_env++] = *s;
                else {
                        _cleanup_free_ char *p = strappend(*s, "=");
                        if (!p)
                                return log_oom();
                        envp[n_env] = strv_find_prefix(env, p);
                        if (envp[n_env])
                                n_env ++;
                }
        }

        for (i = 0; i < ELEMENTSOF(tocopy); i++) {
                envp[n_env] = strv_find_prefix(env, tocopy[i]);
                if (envp[n_env])
                        n_env ++;
        }

        if ((asprintf((char**)(envp + n_env++), "LISTEN_FDS=%d", fds) < 0) ||
            (asprintf((char**)(envp + n_env++), "LISTEN_PID=%d", getpid()) < 0))
                return log_oom();

        tmp = strv_join(argv, " ");
        if (!tmp)
                return log_oom();

        log_info("Execing %s (%s)", name, tmp);
        execvpe(name, argv, envp);
        log_error_errno(errno, "Failed to execp %s (%s): %m", name, tmp);

        return -errno;
}

static int launch1(const char* child, char** argv, char **env, int fd) {
        _cleanup_free_ char *tmp = NULL;
        pid_t parent_pid, child_pid;
        int r;

        tmp = strv_join(argv, " ");
        if (!tmp)
                return log_oom();

        parent_pid = getpid();

        child_pid = fork();
        if (child_pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");

        /* In the child */
        if (child_pid == 0) {
                r = dup2(fd, STDIN_FILENO);
                if (r < 0) {
                        log_error_errno(errno, "Failed to dup connection to stdin: %m");
                        _exit(EXIT_FAILURE);
                }

                r = dup2(fd, STDOUT_FILENO);
                if (r < 0) {
                        log_error_errno(errno, "Failed to dup connection to stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                r = close(fd);
                if (r < 0) {
                        log_error_errno(errno, "Failed to close dupped connection: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Make sure the child goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                execvp(child, argv);
                log_error_errno(errno, "Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        log_info("Spawned %s (%s) as PID %d", child, tmp, child_pid);

        return 0;
}

static int do_accept(const char* name, char **argv, char **envp, int fd) {
        _cleanup_free_ char *local = NULL, *peer = NULL;
        _cleanup_close_ int fd2 = -1;

        fd2 = accept(fd, NULL, NULL);
        if (fd2 < 0) {
                log_error_errno(errno, "Failed to accept connection on fd:%d: %m", fd);
                return fd2;
        }

        getsockname_pretty(fd2, &local);
        getpeername_pretty(fd2, &peer);
        log_info("Connection from %s to %s", strna(peer), strna(local));

        return launch1(name, argv, envp, fd2);
}

/* SIGCHLD handler. */
static void sigchld_hdl(int sig, siginfo_t *t, void *data) {
        PROTECT_ERRNO;

        log_info("Child %d died with code %d", t->si_pid, t->si_status);
        /* Wait for a dead child. */
        waitpid(t->si_pid, NULL, 0);
}

static int install_chld_handler(void) {
        int r;
        struct sigaction act = {
                .sa_flags = SA_SIGINFO,
                .sa_sigaction = sigchld_hdl,
        };

        r = sigaction(SIGCHLD, &act, 0);
        if (r < 0)
                log_error_errno(errno, "Failed to install SIGCHLD handler: %m");
        return r;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Listen on sockets and launch child on connection.\n\n"
               "Options:\n"
               "  -l --listen=ADDR         Listen for raw connections at ADDR\n"
               "  -a --accept              Spawn separate child for each connection\n"
               "  -h --help                Show this help and exit\n"
               "  -E --setenv=NAME[=VALUE] Pass an environment variable to children\n"
               "  --version                Print version string and exit\n"
               "\n"
               "Note: file descriptors from sd_listen_fds() will be passed through.\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'           },
                { "version",     no_argument,       NULL, ARG_VERSION   },
                { "listen",      required_argument, NULL, 'l'           },
                { "accept",      no_argument,       NULL, 'a'           },
                { "setenv",      required_argument, NULL, 'E'           },
                { "environment", required_argument, NULL, 'E'           }, /* alias */
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hl:aE:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case 'l': {
                        int r = strv_extend(&arg_listen, optarg);
                        if (r < 0)
                                return r;

                        break;
                }

                case 'a':
                        arg_accept = true;
                        break;

                case 'E': {
                        int r = strv_extend(&arg_setenv, optarg);
                        if (r < 0)
                                return r;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind == argc) {
                log_error("%s: command to execute is missing.",
                          program_invocation_short_name);
                return -EINVAL;
        }

        arg_args = argv + optind;

        return 1 /* work to do */;
}

int main(int argc, char **argv, char **envp) {
        int r, n;
        int epoll_fd = -1;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

        r = install_chld_handler();
        if (r < 0)
                return EXIT_FAILURE;

        n = open_sockets(&epoll_fd, arg_accept);
        if (n < 0)
                return EXIT_FAILURE;
        if (n == 0) {
                log_error("No sockets to listen on specified or passed in.");
                return EXIT_FAILURE;
        }

        for (;;) {
                struct epoll_event event;

                r = epoll_wait(epoll_fd, &event, 1, -1);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;

                        log_error_errno(errno, "epoll_wait() failed: %m");
                        return EXIT_FAILURE;
                }

                log_info("Communication attempt on fd %i.", event.data.fd);
                if (arg_accept) {
                        r = do_accept(argv[optind], argv + optind, envp,
                                      event.data.fd);
                        if (r < 0)
                                return EXIT_FAILURE;
                } else
                        break;
        }

        launch(argv[optind], argv + optind, envp, n);

        return EXIT_SUCCESS;
}
