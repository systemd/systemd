/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <termios.h>
#include <limits.h>
#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "util.h"

static const char *arg_icon = NULL;
static const char *arg_message = NULL;
static bool arg_use_tty = true;
static usec_t arg_timeout = 60 * USEC_PER_SEC;

static int create_socket(char **name) {
        int fd;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;
        int one = 1, r;
        char *c;

        assert(name);

        if ((fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)) < 0) {
                log_error("socket() failed: %m");
                return -errno;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        snprintf(sa.un.sun_path, sizeof(sa.un.sun_path)-1, "/dev/.systemd/ask-password/sck.%llu", random_ull());

        if (bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                r = -errno;
                log_error("bind() failed: %m");
                goto fail;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
                r = -errno;
                log_error("SO_PASSCRED failed: %m");
                goto fail;
        }

        if (!(c = strdup(sa.un.sun_path))) {
                r = -ENOMEM;
                log_error("Out of memory");
                goto fail;
        }

        *name = c;
        return fd;

fail:
        close_nointr_nofail(fd);

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...] MESSAGE\n\n"
               "Query the user for a system passphrase, via the TTY or an UI agent.\n\n"
               "  -h --help         Show this help\n"
               "     --icon=NAME    Icon name\n"
               "     --timeout=SEC Timeout in sec\n"
               "     --no-tty       Ask question via agent even on TTY\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_ICON = 0x100,
                ARG_TIMEOUT,
                ARG_NO_TTY
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'         },
                { "icon",      required_argument, NULL, ARG_ICON    },
                { "timeout",   required_argument, NULL, ARG_TIMEOUT },
                { "no-tty",    no_argument,       NULL, ARG_NO_TTY  },
                { NULL,        0,                 NULL, 0           }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_ICON:
                        arg_icon = optarg;
                        break;

                case ARG_TIMEOUT:
                        if (parse_usec(optarg, &arg_timeout) < 0 || arg_timeout <= 0) {
                                log_error("Failed to parse --timeout parameter %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_TTY:
                        arg_use_tty = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind != argc-1) {
                help();
                return -EINVAL;
        }

        arg_message = argv[optind];
        return 1;
}

static int ask_agent(void) {
        char temp[] = "/dev/.systemd/ask-password/tmp.XXXXXX";
        char final[sizeof(temp)] = "";
        int fd = -1, r;
        FILE *f = NULL;
        char *socket_name = NULL;
        int socket_fd = -1, signal_fd;
        sigset_t mask;
        usec_t not_after;

        mkdir_p("/dev/.systemd/ask-password", 0755);

        if ((fd = mkostemp(temp, O_CLOEXEC|O_CREAT|O_WRONLY)) < 0) {
                log_error("Failed to create password file: %m");
                r = -errno;
                goto finish;
        }

        fchmod(fd, 0644);

        if (!(f = fdopen(fd, "w"))) {
                log_error("Failed to allocate FILE: %m");
                r = -errno;
                goto finish;
        }

        fd = -1;

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        if ((signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                log_error("signalfd(): %m");
                r = -errno;
                goto finish;
        }

        if ((socket_fd = create_socket(&socket_name)) < 0) {
                r = socket_fd;
                goto finish;
        }

        not_after = now(CLOCK_MONOTONIC) + arg_timeout;

        fprintf(f,
                "[Ask]\n"
                "PID=%lu\n"
                "Socket=%s\n"
                "NotAfter=%llu\n",
                (unsigned long) getpid(),
                socket_name,
                (unsigned long long) not_after);

        if (arg_message)
                fprintf(f, "Message=%s\n", arg_message);

        if (arg_icon)
                fprintf(f, "Icon=%s\n", arg_icon);

        fflush(f);

        if (ferror(f)) {
                log_error("Failed to write query file: %m");
                r = -errno;
                goto finish;
        }

        memcpy(final, temp, sizeof(temp));

        final[sizeof(final)-11] = 'a';
        final[sizeof(final)-10] = 's';
        final[sizeof(final)-9] = 'k';

        if (rename(temp, final) < 0) {
                log_error("Failed to rename query file: %m");
                r = -errno;
                goto finish;
        }

        for (;;) {
                enum {
                        FD_SOCKET,
                        FD_SIGNAL,
                        _FD_MAX
                };

                char passphrase[LINE_MAX+1];
                struct msghdr msghdr;
                struct iovec iovec;
                struct ucred *ucred;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control;
                ssize_t n;
                struct pollfd pollfd[_FD_MAX];
                int k;

                zero(pollfd);
                pollfd[FD_SOCKET].fd = socket_fd;
                pollfd[FD_SOCKET].events = POLLIN;
                pollfd[FD_SIGNAL].fd = signal_fd;
                pollfd[FD_SIGNAL].events = POLLIN;

                if ((k = poll(pollfd, 2, arg_timeout/USEC_PER_MSEC)) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("poll() failed: %m");
                        r = -errno;
                        goto finish;
                }

                if (k <= 0) {
                        log_notice("Timed out");
                        r = -ETIME;
                        goto finish;
                }

                if (pollfd[FD_SIGNAL].revents & POLLIN)
                        break;

                if (pollfd[FD_SOCKET].revents != POLLIN) {
                        log_error("Unexpected poll() event.");
                        r = -EIO;
                        goto finish;
                }

                zero(iovec);
                iovec.iov_base = passphrase;
                iovec.iov_len = sizeof(passphrase)-1;

                zero(control);
                zero(msghdr);
                msghdr.msg_iov = &iovec;
                msghdr.msg_iovlen = 1;
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                if ((n = recvmsg(socket_fd, &msghdr, 0)) < 0) {

                        if (errno == EAGAIN ||
                            errno == EINTR)
                                continue;

                        log_error("recvmsg() failed: %m");
                        r = -errno;
                        goto finish;
                }

                if (n <= 0) {
                        log_error("Message too short");
                        continue;
                }

                if (msghdr.msg_controllen < CMSG_LEN(sizeof(struct ucred)) ||
                    control.cmsghdr.cmsg_level != SOL_SOCKET ||
                    control.cmsghdr.cmsg_type != SCM_CREDENTIALS ||
                    control.cmsghdr.cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                        log_warning("Received message without credentials. Ignoring.");
                        continue;
                }

                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
                if (ucred->uid != 0) {
                        log_warning("Got request from unprivileged user. Ignoring.");
                        continue;
                }

                if (passphrase[0] == '+') {
                        passphrase[n] = 0;
                        fputs(passphrase+1, stdout);
                        fflush(stdout);
                } else if (passphrase[0] == '-') {
                        r = -ECANCELED;
                        goto finish;
                } else {
                        log_error("Invalid packet");
                        continue;
                }

                break;
        }

        r = 0;

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        if (socket_name) {
                unlink(socket_name);
                free(socket_name);
        }

        if (socket_fd >= 0)
                close_nointr_nofail(socket_fd);

        if (f)
                fclose(f);

        unlink(temp);

        if (final[0])
                unlink(final);

        return r;
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        if ((r = parse_argv(argc, argv)) <= 0)
                goto finish;

        if (arg_use_tty && isatty(STDIN_FILENO)) {
                char *password = NULL;

                if ((r = ask_password_tty(arg_message, now(CLOCK_MONOTONIC) + arg_timeout, NULL, &password)) >= 0) {
                        fputs(password, stdout);
                        fflush(stdout);
                        free(password);
                }

        } else
                r = ask_agent();

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
