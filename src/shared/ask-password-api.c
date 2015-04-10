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
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/signalfd.h>

#include "util.h"
#include "formats-util.h"
#include "mkdir.h"
#include "strv.h"
#include "random-util.h"
#include "terminal-util.h"

#include "ask-password-api.h"

static void backspace_chars(int ttyfd, size_t p) {

        if (ttyfd < 0)
                return;

        while (p > 0) {
                p--;

                loop_write(ttyfd, "\b \b", 3, false);
        }
}

int ask_password_tty(
                const char *message,
                usec_t until,
                bool echo,
                const char *flag_file,
                char **_passphrase) {

        struct termios old_termios, new_termios;
        char passphrase[LINE_MAX], *x;
        size_t p = 0;
        int r;
        _cleanup_close_ int ttyfd = -1, notify = -1;
        struct pollfd pollfd[2];
        bool reset_tty = false;
        bool silent_mode = false;
        bool dirty = false;
        enum {
                POLL_TTY,
                POLL_INOTIFY
        };

        assert(message);
        assert(_passphrase);

        if (flag_file) {
                notify = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
                if (notify < 0) {
                        r = -errno;
                        goto finish;
                }

                if (inotify_add_watch(notify, flag_file, IN_ATTRIB /* for the link count */) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        ttyfd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (ttyfd >= 0) {

                if (tcgetattr(ttyfd, &old_termios) < 0) {
                        r = -errno;
                        goto finish;
                }

                loop_write(ttyfd, ANSI_HIGHLIGHT_ON, sizeof(ANSI_HIGHLIGHT_ON)-1, false);
                loop_write(ttyfd, message, strlen(message), false);
                loop_write(ttyfd, " ", 1, false);
                loop_write(ttyfd, ANSI_HIGHLIGHT_OFF, sizeof(ANSI_HIGHLIGHT_OFF)-1, false);

                new_termios = old_termios;
                new_termios.c_lflag &= ~(ICANON|ECHO);
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(ttyfd, TCSADRAIN, &new_termios) < 0) {
                        r = -errno;
                        goto finish;
                }

                reset_tty = true;
        }

        zero(pollfd);
        pollfd[POLL_TTY].fd = ttyfd >= 0 ? ttyfd : STDIN_FILENO;
        pollfd[POLL_TTY].events = POLLIN;
        pollfd[POLL_INOTIFY].fd = notify;
        pollfd[POLL_INOTIFY].events = POLLIN;

        for (;;) {
                char c;
                int sleep_for = -1, k;
                ssize_t n;

                if (until > 0) {
                        usec_t y;

                        y = now(CLOCK_MONOTONIC);

                        if (y > until) {
                                r = -ETIME;
                                goto finish;
                        }

                        sleep_for = (int) ((until - y) / USEC_PER_MSEC);
                }

                if (flag_file)
                        if (access(flag_file, F_OK) < 0) {
                                r = -errno;
                                goto finish;
                        }

                k = poll(pollfd, notify > 0 ? 2 : 1, sleep_for);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                } else if (k == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (notify > 0 && pollfd[POLL_INOTIFY].revents != 0)
                        flush_fd(notify);

                if (pollfd[POLL_TTY].revents == 0)
                        continue;

                n = read(ttyfd >= 0 ? ttyfd : STDIN_FILENO, &c, 1);
                if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        r = -errno;
                        goto finish;

                } else if (n == 0)
                        break;

                if (c == '\n')
                        break;
                else if (c == 21) { /* C-u */

                        if (!silent_mode)
                                backspace_chars(ttyfd, p);
                        p = 0;

                } else if (c == '\b' || c == 127) {

                        if (p > 0) {

                                if (!silent_mode)
                                        backspace_chars(ttyfd, 1);

                                p--;
                        } else if (!dirty && !silent_mode) {

                                silent_mode = true;

                                /* There are two ways to enter silent
                                 * mode. Either by pressing backspace
                                 * as first key (and only as first key),
                                 * or ... */
                                if (ttyfd >= 0)
                                        loop_write(ttyfd, "(no echo) ", 10, false);

                        } else if (ttyfd >= 0)
                                loop_write(ttyfd, "\a", 1, false);

                } else if (c == '\t' && !silent_mode) {

                        backspace_chars(ttyfd, p);
                        silent_mode = true;

                        /* ... or by pressing TAB at any time. */

                        if (ttyfd >= 0)
                                loop_write(ttyfd, "(no echo) ", 10, false);
                } else {
                        if (p >= sizeof(passphrase)-1) {
                                loop_write(ttyfd, "\a", 1, false);
                                continue;
                        }

                        passphrase[p++] = c;

                        if (!silent_mode && ttyfd >= 0)
                                loop_write(ttyfd, echo ? &c : "*", 1, false);

                        dirty = true;
                }
        }

        x = strndup(passphrase, p);
        if (!x) {
                r = -ENOMEM;
                goto finish;
        }

        *_passphrase = x;
        r = 0;

finish:
        if (ttyfd >= 0 && reset_tty) {
                loop_write(ttyfd, "\n", 1, false);
                tcsetattr(ttyfd, TCSADRAIN, &old_termios);
        }

        return r;
}

static int create_socket(char **name) {
        int fd;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .un.sun_family = AF_UNIX,
        };
        int one = 1;
        int r = 0;
        char *c;

        assert(name);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "socket() failed: %m");

        snprintf(sa.un.sun_path, sizeof(sa.un.sun_path)-1, "/run/systemd/ask-password/sck.%" PRIx64, random_u64());

        RUN_WITH_UMASK(0177) {
                r = bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path));
        }

        if (r < 0) {
                r = -errno;
                log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);
                goto fail;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
                r = -errno;
                log_error_errno(errno, "SO_PASSCRED failed: %m");
                goto fail;
        }

        c = strdup(sa.un.sun_path);
        if (!c) {
                r = log_oom();
                goto fail;
        }

        *name = c;
        return fd;

fail:
        safe_close(fd);

        return r;
}

int ask_password_agent(
                const char *message,
                const char *icon,
                const char *id,
                usec_t until,
                bool echo,
                bool accept_cached,
                char ***_passphrases) {

        enum {
                FD_SOCKET,
                FD_SIGNAL,
                _FD_MAX
        };

        char temp[] = "/run/systemd/ask-password/tmp.XXXXXX";
        char final[sizeof(temp)] = "";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *socket_name = NULL;
        _cleanup_close_ int socket_fd = -1, signal_fd = -1, fd = -1;
        sigset_t mask, oldmask;
        struct pollfd pollfd[_FD_MAX];
        int r;

        assert(_passphrases);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        mkdir_p_label("/run/systemd/ask-password", 0755);

        fd = mkostemp_safe(temp, O_WRONLY|O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to create password file: %m");
                r = -errno;
                goto finish;
        }

        fchmod(fd, 0644);

        f = fdopen(fd, "w");
        if (!f) {
                log_error_errno(errno, "Failed to allocate FILE: %m");
                r = -errno;
                goto finish;
        }

        fd = -1;

        signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0) {
                log_error_errno(errno, "signalfd(): %m");
                r = -errno;
                goto finish;
        }

        socket_fd = create_socket(&socket_name);
        if (socket_fd < 0) {
                r = socket_fd;
                goto finish;
        }

        fprintf(f,
                "[Ask]\n"
                "PID="PID_FMT"\n"
                "Socket=%s\n"
                "AcceptCached=%i\n"
                "Echo=%i\n"
                "NotAfter="USEC_FMT"\n",
                getpid(),
                socket_name,
                accept_cached ? 1 : 0,
                echo ? 1 : 0,
                until);

        if (message)
                fprintf(f, "Message=%s\n", message);

        if (icon)
                fprintf(f, "Icon=%s\n", icon);

        if (id)
                fprintf(f, "Id=%s\n", id);

        fflush(f);

        if (ferror(f)) {
                log_error_errno(errno, "Failed to write query file: %m");
                r = -errno;
                goto finish;
        }

        memcpy(final, temp, sizeof(temp));

        final[sizeof(final)-11] = 'a';
        final[sizeof(final)-10] = 's';
        final[sizeof(final)-9] = 'k';

        if (rename(temp, final) < 0) {
                log_error_errno(errno, "Failed to rename query file: %m");
                r = -errno;
                goto finish;
        }

        zero(pollfd);
        pollfd[FD_SOCKET].fd = socket_fd;
        pollfd[FD_SOCKET].events = POLLIN;
        pollfd[FD_SIGNAL].fd = signal_fd;
        pollfd[FD_SIGNAL].events = POLLIN;

        for (;;) {
                char passphrase[LINE_MAX+1];
                struct msghdr msghdr;
                struct iovec iovec;
                struct ucred *ucred;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control;
                ssize_t n;
                int k;
                usec_t t;

                t = now(CLOCK_MONOTONIC);

                if (until > 0 && until <= t) {
                        log_notice("Timed out");
                        r = -ETIME;
                        goto finish;
                }

                k = poll(pollfd, _FD_MAX, until > 0 ? (int) ((until-t)/USEC_PER_MSEC) : -1);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        log_error_errno(errno, "poll() failed: %m");
                        r = -errno;
                        goto finish;
                }

                if (k <= 0) {
                        log_notice("Timed out");
                        r = -ETIME;
                        goto finish;
                }

                if (pollfd[FD_SIGNAL].revents & POLLIN) {
                        r = -EINTR;
                        goto finish;
                }

                if (pollfd[FD_SOCKET].revents != POLLIN) {
                        log_error("Unexpected poll() event.");
                        r = -EIO;
                        goto finish;
                }

                zero(iovec);
                iovec.iov_base = passphrase;
                iovec.iov_len = sizeof(passphrase);

                zero(control);
                zero(msghdr);
                msghdr.msg_iov = &iovec;
                msghdr.msg_iovlen = 1;
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                n = recvmsg(socket_fd, &msghdr, 0);
                if (n < 0) {
                        if (errno == EAGAIN ||
                            errno == EINTR)
                                continue;

                        log_error_errno(errno, "recvmsg() failed: %m");
                        r = -errno;
                        goto finish;
                }

                cmsg_close_all(&msghdr);

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
                        char **l;

                        if (n == 1)
                                l = strv_new("", NULL);
                        else
                                l = strv_parse_nulstr(passphrase+1, n-1);
                                /* An empty message refers to the empty password */

                        if (!l) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (strv_length(l) <= 0) {
                                strv_free(l);
                                log_error("Invalid packet");
                                continue;
                        }

                        *_passphrases = l;

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
        if (socket_name)
                unlink(socket_name);

        unlink(temp);

        if (final[0])
                unlink(final);

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);

        return r;
}

int ask_password_auto(const char *message, const char *icon, const char *id,
                      usec_t until, bool accept_cached, char ***_passphrases) {
        assert(message);
        assert(_passphrases);

        if (isatty(STDIN_FILENO)) {
                int r;
                char *s = NULL, **l = NULL;

                r = ask_password_tty(message, until, false, NULL, &s);
                if (r < 0)
                        return r;

                r = strv_consume(&l, s);
                if (r < 0)
                        return r;

                *_passphrases = l;
                return r;
        } else
                return ask_password_agent(message, icon, id, until, false, accept_cached, _passphrases);
}
