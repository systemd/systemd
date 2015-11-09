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
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "io-util.h"
#include "missing.h"
#include "mkdir.h"
#include "random-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "umask-util.h"
#include "util.h"

#define KEYRING_TIMEOUT_USEC ((5 * USEC_PER_MINUTE) / 2)

static int lookup_key(const char *keyname, key_serial_t *ret) {
        key_serial_t serial;

        assert(keyname);
        assert(ret);

        serial = request_key("user", keyname, NULL, 0);
        if (serial == -1)
                return -errno;

        *ret = serial;
        return 0;
}

static int retrieve_key(key_serial_t serial, char ***ret) {
        _cleanup_free_ char *p = NULL;
        long m = 100, n;
        char **l;

        assert(ret);

        for (;;) {
                p = new(char, m);
                if (!p)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) p, (unsigned long) m, 0);
                if (n < 0)
                        return -errno;

                if (n < m)
                        break;

                memory_erase(p, n);
                free(p);
                m *= 2;
        }

        l = strv_parse_nulstr(p, n);
        if (!l)
                return -ENOMEM;

        memory_erase(p, n);

        *ret = l;
        return 0;
}

static int add_to_keyring(const char *keyname, AskPasswordFlags flags, char **passwords) {
        _cleanup_strv_free_erase_ char **l = NULL;
        _cleanup_free_ char *p = NULL;
        key_serial_t serial;
        size_t n;
        int r;

        assert(keyname);
        assert(passwords);

        if (!(flags & ASK_PASSWORD_PUSH_CACHE))
                return 0;

        r = lookup_key(keyname, &serial);
        if (r >= 0) {
                r = retrieve_key(serial, &l);
                if (r < 0)
                        return r;
        } else if (r != -ENOKEY)
                return r;

        r = strv_extend_strv(&l, passwords, true);
        if (r <= 0)
                return r;

        r = strv_make_nulstr(l, &p, &n);
        if (r < 0)
                return r;

        /* Truncate trailing NUL */
        assert(n > 0);
        assert(p[n-1] == 0);

        serial = add_key("user", keyname, p, n-1, KEY_SPEC_USER_KEYRING);
        memory_erase(p, n);
        if (serial == -1)
                return -errno;

        if (keyctl(KEYCTL_SET_TIMEOUT,
                   (unsigned long) serial,
                   (unsigned long) DIV_ROUND_UP(KEYRING_TIMEOUT_USEC, USEC_PER_SEC), 0, 0) < 0)
                log_debug_errno(errno, "Failed to adjust timeout: %m");

        log_debug("Added key to keyring as %" PRIi32 ".", serial);

        return 1;
}

static int add_to_keyring_and_log(const char *keyname, AskPasswordFlags flags, char **passwords) {
        int r;

        assert(keyname);
        assert(passwords);

        r = add_to_keyring(keyname, flags, passwords);
        if (r < 0)
                return log_debug_errno(r, "Failed to add password to keyring: %m");

        return 0;
}

int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret) {

        key_serial_t serial;
        int r;

        assert(keyname);
        assert(ret);

        if (!(flags & ASK_PASSWORD_ACCEPT_CACHED))
                return -EUNATCH;

        r = lookup_key(keyname, &serial);
        if (r == -ENOSYS) /* when retrieving the distinction doesn't matter */
                return -ENOKEY;
        if (r < 0)
                return r;

        return retrieve_key(serial, ret);
}

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
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                const char *flag_file,
                char **ret) {

        struct termios old_termios, new_termios;
        char passphrase[LINE_MAX], *x;
        size_t p = 0;
        int r;
        _cleanup_close_ int ttyfd = -1, notify = -1;
        struct pollfd pollfd[2];
        bool reset_tty = false;
        bool dirty = false;
        enum {
                POLL_TTY,
                POLL_INOTIFY
        };

        assert(ret);

        if (flags & ASK_PASSWORD_NO_TTY)
                return -EUNATCH;

        if (!message)
                message = "Password:";

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

                loop_write(ttyfd, ANSI_HIGHLIGHT, strlen(ANSI_HIGHLIGHT), false);
                loop_write(ttyfd, message, strlen(message), false);
                loop_write(ttyfd, " ", 1, false);
                loop_write(ttyfd, ANSI_NORMAL, strlen(ANSI_NORMAL), false);

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

                k = poll(pollfd, notify >= 0 ? 2 : 1, sleep_for);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                } else if (k == 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (notify >= 0 && pollfd[POLL_INOTIFY].revents != 0)
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

                        if (!(flags & ASK_PASSWORD_SILENT))
                                backspace_chars(ttyfd, p);
                        p = 0;

                } else if (c == '\b' || c == 127) {

                        if (p > 0) {

                                if (!(flags & ASK_PASSWORD_SILENT))
                                        backspace_chars(ttyfd, 1);

                                p--;
                        } else if (!dirty && !(flags & ASK_PASSWORD_SILENT)) {

                                flags |= ASK_PASSWORD_SILENT;

                                /* There are two ways to enter silent
                                 * mode. Either by pressing backspace
                                 * as first key (and only as first
                                 * key), or ... */
                                if (ttyfd >= 0)
                                        loop_write(ttyfd, "(no echo) ", 10, false);

                        } else if (ttyfd >= 0)
                                loop_write(ttyfd, "\a", 1, false);

                } else if (c == '\t' && !(flags & ASK_PASSWORD_SILENT)) {

                        backspace_chars(ttyfd, p);
                        flags |= ASK_PASSWORD_SILENT;

                        /* ... or by pressing TAB at any time. */

                        if (ttyfd >= 0)
                                loop_write(ttyfd, "(no echo) ", 10, false);
                } else {
                        if (p >= sizeof(passphrase)-1) {
                                loop_write(ttyfd, "\a", 1, false);
                                continue;
                        }

                        passphrase[p++] = c;

                        if (!(flags & ASK_PASSWORD_SILENT) && ttyfd >= 0)
                                loop_write(ttyfd, (flags & ASK_PASSWORD_ECHO) ? &c : "*", 1, false);

                        dirty = true;
                }

                c = 'x';
        }

        x = strndup(passphrase, p);
        memory_erase(passphrase, p);
        if (!x) {
                r = -ENOMEM;
                goto finish;
        }

        if (keyname)
                (void) add_to_keyring_and_log(keyname, flags, STRV_MAKE(x));

        *ret = x;
        r = 0;

finish:
        if (ttyfd >= 0 && reset_tty) {
                loop_write(ttyfd, "\n", 1, false);
                tcsetattr(ttyfd, TCSADRAIN, &old_termios);
        }

        return r;
}

static int create_socket(char **name) {
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        _cleanup_close_ int fd = -1;
        static const int one = 1;
        char *c;
        int r;

        assert(name);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        snprintf(sa.un.sun_path, sizeof(sa.un.sun_path)-1, "/run/systemd/ask-password/sck.%" PRIx64, random_u64());

        RUN_WITH_UMASK(0177) {
                if (bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0)
                        return -errno;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0)
                return -errno;

        c = strdup(sa.un.sun_path);
        if (!c)
                return -ENOMEM;

        *name = c;

        r = fd;
        fd = -1;

        return r;
}

int ask_password_agent(
                const char *message,
                const char *icon,
                const char *id,
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                char ***ret) {

        enum {
                FD_SOCKET,
                FD_SIGNAL,
                _FD_MAX
        };

        _cleanup_close_ int socket_fd = -1, signal_fd = -1, fd = -1;
        char temp[] = "/run/systemd/ask-password/tmp.XXXXXX";
        char final[sizeof(temp)] = "";
        _cleanup_free_ char *socket_name = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct pollfd pollfd[_FD_MAX];
        sigset_t mask, oldmask;
        int r;

        assert(ret);

        if (flags & ASK_PASSWORD_NO_AGENT)
                return -EUNATCH;

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM, -1) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) >= 0);

        (void) mkdir_p_label("/run/systemd/ask-password", 0755);

        fd = mkostemp_safe(temp, O_WRONLY|O_CLOEXEC);
        if (fd < 0) {
                r = fd;
                goto finish;
        }

        (void) fchmod(fd, 0644);

        f = fdopen(fd, "w");
        if (!f) {
                r = -errno;
                goto finish;
        }

        fd = -1;

        signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0) {
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
                (flags & ASK_PASSWORD_ACCEPT_CACHED) ? 1 : 0,
                (flags & ASK_PASSWORD_ECHO) ? 1 : 0,
                until);

        if (message)
                fprintf(f, "Message=%s\n", message);

        if (icon)
                fprintf(f, "Icon=%s\n", icon);

        if (id)
                fprintf(f, "Id=%s\n", id);

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        memcpy(final, temp, sizeof(temp));

        final[sizeof(final)-11] = 'a';
        final[sizeof(final)-10] = 's';
        final[sizeof(final)-9] = 'k';

        if (rename(temp, final) < 0) {
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
                        r = -ETIME;
                        goto finish;
                }

                k = poll(pollfd, _FD_MAX, until > 0 ? (int) ((until-t)/USEC_PER_MSEC) : -1);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                }

                if (k <= 0) {
                        r = -ETIME;
                        goto finish;
                }

                if (pollfd[FD_SIGNAL].revents & POLLIN) {
                        r = -EINTR;
                        goto finish;
                }

                if (pollfd[FD_SOCKET].revents != POLLIN) {
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

                        r = -errno;
                        goto finish;
                }

                cmsg_close_all(&msghdr);

                if (n <= 0) {
                        log_debug("Message too short");
                        continue;
                }

                if (msghdr.msg_controllen < CMSG_LEN(sizeof(struct ucred)) ||
                    control.cmsghdr.cmsg_level != SOL_SOCKET ||
                    control.cmsghdr.cmsg_type != SCM_CREDENTIALS ||
                    control.cmsghdr.cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                        log_debug("Received message without credentials. Ignoring.");
                        continue;
                }

                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
                if (ucred->uid != 0) {
                        log_debug("Got request from unprivileged user. Ignoring.");
                        continue;
                }

                if (passphrase[0] == '+') {
                        /* An empty message refers to the empty password */
                        if (n == 1)
                                l = strv_new("", NULL);
                        else
                                l = strv_parse_nulstr(passphrase+1, n-1);
                        memory_erase(passphrase, n);
                        if (!l) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (strv_length(l) <= 0) {
                                l = strv_free(l);
                                log_debug("Invalid packet");
                                continue;
                        }

                        break;
                }

                if (passphrase[0] == '-') {
                        r = -ECANCELED;
                        goto finish;
                }

                log_debug("Invalid packet");
        }

        if (keyname)
                (void) add_to_keyring_and_log(keyname, flags, l);

        *ret = l;
        l = NULL;
        r = 0;

finish:
        if (socket_name)
                (void) unlink(socket_name);

        (void) unlink(temp);

        if (final[0])
                (void) unlink(final);

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);
        return r;
}

int ask_password_auto(
                const char *message,
                const char *icon,
                const char *id,
                const char *keyname,
                usec_t until,
                AskPasswordFlags flags,
                char ***ret) {

        int r;

        assert(ret);

        if ((flags & ASK_PASSWORD_ACCEPT_CACHED) && keyname) {
                r = ask_password_keyring(keyname, flags, ret);
                if (r != -ENOKEY)
                        return r;
        }

        if (!(flags & ASK_PASSWORD_NO_TTY) && isatty(STDIN_FILENO)) {
                char *s = NULL, **l = NULL;

                r = ask_password_tty(message, keyname, until, flags, NULL, &s);
                if (r < 0)
                        return r;

                r = strv_push(&l, s);
                if (r < 0) {
                        string_erase(s);
                        free(s);
                        return -ENOMEM;
                }

                *ret = l;
                return 0;
        }

        if (!(flags & ASK_PASSWORD_NO_AGENT))
                return ask_password_agent(message, icon, id, keyname, until, flags, ret);

        return -EUNATCH;
}
