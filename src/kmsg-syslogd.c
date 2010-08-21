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
#include <sys/types.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/signalfd.h>

#include "util.h"
#include "log.h"
#include "sd-daemon.h"
#include "fdset.h"

#define SERVER_FD_MAX 16
#define TIMEOUT ((int) (10*MSEC_PER_SEC))

typedef struct Stream Stream;

typedef struct Server {
        FDSet *syslog_fds;
        int kmsg_fd;
        int epoll_fd;
        int signal_fd;
} Server;

static void server_done(Server *s) {
        assert(s);

        if (s->epoll_fd >= 0)
                close_nointr_nofail(s->epoll_fd);

        if (s->kmsg_fd >= 0)
                close_nointr_nofail(s->kmsg_fd);

        if (s->signal_fd >= 0)
                close_nointr_nofail(s->signal_fd);

        if (s->syslog_fds)
                fdset_free(s->syslog_fds);
}

static int server_init(Server *s, unsigned n_sockets) {
        int r;
        unsigned i;
        struct epoll_event ev;
        sigset_t mask;

        assert(s);
        assert(n_sockets > 0);

        zero(*s);

        s->kmsg_fd = s->signal_fd = -1;

        if ((s->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
                r = -errno;
                log_error("Failed to create epoll object: %s", strerror(errno));
                goto fail;
        }

        if (!(s->syslog_fds = fdset_new())) {
                r = -ENOMEM;
                log_error("Failed to allocate file descriptor set: %s", strerror(errno));
                goto fail;
        }

        for (i = 0; i < n_sockets; i++) {
                int fd, one = 1;

                fd = SD_LISTEN_FDS_START+i;

                if ((r = sd_is_socket(fd, AF_UNSPEC, SOCK_DGRAM, -1)) < 0) {
                        log_error("Failed to determine file descriptor type: %s", strerror(-r));
                        goto fail;
                }

                if (!r) {
                        log_error("Wrong file descriptor type.");
                        r = -EINVAL;
                        goto fail;
                }

                if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0)
                        log_error("SO_PASSCRED failed: %m");

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.fd = fd;
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                        r = -errno;
                        log_error("Failed to add server fd to epoll object: %s", strerror(errno));
                        goto fail;
                }

                if ((r = fdset_put(s->syslog_fds, fd)) < 0) {
                        log_error("Failed to store file descriptor in set: %s", strerror(-r));
                        goto fail;
                }
        }

        if ((s->kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0) {
                log_error("Failed to open /dev/kmsg for logging: %m");
                return -errno;
        }

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        if ((s->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                log_error("signalfd(): %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->signal_fd;

        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->signal_fd, &ev) < 0) {
                log_error("epoll_ctl(): %m");
                return -errno;
        }

        return 0;

fail:
        server_done(s);
        return r;
}

static int read_priority(const char **buf) {
        int priority;
        size_t n;
        const char *p;
        int a, b, c;

        assert(buf);
        assert(*buf);

        p = *buf;
        n = strlen(p);

        if (n < 3 || p[0] != '<')
                goto fail;

        if (p[2] == '>') {
                a = b = 0;
                c = undecchar(p[1]);
                p += 3;
        } else if (n >= 4 && p[3] == '>') {
                a = 0;
                b = undecchar(p[1]);
                c = undecchar(p[2]);
                p += 4;
        } else if (n >= 5 && p[4] == '>') {
                a = undecchar(p[1]);
                b = undecchar(p[2]);
                c = undecchar(p[3]);
                p += 5;
        } else
                goto fail;

        if (a < 0 || b < 0 || c < 0)
                goto fail;

        *buf = p;

        priority = 100*a + 10*b + c;
        return LOG_PRI(priority);

fail:
        return LOG_INFO;
}

static void skip_date(const char **buf) {
        enum {
                LETTER,
                SPACE,
                NUMBER,
                SPACE_OR_NUMBER,
                COLON
        } sequence[] = {
                LETTER, LETTER, LETTER,
                SPACE,
                SPACE_OR_NUMBER, NUMBER,
                SPACE,
                SPACE_OR_NUMBER, NUMBER,
                COLON,
                SPACE_OR_NUMBER, NUMBER,
                COLON,
                SPACE_OR_NUMBER, NUMBER,
                SPACE
        };

        const char *p;
        unsigned i;

        assert(buf);
        assert(*buf);

        p = *buf;

        for (i = 0; i < ELEMENTSOF(sequence); i++, p++) {

                if (!*p)
                        return;

                switch (sequence[i]) {

                case SPACE:
                        if (*p != ' ')
                                return;
                        break;

                case SPACE_OR_NUMBER:
                        if (*p == ' ')
                                break;

                        /* fall through */

                case NUMBER:
                        if (*p < '0' || *p > '9')
                                return;

                        break;

                case LETTER:
                        if (!(*p >= 'A' && *p <= 'Z') &&
                            !(*p >= 'a' && *p <= 'z'))
                                return;

                        break;

                case COLON:
                        if (*p != ':')
                                return;
                        break;

                }
        }

        *buf = p;
}

static int read_process(const char **buf, struct iovec *iovec) {
        const char *p;
        size_t l;

        assert(buf);
        assert(*buf);
        assert(iovec);

        p = *buf;

        p += strspn(p, WHITESPACE);
        l = strcspn(p, WHITESPACE);

        if (l <= 0 ||
            p[l-1] != ':')
                return 0;

        l--;

        if (p[l-1] == ']') {
                size_t k = l-1;

                for (;;) {

                        if (p[k] == '[') {
                                l = k;
                                break;
                        }

                        if (k == 0)
                                break;

                        k--;
                }
        }

        iovec->iov_base = (char*) p;
        iovec->iov_len = l;
        *buf = p + l;
        return 1;
}

static void skip_pid(const char **buf) {
        const char *p;

        assert(buf);
        assert(*buf);

        p = *buf;

        if (*p != '[')
                return;

        p++;
        p += strspn(p, "0123456789");

        if (*p != ']')
                return;

        p++;

        *buf = p;
}

static int write_message(Server *s, const char *buf, struct ucred *ucred) {
        ssize_t k;
        char priority[4], pid[16];
        struct iovec iovec[5];
        unsigned i = 0;
        char *process = NULL;
        int r = 0;

        assert(s);
        assert(buf);

        /* First, set priority field */
        snprintf(priority, sizeof(priority), "<%i>", read_priority(&buf));
        char_array_0(priority);
        IOVEC_SET_STRING(iovec[i++], priority);

        /* Second, skip date */
        skip_date(&buf);

        /* Then, add process if set */
        if (read_process(&buf, &iovec[i]) > 0)
                i++;
        else if (ucred && get_process_name(ucred->pid, &process) >= 0)
                IOVEC_SET_STRING(iovec[i++], process);

        /* Skip the stored PID if we have a better one */
        if (ucred) {
                snprintf(pid, sizeof(pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(pid);
                IOVEC_SET_STRING(iovec[i++], pid);

                skip_pid(&buf);

                if (*buf == ':')
                        buf++;

                buf += strspn(buf, WHITESPACE);
        }

        /* Is the remaining message empty? */
        if (*buf) {

                /* And the rest is the message */
                IOVEC_SET_STRING(iovec[i++], buf);
                IOVEC_SET_STRING(iovec[i++], "\n");

                if ((k = writev(s->kmsg_fd, iovec, i)) <= 0) {
                        log_error("Failed to write log message to kmsg: %s", k < 0 ? strerror(errno) : "short write");
                        r = k < 0 ? -errno : -EIO;
                }
        }

        free(process);

        return r;
}

static int process_event(Server *s, struct epoll_event *ev) {
        assert(s);

        if (ev->events != EPOLLIN) {
                log_info("Got invalid event from epoll.");
                return -EIO;
        }

        if (ev->data.fd == s->signal_fd) {
                struct signalfd_siginfo sfsi;
                ssize_t n;

                if ((n = read(s->signal_fd, &sfsi, sizeof(sfsi))) != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                log_debug("Received SIG%s", strna(signal_to_string(sfsi.ssi_signo)));
                return 0;

        } else {
                for (;;) {
                        char buf[LINE_MAX+1];
                        struct msghdr msghdr;
                        struct iovec iovec;
                        struct ucred *ucred;
                        union {
                                struct cmsghdr cmsghdr;
                                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                        } control;
                        ssize_t n;
                        int k;
                        char *e;

                        zero(iovec);
                        iovec.iov_base = buf;
                        iovec.iov_len = sizeof(buf)-1;

                        zero(control);
                        zero(msghdr);
                        msghdr.msg_iov = &iovec;
                        msghdr.msg_iovlen = 1;
                        msghdr.msg_control = &control;
                        msghdr.msg_controllen = sizeof(control);

                        if ((n = recvmsg(ev->data.fd, &msghdr, MSG_DONTWAIT)) < 0) {

                                if (errno == EINTR || errno == EAGAIN)
                                        return 1;

                                log_error("recvmsg() failed: %m");
                                return -errno;
                        }

                        if (msghdr.msg_controllen >= CMSG_LEN(sizeof(struct ucred)) &&
                            control.cmsghdr.cmsg_level == SOL_SOCKET &&
                            control.cmsghdr.cmsg_type == SCM_CREDENTIALS &&
                            control.cmsghdr.cmsg_len == CMSG_LEN(sizeof(struct ucred)))
                                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
                        else
                                ucred = NULL;

                        if ((e = memchr(buf, '\n', n)))
                                *e = 0;
                        else
                                buf[n] = 0;

                        if ((k = write_message(s, strstrip(buf), ucred)) < 0)
                                return k;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        Server server;
        int r = 3, n;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return 1;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return 1;
        }

        log_set_target(LOG_TARGET_KMSG);
        log_parse_environment();
        log_open();

        if ((n = sd_listen_fds(true)) < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-r));
                return 1;
        }

        if (n <= 0 || n > SERVER_FD_MAX) {
                log_error("No or too many file descriptors passed.");
                return 2;
        }

        if (server_init(&server, (unsigned) n) < 0)
                return 3;

        log_debug("systemd-kmsg-syslogd running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing messages...");

        for (;;) {
                struct epoll_event event;
                int k;

                if ((k = epoll_wait(server.epoll_fd, &event, 1, TIMEOUT)) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %m");
                        goto fail;
                }

                if (k <= 0)
                        break;

                if ((k = process_event(&server, &event)) < 0)
                        goto fail;

                if (k == 0)
                        break;
        }

        r = 0;

        log_debug("systemd-kmsg-syslogd stopped as pid %lu", (unsigned long) getpid());

fail:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r;
}
