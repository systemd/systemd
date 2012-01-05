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

#include <systemd/sd-daemon.h>

#include "util.h"
#include "log.h"
#include "fdset.h"

#define SERVER_FD_MAX 16

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

static int server_init(Server *s) {
        int i, r, n;
        struct epoll_event ev;
        sigset_t mask;

        assert(s);

        zero(*s);
        s->kmsg_fd = s->signal_fd = -1;

        s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (s->epoll_fd < 0) {
                log_error("Failed to create epoll object: %m");
                return -errno;
        }

        s->syslog_fds = fdset_new();
        if (!s->syslog_fds) {
                log_error("Failed to allocate file descriptor set: %s", strerror(ENOMEM));
                return -ENOMEM;
        }

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-n));
                return n;
        }

        if (n <= 0 || n > SERVER_FD_MAX) {
                log_error("No or too many file descriptors passed.");
                return -EINVAL;
        }

        for (i = 0; i < n; i++) {
                int fd;

                fd = SD_LISTEN_FDS_START+i;

                r = sd_is_socket(fd, AF_UNSPEC, SOCK_DGRAM, -1);
                if (r < 0) {
                        log_error("Failed to determine file descriptor type: %s", strerror(-r));
                        return r;
                }

                if (!r) {
                        log_error("Wrong file descriptor type.");
                        return -EINVAL;
                }

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.fd = fd;
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                        log_error("Failed to add server fd to epoll object: %m");
                        return -errno;
                }

                r = fdset_put(s->syslog_fds, fd);
                if (r < 0) {
                        log_error("Failed to store file descriptor in set: %s", strerror(-r));
                        return r;
                }
        }

        s->kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (s->kmsg_fd < 0) {
                log_error("Failed to open /dev/kmsg for logging: %m");
                return -errno;
        }

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        s->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (s->signal_fd < 0) {
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

static int write_message(Server *s, const char *buf, struct ucred *ucred) {
        ssize_t k;
        char priority[6], pid[16];
        struct iovec iovec[5];
        unsigned i = 0;
        char *process = NULL;
        int r = 0;
        int prio = LOG_USER | LOG_INFO;

        assert(s);
        assert(buf);

        parse_syslog_priority((char**) &buf, &prio);

        if (*buf == 0)
                return 0;

        if ((prio & LOG_FACMASK) == 0)
                prio = LOG_USER | LOG_PRI(prio);

        /* First, set priority field */
        snprintf(priority, sizeof(priority), "<%i>", prio);
        char_array_0(priority);
        IOVEC_SET_STRING(iovec[i++], priority);

        /* Second, skip date */
        skip_syslog_date((char**) &buf);

        /* Then, add process if set */
        if (read_process(&buf, &iovec[i]) > 0)
                i++;
        else if (ucred &&
                 ucred->pid > 0 &&
                 get_process_comm(ucred->pid, &process) >= 0)
                IOVEC_SET_STRING(iovec[i++], process);

        /* Skip the stored PID if we have a better one */
        if (ucred) {
                snprintf(pid, sizeof(pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(pid);
                IOVEC_SET_STRING(iovec[i++], pid);

                skip_syslog_pid((char**) &buf);

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

                n = read(s->signal_fd, &sfsi, sizeof(sfsi));
                if (n != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                log_debug("Received SIG%s", signal_to_string(sfsi.ssi_signo));
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

                        n = recvmsg(ev->data.fd, &msghdr, MSG_DONTWAIT);
                        if (n < 0) {

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

                        e = memchr(buf, '\n', n);
                        if (e)
                                *e = 0;
                        else
                                buf[n] = 0;

                        k = write_message(s, strstrip(buf), ucred);
                        if (k < 0)
                                return k;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        Server server;
        int r;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_KMSG);
        log_parse_environment();
        log_open();

        umask(0022);

        r = server_init(&server);
        if (r < 0)
                goto finish;

        log_debug("systemd-kmsg-syslogd running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing messages...");

        for (;;) {
                struct epoll_event event;

                r = epoll_wait(server.epoll_fd, &event, 1, -1);
                if (r < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %m");
                        r = -errno;
                        goto finish;
                } else if (r == 0)
                        break;

                r = process_event(&server, &event);
                if (r < 0)
                        goto finish;
                else if (r == 0)
                        break;
        }

        log_debug("systemd-kmsg-syslogd stopped as pid %lu", (unsigned long) getpid());

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
