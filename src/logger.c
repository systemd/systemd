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

#include "util.h"
#include "log.h"
#include "list.h"
#include "sd-daemon.h"
#include "tcpwrap.h"

#define STREAMS_MAX 256
#define SERVER_FD_MAX 16
#define TIMEOUT ((int) (10*MSEC_PER_SEC))

typedef struct Stream Stream;

typedef struct Server {
        int syslog_fd;
        int kmsg_fd;
        int epoll_fd;

        unsigned n_server_fd;

        LIST_HEAD(Stream, streams);
        unsigned n_streams;
} Server;

typedef enum StreamTarget {
        STREAM_SYSLOG,
        STREAM_KMSG
} StreamTarget;

typedef enum StreamState {
        STREAM_TARGET,
        STREAM_PRIORITY,
        STREAM_PROCESS,
        STREAM_PREFIX,
        STREAM_RUNNING
} StreamState;

struct Stream {
        Server *server;

        StreamState state;

        int fd;

        StreamTarget target;
        int priority;
        char *process;
        pid_t pid;
        uid_t uid;
        gid_t gid;

        bool prefix;

        char buffer[LINE_MAX];
        size_t length;

        LIST_FIELDS(Stream, stream);
};

static int stream_log(Stream *s, char *p, usec_t ts) {

        char header_priority[16], header_time[64], header_pid[16];
        struct iovec iovec[5];
        int priority;

        assert(s);
        assert(p);

        priority = s->priority;

        if (s->prefix &&
            p[0] == '<' &&
            p[1] >= '0' && p[1] <= '7' &&
            p[2] == '>') {

                /* Detected priority prefix */
                priority = LOG_MAKEPRI(LOG_FAC(priority), (p[1] - '0'));

                p += 3;
        }

        if (*p == 0)
                return 0;

        /*
         * The format glibc uses to talk to the syslog daemon is:
         *
         *     <priority>time process[pid]: msg
         *
         * The format the kernel uses is:
         *
         *     <priority>msg\n
         *
         *  We extend the latter to include the process name and pid.
         */

        snprintf(header_priority, sizeof(header_priority), "<%i>",
                 s->target == STREAM_SYSLOG ? priority : LOG_PRI(priority));
        char_array_0(header_priority);

        if (s->target == STREAM_SYSLOG) {
                time_t t;
                struct tm *tm;

                t = (time_t) (ts / USEC_PER_SEC);
                if (!(tm = localtime(&t)))
                        return -EINVAL;

                if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                        return -EINVAL;
        }

        snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) s->pid);
        char_array_0(header_pid);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);

        if (s->target == STREAM_SYSLOG) {
                struct msghdr msghdr;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control;
                struct ucred *ucred;

                zero(control);
                control.cmsghdr.cmsg_level = SOL_SOCKET;
                control.cmsghdr.cmsg_type = SCM_CREDENTIALS;
                control.cmsghdr.cmsg_len = CMSG_LEN(sizeof(struct ucred));

                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
                ucred->pid = s->pid;
                ucred->uid = s->uid;
                ucred->gid = s->gid;

                IOVEC_SET_STRING(iovec[1], header_time);
                IOVEC_SET_STRING(iovec[2], s->process);
                IOVEC_SET_STRING(iovec[3], header_pid);
                IOVEC_SET_STRING(iovec[4], p);

                zero(msghdr);
                msghdr.msg_iov = iovec;
                msghdr.msg_iovlen = ELEMENTSOF(iovec);
                msghdr.msg_control = &control;
                msghdr.msg_controllen = control.cmsghdr.cmsg_len;

                if (sendmsg(s->server->syslog_fd, &msghdr, MSG_NOSIGNAL) < 0)
                        return -errno;

        } else if (s->target == STREAM_KMSG) {
                IOVEC_SET_STRING(iovec[1], s->process);
                IOVEC_SET_STRING(iovec[2], header_pid);
                IOVEC_SET_STRING(iovec[3], p);
                IOVEC_SET_STRING(iovec[4], (char*) "\n");

                if (writev(s->server->kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                        return -errno;
        } else
                assert_not_reached("Unknown log target");

        return 0;
}

static int stream_line(Stream *s, char *p, usec_t ts) {
        int r;

        assert(s);
        assert(p);

        p = strstrip(p);

        switch (s->state) {

        case STREAM_TARGET:
                if (streq(p, "syslog"))
                        s->target = STREAM_SYSLOG;
                else if (streq(p, "kmsg")) {

                        if (s->server->kmsg_fd >= 0 && s->uid == 0)
                                s->target = STREAM_KMSG;
                        else {
                                log_warning("/dev/kmsg logging not available.");
                                return -EPERM;
                        }
                } else {
                        log_warning("Failed to parse log target line.");
                        return -EBADMSG;
                }
                s->state = STREAM_PRIORITY;
                return 0;

        case STREAM_PRIORITY:
                if ((r = safe_atoi(p, &s->priority)) < 0) {
                        log_warning("Failed to parse log priority line: %m");
                        return r;
                }

                if (s->priority < 0) {
                        log_warning("Log priority negative: %m");
                        return -ERANGE;
                }

                s->state = STREAM_PROCESS;
                return 0;

        case STREAM_PROCESS:
                if (!(s->process = strdup(p)))
                        return -ENOMEM;

                s->state = STREAM_PREFIX;
                return 0;

        case STREAM_PREFIX:

                if ((r = parse_boolean(p)) < 0)
                        return r;

                s->prefix = r;
                s->state = STREAM_RUNNING;
                return 0;

        case STREAM_RUNNING:
                return stream_log(s, p, ts);
        }

        assert_not_reached("Unknown stream state");
}

static int stream_scan(Stream *s, usec_t ts) {
        char *p;
        size_t remaining;
        int r = 0;

        assert(s);

        p = s->buffer;
        remaining = s->length;
        for (;;) {
                char *newline;

                if (!(newline = memchr(p, '\n', remaining)))
                        break;

                *newline = 0;

                if ((r = stream_line(s, p, ts)) >= 0) {
                        remaining -= newline-p+1;
                        p = newline+1;
                }
        }

        if (p > s->buffer) {
                memmove(s->buffer, p, remaining);
                s->length = remaining;
        }

        return r;
}

static int stream_process(Stream *s, usec_t ts) {
        ssize_t l;
        int r;
        assert(s);

        if ((l = read(s->fd, s->buffer+s->length, LINE_MAX-s->length)) < 0) {

                if (errno == EAGAIN)
                        return 0;

                log_warning("Failed to read from stream: %m");
                return -1;
        }


        if (l == 0)
                return 0;

        s->length += l;
        r = stream_scan(s, ts);

        if (r < 0)
                return r;

        return 1;
}

static void stream_free(Stream *s) {
        assert(s);

        if (s->server) {
                assert(s->server->n_streams > 0);
                s->server->n_streams--;
                LIST_REMOVE(Stream, stream, s->server->streams, s);

        }

        if (s->fd >= 0) {
                if (s->server)
                        epoll_ctl(s->server->epoll_fd, EPOLL_CTL_DEL, s->fd, NULL);

                close_nointr_nofail(s->fd);
        }

        free(s->process);
        free(s);
}

static int stream_new(Server *s, int server_fd) {
        Stream *stream;
        int fd;
        struct ucred ucred;
        socklen_t len = sizeof(ucred);
        struct epoll_event ev;
        int r;

        assert(s);

        if ((fd = accept4(server_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC)) < 0)
                return -errno;

        if (s->n_streams >= STREAMS_MAX) {
                log_warning("Too many connections, refusing connection.");
                close_nointr_nofail(fd);
                return 0;
        }

        if (!socket_tcpwrap(fd, "systemd-logger")) {
                close_nointr_nofail(fd);
                return 0;
        }

        if (!(stream = new0(Stream, 1))) {
                close_nointr_nofail(fd);
                return -ENOMEM;
        }

        stream->fd = fd;

        if (getsockopt(stream->fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
                r = -errno;
                goto fail;
        }

        if (shutdown(fd, SHUT_WR) < 0) {
                r = -errno;
                goto fail;
        }

        zero(ev);
        ev.data.ptr = stream;
        ev.events = EPOLLIN;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                r = -errno;
                goto fail;
        }

        stream->pid = ucred.pid;
        stream->uid = ucred.uid;
        stream->gid = ucred.gid;

        stream->server = s;
        LIST_PREPEND(Stream, stream, s->streams, stream);
        s->n_streams ++;

        return 0;

fail:
        stream_free(stream);
        return r;
}

static void server_done(Server *s) {
        unsigned i;
        assert(s);

        while (s->streams)
                stream_free(s->streams);

        for (i = 0; i < s->n_server_fd; i++)
                close_nointr_nofail(SD_LISTEN_FDS_START+i);

        if (s->syslog_fd >= 0)
                close_nointr_nofail(s->syslog_fd);

        if (s->epoll_fd >= 0)
                close_nointr_nofail(s->epoll_fd);

        if (s->kmsg_fd >= 0)
                close_nointr_nofail(s->kmsg_fd);
}

static int server_init(Server *s, unsigned n_sockets) {
        int r;
        unsigned i;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;

        assert(s);
        assert(n_sockets > 0);

        zero(*s);

        s->n_server_fd = n_sockets;
        s->syslog_fd = -1;
        s->kmsg_fd = -1;

        if ((s->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
                r = -errno;
                log_error("Failed to create epoll object: %m");
                goto fail;
        }

        for (i = 0; i < n_sockets; i++) {
                struct epoll_event ev;
                int fd;

                fd = SD_LISTEN_FDS_START+i;

                if ((r = sd_is_socket(fd, AF_UNSPEC, SOCK_STREAM, 1)) < 0) {
                        log_error("Failed to determine file descriptor type: %s", strerror(-r));
                        goto fail;
                }

                if (!r) {
                        log_error("Wrong file descriptor type.");
                        r = -EINVAL;
                        goto fail;
                }

                /* We use ev.data.ptr instead of ev.data.fd here,
                 * since on 64bit archs fd is 32bit while a pointer is
                 * 64bit. To make sure we can easily distuingish fd
                 * values and pointer values we want to make sure to
                 * write the full field unconditionally. */

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.ptr = INT_TO_PTR(fd);
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                        r = -errno;
                        log_error("Failed to add server fd to epoll object: %m");
                        goto fail;
                }
        }

        if ((s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
                r = -errno;
                log_error("Failed to create log fd: %m");
                goto fail;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/dev/log", sizeof(sa.un.sun_path));

        if (connect(s->syslog_fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                log_error("Failed to connect log socket to /dev/log: %m");
                goto fail;
        }

        /* /dev/kmsg logging is strictly optional */
        if ((s->kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0)
                log_warning("Failed to open /dev/kmsg for logging, disabling kernel log buffer support: %m");

        return 0;

fail:
        server_done(s);
        return r;
}

static int process_event(Server *s, struct epoll_event *ev) {
        int r;

        assert(s);

        /* Yes, this is a bit ugly, we assume that that valid pointers
         * are > SD_LISTEN_FDS_START+SERVER_FD_MAX. Which is certainly
         * true on Linux (and probably most other OSes, too, since the
         * first 4k usually are part of a seperate null pointer
         * dereference page. */

        if (PTR_TO_INT(ev->data.ptr) >= SD_LISTEN_FDS_START &&
            PTR_TO_INT(ev->data.ptr) < SD_LISTEN_FDS_START+(int)s->n_server_fd) {

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll. (1)");
                        return -EIO;
                }

                if ((r = stream_new(s, PTR_TO_INT(ev->data.ptr))) < 0) {
                        log_info("Failed to accept new connection: %s", strerror(-r));
                        return r;
                }

        } else {
                usec_t ts;
                Stream *stream = ev->data.ptr;

                ts = now(CLOCK_REALTIME);

                if (!(ev->events & EPOLLIN)) {
                        log_info("Got invalid event from epoll. (2)");
                        stream_free(stream);
                        return 0;
                }

                if ((r = stream_process(stream, ts)) <= 0) {

                        if (r < 0)
                                log_info("Got error on stream: %s", strerror(-r));

                        stream_free(stream);
                        return 0;
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Server server;
        int r = EXIT_FAILURE, n;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if ((n = sd_listen_fds(true)) < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        if (n <= 0 || n > SERVER_FD_MAX) {
                log_error("No or too many file descriptors passed.");
                return EXIT_FAILURE;
        }

        if (server_init(&server, (unsigned) n) < 0)
                return EXIT_FAILURE;

        log_debug("systemd-logger running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        for (;;) {
                struct epoll_event event;
                int k;

                if ((k = epoll_wait(server.epoll_fd,
                                    &event, 1,
                                    server.n_streams <= 0 ? TIMEOUT : -1)) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %m");
                        goto fail;
                }

                if (k <= 0)
                        break;

                if (process_event(&server, &event) < 0)
                        goto fail;
        }

        r = EXIT_SUCCESS;

        log_debug("systemd-logger stopped as pid %lu", (unsigned long) getpid());

fail:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r;
}
