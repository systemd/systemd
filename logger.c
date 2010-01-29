/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#define STREAM_BUFFER 2048
#define STREAMS_MAX 256
#define SERVER_FD_START 3
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

typedef enum StreamState {
        STREAM_LOG_TARGET,
        STREAM_PRIORITY,
        STREAM_PROCESS,
        STREAM_RUNNING
} StreamState;

typedef enum LogTarget {
        LOG_TARGET_SYSLOG,
        LOG_TARGET_KMSG
} LogTarget;

struct Stream {
        Server *server;

        StreamState state;

        int fd;

        LogTarget target;
        int priority;
        char *process;
        pid_t pid;
        uid_t uid;

        char buffer[STREAM_BUFFER];
        size_t length;

        LIST_FIELDS(Stream, stream);
};

#define IOVEC_SET_STRING(iovec, s)              \
        do {                                    \
                (iovec).iov_base = s;           \
                (iovec).iov_len = strlen(s);    \
        } while(false);

static int stream_log(Stream *s, char *p, usec_t timestamp) {

        char header_priority[16], header_time[64], header_pid[16];
        struct msghdr msghdr;
        struct iovec iovec[5];

        assert(s);
        assert(p);

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
                 s->target == LOG_TARGET_SYSLOG ? s->priority : LOG_PRI(s->priority));
        char_array_0(header_priority);

        if (s->target == LOG_TARGET_SYSLOG) {
                time_t t;
                struct tm *tm;

                t = (time_t) (timestamp / USEC_PER_SEC);
                if (!(tm = localtime(&t)))
                        return -EINVAL;

                if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                        return -EINVAL;
        }

        snprintf(header_pid, sizeof(header_pid), "[%llu]: ", (unsigned long long) s->pid);
        char_array_0(header_pid);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);

        if (s->target == LOG_TARGET_SYSLOG) {
                IOVEC_SET_STRING(iovec[1], header_time);
                IOVEC_SET_STRING(iovec[2], s->process);
                IOVEC_SET_STRING(iovec[3], header_pid);
                IOVEC_SET_STRING(iovec[4], p);

                zero(msghdr);
                msghdr.msg_iov = iovec;
                msghdr.msg_iovlen = ELEMENTSOF(iovec);

                if (sendmsg(s->server->syslog_fd, &msghdr, MSG_NOSIGNAL) < 0)
                        return -errno;

        } else if (s->target == LOG_TARGET_KMSG) {
                IOVEC_SET_STRING(iovec[1], s->process);
                IOVEC_SET_STRING(iovec[2], header_pid);
                IOVEC_SET_STRING(iovec[3], p);
                IOVEC_SET_STRING(iovec[4], "\n");

                if (writev(s->server->kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                        return -errno;
        } else
                assert_not_reached("Unknown log target");

        return 0;
}

static int stream_line(Stream *s, char *p, usec_t timestamp) {
        int r;

        assert(s);
        assert(p);

        p = strstrip(p);

        switch (s->state) {

        case STREAM_LOG_TARGET:
                if (streq(p, "syslog"))
                        s->target = LOG_TARGET_SYSLOG;
                else if (streq(p, "kmsg")) {

                        if (s->server->kmsg_fd >= 0 && s->uid == 0)
                                s->target = LOG_TARGET_KMSG;
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
                        log_warning("Failed to parse log priority line: %s", strerror(errno));
                        return r;
                }

                if (s->priority < 0) {
                        log_warning("Log priority negative: %s", strerror(errno));
                        return -ERANGE;
                }

                s->state = STREAM_PROCESS;
                return 0;

        case STREAM_PROCESS:
                if (!(s->process = strdup(p)))
                        return -ENOMEM;

                s->state = STREAM_RUNNING;
                return 0;

        case STREAM_RUNNING:
                return stream_log(s, p, timestamp);
        }

        assert_not_reached("Unknown stream state");
}

static int stream_scan(Stream *s, usec_t timestamp) {
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

                if ((r = stream_line(s, p, timestamp)) >= 0) {
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

static int stream_process(Stream *s, usec_t timestamp) {
        ssize_t l;
        int r;
        assert(s);

        if ((l = read(s->fd, s->buffer+s->length, STREAM_BUFFER-s->length)) < 0) {

                if (errno == EAGAIN)
                        return 0;

                log_warning("Failed to read from stream: %s", strerror(errno));
                return -1;
        }


        if (l == 0)
                return 0;

        s->length += l;
        r = stream_scan(s, timestamp);

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

                assert_se(close_nointr(s->fd) == 0);
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
                assert_se(close_nointr(fd) == 0);
                return 0;
        }

        if (!(stream = new0(Stream, 1))) {
                assert_se(close_nointr(fd) == 0);
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

        stream->server = s;
        LIST_PREPEND(Stream, stream, s->streams, stream);
        s->n_streams ++;

        return 0;

fail:
        stream_free(stream);
        return r;
}

static int verify_environment(unsigned *n_sockets) {
        unsigned long long pid;
        const char *e;
        int r;
        unsigned ns;

        assert_se(n_sockets);

        if (!(e = getenv("LISTEN_PID"))) {
                log_error("Missing $LISTEN_PID environment variable.");
                return -ENOENT;
        }

        if ((r = safe_atollu(e, &pid)) < 0) {
                log_error("Failed to parse $LISTEN_PID: %s", strerror(-r));
                return r;
        }

        if (pid != (unsigned long long) getpid()) {
                log_error("Socket nor for me.");
                return -ENOENT;
        }

        if (!(e = getenv("LISTEN_FDS"))) {
                log_error("Missing $LISTEN_FDS environment variable.");
                return -ENOENT;
        }

        if ((r = safe_atou(e, &ns)) < 0) {
                log_error("Failed to parse $LISTEN_FDS: %s", strerror(-r));
                return -E2BIG;
        }

        if (ns <= 0 || ns > SERVER_FD_MAX) {
                log_error("Wrong number of file descriptors passed: %s", e);
                return -E2BIG;
        }

        *n_sockets = ns;

        return 0;
}

static void server_done(Server *s) {
        unsigned i;
        assert(s);

        while (s->streams)
                stream_free(s->streams);

        for (i = 0; i < s->n_server_fd; i++)
                assert_se(close_nointr(SERVER_FD_START+i) == 0);

        if (s->syslog_fd >= 0)
                assert_se(close_nointr(s->syslog_fd) == 0);

        if (s->epoll_fd >= 0)
                assert_se(close_nointr(s->epoll_fd) == 0);

        if (s->kmsg_fd >= 0)
                assert_se(close_nointr(s->kmsg_fd) == 0);
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
                log_error("Failed to create epoll object: %s", strerror(errno));
                goto fail;
        }

        for (i = 0; i < n_sockets; i++) {
                struct epoll_event ev;

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.ptr = UINT_TO_PTR(SERVER_FD_START+i);
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, SERVER_FD_START+i, &ev) < 0) {
                        r = -errno;
                        log_error("Failed to add server fd to epoll object: %s", strerror(errno));
                        goto fail;
                }
        }

        if ((s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
                r = -errno;
                log_error("Failed to create log fd: %s", strerror(errno));
                goto fail;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/dev/log", sizeof(sa.un.sun_path));

        if (connect(s->syslog_fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                log_error("Failed to connect log socket to /dev/log: %s", strerror(errno));
                goto fail;
        }

        /* /dev/kmsg logging is strictly optional */
        if ((s->kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0)
                log_debug("Failed to open /dev/kmsg for logging, disabling kernel log buffer support: %s", strerror(errno));

        return 0;

fail:
        server_done(s);
        return r;
}

static int process_event(Server *s, struct epoll_event *ev) {
        int r;

        assert(s);

        /* Yes, this is a bit ugly, we assume that that valid pointers
         * are > SERVER_FD_START+SERVER_FD_MAX. Which is certainly
         * true on Linux (and probably most other OSes, too, since the
         * first 4k usually are part of a seperate null pointer
         * dereference page. */

        if (PTR_TO_UINT(ev->data.ptr) >= SERVER_FD_START &&
            PTR_TO_UINT(ev->data.ptr) < SERVER_FD_START+s->n_server_fd) {

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll. (1)");
                        return -EIO;
                }

                if ((r = stream_new(s, PTR_TO_UINT(ev->data.ptr))) < 0) {
                        log_info("Failed to accept new connection: %s", strerror(-r));
                        return r;
                }

        } else {
                usec_t timestamp;
                Stream *stream = ev->data.ptr;

                timestamp = now(CLOCK_REALTIME);

                if (!(ev->events & EPOLLIN)) {
                        log_info("Got invalid event from epoll. (3)");
                        stream_free(stream);
                        return 0;
                }

                if ((r = stream_process(stream, timestamp)) <= 0) {

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
        int r = 3;
        unsigned n;

        log_info("systemd-logger running as pid %llu", (unsigned long long) getpid());

        if (verify_environment(&n) < 0)
                return 1;

        if (server_init(&server, n) < 0)
                return 2;

        for (;;) {
                struct epoll_event event;
                int n;

                if ((n = epoll_wait(server.epoll_fd,
                                    &event, 1,
                                    server.n_streams <= 0 ? TIMEOUT : -1)) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %s", strerror(errno));
                        goto fail;
                }

                if (n <= 0)
                        break;

                if ((r = process_event(&server, &event)) < 0)
                        goto fail;
        }
        r = 0;

fail:
        server_done(&server);

        log_info("systemd-logger stopped as pid %llu", (unsigned long long) getpid());

        return r;
}
