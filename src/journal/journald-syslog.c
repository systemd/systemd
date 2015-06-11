/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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
#include <stddef.h>
#include <sys/epoll.h>

#include "systemd/sd-messages.h"
#include "socket-util.h"
#include "selinux-util.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-kmsg.h"
#include "journald-console.h"
#include "journald-wall.h"
#include "formats-util.h"
#include "process-util.h"

/* Warn once every 30s if we missed syslog message */
#define WARN_FORWARD_SYSLOG_MISSED_USEC (30 * USEC_PER_SEC)

static void forward_syslog_iovec(Server *s, const struct iovec *iovec, unsigned n_iovec, const struct ucred *ucred, const struct timeval *tv) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/syslog",
        };
        struct msghdr msghdr = {
                .msg_iov = (struct iovec *) iovec,
                .msg_iovlen = n_iovec,
                .msg_name = (struct sockaddr*) &sa.sa,
                .msg_namelen = offsetof(union sockaddr_union, un.sun_path)
                               + strlen("/run/systemd/journal/syslog"),
        };
        struct cmsghdr *cmsg;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control;

        assert(s);
        assert(iovec);
        assert(n_iovec > 0);

        if (ucred) {
                zero(control);
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&msghdr);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));
                msghdr.msg_controllen = cmsg->cmsg_len;
        }

        /* Forward the syslog message we received via /dev/log to
         * /run/systemd/syslog. Unfortunately we currently can't set
         * the SO_TIMESTAMP auxiliary data, and hence we don't. */

        if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return;

        /* The socket is full? I guess the syslog implementation is
         * too slow, and we shouldn't wait for that... */
        if (errno == EAGAIN) {
                s->n_forward_syslog_missed++;
                return;
        }

        if (ucred && (errno == ESRCH || errno == EPERM)) {
                struct ucred u;

                /* Hmm, presumably the sender process vanished
                 * by now, or we don't have CAP_SYS_AMDIN, so
                 * let's fix it as good as we can, and retry */

                u = *ucred;
                u.pid = getpid();
                memcpy(CMSG_DATA(cmsg), &u, sizeof(struct ucred));

                if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                        return;

                if (errno == EAGAIN) {
                        s->n_forward_syslog_missed++;
                        return;
                }
        }

        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to forward syslog message: %m");
}

static void forward_syslog_raw(Server *s, int priority, const char *buffer, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec;

        assert(s);
        assert(buffer);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        IOVEC_SET_STRING(iovec, buffer);
        forward_syslog_iovec(s, &iovec, 1, ucred, tv);
}

void server_forward_syslog(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec[5];
        char header_priority[DECIMAL_STR_MAX(priority) + 3], header_time[64],
             header_pid[sizeof("[]: ")-1 + DECIMAL_STR_MAX(pid_t) + 1];
        int n = 0;
        time_t t;
        struct tm *tm;
        char *ident_buf = NULL;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        /* First: priority field */
        xsprintf(header_priority, "<%i>", priority);
        IOVEC_SET_STRING(iovec[n++], header_priority);

        /* Second: timestamp */
        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        tm = localtime(&t);
        if (!tm)
                return;
        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return;
        IOVEC_SET_STRING(iovec[n++], header_time);

        /* Third: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                xsprintf(header_pid, "["PID_FMT"]: ", ucred->pid);

                if (identifier)
                        IOVEC_SET_STRING(iovec[n++], identifier);

                IOVEC_SET_STRING(iovec[n++], header_pid);
        } else if (identifier) {
                IOVEC_SET_STRING(iovec[n++], identifier);
                IOVEC_SET_STRING(iovec[n++], ": ");
        }

        /* Fourth: message */
        IOVEC_SET_STRING(iovec[n++], message);

        forward_syslog_iovec(s, iovec, n, ucred, tv);

        free(ident_buf);
}

int syslog_fixup_facility(int priority) {

        if ((priority & LOG_FACMASK) == 0)
                return (priority & LOG_PRIMASK) | LOG_USER;

        return priority;
}

size_t syslog_parse_identifier(const char **buf, char **identifier, char **pid) {
        const char *p;
        char *t;
        size_t l, e;

        assert(buf);
        assert(identifier);
        assert(pid);

        p = *buf;

        p += strspn(p, WHITESPACE);
        l = strcspn(p, WHITESPACE);

        if (l <= 0 ||
            p[l-1] != ':')
                return 0;

        e = l;
        l--;

        if (p[l-1] == ']') {
                size_t k = l-1;

                for (;;) {

                        if (p[k] == '[') {
                                t = strndup(p+k+1, l-k-2);
                                if (t)
                                        *pid = t;

                                l = k;
                                break;
                        }

                        if (k == 0)
                                break;

                        k--;
                }
        }

        t = strndup(p, l);
        if (t)
                *identifier = t;

        if (strchr(WHITESPACE, p[e]))
                e++;
        *buf = p + e;
        return e;
}

static void syslog_skip_date(char **buf) {
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

        char *p;
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

void server_process_syslog_message(
        Server *s,
        const char *buf,
        const struct ucred *ucred,
        const struct timeval *tv,
        const char *label,
        size_t label_len) {

        char syslog_priority[sizeof("PRIORITY=") + DECIMAL_STR_MAX(int)],
             syslog_facility[sizeof("SYSLOG_FACILITY") + DECIMAL_STR_MAX(int)];
        const char *message = NULL, *syslog_identifier = NULL, *syslog_pid = NULL;
        struct iovec iovec[N_IOVEC_META_FIELDS + 6];
        unsigned n = 0;
        int priority = LOG_USER | LOG_INFO;
        _cleanup_free_ char *identifier = NULL, *pid = NULL;
        const char *orig;

        assert(s);
        assert(buf);

        orig = buf;
        syslog_parse_priority(&buf, &priority, true);

        if (s->forward_to_syslog)
                forward_syslog_raw(s, priority, orig, ucred, tv);

        syslog_skip_date((char**) &buf);
        syslog_parse_identifier(&buf, &identifier, &pid);

        if (s->forward_to_kmsg)
                server_forward_kmsg(s, priority, identifier, buf, ucred);

        if (s->forward_to_console)
                server_forward_console(s, priority, identifier, buf, ucred);

        if (s->forward_to_wall)
                server_forward_wall(s, priority, identifier, buf, ucred);

        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=syslog");

        sprintf(syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK);
        IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if (priority & LOG_FACMASK) {
                sprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                IOVEC_SET_STRING(iovec[n++], syslog_facility);
        }

        if (identifier) {
                syslog_identifier = strjoina("SYSLOG_IDENTIFIER=", identifier);
                if (syslog_identifier)
                        IOVEC_SET_STRING(iovec[n++], syslog_identifier);
        }

        if (pid) {
                syslog_pid = strjoina("SYSLOG_PID=", pid);
                if (syslog_pid)
                        IOVEC_SET_STRING(iovec[n++], syslog_pid);
        }

        message = strjoina("MESSAGE=", buf);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

        server_dispatch_message(s, iovec, n, ELEMENTSOF(iovec), ucred, tv, label, label_len, NULL, priority, 0);
}

int server_open_syslog_socket(Server *s) {
        static const int one = 1;
        int r;

        assert(s);

        if (s->syslog_fd < 0) {
                static const union sockaddr_union sa = {
                        .un.sun_family = AF_UNIX,
                        .un.sun_path = "/run/systemd/journal/dev-log",
                };

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->syslog_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                unlink(sa.un.sun_path);

                r = bind(s->syslog_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);
        } else
                fd_nonblock(s->syslog_fd, 1);

        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_PASSCRED failed: %m");

#ifdef HAVE_SELINUX
        if (mac_selinux_use()) {
                r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));
                if (r < 0)
                        log_warning_errno(errno, "SO_PASSSEC failed: %m");
        }
#endif

        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_TIMESTAMP failed: %m");

        r = sd_event_add_io(s->event, &s->syslog_event_source, s->syslog_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add syslog server fd to event loop: %m");

        return 0;
}

void server_maybe_warn_forward_syslog_missed(Server *s) {
        usec_t n;
        assert(s);

        if (s->n_forward_syslog_missed <= 0)
                return;

        n = now(CLOCK_MONOTONIC);
        if (s->last_warn_forward_syslog_missed + WARN_FORWARD_SYSLOG_MISSED_USEC > n)
                return;

        server_driver_message(s, SD_MESSAGE_FORWARD_SYSLOG_MISSED, "Forwarding to syslog missed %u messages.", s->n_forward_syslog_missed);

        s->n_forward_syslog_missed = 0;
        s->last_warn_forward_syslog_missed = n;
}
