/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "process-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "syslog-util.h"

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
                .msg_namelen = SOCKADDR_UN_LEN(sa.un),
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

        if (ucred && IN_SET(errno, ESRCH, EPERM)) {
                struct ucred u;

                /* Hmm, presumably the sender process vanished
                 * by now, or we don't have CAP_SYS_AMDIN, so
                 * let's fix it as good as we can, and retry */

                u = *ucred;
                u.pid = getpid_cached();
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

static void forward_syslog_raw(Server *s, int priority, const char *buffer, size_t buffer_len, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec;

        assert(s);
        assert(buffer);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        iovec = IOVEC_MAKE((char *) buffer, buffer_len);
        forward_syslog_iovec(s, &iovec, 1, ucred, tv);
}

void server_forward_syslog(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv) {
        struct iovec iovec[5];
        char header_priority[DECIMAL_STR_MAX(priority) + 3], header_time[64],
             header_pid[STRLEN("[]: ") + DECIMAL_STR_MAX(pid_t) + 1];
        int n = 0;
        time_t t;
        struct tm tm;
        _cleanup_free_ char *ident_buf = NULL;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (LOG_PRI(priority) > s->max_level_syslog)
                return;

        /* First: priority field */
        xsprintf(header_priority, "<%i>", priority);
        iovec[n++] = IOVEC_MAKE_STRING(header_priority);

        /* Second: timestamp */
        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        if (!localtime_r(&t, &tm))
                return;
        if (strftime(header_time, sizeof(header_time), "%h %e %T ", &tm) <= 0)
                return;
        iovec[n++] = IOVEC_MAKE_STRING(header_time);

        /* Third: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                xsprintf(header_pid, "["PID_FMT"]: ", ucred->pid);

                if (identifier)
                        iovec[n++] = IOVEC_MAKE_STRING(identifier);

                iovec[n++] = IOVEC_MAKE_STRING(header_pid);
        } else if (identifier) {
                iovec[n++] = IOVEC_MAKE_STRING(identifier);
                iovec[n++] = IOVEC_MAKE_STRING(": ");
        }

        /* Fourth: message */
        iovec[n++] = IOVEC_MAKE_STRING(message);

        forward_syslog_iovec(s, iovec, n, ucred, tv);
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

        if (l > 0 && p[l-1] == ']') {
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

        /* Single space is used as separator */
        if (p[e] != '\0' && strchr(WHITESPACE, p[e]))
                e++;

        l = (p - *buf) + e;
        *buf = p + e;
        return l;
}

static int syslog_skip_timestamp(const char **buf) {
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

        const char *p, *t;
        unsigned i;

        assert(buf);
        assert(*buf);

        for (i = 0, p = *buf; i < ELEMENTSOF(sequence); i++, p++) {
                if (!*p)
                        return 0;

                switch (sequence[i]) {

                case SPACE:
                        if (*p != ' ')
                                return 0;
                        break;

                case SPACE_OR_NUMBER:
                        if (*p == ' ')
                                break;

                        _fallthrough_;
                case NUMBER:
                        if (*p < '0' || *p > '9')
                                return 0;

                        break;

                case LETTER:
                        if (!(*p >= 'A' && *p <= 'Z') &&
                            !(*p >= 'a' && *p <= 'z'))
                                return 0;

                        break;

                case COLON:
                        if (*p != ':')
                                return 0;
                        break;

                }
        }

        t = *buf;
        *buf = p;
        return p - t;
}

void server_process_syslog_message(
                Server *s,
                const char *buf,
                size_t raw_len,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len) {

        char *t, syslog_priority[sizeof("PRIORITY=") + DECIMAL_STR_MAX(int)],
                 syslog_facility[sizeof("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int)];
        const char *msg, *syslog_ts, *a;
        _cleanup_free_ char *identifier = NULL, *pid = NULL,
                *dummy = NULL, *msg_msg = NULL, *msg_raw = NULL;
        int priority = LOG_USER | LOG_INFO, r;
        ClientContext *context = NULL;
        struct iovec *iovec;
        size_t n = 0, m, i, leading_ws, syslog_ts_len;
        bool store_raw;

        assert(s);
        assert(buf);
        /* The message cannot be empty. */
        assert(raw_len > 0);
        /* The buffer NUL-terminated and can be used a string. raw_len is the length
         * without the terminating NUL byte, the buffer is actually one bigger. */
        assert(buf[raw_len] == '\0');

        if (ucred && pid_is_valid(ucred->pid)) {
                r = client_context_get(s, ucred->pid, ucred, label, label_len, NULL, &context);
                if (r < 0)
                        log_warning_errno(r, "Failed to retrieve credentials for PID " PID_FMT ", ignoring: %m", ucred->pid);
        }

        /* We are creating a copy of the message because we want to forward the original message
           verbatim to the legacy syslog implementation */
        for (i = raw_len; i > 0; i--)
                if (!strchr(WHITESPACE, buf[i-1]))
                        break;

        leading_ws = strspn(buf, WHITESPACE);

        if (i == 0)
                /* The message contains only whitespaces */
                msg = buf + raw_len;
        else if (i == raw_len)
                /* Nice! No need to strip anything on the end, let's optimize this a bit */
                msg = buf + leading_ws;
        else {
                msg = dummy = new(char, i - leading_ws + 1);
                if (!dummy) {
                        log_oom();
                        return;
                }

                memcpy(dummy, buf + leading_ws, i - leading_ws);
                dummy[i - leading_ws] = 0;
        }

        /* We will add the SYSLOG_RAW= field when we stripped anything
         * _or_ if the input message contained NUL bytes. */
        store_raw = msg != buf || strlen(msg) != raw_len;

        syslog_parse_priority(&msg, &priority, true);

        if (!client_context_test_priority(context, priority))
                return;

        syslog_ts = msg;
        syslog_ts_len = syslog_skip_timestamp(&msg);
        if (syslog_ts_len == 0)
                /* We failed to parse the full timestamp, store the raw message too */
                store_raw = true;

        syslog_parse_identifier(&msg, &identifier, &pid);

        if (s->forward_to_syslog)
                forward_syslog_raw(s, priority, buf, raw_len, ucred, tv);

        if (s->forward_to_kmsg)
                server_forward_kmsg(s, priority, identifier, msg, ucred);

        if (s->forward_to_console)
                server_forward_console(s, priority, identifier, msg, ucred);

        if (s->forward_to_wall)
                server_forward_wall(s, priority, identifier, msg, ucred);

        m = N_IOVEC_META_FIELDS + 8 + client_context_extra_fields_n_iovec(context);
        iovec = newa(struct iovec, m);

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=syslog");

        xsprintf(syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK);
        iovec[n++] = IOVEC_MAKE_STRING(syslog_priority);

        if (priority & LOG_FACMASK) {
                xsprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                iovec[n++] = IOVEC_MAKE_STRING(syslog_facility);
        }

        if (identifier) {
                a = strjoina("SYSLOG_IDENTIFIER=", identifier);
                iovec[n++] = IOVEC_MAKE_STRING(a);
        }

        if (pid) {
                a = strjoina("SYSLOG_PID=", pid);
                iovec[n++] = IOVEC_MAKE_STRING(a);
        }

        if (syslog_ts_len > 0) {
                const size_t hlen = STRLEN("SYSLOG_TIMESTAMP=");

                t = newa(char, hlen + syslog_ts_len);
                memcpy(t, "SYSLOG_TIMESTAMP=", hlen);
                memcpy(t + hlen, syslog_ts, syslog_ts_len);

                iovec[n++] = IOVEC_MAKE(t, hlen + syslog_ts_len);
        }

        msg_msg = strjoin("MESSAGE=", msg);
        if (!msg_msg) {
                log_oom();
                return;
        }
        iovec[n++] = IOVEC_MAKE_STRING(msg_msg);

        if (store_raw) {
                const size_t hlen = STRLEN("SYSLOG_RAW=");

                msg_raw = new(char, hlen + raw_len);
                if (!msg_raw) {
                        log_oom();
                        return;
                }

                memcpy(msg_raw, "SYSLOG_RAW=", hlen);
                memcpy(msg_raw + hlen, buf, raw_len);

                iovec[n++] = IOVEC_MAKE(msg_raw, hlen + raw_len);
        }

        server_dispatch_message(s, iovec, n, m, context, tv, priority, 0);
}

int server_open_syslog_socket(Server *s) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/dev-log",
        };
        int r;

        assert(s);

        if (s->syslog_fd < 0) {
                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->syslog_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                (void) sockaddr_un_unlink(&sa.un);

                r = bind(s->syslog_fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);
        } else
                (void) fd_nonblock(s->syslog_fd, true);

        r = setsockopt_int(s->syslog_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

#if HAVE_SELINUX
        if (mac_selinux_use()) {
                r = setsockopt_int(s->syslog_fd, SOL_SOCKET, SO_PASSSEC, true);
                if (r < 0)
                        log_warning_errno(r, "SO_PASSSEC failed: %m");
        }
#endif

        r = setsockopt_int(s->syslog_fd, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return log_error_errno(r, "SO_TIMESTAMP failed: %m");

        r = sd_event_add_io(s->event, &s->syslog_event_source, s->syslog_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add syslog server fd to event loop: %m");

        r = sd_event_source_set_priority(s->syslog_event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust syslog event source priority: %m");

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

        server_driver_message(s, 0,
                              "MESSAGE_ID=" SD_MESSAGE_FORWARD_SYSLOG_MISSED_STR,
                              LOG_MESSAGE("Forwarding to syslog missed %u messages.",
                                          s->n_forward_syslog_missed),
                              NULL);

        s->n_forward_syslog_missed = 0;
        s->last_warn_forward_syslog_missed = n;
}
