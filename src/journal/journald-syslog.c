/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "iovec-util.h"
#include "journal-internal.h"
#include "journald-client.h"
#include "journald-console.h"
#include "journald-context.h"
#include "journald-kmsg.h"
#include "journald-manager.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "log.h"
#include "log-ratelimit.h"
#include "parse-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "time-util.h"

/* Warn once every 30s if we missed syslog message */
#define WARN_FORWARD_SYSLOG_MISSED_USEC (30 * USEC_PER_SEC)

static void forward_syslog_iovec(
                Manager *m,
                const struct iovec *iovec,
                unsigned n_iovec,
                const struct ucred *ucred,
                const struct timeval *tv) {

        union sockaddr_union sa;

        struct msghdr msghdr = {
                .msg_iov = (struct iovec *) iovec,
                .msg_iovlen = n_iovec,
        };
        struct cmsghdr *cmsg;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        const char *j;
        int r;

        assert(m);
        assert(iovec);
        assert(n_iovec > 0);

        j = strjoina(m->runtime_directory, "/syslog");
        r = sockaddr_un_set_path(&sa.un, j);
        if (r < 0) {
                log_debug_errno(r, "Forwarding socket path %s too long for AF_UNIX, not forwarding: %m", j);
                return;
        }

        msghdr.msg_name = &sa.sa;
        msghdr.msg_namelen = r;

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

        /* Forward the syslog message we received via /dev/log to /run/systemd/syslog. Unfortunately we
         * currently can't set the SO_TIMESTAMP auxiliary data, and hence we don't. */

        if (sendmsg(m->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return;

        /* The socket is full? I guess the syslog implementation is
         * too slow, and we shouldn't wait for that... */
        if (errno == EAGAIN) {
                m->n_forward_syslog_missed++;
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

                if (sendmsg(m->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                        return;

                if (errno == EAGAIN) {
                        m->n_forward_syslog_missed++;
                        return;
                }
        }

        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to forward syslog message: %m");
}

static void forward_syslog_raw(
                Manager *m,
                int priority,
                const char *buffer,
                size_t buffer_len,
                const struct ucred *ucred,
                const struct timeval *tv) {

        struct iovec iovec;

        assert(m);
        assert(buffer);

        if (LOG_PRI(priority) > m->config.max_level_syslog)
                return;

        iovec = IOVEC_MAKE((char *) buffer, buffer_len);
        forward_syslog_iovec(m, &iovec, 1, ucred, tv);
}

void manager_forward_syslog(
                Manager *m,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred,
                const struct timeval *tv) {

        struct iovec iovec[5];
        char header_priority[DECIMAL_STR_MAX(priority) + 3], header_time[64],
             header_pid[STRLEN("[]: ") + DECIMAL_STR_MAX(pid_t) + 1];
        int n = 0;
        struct tm tm;
        _cleanup_free_ char *ident_buf = NULL;

        assert(m);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (LOG_PRI(priority) > m->config.max_level_syslog)
                return;

        /* First: priority field */
        xsprintf(header_priority, "<%i>", priority);
        iovec[n++] = IOVEC_MAKE_STRING(header_priority);

        /* Second: timestamp */
        if (localtime_or_gmtime_usec(tv ? tv->tv_sec * USEC_PER_SEC : now(CLOCK_REALTIME), /* utc= */ false, &tm) < 0)
                return;
        if (strftime(header_time, sizeof(header_time), "%h %e %T ", &tm) <= 0)
                return;
        iovec[n++] = IOVEC_MAKE_STRING(header_time);

        /* Third: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        (void) pid_get_comm(ucred->pid, &ident_buf);
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

        forward_syslog_iovec(m, iovec, n, ucred, tv);
}

int syslog_fixup_facility(int priority) {

        if (LOG_FAC(priority) == 0)
                return LOG_PRI(priority) | LOG_USER;

        return priority;
}

size_t syslog_parse_identifier(const char **buf, char **ret_identifier, pid_t *ret_pid) {
        const char *p;
        size_t l, e;
        pid_t pid = 0;

        assert(buf);
        assert(ret_identifier);
        assert(ret_pid);

        p = *buf;

        p += strspn(p, WHITESPACE);
        l = strcspn(p, WHITESPACE);

        if (l <= 0 ||
            p[l-1] != ':') {
                *ret_identifier = NULL;
                *ret_pid = 0;
                return 0;
        }

        e = l;
        l--;

        if (l > 0 && p[l-1] == ']') {
                size_t k = l-1;

                for (;;) {

                        if (p[k] == '[') {
                                _cleanup_free_ char *t = strndup(p+k+1, l-k-2);
                                if (t)
                                        (void) parse_pid(t, &pid);

                                l = k;
                                break;
                        }

                        if (k == 0)
                                break;

                        k--;
                }
        }

        /* The syslog identifier should be short enough in most cases and NAME_MAX should be enough. Let's
         * refuse ridiculously long identifier string as "no identifier string found", because if it is
         * longer than some threshold then it is quite likely some misformatted data, and not a valid syslog
         * message. Note. NAME_MAX is counted *without* the trailing NUL. */
        _cleanup_free_ char *identifier = NULL;
        if (l <= NAME_MAX)
                identifier = strndup(p, l); /* ignore OOM here. */

        /* Single space is used as separator */
        if (p[e] != '\0' && strchr(WHITESPACE, p[e]))
                e++;

        l = (p - *buf) + e;
        *buf = p + e;
        *ret_identifier = TAKE_PTR(identifier);
        *ret_pid = pid;
        return l;
}

static size_t syslog_skip_timestamp(const char **buf) {
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
        size_t i;

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
                        if (!ascii_isdigit(*p))
                                return 0;

                        break;

                case LETTER:
                        if (!ascii_isalpha(*p))
                                return 0;

                        break;

                case COLON:
                        if (*p != ':')
                                return 0;
                        break;
                }
        }

        assert(p >= *buf);
        size_t n = p - *buf;
        assert(n <= ELEMENTSOF(sequence));

        *buf = p;
        return n;
}

void manager_process_syslog_message(
                Manager *m,
                const char *buf,
                size_t raw_len,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len) {

        char *t, syslog_priority[STRLEN("PRIORITY=") + DECIMAL_STR_MAX(int)],
                 syslog_facility[STRLEN("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int)];
        const char *msg, *syslog_ts, *a;
        _cleanup_free_ char *dummy = NULL, *msg_msg = NULL, *msg_raw = NULL;
        int priority = LOG_USER | LOG_INFO, r;
        ClientContext *context = NULL;
        struct iovec *iovec;
        size_t n = 0, mm, i, leading_ws, syslog_ts_len;
        bool store_raw;

        assert(m);
        assert(buf);
        /* The message cannot be empty. */
        assert(raw_len > 0);
        /* The buffer NUL-terminated and can be used a string. raw_len is the length
         * without the terminating NUL byte, the buffer is actually one bigger. */
        assert(buf[raw_len] == '\0');

        if (ucred && pid_is_valid(ucred->pid)) {
                r = client_context_get(m, ucred->pid, ucred, label, label_len, NULL, &context);
                if (r < 0)
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to retrieve credentials for PID " PID_FMT ", ignoring: %m",
                                                    ucred->pid);
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

        _cleanup_free_ char *identifier = NULL;
        pid_t pid;
        syslog_parse_identifier(&msg, &identifier, &pid);

        if (client_context_check_keep_log(context, msg, strlen(msg)) <= 0)
                return;

        if (m->config.forward_to_syslog)
                forward_syslog_raw(m, priority, buf, raw_len, ucred, tv);

        if (m->config.forward_to_kmsg)
                manager_forward_kmsg(m, priority, identifier, msg, ucred);

        if (m->config.forward_to_console)
                manager_forward_console(m, priority, identifier, msg, ucred);

        if (m->config.forward_to_wall)
                manager_forward_wall(m, priority, identifier, msg, ucred);

        mm = N_IOVEC_META_FIELDS + 8 + client_context_extra_fields_n_iovec(context);
        iovec = newa(struct iovec, mm);

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=syslog");

        xsprintf(syslog_priority, "PRIORITY=%i", LOG_PRI(priority));
        iovec[n++] = IOVEC_MAKE_STRING(syslog_priority);

        if (LOG_FAC(priority) != 0) {
                xsprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                iovec[n++] = IOVEC_MAKE_STRING(syslog_facility);
        }

        if (identifier) {
                a = strjoina("SYSLOG_IDENTIFIER=", identifier);
                iovec[n++] = IOVEC_MAKE_STRING(a);
        }

        char syslog_pid[STRLEN("SYSLOG_PID=") + DECIMAL_STR_MAX(pid_t)];
        if (pid_is_valid(pid)) {
                xsprintf(syslog_pid, "SYSLOG_PID="PID_FMT, pid);
                iovec[n++] = IOVEC_MAKE_STRING(syslog_pid);
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

        manager_dispatch_message(m, iovec, n, mm, context, tv, priority, 0);
}

int manager_open_syslog_socket(Manager *m, const char *syslog_socket) {
        int r;

        assert(m);
        assert(syslog_socket);

        if (m->syslog_fd < 0) {
                union sockaddr_union sa;
                socklen_t sa_len;

                r = sockaddr_un_set_path(&sa.un, syslog_socket);
                if (r < 0)
                        return log_error_errno(r, "Unable to use namespace path %s for AF_UNIX socket: %m", syslog_socket);
                sa_len = r;

                m->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (m->syslog_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                (void) sockaddr_un_unlink(&sa.un);

                r = bind(m->syslog_fd, &sa.sa, sa_len);
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);
        } else
                (void) fd_nonblock(m->syslog_fd, true);

        r = setsockopt_int(m->syslog_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SO_PASSCRED: %m");

        r = setsockopt_int(m->syslog_fd, SOL_SOCKET, SO_PASSRIGHTS, false);
        if (r < 0)
                log_debug_errno(r, "Failed to turn off SO_PASSRIGHTS, ignoring: %m");

        if (mac_selinux_use()) {
                r = setsockopt_int(m->syslog_fd, SOL_SOCKET, SO_PASSSEC, true);
                if (r < 0)
                        log_full_errno(ERRNO_IS_NEG_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to enable SO_PASSSEC, ignoring: %m");
        }

        r = setsockopt_int(m->syslog_fd, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SO_TIMESTAMP: %m");

        r = sd_event_add_io(m->event, &m->syslog_event_source, m->syslog_fd, EPOLLIN, manager_process_datagram, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add syslog sevrer fd to event loop: %m");

        r = sd_event_source_set_priority(m->syslog_event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust syslog event source priority: %m");

        return 0;
}

void manager_maybe_warn_forward_syslog_missed(Manager *m) {
        usec_t n;

        assert(m);

        if (m->n_forward_syslog_missed <= 0)
                return;

        n = now(CLOCK_MONOTONIC);
        if (m->last_warn_forward_syslog_missed + WARN_FORWARD_SYSLOG_MISSED_USEC > n)
                return;

        manager_driver_message(m, 0,
                               LOG_MESSAGE_ID(SD_MESSAGE_FORWARD_SYSLOG_MISSED_STR),
                               LOG_MESSAGE("Forwarding to syslog missed %u messages.",
                                           m->n_forward_syslog_missed));

        m->n_forward_syslog_missed = 0;
        m->last_warn_forward_syslog_missed = n;
}
