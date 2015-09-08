/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "missing.h"
#include "journald-audit.h"
#include "audit-type.h"

typedef struct MapField {
        const char *audit_field;
        const char *journal_field;
        int (*map)(const char *field, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov);
} MapField;

static int map_simple_field(const char *field, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov) {
        _cleanup_free_ char *c = NULL;
        size_t l = 0, allocated = 0;
        const char *e;

        assert(field);
        assert(p);
        assert(iov);
        assert(n_iov);

        l = strlen(field);
        allocated = l + 1;
        c = malloc(allocated);
        if (!c)
                return -ENOMEM;

        memcpy(c, field, l);
        for (e = *p; *e != ' ' && *e != 0; e++) {
                if (!GREEDY_REALLOC(c, allocated, l+2))
                        return -ENOMEM;

                c[l++] = *e;
        }

        c[l] = 0;

        if (!GREEDY_REALLOC(*iov, *n_iov_allocated, *n_iov + 1))
                return -ENOMEM;

        (*iov)[*n_iov].iov_base = c;
        (*iov)[*n_iov].iov_len = l;
        (*n_iov) ++;

        *p = e;
        c = NULL;

        return 1;
}

static int map_string_field_internal(const char *field, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov, bool filter_printable) {
        _cleanup_free_ char *c = NULL;
        const char *s, *e;
        size_t l;

        assert(field);
        assert(p);
        assert(iov);
        assert(n_iov);

        /* The kernel formats string fields in one of two formats. */

        if (**p == '"') {
                /* Normal quoted syntax */
                s = *p + 1;
                e = strchr(s, '"');
                if (!e)
                        return 0;

                l = strlen(field) + (e - s);
                c = malloc(l+1);
                if (!c)
                        return -ENOMEM;

                *((char*) mempcpy(stpcpy(c, field), s, e - s)) = 0;

                e += 1;

        } else if (unhexchar(**p) >= 0) {
                /* Hexadecimal escaping */
                size_t allocated = 0;

                l = strlen(field);
                allocated = l + 2;
                c = malloc(allocated);
                if (!c)
                        return -ENOMEM;

                memcpy(c, field, l);
                for (e = *p; *e != ' ' && *e != 0; e += 2) {
                        int a, b;
                        uint8_t x;

                        a = unhexchar(e[0]);
                        if (a < 0)
                                return 0;

                        b = unhexchar(e[1]);
                        if (b < 0)
                                return 0;

                        x = ((uint8_t) a << 4 | (uint8_t) b);

                        if (filter_printable && x < (uint8_t) ' ')
                                x = (uint8_t) ' ';

                        if (!GREEDY_REALLOC(c, allocated, l+2))
                                return -ENOMEM;

                        c[l++] = (char) x;
                }

                c[l] = 0;
        } else
                return 0;

        if (!GREEDY_REALLOC(*iov, *n_iov_allocated, *n_iov + 1))
                return -ENOMEM;

        (*iov)[*n_iov].iov_base = c;
        (*iov)[*n_iov].iov_len = l;
        (*n_iov) ++;

        *p = e;
        c = NULL;

        return 1;
}

static int map_string_field(const char *field, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov) {
        return map_string_field_internal(field, p, iov, n_iov_allocated, n_iov, false);
}

static int map_string_field_printable(const char *field, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov) {
        return map_string_field_internal(field, p, iov, n_iov_allocated, n_iov, true);
}

static int map_generic_field(const char *prefix, const char **p, struct iovec **iov, size_t *n_iov_allocated, unsigned *n_iov) {
        const char *e, *f;
        char *c, *t;
        int r;

        /* Implements fallback mappings for all fields we don't know */

        for (e = *p; e < *p + 16; e++) {

                if (*e == 0 || *e == ' ')
                        return 0;

                if (*e == '=')
                        break;

                if (!((*e >= 'a' && *e <= 'z') ||
                      (*e >= 'A' && *e <= 'Z') ||
                      (*e >= '0' && *e <= '9') ||
                      *e == '_' || *e == '-'))
                        return 0;
        }

        if (e <= *p || e >= *p + 16)
                return 0;

        c = alloca(strlen(prefix) + (e - *p) + 2);

        t = stpcpy(c, prefix);
        for (f = *p; f < e; f++) {
                char x;

                if (*f >= 'a' && *f <= 'z')
                        x = (*f - 'a') + 'A'; /* uppercase */
                else if (*f == '-')
                        x = '_'; /* dashes → underscores */
                else
                        x = *f;

                *(t++) = x;
        }
        strcpy(t, "=");

        e ++;

        r = map_simple_field(c, &e, iov, n_iov_allocated, n_iov);
        if (r < 0)
                return r;

        *p = e;
        return r;
}

/* Kernel fields are those occurring in the audit string before
 * msg='. All of these fields are trusted, hence carry the "_" prefix.
 * We try to translate the fields we know into our native names. The
 * other's are generically mapped to _AUDIT_FIELD_XYZ= */
static const MapField map_fields_kernel[] = {

        /* First, we map certain well-known audit fields into native
         * well-known fields */
        { "pid=",       "_PID=",                   map_simple_field },
        { "ppid=",      "_PPID=",                  map_simple_field },
        { "uid=",       "_UID=",                   map_simple_field },
        { "euid=",      "_EUID=",                  map_simple_field },
        { "fsuid=",     "_FSUID=",                 map_simple_field },
        { "gid=",       "_GID=",                   map_simple_field },
        { "egid=",      "_EGID=",                  map_simple_field },
        { "fsgid=",     "_FSGID=",                 map_simple_field },
        { "tty=",       "_TTY=",                   map_simple_field },
        { "ses=",       "_AUDIT_SESSION=",         map_simple_field },
        { "auid=",      "_AUDIT_LOGINUID=",        map_simple_field },
        { "subj=",      "_SELINUX_CONTEXT=",       map_simple_field },
        { "comm=",      "_COMM=",                  map_string_field },
        { "exe=",       "_EXE=",                   map_string_field },
        { "proctitle=", "_CMDLINE=",               map_string_field_printable },

        /* Some fields don't map to native well-known fields. However,
         * we know that they are string fields, hence let's undo
         * string field escaping for them, though we stick to the
         * generic field names. */
        { "path=",      "_AUDIT_FIELD_PATH=",      map_string_field },
        { "dev=",       "_AUDIT_FIELD_DEV=",       map_string_field },
        { "name=",      "_AUDIT_FIELD_NAME=",      map_string_field },
        {}
};

/* Userspace fields are those occurring in the audit string after
 * msg='. All of these fields are untrusted, hence carry no "_"
 * prefix. We map the fields we don't know to AUDIT_FIELD_XYZ= */
static const MapField map_fields_userspace[] = {
        { "cwd=",       "AUDIT_FIELD_CWD=",  map_string_field },
        { "cmd=",       "AUDIT_FIELD_CMD=",  map_string_field },
        { "acct=",      "AUDIT_FIELD_ACCT=", map_string_field },
        { "exe=",       "AUDIT_FIELD_EXE=",  map_string_field },
        { "comm=",      "AUDIT_FIELD_COMM=", map_string_field },
        {}
};

static int map_all_fields(
                const char *p,
                const MapField map_fields[],
                const char *prefix,
                bool handle_msg,
                struct iovec **iov,
                size_t *n_iov_allocated,
                unsigned *n_iov) {

        int r;

        assert(p);
        assert(iov);
        assert(n_iov_allocated);
        assert(n_iov);

        for (;;) {
                bool mapped = false;
                const MapField *m;
                const char *v;

                p += strspn(p, WHITESPACE);

                if (*p == 0)
                        return 0;

                if (handle_msg) {
                        v = startswith(p, "msg='");
                        if (v) {
                                const char *e;
                                char *c;

                                /* Userspace message. It's enclosed in
                                   simple quotation marks, is not
                                   escaped, but the last field in the
                                   line, hence let's remove the
                                   quotation mark, and apply the
                                   userspace mapping instead of the
                                   kernel mapping. */

                                e = endswith(v, "'");
                                if (!e)
                                        return 0; /* don't continue splitting up if the final quotation mark is missing */

                                c = strndupa(v, e - v);
                                return map_all_fields(c, map_fields_userspace, "AUDIT_FIELD_", false, iov, n_iov_allocated, n_iov);
                        }
                }

                /* Try to map the kernel fields to our own names */
                for (m = map_fields; m->audit_field; m++) {
                        v = startswith(p, m->audit_field);
                        if (!v)
                                continue;

                        r = m->map(m->journal_field, &v, iov, n_iov_allocated, n_iov);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse audit array: %m");

                        if (r > 0) {
                                mapped = true;
                                p = v;
                                break;
                        }
                }

                if (!mapped) {
                        r = map_generic_field(prefix, &p, iov, n_iov_allocated, n_iov);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse audit array: %m");

                        if (r == 0)
                                /* Couldn't process as generic field, let's just skip over it */
                                p += strcspn(p, WHITESPACE);
                }
        }
}

static void process_audit_string(Server *s, int type, const char *data, size_t size) {
        _cleanup_free_ struct iovec *iov = NULL;
        size_t n_iov_allocated = 0;
        unsigned n_iov = 0, k;
        uint64_t seconds, msec, id;
        const char *p, *type_name;
        unsigned z;
        char id_field[sizeof("_AUDIT_ID=") + DECIMAL_STR_MAX(uint64_t)],
             type_field[sizeof("_AUDIT_TYPE=") + DECIMAL_STR_MAX(int)],
             source_time_field[sizeof("_SOURCE_REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t)];
        char *m;

        assert(s);

        if (size <= 0)
                return;

        if (!data)
                return;

        /* Note that the input buffer is NUL terminated, but let's
         * check whether there is a spurious NUL byte */
        if (memchr(data, 0, size))
                return;

        p = startswith(data, "audit");
        if (!p)
                return;

        if (sscanf(p, "(%" PRIu64 ".%" PRIu64 ":%" PRIu64 "):%n",
                   &seconds,
                   &msec,
                   &id,
                   &k) != 3)
                return;

        p += k;
        p += strspn(p, WHITESPACE);

        if (isempty(p))
                return;

        n_iov_allocated = N_IOVEC_META_FIELDS + 7;
        iov = new(struct iovec, n_iov_allocated);
        if (!iov) {
                log_oom();
                return;
        }

        IOVEC_SET_STRING(iov[n_iov++], "_TRANSPORT=audit");

        sprintf(source_time_field, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64,
                (usec_t) seconds * USEC_PER_SEC + (usec_t) msec * USEC_PER_MSEC);
        IOVEC_SET_STRING(iov[n_iov++], source_time_field);

        sprintf(type_field, "_AUDIT_TYPE=%i", type);
        IOVEC_SET_STRING(iov[n_iov++], type_field);

        sprintf(id_field, "_AUDIT_ID=%" PRIu64, id);
        IOVEC_SET_STRING(iov[n_iov++], id_field);

        assert_cc(32 == LOG_AUTH);
        IOVEC_SET_STRING(iov[n_iov++], "SYSLOG_FACILITY=32");
        IOVEC_SET_STRING(iov[n_iov++], "SYSLOG_IDENTIFIER=audit");

        type_name = audit_type_name_alloca(type);

        m = strjoina("MESSAGE=", type_name, " ", p);
        IOVEC_SET_STRING(iov[n_iov++], m);

        z = n_iov;

        map_all_fields(p, map_fields_kernel, "_AUDIT_FIELD_", true, &iov, &n_iov_allocated, &n_iov);

        if (!GREEDY_REALLOC(iov, n_iov_allocated, n_iov + N_IOVEC_META_FIELDS)) {
                log_oom();
                goto finish;
        }

        server_dispatch_message(s, iov, n_iov, n_iov_allocated, NULL, NULL, NULL, 0, NULL, LOG_NOTICE, 0);

finish:
        /* free() all entries that map_all_fields() added. All others
         * are allocated on the stack or are constant. */

        for (; z < n_iov; z++)
                free(iov[z].iov_base);
}

void server_process_audit_message(
                Server *s,
                const void *buffer,
                size_t buffer_size,
                const struct ucred *ucred,
                const union sockaddr_union *sa,
                socklen_t salen) {

        const struct nlmsghdr *nl = buffer;

        assert(s);

        if (buffer_size < ALIGN(sizeof(struct nlmsghdr)))
                return;

        assert(buffer);

        /* Filter out fake data */
        if (!sa ||
            salen != sizeof(struct sockaddr_nl) ||
            sa->nl.nl_family != AF_NETLINK ||
            sa->nl.nl_pid != 0) {
                log_debug("Audit netlink message from invalid sender.");
                return;
        }

        if (!ucred || ucred->pid != 0) {
                log_debug("Audit netlink message with invalid credentials.");
                return;
        }

        if (!NLMSG_OK(nl, buffer_size)) {
                log_error("Audit netlink message truncated.");
                return;
        }

        /* Ignore special Netlink messages */
        if (IN_SET(nl->nlmsg_type, NLMSG_NOOP, NLMSG_ERROR))
                return;

        /* Below AUDIT_FIRST_USER_MSG theer are only control messages, let's ignore those */
        if (nl->nlmsg_type < AUDIT_FIRST_USER_MSG)
                return;

        process_audit_string(s, nl->nlmsg_type, NLMSG_DATA(nl), nl->nlmsg_len - ALIGN(sizeof(struct nlmsghdr)));
}

static int enable_audit(int fd, bool b) {
        struct {
                union {
                        struct nlmsghdr header;
                        uint8_t header_space[NLMSG_HDRLEN];
                };
                struct audit_status body;
        } _packed_ request = {
                .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct audit_status)),
                .header.nlmsg_type = AUDIT_SET,
                .header.nlmsg_flags = NLM_F_REQUEST,
                .header.nlmsg_seq = 1,
                .header.nlmsg_pid = 0,
                .body.mask = AUDIT_STATUS_ENABLED,
                .body.enabled = b,
        };
        union sockaddr_union sa = {
                .nl.nl_family = AF_NETLINK,
                .nl.nl_pid = 0,
        };
        struct iovec iovec = {
                .iov_base = &request,
                .iov_len = NLMSG_LENGTH(sizeof(struct audit_status)),
        };
        struct msghdr mh = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.nl),
        };

        ssize_t n;

        n = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (n < 0)
                return -errno;
        if (n != NLMSG_LENGTH(sizeof(struct audit_status)))
                return -EIO;

        /* We don't wait for the result here, we can't do anything
         * about it anyway */

        return 0;
}

int server_open_audit(Server *s) {
        static const int one = 1;
        int r;

        if (s->audit_fd < 0) {
                static const union sockaddr_union sa = {
                        .nl.nl_family = AF_NETLINK,
                        .nl.nl_pid    = 0,
                        .nl.nl_groups = AUDIT_NLGRP_READLOG,
                };

                s->audit_fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
                if (s->audit_fd < 0) {
                        if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
                                log_debug("Audit not supported in the kernel.");
                        else
                                log_warning_errno(errno, "Failed to create audit socket, ignoring: %m");

                        return 0;
                }

                if (bind(s->audit_fd, &sa.sa, sizeof(sa.nl)) < 0) {
                        log_warning_errno(errno,
                                          "Failed to join audit multicast group. "
                                          "The kernel is probably too old or multicast reading is not supported. "
                                          "Ignoring: %m");
                        s->audit_fd = safe_close(s->audit_fd);
                        return 0;
                }
        } else
                fd_nonblock(s->audit_fd, 1);

        r = setsockopt(s->audit_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "Failed to set SO_PASSCRED on audit socket: %m");

        r = sd_event_add_io(s->event, &s->audit_event_source, s->audit_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add audit fd to event loop: %m");

        /* We are listening now, try to enable audit */
        r = enable_audit(s->audit_fd, true);
        if (r < 0)
                log_warning_errno(r, "Failed to issue audit enable call: %m");

        return 0;
}
