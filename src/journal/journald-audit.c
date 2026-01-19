/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/audit.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "audit-type.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "journal-internal.h"
#include "journald-audit.h"
#include "journald-manager.h"
#include "log.h"
#include "log-ratelimit.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"

typedef struct MapField {
        const char *audit_field;
        const char *journal_field;
        int (*map)(const char *field, const char **p, struct iovec *iovec, size_t *n);
} MapField;

static int map_simple_field(
                const char *field,
                const char **p,
                struct iovec *iovec,
                size_t *n) {

        _cleanup_free_ char *c = NULL;
        size_t l = 0;
        const char *e;

        assert(field);
        assert(p);
        assert(iovec);
        assert(n);

        l = strlen(field);
        c = malloc(l + 1);
        if (!c)
                return -ENOMEM;

        memcpy(c, field, l);
        for (e = *p; !IN_SET(*e, 0, ' '); e++) {
                if (!GREEDY_REALLOC(c, l+2))
                        return -ENOMEM;

                c[l++] = *e;
        }

        c[l] = 0;

        iovec[(*n)++] = IOVEC_MAKE(c, l);

        *p = e;
        c = NULL;

        return 1;
}

static int map_string_field_internal(
                const char *field,
                const char **p,
                struct iovec *iovec,
                size_t *n,
                bool filter_printable) {

        _cleanup_free_ char *c = NULL;
        const char *s, *e;
        size_t l;

        assert(field);
        assert(p);
        assert(iovec);
        assert(n);

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

                *mempcpy_typesafe(stpcpy(c, field), s, e - s) = 0;

                e += 1;

        } else if (unhexchar(**p) >= 0) {
                /* Hexadecimal escaping */
                l = strlen(field);
                c = malloc(l + 2);
                if (!c)
                        return -ENOMEM;

                memcpy(c, field, l);
                for (e = *p; !IN_SET(*e, 0, ' '); e += 2) {
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

                        if (!GREEDY_REALLOC(c, l+2))
                                return -ENOMEM;

                        c[l++] = (char) x;
                }

                c[l] = 0;
        } else
                return 0;

        iovec[(*n)++] = IOVEC_MAKE(c, l);

        *p = e;
        c = NULL;

        return 1;
}

static int map_string_field(const char *field, const char **p, struct iovec *iovec, size_t *n) {
        return map_string_field_internal(field, p, iovec, n, false);
}

static int map_string_field_printable(const char *field, const char **p, struct iovec *iovec, size_t *n) {
        return map_string_field_internal(field, p, iovec, n, true);
}

static int map_generic_field(
                const char *prefix,
                const char **p,
                struct iovec *iovec,
                size_t *n) {

        const char *e, *f;
        char *c, *t;
        int r;

        /* Implements fallback mappings for all fields we don't know */

        for (e = *p; e < *p + 16; e++) {

                if (IN_SET(*e, 0, ' '))
                        return 0;

                if (*e == '=')
                        break;

                if (!(ascii_isalpha(*e) ||
                      ascii_isdigit(*e) ||
                      IN_SET(*e, '_', '-')))
                        return 0;
        }

        if (e <= *p || e >= *p + 16)
                return 0;

        c = newa(char, strlen(prefix) + (e - *p) + 2);

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

        e++;

        r = map_simple_field(c, &e, iovec, n);
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
        { "pid=",       "_PID=",              map_simple_field },
        { "ppid=",      "_PPID=",             map_simple_field },
        { "uid=",       "_UID=",              map_simple_field },
        { "euid=",      "_EUID=",             map_simple_field },
        { "fsuid=",     "_FSUID=",            map_simple_field },
        { "gid=",       "_GID=",              map_simple_field },
        { "egid=",      "_EGID=",             map_simple_field },
        { "fsgid=",     "_FSGID=",            map_simple_field },
        { "tty=",       "_TTY=",              map_simple_field },
        { "ses=",       "_AUDIT_SESSION=",    map_simple_field },
        { "auid=",      "_AUDIT_LOGINUID=",   map_simple_field },
        { "subj=",      "_SELINUX_CONTEXT=",  map_simple_field },
        { "comm=",      "_COMM=",             map_string_field },
        { "exe=",       "_EXE=",              map_string_field },
        { "proctitle=", "_CMDLINE=",          map_string_field_printable },

        /* Some fields don't map to native well-known fields. However,
         * we know that they are string fields, hence let's undo
         * string field escaping for them, though we stick to the
         * generic field names. */
        { "path=",      "_AUDIT_FIELD_PATH=", map_string_field },
        { "dev=",       "_AUDIT_FIELD_DEV=",  map_string_field },
        { "name=",      "_AUDIT_FIELD_NAME=", map_string_field },
        {}
};

/* Userspace fields are those occurring in the audit string after
 * msg='. All of these fields are untrusted, hence carry no "_"
 * prefix. We map the fields we don't know to AUDIT_FIELD_XYZ= */
static const MapField map_fields_userspace[] = {
        { "cwd=",       "AUDIT_FIELD_CWD=",   map_string_field },
        { "cmd=",       "AUDIT_FIELD_CMD=",   map_string_field },
        { "acct=",      "AUDIT_FIELD_ACCT=",  map_string_field },
        { "exe=",       "AUDIT_FIELD_EXE=",   map_string_field },
        { "comm=",      "AUDIT_FIELD_COMM=",  map_string_field },
        {}
};

static int map_all_fields(
                const char *p,
                const MapField map_fields[],
                const char *prefix,
                bool handle_msg,
                struct iovec *iovec,
                size_t *n,
                size_t m) {

        int r;

        assert(p);
        assert(iovec);
        assert(n);

        for (;;) {
                bool mapped = false;
                const MapField *mf;
                const char *v;

                if (*n >= m) {
                        log_debug(
                                "More fields in audit message than audit field limit (%i), skipping remaining fields",
                                N_IOVEC_AUDIT_FIELDS);
                        return 0;
                }

                p += strspn(p, WHITESPACE);

                if (*p == 0)
                        return 0;

                if (handle_msg) {
                        v = startswith(p, "msg='");
                        if (v) {
                                _cleanup_free_ char *c = NULL;
                                const char *e;

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

                                c = strndup(v, e - v);
                                if (!c)
                                        return -ENOMEM;

                                return map_all_fields(c, map_fields_userspace, "AUDIT_FIELD_", false, iovec, n, m);
                        }
                }

                /* Try to map the kernel fields to our own names */
                for (mf = map_fields; mf->audit_field; mf++) {
                        v = startswith(p, mf->audit_field);
                        if (!v)
                                continue;

                        r = mf->map(mf->journal_field, &v, iovec, n);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse audit array: %m");

                        if (r > 0) {
                                mapped = true;
                                p = v;
                                break;
                        }
                }

                if (!mapped) {
                        r = map_generic_field(prefix, &p, iovec, n);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse audit array: %m");

                        if (r == 0)
                                /* Couldn't process as generic field, let's just skip over it */
                                p += strcspn(p, WHITESPACE);
                }
        }
}

void process_audit_string(Manager *m, int type, const char *data, size_t size) {
        size_t n = 0, z;
        uint64_t seconds, msec, id;
        const char *p, *type_name, *type_field_name, *mm;
        char id_field[STRLEN("_AUDIT_ID=") + DECIMAL_STR_MAX(uint64_t)],
                type_field[STRLEN("_AUDIT_TYPE=") + DECIMAL_STR_MAX(int)];
        struct iovec iovec[N_IOVEC_META_FIELDS + 7 + N_IOVEC_AUDIT_FIELDS];
        int k;

        assert(m);

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

        k = 0;
        if (sscanf(p, "(%" PRIu64 ".%" PRIu64 ":%" PRIu64 "):%n",
                   &seconds,
                   &msec,
                   &id,
                   &k) != 3 || k == 0)
                return;

        p += k;
        p += strspn(p, WHITESPACE);

        if (isempty(p))
                return;

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=audit");

        xsprintf(type_field, "_AUDIT_TYPE=%i", type);
        iovec[n++] = IOVEC_MAKE_STRING(type_field);

        xsprintf(id_field, "_AUDIT_ID=%" PRIu64, id);
        iovec[n++] = IOVEC_MAKE_STRING(id_field);

        assert_cc(4 == LOG_FAC(LOG_AUTH));
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_FACILITY=4");
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_IDENTIFIER=audit");

        type_name = audit_type_name_alloca(type);

        type_field_name = strjoina("_AUDIT_TYPE_NAME=", type_name);
        iovec[n++] = IOVEC_MAKE_STRING(type_field_name);

        _cleanup_free_ char *mm_alloc = strjoin("MESSAGE=", type_name, " ", p);
        if (mm_alloc)
                mm = mm_alloc;
        else
                mm = strjoina("MESSAGE=", type_name, " (message is truncated because of OOM)");
        iovec[n++] = IOVEC_MAKE_STRING(mm);

        z = n;

        map_all_fields(p, map_fields_kernel, "_AUDIT_FIELD_", true, iovec, &n, n + N_IOVEC_AUDIT_FIELDS);

        manager_dispatch_message(m, iovec, n, ELEMENTSOF(iovec), NULL,
                                 TIMEVAL_STORE((usec_t) seconds * USEC_PER_SEC + (usec_t) msec * USEC_PER_MSEC),
                                 LOG_NOTICE, 0);

        /* free() all entries that map_all_fields() added. All others are allocated on the stack, constant,
         * or freed by their _cleanup_ attributes. */
        for (; z < n; z++)
                free(iovec[z].iov_base);
}

void manager_process_audit_message(
                Manager *m,
                const void *buffer,
                size_t buffer_size,
                const struct ucred *ucred,
                const union sockaddr_union *sa,
                socklen_t salen) {

        const struct nlmsghdr *nl = buffer;

        assert(m);

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
                log_ratelimit_error(JOURNAL_LOG_RATELIMIT, "Audit netlink message truncated.");
                return;
        }

        /* Ignore special Netlink messages */
        if (IN_SET(nl->nlmsg_type, NLMSG_NOOP, NLMSG_ERROR))
                return;

        /* Except AUDIT_USER, all messages below AUDIT_FIRST_USER_MSG are control messages, let's ignore those */
        if (nl->nlmsg_type < AUDIT_FIRST_USER_MSG && nl->nlmsg_type != AUDIT_USER)
                return;

        process_audit_string(m, nl->nlmsg_type, NLMSG_DATA(nl), nl->nlmsg_len - ALIGN(sizeof(struct nlmsghdr)));
}

static int manager_set_kernel_audit(Manager *m) {
        int r;

        assert(m);
        assert(m->audit_fd >= 0);
        assert(m->config.set_audit >= 0);

        if (m->config.set_audit == AUDIT_KEEP)
                return 0;

        /* In the following, we can handle 'set_audit' as a boolean. */
        assert(IN_SET(m->config.set_audit, AUDIT_NO, AUDIT_YES));

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
                .body.enabled = m->config.set_audit,
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

        r = 0;
        ssize_t n = sendmsg(m->audit_fd, &mh, MSG_NOSIGNAL);
        if (n < 0)
                r = -errno;
        if (n != NLMSG_LENGTH(sizeof(struct audit_status)))
                r = SYNTHETIC_ERRNO(EIO);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s kernel auditing: %m", enable_disable(m->config.set_audit));

        /* We don't wait for the result here, we can't do anything about it anyway. */

        log_debug("Auditing in kernel is %s.", enabled_disabled(m->config.set_audit));
        return 0;
}

int manager_open_audit(Manager *m) {
        int r;

        if (m->audit_fd < 0) {
                static const union sockaddr_union sa = {
                        .nl.nl_family = AF_NETLINK,
                        .nl.nl_pid    = 0,
                        .nl.nl_groups = AUDIT_NLGRP_READLOG,
                };

                m->audit_fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
                if (m->audit_fd < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno))
                                log_debug("Audit not supported in the kernel.");
                        else
                                log_warning_errno(errno, "Failed to create audit socket, ignoring: %m");

                        return 0;
                }

                if (bind(m->audit_fd, &sa.sa, sizeof(sa.nl)) < 0) {
                        log_warning_errno(errno,
                                          "Failed to join audit multicast group. "
                                          "The kernel is probably too old or multicast reading is not supported. "
                                          "Ignoring: %m");
                        m->audit_fd = safe_close(m->audit_fd);
                        return 0;
                }
        } else
                (void) fd_nonblock(m->audit_fd, true);

        r = setsockopt_int(m->audit_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set SO_PASSCRED on audit socket: %m");

        r = sd_event_add_io(m->event, &m->audit_event_source, m->audit_fd, EPOLLIN, manager_process_datagram, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add audit fd to event loop: %m");

        (void) manager_set_kernel_audit(m);
        return 0;
}

void manager_reset_kernel_audit(Manager *m, AuditSetMode old_set_audit) {
        assert(m);

        if (m->audit_fd < 0)
                return;

        if (m->config.set_audit == old_set_audit)
                return;

        (void) manager_set_kernel_audit(m);
}
