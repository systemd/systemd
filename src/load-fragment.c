/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <linux/oom.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <linux/fs.h>

#include "unit.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "log.h"
#include "ioprio.h"
#include "securebits.h"
#include "missing.h"
#include "unit-name.h"

#define COMMENTS "#;\n"
#define LINE_MAX 4096

#define DEFINE_CONFIG_PARSE_ENUM(function,name,type,msg)                \
        static int function(                                            \
                        const char *filename,                           \
                        unsigned line,                                  \
                        const char *section,                            \
                        const char *lvalue,                             \
                        const char *rvalue,                             \
                        void *data,                                     \
                        void *userdata) {                               \
                                                                        \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                if ((x = name##_from_string(rvalue)) < 0) {             \
                        log_error("[%s:%u] " msg ": %s", filename, line, rvalue); \
                        return -EBADMSG;                                \
                }                                                       \
                                                                        \
                *i = x;                                                 \
                                                                        \
                return 0;                                               \
        }

static int config_parse_deps(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitDependency d = PTR_TO_UINT(data);
        Unit *u = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD(w, l, rvalue, state) {
                char *t, *k;
                int r;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                k = unit_name_printf(u, t);
                free(t);

                if (!k)
                        return -ENOMEM;

                r = unit_add_dependency_by_name(u, d, k, NULL, true);
                free(k);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int config_parse_names(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Unit *u = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                char *t, *k;
                int r;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                k = unit_name_printf(u, t);
                free(t);

                if (!k)
                        return -ENOMEM;

                r = unit_merge_by_name(u, k);
                free(k);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int config_parse_string_printf(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Unit *u = userdata;
        char **s = data;
        char *k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);
        assert(u);

        if (!(k = unit_full_printf(u, rvalue)))
                return -ENOMEM;

        free(*s);
        if (*k)
                *s = k;
        else {
                free(k);
                *s = NULL;
        }

        return 0;
}

static int config_parse_listen(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r;
        SocketPort *p;
        Socket *s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = (Socket*) data;

        if (!(p = new0(SocketPort, 1)))
                return -ENOMEM;

        if (streq(lvalue, "ListenFIFO")) {
                p->type = SOCKET_FIFO;

                if (!(p->path = strdup(rvalue))) {
                        free(p);
                        return -ENOMEM;
                }

                path_kill_slashes(p->path);
        } else {
                p->type = SOCKET_SOCKET;

                if ((r = socket_address_parse(&p->address, rvalue)) < 0) {
                        log_error("[%s:%u] Failed to parse address value: %s", filename, line, rvalue);
                        free(p);
                        return r;
                }

                if (streq(lvalue, "ListenStream"))
                        p->address.type = SOCK_STREAM;
                else if (streq(lvalue, "ListenDatagram"))
                        p->address.type = SOCK_DGRAM;
                else {
                        assert(streq(lvalue, "ListenSequentialPacket"));
                        p->address.type = SOCK_SEQPACKET;
                }

                if (socket_address_family(&p->address) != AF_LOCAL && p->address.type == SOCK_SEQPACKET) {
                        free(p);
                        return -EPROTONOSUPPORT;
                }
        }

        p->fd = -1;
        LIST_PREPEND(SocketPort, port, s->ports, p);

        return 0;
}

static int config_parse_socket_bind(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Socket *s;
        SocketAddressBindIPv6Only b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = (Socket*) data;

        if ((b = socket_address_bind_ipv6_only_from_string(rvalue)) < 0) {
                int r;

                if ((r = parse_boolean(rvalue)) < 0) {
                        log_error("[%s:%u] Failed to parse bind IPv6 only value: %s", filename, line, rvalue);
                        return -EBADMSG;
                }

                s->bind_ipv6_only = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;
        } else
                s->bind_ipv6_only = b;

        return 0;
}

static int config_parse_nice(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int priority, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, &priority)) < 0) {
                log_error("[%s:%u] Failed to parse nice priority: %s", filename, line, rvalue);
                return r;
        }

        if (priority < PRIO_MIN || priority >= PRIO_MAX) {
                log_error("[%s:%u] Nice priority out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        c->nice = priority;
        c->nice_set = false;

        return 0;
}

static int config_parse_oom_adjust(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int oa, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, &oa)) < 0) {
                log_error("[%s:%u] Failed to parse OOM adjust value: %s", filename, line, rvalue);
                return r;
        }

        if (oa < OOM_DISABLE || oa > OOM_ADJUST_MAX) {
                log_error("[%s:%u] OOM adjust value out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        c->oom_adjust = oa;
        c->oom_adjust_set = true;

        return 0;
}

static int config_parse_mode(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        mode_t *m = data;
        long l;
        char *x = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        errno = 0;
        l = strtol(rvalue, &x, 8);
        if (!x || *x || errno) {
                log_error("[%s:%u] Failed to parse mode value: %s", filename, line, rvalue);
                return errno ? -errno : -EINVAL;
        }

        if (l < 0000 || l > 07777) {
                log_error("[%s:%u] mode value out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        *m = (mode_t) l;
        return 0;
}

static int config_parse_exec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecCommand **e = data, *nce = NULL;
        char **n;
        char *w;
        unsigned k;
        size_t l;
        char *state, *path = NULL;
        bool honour_argv0, write_to_path;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* We accept an absolute path as first argument, or
         * alternatively an absolute prefixed with @ to allow
         * overriding of argv[0]. */

        honour_argv0 = rvalue[0] == '@';

        if (rvalue[honour_argv0 ? 1 : 0] != '/') {
                log_error("[%s:%u] Invalid executable path in command line: %s", filename, line, rvalue);
                return -EINVAL;
        }

        k = 0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        if (!(n = new(char*, k + (honour_argv0 ? 0 : 1))))
                return -ENOMEM;

        k = 0;
        write_to_path = honour_argv0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                if (write_to_path) {
                        if (!(path = strndup(w+1, l-1)))
                                goto fail;
                        write_to_path = false;
                } else {
                        if (!(n[k++] = strndup(w, l)))
                                goto fail;
                }
        }

        n[k] = NULL;

        if (!n[0]) {
                log_error("[%s:%u] Invalid command line: %s", filename, line, rvalue);
                strv_free(n);
                return -EINVAL;
        }

        if (!path)
                if (!(path = strdup(n[0])))
                        goto fail;

        assert(path_is_absolute(path));

        if (!(nce = new0(ExecCommand, 1)))
                goto fail;

        nce->argv = n;
        nce->path = path;

        path_kill_slashes(nce->path);

        exec_command_append_list(e, nce);

        return 0;

fail:
        n[k] = NULL;
        strv_free(n);
        free(path);
        free(nce);

        return -ENOMEM;
}

static int config_parse_usec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        usec_t *usec = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = parse_usec(rvalue, usec)) < 0) {
                log_error("[%s:%u] Failed to parse time value: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_service_type, service_type, ServiceType, "Failed to parse service type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart, service_restart, ServiceRestart, "Failed to parse service restart specifier");

static int config_parse_bindtodevice(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Socket *s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (rvalue[0] && !streq(rvalue, "*")) {
                if (!(n = strdup(rvalue)))
                        return -ENOMEM;
        } else
                n = NULL;

        free(s->bind_to_device);
        s->bind_to_device = n;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_output, exec_output, ExecOutput, "Failed to parse output specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_input, exec_input, ExecInput, "Failed to parse input specifier");

static int config_parse_facility(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = log_facility_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse log facility: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        *o = LOG_MAKEPRI(x, LOG_PRI(*o));

        return 0;
}

static int config_parse_level(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = log_level_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse log level: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        *o = LOG_MAKEPRI(LOG_FAC(*o), x);
        return 0;
}

static int config_parse_io_class(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = ioprio_class_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse IO scheduling class: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        c->ioprio = IOPRIO_PRIO_VALUE(x, IOPRIO_PRIO_DATA(c->ioprio));
        c->ioprio_set = true;

        return 0;
}

static int config_parse_io_priority(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int i;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (safe_atoi(rvalue, &i) < 0 || i < 0 || i >= IOPRIO_BE_NR) {
                log_error("[%s:%u] Failed to parse io priority: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_PRIO_CLASS(c->ioprio), i);
        c->ioprio_set = true;

        return 0;
}

static int config_parse_cpu_sched_policy(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {


        ExecContext *c = data;
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = sched_policy_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse CPU scheduling policy: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        c->cpu_sched_policy = x;
        c->cpu_sched_set = true;

        return 0;
}

static int config_parse_cpu_sched_prio(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int i;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* On Linux RR/FIFO have the same range */
        if (safe_atoi(rvalue, &i) < 0 || i < sched_get_priority_min(SCHED_RR) || i > sched_get_priority_max(SCHED_RR)) {
                log_error("[%s:%u] Failed to parse CPU scheduling priority: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        c->cpu_sched_priority = i;
        c->cpu_sched_set = true;

        return 0;
}

static int config_parse_cpu_affinity(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                char *t;
                int r;
                unsigned cpu;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = safe_atou(t, &cpu);
                free(t);

                if (r < 0 || cpu >= CPU_SETSIZE) {
                        log_error("[%s:%u] Failed to parse CPU affinity: %s", filename, line, rvalue);
                        return -EBADMSG;
                }

                CPU_SET(cpu, &c->cpu_affinity);
        }

        c->cpu_affinity_set = true;

        return 0;
}

static int config_parse_capabilities(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        cap_t cap;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!(cap = cap_from_text(rvalue))) {
                if (errno == ENOMEM)
                        return -ENOMEM;

                log_error("[%s:%u] Failed to parse capabilities: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        if (c->capabilities)
                cap_free(c->capabilities);
        c->capabilities = cap;

        return 0;
}

static int config_parse_secure_bits(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                if (first_word(w, "keep-caps"))
                        c->secure_bits |= SECURE_KEEP_CAPS;
                else if (first_word(w, "keep-caps-locked"))
                        c->secure_bits |= SECURE_KEEP_CAPS_LOCKED;
                else if (first_word(w, "no-setuid-fixup"))
                        c->secure_bits |= SECURE_NO_SETUID_FIXUP;
                else if (first_word(w, "no-setuid-fixup-locked"))
                        c->secure_bits |= SECURE_NO_SETUID_FIXUP_LOCKED;
                else if (first_word(w, "noroot"))
                        c->secure_bits |= SECURE_NOROOT;
                else if (first_word(w, "noroot-locked"))
                        c->secure_bits |= SECURE_NOROOT_LOCKED;
                else {
                        log_error("[%s:%u] Failed to parse secure bits: %s", filename, line, rvalue);
                        return -EBADMSG;
                }
        }

        return 0;
}

static int config_parse_bounding_set(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                char *t;
                int r;
                cap_value_t cap;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = cap_from_name(t, &cap);
                free(t);

                if (r < 0) {
                        log_error("[%s:%u] Failed to parse capability bounding set: %s", filename, line, rvalue);
                        return -EBADMSG;
                }

                c->capability_bounding_set_drop |= 1 << cap;
        }

        return 0;
}

static int config_parse_timer_slack_ns(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        unsigned long u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atolu(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse time slack value: %s", filename, line, rvalue);
                return r;
        }

        c->timer_slack_ns = u;

        return 0;
}

static int config_parse_limit(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        struct rlimit **rl = data;
        unsigned long long u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atollu(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse resource value: %s", filename, line, rvalue);
                return r;
        }

        if (!*rl)
                if (!(*rl = new(struct rlimit, 1)))
                        return -ENOMEM;

        (*rl)->rlim_cur = (*rl)->rlim_max = (rlim_t) u;
        return 0;
}

static int config_parse_cgroup(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Unit *u = userdata;
        char *w;
        size_t l;
        char *state;

        FOREACH_WORD(w, l, rvalue, state) {
                char *t;
                int r;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = unit_add_cgroup_from_text(u, t);
                free(t);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int config_parse_sysv_priority(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *priority = data;
        int r, i;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, &i)) < 0 || i < 0) {
                log_error("[%s:%u] Failed to parse SysV start priority: %s", filename, line, rvalue);
                return r;
        }

        *priority = (int) i;
        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_kill_mode, kill_mode, KillMode, "Failed to parse kill mode");

static int config_parse_mount_flags(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        char *w;
        size_t l;
        char *state;
        unsigned long flags = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                if (strncmp(w, "shared", l) == 0)
                        flags |= MS_SHARED;
                else if (strncmp(w, "slave", l) == 0)
                        flags |= MS_SLAVE;
                else if (strncmp(w, "private", l) == 0)
                        flags |= MS_PRIVATE;
                else {
                        log_error("[%s:%u] Failed to parse mount flags: %s", filename, line, rvalue);
                        return -EINVAL;
                }
        }

        c->mount_flags = flags;
        return 0;
}

static int config_parse_timer(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Timer *t = data;
        usec_t u;
        int r;
        TimerValue *v;
        TimerBase b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((b = timer_base_from_string(lvalue)) < 0) {
                log_error("[%s:%u] Failed to parse timer base: %s", filename, line, lvalue);
                return -EINVAL;
        }

        if ((r = parse_usec(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse timer value: %s", filename, line, rvalue);
                return r;
        }

        if (!(v = new0(TimerValue, 1)))
                return -ENOMEM;

        v->base = b;
        v->value = u;

        LIST_PREPEND(TimerValue, value, t->values, v);

        return 0;
}

static int config_parse_timer_unit(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Timer *t = data;
        int r;

        if (endswith(rvalue, ".timer")) {
                log_error("[%s:%u] Unit cannot be of type timer: %s", filename, line, rvalue);
                return -EINVAL;
        }

        if ((r = manager_load_unit(t->meta.manager, rvalue, NULL, &t->unit)) < 0) {
                log_error("[%s:%u] Failed to load unit: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

static int config_parse_path_spec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Path *p = data;
        PathSpec *s;
        PathType b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((b = path_type_from_string(lvalue)) < 0) {
                log_error("[%s:%u] Failed to parse path type: %s", filename, line, lvalue);
                return -EINVAL;
        }

        if (!path_is_absolute(rvalue)) {
                log_error("[%s:%u] Path is not absolute: %s", filename, line, rvalue);
                return -EINVAL;
        }

        if (!(s = new0(PathSpec, 1)))
                return -ENOMEM;

        if (!(s->path = strdup(rvalue))) {
                free(s);
                return -ENOMEM;
        }

        path_kill_slashes(s->path);

        s->type = b;
        s->inotify_fd = -1;

        LIST_PREPEND(PathSpec, spec, p->specs, s);

        return 0;
}

static int config_parse_path_unit(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Path *t = data;
        int r;

        if (endswith(rvalue, ".path")) {
                log_error("[%s:%u] Unit cannot be of type path: %s", filename, line, rvalue);
                return -EINVAL;
        }

        if ((r = manager_load_unit(t->meta.manager, rvalue, NULL, &t->unit)) < 0) {
                log_error("[%s:%u] Failed to load unit: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

static int config_parse_env_file(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        FILE *f;
        int r;
        char ***env = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!(f = fopen(rvalue, "re"))) {
                log_error("[%s:%u] Failed to open environment file '%s': %m", filename, line, rvalue);
                return -errno;
        }

        while (!feof(f)) {
                char l[LINE_MAX], *p;
                char **t;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        log_error("[%s:%u] Failed to read environment file '%s': %m", filename, line, rvalue);
                        goto finish;
                }

                p = strstrip(l);

                if (!*p)
                        continue;

                if (strchr(COMMENTS, *p))
                        continue;

                t = strv_env_set(*env, p);
                strv_free(*env);
                *env = t;
        }

        r = 0;

finish:
        if (f)
                fclose(f);

        return r;
}

static int config_parse_ip_tos(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *ip_tos = data, x;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = ip_tos_from_string(rvalue)) < 0)
                if ((r = safe_atoi(rvalue, &x)) < 0) {
                        log_error("[%s:%u] Failed to parse IP TOS value: %s", filename, line, rvalue);
                        return r;
                }

        *ip_tos = x;
        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_notify_access, notify_access, NotifyAccess, "Failed to parse notify access specifier");

#define FOLLOW_MAX 8

static int open_follow(char **filename, FILE **_f, Set *names, char **_final) {
        unsigned c = 0;
        int fd, r;
        FILE *f;
        char *id = NULL;

        assert(filename);
        assert(*filename);
        assert(_f);
        assert(names);

        /* This will update the filename pointer if the loaded file is
         * reached by a symlink. The old string will be freed. */

        for (;;) {
                char *target, *name;

                if (c++ >= FOLLOW_MAX)
                        return -ELOOP;

                path_kill_slashes(*filename);

                /* Add the file name we are currently looking at to
                 * the names of this unit */
                name = file_name_from_path(*filename);
                if (!(id = set_get(names, name))) {

                        if (!(id = strdup(name)))
                                return -ENOMEM;

                        if ((r = set_put(names, id)) < 0) {
                                free(id);
                                return r;
                        }
                }

                /* Try to open the file name, but don't if its a symlink */
                if ((fd = open(*filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW)) >= 0)
                        break;

                if (errno != ELOOP)
                        return -errno;

                /* Hmm, so this is a symlink. Let's read the name, and follow it manually */
                if ((r = readlink_and_make_absolute(*filename, &target)) < 0)
                        return r;

                free(*filename);
                *filename = target;
        }

        if (!(f = fdopen(fd, "r"))) {
                r = -errno;
                close_nointr_nofail(fd);
                return r;
        }

        *_f = f;
        *_final = id;
        return 0;
}

static int merge_by_names(Unit **u, Set *names, const char *id) {
        char *k;
        int r;

        assert(u);
        assert(*u);
        assert(names);

        /* Let's try to add in all symlink names we found */
        while ((k = set_steal_first(names))) {

                /* First try to merge in the other name into our
                 * unit */
                if ((r = unit_merge_by_name(*u, k)) < 0) {
                        Unit *other;

                        /* Hmm, we couldn't merge the other unit into
                         * ours? Then let's try it the other way
                         * round */

                        other = manager_get_unit((*u)->meta.manager, k);
                        free(k);

                        if (other)
                                if ((r = unit_merge(other, *u)) >= 0) {
                                        *u = other;
                                        return merge_by_names(u, names, NULL);
                                }

                        return r;
                }

                if (id == k)
                        unit_choose_id(*u, id);

                free(k);
        }

        return 0;
}

static void dump_items(FILE *f, const ConfigItem *items) {
        const ConfigItem *i;
        const char *prev_section = NULL;
        bool not_first = false;

        struct {
                ConfigParserCallback callback;
                const char *rvalue;
        } table[] = {
                { config_parse_int,              "INTEGER" },
                { config_parse_unsigned,         "UNSIGNED" },
                { config_parse_size,             "SIZE" },
                { config_parse_bool,             "BOOLEAN" },
                { config_parse_string,           "STRING" },
                { config_parse_path,             "PATH" },
                { config_parse_strv,             "STRING [...]" },
                { config_parse_nice,             "NICE" },
                { config_parse_oom_adjust,       "OOMADJUST" },
                { config_parse_io_class,         "IOCLASS" },
                { config_parse_io_priority,      "IOPRIORITY" },
                { config_parse_cpu_sched_policy, "CPUSCHEDPOLICY" },
                { config_parse_cpu_sched_prio,   "CPUSCHEDPRIO" },
                { config_parse_cpu_affinity,     "CPUAFFINITY" },
                { config_parse_mode,             "MODE" },
                { config_parse_env_file,         "FILE" },
                { config_parse_output,           "OUTPUT" },
                { config_parse_input,            "INPUT" },
                { config_parse_facility,         "FACILITY" },
                { config_parse_level,            "LEVEL" },
                { config_parse_capabilities,     "CAPABILITIES" },
                { config_parse_secure_bits,      "SECUREBITS" },
                { config_parse_bounding_set,     "BOUNDINGSET" },
                { config_parse_timer_slack_ns,   "TIMERSLACK" },
                { config_parse_limit,            "LIMIT" },
                { config_parse_cgroup,           "CGROUP [...]" },
                { config_parse_deps,             "UNIT [...]" },
                { config_parse_names,            "UNIT [...]" },
                { config_parse_exec,             "PATH [ARGUMENT [...]]" },
                { config_parse_service_type,     "SERVICETYPE" },
                { config_parse_service_restart,  "SERVICERESTART" },
                { config_parse_sysv_priority,    "SYSVPRIORITY" },
                { config_parse_kill_mode,        "KILLMODE" },
                { config_parse_listen,           "SOCKET [...]" },
                { config_parse_socket_bind,      "SOCKETBIND" },
                { config_parse_bindtodevice,     "NETWORKINTERFACE" },
                { config_parse_usec,             "SECONDS" },
                { config_parse_path_strv,        "PATH [...]" },
                { config_parse_mount_flags,      "MOUNTFLAG [...]" },
                { config_parse_string_printf,    "STRING" },
                { config_parse_timer,            "TIMER" },
                { config_parse_timer_unit,       "NAME" },
                { config_parse_path_spec,        "PATH" },
                { config_parse_path_unit,        "UNIT" },
                { config_parse_notify_access,    "ACCESS" }
        };

        assert(f);
        assert(items);

        for (i = items; i->lvalue; i++) {
                unsigned j;
                const char *rvalue = "OTHER";

                if (!streq_ptr(i->section, prev_section)) {
                        if (!not_first)
                                not_first = true;
                        else
                                fputc('\n', f);

                        fprintf(f, "[%s]\n", i->section);
                        prev_section = i->section;
                }

                for (j = 0; j < ELEMENTSOF(table); j++)
                        if (i->parse == table[j].callback) {
                                rvalue = table[j].rvalue;
                                break;
                        }

                fprintf(f, "%s=%s\n", i->lvalue, rvalue);
        }
}

static int load_from_path(Unit *u, const char *path) {

        static const char* const section_table[_UNIT_TYPE_MAX] = {
                [UNIT_SERVICE]   = "Service",
                [UNIT_TIMER]     = "Timer",
                [UNIT_SOCKET]    = "Socket",
                [UNIT_TARGET]    = "Target",
                [UNIT_DEVICE]    = "Device",
                [UNIT_MOUNT]     = "Mount",
                [UNIT_AUTOMOUNT] = "Automount",
                [UNIT_SNAPSHOT]  = "Snapshot",
                [UNIT_SWAP]      = "Swap",
                [UNIT_PATH]      = "Path"
        };

#define EXEC_CONTEXT_CONFIG_ITEMS(context, section) \
                { "WorkingDirectory",       config_parse_path,            &(context).working_directory,                    section   }, \
                { "RootDirectory",          config_parse_path,            &(context).root_directory,                       section   }, \
                { "User",                   config_parse_string_printf,   &(context).user,                                 section   }, \
                { "Group",                  config_parse_string_printf,   &(context).group,                                section   }, \
                { "SupplementaryGroups",    config_parse_strv,            &(context).supplementary_groups,                 section   }, \
                { "Nice",                   config_parse_nice,            &(context),                                      section   }, \
                { "OOMAdjust",              config_parse_oom_adjust,      &(context),                                      section   }, \
                { "IOSchedulingClass",      config_parse_io_class,        &(context),                                      section   }, \
                { "IOSchedulingPriority",   config_parse_io_priority,     &(context),                                      section   }, \
                { "CPUSchedulingPolicy",    config_parse_cpu_sched_policy,&(context),                                      section   }, \
                { "CPUSchedulingPriority",  config_parse_cpu_sched_prio,  &(context),                                      section   }, \
                { "CPUSchedulingResetOnFork", config_parse_bool,          &(context).cpu_sched_reset_on_fork,              section   }, \
                { "CPUAffinity",            config_parse_cpu_affinity,    &(context),                                      section   }, \
                { "UMask",                  config_parse_mode,            &(context).umask,                                section   }, \
                { "Environment",            config_parse_strv,            &(context).environment,                          section   }, \
                { "EnvironmentFile",        config_parse_env_file,        &(context).environment,                          section   }, \
                { "StandardInput",          config_parse_input,           &(context).std_input,                            section   }, \
                { "StandardOutput",         config_parse_output,          &(context).std_output,                           section   }, \
                { "StandardError",          config_parse_output,          &(context).std_error,                            section   }, \
                { "TTYPath",                config_parse_path,            &(context).tty_path,                             section   }, \
                { "SyslogIdentifier",       config_parse_string_printf,   &(context).syslog_identifier,                    section   }, \
                { "SyslogFacility",         config_parse_facility,        &(context).syslog_priority,                      section   }, \
                { "SyslogLevel",            config_parse_level,           &(context).syslog_priority,                      section   }, \
                { "SyslogNoPrefix",         config_parse_bool,            &(context).syslog_no_prefix,                     section   }, \
                { "Capabilities",           config_parse_capabilities,    &(context),                                      section   }, \
                { "SecureBits",             config_parse_secure_bits,     &(context),                                      section   }, \
                { "CapabilityBoundingSetDrop", config_parse_bounding_set, &(context),                                      section   }, \
                { "TimerSlackNS",           config_parse_timer_slack_ns,  &(context),                                      section   }, \
                { "LimitCPU",               config_parse_limit,           &(context).rlimit[RLIMIT_CPU],                   section   }, \
                { "LimitFSIZE",             config_parse_limit,           &(context).rlimit[RLIMIT_FSIZE],                 section   }, \
                { "LimitDATA",              config_parse_limit,           &(context).rlimit[RLIMIT_DATA],                  section   }, \
                { "LimitSTACK",             config_parse_limit,           &(context).rlimit[RLIMIT_STACK],                 section   }, \
                { "LimitCORE",              config_parse_limit,           &(context).rlimit[RLIMIT_CORE],                  section   }, \
                { "LimitRSS",               config_parse_limit,           &(context).rlimit[RLIMIT_RSS],                   section   }, \
                { "LimitNOFILE",            config_parse_limit,           &(context).rlimit[RLIMIT_NOFILE],                section   }, \
                { "LimitAS",                config_parse_limit,           &(context).rlimit[RLIMIT_AS],                    section   }, \
                { "LimitNPROC",             config_parse_limit,           &(context).rlimit[RLIMIT_NPROC],                 section   }, \
                { "LimitMEMLOCK",           config_parse_limit,           &(context).rlimit[RLIMIT_MEMLOCK],               section   }, \
                { "LimitLOCKS",             config_parse_limit,           &(context).rlimit[RLIMIT_LOCKS],                 section   }, \
                { "LimitSIGPENDING",        config_parse_limit,           &(context).rlimit[RLIMIT_SIGPENDING],            section   }, \
                { "LimitMSGQUEUE",          config_parse_limit,           &(context).rlimit[RLIMIT_MSGQUEUE],              section   }, \
                { "LimitNICE",              config_parse_limit,           &(context).rlimit[RLIMIT_NICE],                  section   }, \
                { "LimitRTPRIO",            config_parse_limit,           &(context).rlimit[RLIMIT_RTPRIO],                section   }, \
                { "LimitRTTIME",            config_parse_limit,           &(context).rlimit[RLIMIT_RTTIME],                section   }, \
                { "ControlGroup",           config_parse_cgroup,          u,                                               section   }, \
                { "ReadWriteDirectories",   config_parse_path_strv,       &(context).read_write_dirs,                      section   }, \
                { "ReadOnlyDirectories",    config_parse_path_strv,       &(context).read_only_dirs,                       section   }, \
                { "InaccessibleDirectories",config_parse_path_strv,       &(context).inaccessible_dirs,                    section   }, \
                { "PrivateTmp",             config_parse_bool,            &(context).private_tmp,                          section   }, \
                { "MountFlags",             config_parse_mount_flags,     &(context),                                      section   }, \
                { "TCPWrapName",            config_parse_string_printf,   &(context).tcpwrap_name,                         section   }, \
                { "PAMName",                config_parse_string_printf,   &(context).pam_name,                             section   }

        const ConfigItem items[] = {
                { "Names",                  config_parse_names,           u,                                               "Unit"    },
                { "Description",            config_parse_string_printf,   &u->meta.description,                            "Unit"    },
                { "Requires",               config_parse_deps,            UINT_TO_PTR(UNIT_REQUIRES),                      "Unit"    },
                { "RequiresOverridable",    config_parse_deps,            UINT_TO_PTR(UNIT_REQUIRES_OVERRIDABLE),          "Unit"    },
                { "Requisite",              config_parse_deps,            UINT_TO_PTR(UNIT_REQUISITE),                     "Unit"    },
                { "RequisiteOverridable",   config_parse_deps,            UINT_TO_PTR(UNIT_REQUISITE_OVERRIDABLE),         "Unit"    },
                { "Wants",                  config_parse_deps,            UINT_TO_PTR(UNIT_WANTS),                         "Unit"    },
                { "Conflicts",              config_parse_deps,            UINT_TO_PTR(UNIT_CONFLICTS),                     "Unit"    },
                { "Before",                 config_parse_deps,            UINT_TO_PTR(UNIT_BEFORE),                        "Unit"    },
                { "After",                  config_parse_deps,            UINT_TO_PTR(UNIT_AFTER),                         "Unit"    },
                { "RecursiveStop",          config_parse_bool,            &u->meta.recursive_stop,                         "Unit"    },
                { "StopWhenUnneeded",       config_parse_bool,            &u->meta.stop_when_unneeded,                     "Unit"    },
                { "OnlyByDependency",       config_parse_bool,            &u->meta.only_by_dependency,                     "Unit"    },

                { "PIDFile",                config_parse_path,            &u->service.pid_file,                            "Service" },
                { "ExecStartPre",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_PRE,  "Service" },
                { "ExecStart",              config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START,      "Service" },
                { "ExecStartPost",          config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_POST, "Service" },
                { "ExecReload",             config_parse_exec,            u->service.exec_command+SERVICE_EXEC_RELOAD,     "Service" },
                { "ExecStop",               config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP,       "Service" },
                { "ExecStopPost",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP_POST,  "Service" },
                { "RestartSec",             config_parse_usec,            &u->service.restart_usec,                        "Service" },
                { "TimeoutSec",             config_parse_usec,            &u->service.timeout_usec,                        "Service" },
                { "Type",                   config_parse_service_type,    &u->service.type,                                "Service" },
                { "Restart",                config_parse_service_restart, &u->service.restart,                             "Service" },
                { "PermissionsStartOnly",   config_parse_bool,            &u->service.permissions_start_only,              "Service" },
                { "RootDirectoryStartOnly", config_parse_bool,            &u->service.root_directory_start_only,           "Service" },
                { "ValidNoProcess",         config_parse_bool,            &u->service.valid_no_process,                    "Service" },
                { "SysVStartPriority",      config_parse_sysv_priority,   &u->service.sysv_start_priority,                 "Service" },
                { "KillMode",               config_parse_kill_mode,       &u->service.kill_mode,                           "Service" },
                { "NonBlocking",            config_parse_bool,            &u->service.exec_context.non_blocking,           "Service" },
                { "BusName",                config_parse_string_printf,   &u->service.bus_name,                            "Service" },
                { "NotifyAccess",           config_parse_notify_access,   &u->service.notify_access,                       "Service" },
                EXEC_CONTEXT_CONFIG_ITEMS(u->service.exec_context, "Service"),

                { "ListenStream",           config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenDatagram",         config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenSequentialPacket", config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenFIFO",             config_parse_listen,          &u->socket,                                      "Socket"  },
                { "BindIPv6Only",           config_parse_socket_bind,     &u->socket,                                      "Socket"  },
                { "Backlog",                config_parse_unsigned,        &u->socket.backlog,                              "Socket"  },
                { "BindToDevice",           config_parse_bindtodevice,    &u->socket,                                      "Socket"  },
                { "ExecStartPre",           config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_START_PRE,    "Socket"  },
                { "ExecStartPost",          config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_START_POST,   "Socket"  },
                { "ExecStopPre",            config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_STOP_PRE,     "Socket"  },
                { "ExecStopPost",           config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_STOP_POST,    "Socket"  },
                { "TimeoutSec",             config_parse_usec,            &u->socket.timeout_usec,                         "Socket"  },
                { "DirectoryMode",          config_parse_mode,            &u->socket.directory_mode,                       "Socket"  },
                { "SocketMode",             config_parse_mode,            &u->socket.socket_mode,                          "Socket"  },
                { "KillMode",               config_parse_kill_mode,       &u->socket.kill_mode,                            "Socket"  },
                { "Accept",                 config_parse_bool,            &u->socket.accept,                               "Socket"  },
                { "MaxConnections",         config_parse_unsigned,        &u->socket.max_connections,                      "Socket"  },
                { "KeepAlive",              config_parse_bool,            &u->socket.keep_alive,                           "Socket"  },
                { "Priority",               config_parse_int,             &u->socket.priority,                             "Socket"  },
                { "ReceiveBuffer",          config_parse_size,            &u->socket.receive_buffer,                       "Socket"  },
                { "SendBuffer",             config_parse_size,            &u->socket.send_buffer,                          "Socket"  },
                { "IPTOS",                  config_parse_ip_tos,          &u->socket.ip_tos,                               "Socket"  },
                { "IPTTL",                  config_parse_int,             &u->socket.ip_ttl,                               "Socket"  },
                { "Mark",                   config_parse_int,             &u->socket.mark,                                 "Socket"  },
                { "PipeSize",               config_parse_size,            &u->socket.pipe_size,                            "Socket"  },
                { "FreeBind",               config_parse_bool,            &u->socket.free_bind,                            "Socket"  },
                EXEC_CONTEXT_CONFIG_ITEMS(u->socket.exec_context, "Socket"),

                { "What",                   config_parse_string,          &u->mount.parameters_fragment.what,              "Mount"   },
                { "Where",                  config_parse_path,            &u->mount.where,                                 "Mount"   },
                { "Options",                config_parse_string,          &u->mount.parameters_fragment.options,           "Mount"   },
                { "Type",                   config_parse_string,          &u->mount.parameters_fragment.fstype,            "Mount"   },
                { "TimeoutSec",             config_parse_usec,            &u->mount.timeout_usec,                          "Mount"   },
                { "KillMode",               config_parse_kill_mode,       &u->mount.kill_mode,                             "Mount"   },
                EXEC_CONTEXT_CONFIG_ITEMS(u->mount.exec_context, "Mount"),

                { "Where",                  config_parse_path,            &u->automount.where,                             "Automount" },

                { "What",                   config_parse_path,            &u->swap.parameters_fragment.what,               "Swap"    },
                { "Priority",               config_parse_int,             &u->swap.parameters_fragment.priority,           "Swap"    },

                { "OnActive",               config_parse_timer,           &u->timer,                                       "Timer"   },
                { "OnBoot",                 config_parse_timer,           &u->timer,                                       "Timer"   },
                { "OnStartup",              config_parse_timer,           &u->timer,                                       "Timer"   },
                { "OnUnitActive",           config_parse_timer,           &u->timer,                                       "Timer"   },
                { "OnUnitInactive",         config_parse_timer,           &u->timer,                                       "Timer"   },
                { "Unit",                   config_parse_timer_unit,      &u->timer,                                       "Timer"   },

                { "PathExists",             config_parse_path_spec,       &u->path,                                        "Path"    },
                { "PathChanged",            config_parse_path_spec,       &u->path,                                        "Path"    },
                { "DirectoryNotEmpty",      config_parse_path_spec,       &u->path,                                        "Path"    },
                { "Unit",                   config_parse_path_unit,       &u->path,                                        "Path"    },

                /* The [Install] section is ignored here. */
                { "Alias",                  NULL,                         NULL,                                            "Install" },
                { "WantedBy",               NULL,                         NULL,                                            "Install" },
                { "Also",                   NULL,                         NULL,                                            "Install" },

                { NULL, NULL, NULL, NULL }
        };

#undef EXEC_CONTEXT_CONFIG_ITEMS

        const char *sections[4];
        int r;
        Set *symlink_names;
        FILE *f = NULL;
        char *filename = NULL, *id = NULL;
        Unit *merged;

        if (!u) {
                /* Dirty dirty hack. */
                dump_items((FILE*) path, items);
                return 0;
        }

        assert(u);
        assert(path);

        sections[0] = "Unit";
        sections[1] = section_table[u->meta.type];
        sections[2] = "Install";
        sections[3] = NULL;

        if (!(symlink_names = set_new(string_hash_func, string_compare_func)))
                return -ENOMEM;

        if (path_is_absolute(path)) {

                if (!(filename = strdup(path))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = open_follow(&filename, &f, symlink_names, &id)) < 0) {
                        free(filename);
                        filename = NULL;

                        if (r != -ENOENT)
                                goto finish;
                }

        } else  {
                char **p;

                STRV_FOREACH(p, u->meta.manager->lookup_paths.unit_path) {

                        /* Instead of opening the path right away, we manually
                         * follow all symlinks and add their name to our unit
                         * name set while doing so */
                        if (!(filename = path_make_absolute(path, *p))) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if ((r = open_follow(&filename, &f, symlink_names, &id)) < 0) {
                                char *sn;

                                free(filename);
                                filename = NULL;

                                if (r != -ENOENT)
                                        goto finish;

                                /* Empty the symlink names for the next run */
                                while ((sn = set_steal_first(symlink_names)))
                                        free(sn);

                                continue;
                        }

                        break;
                }
        }

        if (!filename) {
                r = 0;
                goto finish;
        }

        merged = u;
        if ((r = merge_by_names(&merged, symlink_names, id)) < 0)
                goto finish;

        if (merged != u) {
                u->meta.load_state = UNIT_MERGED;
                r = 0;
                goto finish;
        }

        /* Now, parse the file contents */
        if ((r = config_parse(filename, f, sections, items, false, u)) < 0)
                goto finish;

        free(u->meta.fragment_path);
        u->meta.fragment_path = filename;
        filename = NULL;

        u->meta.load_state = UNIT_LOADED;
        r = 0;

finish:
        set_free_free(symlink_names);
        free(filename);

        if (f)
                fclose(f);

        return r;
}

int unit_load_fragment(Unit *u) {
        int r;

        assert(u);

        if (u->meta.fragment_path) {

                if ((r = load_from_path(u, u->meta.fragment_path)) < 0)
                        return r;

        } else {
                Iterator i;
                const char *t;

                /* Try to find the unit under its id */
                if ((r = load_from_path(u, u->meta.id)) < 0)
                        return r;

                /* Try to find an alias we can load this with */
                if (u->meta.load_state == UNIT_STUB)
                        SET_FOREACH(t, u->meta.names, i) {

                                if (t == u->meta.id)
                                        continue;

                                if ((r = load_from_path(u, t)) < 0)
                                        return r;

                                if (u->meta.load_state != UNIT_STUB)
                                        break;
                        }

                /* Now, follow the same logic, but look for a template */
                if (u->meta.load_state == UNIT_STUB && u->meta.instance) {
                        char *k;

                        if (!(k = unit_name_template(u->meta.id)))
                                return -ENOMEM;

                        r = load_from_path(u, k);
                        free(k);

                        if (r < 0)
                                return r;

                        if (u->meta.load_state == UNIT_STUB)
                                SET_FOREACH(t, u->meta.names, i) {

                                        if (t == u->meta.id)
                                                continue;

                                        if (!(k = unit_name_template(t)))
                                                return -ENOMEM;

                                        r = load_from_path(u, k);
                                        free(k);

                                        if (r < 0)
                                                return r;

                                        if (u->meta.load_state != UNIT_STUB)
                                                break;
                                }
                }
        }

        return 0;
}

void unit_dump_config_items(FILE *f) {
        /* OK, this wins a prize for extreme ugliness. */

        load_from_path(NULL, (const void*) f);
}
