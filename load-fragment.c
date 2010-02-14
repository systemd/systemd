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

#include "unit.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "log.h"
#include "ioprio.h"
#include "securebits.h"
#include "missing.h"

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
                char *t;
                int r;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = unit_add_dependency_by_name(u, d, t);
                free(t);

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
                char *t;
                int r;
                Unit *other;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                other = manager_get_unit(u->meta.manager, t);

                if (other) {

                        if (other != u) {

                                if (other->meta.load_state != UNIT_STUB) {
                                        free(t);
                                        return -EEXIST;
                                }

                                if ((r = unit_merge(u, other)) < 0) {
                                        free(t);
                                        return r;
                                }
                        }

                } else {
                        if ((r = unit_add_name(u, t)) < 0) {
                                free(t);
                                return r;
                        }
                }

                free(t);
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

        int r;
        Socket *s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = (Socket*) data;

        if ((r = parse_boolean(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse bind IPv6 only value: %s", filename, line, rvalue);
                return r;
        }

        s->bind_ipv6_only = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;

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
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = 0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        if (!(n = new(char*, k+1)))
                return -ENOMEM;

        k = 0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                if (!(n[k++] = strndup(w, l)))
                        goto fail;

        n[k] = NULL;

        if (!n[0] || !path_is_absolute(n[0])) {
                log_error("[%s:%u] Invalid executable path in command line: %s", filename, line, rvalue);
                strv_free(n);
                return -EINVAL;
        }

        if (!(nce = new0(ExecCommand, 1)))
                goto fail;

        nce->argv = n;
        if (!(nce->path = strdup(n[0])))
                goto fail;

        exec_command_append_list(e, nce);

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);
        free(n);

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
        unsigned long long u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atollu(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse time value: %s", filename, line, rvalue);
                return r;
        }

        /* We actually assume the user configures seconds. Later on we
         * might choose to support suffixes for time values, to
         * configure bigger or smaller units */

        *usec = u * USEC_PER_SEC;

        return 0;
}

static int config_parse_service_type(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Service *s = data;
        ServiceType x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = service_type_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse service type: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        s->type = x;

        return 0;
}

static int config_parse_service_restart(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Service *s = data;
        ServiceRestart x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = service_restart_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse service restart specifier: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        s->restart = x;

        return 0;
}

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

static int config_parse_output(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecOutput *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = exec_output_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse output specifier: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        *o = x;

        return 0;
}

static int config_parse_input(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecInput *i = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((x = exec_input_from_string(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse input specifier: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        *i = x;

        return 0;
}

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

        if ((x = log_facility_from_string(rvalue)) < 0)

                /* Second try, let's see if this is a number. */
                if (safe_atoi(rvalue, &x) < 0 || !log_facility_to_string(x)) {
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

        if ((x = log_level_from_string(rvalue)) < 0)

                /* Second try, let's see if this is a number. */
                if (safe_atoi(rvalue, &x) < 0 || !log_level_to_string(x)) {
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

        if ((x = ioprio_class_from_string(rvalue)) < 0)

                /* Second try, let's see if this is a number. */
                if (safe_atoi(rvalue, &x) < 0 || !ioprio_class_to_string(x)) {
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

        if ((x = sched_policy_from_string(rvalue)) < 0)

                /* Second try, let's see if this is a number. */
                if (safe_atoi(rvalue, &x) < 0 || !sched_policy_to_string(x)) {
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

#define FOLLOW_MAX 8

static int open_follow(char **filename, FILE **_f, Set *names, char **_id) {
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
                char *target, *k, *name;

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
                if ((r = readlink_malloc(*filename, &target)) < 0)
                        return r;

                k = file_in_same_dir(*filename, target);
                free(target);

                if (!k)
                        return -ENOMEM;

                free(*filename);
                *filename = k;
        }

        if (!(f = fdopen(fd, "r"))) {
                r = -errno;
                assert(close_nointr(fd) == 0);
                return r;
        }

        *_f = f;
        *_id = id;
        return 0;
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
                [UNIT_SNAPSHOT]  = "Snapshot"
        };

#define EXEC_CONTEXT_CONFIG_ITEMS(context, section) \
                { "WorkingDirectory",       config_parse_path,            &(context).working_directory,                    section   }, \
                { "RootDirectory",          config_parse_path,            &(context).root_directory,                       section   }, \
                { "User",                   config_parse_string,          &(context).user,                                 section   }, \
                { "Group",                  config_parse_string,          &(context).group,                                section   }, \
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
                { "Output",                 config_parse_output,          &(context).output,                               section   }, \
                { "Input",                  config_parse_input,           &(context).input,                                section   }, \
                { "SyslogIdentifier",       config_parse_string,          &(context).syslog_identifier,                    section   }, \
                { "SyslogFacility",         config_parse_facility,        &(context).syslog_priority,                      section   }, \
                { "SyslogLevel",            config_parse_level,           &(context).syslog_priority,                      section   }, \
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
                { "NonBlocking",            config_parse_bool,            &(context).non_blocking,                         section   }

        const ConfigItem items[] = {
                { "Names",                  config_parse_names,           u,                                               "Meta"    },
                { "Description",            config_parse_string,          &u->meta.description,                            "Meta"    },
                { "Requires",               config_parse_deps,            UINT_TO_PTR(UNIT_REQUIRES),                      "Meta"    },
                { "SoftRequires",           config_parse_deps,            UINT_TO_PTR(UNIT_SOFT_REQUIRES),                 "Meta"    },
                { "Wants",                  config_parse_deps,            UINT_TO_PTR(UNIT_WANTS),                         "Meta"    },
                { "Requisite",              config_parse_deps,            UINT_TO_PTR(UNIT_REQUISITE),                     "Meta"    },
                { "SoftRequisite",          config_parse_deps,            UINT_TO_PTR(UNIT_SOFT_REQUISITE),                "Meta"    },
                { "Conflicts",              config_parse_deps,            UINT_TO_PTR(UNIT_CONFLICTS),                     "Meta"    },
                { "Before",                 config_parse_deps,            UINT_TO_PTR(UNIT_BEFORE),                        "Meta"    },
                { "After",                  config_parse_deps,            UINT_TO_PTR(UNIT_AFTER),                         "Meta"    },
                { "RecursiveStop",          config_parse_bool,            &u->meta.recursive_stop,                         "Meta"    },
                { "StopWhenUnneeded",       config_parse_bool,            &u->meta.stop_when_unneeded,                     "Meta"    },

                { "PIDFile",                config_parse_path,            &u->service.pid_file,                            "Service" },
                { "ExecStartPre",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_PRE,  "Service" },
                { "ExecStart",              config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START,      "Service" },
                { "ExecStartPost",          config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_POST, "Service" },
                { "ExecReload",             config_parse_exec,            u->service.exec_command+SERVICE_EXEC_RELOAD,     "Service" },
                { "ExecStop",               config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP,       "Service" },
                { "ExecStopPost",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP_POST,  "Service" },
                { "RestartSec",             config_parse_usec,            &u->service.restart_usec,                        "Service" },
                { "TimeoutSec",             config_parse_usec,            &u->service.timeout_usec,                        "Service" },
                { "Type",                   config_parse_service_type,    &u->service,                                     "Service" },
                { "Restart",                config_parse_service_restart, &u->service,                                     "Service" },
                { "PermissionsStartOnly",   config_parse_bool,            &u->service.permissions_start_only,              "Service" },
                { "RootDirectoryStartOnly", config_parse_bool,            &u->service.root_directory_start_only,           "Service" },
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
                { "DirectoryMode",          config_parse_mode,            &u->socket.directory_mode,                       "Socket"  },
                { "SocketMode",             config_parse_mode,            &u->socket.socket_mode,                          "Socket"  },
                EXEC_CONTEXT_CONFIG_ITEMS(u->socket.exec_context, "Socket"),

                EXEC_CONTEXT_CONFIG_ITEMS(u->automount.exec_context, "Automount"),

                { NULL, NULL, NULL, NULL }
        };

#undef EXEC_CONTEXT_CONFIG_ITEMS

        const char *sections[3];
        char *k;
        int r;
        Set *symlink_names;
        FILE *f;
        char *filename = NULL, *id;

        sections[0] = "Meta";
        sections[1] = section_table[u->meta.type];
        sections[2] = NULL;

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

                STRV_FOREACH(p, u->meta.manager->unit_path) {

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
                r = 0; /* returning 0 means: no suitable config file found */
                goto finish;
        }

        /* Now, parse the file contents */
        r = config_parse(filename, f, sections, items, u);
        if (r < 0)
                goto finish;

        /* Let's try to add in all symlink names we found */
        while ((k = set_steal_first(symlink_names))) {
                if ((r = unit_add_name(u, k)) < 0)
                        goto finish;


                if (id == k)
                        unit_choose_id(u, id);
                free(k);
        }


        free(u->meta.fragment_path);
        u->meta.fragment_path = filename;
        filename = NULL;

        r = 1; /* returning 1 means: suitable config file found and loaded */

finish:
        while ((k = set_steal_first(symlink_names)))
                free(k);
        set_free(symlink_names);
        free(filename);

        return r;
}

int unit_load_fragment(Unit *u) {
        int r = 0;

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        if (u->meta.fragment_path)
                r = load_from_path(u, u->meta.fragment_path);
        else {
                Iterator i;
                const char *t;

                /* Try to find the unit under its id */
                if ((t = unit_id(u)))
                        r = load_from_path(u, t);

                /* Try to find an alias we can load this with */
                if (r == 0)
                        SET_FOREACH(t, u->meta.names, i)
                                if ((r = load_from_path(u, t)) != 0)
                                        break;
        }

        if (r >= 0) {
                ExecContext *c;

                if (u->meta.type == UNIT_SOCKET)
                        c = &u->socket.exec_context;
                else if (u->meta.type == UNIT_SERVICE)
                        c = &u->service.exec_context;
                else
                        c = NULL;

                if (c &&
                    (c->output == EXEC_OUTPUT_KERNEL || c->output == EXEC_OUTPUT_SYSLOG) &&
                    u->meta.manager->running_as != MANAGER_SESSION) {
                        int k;

                        /* If syslog or kernel logging is requested, make sure
                         * our own logging daemon is run first. */

                        if ((k = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_LOGGER_SOCKET)) < 0)
                                return k;

                        if ((k = unit_add_dependency_by_name(u, UNIT_REQUIRES, SPECIAL_LOGGER_SOCKET)) < 0)
                                return k;
                }
        }

        return r;
}
