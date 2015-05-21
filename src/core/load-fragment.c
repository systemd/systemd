/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2012 Holger Hans Peter Freyther

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

#include <linux/oom.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/resource.h>

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "unit.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "log.h"
#include "ioprio.h"
#include "securebits.h"
#include "missing.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "utf8.h"
#include "path-util.h"
#include "env-util.h"
#include "cgroup.h"
#include "bus-util.h"
#include "bus-error.h"
#include "errno-list.h"
#include "af-list.h"
#include "cap-list.h"
#include "bus-internal.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif

int config_parse_warn_compat(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        Disabled reason = ltype;

        switch(reason) {
        case DISABLED_CONFIGURATION:
                log_syntax(unit, LOG_DEBUG, filename, line, EINVAL,
                           "Support for option %s= has been disabled at compile time and it is ignored", lvalue);
                break;
        case DISABLED_LEGACY:
                log_syntax(unit, LOG_INFO, filename, line, EINVAL,
                           "Support for option %s= has been removed and it is ignored", lvalue);
                break;
        case DISABLED_EXPERIMENTAL:
                log_syntax(unit, LOG_INFO, filename, line, EINVAL,
                           "Support for option %s= has not yet been enabled and it is ignored", lvalue);
                break;
        };

        return 0;
}

int config_parse_unit_deps(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        UnitDependency d = ltype;
        Unit *u = userdata;
        const char *word, *state;
        size_t l;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL, *k = NULL;
                int r;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                r = unit_name_printf(u, t, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to resolve specifiers, ignoring: %s", strerror(-r));
                        continue;
                }

                r = unit_add_dependency_by_name(u, d, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to add dependency on %s, ignoring: %s", k, strerror(-r));
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Invalid syntax, ignoring.");

        return 0;
}

int config_parse_unit_string_printf(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *k = NULL;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s, ignoring: %m", rvalue);
                return 0;
        }

        return config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_unit_strv_printf(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        Unit *u = userdata;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve unit specifiers on %s, ignoring: %s", rvalue, strerror(-r));

        return config_parse_strv(unit, filename, line, section, section_line, lvalue, ltype,
                                 k ? k : rvalue, data, userdata);
}

int config_parse_unit_path_printf(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        _cleanup_free_ char *k = NULL;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to resolve unit specifiers on %s, ignoring: %s", rvalue, strerror(-r));
                return 0;
        }

        return config_parse_path(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_unit_path_strv_printf(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***x = data;
        const char *word, *state;
        Unit *u = userdata;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *k = NULL;
                char t[l+1];

                memcpy(t, word, l);
                t[l] = 0;

                r = unit_full_printf(u, t, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to resolve unit specifiers on %s, ignoring: %s", t, strerror(-r));
                        return 0;
                }

                if (!utf8_is_valid(k)) {
                        log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                        return 0;
                }

                if (!path_is_absolute(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Symlink path %s is not absolute, ignoring: %s", k, strerror(-r));
                        return 0;
                }

                path_kill_slashes(k);

                r = strv_push(x, k);
                if (r < 0)
                        return log_oom();

                k = NULL;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Invalid syntax, ignoring.");

        return 0;
}

int config_parse_socket_listen(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        _cleanup_free_ SocketPort *p = NULL;
        SocketPort *tail;
        Socket *s;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = SOCKET(data);

        if (isempty(rvalue)) {
                /* An empty assignment removes all ports */
                socket_free_ports(s);
                return 0;
        }

        p = new0(SocketPort, 1);
        if (!p)
                return log_oom();

        if (ltype != SOCKET_SOCKET) {

                p->type = ltype;
                r = unit_full_printf(UNIT(s), rvalue, &p->path);
                if (r < 0) {
                        p->path = strdup(rvalue);
                        if (!p->path)
                                return log_oom();
                        else
                                log_syntax(unit, LOG_ERR, filename, line, -r,
                                           "Failed to resolve unit specifiers on %s, ignoring: %s", rvalue, strerror(-r));
                }

                path_kill_slashes(p->path);

        } else if (streq(lvalue, "ListenNetlink")) {
                _cleanup_free_ char  *k = NULL;

                p->type = SOCKET_SOCKET;
                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to resolve unit specifiers on %s, ignoring: %s", rvalue, strerror(-r));

                r = socket_address_parse_netlink(&p->address, k ?: rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to parse address value, ignoring: %s", rvalue);
                        return 0;
                }

        } else {
                _cleanup_free_ char *k = NULL;

                p->type = SOCKET_SOCKET;
                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to resolve unit specifiers on %s, ignoring: %s", rvalue, strerror(-r));

                r = socket_address_parse_and_warn(&p->address, k ? k : rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to parse address value, ignoring: %s", rvalue);
                        return 0;
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
                        log_syntax(unit, LOG_ERR, filename, line, EOPNOTSUPP,
                                   "Address family not supported, ignoring: %s", rvalue);
                        return 0;
                }
        }

        p->fd = -1;
        p->socket = s;

        if (s->ports) {
                LIST_FIND_TAIL(port, s->ports, tail);
                LIST_INSERT_AFTER(port, s->ports, tail, p);
        } else
                LIST_PREPEND(port, s->ports, p);
        p = NULL;

        return 0;
}

int config_parse_socket_bind(const char *unit,
                             const char *filename,
                             unsigned line,
                             const char *section,
                             unsigned section_line,
                             const char *lvalue,
                             int ltype,
                             const char *rvalue,
                             void *data,
                             void *userdata) {

        Socket *s;
        SocketAddressBindIPv6Only b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = SOCKET(data);

        b = socket_address_bind_ipv6_only_from_string(rvalue);
        if (b < 0) {
                int r;

                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse bind IPv6 only value, ignoring: %s", rvalue);
                        return 0;
                }

                s->bind_ipv6_only = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;
        } else
                s->bind_ipv6_only = b;

        return 0;
}

int config_parse_exec_nice(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        ExecContext *c = data;
        int priority, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atoi(rvalue, &priority);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse nice priority, ignoring: %s. ", rvalue);
                return 0;
        }

        if (priority < PRIO_MIN || priority >= PRIO_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                           "Nice priority out of range, ignoring: %s", rvalue);
                return 0;
        }

        c->nice = priority;
        c->nice_set = true;

        return 0;
}

int config_parse_exec_oom_score_adjust(const char* unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {

        ExecContext *c = data;
        int oa, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atoi(rvalue, &oa);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse the OOM score adjust value, ignoring: %s", rvalue);
                return 0;
        }

        if (oa < OOM_SCORE_ADJ_MIN || oa > OOM_SCORE_ADJ_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                           "OOM score adjust value out of range, ignoring: %s", rvalue);
                return 0;
        }

        c->oom_score_adjust = oa;
        c->oom_score_adjust_set = true;

        return 0;
}

int config_parse_exec(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecCommand **e = data, *nce;
        char *path, **n;
        unsigned k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(e);

        e += ltype;

        if (isempty(rvalue)) {
                /* An empty assignment resets the list */
                *e = exec_command_free_list(*e);
                return 0;
        }

        /* We accept an absolute path as first argument, or
         * alternatively an absolute prefixed with @ to allow
         * overriding of argv[0]. */
        for (;;) {
                int i;
                const char *word, *state, *reason;
                size_t l;
                bool separate_argv0 = false, ignore = false;

                path = NULL;
                nce = NULL;
                n = NULL;

                rvalue += strspn(rvalue, WHITESPACE);

                if (rvalue[0] == 0)
                        break;

                k = 0;
                FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                        if (k == 0) {
                                for (i = 0; i < 2; i++) {
                                        if (*word == '-' && !ignore) {
                                                ignore = true;
                                                word ++;
                                        }

                                        if (*word == '@' && !separate_argv0) {
                                                separate_argv0 = true;
                                                word ++;
                                        }
                                }
                        } else if (strneq(word, ";", MAX(l, 1U)))
                                goto found;

                        k++;
                }
                if (!isempty(state)) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Trailing garbage, ignoring.");
                        return 0;
                }

        found:
                /* If separate_argv0, we'll move first element to path variable */
                n = new(char*, MAX(k + !separate_argv0, 1u));
                if (!n)
                        return log_oom();

                k = 0;
                FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                        char *c;
                        unsigned skip;

                        if (separate_argv0 ? path == NULL : k == 0) {
                                /* first word, very special */
                                skip = separate_argv0 + ignore;

                                /* skip special chars in the beginning */
                                if (l <= skip) {
                                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                                   "Empty path in command line, ignoring: \"%s\"", rvalue);
                                        r = 0;
                                        goto fail;
                                }

                        } else if (strneq(word, ";", MAX(l, 1U)))
                                /* new commandline */
                                break;

                        else
                                skip = strneq(word, "\\;", MAX(l, 1U));

                        r = cunescape_length(word + skip, l - skip, 0, &c);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to unescape command line, ignoring: %s", rvalue);
                                r = 0;
                                goto fail;
                        }

                        if (!utf8_is_valid(c)) {
                                log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                                r = 0;
                                goto fail;
                        }

                        /* where to stuff this? */
                        if (separate_argv0 && path == NULL)
                                path = c;
                        else
                                n[k++] = c;
                }

                n[k] = NULL;

                if (!n[0])
                        reason = "Empty executable name or zeroeth argument";
                else if (!string_is_safe(path ?: n[0]))
                        reason = "Executable path contains special characters";
                else if (!path_is_absolute(path ?: n[0]))
                        reason = "Executable path is not absolute";
                else if (endswith(path ?: n[0], "/"))
                        reason = "Executable path specifies a directory";
                else
                        goto ok;

                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "%s, ignoring: %s", reason, rvalue);
                r = 0;
                goto fail;

ok:
                if (!path) {
                        path = strdup(n[0]);
                        if (!path) {
                                r = log_oom();
                                goto fail;
                        }
                }

                nce = new0(ExecCommand, 1);
                if (!nce) {
                        r = log_oom();
                        goto fail;
                }

                nce->argv = n;
                nce->path = path;
                nce->ignore = ignore;

                path_kill_slashes(nce->path);

                exec_command_append_list(e, nce);

                rvalue = state;
        }

        return 0;

fail:
        n[k] = NULL;
        strv_free(n);
        free(path);
        free(nce);

        return r;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_service_type, service_type, ServiceType, "Failed to parse service type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart, service_restart, ServiceRestart, "Failed to parse service restart specifier");

int config_parse_socket_bindtodevice(const char* unit,
                                     const char *filename,
                                     unsigned line,
                                     const char *section,
                                     unsigned section_line,
                                     const char *lvalue,
                                     int ltype,
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
                n = strdup(rvalue);
                if (!n)
                        return log_oom();
        } else
                n = NULL;

        free(s->bind_to_device);
        s->bind_to_device = n;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_output, exec_output, ExecOutput, "Failed to parse output specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_input, exec_input, ExecInput, "Failed to parse input specifier");

int config_parse_exec_io_class(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        ExecContext *c = data;
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = ioprio_class_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse IO scheduling class, ignoring: %s", rvalue);
                return 0;
        }

        c->ioprio = IOPRIO_PRIO_VALUE(x, IOPRIO_PRIO_DATA(c->ioprio));
        c->ioprio_set = true;

        return 0;
}

int config_parse_exec_io_priority(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        ExecContext *c = data;
        int i, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atoi(rvalue, &i);
        if (r < 0 || i < 0 || i >= IOPRIO_BE_NR) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse IO priority, ignoring: %s", rvalue);
                return 0;
        }

        c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_PRIO_CLASS(c->ioprio), i);
        c->ioprio_set = true;

        return 0;
}

int config_parse_exec_cpu_sched_policy(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {


        ExecContext *c = data;
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = sched_policy_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -x,
                           "Failed to parse CPU scheduling policy, ignoring: %s", rvalue);
                return 0;
        }

        c->cpu_sched_policy = x;
        /* Moving to or from real-time policy? We need to adjust the priority */
        c->cpu_sched_priority = CLAMP(c->cpu_sched_priority, sched_get_priority_min(x), sched_get_priority_max(x));
        c->cpu_sched_set = true;

        return 0;
}

int config_parse_exec_cpu_sched_prio(const char *unit,
                                     const char *filename,
                                     unsigned line,
                                     const char *section,
                                     unsigned section_line,
                                     const char *lvalue,
                                     int ltype,
                                     const char *rvalue,
                                     void *data,
                                     void *userdata) {

        ExecContext *c = data;
        int i, min, max, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atoi(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse CPU scheduling policy, ignoring: %s", rvalue);
                return 0;
        }

        /* On Linux RR/FIFO range from 1 to 99 and OTHER/BATCH may only be 0 */
        min = sched_get_priority_min(c->cpu_sched_policy);
        max = sched_get_priority_max(c->cpu_sched_policy);

        if (i < min || i > max) {
                log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                           "CPU scheduling priority is out of range, ignoring: %s", rvalue);
                return 0;
        }

        c->cpu_sched_priority = i;
        c->cpu_sched_set = true;

        return 0;
}

int config_parse_exec_cpu_affinity(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata) {

        ExecContext *c = data;
        const char *word, *state;
        size_t l;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* An empty assignment resets the CPU list */
                if (c->cpuset)
                        CPU_FREE(c->cpuset);
                c->cpuset = NULL;
                return 0;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL;
                int r;
                unsigned cpu;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                r = safe_atou(t, &cpu);

                if (!c->cpuset) {
                        c->cpuset = cpu_set_malloc(&c->cpuset_ncpus);
                        if (!c->cpuset)
                                return log_oom();
                }

                if (r < 0 || cpu >= c->cpuset_ncpus) {
                        log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                                   "Failed to parse CPU affinity '%s', ignoring: %s", t, rvalue);
                        return 0;
                }

                CPU_SET_S(cpu, CPU_ALLOC_SIZE(c->cpuset_ncpus), c->cpuset);
        }
        if (!isempty(state))
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_exec_capabilities(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata) {

        ExecContext *c = data;
        cap_t cap;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        cap = cap_from_text(rvalue);
        if (!cap) {
                log_syntax(unit, LOG_ERR, filename, line, errno,
                           "Failed to parse capabilities, ignoring: %s", rvalue);
                return 0;
        }

        if (c->capabilities)
                cap_free(c->capabilities);
        c->capabilities = cap;

        return 0;
}

int config_parse_exec_secure_bits(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        ExecContext *c = data;
        size_t l;
        const char *word, *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* An empty assignment resets the field */
                c->secure_bits = 0;
                return 0;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                if (first_word(word, "keep-caps"))
                        c->secure_bits |= 1<<SECURE_KEEP_CAPS;
                else if (first_word(word, "keep-caps-locked"))
                        c->secure_bits |= 1<<SECURE_KEEP_CAPS_LOCKED;
                else if (first_word(word, "no-setuid-fixup"))
                        c->secure_bits |= 1<<SECURE_NO_SETUID_FIXUP;
                else if (first_word(word, "no-setuid-fixup-locked"))
                        c->secure_bits |= 1<<SECURE_NO_SETUID_FIXUP_LOCKED;
                else if (first_word(word, "noroot"))
                        c->secure_bits |= 1<<SECURE_NOROOT;
                else if (first_word(word, "noroot-locked"))
                        c->secure_bits |= 1<<SECURE_NOROOT_LOCKED;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse secure bits, ignoring: %s", rvalue);
                        return 0;
                }
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid syntax, garbage at the end, ignoring.");

        return 0;
}

int config_parse_bounding_set(const char *unit,
                              const char *filename,
                              unsigned line,
                              const char *section,
                              unsigned section_line,
                              const char *lvalue,
                              int ltype,
                              const char *rvalue,
                              void *data,
                              void *userdata) {

        uint64_t *capability_bounding_set_drop = data;
        const char *word, *state;
        size_t l;
        bool invert = false;
        uint64_t sum = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        /* Note that we store this inverted internally, since the
         * kernel wants it like this. But we actually expose it
         * non-inverted everywhere to have a fully normalized
         * interface. */

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL;
                int cap;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                cap = capability_from_name(t);
                if (cap < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, errno, "Failed to parse capability in bounding set, ignoring: %s", t);
                        continue;
                }

                sum |= ((uint64_t) 1ULL) << (uint64_t) cap;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        if (invert)
                *capability_bounding_set_drop |= sum;
        else
                *capability_bounding_set_drop |= ~sum;

        return 0;
}

int config_parse_limit(const char *unit,
                       const char *filename,
                       unsigned line,
                       const char *section,
                       unsigned section_line,
                       const char *lvalue,
                       int ltype,
                       const char *rvalue,
                       void *data,
                       void *userdata) {

        struct rlimit **rl = data;
        unsigned long long u;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        rl += ltype;

        if (streq(rvalue, "infinity"))
                u = (unsigned long long) RLIM_INFINITY;
        else {
                int r;

                r = safe_atollu(rvalue, &u);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to parse resource value, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (!*rl) {
                *rl = new(struct rlimit, 1);
                if (!*rl)
                        return log_oom();
        }

        (*rl)->rlim_cur = (*rl)->rlim_max = (rlim_t) u;
        return 0;
}

#ifdef HAVE_SYSV_COMPAT
int config_parse_sysv_priority(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        int *priority = data;
        int i, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atoi(rvalue, &i);
        if (r < 0 || i < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse SysV start priority, ignoring: %s", rvalue);
                return 0;
        }

        *priority = (int) i;
        return 0;
}
#endif

DEFINE_CONFIG_PARSE_ENUM(config_parse_kill_mode, kill_mode, KillMode, "Failed to parse kill mode");

int config_parse_kill_signal(const char *unit,
                             const char *filename,
                             unsigned line,
                             const char *section,
                             unsigned section_line,
                             const char *lvalue,
                             int ltype,
                             const char *rvalue,
                             void *data,
                             void *userdata) {

        int *sig = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(sig);

        r = signal_from_string_try_harder(rvalue);
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse kill signal, ignoring: %s", rvalue);
                return 0;
        }

        *sig = r;
        return 0;
}

int config_parse_exec_mount_flags(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        ExecContext *c = data;
        const char *word, *state;
        size_t l;
        unsigned long flags = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD_SEPARATOR(word, l, rvalue, ", ", state) {
                _cleanup_free_ char *t;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                if (streq(t, "shared"))
                        flags = MS_SHARED;
                else if (streq(t, "slave"))
                        flags = MS_SLAVE;
                else if (streq(t, "private"))
                        flags = MS_PRIVATE;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Failed to parse mount flag %s, ignoring: %s", t, rvalue);
                        return 0;
                }
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Trailing garbage, ignoring.");

        c->mount_flags = flags;
        return 0;
}

int config_parse_exec_selinux_context(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                free(c->selinux_context);
                c->selinux_context = NULL;
                c->selinux_context_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", strerror(-r));
                return 0;
        }

        free(c->selinux_context);
        c->selinux_context = k;
        c->selinux_context_ignore = ignore;

        return 0;
}

int config_parse_exec_apparmor_profile(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                free(c->apparmor_profile);
                c->apparmor_profile = NULL;
                c->apparmor_profile_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", strerror(-r));
                return 0;
        }

        free(c->apparmor_profile);
        c->apparmor_profile = k;
        c->apparmor_profile_ignore = ignore;

        return 0;
}

int config_parse_exec_smack_process_label(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                free(c->smack_process_label);
                c->smack_process_label = NULL;
                c->smack_process_label_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", strerror(-r));
                return 0;
        }

        free(c->smack_process_label);
        c->smack_process_label = k;
        c->smack_process_label_ignore = ignore;

        return 0;
}

int config_parse_timer(const char *unit,
                       const char *filename,
                       unsigned line,
                       const char *section,
                       unsigned section_line,
                       const char *lvalue,
                       int ltype,
                       const char *rvalue,
                       void *data,
                       void *userdata) {

        Timer *t = data;
        usec_t u = 0;
        TimerValue *v;
        TimerBase b;
        CalendarSpec *c = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets list */
                timer_free_values(t);
                return 0;
        }

        b = timer_base_from_string(lvalue);
        if (b < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -b,
                           "Failed to parse timer base, ignoring: %s", lvalue);
                return 0;
        }

        if (b == TIMER_CALENDAR) {
                if (calendar_spec_from_string(rvalue, &c) < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse calendar specification, ignoring: %s",
                                   rvalue);
                        return 0;
                }
        } else {
                if (parse_sec(rvalue, &u) < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse timer value, ignoring: %s",
                                   rvalue);
                        return 0;
                }
        }

        v = new0(TimerValue, 1);
        if (!v) {
                calendar_spec_free(c);
                return log_oom();
        }

        v->base = b;
        v->value = u;
        v->calendar_spec = c;

        LIST_PREPEND(value, t->values, v);

        return 0;
}

int config_parse_trigger_unit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *p = NULL;
        Unit *u = data;
        UnitType type;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!set_isempty(u->dependencies[UNIT_TRIGGERS])) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Multiple units to trigger specified, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_name_printf(u, rvalue, &p);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", strerror(-r));

        type = unit_name_to_type(p ?: rvalue);
        if (type < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Unit type not valid, ignoring: %s", rvalue);
                return 0;
        }

        if (type == u->type) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trigger cannot be of same type, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_add_two_dependencies_by_name(u, UNIT_BEFORE, UNIT_TRIGGERS, p ?: rvalue, NULL, true);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to add trigger on %s, ignoring: %s", p ?: rvalue, strerror(-r));
                return 0;
        }

        return 0;
}

int config_parse_path_spec(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        Path *p = data;
        PathSpec *s;
        PathType b;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment clears list */
                path_free_specs(p);
                return 0;
        }

        b = path_type_from_string(lvalue);
        if (b < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse path type, ignoring: %s", lvalue);
                return 0;
        }

        r = unit_full_printf(UNIT(p), rvalue, &k);
        if (r < 0) {
                k = strdup(rvalue);
                if (!k)
                        return log_oom();
                else
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to resolve unit specifiers on %s. Ignoring.",
                                   rvalue);
        }

        if (!path_is_absolute(k)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Path is not absolute, ignoring: %s", k);
                return 0;
        }

        s = new0(PathSpec, 1);
        if (!s)
                return log_oom();

        s->unit = UNIT(p);
        s->path = path_kill_slashes(k);
        k = NULL;
        s->type = b;
        s->inotify_fd = -1;

        LIST_PREPEND(spec, p->specs, s);

        return 0;
}

int config_parse_socket_service(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        Socket *s = data;
        int r;
        Unit *x;
        _cleanup_free_ char *p = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = unit_name_printf(UNIT(s), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!endswith(p, ".service")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Unit must be of type service, ignoring: %s", rvalue);
                return 0;
        }

        r = manager_load_unit(UNIT(s)->manager, p, NULL, &error, &x);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to load unit %s, ignoring: %s", rvalue, bus_error_message(&error, r));
                return 0;
        }

        unit_ref_set(&s->service, x);

        return 0;
}

int config_parse_service_sockets(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Service *s = data;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL, *k = NULL;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                r = unit_name_printf(UNIT(s), t, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %m");
                        continue;
                }

                if (!endswith(k, ".socket")) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Unit must be of type socket, ignoring: %s", k);
                        continue;
                }

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_WANTS, UNIT_AFTER, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);

                r = unit_add_dependency_by_name(UNIT(s), UNIT_TRIGGERED_BY, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_bus_name(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *k = NULL;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s, ignoring: %m", rvalue);
                return 0;
        }

        if (!service_name_is_valid(k)) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid bus name %s, ignoring.", k);
                return 0;
        }

        return config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_service_timeout(const char *unit,
                                 const char *filename,
                                 unsigned line,
                                 const char *section,
                                 unsigned section_line,
                                 const char *lvalue,
                                 int ltype,
                                 const char *rvalue,
                                 void *data,
                                 void *userdata) {

        Service *s = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        r = config_parse_sec(unit, filename, line, section, section_line, lvalue, ltype,
                             rvalue, data, userdata);
        if (r < 0)
                return r;

        if (streq(lvalue, "TimeoutSec")) {
                s->start_timeout_defined = true;
                s->timeout_stop_usec = s->timeout_start_usec;
        } else if (streq(lvalue, "TimeoutStartSec"))
                s->start_timeout_defined = true;

        return 0;
}

int config_parse_busname_service(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        BusName *n = data;
        int r;
        Unit *x;
        _cleanup_free_ char *p = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = unit_name_printf(UNIT(n), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!endswith(p, ".service")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Unit must be of type service, ignoring: %s", rvalue);
                return 0;
        }

        r = manager_load_unit(UNIT(n)->manager, p, NULL, &error, &x);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to load unit %s, ignoring: %s", rvalue, bus_error_message(&error, r));
                return 0;
        }

        unit_ref_set(&n->service, x);

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_bus_policy_world, bus_policy_access, BusPolicyAccess, "Failed to parse bus name policy access");

int config_parse_bus_policy(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ BusNamePolicy *p = NULL;
        _cleanup_free_ char *id_str = NULL;
        BusName *busname = data;
        char *access_str;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        p = new0(BusNamePolicy, 1);
        if (!p)
                return log_oom();

        if (streq(lvalue, "AllowUser"))
                p->type = BUSNAME_POLICY_TYPE_USER;
        else if (streq(lvalue, "AllowGroup"))
                p->type = BUSNAME_POLICY_TYPE_GROUP;
        else
                assert_not_reached("Unknown lvalue");

        id_str = strdup(rvalue);
        if (!id_str)
                return log_oom();

        access_str = strpbrk(id_str, WHITESPACE);
        if (!access_str) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid busname policy value '%s'", rvalue);
                return 0;
        }

        *access_str = '\0';
        access_str++;
        access_str += strspn(access_str, WHITESPACE);

        p->access = bus_policy_access_from_string(access_str);
        if (p->access < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid busname policy access type '%s'", access_str);
                return 0;
        }

        p->name = id_str;
        id_str = NULL;

        LIST_PREPEND(policy, busname->policy, p);
        p = NULL;

        return 0;
}

int config_parse_bus_endpoint_policy(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *name = NULL;
        BusPolicyAccess access;
        ExecContext *c = data;
        char *access_str;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        name = strdup(rvalue);
        if (!name)
                return log_oom();

        access_str = strpbrk(name, WHITESPACE);
        if (!access_str) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid endpoint policy value '%s'", rvalue);
                return 0;
        }

        *access_str = '\0';
        access_str++;
        access_str += strspn(access_str, WHITESPACE);

        access = bus_policy_access_from_string(access_str);
        if (access <= _BUS_POLICY_ACCESS_INVALID ||
            access >= _BUS_POLICY_ACCESS_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid endpoint policy access type '%s'", access_str);
                return 0;
        }

        if (!c->bus_endpoint) {
                r = bus_endpoint_new(&c->bus_endpoint);

                if (r < 0)
                        return r;
        }

        return bus_endpoint_add_policy(c->bus_endpoint, name, access);
}

int config_parse_unit_env_file(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        char ***env = data;
        Unit *u = userdata;
        _cleanup_free_ char *n = NULL;
        const char *s;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment frees the list */
                strv_free(*env);
                *env = NULL;
                return 0;
        }

        r = unit_full_printf(u, rvalue, &n);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve specifiers, ignoring: %s", rvalue);

        s = n ?: rvalue;
        if (!path_is_absolute(s[0] == '-' ? s + 1 : s)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Path '%s' is not absolute, ignoring.", s);
                return 0;
        }

        r = strv_extend(env, s);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_environ(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata) {

        Unit *u = userdata;
        char*** env = data;
        const char *word, *state;
        size_t l;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                strv_free(*env);
                *env = NULL;
                return 0;
        }

        if (u) {
                r = unit_full_printf(u, rvalue, &k);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to resolve specifiers, ignoring: %s", rvalue);
        }

        if (!k)
                k = strdup(rvalue);
        if (!k)
                return log_oom();

        FOREACH_WORD_QUOTED(word, l, k, state) {
                _cleanup_free_ char *n;
                char **x;

                r = cunescape_length(word, l, 0, &n);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Couldn't unescape assignment, ignoring: %s", rvalue);
                        continue;
                }

                if (!env_assignment_is_valid(n)) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Invalid environment assignment, ignoring: %s", rvalue);
                        continue;
                }

                x = strv_env_set(*env, n);
                if (!x)
                        return log_oom();

                strv_free(*env);
                *env = x;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_ip_tos(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata) {

        int *ip_tos = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = ip_tos_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse IP TOS value, ignoring: %s", rvalue);
                return 0;
        }

        *ip_tos = x;
        return 0;
}

int config_parse_unit_condition_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *p = NULL;
        Condition **list = data, *c;
        ConditionType t = ltype;
        bool trigger, negate;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *list = condition_free_list(*list);
                return 0;
        }

        trigger = rvalue[0] == '|';
        if (trigger)
                rvalue++;

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        r = unit_full_printf(u, rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!path_is_absolute(p)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Path in condition not absolute, ignoring: %s", p);
                return 0;
        }

        c = condition_new(t, p, trigger, negate);
        if (!c)
                return log_oom();

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

int config_parse_unit_condition_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *s = NULL;
        Condition **list = data, *c;
        ConditionType t = ltype;
        bool trigger, negate;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *list = condition_free_list(*list);
                return 0;
        }

        trigger = rvalue[0] == '|';
        if (trigger)
                rvalue++;

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        r = unit_full_printf(u, rvalue, &s);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        c = condition_new(t, s, trigger, negate);
        if (!c)
                return log_oom();

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

int config_parse_unit_condition_null(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Condition **list = data, *c;
        bool trigger, negate;
        int b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *list = condition_free_list(*list);
                return 0;
        }

        trigger = rvalue[0] == '|';
        if (trigger)
                rvalue++;

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        b = parse_boolean(rvalue);
        if (b < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -b, "Failed to parse boolean value in condition, ignoring: %s", rvalue);
                return 0;
        }

        if (!b)
                negate = !negate;

        c = condition_new(CONDITION_NULL, NULL, trigger, negate);
        if (!c)
                return log_oom();

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_notify_access, notify_access, NotifyAccess, "Failed to parse notify access specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_failure_action, failure_action, FailureAction, "Failed to parse failure action specifier");

int config_parse_unit_requires_mounts_for(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Unit *u = userdata;
        const char *word, *state;
        size_t l;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                int r;
                _cleanup_free_ char *n;

                n = strndup(word, l);
                if (!n)
                        return log_oom();

                if (!utf8_is_valid(n)) {
                        log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                        continue;
                }

                r = unit_require_mounts_for(u, n);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to add required mount for, ignoring: %s", rvalue);
                        continue;
                }
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_documentation(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        Unit *u = userdata;
        int r;
        char **a, **b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                strv_free(u->documentation);
                u->documentation = NULL;
                return 0;
        }

        r = config_parse_unit_strv_printf(unit, filename, line, section, section_line, lvalue, ltype,
                                          rvalue, data, userdata);
        if (r < 0)
                return r;

        for (a = b = u->documentation; a && *a; a++) {

                if (documentation_url_is_valid(*a))
                        *(b++) = *a;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Invalid URL, ignoring: %s", *a);
                        free(*a);
                }
        }
        if (b)
                *b = NULL;

        return r;
}

#ifdef HAVE_SECCOMP
int config_parse_syscall_filter(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        static const char default_syscalls[] =
                "execve\0"
                "exit\0"
                "exit_group\0"
                "rt_sigreturn\0"
                "sigreturn\0";

        ExecContext *c = data;
        Unit *u = userdata;
        bool invert = false;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                set_free(c->syscall_filter);
                c->syscall_filter = NULL;
                c->syscall_whitelist = false;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (!c->syscall_filter) {
                c->syscall_filter = set_new(NULL);
                if (!c->syscall_filter)
                        return log_oom();

                if (invert)
                        /* Allow everything but the ones listed */
                        c->syscall_whitelist = false;
                else {
                        const char *i;

                        /* Allow nothing but the ones listed */
                        c->syscall_whitelist = true;

                        /* Accept default syscalls if we are on a whitelist */
                        NULSTR_FOREACH(i, default_syscalls)  {
                                int id;

                                id = seccomp_syscall_resolve_name(i);
                                if (id < 0)
                                        continue;

                                r = set_put(c->syscall_filter, INT_TO_PTR(id + 1));
                                if (r == 0)
                                        continue;
                                if (r < 0)
                                        return log_oom();
                        }
                }
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL;
                int id;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                id = seccomp_syscall_resolve_name(t);
                if (id < 0)  {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse system call, ignoring: %s", t);
                        continue;
                }

                /* If we previously wanted to forbid a syscall and now
                 * we want to allow it, then remove it from the list
                 */
                if (!invert == c->syscall_whitelist)  {
                        r = set_put(c->syscall_filter, INT_TO_PTR(id + 1));
                        if (r == 0)
                                continue;
                        if (r < 0)
                                return log_oom();
                } else
                        set_remove(c->syscall_filter, INT_TO_PTR(id + 1));
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        /* Turn on NNP, but only if it wasn't configured explicitly
         * before, and only if we are in user mode. */
        if (!c->no_new_privileges_set && u->manager->running_as == MANAGER_USER)
                c->no_new_privileges = true;

        return 0;
}

int config_parse_syscall_archs(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **archs = data;
        const char *word, *state;
        size_t l;
        int r;

        if (isempty(rvalue)) {
                set_free(*archs);
                *archs = NULL;
                return 0;
        }

        r = set_ensure_allocated(archs, NULL);
        if (r < 0)
                return log_oom();

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL;
                uint32_t a;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                r = seccomp_arch_from_string(t, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse system call architecture, ignoring: %s", t);
                        continue;
                }

                r = set_put(*archs, UINT32_TO_PTR(a + 1));
                if (r == 0)
                        continue;
                if (r < 0)
                        return log_oom();
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_syscall_errno(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int e;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets to KILL */
                c->syscall_errno = 0;
                return 0;
        }

        e = errno_from_name(rvalue);
        if (e < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse error number, ignoring: %s", rvalue);
                return 0;
        }

        c->syscall_errno = e;
        return 0;
}

int config_parse_address_families(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        bool invert = false;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                set_free(c->address_families);
                c->address_families = NULL;
                c->address_families_whitelist = false;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (!c->address_families) {
                c->address_families = set_new(NULL);
                if (!c->address_families)
                        return log_oom();

                c->address_families_whitelist = !invert;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *t = NULL;
                int af;

                t = strndup(word, l);
                if (!t)
                        return log_oom();

                af = af_from_name(t);
                if (af <= 0)  {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Failed to parse address family, ignoring: %s", t);
                        continue;
                }

                /* If we previously wanted to forbid an address family and now
                 * we want to allow it, then remove it from the list
                 */
                if (!invert == c->address_families_whitelist)  {
                        r = set_put(c->address_families, INT_TO_PTR(af));
                        if (r == 0)
                                continue;
                        if (r < 0)
                                return log_oom();
                } else
                        set_remove(c->address_families, INT_TO_PTR(af));
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}
#endif

int config_parse_unit_slice(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *k = NULL;
        Unit *u = userdata, *slice;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to resolve unit specifiers on %s. Ignoring.", rvalue);
        if (!k) {
                k = strdup(rvalue);
                if (!k)
                        return log_oom();
        }

        r = manager_load_unit(u->manager, k, NULL, NULL, &slice);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to load slice unit %s. Ignoring.", k);
                return 0;
        }

        if (slice->type != UNIT_SLICE) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Slice unit %s is not a slice. Ignoring.", k);
                return 0;
        }

        unit_ref_set(&u->slice, slice);
        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_device_policy, cgroup_device_policy, CGroupDevicePolicy, "Failed to parse device policy");

int config_parse_cpu_shares(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned long *shares = data, lu;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *shares = (unsigned long) -1;
                return 0;
        }

        r = safe_atolu(rvalue, &lu);
        if (r < 0 || lu <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "CPU shares '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        *shares = lu;
        return 0;
}

int config_parse_cpu_quota(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        CGroupContext *c = data;
        double percent;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->cpu_quota_per_sec_usec = USEC_INFINITY;
                return 0;
        }

        if (!endswith(rvalue, "%")) {

                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "CPU quota '%s' not ending in '%%'. Ignoring.", rvalue);
                return 0;
        }

        if (sscanf(rvalue, "%lf%%", &percent) != 1 || percent <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "CPU quota '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        c->cpu_quota_per_sec_usec = (usec_t) (percent * USEC_PER_SEC / 100);

        return 0;
}

int config_parse_memory_limit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        CGroupContext *c = data;
        off_t bytes;
        int r;

        if (isempty(rvalue)) {
                c->memory_limit = (uint64_t) -1;
                return 0;
        }

        assert_cc(sizeof(uint64_t) == sizeof(off_t));

        r = parse_size(rvalue, 1024, &bytes);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Memory limit '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        c->memory_limit = (uint64_t) bytes;
        return 0;
}

int config_parse_device_allow(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *path = NULL;
        CGroupContext *c = data;
        CGroupDeviceAllow *a;
        const char *m;
        size_t n;

        if (isempty(rvalue)) {
                while (c->device_allow)
                        cgroup_context_free_device_allow(c, c->device_allow);

                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!startswith(path, "/dev/") &&
            !startswith(path, "block-") &&
            !startswith(path, "char-")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        m = rvalue + n + strspn(rvalue + n, WHITESPACE);
        if (isempty(m))
                m = "rwm";

        if (!in_charset(m, "rwm")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid device rights '%s'. Ignoring.", m);
                return 0;
        }

        a = new0(CGroupDeviceAllow, 1);
        if (!a)
                return log_oom();

        a->path = path;
        path = NULL;
        a->r = !!strchr(m, 'r');
        a->w = !!strchr(m, 'w');
        a->m = !!strchr(m, 'm');

        LIST_PREPEND(device_allow, c->device_allow, a);
        return 0;
}

int config_parse_blockio_weight(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned long *weight = data, lu;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *weight = (unsigned long) -1;
                return 0;
        }

        r = safe_atolu(rvalue, &lu);
        if (r < 0 || lu < 10 || lu > 1000) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Block IO weight '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        *weight = lu;
        return 0;
}

int config_parse_blockio_device_weight(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *path = NULL;
        CGroupBlockIODeviceWeight *w;
        CGroupContext *c = data;
        unsigned long lu;
        const char *weight;
        size_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                while (c->blockio_device_weights)
                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);

                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        weight = rvalue + n;
        if (!*weight) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Expected block device and device weight. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        weight += strspn(weight, WHITESPACE);
        r = safe_atolu(weight, &lu);
        if (r < 0 || lu < 10 || lu > 1000) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Block IO weight '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        w = new0(CGroupBlockIODeviceWeight, 1);
        if (!w)
                return log_oom();

        w->path = path;
        path = NULL;

        w->weight = lu;

        LIST_PREPEND(device_weights, c->blockio_device_weights, w);
        return 0;
}

int config_parse_blockio_bandwidth(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *path = NULL;
        CGroupBlockIODeviceBandwidth *b;
        CGroupContext *c = data;
        const char *bandwidth;
        off_t bytes;
        bool read;
        size_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        read = streq("BlockIOReadBandwidth", lvalue);

        if (isempty(rvalue)) {
                CGroupBlockIODeviceBandwidth *next;

                LIST_FOREACH_SAFE (device_bandwidths, b, next, c->blockio_device_bandwidths)
                        if (b->read == read)
                                cgroup_context_free_blockio_device_bandwidth(c, b);

                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        bandwidth = rvalue + n;
        bandwidth += strspn(bandwidth, WHITESPACE);

        if (!*bandwidth) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Expected space separated pair of device node and bandwidth. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        r = parse_size(bandwidth, 1000, &bytes);
        if (r < 0 || bytes <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Block IO Bandwidth '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        b = new0(CGroupBlockIODeviceBandwidth, 1);
        if (!b)
                return log_oom();

        b->path = path;
        path = NULL;
        b->bandwidth = (uint64_t) bytes;
        b->read = read;

        LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, b);

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_job_mode, job_mode, JobMode, "Failed to parse job mode");

int config_parse_job_mode_isolate(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        JobMode *m = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse boolean, ignoring: %s", rvalue);
                return 0;
        }

        *m = r ? JOB_ISOLATE : JOB_REPLACE;
        return 0;
}

int config_parse_personality(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned long *personality = data, p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(personality);

        p = personality_from_string(rvalue);
        if (p == PERSONALITY_INVALID) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Failed to parse personality, ignoring: %s", rvalue);
                return 0;
        }

        *personality = p;
        return 0;
}

int config_parse_runtime_directory(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char***rt = data;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                strv_free(*rt);
                *rt = NULL;
                return 0;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *n;

                n = strndup(word, l);
                if (!n)
                        return log_oom();

                if (!filename_is_valid(n)) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Runtime directory is not valid, ignoring assignment: %s", rvalue);
                        continue;
                }

                r = strv_push(rt, n);
                if (r < 0)
                        return log_oom();

                n = NULL;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_set_status(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t l;
        const char *word, *state;
        int r;
        ExitStatusSet *status_set = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Empty assignment resets the list */
        if (isempty(rvalue)) {
                exit_status_set_free(status_set);
                return 0;
        }

        FOREACH_WORD(word, l, rvalue, state) {
                _cleanup_free_ char *temp;
                int val;
                Set **set;

                temp = strndup(word, l);
                if (!temp)
                        return log_oom();

                r = safe_atoi(temp, &val);
                if (r < 0) {
                        val = signal_from_string_try_harder(temp);

                        if (val <= 0) {
                                log_syntax(unit, LOG_ERR, filename, line, -val,
                                           "Failed to parse value, ignoring: %s", word);
                                continue;
                        }
                        set = &status_set->signal;
                } else {
                        if (val < 0 || val > 255) {
                                log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                                           "Value %d is outside range 0-255, ignoring", val);
                                continue;
                        }
                        set = &status_set->status;
                }

                r = set_ensure_allocated(set, NULL);
                if (r < 0)
                        return log_oom();

                r = set_put(*set, INT_TO_PTR(val));
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Unable to store: %s", word);
                        return r;
                }
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_namespace_path_strv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char*** sv = data;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                strv_free(*sv);
                *sv = NULL;
                return 0;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *n;
                int offset;

                n = strndup(word, l);
                if (!n)
                        return log_oom();

                if (!utf8_is_valid(n)) {
                        log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                        continue;
                }

                offset = n[0] == '-';
                if (!path_is_absolute(n + offset)) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Not an absolute path, ignoring: %s", rvalue);
                        continue;
                }

                path_kill_slashes(n);

                r = strv_push(sv, n);
                if (r < 0)
                        return log_oom();

                n = NULL;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_no_new_privileges(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -k,
                           "Failed to parse boolean value, ignoring: %s", rvalue);
                return 0;
        }

        c->no_new_privileges = !!k;
        c->no_new_privileges_set = true;

        return 0;
}

int config_parse_protect_home(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                c->protect_home = PROTECT_HOME_YES;
        else if (k == 0)
                c->protect_home = PROTECT_HOME_NO;
        else {
                ProtectHome h;

                h = protect_home_from_string(rvalue);
                if (h < 0){
                        log_syntax(unit, LOG_ERR, filename, line, -h,
                                   "Failed to parse protect home value, ignoring: %s", rvalue);
                        return 0;
                }

                c->protect_home = h;
        }

        return 0;
}

int config_parse_protect_system(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecContext *c = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                c->protect_system = PROTECT_SYSTEM_YES;
        else if (k == 0)
                c->protect_system = PROTECT_SYSTEM_NO;
        else {
                ProtectSystem s;

                s = protect_system_from_string(rvalue);
                if (s < 0){
                        log_syntax(unit, LOG_ERR, filename, line, -s,
                                   "Failed to parse protect system value, ignoring: %s", rvalue);
                        return 0;
                }

                c->protect_system = s;
        }

        return 0;
}

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
                 * the names of this unit, but only if it is a valid
                 * unit name. */
                name = basename(*filename);

                if (unit_name_is_valid(name, UNIT_NAME_ANY)) {

                        id = set_get(names, name);
                        if (!id) {
                                id = strdup(name);
                                if (!id)
                                        return -ENOMEM;

                                r = set_consume(names, id);
                                if (r < 0)
                                        return r;
                        }
                }

                /* Try to open the file name, but don't if its a symlink */
                fd = open(*filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd >= 0)
                        break;

                if (errno != ELOOP)
                        return -errno;

                /* Hmm, so this is a symlink. Let's read the name, and follow it manually */
                r = readlink_and_make_absolute(*filename, &target);
                if (r < 0)
                        return r;

                free(*filename);
                *filename = target;
        }

        f = fdopen(fd, "re");
        if (!f) {
                safe_close(fd);
                return -errno;
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
                r = unit_merge_by_name(*u, k);
                if (r < 0) {
                        Unit *other;

                        /* Hmm, we couldn't merge the other unit into
                         * ours? Then let's try it the other way
                         * round */

                        other = manager_get_unit((*u)->manager, k);
                        free(k);

                        if (other) {
                                r = unit_merge(other, *u);
                                if (r >= 0) {
                                        *u = other;
                                        return merge_by_names(u, names, NULL);
                                }
                        }

                        return r;
                }

                if (id == k)
                        unit_choose_id(*u, id);

                free(k);
        }

        return 0;
}

static int load_from_path(Unit *u, const char *path) {
        int r;
        _cleanup_set_free_free_ Set *symlink_names = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *filename = NULL;
        char *id = NULL;
        Unit *merged;
        struct stat st;

        assert(u);
        assert(path);

        symlink_names = set_new(&string_hash_ops);
        if (!symlink_names)
                return -ENOMEM;

        if (path_is_absolute(path)) {

                filename = strdup(path);
                if (!filename)
                        return -ENOMEM;

                r = open_follow(&filename, &f, symlink_names, &id);
                if (r < 0) {
                        free(filename);
                        filename = NULL;

                        if (r != -ENOENT)
                                return r;
                }

        } else  {
                char **p;

                STRV_FOREACH(p, u->manager->lookup_paths.unit_path) {

                        /* Instead of opening the path right away, we manually
                         * follow all symlinks and add their name to our unit
                         * name set while doing so */
                        filename = path_make_absolute(path, *p);
                        if (!filename)
                                return -ENOMEM;

                        if (u->manager->unit_path_cache &&
                            !set_get(u->manager->unit_path_cache, filename))
                                r = -ENOENT;
                        else
                                r = open_follow(&filename, &f, symlink_names, &id);

                        if (r < 0) {
                                free(filename);
                                filename = NULL;

                                if (r != -ENOENT)
                                        return r;

                                /* Empty the symlink names for the next run */
                                set_clear_free(symlink_names);
                                continue;
                        }

                        break;
                }
        }

        if (!filename)
                /* Hmm, no suitable file found? */
                return 0;

        merged = u;
        r = merge_by_names(&merged, symlink_names, id);
        if (r < 0)
                return r;

        if (merged != u) {
                u->load_state = UNIT_MERGED;
                return 0;
        }

        if (fstat(fileno(f), &st) < 0)
                return -errno;

        if (null_or_empty(&st))
                u->load_state = UNIT_MASKED;
        else {
                u->load_state = UNIT_LOADED;

                /* Now, parse the file contents */
                r = config_parse(u->id, filename, f,
                                 UNIT_VTABLE(u)->sections,
                                 config_item_perf_lookup, load_fragment_gperf_lookup,
                                 false, true, false, u);
                if (r < 0)
                        return r;
        }

        free(u->fragment_path);
        u->fragment_path = filename;
        filename = NULL;

        u->fragment_mtime = timespec_load(&st.st_mtim);

        if (u->source_path) {
                if (stat(u->source_path, &st) >= 0)
                        u->source_mtime = timespec_load(&st.st_mtim);
                else
                        u->source_mtime = 0;
        }

        return 0;
}

int unit_load_fragment(Unit *u) {
        int r;
        Iterator i;
        const char *t;

        assert(u);
        assert(u->load_state == UNIT_STUB);
        assert(u->id);

        /* First, try to find the unit under its id. We always look
         * for unit files in the default directories, to make it easy
         * to override things by placing things in /etc/systemd/system */
        r = load_from_path(u, u->id);
        if (r < 0)
                return r;

        /* Try to find an alias we can load this with */
        if (u->load_state == UNIT_STUB) {
                SET_FOREACH(t, u->names, i) {

                        if (t == u->id)
                                continue;

                        r = load_from_path(u, t);
                        if (r < 0)
                                return r;

                        if (u->load_state != UNIT_STUB)
                                break;
                }
        }

        /* And now, try looking for it under the suggested (originally linked) path */
        if (u->load_state == UNIT_STUB && u->fragment_path) {

                r = load_from_path(u, u->fragment_path);
                if (r < 0)
                        return r;

                if (u->load_state == UNIT_STUB) {
                        /* Hmm, this didn't work? Then let's get rid
                         * of the fragment path stored for us, so that
                         * we don't point to an invalid location. */
                        free(u->fragment_path);
                        u->fragment_path = NULL;
                }
        }

        /* Look for a template */
        if (u->load_state == UNIT_STUB && u->instance) {
                _cleanup_free_ char *k = NULL;

                r = unit_name_template(u->id, &k);
                if (r < 0)
                        return r;

                r = load_from_path(u, k);
                if (r < 0)
                        return r;

                if (u->load_state == UNIT_STUB) {
                        SET_FOREACH(t, u->names, i) {
                                _cleanup_free_ char *z = NULL;

                                if (t == u->id)
                                        continue;

                                r = unit_name_template(t, &z);
                                if (r < 0)
                                        return r;

                                r = load_from_path(u, z);
                                if (r < 0)
                                        return r;

                                if (u->load_state != UNIT_STUB)
                                        break;
                        }
                }
        }

        return 0;
}

void unit_dump_config_items(FILE *f) {
        static const struct {
                const ConfigParserCallback callback;
                const char *rvalue;
        } table[] = {
#if !defined(HAVE_SYSV_COMPAT) || !defined(HAVE_SECCOMP) || !defined(HAVE_PAM) || !defined(HAVE_SELINUX) || !defined(HAVE_SMACK) || !defined(HAVE_APPARMOR)
                { config_parse_warn_compat,           "NOTSUPPORTED" },
#endif
                { config_parse_int,                   "INTEGER" },
                { config_parse_unsigned,              "UNSIGNED" },
                { config_parse_iec_size,              "SIZE" },
                { config_parse_iec_off,               "SIZE" },
                { config_parse_si_size,               "SIZE" },
                { config_parse_bool,                  "BOOLEAN" },
                { config_parse_string,                "STRING" },
                { config_parse_path,                  "PATH" },
                { config_parse_unit_path_printf,      "PATH" },
                { config_parse_strv,                  "STRING [...]" },
                { config_parse_exec_nice,             "NICE" },
                { config_parse_exec_oom_score_adjust, "OOMSCOREADJUST" },
                { config_parse_exec_io_class,         "IOCLASS" },
                { config_parse_exec_io_priority,      "IOPRIORITY" },
                { config_parse_exec_cpu_sched_policy, "CPUSCHEDPOLICY" },
                { config_parse_exec_cpu_sched_prio,   "CPUSCHEDPRIO" },
                { config_parse_exec_cpu_affinity,     "CPUAFFINITY" },
                { config_parse_mode,                  "MODE" },
                { config_parse_unit_env_file,         "FILE" },
                { config_parse_output,                "OUTPUT" },
                { config_parse_input,                 "INPUT" },
                { config_parse_log_facility,          "FACILITY" },
                { config_parse_log_level,             "LEVEL" },
                { config_parse_exec_capabilities,     "CAPABILITIES" },
                { config_parse_exec_secure_bits,      "SECUREBITS" },
                { config_parse_bounding_set,          "BOUNDINGSET" },
                { config_parse_limit,                 "LIMIT" },
                { config_parse_unit_deps,             "UNIT [...]" },
                { config_parse_exec,                  "PATH [ARGUMENT [...]]" },
                { config_parse_service_type,          "SERVICETYPE" },
                { config_parse_service_restart,       "SERVICERESTART" },
#ifdef HAVE_SYSV_COMPAT
                { config_parse_sysv_priority,         "SYSVPRIORITY" },
#endif
                { config_parse_kill_mode,             "KILLMODE" },
                { config_parse_kill_signal,           "SIGNAL" },
                { config_parse_socket_listen,         "SOCKET [...]" },
                { config_parse_socket_bind,           "SOCKETBIND" },
                { config_parse_socket_bindtodevice,   "NETWORKINTERFACE" },
                { config_parse_sec,                   "SECONDS" },
                { config_parse_nsec,                  "NANOSECONDS" },
                { config_parse_namespace_path_strv,   "PATH [...]" },
                { config_parse_unit_requires_mounts_for, "PATH [...]" },
                { config_parse_exec_mount_flags,      "MOUNTFLAG [...]" },
                { config_parse_unit_string_printf,    "STRING" },
                { config_parse_trigger_unit,          "UNIT" },
                { config_parse_timer,                 "TIMER" },
                { config_parse_path_spec,             "PATH" },
                { config_parse_notify_access,         "ACCESS" },
                { config_parse_ip_tos,                "TOS" },
                { config_parse_unit_condition_path,   "CONDITION" },
                { config_parse_unit_condition_string, "CONDITION" },
                { config_parse_unit_condition_null,   "CONDITION" },
                { config_parse_unit_slice,            "SLICE" },
                { config_parse_documentation,         "URL" },
                { config_parse_service_timeout,       "SECONDS" },
                { config_parse_failure_action,        "ACTION" },
                { config_parse_set_status,            "STATUS" },
                { config_parse_service_sockets,       "SOCKETS" },
                { config_parse_environ,               "ENVIRON" },
#ifdef HAVE_SECCOMP
                { config_parse_syscall_filter,        "SYSCALLS" },
                { config_parse_syscall_archs,         "ARCHS" },
                { config_parse_syscall_errno,         "ERRNO" },
                { config_parse_address_families,      "FAMILIES" },
#endif
                { config_parse_cpu_shares,            "SHARES" },
                { config_parse_memory_limit,          "LIMIT" },
                { config_parse_device_allow,          "DEVICE" },
                { config_parse_device_policy,         "POLICY" },
                { config_parse_blockio_bandwidth,     "BANDWIDTH" },
                { config_parse_blockio_weight,        "WEIGHT" },
                { config_parse_blockio_device_weight, "DEVICEWEIGHT" },
                { config_parse_long,                  "LONG" },
                { config_parse_socket_service,        "SERVICE" },
#ifdef HAVE_SELINUX
                { config_parse_exec_selinux_context,  "LABEL" },
#endif
                { config_parse_job_mode,              "MODE" },
                { config_parse_job_mode_isolate,      "BOOLEAN" },
                { config_parse_personality,           "PERSONALITY" },
        };

        const char *prev = NULL;
        const char *i;

        assert(f);

        NULSTR_FOREACH(i, load_fragment_gperf_nulstr) {
                const char *rvalue = "OTHER", *lvalue;
                unsigned j;
                size_t prefix_len;
                const char *dot;
                const ConfigPerfItem *p;

                assert_se(p = load_fragment_gperf_lookup(i, strlen(i)));

                dot = strchr(i, '.');
                lvalue = dot ? dot + 1 : i;
                prefix_len = dot-i;

                if (dot)
                        if (!prev || !strneq(prev, i, prefix_len+1)) {
                                if (prev)
                                        fputc('\n', f);

                                fprintf(f, "[%.*s]\n", (int) prefix_len, i);
                        }

                for (j = 0; j < ELEMENTSOF(table); j++)
                        if (p->parse == table[j].callback) {
                                rvalue = table[j].rvalue;
                                break;
                        }

                fprintf(f, "%s=%s\n", lvalue, rvalue);
                prev = i;
        }
}
