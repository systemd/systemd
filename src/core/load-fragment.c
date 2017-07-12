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

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/oom.h>
#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif
#include <sched.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "af-list.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "escape.h"
#include "fd-util.h"
#include "fs-util.h"
#include "ioprio.h"
#include "load-fragment.h"
#include "log.h"
#include "missing.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "securebits.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"
#include "utf8.h"
#include "web-util.h"

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
                log_syntax(unit, LOG_DEBUG, filename, line, 0,
                           "Support for option %s= has been disabled at compile time and it is ignored", lvalue);
                break;
        case DISABLED_LEGACY:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has been removed and it is ignored", lvalue);
                break;
        case DISABLED_EXPERIMENTAL:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has not yet been enabled and it is ignored", lvalue);
                break;
        };

        return 0;
}

int config_parse_unit_deps(
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

        UnitDependency d = ltype;
        Unit *u = userdata;
        const char *p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;
                int r;

                r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                r = unit_name_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %m");
                        continue;
                }

                r = unit_add_dependency_by_name(u, d, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);
        }

        return 0;
}

int config_parse_obsolete_unit_deps(
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

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "Unit dependency type %s= is obsolete, replacing by %s=, please update your unit file", lvalue, unit_dependency_to_string(ltype));

        return config_parse_unit_deps(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
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

int config_parse_unit_strv_printf(
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
        _cleanup_free_ char *k = NULL;
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

        return config_parse_strv(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_unit_path_printf(
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
        bool fatal = ltype;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve unit specifiers on %s%s: %m",
                           fatal ? "" : ", ignoring", rvalue);
                return fatal ? -ENOEXEC : 0;
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
        Unit *u = userdata;
        int r;
        const char *p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers on \"%s\", ignoring: %m", word);
                        return 0;
                }

                if (!utf8_is_valid(k)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                        return 0;
                }

                if (!path_is_absolute(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Symlink path is not absolute: %s", k);
                        return 0;
                }

                path_kill_slashes(k);

                r = strv_push(x, k);
                if (r < 0)
                        return log_oom();
                k = NULL;
        }
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s, ignoring: %m", rvalue);
                        return 0;
                }

                path_kill_slashes(p->path);

        } else if (streq(lvalue, "ListenNetlink")) {
                _cleanup_free_ char  *k = NULL;

                p->type = SOCKET_SOCKET;
                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s, ignoring: %m", rvalue);
                        return 0;
                }

                r = socket_address_parse_netlink(&p->address, k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address value, ignoring: %s", rvalue);
                        return 0;
                }

        } else {
                _cleanup_free_ char *k = NULL;

                p->type = SOCKET_SOCKET;
                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,"Failed to resolve unit specifiers on %s, ignoring: %m", rvalue);
                        return 0;
                }

                r = socket_address_parse_and_warn(&p->address, k);
                if (r < 0) {
                        if (r != -EAFNOSUPPORT)
                                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address value, ignoring: %s", rvalue);

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
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Address family not supported, ignoring: %s", rvalue);
                        return 0;
                }
        }

        p->fd = -1;
        p->auxiliary_fds = NULL;
        p->n_auxiliary_fds = 0;
        p->socket = s;

        if (s->ports) {
                LIST_FIND_TAIL(port, s->ports, tail);
                LIST_INSERT_AFTER(port, s->ports, tail, p);
        } else
                LIST_PREPEND(port, s->ports, p);
        p = NULL;

        return 0;
}

int config_parse_socket_protocol(const char *unit,
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = SOCKET(data);

        if (streq(rvalue, "udplite"))
                s->socket_protocol = IPPROTO_UDPLITE;
        else if (streq(rvalue, "sctp"))
                s->socket_protocol = IPPROTO_SCTP;
        else {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Socket protocol not supported, ignoring: %s", rvalue);
                return 0;
        }

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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse bind IPv6 only value, ignoring: %s", rvalue);
                        return 0;
                }

                s->bind_ipv6_only = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;
        } else
                s->bind_ipv6_only = b;

        return 0;
}

int config_parse_exec_nice(
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
        int priority, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_nice(rvalue, &priority);
        if (r < 0) {
                if (r == -ERANGE)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Nice priority out of range, ignoring: %s", rvalue);
                else
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse nice priority, ignoring: %s", rvalue);

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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse the OOM score adjust value, ignoring: %s", rvalue);
                return 0;
        }

        if (oa < OOM_SCORE_ADJ_MIN || oa > OOM_SCORE_ADJ_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "OOM score adjust value out of range, ignoring: %s", rvalue);
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

        ExecCommand **e = data;
        Unit *u = userdata;
        const char *p;
        bool semicolon;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(e);

        e += ltype;
        rvalue += strspn(rvalue, WHITESPACE);

        if (isempty(rvalue)) {
                /* An empty assignment resets the list */
                *e = exec_command_free_list(*e);
                return 0;
        }

        p = rvalue;
        do {
                _cleanup_free_ char *path = NULL, *firstword = NULL;
                bool separate_argv0 = false, ignore = false, privileged = false;
                _cleanup_free_ ExecCommand *nce = NULL;
                _cleanup_strv_free_ char **n = NULL;
                size_t nlen = 0, nbufsize = 0;
                const char *f;

                semicolon = false;

                r = extract_first_word_and_warn(&p, &firstword, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE, unit, filename, line, rvalue);
                if (r <= 0)
                        return 0;

                f = firstword;
                for (;;) {
                        /* We accept an absolute path as first argument.
                         * If it's prefixed with - and the path doesn't exist,
                         * we ignore it instead of erroring out;
                         * if it's prefixed with @, we allow overriding of argv[0];
                         * and if it's prefixed with +, it will be run with full privileges */
                        if (*f == '-' && !ignore)
                                ignore = true;
                        else if (*f == '@' && !separate_argv0)
                                separate_argv0 = true;
                        else if (*f == '+' && !privileged)
                                privileged = true;
                        else
                                break;
                        f++;
                }

                r = unit_full_printf(u, f, &path);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers on %s%s: %m",
                                   f, ignore ? ", ignoring" : "");
                        return ignore ? 0 : -ENOEXEC;
                }

                if (isempty(path)) {
                        /* First word is either "-" or "@" with no command. */
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Empty path in command line%s: \"%s\"",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (!string_is_safe(path)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Executable path contains special characters%s: %s",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (!path_is_absolute(path)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Executable path is not absolute%s: %s",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (endswith(path, "/")) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Executable path specifies a directory%s: %s",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }

                if (!separate_argv0) {
                        char *w = NULL;

                        if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                                return log_oom();

                        w = strdup(path);
                        if (!w)
                                return log_oom();
                        n[nlen++] = w;
                        n[nlen] = NULL;
                }

                path_kill_slashes(path);

                while (!isempty(p)) {
                        _cleanup_free_ char *word = NULL, *resolved = NULL;

                        /* Check explicitly for an unquoted semicolon as
                         * command separator token.  */
                        if (p[0] == ';' && (!p[1] || strchr(WHITESPACE, p[1]))) {
                                p++;
                                p += strspn(p, WHITESPACE);
                                semicolon = true;
                                break;
                        }

                        /* Check for \; explicitly, to not confuse it with \\; or "\;" or "\\;" etc.
                         * extract_first_word() would return the same for all of those.  */
                        if (p[0] == '\\' && p[1] == ';' && (!p[2] || strchr(WHITESPACE, p[2]))) {
                                char *w;

                                p += 2;
                                p += strspn(p, WHITESPACE);

                                if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                                        return log_oom();

                                w = strdup(";");
                                if (!w)
                                        return log_oom();
                                n[nlen++] = w;
                                n[nlen] = NULL;
                                continue;
                        }

                        r = extract_first_word_and_warn(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE, unit, filename, line, rvalue);
                        if (r == 0)
                                break;
                        if (r < 0)
                                return ignore ? 0 : -ENOEXEC;

                        r = unit_full_printf(u, word, &resolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolve unit specifiers on %s%s: %m",
                                           word, ignore ? ", ignoring" : "");
                                return ignore ? 0 : -ENOEXEC;
                        }

                        if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                                return log_oom();
                        n[nlen++] = resolved;
                        n[nlen] = NULL;
                        resolved = NULL;
                }

                if (!n || !n[0]) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Empty executable name or zeroeth argument%s: %s",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }

                nce = new0(ExecCommand, 1);
                if (!nce)
                        return log_oom();

                nce->argv = n;
                nce->path = path;
                nce->ignore = ignore;
                nce->privileged = privileged;

                exec_command_append_list(e, nce);

                /* Do not _cleanup_free_ these. */
                n = NULL;
                path = NULL;
                nce = NULL;

                rvalue = p;
        } while (semicolon);

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_service_type, service_type, ServiceType, "Failed to parse service type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart, service_restart, ServiceRestart, "Failed to parse service restart specifier");

int config_parse_socket_bindtodevice(
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

        Socket *s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (rvalue[0] && !streq(rvalue, "*")) {
                if (!ifname_valid(rvalue)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Interface name is invalid, ignoring: %s", rvalue);
                        return 0;
                }

                n = strdup(rvalue);
                if (!n)
                        return log_oom();
        } else
                n = NULL;

        free(s->bind_to_device);
        s->bind_to_device = n;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_input, exec_input, ExecInput, "Failed to parse input literal specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_output, exec_output, ExecOutput, "Failed to parse output literal specifier");

int config_parse_exec_input(const char *unit,
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
        const char *name;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(rvalue);

        name = startswith(rvalue, "fd:");
        if (name) {
                /* Strip prefix and validate fd name */
                if (!fdname_is_valid(name)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid file descriptor name, ignoring: %s", name);
                        return 0;
                }
                c->std_input = EXEC_INPUT_NAMED_FD;
                r = free_and_strdup(&c->stdio_fdname[STDIN_FILENO], name);
                if (r < 0)
                        log_oom();
                return r;
        } else {
                ExecInput ei = exec_input_from_string(rvalue);
                if (ei == _EXEC_INPUT_INVALID)
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse input specifier, ignoring: %s", rvalue);
                else
                        c->std_input = ei;
                return 0;
        }
}

int config_parse_exec_output(const char *unit,
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
        ExecOutput eo;
        const char *name;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(lvalue);
        assert(rvalue);

        name = startswith(rvalue, "fd:");
        if (name) {
                /* Strip prefix and validate fd name */
                if (!fdname_is_valid(name)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid file descriptor name, ignoring: %s", name);
                        return 0;
                }
                eo = EXEC_OUTPUT_NAMED_FD;
        } else {
                eo = exec_output_from_string(rvalue);
                if (eo == _EXEC_OUTPUT_INVALID) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse output specifier, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "StandardOutput")) {
                c->std_output = eo;
                r = free_and_strdup(&c->stdio_fdname[STDOUT_FILENO], name);
                if (r < 0)
                        log_oom();
                return r;
        } else if (streq(lvalue, "StandardError")) {
                c->std_error = eo;
                r = free_and_strdup(&c->stdio_fdname[STDERR_FILENO], name);
                if (r < 0)
                        log_oom();
                return r;
        } else {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse output property, ignoring: %s", lvalue);
                return 0;
        }
}

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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IO scheduling class, ignoring: %s", rvalue);
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

        r = ioprio_parse_priority(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse IO priority, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse CPU scheduling policy, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CPU scheduling policy, ignoring: %s", rvalue);
                return 0;
        }

        /* On Linux RR/FIFO range from 1 to 99 and OTHER/BATCH may only be 0 */
        min = sched_get_priority_min(c->cpu_sched_policy);
        max = sched_get_priority_max(c->cpu_sched_policy);

        if (i < min || i > max) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "CPU scheduling priority is out of range, ignoring: %s", rvalue);
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
        _cleanup_cpu_free_ cpu_set_t *cpuset = NULL;
        int ncpus;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        ncpus = parse_cpu_set_and_warn(rvalue, &cpuset, unit, filename, line, lvalue);
        if (ncpus < 0)
                return ncpus;

        if (c->cpuset)
                CPU_FREE(c->cpuset);

        if (ncpus == 0)
                /* An empty assignment resets the CPU list */
                c->cpuset = NULL;
        else {
                c->cpuset = cpuset;
                cpuset = NULL;
        }
        c->cpuset_ncpus = ncpus;

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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* An empty assignment resets the field */
                c->secure_bits = 0;
                return 0;
        }

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (streq(word, "keep-caps"))
                        c->secure_bits |= 1<<SECURE_KEEP_CAPS;
                else if (streq(word, "keep-caps-locked"))
                        c->secure_bits |= 1<<SECURE_KEEP_CAPS_LOCKED;
                else if (streq(word, "no-setuid-fixup"))
                        c->secure_bits |= 1<<SECURE_NO_SETUID_FIXUP;
                else if (streq(word, "no-setuid-fixup-locked"))
                        c->secure_bits |= 1<<SECURE_NO_SETUID_FIXUP_LOCKED;
                else if (streq(word, "noroot"))
                        c->secure_bits |= 1<<SECURE_NOROOT;
                else if (streq(word, "noroot-locked"))
                        c->secure_bits |= 1<<SECURE_NOROOT_LOCKED;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse secure bit \"%s\", ignoring.", word);
                        return 0;
                }
        }
}

int config_parse_capability_set(
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

        uint64_t *capability_set = data;
        uint64_t sum = 0, initial = 0;
        bool invert = false;
        const char *p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (strcmp(lvalue, "CapabilityBoundingSet") == 0)
                initial = CAP_ALL; /* initialized to all bits on */
        /* else "AmbientCapabilities" initialized to all bits off */

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                int cap, r;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse word, ignoring: %s", rvalue);
                        break;
                }

                cap = capability_from_name(word);
                if (cap < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse capability in bounding/ambient set, ignoring: %s", word);
                        continue;
                }

                sum |= ((uint64_t) UINT64_C(1)) << (uint64_t) cap;
        }

        sum = invert ? ~sum : sum;

        if (sum == 0 || *capability_set == initial)
                /* "" or uninitialized data -> replace */
                *capability_set = sum;
        else
                /* previous data -> merge */
                *capability_set |= sum;

        return 0;
}

int config_parse_limit(
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

        struct rlimit **rl = data, d = {};
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = rlimit_parse(ltype, rvalue, &d);
        if (r == -EILSEQ) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Soft resource limit chosen higher than hard limit, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse resource value, ignoring: %s", rvalue);
                return 0;
        }

        if (rl[ltype])
                *rl[ltype] = d;
        else {
                rl[ltype] = newdup(struct rlimit, &d, 1);
                if (!rl[ltype])
                        return log_oom();
        }

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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse SysV start priority, ignoring: %s", rvalue);
                return 0;
        }

        *priority = (int) i;
        return 0;
}
#endif

DEFINE_CONFIG_PARSE_ENUM(config_parse_exec_utmp_mode, exec_utmp_mode, ExecUtmpMode, "Failed to parse utmp mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_kill_mode, kill_mode, KillMode, "Failed to parse kill mode");

int config_parse_exec_mount_flags(
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = mount_propagation_flags_from_string(rvalue, &c->mount_flags);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse mount flag %s, ignoring.", rvalue);

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
                c->selinux_context = mfree(c->selinux_context);
                c->selinux_context_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve specifiers%s: %m",
                           ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
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
                c->apparmor_profile = mfree(c->apparmor_profile);
                c->apparmor_profile_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve specifiers%s: %m",
                           ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
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
                c->smack_process_label = mfree(c->smack_process_label);
                c->smack_process_label_ignore = false;
                return 0;
        }

        if (rvalue[0] == '-') {
                ignore = true;
                rvalue++;
        } else
                ignore = false;

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve specifiers%s: %m",
                           ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
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
        usec_t usec = 0;
        TimerValue *v;
        TimerBase b;
        CalendarSpec *c = NULL;
        Unit *u = userdata;
        _cleanup_free_ char *k = NULL;
        int r;

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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse timer base, ignoring: %s", lvalue);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        if (b == TIMER_CALENDAR) {
                if (calendar_spec_from_string(k, &c) < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse calendar specification, ignoring: %s", k);
                        return 0;
                }
        } else {
                if (parse_sec(k, &usec) < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse timer value, ignoring: %s", k);
                        return 0;
                }
        }

        v = new0(TimerValue, 1);
        if (!v) {
                calendar_spec_free(c);
                return log_oom();
        }

        v->base = b;
        v->value = usec;
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Multiple units to trigger specified, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_name_printf(u, rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %m");
                return 0;
        }

        type = unit_name_to_type(p);
        if (type < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Unit type not valid, ignoring: %s", rvalue);
                return 0;
        }

        if (type == u->type) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Trigger cannot be of same type, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_add_two_dependencies_by_name(u, UNIT_BEFORE, UNIT_TRIGGERS, p, NULL, true);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add trigger on %s, ignoring: %m", p);
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse path type, ignoring: %s", lvalue);
                return 0;
        }

        r = unit_full_printf(UNIT(p), rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s. Ignoring.", rvalue);
                return 0;
        }

        if (!path_is_absolute(k)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Path is not absolute, ignoring: %s", k);
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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *p = NULL;
        Socket *s = data;
        Unit *x;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = unit_name_printf(UNIT(s), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers: %s", rvalue);
                return -ENOEXEC;
        }

        if (!endswith(p, ".service")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Unit must be of type service: %s", rvalue);
                return -ENOEXEC;
        }

        r = manager_load_unit(UNIT(s)->manager, p, NULL, &error, &x);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to load unit %s: %s", rvalue, bus_error_message(&error, r));
                return -ENOEXEC;
        }

        unit_ref_set(&s->service, x);

        return 0;
}

int config_parse_fdname(
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
        Socket *s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                s->fdname = mfree(s->fdname);
                return 0;
        }

        r = unit_full_printf(UNIT(s), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!fdname_is_valid(p)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid file descriptor name, ignoring: %s", p);
                return 0;
        }

        return free_and_replace(s->fdname, p);
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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Trailing garbage in sockets, ignoring: %s", rvalue);
                        break;
                }

                r = unit_name_printf(UNIT(s), word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %m");
                        continue;
                }

                if (!endswith(k, ".socket")) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unit must be of type socket, ignoring: %s", k);
                        continue;
                }

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_WANTS, UNIT_AFTER, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);

                r = unit_add_dependency_by_name(UNIT(s), UNIT_TRIGGERED_BY, k, NULL, true);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);
        }

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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid bus name %s, ignoring.", k);
                return 0;
        }

        return config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_service_timeout(
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

        Service *s = userdata;
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        /* This is called for three cases: TimeoutSec=, TimeoutStopSec= and TimeoutStartSec=. */

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s= parameter, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        /* Traditionally, these options accepted 0 to disable the timeouts. However, a timeout of 0 suggests it happens
         * immediately, hence fix this to become USEC_INFINITY instead. This is in-line with how we internally handle
         * all other timeouts. */
        if (usec <= 0)
                usec = USEC_INFINITY;

        if (!streq(lvalue, "TimeoutStopSec")) {
                s->start_timeout_defined = true;
                s->timeout_start_usec = usec;
        }

        if (!streq(lvalue, "TimeoutStartSec"))
                s->timeout_stop_usec = usec;

        return 0;
}

int config_parse_sec_fix_0(
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

        usec_t *usec = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(usec);

        /* This is pretty much like config_parse_sec(), except that this treats a time of 0 as infinity, for
         * compatibility with older versions of systemd where 0 instead of infinity was used as indicator to turn off a
         * timeout. */

        r = parse_sec_fix_0(rvalue, usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s= parameter, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_user_group(
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

        char **user = data, *n;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue))
                n = NULL;
        else {
                _cleanup_free_ char *k = NULL;

                r = unit_full_printf(u, rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", rvalue);
                        return -ENOEXEC;
                }

                if (!valid_user_group_name_or_id(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid user/group name or numeric ID: %s", k);
                        return -ENOEXEC;
                }

                n = k;
                k = NULL;
        }

        free(*user);
        *user = n;

        return 0;
}

int config_parse_user_group_strv(
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

        char ***users = data;
        Unit *u = userdata;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                char **empty;

                empty = new0(char*, 1);
                if (!empty)
                        return log_oom();

                strv_free(*users);
                *users = empty;

                return 0;
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax: %s", rvalue);
                        return -ENOEXEC;
                }

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", word);
                        return -ENOEXEC;
                }

                if (!valid_user_group_name_or_id(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid user/group name or numeric ID: %s", k);
                        return -ENOEXEC;
                }

                r = strv_push(users, k);
                if (r < 0)
                        return log_oom();

                k = NULL;
        }

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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!endswith(p, ".service")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Unit must be of type service, ignoring: %s", rvalue);
                return 0;
        }

        r = manager_load_unit(UNIT(n)->manager, p, NULL, &error, &x);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to load unit %s, ignoring: %s", rvalue, bus_error_message(&error, r));
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid busname policy value '%s'", rvalue);
                return 0;
        }

        *access_str = '\0';
        access_str++;
        access_str += strspn(access_str, WHITESPACE);

        p->access = bus_policy_access_from_string(access_str);
        if (p->access < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid busname policy access type '%s'", access_str);
                return 0;
        }

        p->name = id_str;
        id_str = NULL;

        LIST_PREPEND(policy, busname->policy, p);
        p = NULL;

        return 0;
}

int config_parse_working_directory(
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
        bool missing_ok;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(c);
        assert(u);

        if (rvalue[0] == '-') {
                missing_ok = true;
                rvalue++;
        } else
                missing_ok = false;

        if (streq(rvalue, "~")) {
                c->working_directory_home = true;
                c->working_directory = mfree(c->working_directory);
        } else {
                _cleanup_free_ char *k = NULL;

                r = unit_full_printf(u, rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers in working directory path '%s'%s: %m",
                                   rvalue, missing_ok ? ", ignoring" : "");
                        return missing_ok ? 0 : -ENOEXEC;
                }

                path_kill_slashes(k);

                if (!utf8_is_valid(k)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                        return missing_ok ? 0 : -ENOEXEC;
                }

                if (!path_is_absolute(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Working directory path '%s' is not absolute%s.",
                                   rvalue, missing_ok ? ", ignoring" : "");
                        return missing_ok ? 0 : -ENOEXEC;
                }

                c->working_directory_home = false;
                free_and_replace(c->working_directory, k);
        }

        c->working_directory_missing_ok = missing_ok;
        return 0;
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment frees the list */
                *env = strv_free(*env);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &n);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!path_is_absolute(n[0] == '-' ? n + 1 : n)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Path '%s' is not absolute, ignoring.", n);
                return 0;
        }

        r = strv_extend(env, n);
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
        char ***env = data;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *env = strv_free(*env);
                return 0;
        }

        for (p = rvalue;; ) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (u) {
                        r = unit_full_printf(u, word, &k);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolve specifiers, ignoring: %s", k);
                                continue;
                        }
                } else {
                        k = word;
                        word = NULL;
                }

                if (!env_assignment_is_valid(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid environment assignment, ignoring: %s", k);
                        continue;
                }

                r = strv_env_replace(env, k);
                if (r < 0)
                        return log_oom();
                k = NULL;
        }
}

int config_parse_pass_environ(const char *unit,
                              const char *filename,
                              unsigned line,
                              const char *section,
                              unsigned section_line,
                              const char *lvalue,
                              int ltype,
                              const char *rvalue,
                              void *data,
                              void *userdata) {

        const char *whole_rvalue = rvalue;
        char*** passenv = data;
        _cleanup_strv_free_ char **n = NULL;
        size_t nlen = 0, nbufsize = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *passenv = strv_free(*passenv);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&rvalue, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, whole_rvalue);
                        break;
                }

                if (!env_name_is_valid(word)) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Invalid environment name for %s, ignoring: %s", lvalue, word);
                        continue;
                }

                if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                        return log_oom();
                n[nlen++] = word;
                n[nlen] = NULL;
                word = NULL;
        }

        if (n) {
                r = strv_extend_strv(passenv, n, true);
                if (r < 0)
                        return r;
        }

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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IP TOS value, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
                return 0;
        }

        if (!path_is_absolute(p)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Path in condition not absolute, ignoring: %s", p);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, b, "Failed to parse boolean value in condition, ignoring: %s", rvalue);
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
DEFINE_CONFIG_PARSE_ENUM(config_parse_emergency_action, emergency_action, EmergencyAction, "Failed to parse failure action specifier");

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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        for (p = rvalue;; ) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (!utf8_is_valid(word)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                        continue;
                }

                r = unit_full_printf(u, word, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit name \"%s\", ignoring: %m", word);
                        continue;
                }

                r = unit_require_mounts_for(u, resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add required mount \"%s\", ignoring: %m", resolved);
                        continue;
                }
        }
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
                u->documentation = strv_free(u->documentation);
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
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid URL, ignoring: %s", *a);
                        free(*a);
                }
        }
        if (b)
                *b = NULL;

        return r;
}

#ifdef HAVE_SECCOMP

static int syscall_filter_parse_one(
                const char *unit,
                const char *filename,
                unsigned line,
                ExecContext *c,
                bool invert,
                const char *t,
                bool warn) {
        int r;

        if (t[0] == '@') {
                const SyscallFilterSet *set;
                const char *i;

                set = syscall_filter_set_find(t);
                if (!set) {
                        if (warn)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Don't know system call group, ignoring: %s", t);
                        return 0;
                }

                NULSTR_FOREACH(i, set->value) {
                        r = syscall_filter_parse_one(unit, filename, line, c, invert, i, false);
                        if (r < 0)
                                return r;
                }
        } else {
                int id;

                id = seccomp_syscall_resolve_name(t);
                if (id == __NR_SCMP_ERROR)  {
                        if (warn)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Failed to parse system call, ignoring: %s", t);
                        return 0;
                }

                /* If we previously wanted to forbid a syscall and now
                 * we want to allow it, then remove it from the list
                 */
                if (!invert == c->syscall_whitelist) {
                        r = set_put(c->syscall_filter, INT_TO_PTR(id + 1));
                        if (r == 0)
                                return 0;
                        if (r < 0)
                                return log_oom();
                } else
                        (void) set_remove(c->syscall_filter, INT_TO_PTR(id + 1));
        }

        return 0;
}

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

        ExecContext *c = data;
        Unit *u = userdata;
        bool invert = false;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->syscall_filter = set_free(c->syscall_filter);
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
                        /* Allow nothing but the ones listed */
                        c->syscall_whitelist = true;

                        /* Accept default syscalls if we are on a whitelist */
                        r = syscall_filter_parse_one(unit, filename, line, c, false, "@default", false);
                        if (r < 0)
                                return r;
                }
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                r = syscall_filter_parse_one(unit, filename, line, c, invert, word, true);
                if (r < 0)
                        return r;
        }

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
        const char *p;
        int r;

        if (isempty(rvalue)) {
                *archs = set_free(*archs);
                return 0;
        }

        r = set_ensure_allocated(archs, NULL);
        if (r < 0)
                return log_oom();

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint32_t a;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = seccomp_arch_from_string(word, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse system call architecture \"%s\", ignoring: %m", word);
                        continue;
                }

                r = set_put(*archs, UINT32_TO_PTR(a + 1));
                if (r < 0)
                        return log_oom();
        }
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse error number, ignoring: %s", rvalue);
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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->address_families = set_free(c->address_families);
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

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                int af;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                af = af_from_name(word);
                if (af <= 0)  {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse address family \"%s\", ignoring: %m", word);
                        continue;
                }

                /* If we previously wanted to forbid an address family and now
                 * we want to allow it, then just remove it from the list.
                 */
                if (!invert == c->address_families_whitelist)  {
                        r = set_put(c->address_families, INT_TO_PTR(af));
                        if (r < 0)
                                return log_oom();
                } else
                        set_remove(c->address_families, INT_TO_PTR(af));
        }
}

int config_parse_restrict_namespaces(
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
        int r;

        if (isempty(rvalue)) {
                /* Reset to the default. */
                c->restrict_namespaces = NAMESPACE_FLAGS_ALL;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        r = parse_boolean(rvalue);
        if (r > 0)
                c->restrict_namespaces = 0;
        else if (r == 0)
                c->restrict_namespaces = NAMESPACE_FLAGS_ALL;
        else {
                /* Not a boolean argument, in this case it's a list of namespace types. */

                r = namespace_flag_from_string_many(rvalue, &c->restrict_namespaces);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse namespace type string, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (invert)
                c->restrict_namespaces = (~c->restrict_namespaces) & NAMESPACE_FLAGS_ALL;

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
        Unit *u = userdata, *slice = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers on %s. Ignoring.", rvalue);
                return 0;
        }

        r = manager_load_unit(u->manager, k, NULL, NULL, &slice);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to load slice unit %s. Ignoring.", k);
                return 0;
        }

        r = unit_set_slice(u, slice);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to assign slice %s to unit %s. Ignoring.", slice->id, u->id);
                return 0;
        }

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_device_policy, cgroup_device_policy, CGroupDevicePolicy, "Failed to parse device policy");

int config_parse_cpu_weight(
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

        uint64_t *weight = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = cg_weight_parse(rvalue, weight);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "CPU weight '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        return 0;
}

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

        uint64_t *shares = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = cg_cpu_shares_parse(rvalue, shares);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "CPU shares '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->cpu_quota_per_sec_usec = USEC_INFINITY;
                return 0;
        }

        r = parse_percent_unbounded(rvalue);
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "CPU quota '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        c->cpu_quota_per_sec_usec = ((usec_t) r * USEC_PER_SEC) / 100U;
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
        uint64_t bytes = CGROUP_LIMIT_MAX;
        int r;

        if (!isempty(rvalue) && !streq(rvalue, "infinity")) {

                r = parse_percent(rvalue);
                if (r < 0) {
                        r = parse_size(rvalue, 1024, &bytes);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Memory limit '%s' invalid. Ignoring.", rvalue);
                                return 0;
                        }
                } else
                        bytes = physical_memory_scale(r, 100U);

                if (bytes <= 0 || bytes >= UINT64_MAX) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Memory limit '%s' out of range. Ignoring.", rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "MemoryLow"))
                c->memory_low = bytes;
        else if (streq(lvalue, "MemoryHigh"))
                c->memory_high = bytes;
        else if (streq(lvalue, "MemoryMax"))
                c->memory_max = bytes;
        else if (streq(lvalue, "MemorySwapMax"))
                c->memory_swap_max = bytes;
        else if (streq(lvalue, "MemoryLimit"))
                c->memory_limit = bytes;
        else
                return -EINVAL;

        return 0;
}

int config_parse_tasks_max(
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

        uint64_t *tasks_max = data, v;
        Unit *u = userdata;
        int r;

        if (isempty(rvalue)) {
                *tasks_max = u->manager->default_tasks_max;
                return 0;
        }

        if (streq(rvalue, "infinity")) {
                *tasks_max = CGROUP_LIMIT_MAX;
                return 0;
        }

        r = parse_percent(rvalue);
        if (r < 0) {
                r = safe_atou64(rvalue, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Maximum tasks value '%s' invalid. Ignoring.", rvalue);
                        return 0;
                }
        } else
                v = system_tasks_max_scale(r, 100U);

        if (v <= 0 || v >= UINT64_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Maximum tasks value '%s' out of range. Ignoring.", rvalue);
                return 0;
        }

        *tasks_max = v;
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

        _cleanup_free_ char *path = NULL, *t = NULL;
        CGroupContext *c = data;
        CGroupDeviceAllow *a;
        const char *m = NULL;
        size_t n;
        int r;

        if (isempty(rvalue)) {
                while (c->device_allow)
                        cgroup_context_free_device_allow(c, c->device_allow);

                return 0;
        }

        r = unit_full_printf(userdata, rvalue, &t);
        if(r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve specifiers in %s, ignoring: %m",
                           rvalue);
        }

        n = strcspn(t, WHITESPACE);

        path = strndup(t, n);
        if (!path)
                return log_oom();

        if (!is_deviceallow_pattern(path)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        m = t + n + strspn(t + n, WHITESPACE);
        if (isempty(m))
                m = "rwm";

        if (!in_charset(m, "rwm")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device rights '%s'. Ignoring.", m);
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

int config_parse_io_weight(
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

        uint64_t *weight = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = cg_weight_parse(rvalue, weight);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "IO weight '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_io_device_weight(
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
        CGroupIODeviceWeight *w;
        CGroupContext *c = data;
        const char *weight;
        uint64_t u;
        size_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                while (c->io_device_weights)
                        cgroup_context_free_io_device_weight(c, c->io_device_weights);

                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        weight = rvalue + n;
        weight += strspn(weight, WHITESPACE);

        if (isempty(weight)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Expected block device and device weight. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        r = cg_weight_parse(weight, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "IO weight '%s' invalid. Ignoring.", weight);
                return 0;
        }

        assert(u != CGROUP_WEIGHT_INVALID);

        w = new0(CGroupIODeviceWeight, 1);
        if (!w)
                return log_oom();

        w->path = path;
        path = NULL;

        w->weight = u;

        LIST_PREPEND(device_weights, c->io_device_weights, w);
        return 0;
}

int config_parse_io_limit(
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
        CGroupIODeviceLimit *l = NULL, *t;
        CGroupContext *c = data;
        CGroupIOLimitType type;
        const char *limit;
        uint64_t num;
        size_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        type = cgroup_io_limit_type_from_string(lvalue);
        assert(type >= 0);

        if (isempty(rvalue)) {
                LIST_FOREACH(device_limits, l, c->io_device_limits)
                        l->limits[type] = cgroup_io_limit_defaults[type];
                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        limit = rvalue + n;
        limit += strspn(limit, WHITESPACE);

        if (!*limit) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Expected space separated pair of device node and bandwidth. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        if (streq("infinity", limit)) {
                num = CGROUP_LIMIT_MAX;
        } else {
                r = parse_size(limit, 1000, &num);
                if (r < 0 || num <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "IO Limit '%s' invalid. Ignoring.", rvalue);
                        return 0;
                }
        }

        LIST_FOREACH(device_limits, t, c->io_device_limits) {
                if (path_equal(path, t->path)) {
                        l = t;
                        break;
                }
        }

        if (!l) {
                CGroupIOLimitType ttype;

                l = new0(CGroupIODeviceLimit, 1);
                if (!l)
                        return log_oom();

                l->path = path;
                path = NULL;
                for (ttype = 0; ttype < _CGROUP_IO_LIMIT_TYPE_MAX; ttype++)
                        l->limits[ttype] = cgroup_io_limit_defaults[ttype];

                LIST_PREPEND(device_limits, c->io_device_limits, l);
        }

        l->limits[type] = num;

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

        uint64_t *weight = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = cg_blkio_weight_parse(rvalue, weight);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Block IO weight '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

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
        const char *weight;
        uint64_t u;
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
        weight += strspn(weight, WHITESPACE);

        if (isempty(weight)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Expected block device and device weight. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        r = cg_blkio_weight_parse(weight, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Block IO weight '%s' invalid. Ignoring.", weight);
                return 0;
        }

        assert(u != CGROUP_BLKIO_WEIGHT_INVALID);

        w = new0(CGroupBlockIODeviceWeight, 1);
        if (!w)
                return log_oom();

        w->path = path;
        path = NULL;

        w->weight = u;

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
        CGroupBlockIODeviceBandwidth *b = NULL, *t;
        CGroupContext *c = data;
        const char *bandwidth;
        uint64_t bytes;
        bool read;
        size_t n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        read = streq("BlockIOReadBandwidth", lvalue);

        if (isempty(rvalue)) {
                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                        b->rbps = CGROUP_LIMIT_MAX;
                        b->wbps = CGROUP_LIMIT_MAX;
                }
                return 0;
        }

        n = strcspn(rvalue, WHITESPACE);
        bandwidth = rvalue + n;
        bandwidth += strspn(bandwidth, WHITESPACE);

        if (!*bandwidth) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Expected space separated pair of device node and bandwidth. Ignoring.");
                return 0;
        }

        path = strndup(rvalue, n);
        if (!path)
                return log_oom();

        if (!path_startswith(path, "/dev")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s'. Ignoring.", path);
                return 0;
        }

        r = parse_size(bandwidth, 1000, &bytes);
        if (r < 0 || bytes <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Block IO Bandwidth '%s' invalid. Ignoring.", rvalue);
                return 0;
        }

        LIST_FOREACH(device_bandwidths, t, c->blockio_device_bandwidths) {
                if (path_equal(path, t->path)) {
                        b = t;
                        break;
                }
        }

        if (!t) {
                b = new0(CGroupBlockIODeviceBandwidth, 1);
                if (!b)
                        return log_oom();

                b->path = path;
                path = NULL;
                b->rbps = CGROUP_LIMIT_MAX;
                b->wbps = CGROUP_LIMIT_MAX;

                LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, b);
        }

        if (read)
                b->rbps = bytes;
        else
                b->wbps = bytes;

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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse boolean, ignoring: %s", rvalue);
                return 0;
        }

        *m = r ? JOB_ISOLATE : JOB_REPLACE;
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
        Unit *u = userdata;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *rt = strv_free(*rt);
                return 0;
        }

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve specifiers in \"%s\", ignoring: %m", word);
                        continue;
                }

                if (!filename_is_valid(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Runtime directory is not valid, ignoring assignment: %s", rvalue);
                        continue;
                }

                r = strv_push(rt, k);
                if (r < 0)
                        return log_oom();
                k = NULL;
        }
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
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse value, ignoring: %s", word);
                                continue;
                        }
                        set = &status_set->signal;
                } else {
                        if (val < 0 || val > 255) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Value %d is outside range 0-255, ignoring", val);
                                continue;
                        }
                        set = &status_set->status;
                }

                r = set_ensure_allocated(set, NULL);
                if (r < 0)
                        return log_oom();

                r = set_put(*set, INT_TO_PTR(val));
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Unable to store: %s", word);
                        return r;
                }
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, 0, "Trailing garbage, ignoring.");

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

        Unit *u = userdata;
        char*** sv = data;
        const char *cur;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *sv = strv_free(*sv);
                return 0;
        }

        cur = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL, *joined = NULL;
                const char *w;
                bool ignore_enoent = false, shall_prefix = false;

                r = extract_first_word(&cur, &word, NULL, EXTRACT_QUOTES);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
                }

                if (!utf8_is_valid(word)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, word);
                        continue;
                }

                w = word;
                if (startswith(w, "-")) {
                        ignore_enoent = true;
                        w++;
                }
                if (startswith(w, "+")) {
                        shall_prefix = true;
                        w++;
                }

                r = unit_full_printf(u, w, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve specifiers in %s: %m", word);
                        continue;
                }

                if (!path_is_absolute(resolved)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Not an absolute path, ignoring: %s", resolved);
                        continue;
                }

                path_kill_slashes(resolved);

                joined = strjoin(ignore_enoent ? "-" : "",
                                 shall_prefix ? "+" : "",
                                 resolved);

                r = strv_push(sv, joined);
                if (r < 0)
                        return log_oom();

                joined = NULL;
        }

        return 0;
}

int config_parse_bind_paths(
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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                bind_mount_free_many(c->bind_mounts, c->n_bind_mounts);
                c->bind_mounts = NULL;
                c->n_bind_mounts = 0;
                return 0;
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *source = NULL, *destination = NULL;
                _cleanup_free_ char *sresolved = NULL, *dresolved = NULL;
                char *s = NULL, *d = NULL;
                bool rbind = true, ignore_enoent = false;

                r = extract_first_word(&p, &source, ":" WHITESPACE, EXTRACT_QUOTES|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s: %s", lvalue, rvalue);
                        return 0;
                }

                r = unit_full_printf(u, source, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolved specifiers in \"%s\", ignoring: %m", source);
                        return 0;
                }

                s = sresolved;
                if (s[0] == '-') {
                        ignore_enoent = true;
                        s++;
                }

                if (!utf8_is_valid(s)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, s);
                        return 0;
                }
                if (!path_is_absolute(s)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Not an absolute source path, ignoring: %s", s);
                        return 0;
                }

                path_kill_slashes(s);

                /* Optionally, the destination is specified. */
                if (p && p[-1] == ':') {
                        r = extract_first_word(&p, &destination, ":" WHITESPACE, EXTRACT_QUOTES|EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s: %s", lvalue, rvalue);
                                return 0;
                        }
                        if (r == 0) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Missing argument after ':': %s", rvalue);
                                return 0;
                        }

                        r = unit_full_printf(u, destination, &dresolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolved specifiers in \"%s\", ignoring: %m", destination);
                                return 0;
                        }

                        if (!utf8_is_valid(dresolved)) {
                                log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, dresolved);
                                return 0;
                        }
                        if (!path_is_absolute(dresolved)) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Not an absolute destination path, ignoring: %s", dresolved);
                                return 0;
                        }

                        d = path_kill_slashes(dresolved);

                        /* Optionally, there's also a short option string specified */
                        if (p && p[-1] == ':') {
                                _cleanup_free_ char *options = NULL;

                                r = extract_first_word(&p, &options, NULL, EXTRACT_QUOTES);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0) {
                                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s: %s", lvalue, rvalue);
                                        return 0;
                                }

                                if (isempty(options) || streq(options, "rbind"))
                                        rbind = true;
                                else if (streq(options, "norbind"))
                                        rbind = false;
                                else {
                                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid option string, ignoring setting: %s", options);
                                        return 0;
                                }
                        }
                } else
                        d = s;

                r = bind_mount_add(&c->bind_mounts, &c->n_bind_mounts,
                                   &(BindMount) {
                                           .source = s,
                                           .destination = d,
                                           .read_only = !!strstr(lvalue, "ReadOnly"),
                                           .recursive = rbind,
                                           .ignore_enoent = ignore_enoent,
                                   });
                if (r < 0)
                        return log_oom();
        }

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
                log_syntax(unit, LOG_ERR, filename, line, k, "Failed to parse boolean value, ignoring: %s", rvalue);
                return 0;
        }

        c->no_new_privileges = k;

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
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                c->protect_home = PROTECT_HOME_YES;
        else if (k == 0)
                c->protect_home = PROTECT_HOME_NO;
        else {
                ProtectHome h;

                h = protect_home_from_string(rvalue);
                if (h < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse protect home value, ignoring: %s", rvalue);
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
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                c->protect_system = PROTECT_SYSTEM_YES;
        else if (k == 0)
                c->protect_system = PROTECT_SYSTEM_NO;
        else {
                ProtectSystem s;

                s = protect_system_from_string(rvalue);
                if (s < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse protect system value, ignoring: %s", rvalue);
                        return 0;
                }

                c->protect_system = s;
        }

        return 0;
}

#define FOLLOW_MAX 8

static int open_follow(char **filename, FILE **_f, Set *names, char **_final) {
        char *id = NULL;
        unsigned c = 0;
        int fd, r;
        FILE *f;

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

                        /* If the symlink name we are looking at is unit template, then
                           we must search for instance of this template */
                        if (unit_name_is_valid(k, UNIT_NAME_TEMPLATE) && (*u)->instance) {
                                _cleanup_free_ char *instance = NULL;

                                r = unit_name_replace_instance(k, (*u)->instance, &instance);
                                if (r < 0)
                                        return r;

                                other = manager_get_unit((*u)->manager, instance);
                        } else
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
        _cleanup_set_free_free_ Set *symlink_names = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *filename = NULL;
        char *id = NULL;
        Unit *merged;
        struct stat st;
        int r;

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
                        filename = mfree(filename);
                        if (r != -ENOENT)
                                return r;
                }

        } else  {
                char **p;

                STRV_FOREACH(p, u->manager->lookup_paths.search_path) {

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
                        if (r >= 0)
                                break;
                        filename = mfree(filename);

                        /* ENOENT means that the file is missing or is a dangling symlink.
                         * ENOTDIR means that one of paths we expect to be is a directory
                         * is not a directory, we should just ignore that.
                         * EACCES means that the directory or file permissions are wrong.
                         */
                        if (r == -EACCES)
                                log_debug_errno(r, "Cannot access \"%s\": %m", filename);
                        else if (!IN_SET(r, -ENOENT, -ENOTDIR))
                                return r;

                        /* Empty the symlink names for the next run */
                        set_clear_free(symlink_names);
                }
        }

        if (!filename)
                /* Hmm, no suitable file found? */
                return 0;

        if (!unit_type_may_alias(u->type) && set_size(symlink_names) > 1) {
                log_unit_warning(u, "Unit type of %s does not support alias names, refusing loading via symlink.", u->id);
                return -ELOOP;
        }

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

        if (null_or_empty(&st)) {
                u->load_state = UNIT_MASKED;
                u->fragment_mtime = 0;
        } else {
                u->load_state = UNIT_LOADED;
                u->fragment_mtime = timespec_load(&st.st_mtim);

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

        if (u->transient) {
                u->load_state = UNIT_LOADED;
                return 0;
        }

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

                if (u->load_state == UNIT_STUB)
                        /* Hmm, this didn't work? Then let's get rid
                         * of the fragment path stored for us, so that
                         * we don't point to an invalid location. */
                        u->fragment_path = mfree(u->fragment_path);
        }

        /* Look for a template */
        if (u->load_state == UNIT_STUB && u->instance) {
                _cleanup_free_ char *k = NULL;

                r = unit_name_template(u->id, &k);
                if (r < 0)
                        return r;

                r = load_from_path(u, k);
                if (r < 0) {
                        if (r == -ENOEXEC)
                                log_unit_notice(u, "Unit configuration has fatal error, unit will not be started.");
                        return r;
                }

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
                { config_parse_iec_uint64,            "SIZE" },
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
                { config_parse_exec_output,           "OUTPUT" },
                { config_parse_exec_input,            "INPUT" },
                { config_parse_log_facility,          "FACILITY" },
                { config_parse_log_level,             "LEVEL" },
                { config_parse_exec_secure_bits,      "SECUREBITS" },
                { config_parse_capability_set,        "BOUNDINGSET" },
                { config_parse_limit,                 "LIMIT" },
                { config_parse_unit_deps,             "UNIT [...]" },
                { config_parse_exec,                  "PATH [ARGUMENT [...]]" },
                { config_parse_service_type,          "SERVICETYPE" },
                { config_parse_service_restart,       "SERVICERESTART" },
#ifdef HAVE_SYSV_COMPAT
                { config_parse_sysv_priority,         "SYSVPRIORITY" },
#endif
                { config_parse_kill_mode,             "KILLMODE" },
                { config_parse_signal,                "SIGNAL" },
                { config_parse_socket_listen,         "SOCKET [...]" },
                { config_parse_socket_bind,           "SOCKETBIND" },
                { config_parse_socket_bindtodevice,   "NETWORKINTERFACE" },
                { config_parse_sec,                   "SECONDS" },
                { config_parse_nsec,                  "NANOSECONDS" },
                { config_parse_namespace_path_strv,   "PATH [...]" },
                { config_parse_bind_paths,            "PATH[:PATH[:OPTIONS]] [...]" },
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
                { config_parse_emergency_action,      "ACTION" },
                { config_parse_set_status,            "STATUS" },
                { config_parse_service_sockets,       "SOCKETS" },
                { config_parse_environ,               "ENVIRON" },
#ifdef HAVE_SECCOMP
                { config_parse_syscall_filter,        "SYSCALLS" },
                { config_parse_syscall_archs,         "ARCHS" },
                { config_parse_syscall_errno,         "ERRNO" },
                { config_parse_address_families,      "FAMILIES" },
                { config_parse_restrict_namespaces,   "NAMESPACES"  },
#endif
                { config_parse_cpu_shares,            "SHARES" },
                { config_parse_cpu_weight,            "WEIGHT" },
                { config_parse_memory_limit,          "LIMIT" },
                { config_parse_device_allow,          "DEVICE" },
                { config_parse_device_policy,         "POLICY" },
                { config_parse_io_limit,              "LIMIT" },
                { config_parse_io_weight,             "WEIGHT" },
                { config_parse_io_device_weight,      "DEVICEWEIGHT" },
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
