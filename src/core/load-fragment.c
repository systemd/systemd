/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2012 Holger Hans Peter Freyther
***/

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/oom.h>
#if HAVE_SECCOMP
#include <seccomp.h>
#endif
#include <sched.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "af-list.h"
#include "alloc-util.h"
#include "all-units.h"
#include "bpf-firewall.h"
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
#include "hexdecoct.h"
#include "io-util.h"
#include "ioprio.h"
#include "ip-protocol-list.h"
#include "journal-util.h"
#include "limits-util.h"
#include "load-fragment.h"
#include "log.h"
#include "missing.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#if HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "securebits-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "user-util.h"
#include "time-util.h"
#include "web-util.h"

static int parse_socket_protocol(const char *s) {
        int r;

        r = parse_ip_protocol(s);
        if (r < 0)
                return r;
        if (!IN_SET(r, IPPROTO_UDPLITE, IPPROTO_SCTP))
                return -EPROTONOSUPPORT;

        return r;
}

int parse_crash_chvt(const char *value, int *data) {
        int b;

        if (safe_atoi(value, data) >= 0)
                return 0;

        b = parse_boolean(value);
        if (b < 0)
                return b;

        if (b > 0)
                *data = 0; /* switch to where kmsg goes */
        else
                *data = -1; /* turn off switching */

        return 0;
}

int parse_confirm_spawn(const char *value, char **console) {
        char *s;
        int r;

        r = value ? parse_boolean(value) : 1;
        if (r == 0) {
                *console = NULL;
                return 0;
        } else if (r > 0) /* on with default tty */
                s = strdup("/dev/console");
        else if (is_path(value)) /* on with fully qualified path */
                s = strdup(value);
        else /* on with only a tty file name, not a fully qualified path */
                s = path_join("/dev/", value);
        if (!s)
                return -ENOMEM;

        *console = s;
        return 0;
}

DEFINE_CONFIG_PARSE(config_parse_socket_protocol, parse_socket_protocol, "Failed to parse socket protocol");
DEFINE_CONFIG_PARSE(config_parse_exec_secure_bits, secure_bits_from_string, "Failed to parse secure bits");
DEFINE_CONFIG_PARSE_ENUM(config_parse_collect_mode, collect_mode, CollectMode, "Failed to parse garbage collection mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_device_policy, cgroup_device_policy, CGroupDevicePolicy, "Failed to parse device policy");
DEFINE_CONFIG_PARSE_ENUM(config_parse_exec_keyring_mode, exec_keyring_mode, ExecKeyringMode, "Failed to parse keyring mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_exec_utmp_mode, exec_utmp_mode, ExecUtmpMode, "Failed to parse utmp mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_job_mode, job_mode, JobMode, "Failed to parse job mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_kill_mode, kill_mode, KillMode, "Failed to parse kill mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_notify_access, notify_access, NotifyAccess, "Failed to parse notify access specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_protect_home, protect_home, ProtectHome, "Failed to parse protect home value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_protect_system, protect_system, ProtectSystem, "Failed to parse protect system value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_runtime_preserve_mode, exec_preserve_mode, ExecPreserveMode, "Failed to parse runtime directory preserve mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_type, service_type, ServiceType, "Failed to parse service type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart, service_restart, ServiceRestart, "Failed to parse service restart specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_socket_bind, socket_address_bind_ipv6_only_or_bool, SocketAddressBindIPv6Only, "Failed to parse bind IPv6 only value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_oom_policy, oom_policy, OOMPolicy, "Failed to parse OOM policy");
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ip_tos, ip_tos, int, -1, "Failed to parse IP TOS value");
DEFINE_CONFIG_PARSE_PTR(config_parse_blockio_weight, cg_blkio_weight_parse, uint64_t, "Invalid block IO weight");
DEFINE_CONFIG_PARSE_PTR(config_parse_cg_weight, cg_weight_parse, uint64_t, "Invalid weight");
DEFINE_CONFIG_PARSE_PTR(config_parse_cpu_shares, cg_cpu_shares_parse, uint64_t, "Invalid CPU shares");
DEFINE_CONFIG_PARSE_PTR(config_parse_exec_mount_flags, mount_propagation_flags_from_string, unsigned long, "Failed to parse mount flag");
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_numa_policy, mpol, int, -1, "Invalid NUMA policy type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_status_unit_format, status_unit_format, StatusUnitFormat, "Failed to parse status unit format");

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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                r = unit_add_dependency_by_name(u, d, k, true, UNIT_DEPENDENCY_FILE);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

        /* Let's not bother with anything that is too long */
        if (strlen(rvalue) >= PATH_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "%s value too long%s.",
                           lvalue, fatal ? "" : ", ignoring");
                return fatal ? -ENAMETOOLONG : 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve unit specifiers in '%s'%s: %m",
                           rvalue, fatal ? "" : ", ignoring");
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

        if (isempty(rvalue)) {
                *x = strv_free(*x);
                return 0;
        }

        for (p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
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
                                   "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        return 0;
                }

                r = path_simplify_and_warn(k, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                r = strv_consume(x, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}

static int patch_var_run(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue,
                char **path) {

        const char *e;
        char *z;

        e = path_startswith(*path, "/var/run/");
        if (!e)
                return 0;

        z = path_join("/run/", e);
        if (!z)
                return log_oom();

        log_syntax(unit, LOG_NOTICE, filename, line, 0,
                   "%s= references a path below legacy directory /var/run/, updating %s → %s; "
                   "please update the unit file accordingly.", lvalue, *path, z);

        free_and_replace(*path, z);

        return 1;
}

int config_parse_socket_listen(
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
                _cleanup_free_ char *k = NULL;

                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                        return 0;
                }

                r = path_simplify_and_warn(k, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                if (ltype == SOCKET_FIFO) {
                        r = patch_var_run(unit, filename, line, lvalue, &k);
                        if (r < 0)
                                return r;
                }

                free_and_replace(p->path, k);
                p->type = ltype;

        } else if (streq(lvalue, "ListenNetlink")) {
                _cleanup_free_ char  *k = NULL;

                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                        return 0;
                }

                r = socket_address_parse_netlink(&p->address, k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address value in '%s', ignoring: %m", k);
                        return 0;
                }

                p->type = SOCKET_SOCKET;

        } else {
                _cleanup_free_ char *k = NULL;

                r = unit_full_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                        return 0;
                }

                if (k[0] == '/') { /* Only for AF_UNIX file system sockets… */
                        r = patch_var_run(unit, filename, line, lvalue, &k);
                        if (r < 0)
                                return r;
                }

                r = socket_address_parse_and_warn(&p->address, k);
                if (r < 0) {
                        if (r != -EAFNOSUPPORT)
                                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address value in '%s', ignoring: %m", k);
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

                p->type = SOCKET_SOCKET;
        }

        p->fd = -1;
        p->auxiliary_fds = NULL;
        p->n_auxiliary_fds = 0;
        p->socket = s;

        LIST_FIND_TAIL(port, s->ports, tail);
        LIST_INSERT_AFTER(port, s->ports, tail, p);

        p = NULL;

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

        if (isempty(rvalue)) {
                c->nice_set = false;
                return 0;
        }

        r = parse_nice(rvalue, &priority);
        if (r < 0) {
                if (r == -ERANGE)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Nice priority out of range, ignoring: %s", rvalue);
                else
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse nice priority '%s', ignoring: %m", rvalue);
                return 0;
        }

        c->nice = priority;
        c->nice_set = true;

        return 0;
}

int config_parse_exec_oom_score_adjust(
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
        int oa, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                c->oom_score_adjust_set = false;
                return 0;
        }

        r = parse_oom_score_adjust(rvalue, &oa);
        if (r < 0) {
                if (r == -ERANGE)
                        log_syntax(unit, LOG_ERR, filename, line, r, "OOM score adjust value out of range, ignoring: %s", rvalue);
                else
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse the OOM score adjust value '%s', ignoring: %m", rvalue);
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
                ExecCommandFlags flags = 0;
                bool ignore = false, separate_argv0 = false;
                _cleanup_free_ ExecCommand *nce = NULL;
                _cleanup_strv_free_ char **n = NULL;
                size_t nlen = 0, nbufsize = 0;
                const char *f;

                semicolon = false;

                r = extract_first_word_and_warn(&p, &firstword, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, unit, filename, line, rvalue);
                if (r <= 0)
                        return 0;

                f = firstword;
                for (;;) {
                        /* We accept an absolute path as first argument.  If it's prefixed with - and the path doesn't
                         * exist, we ignore it instead of erroring out; if it's prefixed with @, we allow overriding of
                         * argv[0]; if it's prefixed with :, we will not do environment variable substitution;
                         * if it's prefixed with +, it will be run with full privileges and no sandboxing; if
                         * it's prefixed with '!' we apply sandboxing, but do not change user/group credentials; if
                         * it's prefixed with '!!', then we apply user/group credentials if the kernel supports ambient
                         * capabilities -- if it doesn't we don't apply the credentials themselves, but do apply most
                         * other sandboxing, with some special exceptions for changing UID.
                         *
                         * The idea is that '!!' may be used to write services that can take benefit of systemd's
                         * UID/GID dropping if the kernel supports ambient creds, but provide an automatic fallback to
                         * privilege dropping within the daemon if the kernel does not offer that. */

                        if (*f == '-' && !(flags & EXEC_COMMAND_IGNORE_FAILURE)) {
                                flags |= EXEC_COMMAND_IGNORE_FAILURE;
                                ignore = true;
                        } else if (*f == '@' && !separate_argv0)
                                separate_argv0 = true;
                        else if (*f == ':' && !(flags & EXEC_COMMAND_NO_ENV_EXPAND))
                                flags |= EXEC_COMMAND_NO_ENV_EXPAND;
                        else if (*f == '+' && !(flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID|EXEC_COMMAND_AMBIENT_MAGIC)))
                                flags |= EXEC_COMMAND_FULLY_PRIVILEGED;
                        else if (*f == '!' && !(flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID|EXEC_COMMAND_AMBIENT_MAGIC)))
                                flags |= EXEC_COMMAND_NO_SETUID;
                        else if (*f == '!' && !(flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_AMBIENT_MAGIC))) {
                                flags &= ~EXEC_COMMAND_NO_SETUID;
                                flags |= EXEC_COMMAND_AMBIENT_MAGIC;
                        } else
                                break;
                        f++;
                }

                r = unit_full_printf(u, f, &path);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers in '%s'%s: %m",
                                   f, ignore ? ", ignoring" : "");
                        return ignore ? 0 : -ENOEXEC;
                }

                if (isempty(path)) {
                        /* First word is either "-" or "@" with no command. */
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Empty path in command line%s: '%s'",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (!string_is_safe(path)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Executable name contains special characters%s: %s",
                                   ignore ? ", ignoring" : "", path);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (endswith(path, "/")) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Executable path specifies a directory%s: %s",
                                   ignore ? ", ignoring" : "", path);
                        return ignore ? 0 : -ENOEXEC;
                }

                if (!path_is_absolute(path)) {
                        const char *prefix;
                        bool found = false;

                        if (!filename_is_valid(path)) {
                                log_syntax(unit, LOG_ERR, filename, line, 0,
                                           "Neither a valid executable name nor an absolute path%s: %s",
                                           ignore ? ", ignoring" : "", path);
                                return ignore ? 0 : -ENOEXEC;
                        }

                        /* Resolve a single-component name to a full path */
                        NULSTR_FOREACH(prefix, DEFAULT_PATH_NULSTR) {
                                _cleanup_free_ char *fullpath = NULL;

                                fullpath = path_join(prefix, path);
                                if (!fullpath)
                                        return log_oom();

                                if (access(fullpath, F_OK) >= 0) {
                                        free_and_replace(path, fullpath);
                                        found = true;
                                        break;
                                }
                        }

                        if (!found) {
                                log_syntax(unit, LOG_ERR, filename, line, 0,
                                           "Executable \"%s\" not found in path \"%s\"%s",
                                           path, DEFAULT_PATH, ignore ? ", ignoring" : "");
                                return ignore ? 0 : -ENOEXEC;
                        }
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

                path_simplify(path, false);

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

                        r = extract_first_word_and_warn(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, unit, filename, line, rvalue);
                        if (r == 0)
                                break;
                        if (r < 0)
                                return ignore ? 0 : -ENOEXEC;

                        r = unit_full_printf(u, word, &resolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolve unit specifiers in %s%s: %m",
                                           word, ignore ? ", ignoring" : "");
                                return ignore ? 0 : -ENOEXEC;
                        }

                        if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                                return log_oom();

                        n[nlen++] = TAKE_PTR(resolved);
                        n[nlen] = NULL;
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

                nce->argv = TAKE_PTR(n);
                nce->path = TAKE_PTR(path);
                nce->flags = flags;

                exec_command_append_list(e, nce);

                /* Do not _cleanup_free_ these. */
                nce = NULL;

                rvalue = p;
        } while (semicolon);

        return 0;
}

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

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue) || streq(rvalue, "*")) {
                s->bind_to_device = mfree(s->bind_to_device);
                return 0;
        }

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid interface name, ignoring: %s", rvalue);
                return 0;
        }

        if (free_and_strdup(&s->bind_to_device, rvalue) < 0)
                return log_oom();

        return 0;
}

int config_parse_exec_input(
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
        const char *n;
        ExecInput ei;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(rvalue);

        n = startswith(rvalue, "fd:");
        if (n) {
                _cleanup_free_ char *resolved = NULL;

                r = unit_full_printf(u, n, &resolved);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s': %m", n);

                if (isempty(resolved))
                        resolved = mfree(resolved);
                else if (!fdname_is_valid(resolved)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid file descriptor name: %s", resolved);
                        return -ENOEXEC;
                }

                free_and_replace(c->stdio_fdname[STDIN_FILENO], resolved);

                ei = EXEC_INPUT_NAMED_FD;

        } else if ((n = startswith(rvalue, "file:"))) {
                _cleanup_free_ char *resolved = NULL;

                r = unit_full_printf(u, n, &resolved);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s': %m", n);

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return -ENOEXEC;

                free_and_replace(c->stdio_file[STDIN_FILENO], resolved);

                ei = EXEC_INPUT_FILE;

        } else {
                ei = exec_input_from_string(rvalue);
                if (ei < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse input specifier, ignoring: %s", rvalue);
                        return 0;
                }
        }

        c->std_input = ei;
        return 0;
}

int config_parse_exec_input_text(
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

        _cleanup_free_ char *unescaped = NULL, *resolved = NULL;
        ExecContext *c = data;
        Unit *u = userdata;
        size_t sz;
        void *p;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->stdin_data = mfree(c->stdin_data);
                c->stdin_data_size = 0;
                return 0;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to decode C escaped text '%s': %m", rvalue);

        r = unit_full_printf(u, unescaped, &resolved);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s': %m", unescaped);

        sz = strlen(resolved);
        if (c->stdin_data_size + sz + 1 < c->stdin_data_size || /* check for overflow */
            c->stdin_data_size + sz + 1 > EXEC_STDIN_DATA_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Standard input data too large (%zu), maximum of %zu permitted, ignoring.", c->stdin_data_size + sz, (size_t) EXEC_STDIN_DATA_MAX);
                return -E2BIG;
        }

        p = realloc(c->stdin_data, c->stdin_data_size + sz + 1);
        if (!p)
                return log_oom();

        *((char*) mempcpy((char*) p + c->stdin_data_size, resolved, sz)) = '\n';

        c->stdin_data = p;
        c->stdin_data_size += sz + 1;

        return 0;
}

int config_parse_exec_input_data(
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

        _cleanup_free_ void *p = NULL;
        ExecContext *c = data;
        size_t sz;
        void *q;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->stdin_data = mfree(c->stdin_data);
                c->stdin_data_size = 0;
                return 0;
        }

        r = unbase64mem(rvalue, (size_t) -1, &p, &sz);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to decode base64 data, ignoring: %s", rvalue);

        assert(sz > 0);

        if (c->stdin_data_size + sz < c->stdin_data_size || /* check for overflow */
            c->stdin_data_size + sz > EXEC_STDIN_DATA_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Standard input data too large (%zu), maximum of %zu permitted, ignoring.", c->stdin_data_size + sz, (size_t) EXEC_STDIN_DATA_MAX);
                return -E2BIG;
        }

        q = realloc(c->stdin_data, c->stdin_data_size + sz);
        if (!q)
                return log_oom();

        memcpy((uint8_t*) q + c->stdin_data_size, p, sz);

        c->stdin_data = q;
        c->stdin_data_size += sz;

        return 0;
}

int config_parse_exec_output(
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

        _cleanup_free_ char *resolved = NULL;
        const char *n;
        ExecContext *c = data;
        Unit *u = userdata;
        ExecOutput eo;
        int r;

        assert(data);
        assert(filename);
        assert(line);
        assert(lvalue);
        assert(rvalue);

        n = startswith(rvalue, "fd:");
        if (n) {
                r = unit_full_printf(u, n, &resolved);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", n);

                if (isempty(resolved))
                        resolved = mfree(resolved);
                else if (!fdname_is_valid(resolved)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid file descriptor name: %s", resolved);
                        return -ENOEXEC;
                }

                eo = EXEC_OUTPUT_NAMED_FD;

        } else if ((n = startswith(rvalue, "file:"))) {

                r = unit_full_printf(u, n, &resolved);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", n);

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return -ENOEXEC;

                eo = EXEC_OUTPUT_FILE;

        } else if ((n = startswith(rvalue, "append:"))) {

                r = unit_full_printf(u, n, &resolved);
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", n);

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return -ENOEXEC;

                eo = EXEC_OUTPUT_FILE_APPEND;
        } else {
                eo = exec_output_from_string(rvalue);
                if (eo < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse output specifier, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "StandardOutput")) {
                if (eo == EXEC_OUTPUT_NAMED_FD)
                        free_and_replace(c->stdio_fdname[STDOUT_FILENO], resolved);
                else
                        free_and_replace(c->stdio_file[STDOUT_FILENO], resolved);

                c->std_output = eo;

        } else {
                assert(streq(lvalue, "StandardError"));

                if (eo == EXEC_OUTPUT_NAMED_FD)
                        free_and_replace(c->stdio_fdname[STDERR_FILENO], resolved);
                else
                        free_and_replace(c->stdio_file[STDERR_FILENO], resolved);

                c->std_error = eo;
        }

        return 0;
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

        if (isempty(rvalue)) {
                c->ioprio_set = false;
                c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0);
                return 0;
        }

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

        if (isempty(rvalue)) {
                c->ioprio_set = false;
                c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0);
                return 0;
        }

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

        if (isempty(rvalue)) {
                c->cpu_sched_set = false;
                c->cpu_sched_policy = SCHED_OTHER;
                c->cpu_sched_priority = 0;
                return 0;
        }

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

int config_parse_numa_mask(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {
        int r;
        NUMAPolicy *p = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_cpu_set_extend(rvalue, &p->nodes, true, unit, filename, line, lvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse NUMA node mask, ignoring: %s", rvalue);
                return 0;
        }

        return r;
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CPU scheduling priority, ignoring: %s", rvalue);
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        return parse_cpu_set_extend(rvalue, &c->cpu_set, true, unit, filename, line, lvalue);
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (streq(lvalue, "CapabilityBoundingSet"))
                initial = CAP_ALL; /* initialized to all bits on */
        /* else "AmbientCapabilities" initialized to all bits off */

        r = capability_set_from_string(rvalue, &sum);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s= specifier '%s', ignoring: %m", lvalue, rvalue);
                return 0;
        }

        if (sum == 0 || *capability_set == initial)
                /* "", "~" or uninitialized data -> replace */
                *capability_set = invert ? ~sum : sum;
        else {
                /* previous data -> merge */
                if (invert)
                        *capability_set &= ~sum;
                else
                        *capability_set |= sum;
        }

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
                           "Failed to resolve unit specifiers in '%s'%s: %m",
                           rvalue, ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
        }

        free_and_replace(c->selinux_context, k);
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
                           "Failed to resolve unit specifiers in '%s'%s: %m",
                           rvalue, ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
        }

        free_and_replace(c->apparmor_profile, k);
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
                           "Failed to resolve unit specifiers in '%s'%s: %m",
                           rvalue, ignore ? ", ignoring" : "");
                return ignore ? 0 : -ENOEXEC;
        }

        free_and_replace(c->smack_process_label, k);
        c->smack_process_label_ignore = ignore;

        return 0;
}

int config_parse_timer(
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

        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;
        _cleanup_free_ char *k = NULL;
        Unit *u = userdata;
        Timer *t = data;
        usec_t usec = 0;
        TimerValue *v;
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

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (ltype == TIMER_CALENDAR) {
                r = calendar_spec_from_string(k, &c);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse calendar specification, ignoring: %s", k);
                        return 0;
                }
        } else {
                r = parse_sec(k, &usec);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse timer value, ignoring: %s", k);
                        return 0;
                }
        }

        v = new(TimerValue, 1);
        if (!v)
                return log_oom();

        *v = (TimerValue) {
                .base = ltype,
                .value = usec,
                .calendar_spec = TAKE_PTR(c),
        };

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

        if (!hashmap_isempty(u->dependencies[UNIT_TRIGGERS])) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Multiple units to trigger specified, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_name_printf(u, rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        type = unit_name_to_type(p);
        if (type < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Unit type not valid, ignoring: %s", rvalue);
                return 0;
        }
        if (unit_has_name(u, p)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Units cannot trigger themselves, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_add_two_dependencies_by_name(u, UNIT_BEFORE, UNIT_TRIGGERS, p, true, UNIT_DEPENDENCY_FILE);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(k, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        s = new0(PathSpec, 1);
        if (!s)
                return log_oom();

        s->unit = UNIT(p);
        s->path = TAKE_PTR(k);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", rvalue);
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

        unit_ref_set(&s->service, UNIT(s), x);

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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                if (!endswith(k, ".socket")) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unit must be of type socket, ignoring: %s", k);
                        continue;
                }

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_WANTS, UNIT_AFTER, k, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);

                r = unit_add_dependency_by_name(UNIT(s), UNIT_TRIGGERED_BY, k, true, UNIT_DEPENDENCY_FILE);
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        if (!service_name_is_valid(k)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid bus name, ignoring: %s", k);
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

        /* This is called for two cases: TimeoutSec= and TimeoutStartSec=. */

        /* Traditionally, these options accepted 0 to disable the timeouts. However, a timeout of 0 suggests it happens
         * immediately, hence fix this to become USEC_INFINITY instead. This is in-line with how we internally handle
         * all other timeouts. */
        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s= parameter, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        s->start_timeout_defined = true;
        s->timeout_start_usec = usec;

        if (streq(lvalue, "TimeoutSec"))
                s->timeout_stop_usec = usec;

        return 0;
}

int config_parse_service_timeout_abort(
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        rvalue += strspn(rvalue, WHITESPACE);
        if (isempty(rvalue)) {
                s->timeout_abort_set = false;
                return 0;
        }

        r = parse_sec(rvalue, &s->timeout_abort_usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse TimeoutAbortSec= setting, ignoring: %s", rvalue);
                return 0;
        }

        s->timeout_abort_set = true;
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

int config_parse_user_group_compat(
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
        char **user = data;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                *user = mfree(*user);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", rvalue);
                return -ENOEXEC;
        }

        if (!valid_user_group_name_or_id_compat(k)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid user/group name or numeric ID: %s", k);
                return -ENOEXEC;
        }

        return free_and_replace(*user, k);
}

int config_parse_user_group_strv_compat(
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
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                *users = strv_free(*users);
                return 0;
        }

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

                if (!valid_user_group_name_or_id_compat(k)) {
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

        if (isempty(rvalue)) {
                c->working_directory_home = false;
                c->working_directory = mfree(c->working_directory);
                return 0;
        }

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

                r = path_simplify_and_warn(k, PATH_CHECK_ABSOLUTE | (missing_ok ? 0 : PATH_CHECK_FATAL), unit, filename, line, lvalue);
                if (r < 0)
                        return missing_ok ? 0 : -ENOEXEC;

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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(n[0] == '-' ? n + 1 : n, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = strv_push(env, n);
        if (r < 0)
                return log_oom();

        n = NULL;

        return 0;
}

int config_parse_environ(
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

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
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
                                           "Failed to resolve unit specifiers in %s, ignoring: %m", word);
                                continue;
                        }
                } else
                        k = TAKE_PTR(word);

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

int config_parse_pass_environ(
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

        _cleanup_strv_free_ char **n = NULL;
        size_t nlen = 0, nbufsize = 0;
        char*** passenv = data;
        const char *p = rvalue;
        Unit *u = userdata;
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
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }

                if (u) {
                        r = unit_full_printf(u, word, &k);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolve specifiers in %s, ignoring: %m", word);
                                continue;
                        }
                } else
                        k = TAKE_PTR(word);

                if (!env_name_is_valid(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid environment name for %s, ignoring: %s", lvalue, k);
                        continue;
                }

                if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                        return log_oom();

                n[nlen++] = TAKE_PTR(k);
                n[nlen] = NULL;
        }

        if (n) {
                r = strv_extend_strv(passenv, n, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_unset_environ(
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

        _cleanup_strv_free_ char **n = NULL;
        size_t nlen = 0, nbufsize = 0;
        char*** unsetenv = data;
        const char *p = rvalue;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *unsetenv = strv_free(*unsetenv);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }

                if (u) {
                        r = unit_full_printf(u, word, &k);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolve unit specifiers in %s, ignoring: %m", word);
                                continue;
                        }
                } else
                        k = TAKE_PTR(word);

                if (!env_assignment_is_valid(k) && !env_name_is_valid(k)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid environment name or assignment %s, ignoring: %s", lvalue, k);
                        continue;
                }

                if (!GREEDY_REALLOC(n, nbufsize, nlen + 2))
                        return log_oom();

                n[nlen++] = TAKE_PTR(k);
                n[nlen] = NULL;
        }

        if (n) {
                r = strv_extend_strv(unsetenv, n, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_log_extra_fields(
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
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(c);

        if (isempty(rvalue)) {
                exec_context_free_log_extra_fields(c);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;
                struct iovec *t;
                const char *eq;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", word);
                        continue;
                }

                eq = strchr(k, '=');
                if (!eq) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Log field lacks '=' character, ignoring: %s", k);
                        continue;
                }

                if (!journal_field_valid(k, eq-k, false)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Log field name is invalid, ignoring: %s", k);
                        continue;
                }

                t = reallocarray(c->log_extra_fields, c->n_log_extra_fields+1, sizeof(struct iovec));
                if (!t)
                        return log_oom();

                c->log_extra_fields = t;
                c->log_extra_fields[c->n_log_extra_fields++] = IOVEC_MAKE_STRING(k);

                k = NULL;
        }
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(p, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

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

        trigger = *rvalue == '|';
        if (trigger)
                rvalue += 1 + strspn(rvalue + 1, WHITESPACE);

        negate = *rvalue == '!';
        if (negate)
                rvalue += 1 + strspn(rvalue + 1, WHITESPACE);

        r = unit_full_printf(u, rvalue, &s);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

        log_syntax(unit, LOG_WARNING, filename, line, 0, "%s= is deprecated, please do not use.", lvalue);

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

        const char *p = rvalue;
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        for (;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = unit_full_printf(u, word, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                r = unit_require_mounts_for(u, resolved, UNIT_DEPENDENCY_FILE);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to add required mount '%s', ignoring: %m", resolved);
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

#if HAVE_SECCOMP
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
                c->syscall_filter = hashmap_free(c->syscall_filter);
                c->syscall_whitelist = false;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (!c->syscall_filter) {
                c->syscall_filter = hashmap_new(NULL);
                if (!c->syscall_filter)
                        return log_oom();

                if (invert)
                        /* Allow everything but the ones listed */
                        c->syscall_whitelist = false;
                else {
                        /* Allow nothing but the ones listed */
                        c->syscall_whitelist = true;

                        /* Accept default syscalls if we are on a whitelist */
                        r = seccomp_parse_syscall_filter(
                                        "@default", -1, c->syscall_filter,
                                        SECCOMP_PARSE_PERMISSIVE|SECCOMP_PARSE_WHITELIST,
                                        unit,
                                        NULL, 0);
                        if (r < 0)
                                return r;
                }
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL, *name = NULL;
                int num;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = parse_syscall_and_errno(word, &name, &num);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse syscall:errno, ignoring: %s", word);
                        continue;
                }

                r = seccomp_parse_syscall_filter(
                                name, num, c->syscall_filter,
                                SECCOMP_PARSE_LOG|SECCOMP_PARSE_PERMISSIVE|
                                (invert ? SECCOMP_PARSE_INVERT : 0)|
                                (c->syscall_whitelist ? SECCOMP_PARSE_WHITELIST : 0),
                                unit, filename, line);
                if (r < 0)
                        return r;
        }
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

        const char *p = rvalue;
        Set **archs = data;
        int r;

        if (isempty(rvalue)) {
                *archs = set_free(*archs);
                return 0;
        }

        r = set_ensure_allocated(archs, NULL);
        if (r < 0)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL;
                uint32_t a;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
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

        e = parse_errno(rvalue);
        if (e <= 0) {
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

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
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
                if (af < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, af,
                                   "Failed to parse address family, ignoring: %s", word);
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
        unsigned long flags;
        bool invert = false;
        int r;

        if (isempty(rvalue)) {
                /* Reset to the default. */
                c->restrict_namespaces = NAMESPACE_FLAGS_INITIAL;
                return 0;
        }

        /* Boolean parameter ignores the previous settings */
        r = parse_boolean(rvalue);
        if (r > 0) {
                c->restrict_namespaces = 0;
                return 0;
        } else if (r == 0) {
                c->restrict_namespaces = NAMESPACE_FLAGS_ALL;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        /* Not a boolean argument, in this case it's a list of namespace types. */
        r = namespace_flags_from_string(rvalue, &flags);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse namespace type string, ignoring: %s", rvalue);
                return 0;
        }

        if (c->restrict_namespaces == NAMESPACE_FLAGS_INITIAL)
                /* Initial assignment. Just set the value. */
                c->restrict_namespaces = invert ? (~flags) & NAMESPACE_FLAGS_ALL : flags;
        else
                /* Merge the value with the previous one. */
                SET_FLAG(c->restrict_namespaces, flags, !invert);

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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *k = NULL;
        Unit *u = userdata, *slice = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        r = manager_load_unit(u->manager, k, NULL, &error, &slice);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to load slice unit %s, ignoring: %s", k, bus_error_message(&error, r));
                return 0;
        }

        r = unit_set_slice(u, slice);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to assign slice %s to unit %s, ignoring: %m", slice->id, u->id);
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

        r = parse_permille_unbounded(rvalue);
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid CPU quota '%s', ignoring.", rvalue);
                return 0;
        }

        c->cpu_quota_per_sec_usec = ((usec_t) r * USEC_PER_SEC) / 1000U;
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

                r = parse_permille(rvalue);
                if (r < 0) {
                        r = parse_size(rvalue, 1024, &bytes);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid memory limit '%s', ignoring: %m", rvalue);
                                return 0;
                        }
                } else
                        bytes = physical_memory_scale(r, 1000U);

                if (bytes >= UINT64_MAX ||
                    (bytes <= 0 && !STR_IN_SET(lvalue, "MemorySwapMax", "MemoryLow", "MemoryMin", "DefaultMemoryLow", "DefaultMemoryMin"))) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Memory limit '%s' out of range, ignoring.", rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "DefaultMemoryLow")) {
                c->default_memory_low_set = true;
                if (isempty(rvalue))
                        c->default_memory_low = CGROUP_LIMIT_MIN;
                else
                        c->default_memory_low = bytes;
        } else if (streq(lvalue, "DefaultMemoryMin")) {
                c->default_memory_min_set = true;
                if (isempty(rvalue))
                        c->default_memory_min = CGROUP_LIMIT_MIN;
                else
                        c->default_memory_min = bytes;
        } else if (streq(lvalue, "MemoryMin")) {
                c->memory_min = bytes;
                c->memory_min_set = true;
        } else if (streq(lvalue, "MemoryLow")) {
                c->memory_low = bytes;
                c->memory_low_set = true;
        } else if (streq(lvalue, "MemoryHigh"))
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
                *tasks_max = u ? u->manager->default_tasks_max : UINT64_MAX;
                return 0;
        }

        if (streq(rvalue, "infinity")) {
                *tasks_max = CGROUP_LIMIT_MAX;
                return 0;
        }

        r = parse_permille(rvalue);
        if (r < 0) {
                r = safe_atou64(rvalue, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid maximum tasks value '%s', ignoring: %m", rvalue);
                        return 0;
                }
        } else
                v = system_tasks_max_scale(r, 1000U);

        if (v <= 0 || v >= UINT64_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Maximum tasks value '%s' out of range, ignoring.", rvalue);
                return 0;
        }

        *tasks_max = v;
        return 0;
}

int config_parse_delegate(
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
        UnitType t;
        int r;

        t = unit_name_to_type(unit);
        assert(t != _UNIT_TYPE_INVALID);

        if (!unit_vtable[t]->can_delegate) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Delegate= setting not supported for this unit type, ignoring.");
                return 0;
        }

        /* We either accept a boolean value, which may be used to turn on delegation for all controllers, or turn it
         * off for all. Or it takes a list of controller names, in which case we add the specified controllers to the
         * mask to delegate. */

        if (isempty(rvalue)) {
                /* An empty string resets controllers and set Delegate=yes. */
                c->delegate = true;
                c->delegate_controllers = 0;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                const char *p = rvalue;
                CGroupMask mask = 0;

                for (;;) {
                        _cleanup_free_ char *word = NULL;
                        CGroupController cc;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                                return 0;
                        }

                        cc = cgroup_controller_from_string(word);
                        if (cc < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid controller name '%s', ignoring", word);
                                continue;
                        }

                        mask |= CGROUP_CONTROLLER_TO_MASK(cc);
                }

                c->delegate = true;
                c->delegate_controllers |= mask;

        } else if (r > 0) {
                c->delegate = true;
                c->delegate_controllers = _CGROUP_MASK_ALL;
        } else {
                c->delegate = false;
                c->delegate_controllers = 0;
        }

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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupContext *c = data;
        const char *p = rvalue;
        int r;

        if (isempty(rvalue)) {
                while (c->device_allow)
                        cgroup_context_free_device_allow(c, c->device_allow);

                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device path and rights from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        if (!STARTSWITH_SET(resolved, "block-", "char-")) {

                r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                if (!valid_device_node_path(resolved)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device node path '%s', ignoring.", resolved);
                        return 0;
                }
        }

        if (!isempty(p) && !in_charset(p, "rwm")) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid device rights '%s', ignoring.", p);
                return 0;
        }

        return cgroup_add_device_allow(c, resolved, p);
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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupIODeviceWeight *w;
        CGroupContext *c = data;
        const char *p = rvalue;
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                while (c->io_device_weights)
                        cgroup_context_free_io_device_weight(c, c->io_device_weights);

                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device path and weight from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = cg_weight_parse(p, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "IO weight '%s' invalid, ignoring: %m", p);
                return 0;
        }

        assert(u != CGROUP_WEIGHT_INVALID);

        w = new0(CGroupIODeviceWeight, 1);
        if (!w)
                return log_oom();

        w->path = TAKE_PTR(resolved);
        w->weight = u;

        LIST_PREPEND(device_weights, c->io_device_weights, w);
        return 0;
}

int config_parse_io_device_latency(
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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupIODeviceLatency *l;
        CGroupContext *c = data;
        const char *p = rvalue;
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                while (c->io_device_latencies)
                        cgroup_context_free_io_device_latency(c, c->io_device_latencies);

                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device path and latency from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        if (parse_sec(p, &usec) < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse timer value, ignoring: %s", p);
                return 0;
        }

        l = new0(CGroupIODeviceLatency, 1);
        if (!l)
                return log_oom();

        l->path = TAKE_PTR(resolved);
        l->target_usec = usec;

        LIST_PREPEND(device_latencies, c->io_device_latencies, l);
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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupIODeviceLimit *l = NULL, *t;
        CGroupContext *c = data;
        CGroupIOLimitType type;
        const char *p = rvalue;
        uint64_t num;
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

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device node and bandwidth from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        if (streq("infinity", p))
                num = CGROUP_LIMIT_MAX;
        else {
                r = parse_size(p, 1000, &num);
                if (r < 0 || num <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid IO limit '%s', ignoring.", p);
                        return 0;
                }
        }

        LIST_FOREACH(device_limits, t, c->io_device_limits) {
                if (path_equal(resolved, t->path)) {
                        l = t;
                        break;
                }
        }

        if (!l) {
                CGroupIOLimitType ttype;

                l = new0(CGroupIODeviceLimit, 1);
                if (!l)
                        return log_oom();

                l->path = TAKE_PTR(resolved);
                for (ttype = 0; ttype < _CGROUP_IO_LIMIT_TYPE_MAX; ttype++)
                        l->limits[ttype] = cgroup_io_limit_defaults[ttype];

                LIST_PREPEND(device_limits, c->io_device_limits, l);
        }

        l->limits[type] = num;

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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupBlockIODeviceWeight *w;
        CGroupContext *c = data;
        const char *p = rvalue;
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                while (c->blockio_device_weights)
                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);

                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device node and weight from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = cg_blkio_weight_parse(p, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid block IO weight '%s', ignoring: %m", p);
                return 0;
        }

        assert(u != CGROUP_BLKIO_WEIGHT_INVALID);

        w = new0(CGroupBlockIODeviceWeight, 1);
        if (!w)
                return log_oom();

        w->path = TAKE_PTR(resolved);
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

        _cleanup_free_ char *path = NULL, *resolved = NULL;
        CGroupBlockIODeviceBandwidth *b = NULL, *t;
        CGroupContext *c = data;
        const char *p = rvalue;
        uint64_t bytes;
        bool read;
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

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract device node and bandwidth from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_full_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = parse_size(p, 1000, &bytes);
        if (r < 0 || bytes <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid Block IO Bandwidth '%s', ignoring.", p);
                return 0;
        }

        LIST_FOREACH(device_bandwidths, t, c->blockio_device_bandwidths) {
                if (path_equal(resolved, t->path)) {
                        b = t;
                        break;
                }
        }

        if (!t) {
                b = new0(CGroupBlockIODeviceBandwidth, 1);
                if (!b)
                        return log_oom();

                b->path = TAKE_PTR(resolved);
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

        log_notice("%s is deprecated. Please use OnFailureJobMode= instead", lvalue);

        *m = r ? JOB_ISOLATE : JOB_REPLACE;
        return 0;
}

int config_parse_exec_directories(
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

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers in \"%s\", ignoring: %m", word);
                        continue;
                }

                r = path_simplify_and_warn(k, PATH_CHECK_RELATIVE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                if (path_startswith(k, "private")) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "%s= path can't be 'private', ignoring assignment: %s", lvalue, word);
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
                Bitmap *bitmap;

                temp = strndup(word, l);
                if (!temp)
                        return log_oom();

                /* We need to call exit_status_from_string() first, because we want
                 * to parse numbers as exit statuses, not signals. */

                r = exit_status_from_string(temp);
                if (r >= 0) {
                        assert(r >= 0 && r < 256);
                        bitmap = &status_set->status;
                } else {
                        r = signal_from_string(temp);

                        if (r <= 0) {
                                log_syntax(unit, LOG_ERR, filename, line, 0,
                                           "Failed to parse value, ignoring: %s", word);
                                continue;
                        }
                        bitmap = &status_set->signal;
                }

                r = bitmap_set(bitmap, r);
                if (r < 0)
                        return log_error_errno(r, "Failed to set signal or status %s: %m", word);
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
        const char *p = rvalue;
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

        for (;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL, *joined = NULL;
                const char *w;
                bool ignore_enoent = false, shall_prefix = false;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", w);
                        continue;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

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

int config_parse_temporary_filesystems(
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
        ExecContext *c = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                temporary_filesystem_free_many(c->temporary_filesystems, c->n_temporary_filesystems);
                c->temporary_filesystems = NULL;
                c->n_temporary_filesystems = 0;
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL, *path = NULL, *resolved = NULL;
                const char *w;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
                }

                w = word;
                r = extract_first_word(&w, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract first word, ignoring: %s", word);
                        continue;
                }
                if (r == 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid syntax, ignoring: %s", word);
                        continue;
                }

                r = unit_full_printf(u, path, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", path);
                        continue;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                r = temporary_filesystem_add(&c->temporary_filesystems, &c->n_temporary_filesystems, resolved, w);
                if (r < 0)
                        return log_oom();
        }
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

                r = extract_first_word(&p, &source, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                        return 0;
                }

                r = unit_full_printf(u, source, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to resolved unit specifiers in \"%s\", ignoring: %m", source);
                        continue;
                }

                s = sresolved;
                if (s[0] == '-') {
                        ignore_enoent = true;
                        s++;
                }

                r = path_simplify_and_warn(s, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                /* Optionally, the destination is specified. */
                if (p && p[-1] == ':') {
                        r = extract_first_word(&p, &destination, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                                return 0;
                        }
                        if (r == 0) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Missing argument after ':', ignoring: %s", s);
                                continue;
                        }

                        r = unit_full_printf(u, destination, &dresolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "Failed to resolved specifiers in \"%s\", ignoring: %m", destination);
                                continue;
                        }

                        r = path_simplify_and_warn(dresolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                        if (r < 0)
                                continue;

                        d = dresolved;

                        /* Optionally, there's also a short option string specified */
                        if (p && p[-1] == ':') {
                                _cleanup_free_ char *options = NULL;

                                r = extract_first_word(&p, &options, NULL, EXTRACT_UNQUOTE);
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
                                        continue;
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

int config_parse_job_timeout_sec(
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

        Unit *u = data;
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse JobTimeoutSec= parameter, ignoring: %s", rvalue);
                return 0;
        }

        /* If the user explicitly changed JobTimeoutSec= also change JobRunningTimeoutSec=, for compatibility with old
         * versions. If JobRunningTimeoutSec= was explicitly set, avoid this however as whatever the user picked should
         * count. */

        if (!u->job_running_timeout_set)
                u->job_running_timeout = usec;

        u->job_timeout = usec;

        return 0;
}

int config_parse_job_running_timeout_sec(
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

        Unit *u = data;
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse JobRunningTimeoutSec= parameter, ignoring: %s", rvalue);
                return 0;
        }

        u->job_running_timeout = usec;
        u->job_running_timeout_set = true;

        return 0;
}

int config_parse_emergency_action(
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

        Manager *m = NULL;
        EmergencyAction *x = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (unit)
                m = ((Unit*) userdata)->manager;
        else
                m = data;

        r = parse_emergency_action(rvalue, MANAGER_IS_SYSTEM(m), x);
        if (r < 0) {
                if (r == -EOPNOTSUPP && MANAGER_IS_USER(m)) {
                        /* Compat mode: remove for systemd 241. */

                        log_syntax(unit, LOG_INFO, filename, line, r,
                                   "%s= in user mode specified as \"%s\", using \"exit-force\" instead.",
                                   lvalue, rvalue);
                        *x = EMERGENCY_ACTION_EXIT_FORCE;
                        return 0;
                }

                if (r == -EOPNOTSUPP)
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "%s= specified as %s mode action, ignoring: %s",
                                   lvalue, MANAGER_IS_SYSTEM(m) ? "user" : "system", rvalue);
                else
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_pid_file(
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

        _cleanup_free_ char *k = NULL, *n = NULL;
        Unit *u = userdata;
        char **s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        if (isempty(rvalue)) {
                /* An empty assignment removes already set value. */
                *s = mfree(*s);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        /* If this is a relative path make it absolute by prefixing the /run */
        n = path_make_absolute(k, u->manager->prefix[EXEC_DIRECTORY_RUNTIME]);
        if (!n)
                return log_oom();

        /* Check that the result is a sensible path */
        r = path_simplify_and_warn(n, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return r;

        r = patch_var_run(unit, filename, line, lvalue, &n);
        if (r < 0)
                return r;

        free_and_replace(*s, n);
        return 0;
}

int config_parse_exit_status(
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

        int *exit_status = data, r;
        uint8_t u;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(exit_status);

        if (isempty(rvalue)) {
                *exit_status = -1;
                return 0;
        }

        r = safe_atou8(rvalue, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse exit status '%s', ignoring: %m", rvalue);
                return 0;
        }

        *exit_status = u;
        return 0;
}

int config_parse_disable_controllers(
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

        int r;
        CGroupContext *c = data;
        CGroupMask disabled_mask;

        /* 1. If empty, make all controllers eligible for use again.
         * 2. If non-empty, merge all listed controllers, space separated. */

        if (isempty(rvalue)) {
                c->disable_controllers = 0;
                return 0;
        }

        r = cg_mask_from_string(rvalue, &disabled_mask);
        if (r < 0 || disabled_mask <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid cgroup string: %s, ignoring", rvalue);
                return 0;
        }

        c->disable_controllers |= disabled_mask;

        return 0;
}

int config_parse_ip_filter_bpf_progs(
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

        _cleanup_free_ char *resolved = NULL;
        Unit *u = userdata;
        char ***paths = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(paths);

        if (isempty(rvalue)) {
                *paths = strv_free(*paths);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        if (strv_contains(*paths, resolved))
                return 0;

        r = strv_extend(paths, resolved);
        if (r < 0)
                return log_oom();

        r = bpf_firewall_supported();
        if (r < 0)
                return r;
        if (r != BPF_FIREWALL_SUPPORTED_WITH_MULTI) {
                static bool warned = false;

                log_full(warned ? LOG_DEBUG : LOG_WARNING,
                         "File %s:%u configures an IP firewall with BPF programs (%s=%s), but the local system does not support BPF/cgroup based firewalling with multiple filters.\n"
                         "Starting this unit will fail! (This warning is only shown for the first loaded unit using IP firewalling.)", filename, line, lvalue, rvalue);

                warned = true;
        }

        return 0;
}

static int merge_by_names(Unit **u, Set *names, const char *id) {
        char *k;
        int r;

        assert(u);
        assert(*u);

        /* Let's try to add in all names that are aliases of this unit */
        while ((k = set_steal_first(names))) {
                _cleanup_free_ _unused_ char *free_k = k;

                /* First try to merge in the other name into our unit */
                r = unit_merge_by_name(*u, k);
                if (r < 0) {
                        Unit *other;

                        /* Hmm, we couldn't merge the other unit into ours? Then let's try it the other way
                         * round. */

                        other = manager_get_unit((*u)->manager, k);
                        if (!other)
                                return r; /* return previous failure */

                        r = unit_merge(other, *u);
                        if (r < 0)
                                return r;

                        *u = other;
                        return merge_by_names(u, names, NULL);
                }

                if (streq_ptr(id, k))
                        unit_choose_id(*u, id);
        }

        return 0;
}

int unit_load_fragment(Unit *u) {
        const char *fragment;
        _cleanup_set_free_free_ Set *names = NULL;
        struct stat st;
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);
        assert(u->id);

        if (u->transient) {
                u->load_state = UNIT_LOADED;
                return 0;
        }

        /* Possibly rebuild the fragment map to catch new units */
        r = unit_file_build_name_map(&u->manager->lookup_paths,
                                     &u->manager->unit_cache_mtime,
                                     &u->manager->unit_id_map,
                                     &u->manager->unit_name_map,
                                     &u->manager->unit_path_cache);
        if (r < 0)
                log_error_errno(r, "Failed to rebuild name map: %m");

        r = unit_file_find_fragment(u->manager->unit_id_map,
                                    u->manager->unit_name_map,
                                    u->id,
                                    &fragment,
                                    &names);
        if (r < 0 && r != -ENOENT)
                return r;

        if (fragment) {
                /* Open the file, check if this is a mask, otherwise read. */
                _cleanup_fclose_ FILE *f = NULL;

                /* Try to open the file name. A symlink is OK, for example for linked files or masks. We
                 * expect that all symlinks within the lookup paths have been already resolved, but we don't
                 * verify this here. */
                f = fopen(fragment, "re");
                if (!f)
                        return log_unit_notice_errno(u, errno, "Failed to open %s: %m", fragment);

                if (fstat(fileno(f), &st) < 0)
                        return -errno;

                r = free_and_strdup(&u->fragment_path, fragment);
                if (r < 0)
                        return r;

                if (null_or_empty(&st)) {
                        u->load_state = UNIT_MASKED;
                        u->fragment_mtime = 0;
                } else {
                        u->load_state = UNIT_LOADED;
                        u->fragment_mtime = timespec_load(&st.st_mtim);

                        /* Now, parse the file contents */
                        r = config_parse(u->id, fragment, f,
                                         UNIT_VTABLE(u)->sections,
                                         config_item_perf_lookup, load_fragment_gperf_lookup,
                                         CONFIG_PARSE_ALLOW_INCLUDE, u);
                        if (r == -ENOEXEC)
                                log_unit_notice_errno(u, r, "Unit configuration has fatal error, unit will not be started.");
                        if (r < 0)
                                return r;
                }
        }

        if (u->source_path) {
                if (stat(u->source_path, &st) >= 0)
                        u->source_mtime = timespec_load(&st.st_mtim);
                else
                        u->source_mtime = 0;
        }

        /* We do the merge dance here because for some unit types, the unit might have aliases which are not
         * declared in the file system. In particular, this is true (and frequent) for device and swap units.
         */
        Unit *merged;
        const char *id = u->id;
        _cleanup_free_ char *free_id = NULL;

        if (fragment) {
                id = basename(fragment);
                if (unit_name_is_valid(id, UNIT_NAME_TEMPLATE)) {
                        assert(u->instance); /* If we're not trying to use a template for non-instanced unit,
                                              * this must be set. */

                        r = unit_name_replace_instance(id, u->instance, &free_id);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to build id (%s + %s): %m", id, u->instance);
                        id = free_id;
                }
        }

        merged = u;
        r = merge_by_names(&merged, names, id);
        if (r < 0)
                return r;

        if (merged != u)
                u->load_state = UNIT_MERGED;

        return 0;
}

void unit_dump_config_items(FILE *f) {
        static const struct {
                const ConfigParserCallback callback;
                const char *rvalue;
        } table[] = {
                { config_parse_warn_compat,           "NOTSUPPORTED" },
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
                { config_parse_rlimit,                "LIMIT" },
                { config_parse_unit_deps,             "UNIT [...]" },
                { config_parse_exec,                  "PATH [ARGUMENT [...]]" },
                { config_parse_service_type,          "SERVICETYPE" },
                { config_parse_service_restart,       "SERVICERESTART" },
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
#if HAVE_SECCOMP
                { config_parse_syscall_filter,        "SYSCALLS" },
                { config_parse_syscall_archs,         "ARCHS" },
                { config_parse_syscall_errno,         "ERRNO" },
                { config_parse_address_families,      "FAMILIES" },
                { config_parse_restrict_namespaces,   "NAMESPACES"  },
#endif
                { config_parse_cpu_shares,            "SHARES" },
                { config_parse_cg_weight,             "WEIGHT" },
                { config_parse_memory_limit,          "LIMIT" },
                { config_parse_device_allow,          "DEVICE" },
                { config_parse_device_policy,         "POLICY" },
                { config_parse_io_limit,              "LIMIT" },
                { config_parse_io_device_weight,      "DEVICEWEIGHT" },
                { config_parse_io_device_latency,     "DEVICELATENCY" },
                { config_parse_blockio_bandwidth,     "BANDWIDTH" },
                { config_parse_blockio_weight,        "WEIGHT" },
                { config_parse_blockio_device_weight, "DEVICEWEIGHT" },
                { config_parse_long,                  "LONG" },
                { config_parse_socket_service,        "SERVICE" },
#if HAVE_SELINUX
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
                const ConfigPerfItem *p;
                size_t prefix_len;
                const char *dot;
                unsigned j;

                assert_se(p = load_fragment_gperf_lookup(i, strlen(i)));

                /* Hide legacy settings */
                if (p->parse == config_parse_warn_compat &&
                    p->ltype == DISABLED_LEGACY)
                        continue;

                for (j = 0; j < ELEMENTSOF(table); j++)
                        if (p->parse == table[j].callback) {
                                rvalue = table[j].rvalue;
                                break;
                        }

                dot = strchr(i, '.');
                lvalue = dot ? dot + 1 : i;
                prefix_len = dot-i;

                if (dot)
                        if (!prev || !strneq(prev, i, prefix_len+1)) {
                                if (prev)
                                        fputc('\n', f);

                                fprintf(f, "[%.*s]\n", (int) prefix_len, i);
                        }

                fprintf(f, "%s=%s\n", lvalue, rvalue);
                prev = i;
        }
}

int config_parse_cpu_affinity2(
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

        CPUSet *affinity = data;

        assert(affinity);

        (void) parse_cpu_set_extend(rvalue, affinity, true, unit, filename, line, lvalue);

        return 0;
}

int config_parse_show_status(
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

        int k;
        ShowStatus *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_show_status(rvalue, b);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, k, "Failed to parse show status setting, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_output_restricted(
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

        ExecOutput t, *eo = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        t = exec_output_from_string(rvalue);
        if (t < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse output type, ignoring: %s", rvalue);
                return 0;
        }

        if (IN_SET(t, EXEC_OUTPUT_SOCKET, EXEC_OUTPUT_NAMED_FD, EXEC_OUTPUT_FILE, EXEC_OUTPUT_FILE_APPEND)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Standard output types socket, fd:, file:, append: are not supported as defaults, ignoring: %s", rvalue);
                return 0;
        }

        *eo = t;
        return 0;
}

int config_parse_crash_chvt(
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

        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_crash_chvt(rvalue, data);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CrashChangeVT= setting, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_timeout_abort(
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

        usec_t *timeout_usec = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(timeout_usec);

        rvalue += strspn(rvalue, WHITESPACE);
        if (isempty(rvalue)) {
                *timeout_usec = false;
                return 0;
        }

        r = parse_sec(rvalue, timeout_usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse DefaultTimeoutAbortSec= setting, ignoring: %s", rvalue);
                return 0;
        }

        *timeout_usec = true;
        return 0;
}
