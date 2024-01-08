/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2012 Holger Hans Peter Freyther
***/

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/oom.h>
#include <sched.h>
#include <sys/resource.h>

#include "sd-messages.h"

#include "af-list.h"
#include "all-units.h"
#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bpf-lsm.h"
#include "bpf-program.h"
#include "bpf-socket-bind.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "conf-parser.h"
#include "core-varlink.h"
#include "cpu-set-util.h"
#include "creds-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "escape.h"
#include "exec-credential.h"
#include "execute.h"
#include "fd-util.h"
#include "fileio.h"
#include "firewall-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "ioprio-util.h"
#include "ip-protocol-list.h"
#include "journal-file.h"
#include "limits-util.h"
#include "load-fragment.h"
#include "log.h"
#include "missing_ioprio.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "open-file.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "pcre2-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-netlink.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "user-util.h"
#include "utf8.h"
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
DEFINE_CONFIG_PARSE_ENUM(config_parse_protect_proc, protect_proc, ProtectProc, "Failed to parse /proc/ protection mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_proc_subset, proc_subset, ProcSubset, "Failed to parse /proc/ subset mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_exec_utmp_mode, exec_utmp_mode, ExecUtmpMode, "Failed to parse utmp mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_job_mode, job_mode, JobMode, "Failed to parse job mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_notify_access, notify_access, NotifyAccess, "Failed to parse notify access specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_protect_home, protect_home, ProtectHome, "Failed to parse protect home value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_protect_system, protect_system, ProtectSystem, "Failed to parse protect system value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_exec_preserve_mode, exec_preserve_mode, ExecPreserveMode, "Failed to parse resource preserve mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_type, service_type, ServiceType, "Failed to parse service type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_exit_type, service_exit_type, ServiceExitType, "Failed to parse service exit type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart, service_restart, ServiceRestart, "Failed to parse service restart specifier");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_restart_mode, service_restart_mode, ServiceRestartMode, "Failed to parse service restart mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_service_timeout_failure_mode, service_timeout_failure_mode, ServiceTimeoutFailureMode, "Failed to parse timeout failure mode");
DEFINE_CONFIG_PARSE_ENUM(config_parse_socket_bind, socket_address_bind_ipv6_only_or_bool, SocketAddressBindIPv6Only, "Failed to parse bind IPv6 only value");
DEFINE_CONFIG_PARSE_ENUM(config_parse_oom_policy, oom_policy, OOMPolicy, "Failed to parse OOM policy");
DEFINE_CONFIG_PARSE_ENUM(config_parse_managed_oom_preference, managed_oom_preference, ManagedOOMPreference, "Failed to parse ManagedOOMPreference=");
DEFINE_CONFIG_PARSE_ENUM(config_parse_memory_pressure_watch, cgroup_pressure_watch, CGroupPressureWatch, "Failed to parse memory pressure watch setting");
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ip_tos, ip_tos, int, -1, "Failed to parse IP TOS value");
DEFINE_CONFIG_PARSE_PTR(config_parse_blockio_weight, cg_blkio_weight_parse, uint64_t, "Invalid block IO weight");
DEFINE_CONFIG_PARSE_PTR(config_parse_cg_weight, cg_weight_parse, uint64_t, "Invalid weight");
DEFINE_CONFIG_PARSE_PTR(config_parse_cg_cpu_weight, cg_cpu_weight_parse, uint64_t, "Invalid CPU weight");
static DEFINE_CONFIG_PARSE_PTR(config_parse_cpu_shares_internal, cg_cpu_shares_parse, uint64_t, "Invalid CPU shares");
DEFINE_CONFIG_PARSE_PTR(config_parse_exec_mount_propagation_flag, mount_propagation_flag_from_string, unsigned long, "Failed to parse mount propagation flag");
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_numa_policy, mpol, int, -1, "Invalid NUMA policy type");
DEFINE_CONFIG_PARSE_ENUM(config_parse_status_unit_format, status_unit_format, StatusUnitFormat, "Failed to parse status unit format");
DEFINE_CONFIG_PARSE_ENUM_FULL(config_parse_socket_timestamping, socket_timestamping_from_string_harder, SocketTimestamping, "Failed to parse timestamping precision");

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

        assert(filename);
        assert(lvalue);
        assert(rvalue);


        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "Unit uses %s=; please use CPUWeight= instead. Support for %s= will be removed soon.",
                   lvalue, lvalue);

        return config_parse_cpu_shares_internal(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
}

bool contains_instance_specifier_superset(const char *s) {
        const char *p, *q;
        bool percent = false;

        assert(s);

        p = strchr(s, '@');
        if (!p)
                return false;

        p++; /* Skip '@' */

        q = strrchr(p, '.');
        if (!q)
                q = p + strlen(p);

        /* If the string is just the instance specifier, it's not a superset of the instance. */
        if (memcmp_nn(p, q - p, "%i", strlen("%i")) == 0)
                return false;

        /* %i, %n and %N all expand to the instance or a superset of it. */
        for (; p < q; p++)
                if (*p == '%')
                        percent = !percent;
                else if (percent) {
                        if (IN_SET(*p, 'n', 'N', 'i'))
                                return true;
                        percent = false;
                }

        return false;
}

/* `name` is the rendered version of `format` via `unit_printf` or similar functions. */
int unit_is_likely_recursive_template_dependency(Unit *u, const char *name, const char *format) {
        const char *fragment_path;
        int r;

        assert(u);
        assert(name);

        /* If a template unit has a direct dependency on itself that includes the unit instance as part of
         * the template instance via a unit specifier (%i, %n or %N), this will almost certainly lead to
         * infinite recursion as systemd will keep instantiating new instances of the template unit.
         * https://github.com/systemd/systemd/issues/17602 shows a good example of how this can happen in
         * practice. To guard against this, we check for templates that depend on themselves and have the
         * instantiated unit instance included as part of the template instance of the dependency via a
         * specifier.
         *
         * For example, if systemd-notify@.service depends on systemd-notify@%n.service, this will result in
         * infinite recursion.
         */

        if (!unit_name_is_valid(name, UNIT_NAME_INSTANCE))
                return false;

        if (!unit_name_prefix_equal(u->id, name))
                return false;

        if (u->type != unit_name_to_type(name))
                return false;

        r = unit_file_find_fragment(u->manager->unit_id_map, u->manager->unit_name_map, name, &fragment_path, NULL);
        if (r < 0)
                return r;

        /* Fragment paths should also be equal as a custom fragment for a specific template instance
         * wouldn't necessarily lead to infinite recursion. */
        if (!path_equal_ptr(u->fragment_path, fragment_path))
                return false;

        if (!contains_instance_specifier_superset(format))
                return false;

        return true;
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;
                int r;

                r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = unit_name_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                r = unit_is_likely_recursive_template_dependency(u, k, word);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to determine if '%s' is a recursive dependency, ignoring: %m", k);
                        continue;
                }
                if (r > 0) {
                        log_syntax(unit, LOG_DEBUG, filename, line, 0,
                                   "Dropping dependency %s=%s that likely leads to infinite recursion.",
                                   unit_dependency_to_string(d), word);
                        continue;
                }

                r = unit_add_dependency_by_name(u, d, k, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);
        }
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
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

        const Unit *u = ASSERT_PTR(userdata);
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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
        const Unit *u = ASSERT_PTR(userdata);
        int r;
        bool fatal = ltype;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_path_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, fatal ? LOG_ERR : LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s'%s: %m",
                           rvalue, fatal ? "" : ", ignoring");
                return fatal ? -ENOEXEC : 0;
        }

        return config_parse_path(unit, filename, line, section, section_line, lvalue, ltype, k, data, userdata);
}

int config_parse_colon_separated_paths(
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
        char ***sv = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *sv = strv_free(*sv);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = unit_path_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        return 0;
                }

                r = path_simplify_and_warn(k, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }

        return 0;
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
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *x = strv_free(*x);
                return 0;
        }

        for (const char *p = rvalue;;) {
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

                r = unit_path_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
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

                r = unit_path_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

                r = unit_path_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                        return 0;
                }

                r = socket_address_parse_netlink(&p->address, k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse address value in '%s', ignoring: %m", k);
                        return 0;
                }

                p->type = SOCKET_SOCKET;

        } else {
                _cleanup_free_ char *k = NULL;

                r = unit_path_printf(UNIT(s), rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse address value in '%s', ignoring: %m", k);
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

                if (socket_address_family(&p->address) != AF_UNIX && p->address.type == SOCK_SEQPACKET) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Address family not supported, ignoring: %s", rvalue);
                        return 0;
                }

                p->type = SOCKET_SOCKET;
        }

        p->fd = -EBADF;
        p->auxiliary_fds = NULL;
        p->n_auxiliary_fds = 0;
        p->socket = s;

        tail = LIST_FIND_TAIL(port, s->ports);
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

        ExecContext *c = ASSERT_PTR(data);
        int priority, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->nice_set = false;
                return 0;
        }

        r = parse_nice(rvalue, &priority);
        if (r < 0) {
                if (r == -ERANGE)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Nice priority out of range, ignoring: %s", rvalue);
                else
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse nice priority '%s', ignoring: %m", rvalue);
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

        ExecContext *c = ASSERT_PTR(data);
        int oa, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->oom_score_adjust_set = false;
                return 0;
        }

        r = parse_oom_score_adjust(rvalue, &oa);
        if (r < 0) {
                if (r == -ERANGE)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "OOM score adjust value out of range, ignoring: %s", rvalue);
                else
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse the OOM score adjust value '%s', ignoring: %m", rvalue);
                return 0;
        }

        c->oom_score_adjust = oa;
        c->oom_score_adjust_set = true;

        return 0;
}

int config_parse_exec_coredump_filter(
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

        ExecContext *c = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->coredump_filter = 0;
                c->coredump_filter_set = false;
                return 0;
        }

        uint64_t f;
        r = coredump_filter_mask_from_string(rvalue, &f);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse the CoredumpFilter=%s, ignoring: %m", rvalue);
                return 0;
        }

        c->coredump_filter |= f;
        c->coredump_filter_set = true;
        return 0;
}

int config_parse_kill_mode(
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

        KillMode *k = data, m;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *k = KILL_CONTROL_GROUP;
                return 0;
        }

        m = kill_mode_from_string(rvalue);
        if (m < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, m,
                           "Failed to parse kill mode specification, ignoring: %s", rvalue);
                return 0;
        }

        if (m == KILL_NONE)
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unit uses KillMode=none. "
                           "This is unsafe, as it disables systemd's process lifecycle management for the service. "
                           "Please update the service to use a safer KillMode=, such as 'mixed' or 'control-group'. "
                           "Support for KillMode=none is deprecated and will eventually be removed.");

        *k = m;
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

        ExecCommand **e = ASSERT_PTR(data);
        const Unit *u = userdata;
        const char *p;
        bool semicolon;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        e += ltype;

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
                size_t nlen = 0;
                const char *f;

                semicolon = false;

                r = extract_first_word_and_warn(&p, &firstword, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, unit, filename, line, rvalue);
                if (r <= 0)
                        return 0;

                /* A lone ";" is a separator. Let's make sure we don't treat it as an executable name. */
                if (streq(firstword, ";")) {
                        semicolon = true;
                        continue;
                }

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

                r = unit_path_printf(u, f, &path);
                if (r < 0) {
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, r,
                                   "Failed to resolve unit specifiers in '%s'%s: %m",
                                   f, ignore ? ", ignoring" : "");
                        return ignore ? 0 : -ENOEXEC;
                }

                if (isempty(path)) {
                        /* First word is either "-" or "@" with no command. */
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, 0,
                                   "Empty path in command line%s: '%s'",
                                   ignore ? ", ignoring" : "", rvalue);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (!string_is_safe(path)) {
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, 0,
                                   "Executable name contains special characters%s: %s",
                                   ignore ? ", ignoring" : "", path);
                        return ignore ? 0 : -ENOEXEC;
                }
                if (endswith(path, "/")) {
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, 0,
                                   "Executable path specifies a directory%s: %s",
                                   ignore ? ", ignoring" : "", path);
                        return ignore ? 0 : -ENOEXEC;
                }

                if (!(path_is_absolute(path) ? path_is_valid(path) : filename_is_valid(path))) {
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, 0,
                                   "Neither a valid executable name nor an absolute path%s: %s",
                                   ignore ? ", ignoring" : "", path);
                        return ignore ? 0 : -ENOEXEC;
                }

                if (!separate_argv0) {
                        char *w = NULL;

                        if (!GREEDY_REALLOC0(n, nlen + 2))
                                return log_oom();

                        w = strdup(path);
                        if (!w)
                                return log_oom();
                        n[nlen++] = w;
                        n[nlen] = NULL;
                }

                path_simplify(path);

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

                                if (!GREEDY_REALLOC0(n, nlen + 2))
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
                                log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, r,
                                           "Failed to resolve unit specifiers in %s%s: %m",
                                           word, ignore ? ", ignoring" : "");
                                return ignore ? 0 : -ENOEXEC;
                        }

                        if (!GREEDY_REALLOC(n, nlen + 2))
                                return log_oom();

                        n[nlen++] = TAKE_PTR(resolved);
                        n[nlen] = NULL;
                }

                if (!n || !n[0]) {
                        log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, 0,
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

        Socket *s = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue) || streq(rvalue, "*")) {
                s->bind_to_device = mfree(s->bind_to_device);
                return 0;
        }

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid interface name, ignoring: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(&s->bind_to_device, rvalue);
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        const char *n;
        ExecInput ei;
        int r;

        assert(filename);
        assert(line);
        assert(rvalue);

        n = startswith(rvalue, "fd:");
        if (n) {
                _cleanup_free_ char *resolved = NULL;

                r = unit_fd_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", n);
                        return 0;
                }

                if (isempty(resolved))
                        resolved = mfree(resolved);
                else if (!fdname_is_valid(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid file descriptor name, ignoring: %s", resolved);
                        return 0;
                }

                free_and_replace(c->stdio_fdname[STDIN_FILENO], resolved);

                ei = EXEC_INPUT_NAMED_FD;

        } else if ((n = startswith(rvalue, "file:"))) {
                _cleanup_free_ char *resolved = NULL;

                r = unit_path_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", n);
                        return 0;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                free_and_replace(c->stdio_file[STDIN_FILENO], resolved);

                ei = EXEC_INPUT_FILE;

        } else {
                ei = exec_input_from_string(rvalue);
                if (ei < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, ei, "Failed to parse input specifier, ignoring: %s", rvalue);
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
        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->stdin_data = mfree(c->stdin_data);
                c->stdin_data_size = 0;
                return 0;
        }

        ssize_t l = cunescape(rvalue, 0, &unescaped);
        if (l < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, l,
                           "Failed to decode C escaped text '%s', ignoring: %m", rvalue);
                return 0;
        }

        r = unit_full_printf_full(u, unescaped, EXEC_STDIN_DATA_MAX, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", unescaped);
                return 0;
        }

        size_t sz = strlen(resolved);
        if (c->stdin_data_size + sz + 1 < c->stdin_data_size || /* check for overflow */
            c->stdin_data_size + sz + 1 > EXEC_STDIN_DATA_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Standard input data too large (%zu), maximum of %zu permitted, ignoring.",
                           c->stdin_data_size + sz, (size_t) EXEC_STDIN_DATA_MAX);
                return 0;
        }

        void *p = realloc(c->stdin_data, c->stdin_data_size + sz + 1);
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
        ExecContext *c = ASSERT_PTR(data);
        size_t sz;
        void *q;
        int r;

        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->stdin_data = mfree(c->stdin_data);
                c->stdin_data_size = 0;
                return 0;
        }

        r = unbase64mem(rvalue, &p, &sz);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to decode base64 data, ignoring: %s", rvalue);
                return 0;
        }

        assert(sz > 0);

        if (c->stdin_data_size + sz < c->stdin_data_size || /* check for overflow */
            c->stdin_data_size + sz > EXEC_STDIN_DATA_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Standard input data too large (%zu), maximum of %zu permitted, ignoring.",
                           c->stdin_data_size + sz, (size_t) EXEC_STDIN_DATA_MAX);
                return 0;
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
        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        bool obsolete = false;
        ExecOutput eo;
        int r;

        assert(filename);
        assert(line);
        assert(lvalue);
        assert(rvalue);

        n = startswith(rvalue, "fd:");
        if (n) {
                r = unit_fd_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s: %m", n);
                        return 0;
                }

                if (isempty(resolved))
                        resolved = mfree(resolved);
                else if (!fdname_is_valid(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid file descriptor name, ignoring: %s", resolved);
                        return 0;
                }

                eo = EXEC_OUTPUT_NAMED_FD;

        } else if (streq(rvalue, "syslog")) {
                eo = EXEC_OUTPUT_JOURNAL;
                obsolete = true;

        } else if (streq(rvalue, "syslog+console")) {
                eo = EXEC_OUTPUT_JOURNAL_AND_CONSOLE;
                obsolete = true;

        } else if ((n = startswith(rvalue, "file:"))) {

                r = unit_path_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", n);
                        return 0;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                eo = EXEC_OUTPUT_FILE;

        } else if ((n = startswith(rvalue, "append:"))) {

                r = unit_path_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", n);
                        return 0;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                eo = EXEC_OUTPUT_FILE_APPEND;

        } else if ((n = startswith(rvalue, "truncate:"))) {

                r = unit_path_printf(u, n, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", n);
                        return 0;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE | PATH_CHECK_FATAL, unit, filename, line, lvalue);
                if (r < 0)
                        return 0;

                eo = EXEC_OUTPUT_FILE_TRUNCATE;
        } else {
                eo = exec_output_from_string(rvalue);
                if (eo < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, eo, "Failed to parse output specifier, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (obsolete)
                log_syntax(unit, LOG_NOTICE, filename, line, 0,
                           "Standard output type %s is obsolete, automatically updating to %s. Please update your unit file, and consider removing the setting altogether.",
                           rvalue, exec_output_to_string(eo));

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

        ExecContext *c = ASSERT_PTR(data);
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->ioprio_set = false;
                c->ioprio = IOPRIO_DEFAULT_CLASS_AND_PRIO;
                return 0;
        }

        x = ioprio_class_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, x, "Failed to parse IO scheduling class, ignoring: %s", rvalue);
                return 0;
        }

        c->ioprio = ioprio_normalize(ioprio_prio_value(x, ioprio_prio_data(c->ioprio)));
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

        ExecContext *c = ASSERT_PTR(data);
        int i, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->ioprio_set = false;
                c->ioprio = IOPRIO_DEFAULT_CLASS_AND_PRIO;
                return 0;
        }

        r = ioprio_parse_priority(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse IO priority, ignoring: %s", rvalue);
                return 0;
        }

        c->ioprio = ioprio_normalize(ioprio_prio_value(ioprio_prio_class(c->ioprio), i));
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

        ExecContext *c = ASSERT_PTR(data);
        int x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->cpu_sched_set = false;
                c->cpu_sched_policy = SCHED_OTHER;
                c->cpu_sched_priority = 0;
                return 0;
        }

        x = sched_policy_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, x, "Failed to parse CPU scheduling policy, ignoring: %s", rvalue);
                return 0;
        }

        c->cpu_sched_policy = x;
        /* Moving to or from real-time policy? We need to adjust the priority */
        c->cpu_sched_priority = CLAMP(c->cpu_sched_priority, sched_get_priority_min(x), sched_get_priority_max(x));
        c->cpu_sched_set = true;

        return 0;
}

int config_parse_exec_mount_apivfs(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata) {

        ExecContext *c = ASSERT_PTR(data);
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->mount_apivfs_set = false;
                c->mount_apivfs = false;
                return 0;
        }

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, k,
                           "Failed to parse boolean value, ignoring: %s",
                           rvalue);
                return 0;
        }

        c->mount_apivfs_set = true;
        c->mount_apivfs = k;
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
        NUMAPolicy *p = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "all")) {
                r = numa_mask_add_all(&p->nodes);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to create NUMA mask representing \"all\" NUMA nodes, ignoring: %m");
        } else {
                r = parse_cpu_set_extend(rvalue, &p->nodes, true, unit, filename, line, lvalue);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse NUMA node mask, ignoring: %s", rvalue);
        }

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

        ExecContext *c = ASSERT_PTR(data);
        int i, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = safe_atoi(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse CPU scheduling priority, ignoring: %s", rvalue);
                return 0;
        }

        /* On Linux RR/FIFO range from 1 to 99 and OTHER/BATCH may only be 0. Policy might be set later so
         * we do not check the precise range, but only the generic outer bounds. */
        if (i < 0 || i > 99) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "CPU scheduling priority is out of range, ignoring: %s", rvalue);
                return 0;
        }

        c->cpu_sched_priority = i;
        c->cpu_sched_set = true;

        return 0;
}

int config_parse_root_image_options(
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

        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->root_image_options = mount_options_free_all(c->root_image_options);
                return 0;
        }

        r = strv_split_colon_pairs(&l, rvalue);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        STRV_FOREACH_PAIR(first, second, l) {
                MountOptions *o = NULL;
                _cleanup_free_ char *mount_options_resolved = NULL;
                const char *mount_options = NULL, *partition = "root";
                PartitionDesignator partition_designator;

                /* Format is either 'root:foo' or 'foo' (root is implied) */
                if (!isempty(*second)) {
                        partition = *first;
                        mount_options = *second;
                } else
                        mount_options = *first;

                partition_designator = partition_designator_from_string(partition);
                if (partition_designator < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, partition_designator,
                                   "Invalid partition name %s, ignoring", partition);
                        continue;
                }
                r = unit_full_printf(u, mount_options, &mount_options_resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", mount_options);
                        continue;
                }

                o = new(MountOptions, 1);
                if (!o)
                        return log_oom();
                *o = (MountOptions) {
                        .partition_designator = partition_designator,
                        .options = TAKE_PTR(mount_options_resolved),
                };
                LIST_APPEND(mount_options, options, TAKE_PTR(o));
        }

        if (options)
                LIST_JOIN(mount_options, c->root_image_options, options);
        else
                /* empty spaces/separators only */
                c->root_image_options = mount_options_free_all(c->root_image_options);

        return 0;
}

int config_parse_exec_root_hash(
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

        _cleanup_free_ void *roothash_decoded = NULL;
        ExecContext *c = ASSERT_PTR(data);
        size_t roothash_decoded_size = 0;
        int r;

        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->root_hash_path = mfree(c->root_hash_path);
                c->root_hash = mfree(c->root_hash);
                c->root_hash_size = 0;
                return 0;
        }

        if (path_is_absolute(rvalue)) {
                /* We have the path to a roothash to load and decode, eg: RootHash=/foo/bar.roothash */
                _cleanup_free_ char *p = NULL;

                p = strdup(rvalue);
                if (!p)
                        return -ENOMEM;

                free_and_replace(c->root_hash_path, p);
                c->root_hash = mfree(c->root_hash);
                c->root_hash_size = 0;
                return 0;
        }

        /* We have a roothash to decode, eg: RootHash=012345789abcdef */
        r = unhexmem(rvalue, &roothash_decoded, &roothash_decoded_size);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to decode RootHash=, ignoring: %s", rvalue);
                return 0;
        }
        if (roothash_decoded_size < sizeof(sd_id128_t)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "RootHash= is too short, ignoring: %s", rvalue);
                return 0;
        }

        free_and_replace(c->root_hash, roothash_decoded);
        c->root_hash_size = roothash_decoded_size;
        c->root_hash_path = mfree(c->root_hash_path);

        return 0;
}

int config_parse_exec_root_hash_sig(
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

        _cleanup_free_ void *roothash_sig_decoded = NULL;
        char *value;
        ExecContext *c = ASSERT_PTR(data);
        size_t roothash_sig_decoded_size = 0;
        int r;

        assert(filename);
        assert(line);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Reset if the empty string is assigned */
                c->root_hash_sig_path = mfree(c->root_hash_sig_path);
                c->root_hash_sig = mfree(c->root_hash_sig);
                c->root_hash_sig_size = 0;
                return 0;
        }

        if (path_is_absolute(rvalue)) {
                /* We have the path to a roothash signature to load and decode, eg: RootHashSignature=/foo/bar.roothash.p7s */
                _cleanup_free_ char *p = NULL;

                p = strdup(rvalue);
                if (!p)
                        return log_oom();

                free_and_replace(c->root_hash_sig_path, p);
                c->root_hash_sig = mfree(c->root_hash_sig);
                c->root_hash_sig_size = 0;
                return 0;
        }

        if (!(value = startswith(rvalue, "base64:"))) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to decode RootHashSignature=, not a path but doesn't start with 'base64:', ignoring: %s", rvalue);
                return 0;
        }

        /* We have a roothash signature to decode, eg: RootHashSignature=base64:012345789abcdef */
        r = unbase64mem(value, &roothash_sig_decoded, &roothash_sig_decoded_size);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to decode RootHashSignature=, ignoring: %s", rvalue);
                return 0;
        }

        free_and_replace(c->root_hash_sig, roothash_sig_decoded);
        c->root_hash_sig_size = roothash_sig_decoded_size;
        c->root_hash_sig_path = mfree(c->root_hash_sig_path);

        return 0;
}

int config_parse_exec_cpu_affinity(
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "numa")) {
                c->cpu_affinity_from_numa = true;
                cpu_set_reset(&c->cpu_set);

                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m",
                           rvalue);
                return 0;
        }

        r = parse_cpu_set_extend(k, &c->cpu_set, true, unit, filename, line, lvalue);
        if (r >= 0)
                c->cpu_affinity_from_numa = false;

        return 0;
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

        uint64_t *capability_set = ASSERT_PTR(data);
        uint64_t sum = 0, initial, def;
        bool invert = false;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (streq(lvalue, "CapabilityBoundingSet")) {
                initial = CAP_MASK_ALL; /* initialized to all bits on */
                def = CAP_MASK_UNSET;   /* not set */
        } else
                def = initial = 0; /* All bits off */

        r = capability_set_from_string(rvalue, &sum);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s= specifier '%s', ignoring: %m", lvalue, rvalue);
                return 0;
        }

        if (sum == 0 || *capability_set == def)
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
                log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, r,
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
                log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, r,
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        bool ignore;
        char *k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
                log_syntax(unit, ignore ? LOG_WARNING : LOG_ERR, filename, line, r,
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
        const Unit *u = userdata;
        Timer *t = ASSERT_PTR(data);
        usec_t usec = 0;
        TimerValue *v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets list */
                timer_free_values(t);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (ltype == TIMER_CALENDAR) {
                r = calendar_spec_from_string(k, &c);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse calendar specification, ignoring: %s", k);
                        return 0;
                }
        } else {
                r = parse_sec(k, &usec);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse timer value, ignoring: %s", k);
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
        Unit *u = ASSERT_PTR(data);
        UnitType type;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (UNIT_TRIGGER(u)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Multiple units to trigger specified, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_name_printf(u, rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        type = unit_name_to_type(p);
        if (type < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, type, "Unit type not valid, ignoring: %s", rvalue);
                return 0;
        }
        if (unit_has_name(u, p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Units cannot trigger themselves, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_add_two_dependencies_by_name(u, UNIT_BEFORE, UNIT_TRIGGERS, p, true, UNIT_DEPENDENCY_FILE);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to add trigger on %s, ignoring: %m", p);
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

        Path *p = ASSERT_PTR(data);
        PathSpec *s;
        PathType b;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment clears list */
                path_free_specs(p);
                return 0;
        }

        b = path_type_from_string(lvalue);
        if (b < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, b, "Failed to parse path type, ignoring: %s", lvalue);
                return 0;
        }

        r = unit_path_printf(UNIT(p), rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
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
        s->inotify_fd = -EBADF;

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
        Socket *s = ASSERT_PTR(data);
        Unit *x;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_name_printf(UNIT(s), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        if (!endswith(p, ".service")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unit must be of type service, ignoring: %s", rvalue);
                return 0;
        }

        r = manager_load_unit(UNIT(s)->manager, p, NULL, &error, &x);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to load unit %s, ignoring: %s", rvalue, bus_error_message(&error, r));
                return 0;
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
        Socket *s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->fdname = mfree(s->fdname);
                return 0;
        }

        r = unit_fd_printf(UNIT(s), rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (!fdname_is_valid(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid file descriptor name, ignoring: %s", p);
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

        Service *s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Trailing garbage in sockets, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = unit_name_printf(UNIT(s), word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                if (!endswith(k, ".socket")) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Unit must be of type socket, ignoring: %s", k);
                        continue;
                }

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_WANTS, UNIT_AFTER, k, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);

                r = unit_add_dependency_by_name(UNIT(s), UNIT_TRIGGERED_BY, k, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to add dependency on %s, ignoring: %m", k);
        }
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
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_full_printf_full(u, rvalue, SD_BUS_MAXIMUM_NAME_LENGTH, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        if (!sd_bus_service_name_is_valid(k)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid bus name, ignoring: %s", k);
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

        Service *s = ASSERT_PTR(userdata);
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* This is called for two cases: TimeoutSec= and TimeoutStartSec=. */

        /* Traditionally, these options accepted 0 to disable the timeouts. However, a timeout of 0 suggests it happens
         * immediately, hence fix this to become USEC_INFINITY instead. This is in-line with how we internally handle
         * all other timeouts. */
        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s= parameter, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        s->start_timeout_defined = true;
        s->timeout_start_usec = usec;

        if (streq(lvalue, "TimeoutSec"))
                s->timeout_stop_usec = usec;

        return 0;
}

int config_parse_timeout_abort(
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

        usec_t *ret = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* Note: apart from setting the arg, this returns an extra bit of information in the return value. */

        if (isempty(rvalue)) {
                *ret = 0;
                return 0; /* "not set" */
        }

        r = parse_sec(rvalue, ret);
        if (r < 0)
                return log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s= setting, ignoring: %s", lvalue, rvalue);

        return 1; /* "set" */
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

        Service *s = ASSERT_PTR(userdata);
        int r;

        r = config_parse_timeout_abort(unit, filename, line, section, section_line, lvalue, ltype, rvalue,
                                       &s->timeout_abort_usec, s);
        if (r >= 0)
                s->timeout_abort_set = r;
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
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *user = mfree(*user);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", rvalue);
                return -ENOEXEC;
        }

        if (!valid_user_group_name(k, VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX|VALID_USER_WARN)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid user/group name or numeric ID: %s", k);
                return -ENOEXEC;
        }

        if (strstr(lvalue, "User") && streq(k, NOBODY_USER_NAME))
                log_struct(LOG_NOTICE,
                           "MESSAGE=%s:%u: Special user %s configured, this is not safe!", filename, line, k,
                           "UNIT=%s", unit,
                           "MESSAGE_ID=" SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR,
                           "OFFENDING_USER=%s", k,
                           "CONFIG_FILE=%s", filename,
                           "CONFIG_LINE=%u", line);

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
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *users = strv_free(*users);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax: %s", rvalue);
                        return -ENOEXEC;
                }
                if (r == 0)
                        return 0;

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to resolve unit specifiers in %s: %m", word);
                        return -ENOEXEC;
                }

                if (!valid_user_group_name(k, VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX|VALID_USER_WARN)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid user/group name or numeric ID: %s", k);
                        return -ENOEXEC;
                }

                r = strv_push(users, k);
                if (r < 0)
                        return log_oom();

                k = NULL;
        }
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = ASSERT_PTR(userdata);
        bool missing_ok;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

                r = unit_path_printf(u, rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, missing_ok ? LOG_WARNING : LOG_ERR, filename, line, r,
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

        char ***env = ASSERT_PTR(data);
        const Unit *u = userdata;
        _cleanup_free_ char *n = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment frees the list */
                *env = strv_free(*env);
                return 0;
        }

        r = unit_full_printf_full(u, rvalue, PATH_MAX, &n);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

        const Unit *u = userdata;
        char ***env = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *env = strv_free(*env);
                return 0;
        }

        /* If 'u' is set, we operate on the regular unit specifier table. Otherwise we use a manager-specific
         * specifier table (in which case ltype must contain the runtime scope). */
        const Specifier *table = u ? NULL : (const Specifier[]) {
                COMMON_SYSTEM_SPECIFIERS,
                COMMON_TMP_SPECIFIERS,
                COMMON_CREDS_SPECIFIERS(ltype),
                { 'h', specifier_user_home,  NULL },
                { 's', specifier_user_shell, NULL },
        };

        for (const char *p = rvalue;; ) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (table)
                        r = specifier_printf(word, sc_arg_max(), table, NULL, NULL, &resolved);
                else
                        r = unit_env_printf(u, word, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve specifiers in %s, ignoring: %m", word);
                        continue;
                }

                if (!env_assignment_is_valid(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid environment assignment, ignoring: %s", resolved);
                        continue;
                }

                r = strv_env_replace_consume(env, TAKE_PTR(resolved));
                if (r < 0)
                        return log_error_errno(r, "Failed to update environment: %m");
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
        const Unit *u = userdata;
        char*** passenv = ASSERT_PTR(data);
        size_t nlen = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *passenv = strv_free(*passenv);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }
                if (r == 0)
                        break;

                if (u) {
                        r = unit_env_printf(u, word, &k);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to resolve specifiers in %s, ignoring: %m", word);
                                continue;
                        }
                } else
                        k = TAKE_PTR(word);

                if (!env_name_is_valid(k)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid environment name for %s, ignoring: %s", lvalue, k);
                        continue;
                }

                if (!GREEDY_REALLOC(n, nlen + 2))
                        return log_oom();

                n[nlen++] = TAKE_PTR(k);
                n[nlen] = NULL;
        }

        if (n) {
                r = strv_extend_strv(passenv, n, true);
                if (r < 0)
                        return log_oom();
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
        char*** unsetenv = ASSERT_PTR(data);
        const Unit *u = userdata;
        size_t nlen = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *unsetenv = strv_free(*unsetenv);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }
                if (r == 0)
                        break;

                if (u) {
                        r = unit_env_printf(u, word, &k);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to resolve unit specifiers in %s, ignoring: %m", word);
                                continue;
                        }
                } else
                        k = TAKE_PTR(word);

                if (!env_assignment_is_valid(k) && !env_name_is_valid(k)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid environment name or assignment %s, ignoring: %s", lvalue, k);
                        continue;
                }

                if (!GREEDY_REALLOC(n, nlen + 2))
                        return log_oom();

                n[nlen++] = TAKE_PTR(k);
                n[nlen] = NULL;
        }

        if (n) {
                r = strv_extend_strv(unsetenv, n, true);
                if (r < 0)
                        return log_oom();
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                exec_context_free_log_extra_fields(c);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;
                struct iovec *t;
                const char *eq;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = unit_full_printf(u, word, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", word);
                        continue;
                }

                eq = strchr(k, '=');
                if (!eq) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Log field lacks '=' character, ignoring: %s", k);
                        continue;
                }

                if (!journal_field_valid(k, eq-k, false)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Log field name is invalid, ignoring: %s", k);
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

int config_parse_log_namespace(
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
        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                c->log_namespace = mfree(c->log_namespace);
                return 0;
        }

        r = unit_full_printf_full(u, rvalue, NAME_MAX, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        if (!log_namespace_name_valid(k)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Specified log namespace name is not valid, ignoring: %s", k);
                return 0;
        }

        free_and_replace(c->log_namespace, k);
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
        Condition **list = ASSERT_PTR(data), *c;
        ConditionType t = ltype;
        bool trigger, negate;
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

        r = unit_path_printf(u, rvalue, &p);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
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
        Condition **list = ASSERT_PTR(data), *c;
        ConditionType t = ltype;
        bool trigger, negate;
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
                return 0;
        }

        c = condition_new(t, s, trigger, negate);
        if (!c)
                return log_oom();

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

int config_parse_unit_mounts_for(
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);
        assert(STR_IN_SET(lvalue, "RequiresMountsFor", "WantsMountsFor"));

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

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

                r = unit_path_printf(u, word, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", word);
                        continue;
                }

                r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                r = unit_add_mounts_for(u, resolved, UNIT_DEPENDENCY_FILE, unit_mount_dependency_type_from_string(lvalue));
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to add requested mount '%s', ignoring: %m", resolved);
                        continue;
                }
        }
}

int config_parse_documentation(
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

        Unit *u = ASSERT_PTR(userdata);
        int r;
        char **a, **b;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid URL, ignoring: %s", *a);
                        free(*a);
                }
        }
        if (b)
                *b = NULL;

        return 0;
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
        _unused_ const Unit *u = ASSERT_PTR(userdata);
        bool invert = false;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->syscall_filter = hashmap_free(c->syscall_filter);
                c->syscall_allow_list = false;
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
                        c->syscall_allow_list = false;
                else {
                        /* Allow nothing but the ones listed */
                        c->syscall_allow_list = true;

                        /* Accept default syscalls if we are on an allow_list */
                        r = seccomp_parse_syscall_filter(
                                        "@default", -1, c->syscall_filter,
                                        SECCOMP_PARSE_PERMISSIVE|SECCOMP_PARSE_ALLOW_LIST,
                                        unit,
                                        NULL, 0);
                        if (r < 0)
                                return r;
                }
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *name = NULL;
                int num;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = parse_syscall_and_errno(word, &name, &num);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse syscall:errno, ignoring: %s", word);
                        continue;
                }
                if (!invert && num >= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Allow-listed system calls cannot take error number, ignoring: %s", word);
                        continue;
                }

                r = seccomp_parse_syscall_filter(
                                name, num, c->syscall_filter,
                                SECCOMP_PARSE_LOG|SECCOMP_PARSE_PERMISSIVE|
                                (invert ? SECCOMP_PARSE_INVERT : 0)|
                                (c->syscall_allow_list ? SECCOMP_PARSE_ALLOW_LIST : 0),
                                unit, filename, line);
                if (r < 0)
                        return r;
        }
}

int config_parse_syscall_log(
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
        _unused_ const Unit *u = ASSERT_PTR(userdata);
        bool invert = false;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->syscall_log = hashmap_free(c->syscall_log);
                c->syscall_log_allow_list = false;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (!c->syscall_log) {
                c->syscall_log = hashmap_new(NULL);
                if (!c->syscall_log)
                        return log_oom();

                if (invert)
                        /* Log everything but the ones listed */
                        c->syscall_log_allow_list = false;
                else
                        /* Log nothing but the ones listed */
                        c->syscall_log_allow_list = true;
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = seccomp_parse_syscall_filter(
                                word, -1, c->syscall_log,
                                SECCOMP_PARSE_LOG|SECCOMP_PARSE_PERMISSIVE|
                                (invert ? SECCOMP_PARSE_INVERT : 0)|
                                (c->syscall_log_allow_list ? SECCOMP_PARSE_ALLOW_LIST : 0),
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

        Set **archs = data;
        int r;

        if (isempty(rvalue)) {
                *archs = set_free(*archs);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                uint32_t a;

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

                r = seccomp_arch_from_string(word, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse system call architecture \"%s\", ignoring: %m", word);
                        continue;
                }

                r = set_ensure_put(archs, NULL, UINT32_TO_PTR(a + 1));
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

        if (isempty(rvalue) || streq(rvalue, "kill")) {
                /* Empty assignment resets to KILL */
                c->syscall_errno = SECCOMP_ERROR_NUMBER_KILL;
                return 0;
        }

        e = parse_errno(rvalue);
        if (e < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, e, "Failed to parse error number, ignoring: %s", rvalue);
                return 0;
        }
        if (e == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid error number, ignoring: %s", rvalue);
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->address_families = set_free(c->address_families);
                c->address_families_allow_list = false;
                return 0;
        }

        if (streq(rvalue, "none")) {
                /* Forbid all address families. */
                c->address_families = set_free(c->address_families);
                c->address_families_allow_list = true;
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

                c->address_families_allow_list = !invert;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                int af;

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

                af = af_from_name(word);
                if (af < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, af,
                                   "Failed to parse address family, ignoring: %s", word);
                        continue;
                }

                /* If we previously wanted to forbid an address family and now
                 * we want to allow it, then just remove it from the list.
                 */
                if (!invert == c->address_families_allow_list)  {
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse namespace type string, ignoring: %s", rvalue);
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

int config_parse_restrict_filesystems(
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
        ExecContext *c = ASSERT_PTR(data);
        bool invert = false;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->restrict_filesystems = set_free_free(c->restrict_filesystems);
                c->restrict_filesystems_allow_list = false;
                return 0;
        }

        if (rvalue[0] == '~') {
                invert = true;
                rvalue++;
        }

        if (!c->restrict_filesystems) {
                if (invert)
                        /* Allow everything but the ones listed */
                        c->restrict_filesystems_allow_list = false;
                else
                        /* Allow nothing but the ones listed */
                        c->restrict_filesystems_allow_list = true;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }

                r = lsm_bpf_parse_filesystem(
                              word,
                              &c->restrict_filesystems,
                              FILESYSTEM_PARSE_LOG|
                              (invert ? FILESYSTEM_PARSE_INVERT : 0)|
                              (c->restrict_filesystems_allow_list ? FILESYSTEM_PARSE_ALLOW_LIST : 0),
                              unit, filename, line);

                if (r < 0)
                        return r;
        }

        return 0;
}

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
        Unit *u = userdata, *slice;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(u);

        r = unit_name_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", rvalue);
                return 0;
        }

        r = manager_load_unit(u->manager, k, NULL, &error, &slice);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to load slice unit %s, ignoring: %s", k, bus_error_message(&error, r));
                return 0;
        }

        r = unit_set_slice(u, slice);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to assign slice %s to unit %s, ignoring: %m", slice->id, u->id);
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

        r = parse_permyriad_unbounded(rvalue);
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid CPU quota '%s', ignoring.", rvalue);
                return 0;
        }

        c->cpu_quota_per_sec_usec = ((usec_t) r * USEC_PER_SEC) / 10000U;
        return 0;
}

int config_parse_allowed_cpuset(
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

        CPUSet *c = data;
        const Unit *u = userdata;
        _cleanup_free_ char *k = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = unit_full_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m",
                           rvalue);
                return 0;
        }

        (void) parse_cpu_set_extend(k, c, true, unit, filename, line, lvalue);
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

        if (isempty(rvalue) && STR_IN_SET(lvalue, "DefaultMemoryLow",
                                                  "DefaultMemoryMin",
                                                  "MemoryLow",
                                                  "StartupMemoryLow",
                                                  "MemoryMin"))
                bytes = CGROUP_LIMIT_MIN;
        else if (!isempty(rvalue) && !streq(rvalue, "infinity")) {

                r = parse_permyriad(rvalue);
                if (r < 0) {
                        r = parse_size(rvalue, 1024, &bytes);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid memory limit '%s', ignoring: %m", rvalue);
                                return 0;
                        }
                } else
                        bytes = physical_memory_scale(r, 10000U);

                if (bytes >= UINT64_MAX ||
                    (bytes <= 0 && !STR_IN_SET(lvalue,
                                               "MemorySwapMax",
                                               "StartupMemorySwapMax",
                                               "MemoryZSwapMax",
                                               "StartupMemoryZSwapMax",
                                               "MemoryLow",
                                               "StartupMemoryLow",
                                               "MemoryMin",
                                               "DefaultMemoryLow",
                                               "DefaultstartupMemoryLow",
                                               "DefaultMemoryMin"))) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Memory limit '%s' out of range, ignoring.", rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "DefaultMemoryLow")) {
                c->default_memory_low = bytes;
                c->default_memory_low_set = true;
        } else if (streq(lvalue, "DefaultStartupMemoryLow")) {
                c->default_startup_memory_low = bytes;
                c->default_startup_memory_low_set = true;
        } else if (streq(lvalue, "DefaultMemoryMin")) {
                c->default_memory_min = bytes;
                c->default_memory_min_set = true;
        } else if (streq(lvalue, "MemoryMin")) {
                c->memory_min = bytes;
                c->memory_min_set = true;
        } else if (streq(lvalue, "MemoryLow")) {
                c->memory_low = bytes;
                c->memory_low_set = true;
        } else if (streq(lvalue, "StartupMemoryLow")) {
                c->startup_memory_low = bytes;
                c->startup_memory_low_set = true;
        } else if (streq(lvalue, "MemoryHigh"))
                c->memory_high = bytes;
        else if (streq(lvalue, "StartupMemoryHigh")) {
                c->startup_memory_high = bytes;
                c->startup_memory_high_set = true;
        } else if (streq(lvalue, "MemoryMax"))
                c->memory_max = bytes;
        else if (streq(lvalue, "StartupMemoryMax")) {
                c->startup_memory_max = bytes;
                c->startup_memory_max_set = true;
        } else if (streq(lvalue, "MemorySwapMax"))
                c->memory_swap_max = bytes;
        else if (streq(lvalue, "StartupMemorySwapMax")) {
                c->startup_memory_swap_max = bytes;
                c->startup_memory_swap_max_set = true;
        } else if (streq(lvalue, "MemoryZSwapMax"))
                c->memory_zswap_max = bytes;
        else if (streq(lvalue, "StartupMemoryZSwapMax")) {
                c->startup_memory_zswap_max = bytes;
                c->startup_memory_zswap_max_set = true;
        } else if (streq(lvalue, "MemoryLimit")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unit uses MemoryLimit=; please use MemoryMax= instead. Support for MemoryLimit= will be removed soon.");
                c->memory_limit = bytes;
        } else
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

        const Unit *u = userdata;
        CGroupTasksMax *tasks_max = data;
        uint64_t v;
        int r;

        if (isempty(rvalue)) {
                *tasks_max = u ? u->manager->defaults.tasks_max : CGROUP_TASKS_MAX_UNSET;
                return 0;
        }

        if (streq(rvalue, "infinity")) {
                *tasks_max = CGROUP_TASKS_MAX_UNSET;
                return 0;
        }

        r = parse_permyriad(rvalue);
        if (r >= 0)
                *tasks_max = (CGroupTasksMax) { r, 10000U }; /* r‱ */
        else {
                r = safe_atou64(rvalue, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid maximum tasks value '%s', ignoring: %m", rvalue);
                        return 0;
                }

                if (v <= 0 || v >= UINT64_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Maximum tasks value '%s' out of range, ignoring.", rvalue);
                        return 0;
                }

                *tasks_max = (CGroupTasksMax) { v };
        }

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
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Delegate= setting not supported for this unit type, ignoring.");
                return 0;
        }

        /* We either accept a boolean value, which may be used to turn on delegation for all controllers, or
         * turn it off for all. Or it takes a list of controller names, in which case we add the specified
         * controllers to the mask to delegate. Delegate= enables delegation without any controllers. */

        if (isempty(rvalue)) {
                /* An empty string resets controllers and sets Delegate=yes. */
                c->delegate = true;
                c->delegate_controllers = 0;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                CGroupMask mask = 0;

                for (const char *p = rvalue;;) {
                        _cleanup_free_ char *word = NULL;
                        CGroupController cc;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                                return 0;
                        }
                        if (r == 0)
                                break;

                        cc = cgroup_controller_from_string(word);
                        if (cc < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid controller name '%s', ignoring", word);
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

int config_parse_delegate_subgroup(
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

        CGroupContext *c = ASSERT_PTR(data);
        UnitType t;

        t = unit_name_to_type(unit);
        assert(t >= 0);

        if (!unit_vtable[t]->can_delegate) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "DelegateSubgroup= setting not supported for this unit type, ignoring.");
                return 0;
        }

        if (isempty(rvalue)) {
                c->delegate_subgroup = mfree(c->delegate_subgroup);
                return 0;
        }

        if (cg_needs_escape(rvalue)) { /* Insist that specified names don't need escaping */
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid control group name, ignoring: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(&c->delegate_subgroup, rvalue);
}

int config_parse_managed_oom_mode(
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

        ManagedOOMMode *mode = data, m;
        UnitType t;

        t = unit_name_to_type(unit);
        assert(t != _UNIT_TYPE_INVALID);

        if (!unit_vtable[t]->can_set_managed_oom)
                return log_syntax(unit, LOG_WARNING, filename, line, 0, "%s= is not supported for this unit type, ignoring.", lvalue);

        if (isempty(rvalue)) {
                *mode = MANAGED_OOM_AUTO;
                return 0;
        }

        m = managed_oom_mode_from_string(rvalue);
        if (m < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, m, "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }

        *mode = m;
        return 0;
}

int config_parse_managed_oom_mem_pressure_limit(
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

        uint32_t *limit = data;
        UnitType t;
        int r;

        t = unit_name_to_type(unit);
        assert(t != _UNIT_TYPE_INVALID);

        if (!unit_vtable[t]->can_set_managed_oom)
                return log_syntax(unit, LOG_WARNING, filename, line, 0, "%s= is not supported for this unit type, ignoring.", lvalue);

        if (isempty(rvalue)) {
                *limit = 0;
                return 0;
        }

        r = parse_permyriad(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse memory pressure limit value, ignoring: %s", rvalue);
                return 0;
        }

        /* Normalize to 2^32-1 == 100% */
        *limit = UINT32_SCALE_FROM_PERMYRIAD(r);
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
        CGroupDevicePermissions permissions;
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
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to extract device path and rights from '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
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
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid device node path '%s', ignoring.", resolved);
                        return 0;
                }
        }

        permissions = isempty(p) ? 0 : cgroup_device_permissions_from_string(p);
        if (permissions < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, permissions, "Invalid device rights '%s', ignoring.", p);
                return 0;
        }

        return cgroup_context_add_device_allow(c, resolved, permissions);
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
        const char *p = ASSERT_PTR(rvalue);
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);

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
                           "Failed to extract device path and weight from '%s', ignoring.", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid device path or weight specified in '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "IO weight '%s' invalid, ignoring: %m", p);
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
        const char *p = ASSERT_PTR(rvalue);
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);

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
                           "Failed to extract device path and latency from '%s', ignoring.", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid device path or latency specified in '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to resolve unit specifiers in '%s', ignoring: %m", path);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = parse_sec(p, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse timer value, ignoring: %s", p);
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
        CGroupIODeviceLimit *l = NULL;
        CGroupContext *c = data;
        CGroupIOLimitType type;
        const char *p = ASSERT_PTR(rvalue);
        uint64_t num;
        int r;

        assert(filename);
        assert(lvalue);

        type = cgroup_io_limit_type_from_string(lvalue);
        assert(type >= 0);

        if (isempty(rvalue)) {
                LIST_FOREACH(device_limits, t, c->io_device_limits)
                        t->limits[type] = cgroup_io_limit_defaults[type];
                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to extract device node and bandwidth from '%s', ignoring.", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid device node or bandwidth specified in '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
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
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid IO limit '%s', ignoring.", p);
                        return 0;
                }
        }

        LIST_FOREACH(device_limits, t, c->io_device_limits)
                if (path_equal(resolved, t->path)) {
                        l = t;
                        break;
                }

        if (!l) {
                l = new0(CGroupIODeviceLimit, 1);
                if (!l)
                        return log_oom();

                l->path = TAKE_PTR(resolved);
                for (CGroupIOLimitType i = 0; i < _CGROUP_IO_LIMIT_TYPE_MAX; i++)
                        l->limits[i] = cgroup_io_limit_defaults[i];

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
        const char *p = ASSERT_PTR(rvalue);
        uint64_t u;
        int r;

        assert(filename);
        assert(lvalue);

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "Unit uses %s=; please use IO*= settings instead. Support for %s= will be removed soon.",
                   lvalue, lvalue);

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
                           "Failed to extract device node and weight from '%s', ignoring.", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid device node or weight specified in '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid block IO weight '%s', ignoring: %m", p);
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
        CGroupBlockIODeviceBandwidth *b = NULL;
        CGroupContext *c = data;
        const char *p = ASSERT_PTR(rvalue);
        uint64_t bytes;
        bool read;
        int r;

        assert(filename);
        assert(lvalue);

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "Unit uses %s=; please use IO*= settings instead. Support for %s= will be removed soon.",
                   lvalue, lvalue);

        read = streq("BlockIOReadBandwidth", lvalue);

        if (isempty(rvalue)) {
                LIST_FOREACH(device_bandwidths, t, c->blockio_device_bandwidths) {
                        t->rbps = CGROUP_LIMIT_MAX;
                        t->wbps = CGROUP_LIMIT_MAX;
                }
                return 0;
        }

        r = extract_first_word(&p, &path, NULL, EXTRACT_UNQUOTE);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to extract device node and bandwidth from '%s', ignoring.", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid device node or bandwidth specified in '%s', ignoring.", rvalue);
                return 0;
        }

        r = unit_path_printf(userdata, path, &resolved);
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid Block IO Bandwidth '%s', ignoring.", p);
                return 0;
        }

        LIST_FOREACH(device_bandwidths, t, c->blockio_device_bandwidths)
                if (path_equal(resolved, t->path)) {
                        b = t;
                        break;
                }

        if (!b) {
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse boolean, ignoring: %s", rvalue);
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

        ExecDirectory *ed = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                exec_directory_done(ed);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *tuple = NULL;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax %s=%s, ignoring: %m", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                _cleanup_free_ char *src = NULL, *dest = NULL;
                const char *q = tuple;
                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &src, &dest, NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax in %s=, ignoring: %s", lvalue, tuple);
                        return 0;
                }

                _cleanup_free_ char *sresolved = NULL;
                r = unit_path_printf(u, src, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve unit specifiers in \"%s\", ignoring: %m", src);
                        continue;
                }

                r = path_simplify_and_warn(sresolved, PATH_CHECK_RELATIVE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                if (path_startswith(sresolved, "private")) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "%s= path can't be 'private', ignoring assignment: %s", lvalue, tuple);
                        continue;
                }

                /* For State and Runtime directories we support an optional destination parameter, which
                 * will be used to create a symlink to the source. */
                _cleanup_free_ char *dresolved = NULL;
                if (!isempty(dest)) {
                        if (streq(lvalue, "ConfigurationDirectory")) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "Destination parameter is not supported for ConfigurationDirectory, ignoring: %s", tuple);
                                continue;
                        }

                        r = unit_path_printf(u, dest, &dresolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                        "Failed to resolve unit specifiers in \"%s\", ignoring: %m", dest);
                                continue;
                        }

                        r = path_simplify_and_warn(dresolved, PATH_CHECK_RELATIVE, unit, filename, line, lvalue);
                        if (r < 0)
                                continue;
                }

                r = exec_directory_add(ed, sresolved, dresolved);
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_set_credential(
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

        _cleanup_free_ char *word = NULL, *k = NULL;
        _cleanup_free_ void *d = NULL;
        ExecContext *context = ASSERT_PTR(data);
        ExecSetCredential *old;
        Unit *u = userdata;
        bool encrypted = ltype;
        const char *p = ASSERT_PTR(rvalue);
        size_t size;
        int r;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                context->set_credentials = hashmap_free(context->set_credentials);
                return 0;
        }

        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to extract credential name, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_cred_printf(u, word, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in \"%s\", ignoring: %m", word);
                return 0;
        }
        if (!credential_name_valid(k)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Credential name \"%s\" not valid, ignoring.", k);
                return 0;
        }

        if (encrypted) {
                r = unbase64mem_full(p, SIZE_MAX, true, &d, &size);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Encrypted credential data not valid Base64 data, ignoring.");
                        return 0;
                }
        } else {
                char *unescaped;
                ssize_t l;

                /* We support escape codes here, so that users can insert trailing \n if they like */
                l = cunescape(p, UNESCAPE_ACCEPT_NUL, &unescaped);
                if (l < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, l, "Can't unescape \"%s\", ignoring: %m", p);
                        return 0;
                }

                d = unescaped;
                size = l;
        }

        old = hashmap_get(context->set_credentials, k);
        if (old) {
                free_and_replace(old->data, d);
                old->size = size;
                old->encrypted = encrypted;
        } else {
                _cleanup_(exec_set_credential_freep) ExecSetCredential *sc = NULL;

                sc = new(ExecSetCredential, 1);
                if (!sc)
                        return log_oom();

                *sc = (ExecSetCredential) {
                        .id = TAKE_PTR(k),
                        .data = TAKE_PTR(d),
                        .size = size,
                        .encrypted = encrypted,
                };

                r = hashmap_ensure_put(&context->set_credentials, &exec_set_credential_hash_ops, sc->id, sc);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Duplicated credential value '%s', ignoring assignment: %s", sc->id, rvalue);
                        return 0;
                }

                TAKE_PTR(sc);
        }

        return 0;
}

int hashmap_put_credential(Hashmap **h, const char *id, const char *path, bool encrypted) {
        ExecLoadCredential *old;
        int r;

        assert(h);
        assert(id);
        assert(path);

        old = hashmap_get(*h, id);
        if (old) {
                r = free_and_strdup(&old->path, path);
                if (r < 0)
                        return r;

                old->encrypted = encrypted;
        } else {
                _cleanup_(exec_load_credential_freep) ExecLoadCredential *lc = NULL;

                lc = new(ExecLoadCredential, 1);
                if (!lc)
                        return log_oom();

                *lc = (ExecLoadCredential) {
                        .id = strdup(id),
                        .path = strdup(path),
                        .encrypted = encrypted,
                };
                if (!lc->id || !lc->path)
                        return -ENOMEM;

                r = hashmap_ensure_put(h, &exec_load_credential_hash_ops, lc->id, lc);
                if (r < 0)
                        return r;

                TAKE_PTR(lc);
        }

        return 0;
}

int config_parse_load_credential(
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

        _cleanup_free_ char *word = NULL, *k = NULL, *q = NULL;
        ExecContext *context = ASSERT_PTR(data);
        bool encrypted = ltype;
        Unit *u = userdata;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                context->load_credentials = hashmap_free(context->load_credentials);
                return 0;
        }

        p = rvalue;
        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }

        r = unit_cred_printf(u, word, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in \"%s\", ignoring: %m", word);
                return 0;
        }
        if (!credential_name_valid(k)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Credential name \"%s\" not valid, ignoring.", k);
                return 0;
        }

        if (isempty(p)) {
                /* If only one field is specified take it as shortcut for inheriting a credential named
                 * the same way from our parent */
                q = strdup(k);
                if (!q)
                        return log_oom();
        } else {
                r = unit_path_printf(u, p, &q);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in \"%s\", ignoring: %m", p);
                        return 0;
                }
                if (path_is_absolute(q) ? !path_is_normalized(q) : !credential_name_valid(q)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Credential source \"%s\" not valid, ignoring.", q);
                        return 0;
                }
        }

        r = hashmap_put_credential(&context->load_credentials, k, q, encrypted);
        if (r < 0)
                return log_error_errno(r, "Failed to store load credential '%s': %m", rvalue);

        return 0;
}

int config_parse_import_credential(
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
        Set** import_credentials = ASSERT_PTR(data);
        Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *import_credentials = set_free_free(*import_credentials);
                return 0;
        }

        r = unit_cred_printf(u, rvalue, &s);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in \"%s\", ignoring: %m", s);
                return 0;
        }
        if (!credential_glob_valid(s)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Credential name or glob \"%s\" not valid, ignoring.", s);
                return 0;
        }

        r = set_put_strdup(import_credentials, s);
        if (r < 0)
                return log_error_errno(r, "Failed to store credential name '%s': %m", rvalue);

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

        ExitStatusSet *status_set = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* Empty assignment resets the list */
        if (isempty(rvalue)) {
                exit_status_set_free(status_set);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                Bitmap *bitmap;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse %s=%s, ignoring: %m", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                /* We need to call exit_status_from_string() first, because we want
                 * to parse numbers as exit statuses, not signals. */

                r = exit_status_from_string(word);
                if (r >= 0) {
                        assert(r >= 0 && r < 256);
                        bitmap = &status_set->status;
                } else {
                        r = signal_from_string(word);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse value, ignoring: %s", word);
                                continue;
                        }
                        bitmap = &status_set->signal;
                }

                r = bitmap_set(bitmap, r);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to set signal or status %s, ignoring: %m", word);
        }
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

        const Unit *u = userdata;
        char*** sv = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *sv = strv_free(*sv);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL, *joined = NULL;
                const char *w;
                bool ignore_enoent = false, shall_prefix = false;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                w = word;
                if (startswith(w, "-")) {
                        ignore_enoent = true;
                        w++;
                }
                if (startswith(w, "+")) {
                        shall_prefix = true;
                        w++;
                }

                r = unit_path_printf(u, w, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s: %m", w);
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

        const Unit *u = userdata;
        ExecContext *c = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                temporary_filesystem_free_many(c->temporary_filesystems, c->n_temporary_filesystems);
                c->temporary_filesystems = NULL;
                c->n_temporary_filesystems = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL, *path = NULL, *resolved = NULL;
                const char *w;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to extract first word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                w = word;
                r = extract_first_word(&w, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to extract first word, ignoring: %s", word);
                        continue;
                }
                if (r == 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax, ignoring: %s", word);
                        continue;
                }

                r = unit_path_printf(u, path, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", path);
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                bind_mount_free_many(c->bind_mounts, c->n_bind_mounts);
                c->bind_mounts = NULL;
                c->n_bind_mounts = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *source = NULL, *destination = NULL;
                _cleanup_free_ char *sresolved = NULL, *dresolved = NULL;
                char *s = NULL, *d = NULL;
                bool rbind = true, ignore_enoent = false;

                r = extract_first_word(&p, &source, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = unit_full_printf_full(u, source, PATH_MAX, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve unit specifiers in \"%s\", ignoring: %m", source);
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
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                                return 0;
                        }
                        if (r == 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Missing argument after ':', ignoring: %s", s);
                                continue;
                        }

                        r = unit_path_printf(u, destination, &dresolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to resolve specifiers in \"%s\", ignoring: %m", destination);
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
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                                        return 0;
                                }

                                if (isempty(options) || streq(options, "rbind"))
                                        rbind = true;
                                else if (streq(options, "norbind"))
                                        rbind = false;
                                else {
                                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid option string, ignoring setting: %s", options);
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

int config_parse_mount_images(
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->mount_images = mount_image_free_many(c->mount_images, &c->n_mount_images);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                _cleanup_free_ char *first = NULL, *second = NULL, *tuple = NULL;
                _cleanup_free_ char *sresolved = NULL, *dresolved = NULL;
                const char *q = NULL;
                char *s = NULL;
                bool permissive = false;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax %s=%s, ignoring: %m", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                q = tuple;
                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &first, &second, NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax in %s=, ignoring: %s", lvalue, tuple);
                        return 0;
                }
                if (r == 0)
                        continue;

                s = first;
                if (s[0] == '-') {
                        permissive = true;
                        s++;
                }

                r = unit_path_printf(u, s, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve unit specifiers in \"%s\", ignoring: %m", s);
                        continue;
                }

                r = path_simplify_and_warn(sresolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                if (isempty(second)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Missing destination in %s, ignoring: %s", lvalue, rvalue);
                        continue;
                }

                r = unit_path_printf(u, second, &dresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                        "Failed to resolve specifiers in \"%s\", ignoring: %m", second);
                        continue;
                }

                r = path_simplify_and_warn(dresolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                for (;;) {
                        _cleanup_free_ char *partition = NULL, *mount_options = NULL, *mount_options_resolved = NULL;
                        MountOptions *o = NULL;
                        PartitionDesignator partition_designator;

                        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options, NULL);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", q);
                                return 0;
                        }
                        if (r == 0)
                                break;
                        /* Single set of options, applying to the root partition/single filesystem */
                        if (r == 1) {
                                r = unit_full_printf(u, partition, &mount_options_resolved);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", first);
                                        continue;
                                }

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom();
                                *o = (MountOptions) {
                                        .partition_designator = PARTITION_ROOT,
                                        .options = TAKE_PTR(mount_options_resolved),
                                };
                                LIST_APPEND(mount_options, options, o);

                                break;
                        }

                        partition_designator = partition_designator_from_string(partition);
                        if (partition_designator < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, partition_designator,
                                           "Invalid partition name %s, ignoring", partition);
                                continue;
                        }
                        r = unit_full_printf(u, mount_options, &mount_options_resolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", mount_options);
                                continue;
                        }

                        o = new(MountOptions, 1);
                        if (!o)
                                return log_oom();
                        *o = (MountOptions) {
                                .partition_designator = partition_designator,
                                .options = TAKE_PTR(mount_options_resolved),
                        };
                        LIST_APPEND(mount_options, options, o);
                }

                r = mount_image_add(&c->mount_images, &c->n_mount_images,
                                    &(MountImage) {
                                            .source = sresolved,
                                            .destination = dresolved,
                                            .mount_options = options,
                                            .ignore_enoent = permissive,
                                            .type = MOUNT_IMAGE_DISCRETE,
                                    });
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_extension_images(
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

        ExecContext *c = ASSERT_PTR(data);
        const Unit *u = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->extension_images = mount_image_free_many(c->extension_images, &c->n_extension_images);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *source = NULL, *tuple = NULL, *sresolved = NULL;
                _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                bool permissive = false;
                const char *q = NULL;
                char *s = NULL;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax %s=%s, ignoring: %m", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                q = tuple;
                r = extract_first_word(&q, &source, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax in %s=, ignoring: %s", lvalue, tuple);
                        return 0;
                }
                if (r == 0)
                        continue;

                s = source;
                if (s[0] == '-') {
                        permissive = true;
                        s++;
                }

                r = unit_path_printf(u, s, &sresolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve unit specifiers in \"%s\", ignoring: %m", s);
                        continue;
                }

                r = path_simplify_and_warn(sresolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
                if (r < 0)
                        continue;

                for (;;) {
                        _cleanup_free_ char *partition = NULL, *mount_options = NULL, *mount_options_resolved = NULL;
                        MountOptions *o = NULL;
                        PartitionDesignator partition_designator;

                        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options, NULL);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", q);
                                return 0;
                        }
                        if (r == 0)
                                break;
                        /* Single set of options, applying to the root partition/single filesystem */
                        if (r == 1) {
                                r = unit_full_printf(u, partition, &mount_options_resolved);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", partition);
                                        continue;
                                }

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom();
                                *o = (MountOptions) {
                                        .partition_designator = PARTITION_ROOT,
                                        .options = TAKE_PTR(mount_options_resolved),
                                };
                                LIST_APPEND(mount_options, options, o);

                                break;
                        }

                        partition_designator = partition_designator_from_string(partition);
                        if (partition_designator < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid partition name %s, ignoring", partition);
                                continue;
                        }
                        r = unit_full_printf(u, mount_options, &mount_options_resolved);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in %s, ignoring: %m", mount_options);
                                continue;
                        }

                        o = new(MountOptions, 1);
                        if (!o)
                                return log_oom();
                        *o = (MountOptions) {
                                .partition_designator = partition_designator,
                                .options = TAKE_PTR(mount_options_resolved),
                        };
                        LIST_APPEND(mount_options, options, o);
                }

                r = mount_image_add(&c->extension_images, &c->n_extension_images,
                                    &(MountImage) {
                                            .source = sresolved,
                                            .mount_options = options,
                                            .ignore_enoent = permissive,
                                            .type = MOUNT_IMAGE_EXTENSION,
                                    });
                if (r < 0)
                        return log_oom();
        }
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

        Unit *u = ASSERT_PTR(data);
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse JobTimeoutSec= parameter, ignoring: %s", rvalue);
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

        Unit *u = ASSERT_PTR(data);
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_sec_fix_0(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse JobRunningTimeoutSec= parameter, ignoring: %s", rvalue);
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

        EmergencyAction *x = ASSERT_PTR(data);
        RuntimeScope runtime_scope;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* If we have a unit determine the scope based on it */
        if (unit)
                runtime_scope = ((Unit*) ASSERT_PTR(userdata))->manager->runtime_scope;
        else
                runtime_scope = ltype; /* otherwise, assume the scope is passed in via ltype */

        r = parse_emergency_action(rvalue, runtime_scope, x);
        if (r < 0) {
                if (r == -EOPNOTSUPP)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s= specified as %s mode action, ignoring: %s",
                                   lvalue, runtime_scope_to_string(runtime_scope), rvalue);
                else
                        log_syntax(unit, LOG_WARNING, filename, line, r,
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
        const Unit *u = ASSERT_PTR(userdata);
        char **s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* An empty assignment removes already set value. */
                *s = mfree(*s);
                return 0;
        }

        r = unit_path_printf(u, rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse exit status '%s', ignoring: %m", rvalue);
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
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid cgroup string: %s, ignoring", rvalue);
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
        const Unit *u = userdata;
        char ***paths = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *paths = strv_free(*paths);
                return 0;
        }

        r = unit_path_printf(u, rvalue, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %m", rvalue);
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

int config_parse_bpf_foreign_program(
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
        _cleanup_free_ char *resolved = NULL, *word = NULL;
        CGroupContext *c = data;
        const char *p = ASSERT_PTR(rvalue);
        Unit *u = userdata;
        int attach_type, r;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                while (c->bpf_foreign_programs)
                        cgroup_context_remove_bpf_foreign_program(c, c->bpf_foreign_programs);

                return 0;
        }

        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse foreign BPF program, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid syntax in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        attach_type = bpf_cgroup_attach_type_from_string(word);
        if (attach_type < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown BPF attach type=%s, ignoring: %s", word, rvalue);
                return 0;
        }

        r = unit_path_printf(u, p, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to resolve unit specifiers in '%s', ignoring: %s", p, rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        r = cgroup_context_add_bpf_foreign_program(c, attach_type, resolved);
        if (r < 0)
                return log_error_errno(r, "Failed to add foreign BPF program to cgroup context: %m");

        return 0;
}

int config_parse_cgroup_socket_bind(
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
        _cleanup_free_ CGroupSocketBindItem *item = NULL;
        CGroupSocketBindItem **head = data;
        uint16_t nr_ports, port_min;
        int af, ip_protocol, r;

        if (isempty(rvalue)) {
                cgroup_context_remove_socket_bind(head);
                return 0;
        }

        r = parse_socket_bind_item(rvalue, &af, &ip_protocol, &nr_ports, &port_min);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Unable to parse %s= assignment, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        item = new(CGroupSocketBindItem, 1);
        if (!item)
                return log_oom();
        *item = (CGroupSocketBindItem) {
                .address_family = af,
                .ip_protocol = ip_protocol,
                .nr_ports = nr_ports,
                .port_min = port_min,
        };

        LIST_PREPEND(socket_bind_items, *head, TAKE_PTR(item));

        return 0;
}

int config_parse_restrict_network_interfaces(
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
        CGroupContext *c = ASSERT_PTR(data);
        bool is_allow_rule = true;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                c->restrict_network_interfaces = set_free_free(c->restrict_network_interfaces);
                return 0;
        }

        if (rvalue[0] == '~') {
                is_allow_rule = false;
                rvalue++;
        }

        if (set_isempty(c->restrict_network_interfaces))
                /* Only initialize this when creating the set */
                c->restrict_network_interfaces_is_allow_list = is_allow_rule;

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Trailing garbage in %s, ignoring: %s", lvalue, rvalue);
                        break;
                }

                if (!ifname_valid_full(word, IFNAME_VALID_ALTERNATIVE)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid interface name, ignoring: %s", word);
                        continue;
                }

                if (c->restrict_network_interfaces_is_allow_list != is_allow_rule)
                        free(set_remove(c->restrict_network_interfaces, word));
                else {
                        r = set_put_strdup(&c->restrict_network_interfaces, word);
                        if (r < 0)
                                return log_oom();
                }
        }

        return 0;
}

static int merge_by_names(Unit *u, Set *names, const char *id) {
        char *k;
        int r;

        assert(u);

        /* Let's try to add in all names that are aliases of this unit */
        while ((k = set_steal_first(names))) {
                _cleanup_free_ _unused_ char *free_k = k;

                /* First try to merge in the other name into our unit */
                r = unit_merge_by_name(u, k);
                if (r < 0) {
                        Unit *other;

                        /* Hmm, we couldn't merge the other unit into ours? Then let's try it the other way
                         * round. */

                        other = manager_get_unit(u->manager, k);
                        if (!other)
                                return r; /* return previous failure */

                        r = unit_merge(other, u);
                        if (r < 0)
                                return r;

                        return merge_by_names(other, names, NULL);
                }

                if (streq_ptr(id, k))
                        unit_choose_id(u, id);
        }

        return 0;
}

int unit_load_fragment(Unit *u) {
        const char *fragment;
        _cleanup_set_free_free_ Set *names = NULL;
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);
        assert(u->id);

        if (u->transient) {
                u->access_selinux_context = mfree(u->access_selinux_context);
                u->load_state = UNIT_LOADED;
                return 0;
        }

        /* Possibly rebuild the fragment map to catch new units */
        r = unit_file_build_name_map(&u->manager->lookup_paths,
                                     &u->manager->unit_cache_timestamp_hash,
                                     &u->manager->unit_id_map,
                                     &u->manager->unit_name_map,
                                     &u->manager->unit_path_cache);
        if (r < 0)
                return log_error_errno(r, "Failed to rebuild name map: %m");

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
                struct stat st;

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
                        /* Unit file is masked */

                        u->load_state = u->perpetual ? UNIT_LOADED : UNIT_MASKED; /* don't allow perpetual units to ever be masked */
                        u->fragment_mtime = 0;
                        u->access_selinux_context = mfree(u->access_selinux_context);
                } else {
#if HAVE_SELINUX
                        if (mac_selinux_use()) {
                                _cleanup_freecon_ char *selcon = NULL;

                                /* Cache the SELinux context of the unit file here. We'll make use of when checking access permissions to loaded units */
                                r = fgetfilecon_raw(fileno(f), &selcon);
                                if (r < 0)
                                        log_unit_warning_errno(u, r, "Failed to read SELinux context of '%s', ignoring: %m", fragment);

                                r = free_and_strdup(&u->access_selinux_context, selcon);
                                if (r < 0)
                                        return r;
                        } else
#endif
                                u->access_selinux_context = mfree(u->access_selinux_context);

                        u->load_state = UNIT_LOADED;
                        u->fragment_mtime = timespec_load(&st.st_mtim);

                        /* Now, parse the file contents */
                        r = config_parse(u->id, fragment, f,
                                         UNIT_VTABLE(u)->sections,
                                         config_item_perf_lookup, load_fragment_gperf_lookup,
                                         0,
                                         u,
                                         NULL);
                        if (r == -ENOEXEC)
                                log_unit_notice_errno(u, r, "Unit configuration has fatal error, unit will not be started.");
                        if (r < 0)
                                return r;
                }
        }

        /* Call merge_by_names with the name derived from the fragment path as the preferred name.
         *
         * We do the merge dance here because for some unit types, the unit might have aliases which are not
         * declared in the file system. In particular, this is true (and frequent) for device and swap units.
         */
        const char *id = u->id;
        _cleanup_free_ char *filename = NULL, *free_id = NULL;

        if (fragment) {
                r = path_extract_filename(fragment, &filename);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract filename from fragment '%s': %m", fragment);
                id = filename;

                if (unit_name_is_valid(id, UNIT_NAME_TEMPLATE)) {
                        assert(u->instance); /* If we're not trying to use a template for non-instanced unit,
                                              * this must be set. */

                        r = unit_name_replace_instance(id, u->instance, &free_id);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to build id (%s + %s): %m", id, u->instance);
                        id = free_id;
                }
        }

        return merge_by_names(u, names, id);
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
                { config_parse_si_uint64,             "SIZE" },
                { config_parse_bool,                  "BOOLEAN" },
                { config_parse_string,                "STRING" },
                { config_parse_path,                  "PATH" },
                { config_parse_unit_path_printf,      "PATH" },
                { config_parse_colon_separated_paths, "PATH" },
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
                { config_parse_service_exit_type,     "SERVICEEXITTYPE" },
                { config_parse_service_restart,       "SERVICERESTART" },
                { config_parse_service_restart_mode,  "SERVICERESTARTMODE" },
                { config_parse_service_timeout_failure_mode, "TIMEOUTMODE" },
                { config_parse_kill_mode,             "KILLMODE" },
                { config_parse_signal,                "SIGNAL" },
                { config_parse_socket_listen,         "SOCKET [...]" },
                { config_parse_socket_bind,           "SOCKETBIND" },
                { config_parse_socket_bindtodevice,   "NETWORKINTERFACE" },
                { config_parse_sec,                   "SECONDS" },
                { config_parse_nsec,                  "NANOSECONDS" },
                { config_parse_namespace_path_strv,   "PATH [...]" },
                { config_parse_bind_paths,            "PATH[:PATH[:OPTIONS]] [...]" },
                { config_parse_unit_mounts_for,       "PATH [...]" },
                { config_parse_exec_mount_propagation_flag,
                                                      "MOUNTFLAG" },
                { config_parse_unit_string_printf,    "STRING" },
                { config_parse_trigger_unit,          "UNIT" },
                { config_parse_timer,                 "TIMER" },
                { config_parse_path_spec,             "PATH" },
                { config_parse_notify_access,         "ACCESS" },
                { config_parse_ip_tos,                "TOS" },
                { config_parse_unit_condition_path,   "CONDITION" },
                { config_parse_unit_condition_string, "CONDITION" },
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
                { config_parse_syscall_log,           "SYSCALLS" },
                { config_parse_address_families,      "FAMILIES" },
                { config_parse_restrict_namespaces,   "NAMESPACES"  },
#endif
                { config_parse_restrict_filesystems,  "FILESYSTEMS"  },
                { config_parse_cpu_shares,            "SHARES" },
                { config_parse_cg_weight,             "WEIGHT" },
                { config_parse_cg_cpu_weight,         "CPUWEIGHT" },
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
                { config_parse_log_filter_patterns,   "REGEX" },
        };

        const char *prev = NULL;

        assert(f);

        NULSTR_FOREACH(i, load_fragment_gperf_nulstr) {
                const char *rvalue = "OTHER", *lvalue;
                const ConfigPerfItem *p;
                const char *dot;

                assert_se(p = load_fragment_gperf_lookup(i, strlen(i)));

                /* Hide legacy settings */
                if (p->parse == config_parse_warn_compat &&
                    p->ltype == DISABLED_LEGACY)
                        continue;

                for (size_t j = 0; j < ELEMENTSOF(table); j++)
                        if (p->parse == table[j].callback) {
                                rvalue = table[j].rvalue;
                                break;
                        }

                dot = strchr(i, '.');
                lvalue = dot ? dot + 1 : i;

                if (dot) {
                        size_t prefix_len = dot - i;

                        if (!prev || !strneq(prev, i, prefix_len+1)) {
                                if (prev)
                                        fputc('\n', f);

                                fprintf(f, "[%.*s]\n", (int) prefix_len, i);
                        }
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

        CPUSet *affinity = ASSERT_PTR(data);

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
        ShowStatus *b = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        k = parse_show_status(rvalue, b);
        if (k < 0)
                log_syntax(unit, LOG_WARNING, filename, line, k, "Failed to parse show status setting, ignoring: %s", rvalue);

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

        ExecOutput t, *eo = ASSERT_PTR(data);
        bool obsolete = false;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "syslog")) {
                t = EXEC_OUTPUT_JOURNAL;
                obsolete = true;
        } else if (streq(rvalue, "syslog+console")) {
                t = EXEC_OUTPUT_JOURNAL_AND_CONSOLE;
                obsolete = true;
        } else {
                t = exec_output_from_string(rvalue);
                if (t < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, t, "Failed to parse output type, ignoring: %s", rvalue);
                        return 0;
                }

                if (IN_SET(t, EXEC_OUTPUT_SOCKET, EXEC_OUTPUT_NAMED_FD, EXEC_OUTPUT_FILE, EXEC_OUTPUT_FILE_APPEND, EXEC_OUTPUT_FILE_TRUNCATE)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Standard output types socket, fd:, file:, append:, truncate: are not supported as defaults, ignoring: %s", rvalue);
                        return 0;
                }
        }

        if (obsolete)
                log_syntax(unit, LOG_NOTICE, filename, line, 0,
                           "Standard output type %s is obsolete, automatically updating to %s. Please update your configuration.",
                           rvalue, exec_output_to_string(t));

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
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse CrashChangeVT= setting, ignoring: %s", rvalue);

        return 0;
}

int config_parse_swap_priority(
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

        Swap *s = ASSERT_PTR(userdata);
        int r, priority;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                s->parameters_fragment.priority = -1;
                s->parameters_fragment.priority_set = false;
                return 0;
        }

        r = safe_atoi(rvalue, &priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid swap priority '%s', ignoring.", rvalue);
                return 0;
        }

        if (priority < -1) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Sorry, swap priorities smaller than -1 may only be assigned by the kernel itself, ignoring: %s", rvalue);
                return 0;
        }

        if (priority > 32767) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Swap priority out of range, ignoring: %s", rvalue);
                return 0;
        }

        s->parameters_fragment.priority = priority;
        s->parameters_fragment.priority_set = true;
        return 0;
}

int config_parse_watchdog_sec(
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* This is called for {Runtime,Reboot,KExec}WatchdogSec= where "default" maps to
         * USEC_INFINITY internally. */

        if (streq(rvalue, "default"))
                *usec = USEC_INFINITY;
        else if (streq(rvalue, "off"))
                *usec = 0;
        else
                return config_parse_sec(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);

        return 0;
}

int config_parse_tty_size(
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

        unsigned *sz = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *sz = UINT_MAX;
                return 0;
        }

        return config_parse_unsigned(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
}

int config_parse_log_filter_patterns(
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

        ExecContext *c = ASSERT_PTR(data);
        const char *pattern = ASSERT_PTR(rvalue);
        bool is_allowlist = true;
        int r;

        assert(filename);
        assert(lvalue);

        if (isempty(pattern)) {
                /* Empty assignment resets the lists. */
                c->log_filter_allowed_patterns = set_free_free(c->log_filter_allowed_patterns);
                c->log_filter_denied_patterns = set_free_free(c->log_filter_denied_patterns);
                return 0;
        }

        if (pattern[0] == '~') {
                is_allowlist = false;
                pattern++;
                if (isempty(pattern))
                        /* LogFilterPatterns=~ is not considered a valid pattern. */
                        return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                          "Regex pattern invalid, ignoring: %s=%s", lvalue, rvalue);
        }

        if (pattern_compile_and_log(pattern, 0, NULL) < 0)
                return 0;

        r = set_put_strdup(is_allowlist ? &c->log_filter_allowed_patterns : &c->log_filter_denied_patterns,
                           pattern);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store log filtering pattern, ignoring: %s=%s", lvalue, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_open_file(
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

        _cleanup_(open_file_freep) OpenFile *of = NULL;
        OpenFile **head = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                open_file_free_many(head);
                return 0;
        }

        r = open_file_parse(rvalue, &of);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse OpenFile= setting, ignoring: %s", rvalue);
                return 0;
        }

        LIST_APPEND(open_files, *head, TAKE_PTR(of));

        return 0;
}

int config_parse_cgroup_nft_set(
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

        CGroupContext *c = ASSERT_PTR(data);
        Unit *u = ASSERT_PTR(userdata);

        return config_parse_nft_set(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &c->nft_set_context, u);
}
