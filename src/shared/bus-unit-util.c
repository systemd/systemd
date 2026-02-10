/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <paths.h>
#include <sys/mount.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "capability-list.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "condition.h"
#include "constants.h"
#include "coredump-util.h"
#include "cpu-set-util.h"
#include "escape.h"
#include "exec-util.h"
#include "exit-status.h"
#include "extract-word.h"
#include "firewall-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "install.h"
#include "ioprio-util.h"
#include "ip-protocol-list.h"
#include "log.h"
#include "mountpoint-util.h"
#include "nsflags.h"
#include "numa-util.h"
#include "open-file.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "time-util.h"
#include "unit-def.h"

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u) {
        assert(message);
        assert(u);

        u->machine = NULL;

        return sd_bus_message_read(
                        message,
                        "(ssssssouso)",
                        &u->id,
                        &u->description,
                        &u->load_state,
                        &u->active_state,
                        &u->sub_state,
                        &u->following,
                        &u->unit_path,
                        &u->job_id,
                        &u->job_type,
                        &u->job_path);
}

static int warn_deprecated(_unused_ sd_bus_message *m, const char *field, const char *eq) {
        log_warning("D-Bus property %s is deprecated, ignoring assignment: %s=%s", field, field, eq);
        return 1;
}

static int parse_log_error(int error, const char *field, const char *eq) {
        if (error == -ENOMEM)
                return log_oom();
        if (error != 0)  /* Allow SYNTHETIC_ERRNO to be used, i.e. positive values. */
                return log_error_errno(error, "Failed to parse %s= value '%s': %m", field, eq);

        /* We don't log the error value for cases where we have a general "syntax error". */
        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Invalid syntax for %s= value: '%s'", field, eq);
}

#define DEFINE_BUS_APPEND_PARSE_PTR(bus_type, cast_type, type, parse_func) \
        static int bus_append_##parse_func(                             \
                        sd_bus_message *m,                              \
                        const char *field,                              \
                        const char *eq) {                               \
                type val;                                               \
                int r;                                                  \
                                                                        \
                r = parse_func(eq, &val);                               \
                if (r < 0)                                              \
                        return parse_log_error(r, field, eq);           \
                                                                        \
                r = sd_bus_message_append(m, "(sv)", field,             \
                                          bus_type, (cast_type) val);   \
                if (r < 0)                                              \
                        return bus_log_create_error(r);                 \
                                                                        \
                return 1;                                               \
        }

#define DEFINE_BUS_APPEND_PARSE(bus_type, parse_func)                   \
        static int bus_append_##parse_func(                             \
                        sd_bus_message *m,                              \
                        const char *field,                              \
                        const char *eq) {                               \
                int r;                                                  \
                                                                        \
                r = parse_func(eq);                                     \
                if (r < 0)                                              \
                        return parse_log_error(r, field, eq);           \
                                                                        \
                r = sd_bus_message_append(m, "(sv)", field,             \
                                          bus_type, (int32_t) r);       \
                if (r < 0)                                              \
                        return bus_log_create_error(r);                 \
                                                                        \
                return 1;                                               \
        }

DEFINE_BUS_APPEND_PARSE("b", parse_boolean);
DEFINE_BUS_APPEND_PARSE("i", ioprio_class_from_string);
DEFINE_BUS_APPEND_PARSE("i", ip_tos_from_string);
DEFINE_BUS_APPEND_PARSE("i", log_facility_unshifted_from_string);
DEFINE_BUS_APPEND_PARSE("i", log_level_from_string);
DEFINE_BUS_APPEND_PARSE("i", seccomp_parse_errno_or_action);
DEFINE_BUS_APPEND_PARSE("i", sched_policy_from_string);
DEFINE_BUS_APPEND_PARSE("i", secure_bits_from_string);
DEFINE_BUS_APPEND_PARSE("i", signal_from_string);
DEFINE_BUS_APPEND_PARSE("i", parse_ip_protocol);
DEFINE_BUS_APPEND_PARSE("i", mpol_from_string);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, ioprio_parse_priority);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, parse_nice);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, safe_atoi);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, nsec_t, parse_nsec);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_weight_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_cpu_weight_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, unsigned long, mount_propagation_flag_from_string);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, safe_atou64);
DEFINE_BUS_APPEND_PARSE_PTR("u", uint32_t, mode_t, parse_mode);
DEFINE_BUS_APPEND_PARSE_PTR("u", uint32_t, unsigned, safe_atou);
DEFINE_BUS_APPEND_PARSE_PTR("x", int64_t, int64_t, safe_atoi64);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, coredump_filter_mask_from_string);

static int bus_append_string(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = sd_bus_message_append(m, "(sv)", field, "s", eq);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_strv_full(sd_bus_message *m, const char *field, const char *eq, const char *separators, ExtractFlags flags) {
        int r;

        assert(m);
        assert(field);

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 's', field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "as");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return bus_log_create_error(r);

        for (const char *p = eq;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, separators, flags);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                r = sd_bus_message_append_basic(m, 's', word);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_strv(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_strv_full(m, field, eq, /* separators= */ NULL, EXTRACT_UNQUOTE);
}

static int bus_append_strv_cunescape(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_strv_full(m, field, eq, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE);
}

static int bus_append_strv_colon(sd_bus_message *m, const char *field, const char *eq) {
        /* This also accepts colon as the separator. */
        return bus_append_strv_full(m, field, eq, ":" WHITESPACE, EXTRACT_UNQUOTE);
}

static int bus_append_byte_array(sd_bus_message *m, const char *field, const void *buf, size_t n) {
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "ay");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_array(m, 'y', buf, n);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_sec_rename(sd_bus_message *m, const char *field, const char *eq) {
        char *n;
        usec_t t;
        size_t l;
        int r;

        r = parse_sec(eq, &t);
        if (r < 0)
                return parse_log_error(r, field, eq);

        l = strlen(field);
        n = newa(char, l + 2);
        /* Change suffix Sec → USec */
        strcpy(mempcpy(n, field, l - 3), "USec");

        r = sd_bus_message_append(m, "(sv)", n, "t", t);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_sec_rename_infinity(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_parse_sec_rename(m, field, isempty(eq) ? "infinity" : eq);
}

static int bus_append_parse_size(sd_bus_message *m, const char *field, const char *eq) {
        uint64_t v;
        int r;

        r = parse_size(eq, /* base= */ 1024, &v);
        if (r < 0)
                return parse_log_error(r, field, eq);

        r = sd_bus_message_append(m, "(sv)", field, "t", v);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_permyriad(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = parse_permyriad(eq);
        if (r < 0)
                return parse_log_error(r, field, eq);

        /* Pass around scaled to 2^32-1 == 100% */
        r = sd_bus_message_append(m, "(sv)", field, "u", UINT32_SCALE_FROM_PERMYRIAD(r));
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_cpu_set(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_(cpu_set_done) CPUSet cpuset = {};
        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;
        int r;

        r = parse_cpu_set(eq, &cpuset);
        if (r < 0)
                return parse_log_error(r, field, eq);

        r = cpu_set_to_dbus(&cpuset, &array, &allocated);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize %s: %m", field);

        return bus_append_byte_array(m, field, array, allocated);
}

static int bus_append_parse_delegate(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = parse_boolean(eq);
        if (r < 0)
                return bus_append_strv(m, "DelegateControllers", eq);

        r = sd_bus_message_append(m, "(sv)", "Delegate", "b", r);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_resource_limit(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq) || streq(eq, "infinity")) {
                uint64_t x = streq(eq, "infinity") ? CGROUP_LIMIT_MAX :
                        STR_IN_SET(field,
                                   "MemoryLow",
                                   "MemoryMin") ? CGROUP_LIMIT_MIN : CGROUP_LIMIT_MAX;

                r = sd_bus_message_append(m, "(sv)", field, "t", x);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        r = parse_permyriad(eq);
        if (r >= 0) {
                char *n;

                /* When this is a percentage we'll convert this into a relative value in the range
                 * 0…UINT32_MAX and pass it in the MemoryLowScale property (and related ones). This
                 * way the physical memory size can be determined server-side. */

                n = strjoina(field, "Scale");
                r = sd_bus_message_append(m, "(sv)", n, "u", UINT32_SCALE_FROM_PERMYRIAD(r));
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "TasksMax"))
                return bus_append_safe_atou64(m, field, eq);

        return bus_append_parse_size(m, field, eq);
}

static int bus_append_parse_cpu_quota(sd_bus_message *m, const char *field, const char *eq) {
        uint64_t x;
        int r;

        if (isempty(eq))
                x = USEC_INFINITY;
        else {
                r = parse_permyriad_unbounded(eq);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        return parse_log_error(SYNTHETIC_ERRNO(ERANGE), field, eq);
                x = r * USEC_PER_SEC / 10000U;
        }

        r = sd_bus_message_append(m, "(sv)", "CPUQuotaPerSecUSec", "t", x);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_device_allow(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 0);
        else {
                _cleanup_free_ char *_path = NULL;
                const char *path = eq, *rwm = NULL, *e;

                e = strchr(eq, ' ');
                if (e) {
                        path = _path = strndup(eq, e - eq);
                        if (!path)
                                return log_oom();

                        rwm = e + 1;
                }

                r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 1, path, strempty(rwm));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_try_append_parse_cgroup_io_limit(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (cgroup_io_limit_type_from_string(field) < 0)
                return 0;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "a(st)", 0);
        else {
                const char *e = strchr(eq, ' ');
                if (!e)
                        return parse_log_error(0, field, eq);

                const char *bandwidth = e + 1;
                _cleanup_free_ char *path = strndup(eq, e - eq);
                if (!path)
                        return log_oom();

                uint64_t bytes;
                if (streq(bandwidth, "infinity"))
                        bytes = CGROUP_LIMIT_MAX;
                else {
                        r = parse_size(bandwidth, 1000, &bytes);
                        if (r < 0)
                                return parse_log_error(r, field, eq);
                }

                r = sd_bus_message_append(m, "(sv)", field, "a(st)", 1, path, bytes);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_io_device_weight(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "a(st)", 0);
        else {
                const char *e = strchr(eq, ' ');
                if (!e)
                        return parse_log_error(0, field, eq);

                const char *weight = e + 1;
                _cleanup_free_ char *path = strndup(eq, e - eq);
                if (!path)
                        return log_oom();

                uint64_t u;
                r = safe_atou64(weight, &u);
                if (r < 0)
                        return parse_log_error(r, field, weight);

                r = sd_bus_message_append(m, "(sv)", field, "a(st)", 1, path, u);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_io_device_latency(sd_bus_message *m, const char *field, const char *eq) {
        const char *field_usec = "IODeviceLatencyTargetUSec";
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field_usec, "a(st)", 0);
        else {
                const char *e = strchr(eq, ' ');
                if (!e)
                        return parse_log_error(0, field, eq);

                const char *target = e + 1;
                _cleanup_free_ char *path = strndup(eq, e - eq);
                if (!path)
                        return log_oom();

                usec_t usec;
                r = parse_sec(target, &usec);
                if (r < 0)
                        return parse_log_error(r, field, target);

                r = sd_bus_message_append(m, "(sv)", field_usec, "a(st)", 1, path, usec);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_bpf_program(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 0);
        else {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&eq, &word, ":", 0);
                if (r < 0)
                        return parse_log_error(r, field, eq);

                r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 1, word, eq);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_socket_filter(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "a(iiqq)", 0);
        else {
                int32_t family, ip_protocol;
                uint16_t nr_ports, port_min;

                r = parse_socket_bind_item(eq, &family, &ip_protocol, &nr_ports, &port_min);
                if (r < 0)
                        return parse_log_error(r, field, eq);

                r = sd_bus_message_append(
                                m, "(sv)", field, "a(iiqq)", 1, family, ip_protocol, nr_ports, port_min);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_exec_command(sd_bus_message *m, const char *field, const char *eq) {
        bool explicit_path = false, done = false, ambient_hack = false;
        _cleanup_strv_free_ char **cmdline = NULL, **ex_opts = NULL;
        _cleanup_free_ char *_path = NULL;
        ExecCommandFlags flags = 0;
        int r;

        do {
                switch (*eq) {

                case '-':
                        if (FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE))
                                done = true;
                        else {
                                flags |= EXEC_COMMAND_IGNORE_FAILURE;
                                eq++;
                        }
                        break;

                case '@':
                        if (explicit_path)
                                done = true;
                        else {
                                explicit_path = true;
                                eq++;
                        }
                        break;

                case ':':
                        if (FLAGS_SET(flags, EXEC_COMMAND_NO_ENV_EXPAND))
                                done = true;
                        else {
                                flags |= EXEC_COMMAND_NO_ENV_EXPAND;
                                eq++;
                        }
                        break;

                case '+':
                        if ((flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID)) != 0 || ambient_hack)
                                done = true;
                        else {
                                flags |= EXEC_COMMAND_FULLY_PRIVILEGED;
                                eq++;
                        }
                        break;

                case '!':
                        if (FLAGS_SET(flags, EXEC_COMMAND_FULLY_PRIVILEGED) || ambient_hack)
                                done = true;
                        else if (FLAGS_SET(flags, EXEC_COMMAND_NO_SETUID)) {
                                /* Compatibility with the old !! ambient caps hack (removed in v258). Since
                                 * we don't support that anymore and !! was a noop on non-supporting systems,
                                 * we'll just turn off the EXEC_COMMAND_NO_SETUID flag again and be done with
                                 * it. */
                                flags &= ~EXEC_COMMAND_NO_SETUID;
                                eq++;
                                ambient_hack = true;

                                log_notice("!! modifier for %s= fields is no longer supported and is now ignored.", field);
                        } else {
                                flags |= EXEC_COMMAND_NO_SETUID;
                                eq++;
                        }
                        break;

                case '|':
                        if (FLAGS_SET(flags, EXEC_COMMAND_VIA_SHELL))
                                done = true;
                        else {
                                flags |= EXEC_COMMAND_VIA_SHELL;
                                eq++;
                        }
                        break;

                default:
                        done = true;
                }
        } while (!done);

        bool ex_prop = flags & (EXEC_COMMAND_NO_ENV_EXPAND|EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID|EXEC_COMMAND_VIA_SHELL);
        if (ex_prop) {
                /* We need to use ExecXYZEx=. */
                if (!endswith(field, "Ex"))
                        field = strjoina(field, "Ex");

                r = exec_command_flags_to_strv(flags, &ex_opts);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize ExecCommand flags: %m");
        } else {
                if (endswith(field, "Ex"))
                        field = strndupa_safe(field, strlen(field) - 2);
        }

        const char *path = NULL;
        if (FLAGS_SET(flags, EXEC_COMMAND_VIA_SHELL))
                path = _PATH_BSHELL;
        else if (explicit_path) {
                r = extract_first_word(&eq, &_path, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No executable path specified for %s=, refusing.", field);
                if (isempty(eq))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Got empty command line for %s=, refusing.", field);
                path = _path;
        }

        r = strv_split_full(&cmdline, eq, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE);
        if (r < 0)
                return parse_log_error(r, field, eq);

        if (FLAGS_SET(flags, EXEC_COMMAND_VIA_SHELL)) {
                r = strv_prepend(&cmdline, explicit_path ? "-sh" : "sh");
                if (r < 0)
                        return log_oom();
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', ex_prop ? "a(sasas)" : "a(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', ex_prop ? "(sasas)" : "(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        if (!strv_isempty(cmdline)) {
                r = sd_bus_message_open_container(m, 'r', ex_prop ? "sasas" : "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", path ?: cmdline[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, cmdline);
                if (r < 0)
                        return bus_log_create_error(r);

                r = ex_prop ? sd_bus_message_append_strv(m, ex_opts) :
                              sd_bus_message_append(m, "b", FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE));
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_open_file(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        assert(m);

        r = open_file_parse(eq, &of);
        if (r < 0)
                return parse_log_error(r, field, eq);

        r = sd_bus_message_append(m, "(sv)", field, "a(sst)", (size_t) 1, of->path, of->fdname, of->flags);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_ip_address_access(sd_bus_message *m, int family, const union in_addr_union *prefix, unsigned char prefixlen) {
        int r;

        assert(m);
        assert(prefix);

        r = sd_bus_message_open_container(m, 'r', "iayu");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "i", family);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(m, 'y', prefix, FAMILY_ADDRESS_SIZE(family));
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "u", prefixlen);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(m);
}

static int bus_append_parse_ip_address_filter(sd_bus_message *m, const char *field, const char *eq) {
        union in_addr_union prefix = {};
        unsigned char prefixlen;
        int family, r;

        if (isempty(eq)) {
                r = sd_bus_message_append(m, "(sv)", field, "a(iayu)", 0);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(iayu)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(iayu)");
        if (r < 0)
                return bus_log_create_error(r);

        if (streq(eq, "any")) {
                /* "any" is a shortcut for 0.0.0.0/0 and ::/0 */

                r = bus_append_ip_address_access(m, AF_INET, &prefix, 0);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_append_ip_address_access(m, AF_INET6, &prefix, 0);
                if (r < 0)
                        return bus_log_create_error(r);

        } else if (is_localhost(eq)) {
                /* "localhost" is a shortcut for 127.0.0.0/8 and ::1/128 */

                prefix.in.s_addr = htobe32(0x7f000000);
                r = bus_append_ip_address_access(m, AF_INET, &prefix, 8);
                if (r < 0)
                        return bus_log_create_error(r);

                prefix.in6 = (struct in6_addr) IN6ADDR_LOOPBACK_INIT;
                r = bus_append_ip_address_access(m, AF_INET6, &prefix, 128);
                if (r < 0)
                        return r;

        } else if (streq(eq, "link-local")) {
                /* "link-local" is a shortcut for 169.254.0.0/16 and fe80::/64 */

                prefix.in.s_addr = htobe32((UINT32_C(169) << 24 | UINT32_C(254) << 16));
                r = bus_append_ip_address_access(m, AF_INET, &prefix, 16);
                if (r < 0)
                        return bus_log_create_error(r);

                prefix.in6 = (struct in6_addr) {
                        .s6_addr32[0] = htobe32(0xfe800000)
                };
                r = bus_append_ip_address_access(m, AF_INET6, &prefix, 64);
                if (r < 0)
                        return bus_log_create_error(r);

        } else if (streq(eq, "multicast")) {
                /* "multicast" is a shortcut for 224.0.0.0/4 and ff00::/8 */

                prefix.in.s_addr = htobe32((UINT32_C(224) << 24));
                r = bus_append_ip_address_access(m, AF_INET, &prefix, 4);
                if (r < 0)
                        return bus_log_create_error(r);

                prefix.in6 = (struct in6_addr) {
                        .s6_addr32[0] = htobe32(0xff000000)
                };
                r = bus_append_ip_address_access(m, AF_INET6, &prefix, 8);
                if (r < 0)
                        return bus_log_create_error(r);

        } else
                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&eq, &word, NULL, 0);
                        if (r < 0)
                                return parse_log_error(r, field, eq);
                        if (r == 0)
                                break;

                        r = in_addr_prefix_from_string_auto(word, &family, &prefix, &prefixlen);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IP address prefix '%s': %m", word);

                        r = bus_append_ip_address_access(m, family, &prefix, prefixlen);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

#define bus_append_trivial_array(m, field, eq, types, ...)              \
        ({                                                              \
                int r;                                                  \
                                                                        \
                if (isempty(eq))                                        \
                        r = sd_bus_message_append(m, "(sv)", field, types, 0); \
                else                                                    \
                        r = sd_bus_message_append(m, "(sv)", field, types, 1, __VA_ARGS__); \
                r < 0 ? bus_log_create_error(r) : 1;                    \
        })

static int bus_append_ip_filter_path(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_trivial_array(m, field, eq,
                                        "as", eq);
}

static int bus_append_nft_set(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        assert(m);
        assert(field);
        assert(eq);

        if (isempty(eq)) {
                r = sd_bus_message_append(m, "(sv)", field, "a(iiss)", 0);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(iiss)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(iiss)");
        if (r < 0)
                return bus_log_create_error(r);

        for (const char *p = eq;;) {
                _cleanup_free_ char *tuple = NULL, *source_str = NULL, *nfproto_str = NULL, *table = NULL, *set = NULL;
                const char *q = NULL;
                int source, nfproto;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;
                if (isempty(tuple))
                        return parse_log_error(0, field, eq);

                q = tuple;
                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE, &source_str, &nfproto_str, &table, &set);
                if (r != 4 || !isempty(q))
                        return parse_log_error(0, field, tuple);

                assert(source_str);
                assert(nfproto_str);
                assert(table);
                assert(set);

                source = r = nft_set_source_from_string(source_str);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse NFT set source '%s': %m", source_str);
                if (!IN_SET(source, NFT_SET_SOURCE_CGROUP, NFT_SET_SOURCE_USER, NFT_SET_SOURCE_GROUP))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad NFT set source value '%s'.",
                                               nft_set_source_to_string(source));

                nfproto = r = nfproto_from_string(nfproto_str);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse nft protocol '%s': %m", nfproto_str);

                if (!nft_identifier_valid(table))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad NFT identifier name '%s'.", table);
                if (!nft_identifier_valid(set))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad NFT identifier name '%s'.", set);

                r = sd_bus_message_append(m, "(iiss)", source, nfproto, table, set);
                if (r < 0)
                        return bus_log_create_error(r);
        }
        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_environment_files(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_trivial_array(m, "EnvironmentFiles", eq,
                                        "a(sb)",
                                        eq[0] == '-' ? eq + 1 : eq,
                                        eq[0] == '-');
}

static int bus_append_set_credential(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 's', field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(say)");
        if (r < 0)
                return bus_log_create_error(r);

        if (isempty(eq))
                r = sd_bus_message_append(m, "a(say)", 0);
        else {
                _cleanup_free_ char *word = NULL;
                const char *p = eq;

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r <= 0 || !p)
                        return parse_log_error(r < 0 ? r : 0, field, eq);

                r = sd_bus_message_open_container(m, 'a', "(say)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'r', "say");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", word);
                if (r < 0)
                        return bus_log_create_error(r);

                if (endswith(field, "Encrypted")) {
                        _cleanup_free_ void *decoded = NULL;
                        size_t decoded_size;

                        r = unbase64mem(p, &decoded, &decoded_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to decode base64 data for %s=: %m", field);

                        r = sd_bus_message_append_array(m, 'y', decoded, decoded_size);
                } else {
                        _cleanup_free_ char *unescaped = NULL;
                        ssize_t l;

                        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &unescaped);
                        if (l < 0)
                                return log_error_errno(l, "Failed to unescape value for %s=: %s", field, p);

                        r = sd_bus_message_append_array(m, 'y', unescaped, l);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
        }
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_load_credential(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 's', field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        if (isempty(eq))
                r = sd_bus_message_append(m, "a(ss)", 0);
        else {
                _cleanup_free_ char *word = NULL;
                const char *p = eq;

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r <= 0)
                        return parse_log_error(r, field, eq);

                if (isempty(p)) /* If only one field is specified, then this means "inherit from above" */
                        p = eq;

                r = sd_bus_message_append(m, "a(ss)", 1, word, p);
        }
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_import_credential(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", "ImportCredential", "as", 0);
        else {
                _cleanup_free_ char *word = NULL;
                const char *p = eq;

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r <= 0)
                        return parse_log_error(r, field, eq);

                if (!p)
                        r = sd_bus_message_append(m, "(sv)", "ImportCredential", "as", 1, eq);
                else {
                        /* We need to send ImportCredentialEx */
                        r = sd_bus_message_open_container(m, 'r', "sv");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append_basic(m, 's', "ImportCredentialEx");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_open_container(m, 'v', "a(ss)");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "a(ss)", 1, word, p);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_close_container(m);
                }
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_refresh_on_reload(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 's', field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(bs)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(bs)");
        if (r < 0)
                return bus_log_create_error(r);

        bool invert = *eq == '~';

        for (const char *p = eq + invert;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                r = sd_bus_message_append(m, "(bs)", invert, word);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_log_extra_fields(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 's', field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "aay");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "ay");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_array(m, 'y', eq, strlen(eq));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_log_filter_patterns(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_trivial_array(m, field, eq,
                                        "a(bs)",
                                        eq[0] != '~',
                                        eq[0] != '~' ? eq : eq + 1);
}

static int bus_append_standard_inputs(sd_bus_message *m, const char *field, const char *eq) {
        const char *n, *appended;
        int r;

        if ((n = startswith(eq, "fd:"))) {
                appended = strjoina(field, "FileDescriptorName");
                r = sd_bus_message_append(m, "(sv)", appended, "s", n);
        } else if ((n = startswith(eq, "file:"))) {
                appended = strjoina(field, "File");
                r = sd_bus_message_append(m, "(sv)", appended, "s", n);
        } else if ((n = startswith(eq, "append:"))) {
                appended = strjoina(field, "FileToAppend");
                r = sd_bus_message_append(m, "(sv)", appended, "s", n);
        } else if ((n = startswith(eq, "truncate:"))) {
                appended = strjoina(field, "FileToTruncate");
                r = sd_bus_message_append(m, "(sv)", appended, "s", n);
        } else
                r = sd_bus_message_append(m, "(sv)", field, "s", eq);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_standard_input_text(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_free_ char *unescaped = NULL;
        ssize_t l;

        l = cunescape(eq, 0, &unescaped);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape value for %s=: %s", field, eq);

        if (!strextend(&unescaped, "\n"))
                return log_oom();

        /* Note that we don't expand specifiers here, but that should be OK, as this is a
         * programmatic interface anyway */

        /* The server side does not have StandardInputText, using StandardInputData instead. */
        return bus_append_byte_array(m, "StandardInputData", unescaped, l + 1);
}

static int bus_append_standard_input_data(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_free_ void *decoded = NULL;
        size_t sz;
        int r;

        r = unbase64mem(eq, &decoded, &sz);
        if (r < 0)
                return log_error_errno(r, "Failed to decode base64 data for %s=: %m", field);

        return bus_append_byte_array(m, field, decoded, sz);
}

static int bus_try_append_resource_limit(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        const char *suffix = startswith(field, "Limit");
        if (!suffix)
                return 0;

        int rl = rlimit_from_string(suffix);
        if (rl < 0)
                return 0;  /* We let the generic error machinery handle this. */

        struct rlimit l;
        r = rlimit_parse(rl, eq, &l);
        if (r < 0)
                return parse_log_error(r, field, eq);

        r = sd_bus_message_append(m, "(sv)", field, "t", (uint64_t) l.rlim_max);
        if (r < 0)
                return bus_log_create_error(r);

        const char *sn = strjoina(field, "Soft");
        r = sd_bus_message_append(m, "(sv)", sn, "t", (uint64_t) l.rlim_cur);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static void dump_resource_limits(void) {
        rlimits_list("Limit");
}

static int bus_append_string_with_ignore(sd_bus_message *m, const char *field, const char *eq) {
        int ignore = 0;
        const char *s = eq;
        int r;

        if (eq[0] == '-') {
                ignore = 1;
                s = eq + 1;
        }

        r = sd_bus_message_append(m, "(sv)", field, "(bs)", ignore, s);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_capabilities(sd_bus_message *m, const char *field, const char *eq) {
        uint64_t sum = 0;
        bool invert = false;
        const char *p = eq;
        int r;

        if (*p == '~') {
                invert = true;
                p++;
        }

        r = capability_set_from_string(p, &sum);
        if (r < 0)
                return parse_log_error(r, field, eq);

        sum = invert ? ~sum : sum;

        r = sd_bus_message_append(m, "(sv)", field, "t", sum);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_cpu_affinity(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (streq_ptr(eq, "numa")) {
                r = sd_bus_message_append(m, "(sv)", "CPUAffinityFromNUMA", "b", true);
                if (r < 0)
                        return bus_log_create_error(r);
                return r;
        }

        return bus_append_parse_cpu_set(m, field, eq);
}

static int bus_append_numa_mask(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_(cpu_set_done) CPUSet nodes = {};
        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;
        int r;

        if (eq && streq(eq, "all")) {
                r = numa_mask_add_all(&nodes);
                if (r < 0)
                        return log_error_errno(r, "Failed to create NUMA mask representing \"all\" NUMA nodes: %m");
        } else {
                r = parse_cpu_set(eq, &nodes);
                if (r < 0)
                        return parse_log_error(r, field, eq);
        }

        r = cpu_set_to_dbus(&nodes, &array, &allocated);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize %s: %m", field);

        return bus_append_byte_array(m, field, array, allocated);
}

static int bus_append_filter_list(sd_bus_message *m, const char *field, const char *eq) {
        int allow_list = 1;
        const char *p = eq;
        int r;

        if (*p == '~') {
                allow_list = 0;
                p++;
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "(bas)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'r', "bas");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, 'b', &allow_list);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return bus_log_create_error(r);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                r = sd_bus_message_append_basic(m, 's', word);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_namespace_list(sd_bus_message *m, const char *field, const char *eq) {
        bool invert = false;
        unsigned long all = UPDATE_FLAG(NAMESPACE_FLAGS_ALL, CLONE_NEWUSER, !streq(field, "DelegateNamespaces"));
        unsigned long flags;
        int r;

        r = parse_boolean(eq);
        if (r > 0)
                /* RestrictNamespaces= value gets stored into a field with reverse semantics (the
                 * namespaces which are retained), so RestrictNamespaces=true means we retain no
                 * access to any namespaces and vice-versa. */
                flags = streq(field, "RestrictNamespaces") ? 0 : all;
        else if (r == 0)
                flags = streq(field, "RestrictNamespaces") ? all : 0;
        else {
                if (eq[0] == '~') {
                        invert = true;
                        eq++;
                }

                r = namespace_flags_from_string(eq, &flags);
                if (r < 0)
                        return parse_log_error(r, field, eq);
        }

        if (invert)
                flags = (~flags) & all;

        r = sd_bus_message_append(m, "(sv)", field, "t", (uint64_t) flags);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_bind_paths(sd_bus_message *m, const char *field, const char *eq) {
        const char *p = eq;
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(ssbt)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(ssbt)");
        if (r < 0)
                return bus_log_create_error(r);

        for (;;) {
                _cleanup_free_ char *source = NULL, *destination = NULL;
                char *s = NULL, *d = NULL;
                bool ignore_enoent = false;
                uint64_t flags = MS_REC;

                r = extract_first_word(&p, &source, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                s = source;
                if (s[0] == '-') {
                        ignore_enoent = true;
                        s++;
                }

                if (p && p[-1] == ':') {
                        r = extract_first_word(&p, &destination, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return parse_log_error(r, field, p);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Missing argument after ':': %s", eq);

                        d = destination;

                        if (p && p[-1] == ':') {
                                _cleanup_free_ char *options = NULL;

                                r = extract_first_word(&p, &options, NULL, EXTRACT_UNQUOTE);
                                if (r < 0)
                                        return parse_log_error(r, field, p);

                                if (isempty(options) || streq(options, "rbind"))
                                        flags = MS_REC;
                                else if (streq(options, "norbind"))
                                        flags = 0;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unknown options: %s", eq);
                        }
                } else
                        d = s;

                r = sd_bus_message_append(m, "(ssbt)", s, d, ignore_enoent, flags);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_temporary_file_system(sd_bus_message *m, const char *field, const char *eq) {
        const char *p = eq;
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        for (;;) {
                _cleanup_free_ char *word = NULL, *path = NULL;
                const char *w;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                w = word;
                r = extract_first_word(&w, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r <= 0)
                        return parse_log_error(r, field, eq);

                r = sd_bus_message_append(m, "(ss)", path, w);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_root_hash(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_free_ void *roothash_decoded = NULL;
        size_t roothash_decoded_size = 0;
        int r;

        /* We have the path to a roothash to load and decode, eg: RootHash=/foo/bar.roothash */
        if (path_is_absolute(eq))
                return bus_append_string(m, "RootHashPath", eq);

        /* We have a roothash to decode, eg: RootHash=012345789abcdef */
        r = unhexmem(eq, &roothash_decoded, &roothash_decoded_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode base64 data for %s=: %m", field);
        if (roothash_decoded_size < sizeof(sd_id128_t))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s value '%s' is too short.", field, eq);

        return bus_append_byte_array(m, field, roothash_decoded, roothash_decoded_size);
}

static int bus_append_root_hash_signature(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_free_ void *roothash_sig_decoded = NULL;
        size_t roothash_sig_decoded_size = 0;
        int r;

        /* We have the path to a roothash signature to load and decode, eg: RootHash=/foo/bar.roothash.p7s */
        if (path_is_absolute(eq))
                return bus_append_string(m, "RootHashSignaturePath", eq);

        const char *value = startswith(eq, "base64:");
        if (!value)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to decode %s value '%s': neither a path nor starts with 'base64:'.",
                                       field, eq);

        /* We have a roothash signature to decode, eg: RootHashSignature=base64:012345789abcdef */
        r = unbase64mem(value, &roothash_sig_decoded, &roothash_sig_decoded_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode base64 data for %s=: %m", field);

        return bus_append_byte_array(m, field, roothash_sig_decoded, roothash_sig_decoded_size);
}

static int bus_append_root_image_options(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_strv_free_ char **l = NULL;
        const char *p = eq;
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        r = strv_split_colon_pairs(&l, p);
        if (r < 0)
                return parse_log_error(r, field, eq);

        STRV_FOREACH_PAIR(first, second, l) {
                r = sd_bus_message_append(m, "(ss)",
                                          !isempty(*second) ? *first : "root",
                                          !isempty(*second) ? *second : *first);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_mount_images(sd_bus_message *m, const char *field, const char *eq) {
        const char *p = eq;
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(ssba(ss))");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(ssba(ss))");
        if (r < 0)
                return bus_log_create_error(r);

        for (;;) {
                _cleanup_free_ char *first = NULL, *second = NULL, *tuple = NULL;
                const char *q = NULL, *source = NULL;
                bool permissive = false;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                q = tuple;
                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &first, &second);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        continue;

                source = first;
                if (source[0] == '-') {
                        permissive = true;
                        source++;
                }

                if (isempty(second))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Missing argument after ':' for %s=: '%s'", field, eq);

                r = sd_bus_message_open_container(m, 'r', "ssba(ss)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "ssb", source, second, permissive);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(ss)");
                if (r < 0)
                        return bus_log_create_error(r);

                for (;;) {
                        _cleanup_free_ char *partition = NULL, *mount_options = NULL;

                        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options);
                        if (r < 0)
                                return parse_log_error(r, field, eq);
                        if (r == 0)
                                break;
                        /* Single set of options, applying to the root partition/single filesystem */
                        if (r == 1) {
                                r = sd_bus_message_append(m, "(ss)", "root", partition);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                break;
                        }

                        r = sd_bus_message_append(m, "(ss)", partition, mount_options);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_extension_images(sd_bus_message *m, const char *field, const char *eq) {
        const char *p = eq;
        int r;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(sba(ss))");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sba(ss))");
        if (r < 0)
                return bus_log_create_error(r);

        for (;;) {
                _cleanup_free_ char *source = NULL, *tuple = NULL;
                const char *q = NULL, *s = NULL;
                bool permissive = false;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                q = tuple;
                r = extract_first_word(&q, &source, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        continue;

                s = source;
                if (s[0] == '-') {
                        permissive = true;
                        s++;
                }

                r = sd_bus_message_open_container(m, 'r', "sba(ss)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "sb", s, permissive);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(ss)");
                if (r < 0)
                        return bus_log_create_error(r);

                for (;;) {
                        _cleanup_free_ char *partition = NULL, *mount_options = NULL;

                        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options);
                        if (r < 0)
                                return parse_log_error(r, field, eq);
                        if (r == 0)
                                break;
                        /* Single set of options, applying to the root partition/single filesystem */
                        if (r == 1) {
                                r = sd_bus_message_append(m, "(ss)", "root", partition);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                break;
                        }

                        r = sd_bus_message_append(m, "(ss)", partition, mount_options);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_directory(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_strv_free_ char **symlinks = NULL, **symlinks_ro = NULL, **sources = NULL, **sources_ro = NULL;
        const char *p = eq;
        int r;

        /* Adding new directories is supported from both *DirectorySymlink methods and the
         * older ones, so first parse the input, and if we are given a new-style src:dst
         * tuple use the new method, else use the old one. */

        for (;;) {
                _cleanup_free_ char *tuple = NULL, *source = NULL, *dest = NULL, *flags = NULL;

                r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                const char *t = tuple;
                r = extract_many_words(&t, ":", EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS, &source, &dest, &flags);
                if (r <= 0)
                        return parse_log_error(r, field, eq);

                path_simplify(source);

                if (isempty(dest) && isempty(flags)) {
                        r = strv_consume(&sources, TAKE_PTR(source));
                        if (r < 0)
                                return bus_log_create_error(r);
                } else if (isempty(flags)) {
                        path_simplify(dest);
                        r = strv_consume_pair(&symlinks, TAKE_PTR(source), TAKE_PTR(dest));
                        if (r < 0)
                                return log_oom();
                } else {
                        ExecDirectoryFlags exec_directory_flags = exec_directory_flags_from_string(flags);
                        if (exec_directory_flags < 0 || (exec_directory_flags & ~_EXEC_DIRECTORY_FLAGS_PUBLIC) != 0)
                                return log_error_errno(r, "Failed to parse flags for %s=: '%s'", field, flags);

                        if (!isempty(dest)) {
                                path_simplify(dest);
                                r = strv_consume_pair(&symlinks_ro, TAKE_PTR(source), TAKE_PTR(dest));
                        } else
                                r = strv_consume(&sources_ro, TAKE_PTR(source));
                        if (r < 0)
                                return log_oom();
                }
        }

        if (!strv_isempty(sources)) {
                r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, sources);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        /* For State and Runtime directories we support an optional destination parameter, which
         * will be used to create a symlink to the source. But it is new so we cannot change the
         * old DBUS signatures, so append a new message type. */
        if (!strv_isempty(symlinks) || !strv_isempty(symlinks_ro) || !strv_isempty(sources_ro)) {
                const char *symlink_field;

                r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                if (streq(field, "StateDirectory"))
                        symlink_field = "StateDirectorySymlink";
                else if (streq(field, "RuntimeDirectory"))
                        symlink_field = "RuntimeDirectorySymlink";
                else if (streq(field, "CacheDirectory"))
                        symlink_field = "CacheDirectorySymlink";
                else if (streq(field, "LogsDirectory"))
                        symlink_field = "LogsDirectorySymlink";
                else
                        assert_not_reached();

                r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, symlink_field);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'v', "a(sst)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sst)");
                if (r < 0)
                        return bus_log_create_error(r);

                STRV_FOREACH_PAIR(source, destination, symlinks) {
                        r = sd_bus_message_append(m, "(sst)", *source, *destination, UINT64_C(0));
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                STRV_FOREACH_PAIR(source, destination, symlinks_ro) {
                        r = sd_bus_message_append(m, "(sst)", *source, *destination, (uint64_t) EXEC_DIRECTORY_READ_ONLY);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                STRV_FOREACH(source, sources_ro) {
                        r = sd_bus_message_append(m, "(sst)", *source, "", (uint64_t) EXEC_DIRECTORY_READ_ONLY);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 1;
}

static int bus_append_quota_directory(sd_bus_message *m, const char *field, const char *eq) {
        uint64_t quota_absolute = UINT64_MAX;
        uint32_t quota_scale = UINT32_MAX;
        int quota_enforce = false;
        int r;

        if (!isempty(eq) && !streq(eq, "off")) {
                r = parse_permyriad(eq);
                if (r < 0) {
                        r = parse_size(eq, 1024, &quota_absolute);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse argument: %s=%s", field, eq);
                } else
                        quota_scale = UINT32_SCALE_FROM_PERMYRIAD(r);

                quota_enforce = true;
        }

        r = sd_bus_message_append(m, "(sv)", field, "(tus)", quota_absolute, quota_scale, yes_no(quota_enforce));
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_protect_hostname(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        /* The command-line field is called "ProtectHostname". We also accept "ProtectHostnameEx" as the
         * field name for backward compatibility. We set ProtectHostame or ProtectHostnameEx. */

        r = parse_boolean(eq);
        if (r >= 0)
                r = sd_bus_message_append(m, "(sv)", "ProtectHostname", "b", r);
        else {
                const char *colon = strchr(eq, ':');
                if (colon) {
                        if (isempty(colon + 1))
                                return parse_log_error(0, field, eq);

                        _cleanup_free_ char *p = strndup(eq, colon - eq);
                        if (!p)
                                return -ENOMEM;

                        r = sd_bus_message_append(m, "(sv)", "ProtectHostnameEx", "(ss)", p, colon + 1);
                } else
                        r = sd_bus_message_append(m, "(sv)", "ProtectHostnameEx", "(ss)", eq, NULL);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_boolean_or_ex_string(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = parse_boolean(eq);
        if (r >= 0) {
                if (endswith(field, "Ex"))
                        field = strndupa_safe(field, strlen(field) - 2);

                r = sd_bus_message_append(m, "(sv)", field, "b", r);
        } else {
                if (!endswith(field, "Ex"))
                        field = strjoina(field, "Ex");

                /* We allow any string through and let the server perform the verification. */
                r = sd_bus_message_append(m, "(sv)", field, "s", eq);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_paths(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_trivial_array(m, "Paths", eq,
                                        "a(ss)", field, eq);
}

static int bus_append_exit_status(sd_bus_message *m, const char *field, const char *eq) {
        _cleanup_free_ int *status = NULL, *signal = NULL;
        size_t n_status = 0, n_signal = 0;
        int r;

        for (const char *p = eq;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return parse_log_error(r, field, eq);
                if (r == 0)
                        break;

                /* We need to call exit_status_from_string() first, because we want
                 * to parse numbers as exit statuses, not signals. */

                r = exit_status_from_string(word);
                if (r >= 0) {
                        assert(r >= 0 && r < 256);

                        if (!GREEDY_REALLOC(status, n_status + 1))
                                return log_oom();

                        status[n_status++] = r;

                } else if ((r = signal_from_string(word)) >= 0) {
                        if (!GREEDY_REALLOC(signal, n_signal + 1))
                                return log_oom();

                        signal[n_signal++] = r;

                } else
                        /* original r from exit_status_to_string() */
                        return parse_log_error(r, field, word);
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "(aiai)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'r', "aiai");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_array(m, 'i', status, n_status * sizeof(int));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_array(m, 'i', signal, n_signal * sizeof(int));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_action_exit_status(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", field, "i", -1);
        else {
                uint8_t u;

                r = safe_atou8(eq, &u);
                if (r < 0)
                        return parse_log_error(r, field, eq);

                r = sd_bus_message_append(m, "(sv)", field, "i", (int) u);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_listen(sd_bus_message *m, const char *field, const char *eq) {
        const char *p = ASSERT_PTR(startswith(field, "Listen"));

        return bus_append_trivial_array(m, "Listen", eq,
                                        "a(ss)", p, eq);
}

static int bus_append_timers_monotonic(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (isempty(eq))
                r = sd_bus_message_append(m, "(sv)", "TimersMonotonic", "a(st)", 0);
        else {
                usec_t t;
                r = parse_sec(eq, &t);
                if (r < 0)
                        return parse_log_error(r, field, eq);

                r = sd_bus_message_append(m, "(sv)", "TimersMonotonic", "a(st)", 1, field, t);
        }
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_timers_calendar(sd_bus_message *m, const char *field, const char *eq) {
        return bus_append_trivial_array(m, "TimersCalendar", eq,
                                        "a(ss)", field, eq);
}

static int bus_append_timeout_sec(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        r = bus_append_parse_sec_rename(m, "TimeoutStartSec", eq);
        if (r < 0)
                return r;

        return bus_append_parse_sec_rename(m, "TimeoutStopSec", eq);
}

static int bus_try_append_condition(sd_bus_message *m, const char *field, const char *eq) {
        ConditionType t = condition_type_from_string(field);
        bool is_condition = t >= 0;

        if (!is_condition) {
                t = assert_type_from_string(field);
                if (t < 0)
                        return 0;
        }

        const char *p = eq;

        int trigger = p && *p == '|';
        if (trigger)
                p++;

        int negate = p && *p == '!';
        if (negate)
                p++;

        return bus_append_trivial_array(m,
                                        is_condition ? "Conditions" : "Asserts",
                                        eq,
                                        "a(sbbs)",
                                        field, trigger, negate, p);
}

static void dump_conditions(void) {
        condition_types_list();
        assert_types_list();
}

static int bus_try_append_unit_dependency(sd_bus_message *m, const char *field, const char *eq) {
        if (unit_dependency_from_string(field) < 0)
                return 0;

        return bus_append_strv(m, field, eq);
}

typedef struct BusProperty {
        const char *name;
        int (*convert)(sd_bus_message *m, const char *field, const char *eq);
        void (*dump)(void);
} BusProperty;

static const BusProperty cgroup_properties[] = {
        { "DevicePolicy",                          bus_append_string                             },
        { "Slice",                                 bus_append_string                             },
        { "ManagedOOMSwap",                        bus_append_string                             },
        { "ManagedOOMMemoryPressure",              bus_append_string                             },
        { "ManagedOOMPreference",                  bus_append_string                             },
        { "MemoryPressureWatch",                   bus_append_string                             },
        { "DelegateSubgroup",                      bus_append_string                             },
        { "ManagedOOMMemoryPressureLimit",         bus_append_parse_permyriad                    },
        { "MemoryAccounting",                      bus_append_parse_boolean                      },
        { "MemoryZSwapWriteback",                  bus_append_parse_boolean                      },
        { "IOAccounting",                          bus_append_parse_boolean                      },
        { "TasksAccounting",                       bus_append_parse_boolean                      },
        { "IPAccounting",                          bus_append_parse_boolean                      },
        { "CoredumpReceive",                       bus_append_parse_boolean                      },
        { "CPUWeight",                             bus_append_cg_cpu_weight_parse                },
        { "StartupCPUWeight",                      bus_append_cg_cpu_weight_parse                },
        { "IOWeight",                              bus_append_cg_weight_parse                    },
        { "StartupIOWeight",                       bus_append_cg_weight_parse                    },
        { "AllowedCPUs",                           bus_append_parse_cpu_set                      },
        { "StartupAllowedCPUs",                    bus_append_parse_cpu_set                      },
        { "AllowedMemoryNodes",                    bus_append_parse_cpu_set                      },
        { "StartupAllowedMemoryNodes",             bus_append_parse_cpu_set                      },
        { "DisableControllers",                    bus_append_strv                               },
        { "Delegate",                              bus_append_parse_delegate                     },
        { "MemoryMin",                             bus_append_parse_resource_limit               },
        { "MemoryLow",                             bus_append_parse_resource_limit               },
        { "MemoryHigh",                            bus_append_parse_resource_limit               },
        { "MemoryMax",                             bus_append_parse_resource_limit               },
        { "MemorySwapMax",                         bus_append_parse_resource_limit               },
        { "MemoryZSwapMax",                        bus_append_parse_resource_limit               },
        { "TasksMax",                              bus_append_parse_resource_limit               },
        { "CPUQuota",                              bus_append_parse_cpu_quota                    },
        { "CPUQuotaPeriodSec",                     bus_append_parse_sec_rename_infinity          },
        { "DeviceAllow",                           bus_append_parse_device_allow                 },
        { "IODeviceWeight",                        bus_append_parse_io_device_weight             },
        { "IODeviceLatencyTargetSec",              bus_append_parse_io_device_latency            },
        { "IPAddressAllow",                        bus_append_parse_ip_address_filter            },
        { "IPAddressDeny",                         bus_append_parse_ip_address_filter            },
        { "IPIngressFilterPath",                   bus_append_ip_filter_path                     },
        { "IPEgressFilterPath",                    bus_append_ip_filter_path                     },
        { "BPFProgram",                            bus_append_bpf_program                        },
        { "SocketBindAllow",                       bus_append_socket_filter                      },
        { "SocketBindDeny",                        bus_append_socket_filter                      },
        { "MemoryPressureThresholdSec",            bus_append_parse_sec_rename                   },
        { "NFTSet",                                bus_append_nft_set                            },
        { "BindNetworkInterface",                  bus_append_string                             },

        /* While infinity is disallowed in unit file, infinity is allowed in D-Bus API which
         * means use the default memory pressure duration from oomd.conf. */
        { "ManagedOOMMemoryPressureDurationSec",   bus_append_parse_sec_rename_infinity          },

        { "MemoryLimit",                           warn_deprecated                               },
        { "CPUShares",                             warn_deprecated                               },
        { "StartupCPUShares",                      warn_deprecated                               },
        { "BlockIOAccounting",                     warn_deprecated                               },
        { "BlockIOWeight",                         warn_deprecated                               },
        { "StartupBlockIOWeight",                  warn_deprecated                               },
        { "BlockIODeviceWeight",                   warn_deprecated                               },
        { "BlockIOReadBandwidth",                  warn_deprecated                               },
        { "BlockIOWriteBandwidth",                 warn_deprecated                               },
        { "CPUAccounting",                         warn_deprecated                               },
        { "DefaultMemoryMin",                      warn_deprecated                               },
        { "DefaultMemoryLow",                      warn_deprecated                               },

        { NULL, bus_try_append_parse_cgroup_io_limit, cgroup_io_limits_list                      },
        {}
};

static const BusProperty automount_properties[] = {
        { "Where",                                 bus_append_string                             },
        { "ExtraOptions",                          bus_append_string                             },
        { "DirectoryMode",                         bus_append_parse_mode                         },
        { "TimeoutIdleSec",                        bus_append_parse_sec_rename                   },
        {}
};

static const BusProperty execute_properties[] = {
        { "User",                                  bus_append_string                             },
        { "Group",                                 bus_append_string                             },
        { "UtmpIdentifier",                        bus_append_string                             },
        { "UtmpMode",                              bus_append_string                             },
        { "PAMName",                               bus_append_string                             },
        { "TTYPath",                               bus_append_string                             },
        { "WorkingDirectory",                      bus_append_string                             },
        { "RootDirectory",                         bus_append_string                             },
        { "SyslogIdentifier",                      bus_append_string                             },
        { "ProtectSystem",                         bus_append_string                             },
        { "ProtectHome",                           bus_append_string                             },
        { "SELinuxContext",                        bus_append_string                             },
        { "RootImage",                             bus_append_string                             },
        { "RootVerity",                            bus_append_string                             },
        { "RuntimeDirectoryPreserve",              bus_append_string                             },
        { "Personality",                           bus_append_string                             },
        { "KeyringMode",                           bus_append_string                             },
        { "ProtectProc",                           bus_append_string                             },
        { "ProcSubset",                            bus_append_string                             },
        { "NetworkNamespacePath",                  bus_append_string                             },
        { "UserNamespacePath",                     bus_append_string                             },
        { "IPCNamespacePath",                      bus_append_string                             },
        { "LogNamespace",                          bus_append_string                             },
        { "RootImagePolicy",                       bus_append_string                             },
        { "MountImagePolicy",                      bus_append_string                             },
        { "ExtensionImagePolicy",                  bus_append_string                             },
        { "PrivatePIDs",                           bus_append_string                             },
        { "PrivateBPF",                            bus_append_string                             },
        { "BPFDelegateCommands",                   bus_append_string                             },
        { "BPFDelegateMaps",                       bus_append_string                             },
        { "BPFDelegatePrograms",                   bus_append_string                             },
        { "BPFDelegateAttachments",                bus_append_string                             },
        { "IgnoreSIGPIPE",                         bus_append_parse_boolean                      },
        { "TTYVHangup",                            bus_append_parse_boolean                      },
        { "TTYReset",                              bus_append_parse_boolean                      },
        { "TTYVTDisallocate",                      bus_append_parse_boolean                      },
        { "PrivateDevices",                        bus_append_parse_boolean                      },
        { "PrivateNetwork",                        bus_append_parse_boolean                      },
        { "PrivateMounts",                         bus_append_parse_boolean                      },
        { "PrivateIPC",                            bus_append_parse_boolean                      },
        { "NoNewPrivileges",                       bus_append_parse_boolean                      },
        { "SyslogLevelPrefix",                     bus_append_parse_boolean                      },
        { "MemoryDenyWriteExecute",                bus_append_parse_boolean                      },
        { "RestrictRealtime",                      bus_append_parse_boolean                      },
        { "DynamicUser",                           bus_append_parse_boolean                      },
        { "RemoveIPC",                             bus_append_parse_boolean                      },
        { "ProtectKernelTunables",                 bus_append_parse_boolean                      },
        { "ProtectKernelModules",                  bus_append_parse_boolean                      },
        { "ProtectKernelLogs",                     bus_append_parse_boolean                      },
        { "ProtectClock",                          bus_append_parse_boolean                      },
        { "MountAPIVFS",                           bus_append_parse_boolean                      },
        { "BindLogSockets",                        bus_append_parse_boolean                      },
        { "CPUSchedulingResetOnFork",              bus_append_parse_boolean                      },
        { "LockPersonality",                       bus_append_parse_boolean                      },
        { "MemoryKSM",                             bus_append_parse_boolean                      },
        { "MemoryTHP",                             bus_append_string                             },
        { "RestrictSUIDSGID",                      bus_append_parse_boolean                      },
        { "RootEphemeral",                         bus_append_parse_boolean                      },
        { "SetLoginEnvironment",                   bus_append_parse_boolean                      },
        { "ReadWriteDirectories",                  bus_append_strv                               },
        { "ReadOnlyDirectories",                   bus_append_strv                               },
        { "InaccessibleDirectories",               bus_append_strv                               },
        { "ReadWritePaths",                        bus_append_strv                               },
        { "ReadOnlyPaths",                         bus_append_strv                               },
        { "InaccessiblePaths",                     bus_append_strv                               },
        { "ExecPaths",                             bus_append_strv                               },
        { "NoExecPaths",                           bus_append_strv                               },
        { "ExecSearchPath",                        bus_append_strv_colon                         },
        { "ExtensionDirectories",                  bus_append_strv                               },
        { "ConfigurationDirectory",                bus_append_strv                               },
        { "SupplementaryGroups",                   bus_append_strv                               },
        { "SystemCallArchitectures",               bus_append_strv                               },
        { "SyslogLevel",                           bus_append_log_level_from_string              },
        { "LogLevelMax",                           bus_append_log_level_from_string              },
        { "SyslogFacility",                        bus_append_log_facility_unshifted_from_string },
        { "SecureBits",                            bus_append_secure_bits_from_string            },
        { "CPUSchedulingPolicy",                   bus_append_sched_policy_from_string           },
        { "CPUSchedulingPriority",                 bus_append_safe_atoi                          },
        { "OOMScoreAdjust",                        bus_append_safe_atoi                          },
        { "CoredumpFilter",                        bus_append_coredump_filter_mask_from_string   },
        { "Nice",                                  bus_append_parse_nice                         },
        { "SystemCallErrorNumber",                 bus_append_seccomp_parse_errno_or_action      },
        { "IOSchedulingClass",                     bus_append_ioprio_class_from_string           },
        { "IOSchedulingPriority",                  bus_append_ioprio_parse_priority              },
        { "RuntimeDirectoryMode",                  bus_append_parse_mode                         },
        { "StateDirectoryMode",                    bus_append_parse_mode                         },
        { "CacheDirectoryMode",                    bus_append_parse_mode                         },
        { "LogsDirectoryMode",                     bus_append_parse_mode                         },
        { "ConfigurationDirectoryMode",            bus_append_parse_mode                         },
        { "UMask",                                 bus_append_parse_mode                         },
        { "TimerSlackNSec",                        bus_append_parse_nsec                         },
        { "LogRateLimitIntervalSec",               bus_append_parse_sec_rename                   },
        { "LogRateLimitBurst",                     bus_append_safe_atou                          },
        { "TTYRows",                               bus_append_safe_atou                          },
        { "TTYColumns",                            bus_append_safe_atou                          },
        { "MountFlags",                            bus_append_mount_propagation_flag_from_string },
        { "Environment",                           bus_append_strv_cunescape                     },
        { "UnsetEnvironment",                      bus_append_strv_cunescape                     },
        { "PassEnvironment",                       bus_append_strv_cunescape                     },
        { "EnvironmentFile",                       bus_append_environment_files                  },
        { "SetCredential",                         bus_append_set_credential                     },
        { "SetCredentialEncrypted",                bus_append_set_credential                     },
        { "LoadCredential",                        bus_append_load_credential                    },
        { "LoadCredentialEncrypted",               bus_append_load_credential                    },
        { "ImportCredential",                      bus_append_import_credential                  },
        { "ImportCredentialEx",                    bus_append_import_credential                  }, /* compat */
        { "LogExtraFields",                        bus_append_log_extra_fields                   },
        { "LogFilterPatterns",                     bus_append_log_filter_patterns                },
        { "StandardInput",                         bus_append_standard_inputs                    },
        { "StandardOutput",                        bus_append_standard_inputs                    },
        { "StandardError",                         bus_append_standard_inputs                    },
        { "StandardInputText",                     bus_append_standard_input_text                },
        { "StandardInputData",                     bus_append_standard_input_data                },
        { "AppArmorProfile",                       bus_append_string_with_ignore                 },
        { "SmackProcessLabel",                     bus_append_string_with_ignore                 },
        { "CapabilityBoundingSet",                 bus_append_capabilities                       },
        { "AmbientCapabilities",                   bus_append_capabilities                       },
        { "CPUAffinity",                           bus_append_cpu_affinity                       },
        { "NUMAPolicy",                            bus_append_mpol_from_string                   },
        { "NUMAMask",                              bus_append_numa_mask                          },
        { "RestrictAddressFamilies",               bus_append_filter_list                        },
        { "RestrictFileSystems",                   bus_append_filter_list                        },
        { "SystemCallFilter",                      bus_append_filter_list                        },
        { "SystemCallLog",                         bus_append_filter_list                        },
        { "RestrictNetworkInterfaces",             bus_append_filter_list                        },
        { "RestrictNamespaces",                    bus_append_namespace_list                     },
        { "DelegateNamespaces",                    bus_append_namespace_list                     },
        { "BindPaths",                             bus_append_bind_paths                         },
        { "BindReadOnlyPaths",                     bus_append_bind_paths                         },
        { "TemporaryFileSystem",                   bus_append_temporary_file_system              },
        { "RootHash",                              bus_append_root_hash                          },
        { "RootHashSignature",                     bus_append_root_hash_signature                },
        { "RootImageOptions",                      bus_append_root_image_options                 },
        { "MountImages",                           bus_append_mount_images                       },
        { "ExtensionImages",                       bus_append_extension_images                   },
        { "StateDirectory",                        bus_append_directory                          },
        { "RuntimeDirectory",                      bus_append_directory                          },
        { "CacheDirectory",                        bus_append_directory                          },
        { "LogsDirectory",                         bus_append_directory                          },
        { "ProtectHostname",                       bus_append_protect_hostname                   },
        { "ProtectHostnameEx",                     bus_append_protect_hostname                   }, /* compat */
        { "PrivateTmp",                            bus_append_boolean_or_ex_string               },
        { "PrivateTmpEx",                          bus_append_boolean_or_ex_string               }, /* compat */
        { "ProtectControlGroups",                  bus_append_boolean_or_ex_string               },
        { "ProtectControlGroupsEx",                bus_append_boolean_or_ex_string               }, /* compat */
        { "PrivateUsers",                          bus_append_boolean_or_ex_string               },
        { "PrivateUsersEx",                        bus_append_boolean_or_ex_string               }, /* compat */
        { "StateDirectoryQuota",                   bus_append_quota_directory                    },
        { "CacheDirectoryQuota",                   bus_append_quota_directory                    },
        { "LogsDirectoryQuota",                    bus_append_quota_directory                    },
        { "StateDirectoryAccounting",              bus_append_parse_boolean                      },
        { "CacheDirectoryAccounting",              bus_append_parse_boolean                      },
        { "LogsDirectoryAccounting",               bus_append_parse_boolean                      },

        { NULL, bus_try_append_resource_limit,     dump_resource_limits                          },
        {}
};

static const BusProperty kill_properties[] = {
        { "KillMode",                              bus_append_string                             },
        { "SendSIGHUP",                            bus_append_parse_boolean                      },
        { "SendSIGKILL",                           bus_append_parse_boolean                      },
        { "KillSignal",                            bus_append_signal_from_string                 },
        { "RestartKillSignal",                     bus_append_signal_from_string                 },
        { "FinalKillSignal",                       bus_append_signal_from_string                 },
        { "WatchdogSignal",                        bus_append_signal_from_string                 },
        {}
};

static const BusProperty mount_properties[] = {
        { "What",                                  bus_append_string                             },
        { "Where",                                 bus_append_string                             },
        { "Options",                               bus_append_string                             },
        { "Type",                                  bus_append_string                             },
        { "TimeoutSec",                            bus_append_parse_sec_rename                   },
        { "DirectoryMode",                         bus_append_parse_mode                         },
        { "SloppyOptions",                         bus_append_parse_boolean                      },
        { "LazyUnmount",                           bus_append_parse_boolean                      },
        { "ForceUnmount",                          bus_append_parse_boolean                      },
        { "ReadwriteOnly",                         bus_append_parse_boolean                      },
        {}
};

static const BusProperty path_properties[] = {
        { "MakeDirectory",                         bus_append_parse_boolean                      },
        { "DirectoryMode",                         bus_append_parse_mode                         },
        { "PathExists",                            bus_append_paths                              },
        { "PathExistsGlob",                        bus_append_paths                              },
        { "PathChanged",                           bus_append_paths                              },
        { "PathModified",                          bus_append_paths                              },
        { "DirectoryNotEmpty",                     bus_append_paths                              },
        { "TriggerLimitBurst",                     bus_append_safe_atou                          },
        { "PollLimitBurst",                        bus_append_safe_atou                          },
        { "TriggerLimitIntervalSec",               bus_append_parse_sec_rename                   },
        { "PollLimitIntervalSec",                  bus_append_parse_sec_rename                   },
        {}
};

static const BusProperty scope_properties[] = {
        { "RuntimeMaxSec",                         bus_append_parse_sec_rename                   },
        { "RuntimeRandomizedExtraSec",             bus_append_parse_sec_rename                   },
        { "TimeoutStopSec",                        bus_append_parse_sec_rename                   },
        { "OOMPolicy",                             bus_append_string                             },

        /* Scope units don't have execution context but we still want to allow setting these two,
         * so let's handle them separately. */
        { "User",                                  bus_append_string                             },
        { "Group",                                 bus_append_string                             },
        {}
};

static const BusProperty service_properties[] = {
        { "PIDFile",                               bus_append_string                             },
        { "Type",                                  bus_append_string                             },
        { "ExitType",                              bus_append_string                             },
        { "Restart",                               bus_append_string                             },
        { "RestartMode",                           bus_append_string                             },
        { "BusName",                               bus_append_string                             },
        { "NotifyAccess",                          bus_append_string                             },
        { "USBFunctionDescriptors",                bus_append_string                             },
        { "USBFunctionStrings",                    bus_append_string                             },
        { "OOMPolicy",                             bus_append_string                             },
        { "TimeoutStartFailureMode",               bus_append_string                             },
        { "TimeoutStopFailureMode",                bus_append_string                             },
        { "FileDescriptorStorePreserve",           bus_append_string                             },
        { "PermissionsStartOnly",                  bus_append_parse_boolean                      },
        { "RootDirectoryStartOnly",                bus_append_parse_boolean                      },
        { "RemainAfterExit",                       bus_append_parse_boolean                      },
        { "GuessMainPID",                          bus_append_parse_boolean                      },
        { "RestartSec",                            bus_append_parse_sec_rename                   },
        { "RestartMaxDelaySec",                    bus_append_parse_sec_rename                   },
        { "TimeoutStartSec",                       bus_append_parse_sec_rename                   },
        { "TimeoutStopSec",                        bus_append_parse_sec_rename                   },
        { "TimeoutAbortSec",                       bus_append_parse_sec_rename                   },
        { "RuntimeMaxSec",                         bus_append_parse_sec_rename                   },
        { "RuntimeRandomizedExtraSec",             bus_append_parse_sec_rename                   },
        { "WatchdogSec",                           bus_append_parse_sec_rename                   },
        { "TimeoutSec",                            bus_append_timeout_sec                        },
        { "FileDescriptorStoreMax",                bus_append_safe_atou                          },
        { "RestartSteps",                          bus_append_safe_atou                          },
        { "ExecCondition",                         bus_append_exec_command                       },
        { "ExecConditionEx",                       bus_append_exec_command                       }, /* compat */
        { "ExecStartPre",                          bus_append_exec_command                       },
        { "ExecStartPreEx",                        bus_append_exec_command                       }, /* compat */
        { "ExecStart",                             bus_append_exec_command                       },
        { "ExecStartEx",                           bus_append_exec_command                       }, /* compat */
        { "ExecStartPost",                         bus_append_exec_command                       },
        { "ExecStartPostEx",                       bus_append_exec_command                       }, /* compat */
        { "ExecReload",                            bus_append_exec_command                       },
        { "ExecReloadEx",                          bus_append_exec_command                       }, /* compat */
        { "ExecReloadPost",                        bus_append_exec_command                       },
        { "ExecReloadPostEx",                      bus_append_exec_command                       }, /* compat */
        { "ExecStop",                              bus_append_exec_command                       },
        { "ExecStopEx",                            bus_append_exec_command                       }, /* compat */
        { "ExecStopPost",                          bus_append_exec_command                       },
        { "ExecStopPostEx",                        bus_append_exec_command                       }, /* compat */
        { "RestartPreventExitStatus",              bus_append_exit_status                        },
        { "RestartForceExitStatus",                bus_append_exit_status                        },
        { "SuccessExitStatus",                     bus_append_exit_status                        },
        { "OpenFile",                              bus_append_open_file                          },
        { "ReloadSignal",                          bus_append_signal_from_string                 },
        { "RefreshOnReload",                       bus_append_refresh_on_reload                  },
        {}
};

static const BusProperty socket_properties[] = {
        { "Accept",                                bus_append_parse_boolean                      },
        { "FlushPending",                          bus_append_parse_boolean                      },
        { "Writable",                              bus_append_parse_boolean                      },
        { "KeepAlive",                             bus_append_parse_boolean                      },
        { "NoDelay",                               bus_append_parse_boolean                      },
        { "FreeBind",                              bus_append_parse_boolean                      },
        { "Transparent",                           bus_append_parse_boolean                      },
        { "Broadcast",                             bus_append_parse_boolean                      },
        { "PassCredentials",                       bus_append_parse_boolean                      },
        { "PassFileDescriptorsToExec",             bus_append_parse_boolean                      },
        { "PassSecurity",                          bus_append_parse_boolean                      },
        { "PassPacketInfo",                        bus_append_parse_boolean                      },
        { "ReusePort",                             bus_append_parse_boolean                      },
        { "RemoveOnStop",                          bus_append_parse_boolean                      },
        { "SELinuxContextFromNet",                 bus_append_parse_boolean                      },
        { "Priority",                              bus_append_safe_atoi                          },
        { "IPTTL",                                 bus_append_safe_atoi                          },
        { "Mark",                                  bus_append_safe_atoi                          },
        { "IPTOS",                                 bus_append_ip_tos_from_string                 },
        { "Backlog",                               bus_append_safe_atou                          },
        { "MaxConnections",                        bus_append_safe_atou                          },
        { "MaxConnectionsPerSource",               bus_append_safe_atou                          },
        { "KeepAliveProbes",                       bus_append_safe_atou                          },
        { "TriggerLimitBurst",                     bus_append_safe_atou                          },
        { "PollLimitBurst",                        bus_append_safe_atou                          },
        { "SocketMode",                            bus_append_parse_mode                         },
        { "DirectoryMode",                         bus_append_parse_mode                         },
        { "MessageQueueMaxMessages",               bus_append_safe_atoi64                        },
        { "MessageQueueMessageSize",               bus_append_safe_atoi64                        },
        { "TimeoutSec",                            bus_append_parse_sec_rename                   },
        { "KeepAliveTimeSec",                      bus_append_parse_sec_rename                   },
        { "KeepAliveIntervalSec",                  bus_append_parse_sec_rename                   },
        { "DeferAcceptSec",                        bus_append_parse_sec_rename                   },
        { "TriggerLimitIntervalSec",               bus_append_parse_sec_rename                   },
        { "PollLimitIntervalSec",                  bus_append_parse_sec_rename                   },
        { "DeferTriggerMaxSec",                    bus_append_parse_sec_rename                   },
        { "ReceiveBuffer",                         bus_append_parse_size                         },
        { "SendBuffer",                            bus_append_parse_size                         },
        { "PipeSize",                              bus_append_parse_size                         },
        { "ExecStartPre",                          bus_append_exec_command                       },
        { "ExecStartPost",                         bus_append_exec_command                       },
        { "ExecReload",                            bus_append_exec_command                       },
        { "ExecStopPost",                          bus_append_exec_command                       },
        { "SmackLabel",                            bus_append_string                             },
        { "SmackLabelIPIn",                        bus_append_string                             },
        { "SmackLabelIPOut",                       bus_append_string                             },
        { "TCPCongestion",                         bus_append_string                             },
        { "BindToDevice",                          bus_append_string                             },
        { "BindIPv6Only",                          bus_append_string                             },
        { "FileDescriptorName",                    bus_append_string                             },
        { "SocketUser",                            bus_append_string                             },
        { "SocketGroup",                           bus_append_string                             },
        { "Timestamping",                          bus_append_string                             },
        { "DeferTrigger",                          bus_append_string                             },
        { "Symlinks",                              bus_append_strv                               },
        { "SocketProtocol",                        bus_append_parse_ip_protocol                  },
        { "ListenStream",                          bus_append_listen                             },
        { "ListenDatagram",                        bus_append_listen                             },
        { "ListenSequentialPacket",                bus_append_listen                             },
        { "ListenNetlink",                         bus_append_listen                             },
        { "ListenSpecial",                         bus_append_listen                             },
        { "ListenMessageQueue",                    bus_append_listen                             },
        { "ListenFIFO",                            bus_append_listen                             },
        { "ListenUSBFunction",                     bus_append_listen                             },
        {}
};

static const BusProperty timer_properties[] = {
        { "WakeSystem",                            bus_append_parse_boolean                      },
        { "RemainAfterElapse",                     bus_append_parse_boolean                      },
        { "Persistent",                            bus_append_parse_boolean                      },
        { "OnTimezoneChange",                      bus_append_parse_boolean                      },
        { "OnClockChange",                         bus_append_parse_boolean                      },
        { "FixedRandomDelay",                      bus_append_parse_boolean                      },
        { "DeferReactivation",                     bus_append_parse_boolean                      },
        { "AccuracySec",                           bus_append_parse_sec_rename                   },
        { "RandomizedDelaySec",                    bus_append_parse_sec_rename                   },
        { "RandomizedOffsetSec",                   bus_append_parse_sec_rename                   },
        { "OnActiveSec",                           bus_append_timers_monotonic                   },
        { "OnBootSec",                             bus_append_timers_monotonic                   },
        { "OnStartupSec",                          bus_append_timers_monotonic                   },
        { "OnUnitActiveSec",                       bus_append_timers_monotonic                   },
        { "OnUnitInactiveSec",                     bus_append_timers_monotonic                   },
        { "OnCalendar",                            bus_append_timers_calendar                    },
        {}
};

static const BusProperty unit_properties[] = {
        { "Description",                           bus_append_string                             },
        { "SourcePath",                            bus_append_string                             },
        { "OnFailureJobMode",                      bus_append_string                             },
        { "JobTimeoutAction",                      bus_append_string                             },
        { "JobTimeoutRebootArgument",              bus_append_string                             },
        { "StartLimitAction",                      bus_append_string                             },
        { "FailureAction",                         bus_append_string                             },
        { "SuccessAction",                         bus_append_string                             },
        { "RebootArgument",                        bus_append_string                             },
        { "CollectMode",                           bus_append_string                             },
        { "StopWhenUnneeded",                      bus_append_parse_boolean                      },
        { "RefuseManualStart",                     bus_append_parse_boolean                      },
        { "RefuseManualStop",                      bus_append_parse_boolean                      },
        { "AllowIsolate",                          bus_append_parse_boolean                      },
        { "IgnoreOnIsolate",                       bus_append_parse_boolean                      },
        { "SurviveFinalKillSignal",                bus_append_parse_boolean                      },
        { "DefaultDependencies",                   bus_append_parse_boolean                      },
        { "JobTimeoutSec",                         bus_append_parse_sec_rename                   },
        { "JobRunningTimeoutSec",                  bus_append_parse_sec_rename                   },
        { "StartLimitIntervalSec",                 bus_append_parse_sec_rename                   },
        { "StartLimitBurst",                       bus_append_safe_atou                          },
        { "SuccessActionExitStatus",               bus_append_action_exit_status                 },
        { "FailureActionExitStatus",               bus_append_action_exit_status                 },
        { "Documentation",                         bus_append_strv                               },
        { "RequiresMountsFor",                     bus_append_strv                               },
        { "WantsMountsFor",                        bus_append_strv                               },
        { "Markers",                               bus_append_strv                               },

        { NULL, bus_try_append_unit_dependency,    unit_types_list                               },
        { NULL, bus_try_append_condition,          dump_conditions                               },
        {}
};

static const BusProperty* service_unit_properties[] = {
        cgroup_properties,
        execute_properties,
        kill_properties,
        service_properties,
        unit_properties,
        NULL,
};

static const BusProperty* socket_unit_properties[] = {
        cgroup_properties,
        execute_properties,
        kill_properties,
        socket_properties,
        unit_properties,
        NULL,
};

static const BusProperty* timer_unit_properties[] = {
        timer_properties,
        unit_properties,
        NULL,
};

static const BusProperty* path_unit_properties[] = {
        path_properties,
        unit_properties,
        NULL,
};

static const BusProperty* slice_unit_properties[] = {
        cgroup_properties,
        unit_properties,
        NULL,
};

static const BusProperty* scope_unit_properties[] = {
        cgroup_properties,
        kill_properties,
        scope_properties,
        unit_properties,
        NULL,
};

static const BusProperty* mount_unit_properties[] = {
        cgroup_properties,
        execute_properties,
        kill_properties,
        mount_properties,
        unit_properties,
        NULL,
};

static const BusProperty* automount_unit_properties[] = {
        automount_properties,
        unit_properties,
        NULL,
};

static const BusProperty* other_unit_properties[] = {
        unit_properties,
        NULL,
};

static const BusProperty** unit_type_properties[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE]   = service_unit_properties,
        [UNIT_SOCKET]    = socket_unit_properties,
        [UNIT_TIMER]     = timer_unit_properties,
        [UNIT_PATH]      = path_unit_properties,
        [UNIT_SLICE]     = slice_unit_properties,
        [UNIT_SCOPE]     = scope_unit_properties,
        [UNIT_MOUNT]     = mount_unit_properties,
        [UNIT_AUTOMOUNT] = automount_unit_properties,
        [UNIT_TARGET]    = other_unit_properties,
        [UNIT_DEVICE]    = other_unit_properties,
        [UNIT_SWAP]      = other_unit_properties,
};

int bus_append_unit_property_assignment(sd_bus_message *m, UnitType t, const char *assignment) {
        _cleanup_free_ char *field = NULL;
        const char *eq;
        int r;

        assert(m);
        assert(assignment);
        assert(t >= 0 && t < _UNIT_TYPE_MAX);

        eq = strchr(assignment, '=');
        if (!eq)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not an assignment: %s", assignment);


        field = strndup(assignment, eq - assignment);
        if (!field)
                return log_oom();
        eq++;

        for (const BusProperty** tables = ASSERT_PTR(unit_type_properties[t]); *tables; tables++)
                for (const BusProperty *item = *tables; item->convert; item++)
                        if (item->name) {
                                if (streq(item->name, field))
                                        return item->convert(m, field, eq);
                        } else {
                                /* If .name is not set, the function must be a "try" helper */
                                r = item->convert(m, field, eq);
                                if (r != 0)
                                        return r;
                        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Unknown assignment: %s", assignment);
}

int bus_append_unit_property_assignment_many(sd_bus_message *m, UnitType t, char * const *l) {
        int r;

        assert(m);

        STRV_FOREACH(i, l) {
                r = bus_append_unit_property_assignment(m, t, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

void bus_dump_transient_settings(UnitType t) {
        assert(t >= 0 && t < _UNIT_TYPE_MAX);

        for (const BusProperty** tables = ASSERT_PTR(unit_type_properties[t]); *tables; tables++)
                for (const BusProperty *item = *tables; item->convert; item++) {
                        assert(item->name || item->dump);

                        /* Do not print deprecated names. All "Ex" variants are deprecated. */
                        if (item->convert == warn_deprecated)
                                continue;
                        if (item->name && endswith(item->name, "Ex"))
                                continue;

                        if (item->name)
                                puts(item->name);
                        else
                                item->dump();
                }
}

int bus_append_scope_pidref(sd_bus_message *m, const PidRef *pidref, bool allow_pidfd) {
        assert(m);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->fd >= 0 && allow_pidfd)
                return sd_bus_message_append(
                                m, "(sv)",
                                "PIDFDs", "ah", 1, pidref->fd);

        return sd_bus_message_append(
                        m, "(sv)",
                        "PIDs", "au", 1, pidref->pid);
}

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet) {
        const char *type, *path, *source;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        int r;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(m, "(sss)", &type, &path, &source)) > 0) {
                InstallChangeType t;

                /* We expect only "success" changes to be sent over the bus. Hence, reject anything
                 * negative. */
                t = install_change_type_from_string(type);
                if (t < 0) {
                        log_notice_errno(t, "Manager reported unknown change type \"%s\" for path \"%s\", ignoring.",
                                         type, path);
                        continue;
                }

                r = install_changes_add(&changes, &n_changes, t, path, source);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        install_changes_dump(0, NULL, changes, n_changes, quiet);

        return 0;
}

int unit_load_state(sd_bus *bus, const char *name, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        path = unit_dbus_path_from_name(name);
        if (!path)
                return log_oom();

        /* This function warns on its own, because otherwise it'd be awkward to pass
         * the dbus error message around. */

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "LoadState",
                        &error,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to get load state of %s: %s", name, bus_error_message(&error, r));

        return 0;
}

int unit_info_compare(const UnitInfo *a, const UnitInfo *b) {
        int r;

        /* First, order by machine */
        r = strcasecmp_ptr(a->machine, b->machine);
        if (r != 0)
                return r;

        /* Second, order by unit type */
        r = strcasecmp_ptr(strrchr(a->id, '.'), strrchr(b->id, '.'));
        if (r != 0)
                return r;

        /* Third, order by name */
        return strcasecmp(a->id, b->id);
}

int bus_service_manager_reload(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "Reload");
        if (r < 0)
                return bus_log_create_error(r);

        /* Reloading the daemon may take long, hence set a longer timeout here */
        r = sd_bus_call(bus, m, DAEMON_RELOAD_TIMEOUT_SEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload service manager: %s", bus_error_message(&error, r));

        return 0;
}

typedef struct UnitFreezer {
        char *name;
        sd_bus *bus;
} UnitFreezer;

/* Wait for 60 seconds at maximum for freezer operation */
#define FREEZE_BUS_CALL_TIMEOUT (60 * USEC_PER_SEC)

UnitFreezer* unit_freezer_free(UnitFreezer *f) {
        if (!f)
                return NULL;

        free(f->name);
        sd_bus_flush_close_unref(f->bus);

        return mfree(f);
}

int unit_freezer_new(const char *name, UnitFreezer **ret) {
        _cleanup_(unit_freezer_freep) UnitFreezer *f = NULL;
        int r;

        assert(name);
        assert(ret);

        f = new(UnitFreezer, 1);
        if (!f)
                return log_oom();

        *f = (UnitFreezer) {
                .name = strdup(name),
        };
        if (!f->name)
                return log_oom();

        r = bus_connect_system_systemd(&f->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open connection to systemd: %m");

        (void) sd_bus_set_method_call_timeout(f->bus, FREEZE_BUS_CALL_TIMEOUT);

        *ret = TAKE_PTR(f);
        return 0;
}

static int unit_freezer_action(UnitFreezer *f, bool freeze) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(f);
        assert(f->name);
        assert(f->bus);

        r = bus_call_method(f->bus, bus_systemd_mgr,
                            freeze ? "FreezeUnit" : "ThawUnit",
                            &error,
                            /* ret_reply= */ NULL,
                            "s",
                            f->name);
        if (r < 0) {
                if (sd_bus_error_has_names(&error,
                                           BUS_ERROR_NO_SUCH_UNIT,
                                           BUS_ERROR_UNIT_INACTIVE,
                                           SD_BUS_ERROR_NOT_SUPPORTED)) {

                        log_debug_errno(r, "Skipping freezer for '%s': %s", f->name, bus_error_message(&error, r));
                        return 0;
                }

                return log_error_errno(r, "Failed to %s unit '%s': %s",
                                       freeze ? "freeze" : "thaw", f->name, bus_error_message(&error, r));
        }

        log_info("Successfully %s unit '%s'.", freeze ? "froze" : "thawed", f->name);
        return 1;
}

int unit_freezer_freeze(UnitFreezer *f) {
        return unit_freezer_action(f, true);
}

int unit_freezer_thaw(UnitFreezer *f) {
        return unit_freezer_action(f, false);
}

ExecDirectoryFlags exec_directory_flags_from_string(const char *s) {
        if (isempty(s))
                return 0;

        if (streq(s, "ro"))
                return EXEC_DIRECTORY_READ_ONLY;

        return _EXEC_DIRECTORY_FLAGS_INVALID;
}
