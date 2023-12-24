/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "cap-list.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "condition.h"
#include "constants.h"
#include "coredump-util.h"
#include "cpu-set-util.h"
#include "dissect-image.h"
#include "escape.h"
#include "exec-util.h"
#include "exit-status.h"
#include "fileio.h"
#include "firewall-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "ioprio-util.h"
#include "ip-protocol-list.h"
#include "libmount-util.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "missing_fs.h"
#include "mountpoint-util.h"
#include "nsflags.h"
#include "numa-util.h"
#include "open-file.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "user-util.h"
#include "utf8.h"

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
                        return log_error_errno(r, "Failed to parse %s=%s: %m", field, eq); \
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
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s: %s", field, eq);                                 \
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
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, ioprio_parse_priority);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, parse_nice);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, safe_atoi);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, nsec_t, parse_nsec);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_blkio_weight_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_cpu_shares_parse);
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

static int bus_append_strv(sd_bus_message *m, const char *field, const char *eq, ExtractFlags flags) {
        const char *p;
        int r;

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

        for (p = eq;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, flags);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Invalid syntax: %s", eq);

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
                return log_error_errno(r, "Failed to parse %s=%s: %m", field, eq);

        l = strlen(field);
        n = newa(char, l + 2);
        /* Change suffix Sec → USec */
        strcpy(mempcpy(n, field, l - 3), "USec");

        r = sd_bus_message_append(m, "(sv)", n, "t", t);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_parse_size(sd_bus_message *m, const char *field, const char *eq, uint64_t base) {
        uint64_t v;
        int r;

        r = parse_size(eq, base, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s=%s: %m", field, eq);

        r = sd_bus_message_append(m, "(sv)", field, "t", v);
        if (r < 0)
                return bus_log_create_error(r);

        return 1;
}

static int bus_append_exec_command(sd_bus_message *m, const char *field, const char *eq) {
        bool explicit_path = false, done = false;
        _cleanup_strv_free_ char **l = NULL, **ex_opts = NULL;
        _cleanup_free_ char *path = NULL, *upgraded_name = NULL;
        ExecCommandFlags flags = 0;
        bool is_ex_prop = endswith(field, "Ex");
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
                        if (flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID|EXEC_COMMAND_AMBIENT_MAGIC))
                                done = true;
                        else {
                                flags |= EXEC_COMMAND_FULLY_PRIVILEGED;
                                eq++;
                        }
                        break;

                case '!':
                        if (flags & (EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_AMBIENT_MAGIC))
                                done = true;
                        else if (FLAGS_SET(flags, EXEC_COMMAND_NO_SETUID)) {
                                flags &= ~EXEC_COMMAND_NO_SETUID;
                                flags |= EXEC_COMMAND_AMBIENT_MAGIC;
                                eq++;
                        } else {
                                flags |= EXEC_COMMAND_NO_SETUID;
                                eq++;
                        }
                        break;

                default:
                        done = true;
                        break;
                }
        } while (!done);

        if (!is_ex_prop && (flags & (EXEC_COMMAND_NO_ENV_EXPAND|EXEC_COMMAND_FULLY_PRIVILEGED|EXEC_COMMAND_NO_SETUID|EXEC_COMMAND_AMBIENT_MAGIC))) {
                /* Upgrade the ExecXYZ= property to ExecXYZEx= for convenience */
                is_ex_prop = true;
                upgraded_name = strjoin(field, "Ex");
                if (!upgraded_name)
                        return log_oom();
        }

        if (is_ex_prop) {
                r = exec_command_flags_to_strv(flags, &ex_opts);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert ExecCommandFlags to strv: %m");
        }

        if (explicit_path) {
                r = extract_first_word(&eq, &path, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse path: %m");
        }

        r = strv_split_full(&l, eq, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE);
        if (r < 0)
                return log_error_errno(r, "Failed to parse command line: %m");

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, upgraded_name ?: field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', is_ex_prop ? "a(sasas)" : "a(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', is_ex_prop ? "(sasas)" : "(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        if (!strv_isempty(l)) {

                r = sd_bus_message_open_container(m, 'r', is_ex_prop ? "sasas" : "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", path ?: l[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, l);
                if (r < 0)
                        return bus_log_create_error(r);

                r = is_ex_prop ? sd_bus_message_append_strv(m, ex_opts) : sd_bus_message_append(m, "b", FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE));
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
                return log_error_errno(r, "Failed to parse OpenFile= setting: %m");

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
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s: %m", field);
                if (r == 0)
                        break;
                if (isempty(tuple))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s", field);

                q = tuple;
                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE, &source_str, &nfproto_str, &table, &set, NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r != 4 || !isempty(q))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s", field);

                assert(source_str);
                assert(nfproto_str);
                assert(table);
                assert(set);

                source = nft_set_source_from_string(source_str);
                if (!IN_SET(source, NFT_SET_SOURCE_CGROUP, NFT_SET_SOURCE_USER, NFT_SET_SOURCE_GROUP))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s", field);

                nfproto = nfproto_from_string(nfproto_str);
                if (nfproto < 0 || !nft_identifier_valid(table) || !nft_identifier_valid(set))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s", field);

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

static int bus_append_cgroup_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field, "DevicePolicy",
                              "Slice",
                              "ManagedOOMSwap",
                              "ManagedOOMMemoryPressure",
                              "ManagedOOMPreference",
                              "MemoryPressureWatch",
                              "DelegateSubgroup"))
                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "ManagedOOMMemoryPressureLimit")) {
                r = parse_permyriad(eq);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value: %s", field, eq);

                /* Pass around scaled to 2^32-1 == 100% */
                r = sd_bus_message_append(m, "(sv)", field, "u", UINT32_SCALE_FROM_PERMYRIAD(r));
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "CPUAccounting",
                              "MemoryAccounting",
                              "IOAccounting",
                              "BlockIOAccounting",
                              "TasksAccounting",
                              "IPAccounting",
                              "CoredumpReceive"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "CPUWeight",
                              "StartupCPUWeight"))
                return bus_append_cg_cpu_weight_parse(m, field, eq);

        if (STR_IN_SET(field, "IOWeight",
                              "StartupIOWeight"))
                return bus_append_cg_weight_parse(m, field, eq);

        if (STR_IN_SET(field, "CPUShares",
                              "StartupCPUShares"))
                return bus_append_cg_cpu_shares_parse(m, field, eq);

        if (STR_IN_SET(field, "AllowedCPUs",
                              "StartupAllowedCPUs",
                              "AllowedMemoryNodes",
                              "StartupAllowedMemoryNodes")) {
                _cleanup_(cpu_set_reset) CPUSet cpuset = {};
                _cleanup_free_ uint8_t *array = NULL;
                size_t allocated;

                r = parse_cpu_set(eq, &cpuset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value: %s", field, eq);

                r = cpu_set_to_dbus(&cpuset, &array, &allocated);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize CPUSet: %m");

                return bus_append_byte_array(m, field, array, allocated);
        }

        if (STR_IN_SET(field, "BlockIOWeight",
                              "StartupBlockIOWeight"))
                return bus_append_cg_blkio_weight_parse(m, field, eq);

        if (streq(field, "DisableControllers"))
                return bus_append_strv(m, "DisableControllers", eq, EXTRACT_UNQUOTE);

        if (streq(field, "Delegate")) {
                r = parse_boolean(eq);
                if (r < 0)
                        return bus_append_strv(m, "DelegateControllers", eq, EXTRACT_UNQUOTE);

                r = sd_bus_message_append(m, "(sv)", "Delegate", "b", r);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "MemoryMin",
                              "DefaultMemoryLow",
                              "DefaultMemoryMin",
                              "MemoryLow",
                              "MemoryHigh",
                              "MemoryMax",
                              "MemorySwapMax",
                              "MemoryZSwapMax",
                              "MemoryLimit",
                              "TasksMax")) {

                if (streq(eq, "infinity")) {
                        r = sd_bus_message_append(m, "(sv)", field, "t", CGROUP_LIMIT_MAX);
                        if (r < 0)
                                return bus_log_create_error(r);
                        return 1;
                } else if (isempty(eq)) {
                        uint64_t empty_value = STR_IN_SET(field,
                                                          "DefaultMemoryLow",
                                                          "DefaultMemoryMin",
                                                          "MemoryLow",
                                                          "MemoryMin") ?
                                               CGROUP_LIMIT_MIN :
                                               CGROUP_LIMIT_MAX;

                        r = sd_bus_message_append(m, "(sv)", field, "t", empty_value);
                        if (r < 0)
                                return bus_log_create_error(r);
                        return 1;
                }

                r = parse_permyriad(eq);
                if (r >= 0) {
                        char *n;

                        /* When this is a percentage we'll convert this into a relative value in the range 0…UINT32_MAX
                         * and pass it in the MemoryLowScale property (and related ones). This way the physical memory
                         * size can be determined server-side. */

                        n = strjoina(field, "Scale");
                        r = sd_bus_message_append(m, "(sv)", n, "u", UINT32_SCALE_FROM_PERMYRIAD(r));
                        if (r < 0)
                                return bus_log_create_error(r);

                        return 1;
                }

                if (streq(field, "TasksMax"))
                        return bus_append_safe_atou64(m, field, eq);

                return bus_append_parse_size(m, field, eq, 1024);
        }

        if (streq(field, "CPUQuota")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "CPUQuotaPerSecUSec", "t", USEC_INFINITY);
                else {
                        r = parse_permyriad_unbounded(eq);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                                       "CPU quota too small.");
                        if (r < 0)
                                return log_error_errno(r, "CPU quota '%s' invalid.", eq);

                        r = sd_bus_message_append(m, "(sv)", "CPUQuotaPerSecUSec", "t", (((uint64_t) r * USEC_PER_SEC) / 10000U));
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "CPUQuotaPeriodSec")) {
                usec_t u = USEC_INFINITY;

                r = parse_sec_def_infinity(eq, &u);
                if (r < 0)
                        return log_error_errno(r, "CPU quota period '%s' invalid.", eq);

                r = sd_bus_message_append(m, "(sv)", "CPUQuotaPeriodUSec", "t", u);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "DeviceAllow")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 0);
                else {
                        const char *path = eq, *rwm = NULL, *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa_safe(eq, e - eq);
                                rwm = e+1;
                        }

                        r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 1, path, strempty(rwm));
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (cgroup_io_limit_type_from_string(field) >= 0 || STR_IN_SET(field, "BlockIOReadBandwidth", "BlockIOWriteBandwidth")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(st)", 0);
                else {
                        const char *path, *bandwidth, *e;
                        uint64_t bytes;

                        e = strchr(eq, ' ');
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse %s value %s.",
                                                       field, eq);

                        path = strndupa_safe(eq, e - eq);
                        bandwidth = e+1;

                        if (streq(bandwidth, "infinity"))
                                bytes = CGROUP_LIMIT_MAX;
                        else {
                                r = parse_size(bandwidth, 1000, &bytes);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse byte value %s: %m", bandwidth);
                        }

                        r = sd_bus_message_append(m, "(sv)", field, "a(st)", 1, path, bytes);
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "IODeviceWeight",
                              "BlockIODeviceWeight")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(st)", 0);
                else {
                        const char *path, *weight, *e;
                        uint64_t u;

                        e = strchr(eq, ' ');
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse %s value %s.",
                                                       field, eq);

                        path = strndupa_safe(eq, e - eq);
                        weight = e+1;

                        r = safe_atou64(weight, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s value %s: %m", field, weight);

                        r = sd_bus_message_append(m, "(sv)", field, "a(st)", 1, path, u);
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "IODeviceLatencyTargetSec")) {
                const char *field_usec = "IODeviceLatencyTargetUSec";

                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field_usec, "a(st)", USEC_INFINITY);
                else {
                        const char *path, *target, *e;
                        usec_t usec;

                        e = strchr(eq, ' ');
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse %s value %s.",
                                                       field, eq);

                        path = strndupa_safe(eq, e - eq);
                        target = e+1;

                        r = parse_sec(target, &usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s value %s: %m", field, target);

                        r = sd_bus_message_append(m, "(sv)", field_usec, "a(st)", 1, path, usec);
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "IPAddressAllow",
                              "IPAddressDeny")) {
                unsigned char prefixlen;
                union in_addr_union prefix = {};
                int family;

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

                } else {
                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&eq, &word, NULL, 0);
                                if (r == 0)
                                        break;
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse %s: %s", field, eq);

                                r = in_addr_prefix_from_string_auto(word, &family, &prefix, &prefixlen);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse IP address prefix: %s", word);

                                r = bus_append_ip_address_access(m, family, &prefix, prefixlen);
                                if (r < 0)
                                        return bus_log_create_error(r);
                        }
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

        if (STR_IN_SET(field, "IPIngressFilterPath",
                              "IPEgressFilterPath")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "as", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", field, "as", 1, eq);

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "BPFProgram")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 0);
                else {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&eq, &word, ":", 0);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", field);

                        r = sd_bus_message_append(m, "(sv)", field, "a(ss)", 1, word, eq);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "SocketBindAllow",
                              "SocketBindDeny")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(iiqq)", 0);
                else {
                        int32_t family, ip_protocol;
                        uint16_t nr_ports, port_min;

                        r = parse_socket_bind_item(eq, &family, &ip_protocol, &nr_ports, &port_min);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s", field);

                        r = sd_bus_message_append(
                                        m, "(sv)", field, "a(iiqq)", 1, family, ip_protocol, nr_ports, port_min);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "MemoryPressureThresholdSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "NFTSet"))
                return bus_append_nft_set(m, field, eq);

        return 0;
}

static int bus_append_automount_property(sd_bus_message *m, const char *field, const char *eq) {
        if (STR_IN_SET(field, "Where",
                              "ExtraOptions"))
                return bus_append_string(m, field, eq);

        if (streq(field, "DirectoryMode"))
                return bus_append_parse_mode(m, field, eq);

        if (streq(field, "TimeoutIdleSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        return 0;
}

static int bus_append_execute_property(sd_bus_message *m, const char *field, const char *eq) {
        const char *suffix;
        int r;

        if (STR_IN_SET(field, "User",
                              "Group",
                              "UtmpIdentifier",
                              "UtmpMode",
                              "PAMName",
                              "TTYPath",
                              "WorkingDirectory",
                              "RootDirectory",
                              "SyslogIdentifier",
                              "ProtectSystem",
                              "ProtectHome",
                              "SELinuxContext",
                              "RootImage",
                              "RootVerity",
                              "RuntimeDirectoryPreserve",
                              "Personality",
                              "KeyringMode",
                              "ProtectProc",
                              "ProcSubset",
                              "NetworkNamespacePath",
                              "IPCNamespacePath",
                              "LogNamespace",
                              "RootImagePolicy",
                              "MountImagePolicy",
                              "ExtensionImagePolicy"))
                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "IgnoreSIGPIPE",
                              "TTYVHangup",
                              "TTYReset",
                              "TTYVTDisallocate",
                              "PrivateTmp",
                              "PrivateDevices",
                              "PrivateNetwork",
                              "PrivateUsers",
                              "PrivateMounts",
                              "PrivateIPC",
                              "NoNewPrivileges",
                              "SyslogLevelPrefix",
                              "MemoryDenyWriteExecute",
                              "RestrictRealtime",
                              "DynamicUser",
                              "RemoveIPC",
                              "ProtectKernelTunables",
                              "ProtectKernelModules",
                              "ProtectKernelLogs",
                              "ProtectClock",
                              "ProtectControlGroups",
                              "MountAPIVFS",
                              "CPUSchedulingResetOnFork",
                              "LockPersonality",
                              "ProtectHostname",
                              "MemoryKSM",
                              "RestrictSUIDSGID",
                              "RootEphemeral",
                              "SetLoginEnvironment"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "ReadWriteDirectories",
                              "ReadOnlyDirectories",
                              "InaccessibleDirectories",
                              "ReadWritePaths",
                              "ReadOnlyPaths",
                              "InaccessiblePaths",
                              "ExecPaths",
                              "NoExecPaths",
                              "ExecSearchPath",
                              "ExtensionDirectories",
                              "ConfigurationDirectory",
                              "SupplementaryGroups",
                              "SystemCallArchitectures"))
                return bus_append_strv(m, field, eq, EXTRACT_UNQUOTE);

        if (STR_IN_SET(field, "SyslogLevel",
                              "LogLevelMax"))
                return bus_append_log_level_from_string(m, field, eq);

        if (streq(field, "SyslogFacility"))
                return bus_append_log_facility_unshifted_from_string(m, field, eq);

        if (streq(field, "SecureBits"))
                return bus_append_secure_bits_from_string(m, field, eq);

        if (streq(field, "CPUSchedulingPolicy"))
                return bus_append_sched_policy_from_string(m, field, eq);

        if (STR_IN_SET(field, "CPUSchedulingPriority",
                              "OOMScoreAdjust"))
                return bus_append_safe_atoi(m, field, eq);

        if (streq(field, "CoredumpFilter"))
                return bus_append_coredump_filter_mask_from_string(m, field, eq);

        if (streq(field, "Nice"))
                return bus_append_parse_nice(m, field, eq);

        if (streq(field, "SystemCallErrorNumber"))
                return bus_append_seccomp_parse_errno_or_action(m, field, eq);

        if (streq(field, "IOSchedulingClass"))
                return bus_append_ioprio_class_from_string(m, field, eq);

        if (streq(field, "IOSchedulingPriority"))
                return bus_append_ioprio_parse_priority(m, field, eq);

        if (STR_IN_SET(field, "RuntimeDirectoryMode",
                              "StateDirectoryMode",
                              "CacheDirectoryMode",
                              "LogsDirectoryMode",
                              "ConfigurationDirectoryMode",
                              "UMask"))
                return bus_append_parse_mode(m, field, eq);

        if (streq(field, "TimerSlackNSec"))
                return bus_append_parse_nsec(m, field, eq);

        if (streq(field, "LogRateLimitIntervalSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (STR_IN_SET(field, "LogRateLimitBurst",
                              "TTYRows",
                              "TTYColumns"))
                return bus_append_safe_atou(m, field, eq);

        if (streq(field, "MountFlags"))
                return bus_append_mount_propagation_flag_from_string(m, field, eq);

        if (STR_IN_SET(field, "Environment",
                              "UnsetEnvironment",
                              "PassEnvironment"))
                return bus_append_strv(m, field, eq, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE);

        if (streq(field, "EnvironmentFile")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "EnvironmentFiles", "a(sb)", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", "EnvironmentFiles", "a(sb)", 1,
                                                  eq[0] == '-' ? eq + 1 : eq,
                                                  eq[0] == '-');
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "SetCredential", "SetCredentialEncrypted")) {
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
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s= parameter: %s", field, eq);
                        if (r == 0 || !p)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing argument to %s=.", field);

                        r = sd_bus_message_open_container(m, 'a', "(say)");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_open_container(m, 'r', "say");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", word);
                        if (r < 0)
                                return bus_log_create_error(r);

                        if (streq(field, "SetCredentialEncrypted")) {
                                _cleanup_free_ void *decoded = NULL;
                                size_t decoded_size;

                                r = unbase64mem(p, SIZE_MAX, &decoded, &decoded_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to base64 decode encrypted credential: %m");

                                r = sd_bus_message_append_array(m, 'y', decoded, decoded_size);
                        } else {
                                _cleanup_free_ char *unescaped = NULL;
                                ssize_t l;

                                l = cunescape(p, UNESCAPE_ACCEPT_NUL, &unescaped);
                                if (l < 0)
                                        return log_error_errno(l, "Failed to unescape %s= value: %s", field, p);

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

        if (STR_IN_SET(field, "LoadCredential", "LoadCredentialEncrypted")) {
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
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s= parameter: %s", field, eq);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing argument to %s=.", field);

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

        if (streq(field, "ImportCredential")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "as", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", field, "as", 1, eq);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "LogExtraFields")) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_basic(m, 's', "LogExtraFields");
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

        if (streq(field, "LogFilterPatterns")) {
                r = sd_bus_message_append(m, "(sv)", "LogFilterPatterns", "a(bs)", 1,
                                          eq[0] != '~',
                                          eq[0] != '~' ? eq : eq + 1);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "StandardInput",
                              "StandardOutput",
                              "StandardError")) {
                const char *n, *appended;

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

        if (streq(field, "StandardInputText")) {
                _cleanup_free_ char *unescaped = NULL;
                ssize_t l;

                l = cunescape(eq, 0, &unescaped);
                if (l < 0)
                        return log_error_errno(l, "Failed to unescape text '%s': %m", eq);

                if (!strextend(&unescaped, "\n"))
                        return log_oom();

                /* Note that we don't expand specifiers here, but that should be OK, as this is a
                 * programmatic interface anyway */

                return bus_append_byte_array(m, field, unescaped, l + 1);
        }

        if (streq(field, "StandardInputData")) {
                _cleanup_free_ void *decoded = NULL;
                size_t sz;

                r = unbase64mem(eq, SIZE_MAX, &decoded, &sz);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode base64 data '%s': %m", eq);

                return bus_append_byte_array(m, field, decoded, sz);
        }

        if ((suffix = startswith(field, "Limit"))) {
                int rl;

                rl = rlimit_from_string(suffix);
                if (rl >= 0) {
                        const char *sn;
                        struct rlimit l;

                        r = rlimit_parse(rl, eq, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resource limit: %s", eq);

                        r = sd_bus_message_append(m, "(sv)", field, "t", l.rlim_max);
                        if (r < 0)
                                return bus_log_create_error(r);

                        sn = strjoina(field, "Soft");
                        r = sd_bus_message_append(m, "(sv)", sn, "t", l.rlim_cur);
                        if (r < 0)
                                return bus_log_create_error(r);

                        return 1;
                }
        }

        if (STR_IN_SET(field, "AppArmorProfile",
                              "SmackProcessLabel")) {
                int ignore = 0;
                const char *s = eq;

                if (eq[0] == '-') {
                        ignore = 1;
                        s = eq + 1;
                }

                r = sd_bus_message_append(m, "(sv)", field, "(bs)", ignore, s);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "CapabilityBoundingSet",
                              "AmbientCapabilities")) {
                uint64_t sum = 0;
                bool invert = false;
                const char *p = eq;

                if (*p == '~') {
                        invert = true;
                        p++;
                }

                r = capability_set_from_string(p, &sum);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value %s: %m", field, eq);

                sum = invert ? ~sum : sum;

                r = sd_bus_message_append(m, "(sv)", field, "t", sum);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "CPUAffinity")) {
                _cleanup_(cpu_set_reset) CPUSet cpuset = {};
                _cleanup_free_ uint8_t *array = NULL;
                size_t allocated;

                if (eq && streq(eq, "numa")) {
                        r = sd_bus_message_append(m, "(sv)", "CPUAffinityFromNUMA", "b", true);
                        if (r < 0)
                                return bus_log_create_error(r);
                        return r;
                }

                r = parse_cpu_set(eq, &cpuset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value: %s", field, eq);

                r = cpu_set_to_dbus(&cpuset, &array, &allocated);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize CPUAffinity: %m");

                return bus_append_byte_array(m, field, array, allocated);
        }

        if (streq(field, "NUMAPolicy")) {
                r = mpol_from_string(eq);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value: %s", field, eq);

                r = sd_bus_message_append(m, "(sv)", field, "i", (int32_t) r);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "NUMAMask")) {
                _cleanup_(cpu_set_reset) CPUSet nodes = {};
                _cleanup_free_ uint8_t *array = NULL;
                size_t allocated;

                if (eq && streq(eq, "all")) {
                        r = numa_mask_add_all(&nodes);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create NUMA mask representing \"all\" NUMA nodes: %m");
                } else {
                        r = parse_cpu_set(eq, &nodes);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s value: %s", field, eq);
                }

                r = cpu_set_to_dbus(&nodes, &array, &allocated);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize NUMAMask: %m");

                return bus_append_byte_array(m, field, array, allocated);
        }

        if (STR_IN_SET(field, "RestrictAddressFamilies",
                              "RestrictFileSystems",
                              "SystemCallFilter",
                              "SystemCallLog",
                              "RestrictNetworkInterfaces")) {
                int allow_list = 1;
                const char *p = eq;

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
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Invalid syntax: %s", eq);

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

        if (streq(field, "RestrictNamespaces")) {
                bool invert = false;
                unsigned long flags;

                r = parse_boolean(eq);
                if (r > 0)
                        flags = 0;
                else if (r == 0)
                        flags = NAMESPACE_FLAGS_ALL;
                else {
                        if (eq[0] == '~') {
                                invert = true;
                                eq++;
                        }

                        r = namespace_flags_from_string(eq, &flags);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s value %s.", field, eq);
                }

                if (invert)
                        flags = (~flags) & NAMESPACE_FLAGS_ALL;

                r = sd_bus_message_append(m, "(sv)", field, "t", (uint64_t) flags);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "BindPaths",
                              "BindReadOnlyPaths")) {
                const char *p = eq;

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
                                return log_error_errno(r, "Failed to parse argument: %m");
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
                                        return log_error_errno(r, "Failed to parse argument: %m");
                                if (r == 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Missing argument after ':': %s",
                                                               eq);

                                d = destination;

                                if (p && p[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&p, &options, NULL, EXTRACT_UNQUOTE);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse argument: %m");

                                        if (isempty(options) || streq(options, "rbind"))
                                                flags = MS_REC;
                                        else if (streq(options, "norbind"))
                                                flags = 0;
                                        else
                                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                       "Unknown options: %s",
                                                                       eq);
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

        if (streq(field, "TemporaryFileSystem")) {
                const char *p = eq;

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
                                return log_error_errno(r, "Failed to parse argument: %m");
                        if (r == 0)
                                break;

                        w = word;
                        r = extract_first_word(&w, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse argument: %m");
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse argument: %s",
                                                       p);

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

        if (streq(field, "RootHash")) {
                _cleanup_free_ void *roothash_decoded = NULL;
                size_t roothash_decoded_size = 0;

                /* We have the path to a roothash to load and decode, eg: RootHash=/foo/bar.roothash */
                if (path_is_absolute(eq))
                        return bus_append_string(m, "RootHashPath", eq);

                /* We have a roothash to decode, eg: RootHash=012345789abcdef */
                r = unhexmem(eq, strlen(eq), &roothash_decoded, &roothash_decoded_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode RootHash= '%s': %m", eq);
                if (roothash_decoded_size < sizeof(sd_id128_t))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "RootHash= '%s' is too short: %m", eq);

                return bus_append_byte_array(m, field, roothash_decoded, roothash_decoded_size);
        }

        if (streq(field, "RootHashSignature")) {
                _cleanup_free_ void *roothash_sig_decoded = NULL;
                char *value;
                size_t roothash_sig_decoded_size = 0;

                /* We have the path to a roothash signature to load and decode, eg: RootHash=/foo/bar.roothash.p7s */
                if (path_is_absolute(eq))
                        return bus_append_string(m, "RootHashSignaturePath", eq);

                if (!(value = startswith(eq, "base64:")))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decode RootHashSignature= '%s', not a path but doesn't start with 'base64:': %m", eq);

                /* We have a roothash signature to decode, eg: RootHashSignature=base64:012345789abcdef */
                r = unbase64mem(value, strlen(value), &roothash_sig_decoded, &roothash_sig_decoded_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode RootHashSignature= '%s': %m", eq);

                return bus_append_byte_array(m, field, roothash_sig_decoded, roothash_sig_decoded_size);
        }

        if (streq(field, "RootImageOptions")) {
                _cleanup_strv_free_ char **l = NULL;
                const char *p = eq;

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
                        return log_error_errno(r, "Failed to parse argument: %m");

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

        if (streq(field, "MountImages")) {
                const char *p = eq;

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
                                return log_error_errno(r, "Failed to parse MountImages= property: %s", eq);
                        if (r == 0)
                                break;

                        q = tuple;
                        r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &first, &second, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse MountImages= property: %s", eq);
                        if (r == 0)
                                continue;

                        source = first;
                        if (source[0] == '-') {
                                permissive = true;
                                source++;
                        }

                        if (isempty(second))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                        "Missing argument after ':': %s",
                                                        eq);

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

                                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse MountImages= property: %s", eq);
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

        if (streq(field, "ExtensionImages")) {
                const char *p = eq;

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
                                return log_error_errno(r, "Failed to parse ExtensionImages= property: %s", eq);
                        if (r == 0)
                                break;

                        q = tuple;
                        r = extract_first_word(&q, &source, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse ExtensionImages= property: %s", eq);
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

                                r = extract_many_words(&q, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse ExtensionImages= property: %s", eq);
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

        if (STR_IN_SET(field, "StateDirectory", "RuntimeDirectory", "CacheDirectory", "LogsDirectory")) {
                _cleanup_strv_free_ char **symlinks = NULL, **sources = NULL;
                const char *p = eq;

                /* Adding new directories is supported from both *DirectorySymlink methods and the
                 * older ones, so first parse the input, and if we are given a new-style src:dst
                 * tuple use the new method, else use the old one. */

                for (;;) {
                        _cleanup_free_ char *tuple = NULL, *source = NULL, *destination = NULL;

                        r = extract_first_word(&p, &tuple, NULL, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse argument: %m");
                        if (r == 0)
                                break;

                        const char *t = tuple;
                        r = extract_many_words(&t, ":", EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS, &source, &destination, NULL);
                        if (r <= 0)
                                return log_error_errno(r ?: SYNTHETIC_ERRNO(EINVAL), "Failed to parse argument: %m");

                        path_simplify(source);

                        if (isempty(destination)) {
                                r = strv_consume(&sources, TAKE_PTR(source));
                                if (r < 0)
                                        return bus_log_create_error(r);
                        } else {
                                path_simplify(destination);

                                r = strv_consume_pair(&symlinks, TAKE_PTR(source), TAKE_PTR(destination));
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
                if (!strv_isempty(symlinks)) {
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
                                r = sd_bus_message_append(m, "(sst)", *source, *destination, 0);
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

        return 0;
}

static int bus_append_kill_property(sd_bus_message *m, const char *field, const char *eq) {
        if (streq(field, "KillMode"))
                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "SendSIGHUP",
                              "SendSIGKILL"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "KillSignal",
                              "RestartKillSignal",
                              "FinalKillSignal",
                              "WatchdogSignal",
                              "ReloadSignal"))
                return bus_append_signal_from_string(m, field, eq);

        return 0;
}

static int bus_append_mount_property(sd_bus_message *m, const char *field, const char *eq) {

        if (STR_IN_SET(field, "What",
                              "Where",
                              "Options",
                              "Type"))
                return bus_append_string(m, field, eq);

        if (streq(field, "TimeoutSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "DirectoryMode"))
                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field, "SloppyOptions",
                              "LazyUnmount",
                              "ForceUnmount",
                              "ReadwriteOnly"))
                return bus_append_parse_boolean(m, field, eq);

        return 0;
}

static int bus_append_path_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (streq(field, "MakeDirectory"))
                return bus_append_parse_boolean(m, field, eq);

        if (streq(field, "DirectoryMode"))
                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field, "PathExists",
                              "PathExistsGlob",
                              "PathChanged",
                              "PathModified",
                              "DirectoryNotEmpty")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "Paths", "a(ss)", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", "Paths", "a(ss)", 1, field, eq);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "TriggerLimitBurst", "PollLimitBurst"))
                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field, "TriggerLimitIntervalSec", "PollLimitIntervalSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        return 0;
}

static int bus_append_scope_property(sd_bus_message *m, const char *field, const char *eq) {
        if (streq(field, "RuntimeMaxSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "RuntimeRandomizedExtraSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "TimeoutStopSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        /* Scope units don't have execution context but we still want to allow setting these two,
         * so let's handle them separately. */
        if (STR_IN_SET(field, "User", "Group"))
                return bus_append_string(m, field, eq);

        if (streq(field, "OOMPolicy"))
                return bus_append_string(m, field, eq);

        return 0;
}

static int bus_append_service_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field, "PIDFile",
                              "Type",
                              "ExitType",
                              "Restart",
                              "RestartMode",
                              "BusName",
                              "NotifyAccess",
                              "USBFunctionDescriptors",
                              "USBFunctionStrings",
                              "OOMPolicy",
                              "TimeoutStartFailureMode",
                              "TimeoutStopFailureMode",
                              "FileDescriptorStorePreserve"))
                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "PermissionsStartOnly",
                              "RootDirectoryStartOnly",
                              "RemainAfterExit",
                              "GuessMainPID"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "RestartSec",
                              "RestartMaxDelaySec",
                              "TimeoutStartSec",
                              "TimeoutStopSec",
                              "TimeoutAbortSec",
                              "RuntimeMaxSec",
                              "RuntimeRandomizedExtraSec",
                              "WatchdogSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "TimeoutSec")) {
                r = bus_append_parse_sec_rename(m, "TimeoutStartSec", eq);
                if (r < 0)
                        return r;

                return bus_append_parse_sec_rename(m, "TimeoutStopSec", eq);
        }

        if (STR_IN_SET(field, "FileDescriptorStoreMax",
                              "RestartSteps"))
                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field, "ExecCondition",
                              "ExecStartPre",
                              "ExecStart",
                              "ExecStartPost",
                              "ExecConditionEx",
                              "ExecStartPreEx",
                              "ExecStartEx",
                              "ExecStartPostEx",
                              "ExecReload",
                              "ExecStop",
                              "ExecStopPost",
                              "ExecReloadEx",
                              "ExecStopEx",
                              "ExecStopPostEx"))
                return bus_append_exec_command(m, field, eq);

        if (STR_IN_SET(field, "RestartPreventExitStatus",
                              "RestartForceExitStatus",
                              "SuccessExitStatus")) {
                _cleanup_free_ int *status = NULL, *signal = NULL;
                size_t n_status = 0, n_signal = 0;
                const char *p;

                for (p = eq;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Invalid syntax in %s: %s", field, eq);

                        /* We need to call exit_status_from_string() first, because we want
                         * to parse numbers as exit statuses, not signals. */

                        r = exit_status_from_string(word);
                        if (r >= 0) {
                                assert(r >= 0 && r < 256);

                                status = reallocarray(status, n_status + 1, sizeof(int));
                                if (!status)
                                        return log_oom();

                                status[n_status++] = r;

                        } else if ((r = signal_from_string(word)) >= 0) {
                                signal = reallocarray(signal, n_signal + 1, sizeof(int));
                                if (!signal)
                                        return log_oom();

                                signal[n_signal++] = r;

                        } else
                                /* original r from exit_status_to_string() */
                                return log_error_errno(r, "Invalid status or signal %s in %s: %m",
                                                       word, field);
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

        if (streq(field, "OpenFile"))
                return bus_append_open_file(m, field, eq);

        return 0;
}

static int bus_append_socket_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field, "Accept",
                              "FlushPending",
                              "Writable",
                              "KeepAlive",
                              "NoDelay",
                              "FreeBind",
                              "Transparent",
                              "Broadcast",
                              "PassCredentials",
                              "PassSecurity",
                              "PassPacketInfo",
                              "ReusePort",
                              "RemoveOnStop",
                              "SELinuxContextFromNet"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "Priority",
                              "IPTTL",
                              "Mark"))
                return bus_append_safe_atoi(m, field, eq);

        if (streq(field, "IPTOS"))
                return bus_append_ip_tos_from_string(m, field, eq);

        if (STR_IN_SET(field, "Backlog",
                              "MaxConnections",
                              "MaxConnectionsPerSource",
                              "KeepAliveProbes",
                              "TriggerLimitBurst",
                              "PollLimitBurst"))
                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field, "SocketMode",
                              "DirectoryMode"))
                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field, "MessageQueueMaxMessages",
                              "MessageQueueMessageSize"))
                return bus_append_safe_atoi64(m, field, eq);

        if (STR_IN_SET(field, "TimeoutSec",
                              "KeepAliveTimeSec",
                              "KeepAliveIntervalSec",
                              "DeferAcceptSec",
                              "TriggerLimitIntervalSec",
                              "PollLimitIntervalSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (STR_IN_SET(field, "ReceiveBuffer",
                              "SendBuffer",
                              "PipeSize"))
                return bus_append_parse_size(m, field, eq, 1024);

        if (STR_IN_SET(field, "ExecStartPre",
                              "ExecStartPost",
                              "ExecReload",
                              "ExecStopPost"))
                return bus_append_exec_command(m, field, eq);

        if (STR_IN_SET(field, "SmackLabel",
                              "SmackLabelIPIn",
                              "SmackLabelIPOut",
                              "TCPCongestion",
                              "BindToDevice",
                              "BindIPv6Only",
                              "FileDescriptorName",
                              "SocketUser",
                              "SocketGroup",
                              "Timestamping"))
                return bus_append_string(m, field, eq);

        if (streq(field, "Symlinks"))
                return bus_append_strv(m, field, eq, EXTRACT_UNQUOTE);

        if (streq(field, "SocketProtocol"))
                return bus_append_parse_ip_protocol(m, field, eq);

        if (STR_IN_SET(field, "ListenStream",
                              "ListenDatagram",
                              "ListenSequentialPacket",
                              "ListenNetlink",
                              "ListenSpecial",
                              "ListenMessageQueue",
                              "ListenFIFO",
                              "ListenUSBFunction")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "Listen", "a(ss)", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", "Listen", "a(ss)", 1, field + STRLEN("Listen"), eq);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        return 0;
}
static int bus_append_timer_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field, "WakeSystem",
                              "RemainAfterElapse",
                              "Persistent",
                              "OnTimezoneChange",
                              "OnClockChange",
                              "FixedRandomDelay"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "AccuracySec",
                              "RandomizedDelaySec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (STR_IN_SET(field, "OnActiveSec",
                              "OnBootSec",
                              "OnStartupSec",
                              "OnUnitActiveSec",
                              "OnUnitInactiveSec")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "TimersMonotonic", "a(st)", 0);
                else {
                        usec_t t;
                        r = parse_sec(eq, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s=%s: %m", field, eq);

                        r = sd_bus_message_append(m, "(sv)", "TimersMonotonic", "a(st)", 1, field, t);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "OnCalendar")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "TimersCalendar", "a(ss)", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", "TimersCalendar", "a(ss)", 1, field, eq);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        return 0;
}

static int bus_append_unit_property(sd_bus_message *m, const char *field, const char *eq) {
        ConditionType t = _CONDITION_TYPE_INVALID;
        bool is_condition = false;
        int r;

        if (STR_IN_SET(field, "Description",
                              "SourcePath",
                              "OnFailureJobMode",
                              "JobTimeoutAction",
                              "JobTimeoutRebootArgument",
                              "StartLimitAction",
                              "FailureAction",
                              "SuccessAction",
                              "RebootArgument",
                              "CollectMode"))
                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "StopWhenUnneeded",
                              "RefuseManualStart",
                              "RefuseManualStop",
                              "AllowIsolate",
                              "IgnoreOnIsolate",
                              "SurviveFinalKillSignal",
                              "DefaultDependencies"))
                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "JobTimeoutSec",
                              "JobRunningTimeoutSec",
                              "StartLimitIntervalSec"))
                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "StartLimitBurst"))
                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field, "SuccessActionExitStatus",
                              "FailureActionExitStatus")) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "i", -1);
                else {
                        uint8_t u;

                        r = safe_atou8(eq, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s=%s", field, eq);

                        r = sd_bus_message_append(m, "(sv)", field, "i", (int) u);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (unit_dependency_from_string(field) >= 0 ||
            STR_IN_SET(field, "Documentation",
                              "RequiresMountsFor",
                              "WantsMountsFor",
                              "Markers"))
                return bus_append_strv(m, field, eq, EXTRACT_UNQUOTE);

        t = condition_type_from_string(field);
        if (t >= 0)
                is_condition = true;
        else
                t = assert_type_from_string(field);
        if (t >= 0) {
                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", is_condition ? "Conditions" : "Asserts", "a(sbbs)", 0);
                else {
                        const char *p = eq;
                        int trigger, negate;

                        trigger = *p == '|';
                        if (trigger)
                                p++;

                        negate = *p == '!';
                        if (negate)
                                p++;

                        r = sd_bus_message_append(m, "(sv)", is_condition ? "Conditions" : "Asserts", "a(sbbs)", 1,
                                                  field, trigger, negate, p);
                }
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        return 0;
}

int bus_append_unit_property_assignment(sd_bus_message *m, UnitType t, const char *assignment) {
        const char *eq, *field;
        int r;

        assert(m);
        assert(assignment);

        eq = strchr(assignment, '=');
        if (!eq)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not an assignment: %s", assignment);

        field = strndupa_safe(assignment, eq - assignment);
        eq++;

        switch (t) {
        case UNIT_SERVICE:
                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_execute_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_kill_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_service_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_SOCKET:
                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_execute_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_kill_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_socket_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_TIMER:
                r = bus_append_timer_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_PATH:
                r = bus_append_path_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_SLICE:
                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_SCOPE:
                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_kill_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_scope_property(m, field, eq);
                if (r != 0)
                        return r;
                break;

        case UNIT_MOUNT:
                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_execute_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_kill_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_mount_property(m, field, eq);
                if (r != 0)
                        return r;

                break;

        case UNIT_AUTOMOUNT:
                r = bus_append_automount_property(m, field, eq);
                if (r != 0)
                        return r;

                break;

        case UNIT_TARGET:
        case UNIT_DEVICE:
        case UNIT_SWAP:
                break;

        default:
                assert_not_reached();
        }

        r = bus_append_unit_property(m, field, eq);
        if (r != 0)
                return r;

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Unknown assignment: %s", assignment);
}

int bus_append_unit_property_assignment_many(sd_bus_message *m, UnitType t, char **l) {
        int r;

        assert(m);

        STRV_FOREACH(i, l) {
                r = bus_append_unit_property_assignment(m, t, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

int bus_append_scope_pidref(sd_bus_message *m, const PidRef *pidref) {
        assert(m);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->fd >= 0)
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

int unit_load_state(sd_bus *bus, const char *name, char **load_state) {
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
                        load_state);
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

int unit_freezer_recover(const char *name, UnitFreezer *ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *namedup = NULL;
        int r;

        assert(name);
        assert(ret);

        namedup = strdup(name);
        if (!namedup)
                return log_oom_debug();

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to open connection to systemd: %m");

        (void) sd_bus_set_method_call_timeout(bus, FREEZE_TIMEOUT);

        *ret = (UnitFreezer) {
                .name = TAKE_PTR(namedup),
                .bus = TAKE_PTR(bus),
        };
        return 0;
}

void unit_freezer_clear(UnitFreezer *f) {
        if (!f)
                return;

        f->name = mfree(f->name);
        f->bus = sd_bus_flush_close_unref(f->bus);
}

int unit_freezer_freeze(const char *name, UnitFreezer *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_freezer_clear) UnitFreezer f = UNIT_FREEZER_NULL;
        int r;

        assert(ret);

        r = unit_freezer_recover(name, &f);
        if (r < 0)
                return r;

        r = bus_call_method(f.bus, bus_systemd_mgr, "FreezeUnit", &error, NULL, "s", f.name);
        if (r < 0)
                return log_debug_errno(r, "Failed to freeze unit %s: %s", f.name, bus_error_message(&error, r));

        *ret = TAKE_STRUCT(f);
        return 0;
}

int unit_freezer_thaw(UnitFreezer *_f) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_freezer_clearp) UnitFreezer *f = TAKE_PTR(_f);
        int r;

        if (!f)
                return 0;

        r = bus_call_method(f->bus, bus_systemd_mgr, "ThawUnit", &error, NULL, "s", f->name);
        if (r < 0)
                return log_debug_errno(r, "Failed to thaw unit %s: %s", f->name, bus_error_message(&error, r));
        return 1;
}
