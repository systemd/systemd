/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "cap-list.h"
#include "cgroup-util.h"
#include "condition.h"
#include "cpu-set-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "escape.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "locale-util.h"
#include "mount-util.h"
#include "nsflags.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "securebits-util.h"
#include "signal-util.h"
#include "socket-protocol-list.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"

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
                if (r < 0) {                                            \
                        log_error("Failed to parse %s: %s", field, eq); \
                        return -EINVAL;                                 \
                }                                                       \
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
DEFINE_BUS_APPEND_PARSE("i", parse_errno);
DEFINE_BUS_APPEND_PARSE("i", sched_policy_from_string);
DEFINE_BUS_APPEND_PARSE("i", secure_bits_from_string);
DEFINE_BUS_APPEND_PARSE("i", signal_from_string);
DEFINE_BUS_APPEND_PARSE("i", socket_protocol_from_name);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, ioprio_parse_priority);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, parse_nice);
DEFINE_BUS_APPEND_PARSE_PTR("i", int32_t, int, safe_atoi);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, nsec_t, parse_nsec);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_blkio_weight_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_cpu_shares_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, cg_weight_parse);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, unsigned long, mount_propagation_flags_from_string);
DEFINE_BUS_APPEND_PARSE_PTR("t", uint64_t, uint64_t, safe_atou64);
DEFINE_BUS_APPEND_PARSE_PTR("u", uint32_t, mode_t, parse_mode);
DEFINE_BUS_APPEND_PARSE_PTR("u", uint32_t, unsigned, safe_atou);
DEFINE_BUS_APPEND_PARSE_PTR("x", int64_t, int64_t, safe_atoi64);

static inline int bus_append_string(sd_bus_message *m, const char *field, const char *eq) {
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
        bool ignore_failure = false, explicit_path = false, done = false;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        do {
                switch (*eq) {

                case '-':
                        if (ignore_failure)
                                done = true;
                        else {
                                ignore_failure = true;
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

                case '+':
                case '!':
                        /* The bus API doesn't support +, ! and !! currently, unfortunately. :-( */
                        log_error("Sorry, but +, ! and !! are currently not supported for transient services.");
                        return -EOPNOTSUPP;

                default:
                        done = true;
                        break;
                }
        } while (!done);

        if (explicit_path) {
                r = extract_first_word(&eq, &path, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse path: %m");
        }

        r = strv_split_extract(&l, eq, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE);
        if (r < 0)
                return log_error_errno(r, "Failed to parse command line: %m");

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        if (!strv_isempty(l)) {

                r = sd_bus_message_open_container(m, 'r', "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", path ?: l[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, l);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "b", ignore_failure);
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

static int bus_append_cgroup_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field, "DevicePolicy", "Slice"))

                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field,
                       "CPUAccounting", "MemoryAccounting", "IOAccounting", "BlockIOAccounting",
                       "TasksAccounting", "IPAccounting"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "CPUWeight", "StartupCPUWeight", "IOWeight", "StartupIOWeight"))

                return bus_append_cg_weight_parse(m, field, eq);

        if (STR_IN_SET(field, "CPUShares", "StartupCPUShares"))

                return bus_append_cg_cpu_shares_parse(m, field, eq);

        if (STR_IN_SET(field, "BlockIOWeight", "StartupBlockIOWeight"))

                return bus_append_cg_blkio_weight_parse(m, field, eq);

        if (streq(field, "Delegate")) {

                r = parse_boolean(eq);
                if (r < 0)
                        return bus_append_strv(m, "DelegateControllers", eq, EXTRACT_QUOTES);

                r = sd_bus_message_append(m, "(sv)", "Delegate", "b", r);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (STR_IN_SET(field, "MemoryMin", "MemoryLow", "MemoryHigh", "MemoryMax", "MemorySwapMax", "MemoryLimit", "TasksMax")) {

                if (isempty(eq) || streq(eq, "infinity")) {
                        r = sd_bus_message_append(m, "(sv)", field, "t", CGROUP_LIMIT_MAX);
                        if (r < 0)
                                return bus_log_create_error(r);
                        return 1;
                }

                r = parse_permille(eq);
                if (r >= 0) {
                        char *n;

                        /* When this is a percentage we'll convert this into a relative value in the range 0…UINT32_MAX
                         * and pass it in the MemoryLowScale property (and related ones). This way the physical memory
                         * size can be determined server-side. */

                        n = strjoina(field, "Scale");
                        r = sd_bus_message_append(m, "(sv)", n, "u", (uint32_t) (((uint64_t) r * UINT32_MAX) / 1000U));
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
                        r = parse_permille_unbounded(eq);
                        if (r == 0) {
                                log_error("CPU quota too small.");
                                return -ERANGE;
                        }
                        if (r < 0)
                                return log_error_errno(r, "CPU quota '%s' invalid.", eq);

                        r = sd_bus_message_append(m, "(sv)", "CPUQuotaPerSecUSec", "t", (((uint64_t) r * USEC_PER_SEC) / 1000U));
                }

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
                                path = strndupa(eq, e - eq);
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
                        if (!e) {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        path = strndupa(eq, e - eq);
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

        if (STR_IN_SET(field, "IODeviceWeight", "BlockIODeviceWeight")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", field, "a(st)", 0);
                else {
                        const char *path, *weight, *e;
                        uint64_t u;

                        e = strchr(eq, ' ');
                        if (!e) {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        path = strndupa(eq, e - eq);
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
                        if (!e) {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        path = strndupa(eq, e - eq);
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

        if (STR_IN_SET(field, "IPAddressAllow", "IPAddressDeny")) {
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

        return 0;
}

static int bus_append_automount_property(sd_bus_message *m, const char *field, const char *eq) {

        if (streq(field, "Where"))

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

        if (STR_IN_SET(field,
                       "User", "Group",
                       "UtmpIdentifier", "UtmpMode", "PAMName", "TTYPath",
                       "WorkingDirectory", "RootDirectory", "SyslogIdentifier",
                       "ProtectSystem", "ProtectHome", "SELinuxContext", "RootImage",
                       "RuntimeDirectoryPreserve", "Personality", "KeyringMode"))

                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field,
                       "IgnoreSIGPIPE", "TTYVHangup", "TTYReset", "TTYVTDisallocate",
                       "PrivateTmp", "PrivateDevices", "PrivateNetwork", "PrivateUsers",
                       "PrivateMounts", "NoNewPrivileges", "SyslogLevelPrefix",
                       "MemoryDenyWriteExecute", "RestrictRealtime", "DynamicUser", "RemoveIPC",
                       "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups",
                       "MountAPIVFS", "CPUSchedulingResetOnFork", "LockPersonality"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field,
                       "ReadWriteDirectories", "ReadOnlyDirectories", "InaccessibleDirectories",
                       "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths",
                       "RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory",
                       "SupplementaryGroups", "SystemCallArchitectures"))

                return bus_append_strv(m, field, eq, EXTRACT_QUOTES);

        if (STR_IN_SET(field, "SyslogLevel", "LogLevelMax"))

                return bus_append_log_level_from_string(m, field, eq);

        if (streq(field, "SyslogFacility"))

                return bus_append_log_facility_unshifted_from_string(m, field, eq);

        if (streq(field, "SecureBits"))

                return bus_append_secure_bits_from_string(m, field, eq);

        if (streq(field, "CPUSchedulingPolicy"))

                return bus_append_sched_policy_from_string(m, field, eq);

        if (STR_IN_SET(field, "CPUSchedulingPriority", "OOMScoreAdjust"))

                return bus_append_safe_atoi(m, field, eq);

        if (streq(field, "Nice"))

                return bus_append_parse_nice(m, field, eq);

        if (streq(field, "SystemCallErrorNumber"))

                return bus_append_parse_errno(m, field, eq);

        if (streq(field, "IOSchedulingClass"))

                return bus_append_ioprio_class_from_string(m, field, eq);

        if (streq(field, "IOSchedulingPriority"))

                return bus_append_ioprio_parse_priority(m, field, eq);

        if (STR_IN_SET(field,
                       "RuntimeDirectoryMode", "StateDirectoryMode", "CacheDirectoryMode",
                       "LogsDirectoryMode", "ConfigurationDirectoryMode", "UMask"))

                return bus_append_parse_mode(m, field, eq);

        if (streq(field, "TimerSlackNSec"))

                return bus_append_parse_nsec(m, field, eq);

        if (streq(field, "LogRateLimitIntervalSec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "LogRateLimitBurst"))

                return bus_append_safe_atou(m, field, eq);

        if (streq(field, "MountFlags"))

                return bus_append_mount_propagation_flags_from_string(m, field, eq);

        if (STR_IN_SET(field, "Environment", "UnsetEnvironment", "PassEnvironment"))

                return bus_append_strv(m, field, eq, EXTRACT_QUOTES|EXTRACT_CUNESCAPE);

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

        if (STR_IN_SET(field, "StandardInput", "StandardOutput", "StandardError")) {
                const char *n, *appended;

                if ((n = startswith(eq, "fd:"))) {
                        appended = strjoina(field, "FileDescriptorName");
                        r = sd_bus_message_append(m, "(sv)", appended, "s", n);
                } else if ((n = startswith(eq, "file:"))) {
                        appended = strjoina(field, "File");
                        r = sd_bus_message_append(m, "(sv)", appended, "s", n);
                } else
                        r = sd_bus_message_append(m, "(sv)", field, "s", eq);

                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        if (streq(field, "StandardInputText")) {
                _cleanup_free_ char *unescaped = NULL;

                r = cunescape(eq, 0, &unescaped);
                if (r < 0)
                        return log_error_errno(r, "Failed to unescape text '%s': %m", eq);

                if (!strextend(&unescaped, "\n", NULL))
                        return log_oom();

                /* Note that we don't expand specifiers here, but that should be OK, as this is a programmatic
                 * interface anyway */

                return bus_append_byte_array(m, field, unescaped, strlen(unescaped));
        }

        if (streq(field, "StandardInputData")) {
                _cleanup_free_ void *decoded = NULL;
                size_t sz;

                r = unbase64mem(eq, (size_t) -1, &decoded, &sz);
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

        if (STR_IN_SET(field, "AppArmorProfile", "SmackProcessLabel")) {
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

        if (STR_IN_SET(field, "CapabilityBoundingSet", "AmbientCapabilities")) {
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
                _cleanup_cpu_free_ cpu_set_t *cpuset = NULL;

                r = parse_cpu_set(eq, &cpuset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s value: %s", field, eq);

                return bus_append_byte_array(m, field, cpuset, CPU_ALLOC_SIZE(r));
        }

        if (STR_IN_SET(field, "RestrictAddressFamilies", "SystemCallFilter")) {
                int whitelist = 1;
                const char *p = eq;

                if (*p == '~') {
                        whitelist = 0;
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

                r = sd_bus_message_append_basic(m, 'b', &whitelist);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return bus_log_create_error(r);

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
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

        if (STR_IN_SET(field, "BindPaths", "BindReadOnlyPaths")) {
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

                        r = extract_first_word(&p, &source, ":" WHITESPACE, EXTRACT_QUOTES|EXTRACT_DONT_COALESCE_SEPARATORS);
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
                                r = extract_first_word(&p, &destination, ":" WHITESPACE, EXTRACT_QUOTES|EXTRACT_DONT_COALESCE_SEPARATORS);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse argument: %m");
                                if (r == 0) {
                                        log_error("Missing argument after ':': %s", eq);
                                        return -EINVAL;
                                }

                                d = destination;

                                if (p && p[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&p, &options, NULL, EXTRACT_QUOTES);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse argument: %m");

                                        if (isempty(options) || streq(options, "rbind"))
                                                flags = MS_REC;
                                        else if (streq(options, "norbind"))
                                                flags = 0;
                                        else {
                                                log_error("Unknown options: %s", eq);
                                                return -EINVAL;
                                        }
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

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse argument: %m");
                        if (r == 0)
                                break;

                        w = word;
                        r = extract_first_word(&w, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse argument: %m");
                        if (r == 0) {
                                log_error("Failed to parse argument: %s", p);
                                return -EINVAL;
                        }

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

        return 0;
}

static int bus_append_kill_property(sd_bus_message *m, const char *field, const char *eq) {

        if (streq(field, "KillMode"))

                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "SendSIGHUP", "SendSIGKILL"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "KillSignal", "FinalKillSignal", "WatchdogSignal"))

                return bus_append_signal_from_string(m, field, eq);

        return 0;
}

static int bus_append_mount_property(sd_bus_message *m, const char *field, const char *eq) {

        if (STR_IN_SET(field, "What", "Where", "Options", "Type"))

                return bus_append_string(m, field, eq);

        if (streq(field, "TimeoutSec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "DirectoryMode"))

                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field, "SloppyOptions", "LazyUnmount", "ForceUnmount"))

                return bus_append_parse_boolean(m, field, eq);

        return 0;
}

static int bus_append_path_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (streq(field, "MakeDirectory"))

                return bus_append_parse_boolean(m, field, eq);

        if (streq(field, "DirectoryMode"))

                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field,
                       "PathExists", "PathExistsGlob", "PathChanged",
                       "PathModified", "DirectoryNotEmpty")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "(sv)", "Paths", "a(ss)", 0);
                else
                        r = sd_bus_message_append(m, "(sv)", "Paths", "a(ss)", 1, field, eq);
                if (r < 0)
                        return bus_log_create_error(r);

                return 1;
        }

        return 0;
}

static int bus_append_service_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field,
                       "PIDFile", "Type", "Restart", "BusName", "NotifyAccess",
                       "USBFunctionDescriptors", "USBFunctionStrings"))

                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field, "PermissionsStartOnly", "RootDirectoryStartOnly", "RemainAfterExit", "GuessMainPID"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "RestartSec", "TimeoutStartSec", "TimeoutStopSec", "RuntimeMaxSec", "WatchdogSec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "TimeoutSec")) {

                r = bus_append_parse_sec_rename(m, "TimeoutStartSec", eq);
                if (r < 0)
                        return r;

                return bus_append_parse_sec_rename(m, "TimeoutStopSec", eq);
        }

        if (streq(field, "FileDescriptorStoreMax"))

                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field,
                       "ExecStartPre", "ExecStart", "ExecStartPost",
                       "ExecReload", "ExecStop", "ExecStopPost"))

                return bus_append_exec_command(m, field, eq);

        if (STR_IN_SET(field, "RestartPreventExitStatus", "RestartForceExitStatus", "SuccessExitStatus")) {
                _cleanup_free_ int *status = NULL, *signal = NULL;
                size_t sz_status = 0, sz_signal = 0;
                const char *p;

                for (p = eq;;) {
                        _cleanup_free_ char *word = NULL;
                        int val;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Invalid syntax in %s: %s", field, eq);

                        r = safe_atoi(word, &val);
                        if (r < 0) {
                                val = signal_from_string(word);
                                if (val < 0)
                                        return log_error_errno(r, "Invalid status or signal %s in %s: %m", word, field);

                                signal = reallocarray(signal, sz_signal + 1, sizeof(int));
                                if (!signal)
                                        return log_oom();

                                signal[sz_signal++] = val;
                        } else {
                                status = reallocarray(status, sz_status + 1, sizeof(int));
                                if (!status)
                                        return log_oom();

                                status[sz_status++] = val;
                        }
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

                r = sd_bus_message_append_array(m, 'i', status, sz_status);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_array(m, 'i', signal, sz_signal);
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

        return 0;
}

static int bus_append_socket_property(sd_bus_message *m, const char *field, const char *eq) {
        int r;

        if (STR_IN_SET(field,
                       "Accept", "Writable", "KeepAlive", "NoDelay", "FreeBind", "Transparent", "Broadcast",
                       "PassCredentials", "PassSecurity", "ReusePort", "RemoveOnStop", "SELinuxContextFromNet"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "Priority", "IPTTL", "Mark"))

                return bus_append_safe_atoi(m, field, eq);

        if (streq(field, "IPTOS"))

                return bus_append_ip_tos_from_string(m, field, eq);

        if (STR_IN_SET(field, "Backlog", "MaxConnections", "MaxConnectionsPerSource", "KeepAliveProbes", "TriggerLimitBurst"))

                return bus_append_safe_atou(m, field, eq);

        if (STR_IN_SET(field, "SocketMode", "DirectoryMode"))

                return bus_append_parse_mode(m, field, eq);

        if (STR_IN_SET(field, "MessageQueueMaxMessages", "MessageQueueMessageSize"))

                return bus_append_safe_atoi64(m, field, eq);

        if (STR_IN_SET(field, "TimeoutSec", "KeepAliveTimeSec", "KeepAliveIntervalSec", "DeferAcceptSec", "TriggerLimitIntervalSec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (STR_IN_SET(field, "ReceiveBuffer", "SendBuffer", "PipeSize"))

                return bus_append_parse_size(m, field, eq, 1024);

        if (STR_IN_SET(field, "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStopPost"))

                return bus_append_exec_command(m, field, eq);

        if (STR_IN_SET(field,
                       "SmackLabel", "SmackLabelIPIn", "SmackLabelIPOut", "TCPCongestion",
                       "BindToDevice", "BindIPv6Only", "FileDescriptorName",
                       "SocketUser", "SocketGroup"))

                return bus_append_string(m, field, eq);

        if (streq(field, "Symlinks"))

                return bus_append_strv(m, field, eq, EXTRACT_QUOTES);

        if (streq(field, "SocketProtocol"))

                return bus_append_socket_protocol_from_name(m, field, eq);

        if (STR_IN_SET(field,
                       "ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenNetlink",
                       "ListenSpecial", "ListenMessageQueue", "ListenFIFO", "ListenUSBFunction")) {

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

        if (STR_IN_SET(field, "WakeSystem", "RemainAfterElapse", "Persistent"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "AccuracySec", "RandomizedDelaySec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (STR_IN_SET(field,
                       "OnActiveSec", "OnBootSec", "OnStartupSec",
                       "OnUnitActiveSec","OnUnitInactiveSec")) {

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

        if (STR_IN_SET(field,
                       "Description", "SourcePath", "OnFailureJobMode",
                       "JobTimeoutAction", "JobTimeoutRebootArgument",
                       "StartLimitAction", "FailureAction", "SuccessAction",
                       "RebootArgument", "CollectMode"))

                return bus_append_string(m, field, eq);

        if (STR_IN_SET(field,
                       "StopWhenUnneeded", "RefuseManualStart", "RefuseManualStop",
                       "AllowIsolate", "IgnoreOnIsolate", "DefaultDependencies"))

                return bus_append_parse_boolean(m, field, eq);

        if (STR_IN_SET(field, "JobTimeoutSec", "JobRunningTimeoutSec", "StartLimitIntervalSec"))

                return bus_append_parse_sec_rename(m, field, eq);

        if (streq(field, "StartLimitBurst"))

                return bus_append_safe_atou(m, field, eq);

        if (unit_dependency_from_string(field) >= 0 ||
            STR_IN_SET(field, "Documentation", "RequiresMountsFor"))

                return bus_append_strv(m, field, eq, EXTRACT_QUOTES);

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
        if (!eq) {
                log_error("Not an assignment: %s", assignment);
                return -EINVAL;
        }

        field = strndupa(assignment, eq - assignment);
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

                if (streq(field, "TimeoutStopSec"))
                        return bus_append_parse_sec_rename(m, field, eq);

                r = bus_append_cgroup_property(m, field, eq);
                if (r != 0)
                        return r;

                r = bus_append_kill_property(m, field, eq);
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
                log_error("Not supported unit type");
                return -EINVAL;

        default:
                log_error("Invalid unit type");
                return -EINVAL;
        }

        r = bus_append_unit_property(m, field, eq);
        if (r != 0)
                return r;

        log_error("Unknown assignment: %s", assignment);
        return -EINVAL;
}

int bus_append_unit_property_assignment_many(sd_bus_message *m, UnitType t, char **l) {
        char **i;
        int r;

        assert(m);

        STRV_FOREACH(i, l) {
                r = bus_append_unit_property_assignment(m, t, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

typedef struct BusWaitForJobs {
        sd_bus *bus;
        Set *jobs;

        char *name;
        char *result;

        sd_bus_slot *slot_job_removed;
        sd_bus_slot *slot_disconnected;
} BusWaitForJobs;

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert(m);

        log_error("Warning! D-Bus connection terminated.");
        sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *path, *unit, *result;
        BusWaitForJobs *d = userdata;
        uint32_t id;
        char *found;
        int r;

        assert(m);
        assert(d);

        r = sd_bus_message_read(m, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        found = set_remove(d->jobs, (char*) path);
        if (!found)
                return 0;

        free(found);

        if (!isempty(result))
                d->result = strdup(result);

        if (!isempty(unit))
                d->name = strdup(unit);

        return 0;
}

void bus_wait_for_jobs_free(BusWaitForJobs *d) {
        if (!d)
                return;

        set_free_free(d->jobs);

        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_slot_unref(d->slot_job_removed);

        sd_bus_unref(d->bus);

        free(d->name);
        free(d->result);

        free(d);
}

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new0(BusWaitForJobs, 1);
        if (!d)
                return -ENOMEM;

        d->bus = sd_bus_ref(bus);

        /* When we are a bus client we match by sender. Direct
         * connections OTOH have no initialized sender field, and
         * hence we ignore the sender then */
        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_job_removed,
                        bus->bus_client ? "org.freedesktop.systemd1" : NULL,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobRemoved",
                        match_job_removed, NULL, d);
        if (r < 0)
                return r;

        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_disconnected,
                        "org.freedesktop.DBus.Local",
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        match_disconnected, NULL, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);

        return 0;
}

static int bus_process_wait(sd_bus *bus) {
        int r;

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

static int bus_job_get_service_result(BusWaitForJobs *d, char **result) {
        _cleanup_free_ char *dbus_path = NULL;

        assert(d);
        assert(d->name);
        assert(result);

        if (!endswith(d->name, ".service"))
                return -EINVAL;

        dbus_path = unit_dbus_path_from_name(d->name);
        if (!dbus_path)
                return -ENOMEM;

        return sd_bus_get_property_string(d->bus,
                                          "org.freedesktop.systemd1",
                                          dbus_path,
                                          "org.freedesktop.systemd1.Service",
                                          "Result",
                                          NULL,
                                          result);
}

static const struct {
        const char *result, *explanation;
} explanations [] = {
        { "resources",   "of unavailable resources or another system error" },
        { "protocol",    "the service did not take the steps required by its unit configuration" },
        { "timeout",     "a timeout was exceeded" },
        { "exit-code",   "the control process exited with error code" },
        { "signal",      "a fatal signal was delivered to the control process" },
        { "core-dump",   "a fatal signal was delivered causing the control process to dump core" },
        { "watchdog",    "the service failed to send watchdog ping" },
        { "start-limit", "start of the service was attempted too often" }
};

static void log_job_error_with_service_result(const char* service, const char *result, const char* const* extra_args) {
        _cleanup_free_ char *service_shell_quoted = NULL;
        const char *systemctl = "systemctl", *journalctl = "journalctl";

        assert(service);

        service_shell_quoted = shell_maybe_quote(service, ESCAPE_BACKSLASH);

        if (!strv_isempty((char**) extra_args)) {
                _cleanup_free_ char *t;

                t = strv_join((char**) extra_args, " ");
                systemctl = strjoina("systemctl ", t ? : "<args>");
                journalctl = strjoina("journalctl ", t ? : "<args>");
        }

        if (!isempty(result)) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(explanations); ++i)
                        if (streq(result, explanations[i].result))
                                break;

                if (i < ELEMENTSOF(explanations)) {
                        log_error("Job for %s failed because %s.\n"
                                  "See \"%s status %s\" and \"%s -xe\" for details.\n",
                                  service,
                                  explanations[i].explanation,
                                  systemctl,
                                  service_shell_quoted ?: "<service>",
                                  journalctl);
                        goto finish;
                }
        }

        log_error("Job for %s failed.\n"
                  "See \"%s status %s\" and \"%s -xe\" for details.\n",
                  service,
                  systemctl,
                  service_shell_quoted ?: "<service>",
                  journalctl);

finish:
        /* For some results maybe additional explanation is required */
        if (streq_ptr(result, "start-limit"))
                log_info("To force a start use \"%1$s reset-failed %2$s\"\n"
                         "followed by \"%1$s start %2$s\" again.",
                         systemctl,
                         service_shell_quoted ?: "<service>");
}

static int check_wait_response(BusWaitForJobs *d, bool quiet, const char* const* extra_args) {
        assert(d->result);

        if (!quiet) {
                if (streq(d->result, "canceled"))
                        log_error("Job for %s canceled.", strna(d->name));
                else if (streq(d->result, "timeout"))
                        log_error("Job for %s timed out.", strna(d->name));
                else if (streq(d->result, "dependency"))
                        log_error("A dependency job for %s failed. See 'journalctl -xe' for details.", strna(d->name));
                else if (streq(d->result, "invalid"))
                        log_error("%s is not active, cannot reload.", strna(d->name));
                else if (streq(d->result, "assert"))
                        log_error("Assertion failed on job for %s.", strna(d->name));
                else if (streq(d->result, "unsupported"))
                        log_error("Operation on or unit type of %s not supported on this system.", strna(d->name));
                else if (streq(d->result, "collected"))
                        log_error("Queued job for %s was garbage collected.", strna(d->name));
                else if (streq(d->result, "once"))
                        log_error("Unit %s was started already once and can't be started again.", strna(d->name));
                else if (!STR_IN_SET(d->result, "done", "skipped")) {
                        if (d->name) {
                                _cleanup_free_ char *result = NULL;
                                int q;

                                q = bus_job_get_service_result(d, &result);
                                if (q < 0)
                                        log_debug_errno(q, "Failed to get Result property of unit %s: %m", d->name);

                                log_job_error_with_service_result(d->name, result, extra_args);
                        } else
                                log_error("Job failed. See \"journalctl -xe\" for details.");
                }
        }

        if (STR_IN_SET(d->result, "canceled", "collected"))
                return -ECANCELED;
        else if (streq(d->result, "timeout"))
                return -ETIME;
        else if (streq(d->result, "dependency"))
                return -EIO;
        else if (streq(d->result, "invalid"))
                return -ENOEXEC;
        else if (streq(d->result, "assert"))
                return -EPROTO;
        else if (streq(d->result, "unsupported"))
                return -EOPNOTSUPP;
        else if (streq(d->result, "once"))
                return -ESTALE;
        else if (STR_IN_SET(d->result, "done", "skipped"))
                return 0;

        log_debug("Unexpected job result, assuming server side newer than us: %s", d->result);
        return -EIO;
}

int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet, const char* const* extra_args) {
        int r = 0;

        assert(d);

        while (!set_isempty(d->jobs)) {
                int q;

                q = bus_process_wait(d->bus);
                if (q < 0)
                        return log_error_errno(q, "Failed to wait for response: %m");

                if (d->result) {
                        q = check_wait_response(d, quiet, extra_args);
                        /* Return the first error as it is most likely to be
                         * meaningful. */
                        if (q < 0 && r == 0)
                                r = q;

                        log_debug_errno(q, "Got result %s/%m for job %s", strna(d->result), strna(d->name));
                }

                d->name = mfree(d->name);
                d->result = mfree(d->result);
        }

        return r;
}

int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path) {
        int r;

        assert(d);

        r = set_ensure_allocated(&d->jobs, &string_hash_ops);
        if (r < 0)
                return r;

        return set_put_strdup(d->jobs, path);
}

int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet) {
        int r;

        r = bus_wait_for_jobs_add(d, path);
        if (r < 0)
                return log_oom();

        return bus_wait_for_jobs(d, quiet, NULL);
}

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet, UnitFileChange **changes, size_t *n_changes) {
        const char *type, *path, *source;
        int r;

        /* changes is dereferenced when calling unit_file_dump_changes() later,
         * so we have to make sure this is not NULL. */
        assert(changes);
        assert(n_changes);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(m, "(sss)", &type, &path, &source)) > 0) {
                /* We expect only "success" changes to be sent over the bus.
                   Hence, reject anything negative. */
                UnitFileChangeType ch = unit_file_change_type_from_string(type);

                if (ch < 0) {
                        log_notice("Manager reported unknown change type \"%s\" for path \"%s\", ignoring.", type, path);
                        continue;
                }

                r = unit_file_changes_add(changes, n_changes, ch, path, source);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        unit_file_dump_changes(0, NULL, *changes, *n_changes, quiet);
        return 0;
}

struct CGroupInfo {
        char *cgroup_path;
        bool is_const; /* If false, cgroup_path should be free()'d */

        Hashmap *pids; /* PID → process name */
        bool done;

        struct CGroupInfo *parent;
        LIST_FIELDS(struct CGroupInfo, siblings);
        LIST_HEAD(struct CGroupInfo, children);
        size_t n_children;
};

static bool IS_ROOT(const char *p) {
        return isempty(p) || streq(p, "/");
}

static int add_cgroup(Hashmap *cgroups, const char *path, bool is_const, struct CGroupInfo **ret) {
        struct CGroupInfo *parent = NULL, *cg;
        int r;

        assert(cgroups);
        assert(ret);

        if (IS_ROOT(path))
                path = "/";

        cg = hashmap_get(cgroups, path);
        if (cg) {
                *ret = cg;
                return 0;
        }

        if (!IS_ROOT(path)) {
                const char *e, *pp;

                e = strrchr(path, '/');
                if (!e)
                        return -EINVAL;

                pp = strndupa(path, e - path);
                if (!pp)
                        return -ENOMEM;

                r = add_cgroup(cgroups, pp, false, &parent);
                if (r < 0)
                        return r;
        }

        cg = new0(struct CGroupInfo, 1);
        if (!cg)
                return -ENOMEM;

        if (is_const)
                cg->cgroup_path = (char*) path;
        else {
                cg->cgroup_path = strdup(path);
                if (!cg->cgroup_path) {
                        free(cg);
                        return -ENOMEM;
                }
        }

        cg->is_const = is_const;
        cg->parent = parent;

        r = hashmap_put(cgroups, cg->cgroup_path, cg);
        if (r < 0) {
                if (!is_const)
                        free(cg->cgroup_path);
                free(cg);
                return r;
        }

        if (parent) {
                LIST_PREPEND(siblings, parent->children, cg);
                parent->n_children++;
        }

        *ret = cg;
        return 1;
}

static int add_process(
                Hashmap *cgroups,
                const char *path,
                pid_t pid,
                const char *name) {

        struct CGroupInfo *cg;
        int r;

        assert(cgroups);
        assert(name);
        assert(pid > 0);

        r = add_cgroup(cgroups, path, true, &cg);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&cg->pids, &trivial_hash_ops);
        if (r < 0)
                return r;

        return hashmap_put(cg->pids, PID_TO_PTR(pid), (void*) name);
}

static void remove_cgroup(Hashmap *cgroups, struct CGroupInfo *cg) {
        assert(cgroups);
        assert(cg);

        while (cg->children)
                remove_cgroup(cgroups, cg->children);

        hashmap_remove(cgroups, cg->cgroup_path);

        if (!cg->is_const)
                free(cg->cgroup_path);

        hashmap_free(cg->pids);

        if (cg->parent)
                LIST_REMOVE(siblings, cg->parent->children, cg);

        free(cg);
}

static int cgroup_info_compare_func(struct CGroupInfo * const *a, struct CGroupInfo * const *b) {
        return strcmp((*a)->cgroup_path, (*b)->cgroup_path);
}

static int dump_processes(
                Hashmap *cgroups,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        struct CGroupInfo *cg;
        int r;

        assert(prefix);

        if (IS_ROOT(cgroup_path))
                cgroup_path = "/";

        cg = hashmap_get(cgroups, cgroup_path);
        if (!cg)
                return 0;

        if (!hashmap_isempty(cg->pids)) {
                const char *name;
                size_t n = 0, i;
                pid_t *pids;
                void *pidp;
                Iterator j;
                int width;

                /* Order processes by their PID */
                pids = newa(pid_t, hashmap_size(cg->pids));

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j)
                        pids[n++] = PTR_TO_PID(pidp);

                assert(n == hashmap_size(cg->pids));
                typesafe_qsort(pids, n, pid_compare_func);

                width = DECIMAL_STR_WIDTH(pids[n-1]);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *e = NULL;
                        const char *special;
                        bool more;

                        name = hashmap_get(cg->pids, PID_TO_PTR(pids[i]));
                        assert(name);

                        if (n_columns != 0) {
                                unsigned k;

                                k = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                                e = ellipsize(name, k, 100);
                                if (e)
                                        name = e;
                        }

                        more = i+1 < n || cg->children;
                        special = special_glyph(more ? TREE_BRANCH : TREE_RIGHT);

                        fprintf(stdout, "%s%s%*"PID_PRI" %s\n",
                                prefix,
                                special,
                                width, pids[i],
                                name);
                }
        }

        if (cg->children) {
                struct CGroupInfo **children, *child;
                size_t n = 0, i;

                /* Order subcgroups by their name */
                children = newa(struct CGroupInfo*, cg->n_children);
                LIST_FOREACH(siblings, child, cg->children)
                        children[n++] = child;
                assert(n == cg->n_children);
                typesafe_qsort(children, n, cgroup_info_compare_func);

                if (n_columns != 0)
                        n_columns = MAX(LESS_BY(n_columns, 2U), 20U);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *pp = NULL;
                        const char *name, *special;
                        bool more;

                        child = children[i];

                        name = strrchr(child->cgroup_path, '/');
                        if (!name)
                                return -EINVAL;
                        name++;

                        more = i+1 < n;
                        special = special_glyph(more ? TREE_BRANCH : TREE_RIGHT);

                        fputs(prefix, stdout);
                        fputs(special, stdout);
                        fputs(name, stdout);
                        fputc('\n', stdout);

                        special = special_glyph(more ? TREE_VERTICAL : TREE_SPACE);

                        pp = strappend(prefix, special);
                        if (!pp)
                                return -ENOMEM;

                        r = dump_processes(cgroups, child->cgroup_path, pp, n_columns, flags);
                        if (r < 0)
                                return r;
                }
        }

        cg->done = true;
        return 0;
}

static int dump_extra_processes(
                Hashmap *cgroups,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        _cleanup_free_ pid_t *pids = NULL;
        _cleanup_hashmap_free_ Hashmap *names = NULL;
        struct CGroupInfo *cg;
        size_t n_allocated = 0, n = 0, k;
        Iterator i;
        int width, r;

        /* Prints the extra processes, i.e. those that are in cgroups we haven't displayed yet. We show them as
         * combined, sorted, linear list. */

        HASHMAP_FOREACH(cg, cgroups, i) {
                const char *name;
                void *pidp;
                Iterator j;

                if (cg->done)
                        continue;

                if (hashmap_isempty(cg->pids))
                        continue;

                r = hashmap_ensure_allocated(&names, &trivial_hash_ops);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(pids, n_allocated, n + hashmap_size(cg->pids)))
                        return -ENOMEM;

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j) {
                        pids[n++] = PTR_TO_PID(pidp);

                        r = hashmap_put(names, pidp, (void*) name);
                        if (r < 0)
                                return r;
                }
        }

        if (n == 0)
                return 0;

        typesafe_qsort(pids, n, pid_compare_func);
        width = DECIMAL_STR_WIDTH(pids[n-1]);

        for (k = 0; k < n; k++) {
                _cleanup_free_ char *e = NULL;
                const char *name;

                name = hashmap_get(names, PID_TO_PTR(pids[k]));
                assert(name);

                if (n_columns != 0) {
                        unsigned z;

                        z = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                        e = ellipsize(name, z, 100);
                        if (e)
                                name = e;
                }

                fprintf(stdout, "%s%s %*" PID_PRI " %s\n",
                        prefix,
                        special_glyph(TRIANGULAR_BULLET),
                        width, pids[k],
                        name);
        }

        return 0;
}

int unit_show_processes(
                sd_bus *bus,
                const char *unit,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Hashmap *cgroups = NULL;
        struct CGroupInfo *cg;
        int r;

        assert(bus);
        assert(unit);

        if (flags & OUTPUT_FULL_WIDTH)
                n_columns = 0;
        else if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "GetUnitProcesses",
                        error,
                        &reply,
                        "s",
                        unit);
        if (r < 0)
                return r;

        cgroups = hashmap_new(&path_hash_ops);
        if (!cgroups)
                return -ENOMEM;

        r = sd_bus_message_enter_container(reply, 'a', "(sus)");
        if (r < 0)
                goto finish;

        for (;;) {
                const char *path = NULL, *name = NULL;
                uint32_t pid;

                r = sd_bus_message_read(reply, "(sus)", &path, &pid, &name);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        break;

                r = add_process(cgroups, path, pid, name);
                if (r < 0)
                        goto finish;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto finish;

        r = dump_processes(cgroups, cgroup_path, prefix, n_columns, flags);
        if (r < 0)
                goto finish;

        r = dump_extra_processes(cgroups, prefix, n_columns, flags);

finish:
        while ((cg = hashmap_first(cgroups)))
               remove_cgroup(cgroups, cg);

        hashmap_free(cgroups);

        return r;
}

int unit_load_state(sd_bus *bus, const char *name, char **load_state) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        path = unit_dbus_path_from_name(name);
        if (!path)
                return log_oom();

        /* This function warns on it's own, because otherwise it'd be awkward to pass
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
