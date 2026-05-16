/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-journal.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ask-password-agent.h"
#include "build.h"
#include "build-path.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-message-util.h"
#include "bus-print-properties.h"
#include "bus-unit-procs.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "edit-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "format-table.h"
#include "format-util.h"
#include "help-util.h"
#include "hostname-util.h"
#include "import-util.h"
#include "in-addr-util.h"
#include "json-util.h"
#include "label-util.h"
#include "log.h"
#include "logs-show.h"
#include "machine-dbus.h"
#include "machine-util.h"
#include "main-func.h"
#include "nulstr-util.h"
#include "options.h"
#include "osc-context.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "runtime-scope.h"
#include "stdio-util.h"
#include "storage-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "unit-name.h"
#include "verbs.h"

typedef enum MachineRunner {
        RUNNER_NSPAWN,
        RUNNER_VMSPAWN,
        _RUNNER_MAX,
        _RUNNER_INVALID = -EINVAL,
} MachineRunner;

static const char* const machine_runner_table[_RUNNER_MAX] = {
        [RUNNER_NSPAWN]  = "nspawn",
        [RUNNER_VMSPAWN] = "vmspawn",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(machine_runner, MachineRunner);

static const char* const machine_runner_unit_prefix_table[_RUNNER_MAX] = {
        [RUNNER_NSPAWN]  = "systemd-nspawn",
        [RUNNER_VMSPAWN] = "systemd-vmspawn",
};

static char **arg_property = NULL;
static bool arg_all = false;
static BusPrintPropertyFlags arg_print_flags = 0;
static bool arg_full = false;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static const char *arg_kill_whom = NULL;
static int arg_signal = SIGTERM;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_read_only = false;
static bool arg_mkdir = false;
static bool arg_quiet = false;
static bool arg_ask_password = true;
static unsigned arg_lines = 10;
static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_now = false;
static bool arg_force = false;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static MachineRunner arg_runner = RUNNER_NSPAWN;
static const char* arg_format = NULL;
static const char *arg_uid = NULL;
static char **arg_setenv = NULL;
static unsigned arg_max_addresses = 1;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_setenv, strv_freep);

static OutputFlags get_output_flags(void) {
        return
                FLAGS_SET(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY) * OUTPUT_SHOW_ALL |
                (arg_full || !on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                colors_enabled() * OUTPUT_COLOR |
                !arg_quiet * OUTPUT_WARN_CUTOFF;
}

static int call_get_os_release(sd_bus *bus, const char *method, const char *name, const char *query, ...) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        va_list ap;
        int r;

        assert(bus);
        assert(method);
        assert(name);
        assert(query);

        r = bus_call_method(bus, bus_machine_mgr, method, &error, &reply, "s", name);
        if (r < 0)
                return log_debug_errno(r, "Failed to call '%s()': %s", method, bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r < 0)
                return bus_log_parse_error(r);

        const char **res;
        size_t n_fields = 0;

        NULSTR_FOREACH(i, query)
                n_fields++;

        res = newa0(const char*, n_fields);

        const char *k, *v;
        while ((r = sd_bus_message_read(reply, "{ss}", &k, &v)) > 0) {
                size_t c = 0;
                NULSTR_FOREACH(i, query) {
                        if (streq(i, k)) {
                                res[c] = v;
                                break;
                        }
                        c++;
                }
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = 0;

        va_start(ap, query);
        FOREACH_ARRAY(i, res, n_fields) {
                r = strdup_to(va_arg(ap, char**), *i);
                if (r < 0)
                        break;
        }
        va_end(ap);

        return r;
}

static int call_get_addresses(
                sd_bus *bus,
                const char *name,
                int ifi,
                const char *prefix,
                const char *prefix2,
                char **ret) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *addresses = NULL;
        unsigned n = 0;
        int r;

        assert(bus);
        assert(name);
        assert(prefix);
        assert(prefix2);
        assert(ret);

        r = bus_call_method(bus, bus_machine_mgr, "GetMachineAddresses", NULL, &reply, "s", name);
        if (r < 0)
                return log_debug_errno(r, "Could not get addresses: %s", bus_error_message(&error, r));

        addresses = strdup(prefix);
        if (!addresses)
                return log_oom();

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                return bus_log_parse_error(r);

        prefix = "";
        while ((r = sd_bus_message_enter_container(reply, 'r', "iay")) > 0) {
                int family;
                const void *a;
                size_t sz;
                char buf_ifi[1 + DECIMAL_STR_MAX(int)] = "";

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (family == AF_INET6 && ifi > 0)
                        xsprintf(buf_ifi, "%%%i", ifi);

                if (!strextend(&addresses, prefix, IN_ADDR_TO_STRING(family, a), buf_ifi))
                        return log_oom();

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                prefix = prefix2;

                n++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        *ret = TAKE_PTR(addresses);
        return (int) n;
}

static int show_table(Table *table, const char *word) {
        int r;

        assert(table);
        assert(word);

        if (!table_isempty(table) || OUTPUT_MODE_IS_JSON(arg_output)) {
                r = table_set_sort(table, (size_t) 0);
                if (r < 0)
                        return table_log_sort_error(r);

                table_set_header(table, arg_legend);

                if (OUTPUT_MODE_IS_JSON(arg_output))
                        r = table_print_json(table, NULL, output_mode_to_json_format_flags(arg_output) | SD_JSON_FORMAT_COLOR_AUTO);
                else
                        r = table_print(table);
                if (r < 0)
                        return table_log_print_error(r);
        }

        if (arg_legend) {
                if (table_isempty(table))
                        printf("No %s.\n", word);
                else
                        printf("\n%zu %s listed.\n", table_get_rows(table) - 1, word);
        }

        return 0;
}

VERB_GROUP("Machine Commands");

VERB_DEFAULT_NOARG(verb_list_machines, "list", "List running VMs and containers");
static int verb_list_machines(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_machine_mgr, "ListMachines", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get machines: %s", bus_error_message(&error, r));

        table = table_new("machine", "class", "service", "os", "version",
                          arg_max_addresses > 0 ? "addresses" : NULL);
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        if (!arg_full && arg_max_addresses > 0 && arg_max_addresses < UINT_MAX)
                table_set_cell_height_max(table, arg_max_addresses);

        if (arg_full)
                table_set_width(table, 0);

        r = sd_bus_message_enter_container(reply, 'a', "(ssso)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                _cleanup_free_ char *os = NULL, *version_id = NULL, *addresses = NULL;
                const char *name, *class, *service;

                r = sd_bus_message_read(reply, "(ssso)", &name, &class, &service, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (name[0] == '.' && !arg_all)
                        continue;

                (void) call_get_os_release(
                                bus,
                                "GetMachineOSRelease",
                                name,
                                "ID\0"
                                "VERSION_ID\0",
                                &os,
                                &version_id);

                r = table_add_many(table,
                                   TABLE_STRING, empty_to_null(name),
                                   TABLE_STRING, empty_to_null(class),
                                   TABLE_STRING, empty_to_null(service),
                                   TABLE_STRING, empty_to_null(os),
                                   TABLE_STRING, empty_to_null(version_id));
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_max_addresses > 0) {
                        (void) call_get_addresses(bus, name, 0, "", "\n", &addresses);

                        r = table_add_many(table,
                                           TABLE_STRING, empty_to_null(addresses));
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return show_table(table, "machines");
}

static int show_unit_cgroup(
                sd_bus *bus,
                const char *unit,
                const char *subgroup,
                pid_t leader) {

        _cleanup_free_ char *cgroup = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        OutputFlags extra_flags = 0;
        int r;

        assert(bus);
        assert(unit);

        r = show_cgroup_get_unit_path_and_warn(bus, unit, &cgroup);
        if (r < 0)
                return r;

        if (isempty(cgroup))
                return 0;

        if (!empty_or_root(subgroup)) {
                if (!path_extend(&cgroup, subgroup))
                        return log_oom();

                /* If we have a subcgroup, then hide all processes outside of it */
                extra_flags |= OUTPUT_HIDE_EXTRA;
        }

        unsigned c = MAX(LESS_BY(columns(), 18U), 10U);
        r = unit_show_processes(bus, unit, cgroup, "\t\t  ", c, get_output_flags() | extra_flags, &error);
        if (r == -EBADR) {

                if (arg_transport == BUS_TRANSPORT_REMOTE)
                        return 0;

                /* Fallback for older systemd versions where the GetUnitProcesses() call is not yet available */

                if (cg_is_empty(cgroup) != 0 && leader <= 0)
                        return 0;

                show_cgroup_and_extra(cgroup, "\t\t  ", c, &leader, leader > 0, get_output_flags());
        } else if (r < 0)
                return log_error_errno(r, "Failed to dump process list: %s", bus_error_message(&error, r));

        return 0;
}

static int print_os_release(sd_bus *bus, const char *method, const char *name, const char *prefix) {
        _cleanup_free_ char *pretty = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(prefix);

        r = call_get_os_release(bus, method, name, "PRETTY_NAME\0", &pretty, NULL);
        if (r < 0)
                return r;

        if (pretty)
                printf("%s%s\n", prefix, pretty);

        return 0;
}

static int print_uid_shift(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        uint32_t shift;
        int r;

        assert(bus);
        assert(name);

        r = bus_call_method(bus, bus_machine_mgr, "GetMachineUIDShift", &error, &reply, "s", name);
        if (r < 0)
                return log_debug_errno(r, "Failed to query UID/GID shift: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "u", &shift);
        if (r < 0)
                return r;

        if (shift == 0) /* Don't show trivial mappings */
                return 0;

        printf("\tID Shift: %" PRIu32 "\n", shift);
        return 0;
}

typedef struct MachineStatusInfo {
        const char *name;
        sd_id128_t id;
        const char *class;
        const char *service;
        const char *unit;
        const char *subgroup;
        const char *root_directory;
        pid_t leader;
        uint64_t leader_pidfdid;
        pid_t supervisor;
        uint64_t supervisor_pidfdid;
        struct dual_timestamp timestamp;
        int *netif;
        size_t n_netif;
        uid_t uid;
} MachineStatusInfo;

static void machine_status_info_done(MachineStatusInfo *info) {
        if (!info)
                return;

        free(info->netif);
        zero(*info);
}

static void print_process_info(const char *field, pid_t pid, uint64_t pidfdid) {
        int r;

        assert(field);

        if (pid <= 0)
                return;

        printf("%s: " PID_FMT, field, pid);

        _cleanup_(pidref_done) PidRef pr = PIDREF_NULL;
        r = pidref_set_pid_and_pidfd_id(&pr, pid, pidfdid);
        if (r < 0)
                log_debug_errno(r, "Failed to acquire reference to process, ignoring: %m");
        else {
                _cleanup_free_ char *t = NULL;
                r = pidref_get_comm(&pr, &t);
                if (r < 0)
                        log_debug_errno(r, "Failed to acquire name of process, ignoring: %m");
                else
                        printf(" (%s)", t);
        }

        putchar('\n');
}

static void print_machine_status_info(sd_bus *bus, MachineStatusInfo *i) {
        _cleanup_free_ char *addresses = NULL, *s1 = NULL, *s2 = NULL;
        int ifi = -1;

        assert(bus);
        assert(i);

        fputs(strna(i->name), stdout);

        if (!sd_id128_is_null(i->id))
                printf("(" SD_ID128_FORMAT_STR ")\n", SD_ID128_FORMAT_VAL(i->id));
        else
                putchar('\n');

        s1 = strdup(strempty(FORMAT_TIMESTAMP_RELATIVE(i->timestamp.realtime)));
        s2 = strdup(strempty(FORMAT_TIMESTAMP(i->timestamp.realtime)));

        if (!isempty(s1))
                printf("\t   Since: %s; %s\n", strna(s2), s1);
        else if (!isempty(s2))
                printf("\t   Since: %s\n", s2);

        print_process_info("\t  Leader", i->leader, i->leader_pidfdid);
        print_process_info("\t Superv.", i->supervisor, i->supervisor_pidfdid);

        if (i->service) {
                printf("\t Service: %s", i->service);

                if (i->class)
                        printf("; class %s", i->class);

                putchar('\n');
        } else if (i->class)
                printf("\t   Class: %s\n", i->class);

        if (i->uid != 0)
                printf("\t     UID: " UID_FMT "\n", i->uid);

        if (i->root_directory)
                printf("\t    Root: %s\n", i->root_directory);

        if (i->n_netif > 0) {
                fputs("\t   Iface:", stdout);

                for (size_t c = 0; c < i->n_netif; c++) {
                        char name[IF_NAMESIZE];

                        if (format_ifname(i->netif[c], name) >= 0) {
                                fputc(' ', stdout);
                                fputs(name, stdout);

                                if (ifi < 0)
                                        ifi = i->netif[c];
                                else
                                        ifi = 0;
                        } else
                                printf(" %i", i->netif[c]);
                }

                fputc('\n', stdout);
        }

        if (call_get_addresses(bus, i->name, ifi,
                               "\t Address: ", "\n\t          ",
                               &addresses) > 0) {
                fputs(addresses, stdout);
                fputc('\n', stdout);
        }

        print_os_release(bus, "GetMachineOSRelease", i->name, "\t      OS: ");

        print_uid_shift(bus, i->name);

        if (i->unit) {
                printf("\t    Unit: %s\n", i->unit);

                if (!empty_or_root(i->subgroup))
                        printf("\tSubgroup: %s\n", i->subgroup);

                show_unit_cgroup(bus, i->unit, i->subgroup, i->leader);

                if (arg_transport == BUS_TRANSPORT_LOCAL)

                        show_journal_by_unit(
                                        stdout,
                                        i->unit,
                                        /* namespace= */ NULL,
                                        arg_output,
                                        /* n_columns= */ 0,
                                        i->timestamp.monotonic,
                                        arg_lines,
                                        get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                                        SD_JOURNAL_LOCAL_ONLY,
                                        /* system_unit= */ true,
                                        /* ellipsized= */ NULL);
        }
}

static int map_netif(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        MachineStatusInfo *i = userdata;
        size_t l;
        const void *v;
        int r;

        assert_cc(sizeof(int32_t) == sizeof(int));
        r = sd_bus_message_read_array(m, SD_BUS_TYPE_INT32, &v, &l);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        i->n_netif = l / sizeof(int32_t);
        i->netif = memdup(v, l);
        if (!i->netif)
                return -ENOMEM;

        return 0;
}

static int show_machine_info(const char *verb, sd_bus *bus, const char *path, bool *new_line) {
        static const struct bus_properties_map map[]  = {
                { "Name",               "s",  NULL,          offsetof(MachineStatusInfo, name)                },
                { "Class",              "s",  NULL,          offsetof(MachineStatusInfo, class)               },
                { "Service",            "s",  NULL,          offsetof(MachineStatusInfo, service)             },
                { "Unit",               "s",  NULL,          offsetof(MachineStatusInfo, unit)                },
                { "Subgroup",           "s",  NULL,          offsetof(MachineStatusInfo, subgroup)            },
                { "RootDirectory",      "s",  NULL,          offsetof(MachineStatusInfo, root_directory)      },
                { "Leader",             "u",  NULL,          offsetof(MachineStatusInfo, leader)              },
                { "LeaderPIDFDId",      "t",  NULL,          offsetof(MachineStatusInfo, leader_pidfdid)      },
                { "Supervisor",         "u",  NULL,          offsetof(MachineStatusInfo, supervisor)          },
                { "SupervisorPIDFDId",  "t",  NULL,          offsetof(MachineStatusInfo, supervisor_pidfdid)  },
                { "Timestamp",          "t",  NULL,          offsetof(MachineStatusInfo, timestamp.realtime)  },
                { "TimestampMonotonic", "t",  NULL,          offsetof(MachineStatusInfo, timestamp.monotonic) },
                { "Id",                 "ay", bus_map_id128, offsetof(MachineStatusInfo, id)                  },
                { "NetworkInterfaces",  "ai", map_netif,     0                                                },
                { "UID",                "u",  NULL,          offsetof(MachineStatusInfo, uid)                 },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(machine_status_info_done) MachineStatusInfo info = {};
        int r;

        assert(verb);
        assert(bus);
        assert(path);
        assert(new_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   path,
                                   map,
                                   0,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %s", bus_error_message(&error, r));

        if (*new_line)
                printf("\n");
        *new_line = true;

        print_machine_status_info(bus, &info);

        return r;
}

static int show_machine_properties(sd_bus *bus, const char *path, bool *new_line) {
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        if (*new_line)
                printf("\n");

        *new_line = true;

        r = bus_print_all_properties(bus, "org.freedesktop.machine1", path, NULL, arg_property, arg_print_flags, NULL);
        if (r < 0)
                log_error_errno(r, "Could not get properties: %m");

        return r;
}

VERB(verb_show_machine, "status", "NAME…", 2, VERB_ANY, 0,
     "Show VM/container details");
VERB(verb_show_machine, "show", "[NAME…]", VERB_ANY, VERB_ANY, 0,
     "Show properties of one or more VMs/containers");
static int verb_show_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool properties, new_line = false;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r = 0;

        properties = !strstr(argv[0], "status");

        pager_open(arg_pager_flags);

        if (properties && argc <= 1) {

                /* If no argument is specified, inspect the manager
                 * itself */
                r = show_machine_properties(bus, "/org/freedesktop/machine1", &new_line);
                if (r < 0)
                        return r;
        }

        for (int i = 1; i < argc; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *path = NULL;

                r = bus_call_method(bus, bus_machine_mgr, "GetMachine", &error, &reply, "s", argv[i]);
                if (r < 0)
                        return log_error_errno(r, "Could not get path to machine: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (properties)
                        r = show_machine_properties(bus, path, &new_line);
                else
                        r = show_machine_info(argv[0], bus, path, &new_line);
        }

        return r;
}

static int make_service_name(const char *name, char **ret) {
        int r;

        assert(name);
        assert(ret);
        assert(arg_runner >= 0 && arg_runner < _RUNNER_MAX);

        if (!hostname_is_valid(name, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid machine name %s.", name);

        r = unit_name_build(machine_runner_unit_prefix_table[arg_runner], name, ".service", ret);
        if (r < 0)
                return log_error_errno(r, "Failed to build unit name: %m");

        return 0;
}

static int image_exists(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(name);

        r = bus_call_method(bus, bus_machine_mgr, "GetImage", &error, NULL, "s", name);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_IMAGE))
                        return 0;

                return log_error_errno(r, "Failed to check whether image %s exists: %s", name, bus_error_message(&error, r));
        }

        return 1;
}

VERB(verb_start_machine, "start", "NAME…", 2, VERB_ANY, 0,
     "Start container as a service");
static int verb_start_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
        ask_password_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        for (int i = 1; i < argc; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_free_ char *unit = NULL;
                const char *object;

                r = make_service_name(argv[i], &unit);
                if (r < 0)
                        return r;

                r = image_exists(bus, argv[i]);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                               "Machine image '%s' does not exist.",
                                               argv[i]);

                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "StartUnit",
                                &error,
                                &reply,
                                "ss", unit, "fail");
                if (r < 0)
                        return log_error_errno(r, "Failed to start unit: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_add(w, object);
                if (r < 0)
                        return log_oom();
        }

        r = bus_wait_for_jobs(w, arg_quiet, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int parse_machine_uid(const char *spec, const char **machine, char **uid) {
        /*
         * Whatever is specified in the spec takes priority over global arguments.
         */
        char *_uid = NULL;
        const char *_machine = NULL;

        assert(uid);
        assert(machine);

        if (spec) {
                const char *at;

                at = strchr(spec, '@');
                if (at) {
                        if (at == spec)
                                /* Do the same as ssh and refuse "@host". */
                                return -EINVAL;

                        _machine = at + 1;
                        _uid = strndup(spec, at - spec);
                        if (!_uid)
                                return -ENOMEM;
                } else
                        _machine = spec;
        };

        if (arg_uid && !_uid) {
                _uid = strdup(arg_uid);
                if (!_uid)
                        return -ENOMEM;
        }

        *uid = _uid;
        *machine = isempty(_machine) ? ".host" : _machine;
        return 0;
}

static int process_forward(sd_event *event, sd_bus_slot *machine_removed_slot, int master, PTYForwardFlags flags, const char *name) {
        int r;

        assert(event);
        assert(machine_removed_slot);
        assert(master >= 0);
        assert(name);

        if (!arg_quiet) {
                if (streq(name, ".host"))
                        log_info("Connected to the local host. Press ^] three times within 1s to exit session.");
                else
                        log_info("Connected to machine %s. Press ^] three times within 1s to exit session.", name);
        }

        _cleanup_(osc_context_closep) sd_id128_t osc_context_id = SD_ID128_NULL;
        if (!terminal_is_dumb()) {
                r = osc_context_open_container(name, /* ret_seq= */ NULL, &osc_context_id);
                if (r < 0)
                        return r;
        }

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SIGINT/SITERM handling: %m");

        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        r = pty_forward_new(event, master, flags, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        /* No userdata should not set previously. */
        assert_se(!sd_bus_slot_set_userdata(machine_removed_slot, forward));

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        bool machine_died =
                FLAGS_SET(flags, PTY_FORWARD_IGNORE_VHANGUP) &&
                !pty_forward_vhangup_honored(forward);

        if (!arg_quiet) {
                if (machine_died)
                        log_info("Machine %s terminated.", name);
                else if (streq(name, ".host"))
                        log_info("Connection to the local host terminated.");
                else
                        log_info("Connection to machine %s terminated.", name);
        }

        return 0;
}

static int on_machine_removed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        PTYForward *forward = ASSERT_PTR(userdata);
        int r;

        assert(m);

        /* Tell the forwarder to exit on the next vhangup(), so that we still flush out what might be queued
         * and exit then. */

        r = pty_forward_honor_vhangup(forward);
        if (r < 0) {
                /* On error, quit immediately. */
                log_error_errno(r, "Failed to make PTY forwarder honor vhangup(): %m");
                (void) sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), EXIT_FAILURE);
        }

        return 0;
}

VERB(verb_login_machine, "login", "[NAME]", VERB_ANY, 2, 0,
     "Get a login prompt in a container or on the local host");
static int verb_login_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int master = -1, r;
        sd_bus *bus = ASSERT_PTR(userdata);
        const char *match, *machine;

        if (!strv_isempty(arg_setenv) || arg_uid)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--setenv= and --uid= are not supported for 'login'. Use 'shell' instead.");

        if (!IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_MACHINE))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Login only supported on local machines.");

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        machine = argc < 2 || isempty(argv[1]) ? ".host" : argv[1];

        match = strjoina("type='signal',"
                         "sender='org.freedesktop.machine1',"
                         "path='/org/freedesktop/machine1',",
                         "interface='org.freedesktop.machine1.Manager',"
                         "member='MachineRemoved',"
                         "arg0='", machine, "'");

        r = sd_bus_add_match_async(bus, &slot, match, on_machine_removed, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request machine removal match: %m");

        r = bus_call_method(bus, bus_machine_mgr, "OpenMachineLogin", &error, &reply, "s", machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get login PTY: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "hs", &master, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        return process_forward(event, slot, master, PTY_FORWARD_IGNORE_VHANGUP, machine);
}

VERB(verb_shell_machine, "shell", "[[USER@]NAME [COMMAND…]]", VERB_ANY, VERB_ANY, 0,
     "Invoke a shell (or other command) in a container or on the local host");
static int verb_shell_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int master = -1, r;
        sd_bus *bus = ASSERT_PTR(userdata);
        const char *match, *machine, *path;
        _cleanup_free_ char *uid = NULL;

        if (!IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_MACHINE))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Shell only supported on local machines.");

        if (terminal_is_dumb()) {
                /* Set TERM=dumb if we are running on a dumb terminal or with a pipe.
                 * Otherwise, we will get unwanted OSC sequences. */
                if (!strv_find_prefix(arg_setenv, "TERM="))
                        if (strv_extend(&arg_setenv, "TERM=dumb") < 0)
                                return log_oom();
        } else
                /* Pass $TERM & Co. to shell session, if not explicitly specified. */
                FOREACH_STRING(v, "TERM=", "COLORTERM=", "NO_COLOR=") {
                        if (strv_find_prefix(arg_setenv, v))
                                continue;

                        const char *t = strv_find_prefix(environ, v);
                        if (!t)
                                continue;

                        if (strv_extend(&arg_setenv, t) < 0)
                                return log_oom();
                }

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = parse_machine_uid(argc >= 2 ? argv[1] : NULL, &machine, &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse machine specification: %m");

        match = strjoina("type='signal',"
                         "sender='org.freedesktop.machine1',"
                         "path='/org/freedesktop/machine1',",
                         "interface='org.freedesktop.machine1.Manager',"
                         "member='MachineRemoved',"
                         "arg0='", machine, "'");

        r = sd_bus_add_match_async(bus, &slot, match, on_machine_removed, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request machine removal match: %m");

        r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "OpenMachineShell");
        if (r < 0)
                return bus_log_create_error(r);

        path = argc < 3 || isempty(argv[2]) ? NULL : argv[2];

        r = sd_bus_message_append(m, "sss", machine, uid, path);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, strv_length(argv) <= 3 ? NULL : argv + 2);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, arg_setenv);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to get shell PTY: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "hs", &master, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        return process_forward(event, slot, master, /* flags= */ 0, machine);
}

static int verb_poweroff_machine(int argc, char *argv[], uintptr_t data, void *userdata);

VERB(verb_enable_machine, "enable", "NAME…", 2, VERB_ANY, 0,
     "Enable automatic container start at boot");
VERB(verb_enable_machine, "disable", "NAME…", 2, VERB_ANY, 0,
     "Disable automatic container start at boot");
static int verb_enable_machine(int argc, char *argv[], uintptr_t data, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *method;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;
        bool enable;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        enable = streq(argv[0], "enable");
        method = enable ? "EnableUnitFiles" : "DisableUnitFiles";

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return bus_log_create_error(r);

        if (enable) {
                r = sd_bus_message_append(m, "s", "machines.target");
                if (r < 0)
                        return bus_log_create_error(r);
        }

        for (int i = 1; i < argc; i++) {
                _cleanup_free_ char *unit = NULL;

                r = make_service_name(argv[i], &unit);
                if (r < 0)
                        return r;

                r = image_exists(bus, argv[i]);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                               "Machine image '%s' does not exist.",
                                               argv[i]);

                r = sd_bus_message_append(m, "s", unit);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        if (enable)
                r = sd_bus_message_append(m, "bb", false, false);
        else
                r = sd_bus_message_append(m, "b", false);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enable or disable unit: %s", bus_error_message(&error, r));

        if (enable) {
                r = sd_bus_message_read(reply, "b", NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet);
        if (r < 0)
                return r;

        r = bus_service_manager_reload(bus);
        if (r < 0)
                return r;

        if (arg_now) {
                _cleanup_strv_free_ char **new_args = NULL;

                new_args = strv_new(enable ? "start" : "poweroff");
                if (!new_args)
                        return log_oom();

                r = strv_extend_strv(&new_args, argv + 1, /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();

                if (enable)
                        return verb_start_machine(strv_length(new_args), new_args, data, userdata);

                return verb_poweroff_machine(strv_length(new_args), new_args, data, userdata);
        }

        return 0;
}

/* Look up the controlAddress of a machine by calling machined's Machine.List varlink interface. */
static int machine_get_control_address(const char *machine_name, char **ret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        int r;

        assert(machine_name);
        assert(ret);

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return -EOPNOTSUPP;

        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/machine/io.systemd.Machine", &p);
        if (r < 0)
                return log_error_errno(r, "Failed to determine Machine varlink socket path: %m");

        r = sd_varlink_connect_address(&vl, p);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machined varlink: %m");

        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Machine.List",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", machine_name));
        if (r < 0)
                return log_error_errno(r, "Failed to list machine: %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to look up machine '%s': %s", machine_name, error_id);

        sd_json_variant *addr = sd_json_variant_by_key(reply, "controlAddress");
        if (!addr || !sd_json_variant_is_string(addr))
                return -EOPNOTSUPP; /* No varlink control socket, caller decides whether to log */

        char *a = strdup(sd_json_variant_string(addr));
        if (!a)
                return log_oom();

        *ret = a;
        return 0;
}

static int verb_machine_control_one(const char *machine_name, const char *method) {
        _cleanup_free_ char *address = NULL;
        int r;

        r = machine_get_control_address(machine_name, &address);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machine control socket: %m");

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_call(vl, method, /* parameters= */ NULL, &reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to call %s: %m", method);
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Machine control call failed: %s", error_id);

        return 0;
}

VERB(verb_poweroff_machine, "poweroff", "NAME…", 2, VERB_ANY, 0,
     "Power off one or more machines");
VERB(verb_poweroff_machine, "stop", "NAME…", 2, VERB_ANY, 0,
     /* help= */ NULL); /* Convenience alias */
static int verb_poweroff_machine(int argc, char *argv[], uintptr_t data, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                /* VM with varlink control socket: QMP graceful powerdown */
                r = verb_machine_control_one(argv[i], "io.systemd.MachineInstance.PowerOff");
                if (r >= 0)
                        continue;
                if (r != -EOPNOTSUPP)
                        return r;

                /* Not a VM: signal-based poweroff */
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = bus_call_method(bus, bus_machine_mgr, "KillMachine", &error, NULL,
                                   "ssi", argv[i], "leader", (int32_t) (SIGRTMIN+4));
                if (r < 0)
                        return log_error_errno(r, "Could not kill machine: %s", bus_error_message(&error, r));
        }

        return 0;
}

VERB(verb_reboot_machine, "reboot", "NAME…", 2, VERB_ANY, 0,
     "Reboot one or more machines");
VERB(verb_reboot_machine, "restart", "NAME…", 2, VERB_ANY, 0,
     /* help= */ NULL); /* Convenience alias */
static int verb_reboot_machine(int argc, char *argv[], uintptr_t data, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                r = verb_machine_control_one(argv[i], "io.systemd.MachineInstance.Reboot");
                if (r >= 0)
                        continue;
                if (r != -EOPNOTSUPP)
                        return r;

                /* Container fallback: SIGINT to init (sysvinit + systemd compatible) */
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = bus_call_method(bus, bus_machine_mgr, "KillMachine", &error, NULL,
                                   "ssi", argv[i], "leader", (int32_t) SIGINT);
                if (r < 0)
                        return log_error_errno(r, "Could not reboot machine '%s': %s", argv[i], bus_error_message(&error, r));
        }

        return 0;
}

static int verb_vm_control(int argc, char *argv[], const char *method) {
        int r;

        for (int i = 1; i < argc; i++) {
                r = verb_machine_control_one(argv[i], method);
                if (r == -EOPNOTSUPP)
                        return log_error_errno(r, "Machine '%s' does not expose a varlink control socket.", argv[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

VERB(verb_pause, "pause", "NAME…", 2, VERB_ANY, 0,
     "Pause one or more machines");
static int verb_pause(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return verb_vm_control(argc, argv, "io.systemd.MachineInstance.Pause");
}

VERB(verb_resume, "resume", "NAME…", 2, VERB_ANY, 0,
     "Resume one or more paused machines");
static int verb_resume(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return verb_vm_control(argc, argv, "io.systemd.MachineInstance.Resume");
}

VERB(verb_terminate_machine, "terminate", "NAME…", 2, VERB_ANY, 0,
     "Terminate one or more machines");
static int verb_terminate_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                /* VM with varlink control socket: QMP quit (immediate termination) */
                r = verb_machine_control_one(argv[i], "io.systemd.MachineInstance.Terminate");
                if (r >= 0)
                        continue;
                if (r != -EOPNOTSUPP)
                        return r;

                /* Not a VM or no varlink socket: fall back to machined */
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = bus_call_method(bus, bus_machine_mgr, "TerminateMachine", &error, NULL, "s", argv[i]);
                if (r < 0)
                        return log_error_errno(r, "Could not terminate machine: %s", bus_error_message(&error, r));
        }

        return 0;
}

VERB(verb_kill_machine, "kill", "NAME…", 2, VERB_ANY, 0,
     "Send signal to processes of a machine");
static int verb_kill_machine(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (!arg_kill_whom)
                arg_kill_whom = "all";

        for (int i = 1; i < argc; i++) {
                r = bus_call_method(
                                bus,
                                bus_machine_mgr,
                                "KillMachine",
                                &error,
                                NULL,
                                "ssi", argv[i], arg_kill_whom, arg_signal);
                if (r < 0)
                        return log_error_errno(r, "Could not kill machine: %s", bus_error_message(&error, r));
        }

        return 0;
}

static const char* select_copy_method(bool copy_from, bool force) {
        if (force)
                return copy_from ? "CopyFromMachineWithFlags" : "CopyToMachineWithFlags";
        else
                return copy_from ? "CopyFromMachine" : "CopyToMachine";
}

VERB(verb_copy_files, "copy-to", "NAME PATH [PATH]", 3, 4, 0,
     "Copy files from the host to a container");
VERB(verb_copy_files, "copy-from", "NAME PATH [PATH]", 3, 4, 0,
     "Copy files from a container to the host");
static int verb_copy_files(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *abs_host_path = NULL;
        char *dest, *host_path, *container_path;
        sd_bus *bus = ASSERT_PTR(userdata);
        bool copy_from;
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        copy_from = streq(argv[0], "copy-from");
        dest = argv[3] ?: argv[2];
        host_path = copy_from ? dest : argv[2];
        container_path = copy_from ? argv[2] : dest;

        if (!path_is_absolute(host_path)) {
                r = path_make_absolute_cwd(host_path, &abs_host_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path absolute: %m");

                host_path = abs_host_path;
        }

        r = bus_message_new_method_call(
                        bus,
                        &m,
                        bus_machine_mgr,
                        select_copy_method(copy_from, arg_force));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sss",
                        argv[1],
                        copy_from ? container_path : host_path,
                        copy_from ? host_path : container_path);
        if (r < 0)
                return bus_log_create_error(r);

        if (arg_force) {
                r = sd_bus_message_append(m, "t", (uint64_t) MACHINE_COPY_REPLACE);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        /* This is a slow operation, hence turn off any method call timeouts */
        r = sd_bus_call(bus, m, USEC_INFINITY, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to copy: %s", bus_error_message(&error, r));

        return 0;
}

VERB(verb_bind_mount, "bind", "NAME PATH [PATH]", 3, 4, 0,
     "Bind mount a path from the host into a container");
static int verb_bind_mount(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_method(
                        bus,
                        bus_machine_mgr,
                        "BindMountMachine",
                        &error,
                        NULL,
                        "sssbb",
                        argv[1],
                        argv[2],
                        argv[3],
                        arg_read_only,
                        arg_mkdir);
        if (r < 0)
                return log_error_errno(r, "Failed to bind mount: %s", bus_error_message(&error, r));

        return 0;
}

VERB_GROUP("Image Commands");

VERB(verb_list_images, "list-images", /* argspec= */ NULL, VERB_ANY, 1, 0,
     "Show available container and VM images");
static int verb_list_images(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_machine_mgr, "ListImages", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get images: %s", bus_error_message(&error, r));

        table = table_new("name", "type", "ro", "usage", "created", "modified");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        (void) table_set_align_percent(table, TABLE_HEADER_CELL(3), 100);

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssbttto)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                uint64_t crtime, mtime, size;
                const char *name, *type;
                int ro_int;

                r = sd_bus_message_read(reply, "(ssbttto)", &name, &type, &ro_int, &crtime, &mtime, &size, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (name[0] == '.' && !arg_all)
                        continue;

                r = table_add_many(table,
                                   TABLE_STRING, name,
                                   TABLE_STRING, type,
                                   TABLE_BOOLEAN, ro_int,
                                   TABLE_SET_COLOR, ro_int ? ansi_highlight_red() : NULL,
                                   TABLE_SIZE, size,
                                   TABLE_TIMESTAMP, crtime,
                                   TABLE_TIMESTAMP, mtime);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return show_table(table, "images");
}

static int print_image_hostname(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *hn;
        int r;

        r = bus_call_method(bus, bus_machine_mgr, "GetImageHostname", NULL, &reply, "s", name);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "s", &hn);
        if (r < 0)
                return r;

        if (!isempty(hn))
                printf("\tHostname: %s\n", hn);

        return 0;
}

static int print_image_machine_id(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        sd_id128_t id;
        int r;

        r = bus_call_method(bus, bus_machine_mgr, "GetImageMachineID", NULL, &reply, "s", name);
        if (r < 0)
                return r;

        r = bus_message_read_id128(reply, &id);
        if (r < 0)
                return r;

        if (!sd_id128_is_null(id))
                printf("      Machine ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));

        return 0;
}

static int print_image_machine_info(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        r = bus_call_method(bus, bus_machine_mgr, "GetImageMachineInfo", NULL, &reply, "s", name);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r < 0)
                return r;

        for (;;) {
                const char *p, *q;

                r = sd_bus_message_read(reply, "{ss}", &p, &q);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(p, "DEPLOYMENT"))
                        printf("      Deployment: %s\n", q);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        return 0;
}

typedef struct ImageStatusInfo {
        const char *name;
        const char *path;
        const char *type;
        bool read_only;
        usec_t crtime;
        usec_t mtime;
        uint64_t usage;
        uint64_t limit;
        uint64_t usage_exclusive;
        uint64_t limit_exclusive;
} ImageStatusInfo;

static void print_image_status_info(sd_bus *bus, ImageStatusInfo *i) {
        assert(bus);
        assert(i);

        if (i->name) {
                fputs(i->name, stdout);
                putchar('\n');
        }

        if (i->type)
                printf("\t    Type: %s\n", i->type);

        if (i->path)
                printf("\t    Path: %s\n", i->path);

        (void) print_image_hostname(bus, i->name);
        (void) print_image_machine_id(bus, i->name);
        (void) print_image_machine_info(bus, i->name);

        print_os_release(bus, "GetImageOSRelease", i->name, "\t      OS: ");

        printf("\t      RO: %s%s%s\n",
               i->read_only ? ansi_highlight_red() : "",
               i->read_only ? "read-only" : "writable",
               i->read_only ? ansi_normal() : "");

        if (timestamp_is_set(i->crtime))
                printf("\t Created: %s; %s\n",
                       FORMAT_TIMESTAMP(i->crtime), FORMAT_TIMESTAMP_RELATIVE(i->crtime));

        if (timestamp_is_set(i->mtime))
                printf("\tModified: %s; %s\n",
                       FORMAT_TIMESTAMP(i->mtime), FORMAT_TIMESTAMP_RELATIVE(i->mtime));

        if (i->usage != UINT64_MAX) {
                if (i->usage_exclusive != i->usage && i->usage_exclusive != UINT64_MAX)
                        printf("\t   Usage: %s (exclusive: %s)\n",
                               FORMAT_BYTES(i->usage), FORMAT_BYTES(i->usage_exclusive));
                else
                        printf("\t   Usage: %s\n", FORMAT_BYTES(i->usage));
        }

        if (i->limit != UINT64_MAX) {
                if (i->limit_exclusive != i->limit && i->limit_exclusive != UINT64_MAX)
                        printf("\t   Limit: %s (exclusive: %s)\n",
                               FORMAT_BYTES(i->limit), FORMAT_BYTES(i->limit_exclusive));
                else
                        printf("\t   Limit: %s\n", FORMAT_BYTES(i->limit));
        }
}

static int show_image_info(sd_bus *bus, const char *path, bool *new_line) {
        static const struct bus_properties_map map[]  = {
                { "Name",                  "s",  NULL, offsetof(ImageStatusInfo, name)            },
                { "Path",                  "s",  NULL, offsetof(ImageStatusInfo, path)            },
                { "Type",                  "s",  NULL, offsetof(ImageStatusInfo, type)            },
                { "ReadOnly",              "b",  NULL, offsetof(ImageStatusInfo, read_only)       },
                { "CreationTimestamp",     "t",  NULL, offsetof(ImageStatusInfo, crtime)          },
                { "ModificationTimestamp", "t",  NULL, offsetof(ImageStatusInfo, mtime)           },
                { "Usage",                 "t",  NULL, offsetof(ImageStatusInfo, usage)           },
                { "Limit",                 "t",  NULL, offsetof(ImageStatusInfo, limit)           },
                { "UsageExclusive",        "t",  NULL, offsetof(ImageStatusInfo, usage_exclusive) },
                { "LimitExclusive",        "t",  NULL, offsetof(ImageStatusInfo, limit_exclusive) },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        ImageStatusInfo info = {};
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   path,
                                   map,
                                   BUS_MAP_BOOLEAN_AS_BOOL,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %s", bus_error_message(&error, r));

        if (*new_line)
                printf("\n");
        *new_line = true;

        print_image_status_info(bus, &info);

        return r;
}

typedef struct PoolStatusInfo {
        const char *path;
        uint64_t usage;
        uint64_t limit;
} PoolStatusInfo;

static void print_pool_status_info(sd_bus *bus, PoolStatusInfo *i) {
        if (i->path)
                printf("\t    Path: %s\n", i->path);

        if (i->usage != UINT64_MAX)
                printf("\t   Usage: %s\n", FORMAT_BYTES(i->usage));

        if (i->limit != UINT64_MAX)
                printf("\t   Limit: %s\n", FORMAT_BYTES(i->limit));
}

static int show_pool_info(sd_bus *bus) {
        static const struct bus_properties_map map[]  = {
                { "PoolPath",  "s",  NULL, offsetof(PoolStatusInfo, path)  },
                { "PoolUsage", "t",  NULL, offsetof(PoolStatusInfo, usage) },
                { "PoolLimit", "t",  NULL, offsetof(PoolStatusInfo, limit) },
                {}
        };

        PoolStatusInfo info = {
                .usage = UINT64_MAX,
                .limit = UINT64_MAX,
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   "/org/freedesktop/machine1",
                                   map,
                                   0,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %s", bus_error_message(&error, r));

        print_pool_status_info(bus, &info);

        return 0;
}

static int show_image_properties(sd_bus *bus, const char *path, bool *new_line) {
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        if (*new_line)
                printf("\n");

        *new_line = true;

        r = bus_print_all_properties(bus, "org.freedesktop.machine1", path, NULL, arg_property, arg_print_flags, NULL);
        if (r < 0)
                log_error_errno(r, "Could not get properties: %m");

        return r;
}

VERB(verb_show_image, "image-status", "[NAME…]", VERB_ANY, VERB_ANY, 0,
     "Show image details");
VERB(verb_show_image, "show-image", "[NAME…]", VERB_ANY, VERB_ANY, 0,
     "Show properties of image");
static int verb_show_image(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool properties, new_line = false;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r = 0;

        properties = !strstr(argv[0], "status");

        pager_open(arg_pager_flags);

        if (argc <= 1) {

                /* If no argument is specified, inspect the manager
                 * itself */

                if (properties)
                        r = show_image_properties(bus, "/org/freedesktop/machine1", &new_line);
                else
                        r = show_pool_info(bus);
                if (r < 0)
                        return r;
        }

        for (int i = 1; i < argc; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *path = NULL;

                r = bus_call_method(bus, bus_machine_mgr, "GetImage", &error, &reply, "s", argv[i]);
                if (r < 0)
                        return log_error_errno(r, "Could not get path to image: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (properties)
                        r = show_image_properties(bus, path, &new_line);
                else
                        r = show_image_info(bus, path, &new_line);
        }

        return r;
}

static int normalize_nspawn_filename(const char *name, char **ret_file) {
        _cleanup_free_ char *file = NULL;

        assert(name);
        assert(ret_file);

        if (!endswith(name, ".nspawn"))
                file = strjoin(name, ".nspawn");
        else
                file = strdup(name);
        if (!file)
                return log_oom();

        if (!filename_is_valid(file))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid settings file name '%s'.", file);

        *ret_file = TAKE_PTR(file);
        return 0;
}

static int get_settings_path(const char *name, char **ret_path) {
        assert(name);
        assert(ret_path);

        FOREACH_STRING(i, "/etc/systemd/nspawn", "/run/systemd/nspawn", "/var/lib/machines") {
                _cleanup_free_ char *path = NULL;

                path = path_join(i, name);
                if (!path)
                        return -ENOMEM;

                if (access(path, F_OK) >= 0) {
                        *ret_path = TAKE_PTR(path);
                        return 0;
                }
        }

        return -ENOENT;
}

VERB(verb_edit_settings, "edit", "NAME|FILE…", 2, VERB_ANY, 0,
     "Edit settings of one or more VMs/containers");
static int verb_edit_settings(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(edit_file_context_done) EditFileContext context = {};
        int r;

        if (!on_tty())
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit machine settings if not on a tty.");

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Edit is only supported on the host machine.");

        if (arg_runner == RUNNER_VMSPAWN)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Edit is only supported for --runner=nspawn");

        r = mac_init();
        if (r < 0)
                return r;

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *file = NULL, *path = NULL;

                if (path_is_absolute(*name)) {
                        if (!path_is_safe(*name))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid settings file path '%s'.",
                                                       *name);

                        r = edit_files_add(&context, *name, NULL, NULL);
                        if (r < 0)
                                return r;
                        continue;
                }

                r = normalize_nspawn_filename(*name, &file);
                if (r < 0)
                        return r;

                r = get_settings_path(file, &path);
                if (r == -ENOENT) {
                        log_debug("No existing settings file for machine '%s' found, creating a new file.", *name);

                        path = path_join("/etc/systemd/nspawn", file);
                        if (!path)
                                return log_oom();

                        r = edit_files_add(&context, path, NULL, NULL);
                        if (r < 0)
                                return r;
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to get the path of the settings file: %m");

                if (path_startswith(path, "/var/lib/machines")) {
                        _cleanup_free_ char *new_path = NULL;

                        new_path = path_join("/etc/systemd/nspawn", file);
                        if (!new_path)
                                return log_oom();

                        r = edit_files_add(&context, new_path, path, NULL);
                } else
                        r = edit_files_add(&context, path, NULL, NULL);
                if (r < 0)
                        return r;
        }

        return do_edit_files_and_install(&context);
}

VERB(verb_cat_settings, "cat", "NAME|FILE…", 2, VERB_ANY, 0,
     "Show settings of one or more VMs/containers");
static int verb_cat_settings(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r = 0;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Cat is only supported on the host machine.");

        if (arg_runner == RUNNER_VMSPAWN)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Cat is only supported for --runner=nspawn");

        pager_open(arg_pager_flags);

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *file = NULL, *path = NULL;
                int q;

                if (path_is_absolute(*name)) {
                        if (!path_is_safe(*name))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid settings file path '%s'.",
                                                       *name);

                        q = cat_files(*name, /* dropins= */ NULL, /* flags= */ CAT_FORMAT_HAS_SECTIONS);
                        if (q < 0)
                                return r < 0 ? r : q;
                        continue;
                }

                q = normalize_nspawn_filename(*name, &file);
                if (q < 0)
                        return r < 0 ? r : q;

                q = get_settings_path(file, &path);
                if (q == -ENOENT) {
                        log_error_errno(q, "No settings file found for machine '%s'.", *name);
                        r = r < 0 ? r : q;
                        continue;
                }
                if (q < 0) {
                        log_error_errno(q, "Failed to get the path of the settings file: %m");
                        return r < 0 ? r : q;
                }

                q = cat_files(path, /* dropins= */ NULL, /* flags= */ CAT_FORMAT_HAS_SECTIONS);
                if (q < 0)
                        return r < 0 ? r : q;
        }

        return r;
}

VERB(verb_clone_image, "clone", "NAME NAME", 3, 3, 0,
     "Clone an image");
static int verb_clone_image(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "CloneImage");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ssb", argv[1], argv[2], arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        /* This is a slow operation, hence turn off any method call timeouts */
        r = sd_bus_call(bus, m, USEC_INFINITY, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not clone image: %s", bus_error_message(&error, r));

        return 0;
}

VERB(verb_rename_image, "rename", "NAME NAME", 3, 3, 0,
     "Rename an image");
static int verb_rename_image(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_method(
                        bus,
                        bus_machine_mgr,
                        "RenameImage",
                        &error,
                        NULL,
                        "ss", argv[1], argv[2]);
        if (r < 0)
                return log_error_errno(r, "Could not rename image: %s", bus_error_message(&error, r));

        return 0;
}

VERB(verb_read_only_image, "read-only", "NAME [BOOL]", 2, 3, 0,
     "Mark or unmark image read-only");
static int verb_read_only_image(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int b = true, r;

        if (argc > 2) {
                b = parse_boolean(argv[2]);
                if (b < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to parse boolean argument: %s",
                                               argv[2]);
        }

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_method(bus, bus_machine_mgr, "MarkImageReadOnly", &error, NULL, "sb", argv[1], b);
        if (r < 0)
                return log_error_errno(r, "Could not mark image read-only: %s", bus_error_message(&error, r));

        return 0;
}

VERB(verb_remove_image, "remove", "NAME…", 2, VERB_ANY, 0,
     "Remove an image");
static int verb_remove_image(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "RemoveImage");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", argv[i]);
                if (r < 0)
                        return bus_log_create_error(r);

                /* This is a slow operation, hence turn off any method call timeouts */
                r = sd_bus_call(bus, m, USEC_INFINITY, &error, NULL);
                if (r < 0)
                        return log_error_errno(r, "Could not remove image: %s", bus_error_message(&error, r));
        }

        return 0;
}

VERB(verb_set_limit, "set-limit", "[NAME] BYTES", 2, 3, 0,
     "Set image or pool size limit (disk quota)");
static int verb_set_limit(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        uint64_t limit;
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (STR_IN_SET(argv[argc-1], "-", "none", "infinity"))
                limit = UINT64_MAX;
        else {
                r = parse_size(argv[argc-1], 1024, &limit);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse size: %s", argv[argc-1]);
        }

        if (argc > 2)
                /* With two arguments changes the quota limit of the
                 * specified image */
                r = bus_call_method(bus, bus_machine_mgr, "SetImageLimit", &error, NULL, "st", argv[1], limit);
        else
                /* With one argument changes the pool quota limit */
                r = bus_call_method(bus, bus_machine_mgr, "SetPoolLimit", &error, NULL, "t", limit);

        if (r < 0)
                return log_error_errno(r, "Could not set limit: %s", bus_error_message(&error, r));

        return 0;
}

VERB(verb_clean_images, "clean", /* argspec= */ NULL, VERB_ANY, 1, 0,
     "Remove hidden (or all) images");
static int verb_clean_images(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        uint64_t usage, total = 0;
        sd_bus *bus = userdata;
        const char *name;
        unsigned c = 0;
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "CleanPool");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", arg_all ? "all" : "hidden");
        if (r < 0)
                return bus_log_create_error(r);

        /* This is a slow operation, hence permit a longer time for completion. */
        r = sd_bus_call(bus, m, USEC_INFINITY, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Could not clean pool: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(st)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(st)", &name, &usage)) > 0) {
                if (usage == UINT64_MAX) {
                        log_info("Removed image '%s'", name);
                        total = UINT64_MAX;
                } else {
                        log_info("Removed image '%s'. Freed exclusive disk space: %s",
                                 name, FORMAT_BYTES(usage));
                        if (total != UINT64_MAX)
                                total += usage;
                }
                c++;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (total == UINT64_MAX)
                log_info("Removed %u images in total.", c);
        else
                log_info("Removed %u images in total. Total freed exclusive disk space: %s.",
                         c, FORMAT_BYTES(total));

        return 0;
}

VERB(verb_bind_volume, "bind-volume", "MACHINE PROVIDER:VOLUME[:…]", 3, 3, 0,
     "Attach a volume to a running machine");
static int verb_bind_volume(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "bind-volume is only supported on the local transport.");

        _cleanup_(bind_volume_freep) BindVolume *bv = NULL;
        r = bind_volume_parse(argv[2], &bv);
        if (r < 0)
                return log_error_errno(r, "Failed to parse bind-volume argument '%s': %m", argv[2]);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        /* Locate and connect to the target machine before acquiring storage, so a missing
         * machine doesn't trigger 'create=new' side effects on the StorageProvider. */
        _cleanup_free_ char *address = NULL;
        r = machine_get_control_address(argv[1], &address);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Machine '%s' does not expose a varlink control socket.", argv[1]);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machine control socket %s: %m", address);

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing on varlink connection: %m");

        _cleanup_(storage_acquire_reply_done) StorageAcquireReply reply = STORAGE_ACQUIRE_REPLY_INIT;
        _cleanup_free_ char *acquire_error_id = NULL;
        r = storage_acquire_volume(arg_runtime_scope, bv, arg_ask_password, &acquire_error_id, &reply);
        if (r < 0) {
                if (acquire_error_id)
                        return log_error_errno(r, "Failed to acquire storage volume '%s:%s' from provider: %s",
                                               bv->provider, bv->volume, acquire_error_id);
                return log_error_errno(r, "Failed to acquire storage volume '%s:%s' from provider: %m",
                                       bv->provider, bv->volume);
        }

        int fd_index = sd_varlink_push_fd(vl, reply.fd);
        if (fd_index < 0)
                return log_error_errno(fd_index, "Failed to push storage fd onto varlink connection: %m");
        TAKE_FD(reply.fd);

        _cleanup_free_ char *name = strjoin(bv->provider, ":", bv->volume);
        if (!name)
                return log_oom();

        sd_json_variant *vl_reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.MachineInstance.AddStorage",
                        &vl_reply, &error_id,
                        SD_JSON_BUILD_PAIR_INTEGER("fileDescriptorIndex", fd_index),
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("config", bv->config));
        if (r < 0)
                return log_error_errno(r, "Failed to call io.systemd.MachineInstance.AddStorage: %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, vl_reply),
                                       "AddStorage failed for '%s': %s", name, error_id);

        return 0;
}

VERB(verb_unbind_volume, "unbind-volume", "MACHINE PROVIDER:VOLUME", 3, 3, 0,
     "Detach a volume from a running machine");
static int verb_unbind_volume(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "unbind-volume is only supported on the local transport.");

        r = machine_storage_name_split(argv[2], /* ret_provider= */ NULL, /* ret_volume= */ NULL);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid unbind-volume name '%s', expected '<provider>:<volume>'.", argv[2]);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        _cleanup_free_ char *address = NULL;
        r = machine_get_control_address(argv[1], &address);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Machine '%s' does not expose a varlink control socket.", argv[1]);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machine control socket %s: %m", address);

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.MachineInstance.RemoveStorage",
                        &reply, &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", argv[2]));
        if (r < 0)
                return log_error_errno(r, "Failed to call io.systemd.MachineInstance.RemoveStorage: %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "RemoveStorage failed for '%s': %s", argv[2], error_id);

        return 0;
}

static int chainload_importctl(char **args) {
        int r;

        if (!arg_quiet)
                log_notice("The 'machinectl %1$s' command has been replaced by 'importctl -m %1$s'. "
                           "Redirecting invocation.", args[0]);

        _cleanup_strv_free_ char **c =
                strv_new("importctl", "--class=machine");
        if (!c)
                return log_oom();

        if (FLAGS_SET(arg_pager_flags, PAGER_DISABLE))
                if (strv_extend(&c, "--no-pager") < 0)
                        return log_oom();
        if (!arg_legend)
                if (strv_extend(&c, "--no-legend") < 0)
                        return log_oom();
        if (arg_read_only)
                if (strv_extend(&c, "--read-only") < 0)
                        return log_oom();
        if (arg_force)
                if (strv_extend(&c, "--force") < 0)
                        return log_oom();
        if (arg_quiet)
                if (strv_extend(&c, "--quiet") < 0)
                        return log_oom();
        if (!arg_ask_password)
                if (strv_extend(&c, "--no-ask-password") < 0)
                        return log_oom();
        if (strv_extend_many(&c, "--verify", import_verify_to_string(arg_verify)) < 0)
                return log_oom();
        if (arg_format)
                if (strv_extend_many(&c, "--format", arg_format) < 0)
                        return log_oom();

        if (strv_extend_strv(&c, args, /* filter_duplicates= */ false) < 0)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = strv_join(c, " ");
                log_debug("Chainloading: %s", joined);
        }

        r = invoke_callout_binary(BINDIR "/importctl", c);
        return log_error_errno(r, "Failed to invoke 'importctl': %m");
}

static int help(void) {
        static const char* const vgroups[] = {
                "Machine Commands",
                "Image Commands",
        };

        Table *vtables[ELEMENTSOF(vgroups)] = {};
        CLEANUP_ELEMENTS(vtables, table_unref_array_clear);
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                r = verbs_get_help_table_group(vgroups[i], &vtables[i]);
                if (r < 0)
                        return r;
        }

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        assert_cc(ELEMENTSOF(vtables) == 2);
        (void) table_sync_column_widths(0, options, vtables[0], vtables[1]);

        pager_open(arg_pager_flags);

        help_cmdline("[OPTIONS…] COMMAND …");

        printf("\n%1$s%2$sSend control commands to or query the virtual machine and container%3$s\n"
               "%1$s%2$sregistration manager.%3$s\n",
               ansi_highlight(),
               ansi_add_italics(),
               ansi_normal());

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                help_section(vgroups[i]);
                r = table_print_or_warn(vtables[i]);
                if (r < 0)
                        return r;
        }

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("machinectl", "1");

        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        /* For "shell" we don't want option reordering; options specified after the command should be passed
         * to the program to execute, and not processed by us. For other verbs, we consume all options as
         * usual. To make this work, start with OPTION_PARSER_RETURN_POSITIONAL_ARGS and switch to either
         * OPTION_PARSER_STOP_AT_FIRST_NONOPTION or OPTION_PARSER_NORMAL after we've seen the verb and one
         * more argument after that. */
        OptionParser opts = { argc, argv, OPTION_PARSER_RETURN_POSITIONAL_ARGS };
        _cleanup_strv_free_ char **args = NULL;
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_POSITIONAL:
                        assert(opts.mode == OPTION_PARSER_RETURN_POSITIONAL_ARGS);

                        if (!args && !streq(opts.arg, "shell"))
                                opts.mode = OPTION_PARSER_NORMAL;
                        else if (args)
                                opts.mode = OPTION_PARSER_STOP_AT_FIRST_NONOPTION;

                        r = strv_extend(&args, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_HOST:
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = opts.arg;
                        break;

                OPTION_COMMON_MACHINE:
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = opts.arg;
                        break;

                OPTION_LONG("system", NULL, "Connect to system machine manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Connect to user machine manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_LONG("value", NULL, "When showing properties, only print the value"):
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);
                        break;

                OPTION('p', "property", "NAME", "Show only properties by this name"): {}
                OPTION_SHORT('P', "NAME", "Equivalent to --value --property=NAME"):
                        r = strv_extend(&arg_property, opts.arg);
                        if (r < 0)
                                return log_oom();

                        /* If the user asked for a particular property, show it to them, even if empty. */
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);

                        if (opts.opt->short_code == 'P')
                                SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);

                        break;

                OPTION('a', "all", NULL, "Show all properties, including empty ones"):
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);
                        arg_all = true;
                        break;

                OPTION('l', "full", NULL, "Do not ellipsize output"):
                        arg_full = true;
                        break;

                OPTION_LONG("kill-whom", "WHOM", "Whom to send signal to"):
                        arg_kill_whom = opts.arg;
                        break;

                OPTION('s', "signal", "SIGNAL", "Which signal to send"):
                        r = parse_signal_argument(opts.arg, &arg_signal);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("uid", "USER", "Specify user ID to invoke shell as"):
                        arg_uid = opts.arg;
                        break;

                OPTION('E', "setenv", "VAR[=VALUE]", "Add an environment variable for shell"):
                        r = strv_env_replace_strdup_passthrough(&arg_setenv, opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", opts.arg);
                        break;

                OPTION_LONG("read-only", NULL, "Create read-only bind mount or clone"):
                        arg_read_only = true;
                        break;

                OPTION_LONG("mkdir", NULL, "Create directory before bind mounting, if missing"):
                        arg_mkdir = true;
                        break;

                OPTION('n', "lines", "INTEGER", "Number of journal entries to show"):
                        if (safe_atou(opts.arg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'", opts.arg);
                        break;

                OPTION_LONG("max-addresses", "INTEGER",
                            "Number of internet addresses to show at most"):
                        if (streq(opts.arg, "all"))
                                arg_max_addresses = UINT_MAX;
                        else if (safe_atou(opts.arg, &arg_max_addresses) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid number of addresses: %s", opts.arg);
                        break;

                OPTION('o', "output", "STRING",
                       "Change journal output mode (short, short-precise, short-iso, "
                       "short-iso-precise, short-full, short-monotonic, short-unix, short-delta, "
                       "json, json-pretty, json-sse, json-seq, cat, verbose, export, with-unit)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);

                        r = output_mode_from_string(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Unknown output '%s'.", opts.arg);
                        arg_output = r;

                        if (OUTPUT_MODE_IS_JSON(arg_output))
                                arg_legend = false;
                        break;

                OPTION_LONG("force", NULL, "Replace target file when copying, if necessary"):
                        arg_force = true;
                        break;

                OPTION_LONG("now", NULL,
                            "Start or power off container after enabling or disabling it"):
                        arg_now = true;
                        break;

                OPTION_LONG("runner", "RUNNER",
                            "Select between nspawn and vmspawn as the runner"):
                        r = machine_runner_from_string(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --runner= setting: %s", opts.arg);

                        arg_runner = r;
                        break;

                OPTION_SHORT('V', NULL, "Short for --runner=vmspawn"):
                        arg_runner = RUNNER_VMSPAWN;
                        break;

                /* Hidden options below */

                OPTION_LONG("verify", "MODE", /* help= */ NULL):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(import_verify, ImportVerify, _IMPORT_VERIFY_MAX);

                        r = import_verify_from_string(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --verify= setting: %s", opts.arg);
                        arg_verify = r;
                        break;

                OPTION_LONG("format", "FORMAT", /* help= */ NULL):
                        if (!STR_IN_SET(opts.arg, "uncompressed", "xz", "gzip", "bzip2", "zstd"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", opts.arg);

                        arg_format = opts.arg;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION('q', "quiet", NULL, "Suppress output"):
                        arg_quiet = true;
                        break;
                }

        /* We gathered some positional args in 'args' ourselves. Append the remaining ones. */
        if (strv_extend_strv(&args, option_parser_get_args(&opts), /* filter_duplicates= */ false) < 0)
                return log_oom();

        *ret_args = TAKE_PTR(args);
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **args = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        if (args && STR_IN_SET(args[0],
                               "import-tar", "import-raw", "import-fs",
                               "export-tar", "export-raw",
                               "pull-tar", "pull-raw",
                               "list-transfers", "cancel-transfer"))
                return chainload_importctl(args);

        r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        return dispatch_verb(args, bus);
}

DEFINE_MAIN_FUNCTION(run);
