/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-print-properties.h"
#include "bus-unit-procs.h"
#include "bus-unit-util.h"
#include "bus-wait-for-jobs.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "constants.h"
#include "copy.h"
#include "edit-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "hostname-util.h"
#include "import-util.h"
#include "locale-util.h"
#include "log.h"
#include "logs-show.h"
#include "machine-dbus.h"
#include "macro.h"
#include "main-func.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "rlimit-util.h"
#include "sigbus.h"
#include "signal-util.h"
#include "sort-util.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "verbs.h"
#include "web-util.h"

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
static const char* arg_format = NULL;
static const char *arg_uid = NULL;
static char **arg_setenv = NULL;
static unsigned arg_max_addresses = 1;

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
        const char *k, *v, **query_res = NULL;
        size_t count = 0, awaited_args = 0;
        va_list ap;
        int r;

        assert(bus);
        assert(name);
        assert(query);

        NULSTR_FOREACH(iter, query)
                awaited_args++;
        query_res = newa0(const char *, awaited_args);

        r = bus_call_method(bus, bus_machine_mgr, method, &error, &reply, "s", name);
        if (r < 0)
                return log_debug_errno(r, "Failed to call '%s()': %s", method, bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "{ss}", &k, &v)) > 0) {
                count = 0;
                NULSTR_FOREACH(iter, query) {
                        if (streq(k, iter)) {
                                query_res[count] = v;
                                break;
                        }
                        count++;
                }
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        va_start(ap, query);
        for (count = 0; count < awaited_args; count++) {
                char *val, **out;

                out = va_arg(ap, char **);
                assert(out);
                if (query_res[count]) {
                        val = strdup(query_res[count]);
                        if (!val) {
                                va_end(ap);
                                return -ENOMEM;
                        }
                        *out = val;
                }
        }
        va_end(ap);

        return 0;
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

        r = bus_call_method(bus, bus_machine_mgr, "GetMachineAddresses", NULL, &reply, "s", name);
        if (r < 0)
                return log_debug_errno(r, "Could not get addresses: %s", bus_error_message(&error, r));

        addresses = strdup(prefix);
        if (!addresses)
                return log_oom();
        prefix = "";

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                return bus_log_parse_error(r);

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

        if (table_get_rows(table) > 1 || OUTPUT_MODE_IS_JSON(arg_output)) {
                r = table_set_sort(table, (size_t) 0);
                if (r < 0)
                        return table_log_sort_error(r);

                table_set_header(table, arg_legend);

                if (OUTPUT_MODE_IS_JSON(arg_output))
                        r = table_print_json(table, NULL, output_mode_to_json_format_flags(arg_output) | JSON_FORMAT_COLOR_AUTO);
                else
                        r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
        }

        if (arg_legend) {
                if (table_get_rows(table) > 1)
                        printf("\n%zu %s listed.\n", table_get_rows(table) - 1, word);
                else
                        printf("No %s.\n", word);
        }

        return 0;
}

static int list_machines(int argc, char *argv[], void *userdata) {
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

static int list_images(int argc, char *argv[], void *userdata) {

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

static int show_unit_cgroup(sd_bus *bus, const char *unit, pid_t leader) {
        _cleanup_free_ char *cgroup = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;
        unsigned c;

        assert(bus);
        assert(unit);

        r = show_cgroup_get_unit_path_and_warn(bus, unit, &cgroup);
        if (r < 0)
                return r;

        if (isempty(cgroup))
                return 0;

        c = columns();
        if (c > 18)
                c -= 18;
        else
                c = 0;

        r = unit_show_processes(bus, unit, cgroup, "\t\t  ", c, get_output_flags(), &error);
        if (r == -EBADR) {

                if (arg_transport == BUS_TRANSPORT_REMOTE)
                        return 0;

                /* Fallback for older systemd versions where the GetUnitProcesses() call is not yet available */

                if (cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, cgroup) != 0 && leader <= 0)
                        return 0;

                show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, cgroup, "\t\t  ", c, &leader, leader > 0, get_output_flags());
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

        printf("  UID Shift: %" PRIu32 "\n", shift);
        return 0;
}

typedef struct MachineStatusInfo {
        const char *name;
        sd_id128_t id;
        const char *class;
        const char *service;
        const char *unit;
        const char *root_directory;
        pid_t leader;
        struct dual_timestamp timestamp;
        int *netif;
        size_t n_netif;
} MachineStatusInfo;

static void machine_status_info_clear(MachineStatusInfo *info) {
        if (info) {
                free(info->netif);
                zero(*info);
        }
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

        if (i->leader > 0) {
                _cleanup_free_ char *t = NULL;

                printf("\t  Leader: %u", (unsigned) i->leader);

                (void) pid_get_comm(i->leader, &t);
                if (t)
                        printf(" (%s)", t);

                putchar('\n');
        }

        if (i->service) {
                printf("\t Service: %s", i->service);

                if (i->class)
                        printf("; class %s", i->class);

                putchar('\n');
        } else if (i->class)
                printf("\t   Class: %s\n", i->class);

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
                show_unit_cgroup(bus, i->unit, i->leader);

                if (arg_transport == BUS_TRANSPORT_LOCAL)

                        show_journal_by_unit(
                                        stdout,
                                        i->unit,
                                        NULL,
                                        arg_output,
                                        0,
                                        i->timestamp.monotonic,
                                        arg_lines,
                                        0,
                                        get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                                        SD_JOURNAL_LOCAL_ONLY,
                                        true,
                                        NULL);
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
                { "RootDirectory",      "s",  NULL,          offsetof(MachineStatusInfo, root_directory)      },
                { "Leader",             "u",  NULL,          offsetof(MachineStatusInfo, leader)              },
                { "Timestamp",          "t",  NULL,          offsetof(MachineStatusInfo, timestamp.realtime)  },
                { "TimestampMonotonic", "t",  NULL,          offsetof(MachineStatusInfo, timestamp.monotonic) },
                { "Id",                 "ay", bus_map_id128, offsetof(MachineStatusInfo, id)                  },
                { "NetworkInterfaces",  "ai", map_netif,     0                                                },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(machine_status_info_clear) MachineStatusInfo info = {};
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

static int show_machine(int argc, char *argv[], void *userdata) {
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
        sd_id128_t id = SD_ID128_NULL;
        const void *p;
        size_t size;
        int r;

        r = bus_call_method(bus, bus_machine_mgr, "GetImageMachineID", NULL, &reply, "s", name);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(reply, 'y', &p, &size);
        if (r < 0)
                return r;

        if (size == sizeof(sd_id128_t))
                memcpy(&id, p, size);

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

static int show_image(int argc, char *argv[], void *userdata) {
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

static int kill_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int reboot_machine(int argc, char *argv[], void *userdata) {
        arg_kill_whom = "leader";
        arg_signal = SIGINT; /* sysvinit + systemd */

        return kill_machine(argc, argv, userdata);
}

static int poweroff_machine(int argc, char *argv[], void *userdata) {
        arg_kill_whom = "leader";
        arg_signal = SIGRTMIN+4; /* only systemd */

        return kill_machine(argc, argv, userdata);
}

static int terminate_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                r = bus_call_method(bus, bus_machine_mgr, "TerminateMachine", &error, NULL, "s", argv[i]);
                if (r < 0)
                        return log_error_errno(r, "Could not terminate machine: %s", bus_error_message(&error, r));
        }

        return 0;
}

static const char *select_copy_method(bool copy_from, bool force) {
        if (force)
                return copy_from ? "CopyFromMachineWithFlags" : "CopyToMachineWithFlags";
        else
                return copy_from ? "CopyFromMachine" : "CopyToMachine";
}

static int copy_files(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *abs_host_path = NULL;
        char *dest, *host_path, *container_path;
        sd_bus *bus = ASSERT_PTR(userdata);
        bool copy_from;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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
                r = sd_bus_message_append(m, "t", MACHINE_COPY_REPLACE);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        /* This is a slow operation, hence turn off any method call timeouts */
        r = sd_bus_call(bus, m, USEC_INFINITY, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to copy: %s", bus_error_message(&error, r));

        return 0;
}

static int bind_mount(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int on_machine_removed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        PTYForward ** forward = (PTYForward**) userdata;
        int r;

        assert(m);
        assert(forward);

        if (*forward) {
                /* If the forwarder is already initialized, tell it to
                 * exit on the next vhangup(), so that we still flush
                 * out what might be queued and exit then. */

                r = pty_forward_set_ignore_vhangup(*forward, false);
                if (r >= 0)
                        return 0;

                log_error_errno(r, "Failed to set ignore_vhangup flag: %m");
        }

        /* On error, or when the forwarder is not initialized yet, quit immediately */
        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), EXIT_FAILURE);
        return 0;
}

static int process_forward(sd_event *event, PTYForward **forward, int master, PTYForwardFlags flags, const char *name) {
        char last_char = 0;
        bool machine_died;
        int r;

        assert(event);
        assert(master >= 0);
        assert(name);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGWINCH, SIGTERM, SIGINT, -1) >= 0);

        if (!arg_quiet) {
                if (streq(name, ".host"))
                        log_info("Connected to the local host. Press ^] three times within 1s to exit session.");
                else
                        log_info("Connected to machine %s. Press ^] three times within 1s to exit session.", name);
        }

        (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);

        r = pty_forward_new(event, master, flags, forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        pty_forward_get_last_char(*forward, &last_char);

        machine_died =
                (flags & PTY_FORWARD_IGNORE_VHANGUP) &&
                pty_forward_get_ignore_vhangup(*forward) == 0;

        *forward = pty_forward_free(*forward);

        if (last_char != '\n')
                fputc('\n', stdout);

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

static int parse_machine_uid(const char *spec, const char **machine, char **uid) {
        /*
         * Whatever is specified in the spec takes priority over global arguments.
         */
        char *_uid = NULL;
        const char *_machine = NULL;

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

static int login_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
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

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

        r = sd_bus_add_match_async(bus, &slot, match, on_machine_removed, NULL, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to request machine removal match: %m");

        r = bus_call_method(bus, bus_machine_mgr, "OpenMachineLogin", &error, &reply, "s", machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get login PTY: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "hs", &master, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        return process_forward(event, &forward, master, PTY_FORWARD_IGNORE_VHANGUP, machine);
}

static int shell_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int master = -1, r;
        sd_bus *bus = ASSERT_PTR(userdata);
        const char *match, *machine, *path;
        _cleanup_free_ char *uid = NULL;

        if (!IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_MACHINE))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Shell only supported on local machines.");

        /* Pass $TERM to shell session, if not explicitly specified. */
        if (!strv_find_prefix(arg_setenv, "TERM=")) {
                const char *t;

                t = strv_find_prefix(environ, "TERM=");
                if (t) {
                        if (strv_extend(&arg_setenv, t) < 0)
                                return log_oom();
                }
        }

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

        r = sd_bus_add_match_async(bus, &slot, match, on_machine_removed, NULL, &forward);
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

        return process_forward(event, &forward, master, 0, machine);
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

static int edit_settings(int argc, char *argv[], void *userdata) {
        _cleanup_(edit_file_context_done) EditFileContext context = {};
        int r;

        if (!on_tty())
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit machine settings if not on a tty.");

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Edit is only supported on the host machine.");

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

static int cat_settings(int argc, char *argv[], void *userdata) {
        int r = 0;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Cat is only supported on the host machine.");

        pager_open(arg_pager_flags);

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *file = NULL, *path = NULL;
                int q;

                if (path_is_absolute(*name)) {
                        if (!path_is_safe(*name))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid settings file path '%s'.",
                                                       *name);

                        q = cat_files(*name, /* dropins = */ NULL, /* flags = */ CAT_FORMAT_HAS_SECTIONS);
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

                q = cat_files(path, /* dropins = */ NULL, /* flags = */ CAT_FORMAT_HAS_SECTIONS);
                if (q < 0)
                        return r < 0 ? r : q;
        }

        return r;
}

static int remove_image(int argc, char *argv[], void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int rename_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int clone_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int read_only_image(int argc, char *argv[], void *userdata) {
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

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_method(bus, bus_machine_mgr, "MarkImageReadOnly", &error, NULL, "sb", argv[1], b);
        if (r < 0)
                return log_error_errno(r, "Could not mark image read-only: %s", bus_error_message(&error, r));

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

static int make_service_name(const char *name, char **ret) {
        int r;

        assert(name);
        assert(ret);

        if (!hostname_is_valid(name, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid machine name %s.", name);

        r = unit_name_build("systemd-nspawn", name, ".service", ret);
        if (r < 0)
                return log_error_errno(r, "Failed to build unit name: %m");

        return 0;
}

static int start_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
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

static int enable_machine(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *method;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;
        bool enable;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

                r = strv_extend_strv(&new_args, argv + 1, /* filter_duplicates = */ false);
                if (r < 0)
                        return log_oom();

                if (enable)
                        return start_machine(strv_length(new_args), new_args, userdata);

                return poweroff_machine(strv_length(new_args), new_args, userdata);
        }

        return 0;
}

static int match_log_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *line;
        unsigned priority;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "us", &priority, &line);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, sd_bus_message_get_path(m)))
                return 0;

        if (arg_quiet && LOG_PRI(priority) >= LOG_INFO)
                return 0;

        log_full(priority, "%s", line);
        return 0;
}

static int match_transfer_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *path, *result;
        uint32_t id;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "uos", &id, &path, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, path))
                return 0;

        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), !streq_ptr(result, "done"));
        return 0;
}

static int transfer_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(s);
        assert(si);

        if (!arg_quiet)
                log_info("Continuing download in the background. Use \"machinectl cancel-transfer %" PRIu32 "\" to abort transfer.", PTR_TO_UINT32(userdata));

        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static int transfer_image_common(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot_job_removed = NULL, *slot_log_message = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_event_unrefp) sd_event* event = NULL;
        const char *path = NULL;
        uint32_t id;
        int r;

        assert(bus);
        assert(m);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = bus_match_signal_async(
                        bus,
                        &slot_job_removed,
                        bus_import_mgr,
                        "TransferRemoved",
                        match_transfer_removed, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_match_signal_async(
                        bus,
                        &slot_log_message,
                        "org.freedesktop.import1",
                        NULL,
                        "org.freedesktop.import1.Transfer",
                        "LogMessage",
                        match_log_message, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to transfer image: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "uo", &id, &path);
        if (r < 0)
                return bus_log_parse_error(r);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        if (!arg_quiet)
                log_info("Enqueued transfer job %u. Press C-c to continue download in background.", id);

        (void) sd_event_add_signal(event, NULL, SIGINT, transfer_signal_handler, UINT32_TO_PTR(id));
        (void) sd_event_add_signal(event, NULL, SIGTERM, transfer_signal_handler, UINT32_TO_PTR(id));

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return -r;
}

static int import_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL, *fn = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                               "Path '%s' refers to directory, but we need a regular file: %m", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = tar_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int import_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL, *fn = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                               "Path '%s' refers to directory, but we need a regular file: %m", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = raw_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int import_fs(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open directory '%s': %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportFileSystem");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static void determine_compression_from_filename(const char *p) {
        if (arg_format)
                return;

        if (!p)
                return;

        if (endswith(p, ".xz"))
                arg_format = "xz";
        else if (endswith(p, ".gz"))
                arg_format = "gzip";
        else if (endswith(p, ".bz2"))
                arg_format = "bzip2";
}

static int export_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        local = argv[1];
        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Machine name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int export_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        local = argv[1];
        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Machine name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        remote = argv[1];
        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "URL '%s' is not valid.", remote);

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        local = empty_or_dash_to_null(local);

        if (local) {
                r = tar_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!hostname_is_valid(local, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable machine name.",
                                               local);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        remote = argv[1];
        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "URL '%s' is not valid.", remote);

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        local = empty_or_dash_to_null(local);

        if (local) {
                r = raw_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!hostname_is_valid(local, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable machine name.",
                                               local);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

typedef struct TransferInfo {
        uint32_t id;
        const char *type;
        const char *remote;
        const char *local;
        double progress;
} TransferInfo;

static int compare_transfer_info(const TransferInfo *a, const TransferInfo *b) {
        return strcmp(a->local, b->local);
}

static int list_transfers(int argc, char *argv[], void *userdata) {
        size_t max_type = STRLEN("TYPE"), max_local = STRLEN("LOCAL"), max_remote = STRLEN("REMOTE");
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ TransferInfo *transfers = NULL;
        const char *type, *remote, *local;
        sd_bus *bus = userdata;
        uint32_t id, max_id = 0;
        size_t n_transfers = 0;
        double progress;
        int r;

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_import_mgr, "ListTransfers", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get transfers: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(usssdo)", &id, &type, &remote, &local, &progress, NULL)) > 0) {
                size_t l;

                if (!GREEDY_REALLOC(transfers, n_transfers + 1))
                        return log_oom();

                transfers[n_transfers].id = id;
                transfers[n_transfers].type = type;
                transfers[n_transfers].remote = remote;
                transfers[n_transfers].local = local;
                transfers[n_transfers].progress = progress;

                l = strlen(type);
                if (l > max_type)
                        max_type = l;

                l = strlen(remote);
                if (l > max_remote)
                        max_remote = l;

                l = strlen(local);
                if (l > max_local)
                        max_local = l;

                if (id > max_id)
                        max_id = id;

                n_transfers++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        typesafe_qsort(transfers, n_transfers, compare_transfer_info);

        if (arg_legend && n_transfers > 0)
                printf("%-*s %-*s %-*s %-*s %-*s\n",
                       (int) MAX(2U, DECIMAL_STR_WIDTH(max_id)), "ID",
                       (int) 7, "PERCENT",
                       (int) max_type, "TYPE",
                       (int) max_local, "LOCAL",
                       (int) max_remote, "REMOTE");

        for (size_t j = 0; j < n_transfers; j++)

                if (transfers[j].progress < 0)
                        printf("%*" PRIu32 " %*s %-*s %-*s %-*s\n",
                               (int) MAX(2U, DECIMAL_STR_WIDTH(max_id)), transfers[j].id,
                               (int) 7, "n/a",
                               (int) max_type, transfers[j].type,
                               (int) max_local, transfers[j].local,
                               (int) max_remote, transfers[j].remote);
                else
                        printf("%*" PRIu32 " %*u%% %-*s %-*s %-*s\n",
                               (int) MAX(2U, DECIMAL_STR_WIDTH(max_id)), transfers[j].id,
                               (int) 6, (unsigned) (transfers[j].progress * 100),
                               (int) max_type, transfers[j].type,
                               (int) max_local, transfers[j].local,
                               (int) max_remote, transfers[j].remote);

        if (arg_legend) {
                if (n_transfers > 0)
                        printf("\n%zu transfers listed.\n", n_transfers);
                else
                        printf("No transfers.\n");
        }

        return 0;
}

static int cancel_transfer(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                uint32_t id;

                r = safe_atou32(argv[i], &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse transfer id: %s", argv[i]);

                r = bus_call_method(bus, bus_import_mgr, "CancelTransfer", &error, NULL, "u", id);
                if (r < 0)
                        return log_error_errno(r, "Could not cancel transfer: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int set_limit(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        uint64_t limit;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int clean_images(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        uint64_t usage, total = 0;
        sd_bus *bus = userdata;
        const char *name;
        unsigned c = 0;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("machinectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sSend control commands to or query the virtual machine and container%6$s\n"
               "%5$sregistration manager.%6$s\n"
               "\n%3$sMachine Commands:%4$s\n"
               "  list                        List running VMs and containers\n"
               "  status NAME...              Show VM/container details\n"
               "  show [NAME...]              Show properties of one or more VMs/containers\n"
               "  start NAME...               Start container as a service\n"
               "  login [NAME]                Get a login prompt in a container or on the\n"
               "                              local host\n"
               "  shell [[USER@]NAME [COMMAND...]]\n"
               "                              Invoke a shell (or other command) in a container\n"
               "                              or on the local host\n"
               "  enable NAME...              Enable automatic container start at boot\n"
               "  disable NAME...             Disable automatic container start at boot\n"
               "  poweroff NAME...            Power off one or more containers\n"
               "  reboot NAME...              Reboot one or more containers\n"
               "  terminate NAME...           Terminate one or more VMs/containers\n"
               "  kill NAME...                Send signal to processes of a VM/container\n"
               "  copy-to NAME PATH [PATH]    Copy files from the host to a container\n"
               "  copy-from NAME PATH [PATH]  Copy files from a container to the host\n"
               "  bind NAME PATH [PATH]       Bind mount a path from the host into a container\n"
               "\n%3$sImage Commands:%4$s\n"
               "  list-images                 Show available container and VM images\n"
               "  image-status [NAME...]      Show image details\n"
               "  show-image [NAME...]        Show properties of image\n"
               "  edit NAME|FILE...           Edit settings of one or more VMs/containers\n"
               "  cat NAME|FILE...            Show settings of one or more VMs/containers\n"
               "  clone NAME NAME             Clone an image\n"
               "  rename NAME NAME            Rename an image\n"
               "  read-only NAME [BOOL]       Mark or unmark image read-only\n"
               "  remove NAME...              Remove an image\n"
               "  set-limit [NAME] BYTES      Set image or pool size limit (disk quota)\n"
               "  clean                       Remove hidden (or all) images\n"
               "\n%3$sImage Transfer Commands:%4$s\n"
               "  pull-tar URL [NAME]         Download a TAR container image\n"
               "  pull-raw URL [NAME]         Download a RAW container or VM image\n"
               "  import-tar FILE [NAME]      Import a local TAR container image\n"
               "  import-raw FILE [NAME]      Import a local RAW container or VM image\n"
               "  import-fs DIRECTORY [NAME]  Import a local directory container image\n"
               "  export-tar NAME [FILE]      Export a TAR container image locally\n"
               "  export-raw NAME [FILE]      Export a RAW container or VM image locally\n"
               "  list-transfers              Show list of downloads in progress\n"
               "  cancel-transfer             Cancel a download\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "  -p --property=NAME          Show only properties by this name\n"
               "  -q --quiet                  Suppress output\n"
               "  -a --all                    Show all properties, including empty ones\n"
               "     --value                  When showing properties, only print the value\n"
               "  -l --full                   Do not ellipsize output\n"
               "     --kill-whom=WHOM         Whom to send signal to\n"
               "  -s --signal=SIGNAL          Which signal to send\n"
               "     --uid=USER               Specify user ID to invoke shell as\n"
               "  -E --setenv=VAR[=VALUE]     Add an environment variable for shell\n"
               "     --read-only              Create read-only bind mount\n"
               "     --mkdir                  Create directory before bind mounting, if missing\n"
               "  -n --lines=INTEGER          Number of journal entries to show\n"
               "     --max-addresses=INTEGER  Number of internet addresses to show at most\n"
               "  -o --output=STRING          Change journal output mode (short, short-precise,\n"
               "                               short-iso, short-iso-precise, short-full,\n"
               "                               short-monotonic, short-unix, short-delta,\n"
               "                               json, json-pretty, json-sse, json-seq, cat,\n"
               "                               verbose, export, with-unit)\n"
               "     --verify=MODE            Verification mode for downloaded images (no,\n"
               "                               checksum, signature)\n"
               "     --force                  Download image even if already exists\n"
               "     --now                    Start or power off container after enabling or\n"
               "                              disabling it\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_VALUE,
                ARG_KILL_WHOM,
                ARG_READ_ONLY,
                ARG_MKDIR,
                ARG_NO_ASK_PASSWORD,
                ARG_VERIFY,
                ARG_NOW,
                ARG_FORCE,
                ARG_FORMAT,
                ARG_UID,
                ARG_MAX_ADDRESSES,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "property",        required_argument, NULL, 'p'                 },
                { "all",             no_argument,       NULL, 'a'                 },
                { "value",           no_argument,       NULL, ARG_VALUE           },
                { "full",            no_argument,       NULL, 'l'                 },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "no-legend",       no_argument,       NULL, ARG_NO_LEGEND       },
                { "kill-whom",       required_argument, NULL, ARG_KILL_WHOM       },
                { "signal",          required_argument, NULL, 's'                 },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
                { "mkdir",           no_argument,       NULL, ARG_MKDIR           },
                { "quiet",           no_argument,       NULL, 'q'                 },
                { "lines",           required_argument, NULL, 'n'                 },
                { "output",          required_argument, NULL, 'o'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "verify",          required_argument, NULL, ARG_VERIFY          },
                { "now",             no_argument,       NULL, ARG_NOW             },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "format",          required_argument, NULL, ARG_FORMAT          },
                { "uid",             required_argument, NULL, ARG_UID             },
                { "setenv",          required_argument, NULL, 'E'                 },
                { "max-addresses",   required_argument, NULL, ARG_MAX_ADDRESSES   },
                {}
        };

        bool reorder = false;
        int c, r, shell = -1;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;

        for (;;) {
                static const char option_string[] = "-hp:als:H:M:qn:o:E:";

                c = getopt_long(argc, argv, option_string + reorder, options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 1: /* getopt_long() returns 1 if "-" was the first character of the option string, and a
                         * non-option argument was discovered. */

                        assert(!reorder);

                        /* We generally are fine with the fact that getopt_long() reorders the command line, and looks
                         * for switches after the main verb. However, for "shell" we really don't want that, since we
                         * want that switches specified after the machine name are passed to the program to execute,
                         * and not processed by us. To make this possible, we'll first invoke getopt_long() with
                         * reordering disabled (i.e. with the "-" prefix in the option string), looking for the first
                         * non-option parameter. If it's the verb "shell" we remember its position and continue
                         * processing options. In this case, as soon as we hit the next non-option argument we found
                         * the machine name, and stop further processing. If the first non-option argument is any other
                         * verb than "shell" we switch to normal reordering mode and continue processing arguments
                         * normally. */

                        if (shell >= 0) {
                                /* If we already found the "shell" verb on the command line, and now found the next
                                 * non-option argument, then this is the machine name and we should stop processing
                                 * further arguments.  */
                                optind--; /* don't process this argument, go one step back */
                                goto done;
                        }
                        if (streq(optarg, "shell"))
                                /* Remember the position of the "shell" verb, and continue processing normally. */
                                shell = optind - 1;
                        else {
                                int saved_optind;

                                /* OK, this is some other verb. In this case, turn on reordering again, and continue
                                 * processing normally. */
                                reorder = true;

                                /* We changed the option string. getopt_long() only looks at it again if we invoke it
                                 * at least once with a reset option index. Hence, let's reset the option index here,
                                 * then invoke getopt_long() again (ignoring what it has to say, after all we most
                                 * likely already processed it), and the bump the option index so that we read the
                                 * intended argument again. */
                                saved_optind = optind;
                                optind = 0;
                                (void) getopt_long(argc, argv, option_string + reorder, options, NULL);
                                optind = saved_optind - 1; /* go one step back, process this argument again */
                        }

                        break;

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case 'p':
                        r = strv_extend(&arg_property, optarg);
                        if (r < 0)
                                return log_oom();

                        /* If the user asked for a particular
                         * property, show it to them, even if it is
                         * empty. */
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);
                        break;

                case 'a':
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);
                        arg_all = true;
                        break;

                case ARG_VALUE:
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'", optarg);
                        break;

                case 'o':
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);
                                return 0;
                        }

                        r = output_mode_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unknown output '%s'.", optarg);
                        arg_output = r;

                        if (OUTPUT_MODE_IS_JSON(arg_output))
                                arg_legend = false;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_KILL_WHOM:
                        arg_kill_whom = optarg;
                        break;

                case 's':
                        r = parse_signal_argument(optarg, &arg_signal);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_MKDIR:
                        arg_mkdir = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERIFY:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(import_verify, ImportVerify, _IMPORT_VERIFY_MAX);
                                return 0;
                        }

                        r = import_verify_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --verify= setting: %s", optarg);
                        arg_verify = r;
                        break;

                case ARG_NOW:
                        arg_now = true;
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_FORMAT:
                        if (!STR_IN_SET(optarg, "uncompressed", "xz", "gzip", "bzip2"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", optarg);

                        arg_format = optarg;
                        break;

                case ARG_UID:
                        arg_uid = optarg;
                        break;

                case 'E':
                        r = strv_env_replace_strdup_passthrough(&arg_setenv, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);
                        break;

                case ARG_MAX_ADDRESSES:
                        if (streq(optarg, "all"))
                                arg_max_addresses = UINT_MAX;
                        else if (safe_atou(optarg, &arg_max_addresses) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid number of addresses: %s", optarg);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

done:
        if (shell >= 0) {
                char *t;

                /* We found the "shell" verb while processing the argument list. Since we turned off reordering of the
                 * argument list initially let's readjust it now, and move the "shell" verb to the back. */

                optind -= 1; /* place the option index where the "shell" verb will be placed */

                t = argv[shell];
                for (int i = shell; i < optind; i++)
                        argv[i] = argv[i+1];
                argv[optind] = t;
        }

        return 1;
}

static int machinectl_main(int argc, char *argv[], sd_bus *bus) {

        static const Verb verbs[] = {
                { "help",            VERB_ANY, VERB_ANY, 0,            help              },
                { "list",            VERB_ANY, 1,        VERB_DEFAULT, list_machines     },
                { "list-images",     VERB_ANY, 1,        0,            list_images       },
                { "status",          2,        VERB_ANY, 0,            show_machine      },
                { "image-status",    VERB_ANY, VERB_ANY, 0,            show_image        },
                { "show",            VERB_ANY, VERB_ANY, 0,            show_machine      },
                { "show-image",      VERB_ANY, VERB_ANY, 0,            show_image        },
                { "terminate",       2,        VERB_ANY, 0,            terminate_machine },
                { "reboot",          2,        VERB_ANY, 0,            reboot_machine    },
                { "poweroff",        2,        VERB_ANY, 0,            poweroff_machine  },
                { "stop",            2,        VERB_ANY, 0,            poweroff_machine  }, /* Convenience alias */
                { "kill",            2,        VERB_ANY, 0,            kill_machine      },
                { "login",           VERB_ANY, 2,        0,            login_machine     },
                { "shell",           VERB_ANY, VERB_ANY, 0,            shell_machine     },
                { "bind",            3,        4,        0,            bind_mount        },
                { "edit",            2,        VERB_ANY, 0,            edit_settings     },
                { "cat",             2,        VERB_ANY, 0,            cat_settings      },
                { "copy-to",         3,        4,        0,            copy_files        },
                { "copy-from",       3,        4,        0,            copy_files        },
                { "remove",          2,        VERB_ANY, 0,            remove_image      },
                { "rename",          3,        3,        0,            rename_image      },
                { "clone",           3,        3,        0,            clone_image       },
                { "read-only",       2,        3,        0,            read_only_image   },
                { "start",           2,        VERB_ANY, 0,            start_machine     },
                { "enable",          2,        VERB_ANY, 0,            enable_machine    },
                { "disable",         2,        VERB_ANY, 0,            enable_machine    },
                { "import-tar",      2,        3,        0,            import_tar        },
                { "import-raw",      2,        3,        0,            import_raw        },
                { "import-fs",       2,        3,        0,            import_fs         },
                { "export-tar",      2,        3,        0,            export_tar        },
                { "export-raw",      2,        3,        0,            export_raw        },
                { "pull-tar",        2,        3,        0,            pull_tar          },
                { "pull-raw",        2,        3,        0,            pull_raw          },
                { "list-transfers",  VERB_ANY, 1,        0,            list_transfers    },
                { "cancel-transfer", 2,        VERB_ANY, 0,            cancel_transfer   },
                { "set-limit",       2,        3,        0,            set_limit         },
                { "clean",           VERB_ANY, 1,        0,            clean_images      },
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        /* The journal merging logic potentially needs a lot of fds. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        sigbus_install();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        return machinectl_main(argc, argv, bus);
}

DEFINE_MAIN_FUNCTION(run);
