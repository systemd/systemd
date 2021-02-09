/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sd-bus.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "architecture.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-map-properties.h"
#include "format-table.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "spawn-polkit-agent.h"
#include "terminal-util.h"
#include "util.h"
#include "verbs.h"

static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_transient = false;
static bool arg_pretty = false;
static bool arg_static = false;

typedef struct StatusInfo {
        const char *hostname;
        const char *static_hostname;
        const char *pretty_hostname;
        const char *icon_name;
        const char *chassis;
        const char *deployment;
        const char *location;
        const char *kernel_name;
        const char *kernel_release;
        const char *os_pretty_name;
        const char *os_cpe_name;
        const char *virtualization;
        const char *architecture;
        const char *home_url;
        const char *hardware_vendor;
        const char *hardware_model;
} StatusInfo;

static int print_status_info(StatusInfo *i) {
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_id128_t mid = {}, bid = {};
        TableCell *cell;
        int r;

        assert(i);

        table = table_new("key", "value");
        if (!table)
                return log_oom();

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_ellipsize_percent(table, cell, 100);
        (void) table_set_align_percent(table, cell, 100);

        table_set_header(table, false);

        r = table_set_empty_string(table, "n/a");
        if (r < 0)
                return log_oom();

        r = table_add_many(table,
                           TABLE_STRING, "Static hostname:",
                           TABLE_STRING, i->static_hostname);
        if (r < 0)
                return table_log_add_error(r);

        if (!isempty(i->pretty_hostname) &&
            !streq_ptr(i->pretty_hostname, i->static_hostname)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Pretty hostname:",
                                   TABLE_STRING, i->pretty_hostname);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->hostname) &&
            !streq_ptr(i->hostname, i->static_hostname)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Transient hostname:",
                                   TABLE_STRING, i->hostname);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->icon_name)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Icon name:",
                                   TABLE_STRING, i->icon_name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->chassis)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Chassis:",
                                   TABLE_STRING, i->chassis);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->deployment)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Deployment:",
                                   TABLE_STRING, i->deployment);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->location)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Location:",
                                   TABLE_STRING, i->location);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_id128_get_machine(&mid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_STRING, "Machine ID:",
                                   TABLE_ID128, mid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_id128_get_boot(&bid);
        if (r >= 0) {
                r = table_add_many(table,
                                   TABLE_STRING, "Boot ID:",
                                   TABLE_ID128, bid);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->virtualization)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Virtualization:",
                                   TABLE_STRING, i->virtualization);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->os_pretty_name)) {
                _cleanup_free_ char *formatted = NULL;
                const char *t = i->os_pretty_name;

                if (i->home_url) {
                        if (terminal_urlify(i->home_url, i->os_pretty_name, &formatted) >= 0)
                                t = formatted;
                }

                r = table_add_many(table,
                                   TABLE_STRING, "Operating System:",
                                   TABLE_STRING, t);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->os_cpe_name)) {
                r = table_add_many(table,
                                   TABLE_STRING, "CPE OS Name:",
                                   TABLE_STRING, i->os_cpe_name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->kernel_name) && !isempty(i->kernel_release)) {
                const char *v;

                v = strjoina(i->kernel_name, " ", i->kernel_release);
                r = table_add_many(table,
                                   TABLE_STRING, "Kernel:",
                                   TABLE_STRING, v);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->architecture)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Architecture:",
                                   TABLE_STRING, i->architecture);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->hardware_vendor)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Hardware Vendor:",
                                   TABLE_STRING, i->hardware_vendor);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->hardware_model)) {
                r = table_add_many(table,
                                   TABLE_STRING, "Hardware Model:",
                                   TABLE_STRING, i->hardware_model);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int get_one_name(sd_bus *bus, const char* attr, char **ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *s;
        int r;

        assert(bus);
        assert(attr);

        /* This obtains one string property, and copy it if 'ret' is set, or print it otherwise. */

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        attr,
                        &error, &reply, "s");
        if (r < 0)
                return log_error_errno(r, "Could not get property: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return bus_log_parse_error(r);

        if (ret) {
                char *str;

                str = strdup(s);
                if (!str)
                        return log_oom();

                *ret = str;
        } else
                printf("%s\n", s);

        return 0;
}

static int show_all_names(sd_bus *bus) {
        StatusInfo info = {};

        static const struct bus_properties_map hostname_map[]  = {
                { "Hostname",                  "s", NULL, offsetof(StatusInfo, hostname)        },
                { "StaticHostname",            "s", NULL, offsetof(StatusInfo, static_hostname) },
                { "PrettyHostname",            "s", NULL, offsetof(StatusInfo, pretty_hostname) },
                { "IconName",                  "s", NULL, offsetof(StatusInfo, icon_name)       },
                { "Chassis",                   "s", NULL, offsetof(StatusInfo, chassis)         },
                { "Deployment",                "s", NULL, offsetof(StatusInfo, deployment)      },
                { "Location",                  "s", NULL, offsetof(StatusInfo, location)        },
                { "KernelName",                "s", NULL, offsetof(StatusInfo, kernel_name)     },
                { "KernelRelease",             "s", NULL, offsetof(StatusInfo, kernel_release)  },
                { "OperatingSystemPrettyName", "s", NULL, offsetof(StatusInfo, os_pretty_name)  },
                { "OperatingSystemCPEName",    "s", NULL, offsetof(StatusInfo, os_cpe_name)     },
                { "HomeURL",                   "s", NULL, offsetof(StatusInfo, home_url)        },
                { "HardwareVendor",            "s", NULL, offsetof(StatusInfo, hardware_vendor) },
                { "HardwareModel",             "s", NULL, offsetof(StatusInfo, hardware_model)  },
                {}
        };

        static const struct bus_properties_map manager_map[] = {
                { "Virtualization",            "s", NULL, offsetof(StatusInfo, virtualization)  },
                { "Architecture",              "s", NULL, offsetof(StatusInfo, architecture)    },
                {}
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *host_message = NULL, *manager_message = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.hostname1",
                                   "/org/freedesktop/hostname1",
                                   hostname_map,
                                   0,
                                   &error,
                                   &host_message,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Failed to query system properties: %s", bus_error_message(&error, r));

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.systemd1",
                                   "/org/freedesktop/systemd1",
                                   manager_map,
                                   0,
                                   &error,
                                   &manager_message,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Failed to query system properties: %s", bus_error_message(&error, r));

        return print_status_info(&info);
}

static int show_status(int argc, char **argv, void *userdata) {
        sd_bus *bus = userdata;

        if (arg_pretty || arg_static || arg_transient) {
                const char *attr;

                if (!!arg_static + !!arg_pretty + !!arg_transient > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Cannot query more than one name type at a time");

                attr = arg_pretty ? "PrettyHostname" :
                        arg_static ? "StaticHostname" : "Hostname";

                return get_one_name(bus, attr, NULL);
        }

        return show_all_names(bus);
}

static int set_simple_string_internal(sd_bus *bus, sd_bus_error *error, const char *target, const char *method, const char *value) {
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (!error)
                error = &e;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        method,
                        error, NULL,
                        "sb", value, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Could not set %s: %s", target, bus_error_message(error, r));

        return 0;
}

static int set_simple_string(sd_bus *bus, const char *target, const char *method, const char *value) {
        return set_simple_string_internal(bus, NULL, target, method, value);
}

static int set_hostname(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *h = NULL;
        const char *hostname = argv[1];
        sd_bus *bus = userdata;
        bool implicit = false, show_hint = false;
        int r, ret = 0;

        if (!arg_pretty && !arg_static && !arg_transient)
                arg_pretty = arg_static = arg_transient = implicit = true;

        if (!implicit && !arg_static && arg_transient) {
                _cleanup_free_ char *source = NULL;

                r = get_one_name(bus, "HostnameSource", &source);
                if (r < 0)
                        return r;

                if (hostname_source_from_string(source) == HOSTNAME_STATIC)
                        log_info("Hint: static hostname is already set, so the specified transient hostname will not be used.");
        }

        if (arg_pretty) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *p;

                /* If the passed hostname is already valid, then assume the user doesn't know anything about pretty
                 * hostnames, so let's unset the pretty hostname, and just set the passed hostname as static/dynamic
                 * hostname. */
                if (implicit && hostname_is_valid(hostname, VALID_HOSTNAME_TRAILING_DOT))
                        p = ""; /* No pretty hostname (as it is redundant), just a static one */
                else
                        p = hostname; /* Use the passed name as pretty hostname */

                r = set_simple_string_internal(bus, &error, "pretty hostname", "SetPrettyHostname", p);
                if (r < 0) {
                        if (implicit &&
                            sd_bus_error_has_names(&error,
                                                   BUS_ERROR_FILE_IS_PROTECTED,
                                                   BUS_ERROR_READ_ONLY_FILESYSTEM)) {
                                show_hint = true;
                                ret = r;
                        } else
                                return r;
                }

                /* Now that we set the pretty hostname, let's clean up the parameter and use that as static
                 * hostname. If the hostname was already valid as static hostname, this will only chop off the trailing
                 * dot if there is one. If it was not valid, then it will be made fully valid by truncating, dropping
                 * multiple dots, and dropping weird chars. Note that we clean the name up only if we also are
                 * supposed to set the pretty name. If the pretty name is not being set we assume the user knows what
                 * he does and pass the name as-is. */
                h = strdup(hostname);
                if (!h)
                        return log_oom();

                hostname = hostname_cleanup(h); /* Use the cleaned up name as static hostname */
        }

        if (arg_static) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = set_simple_string_internal(bus, &error, "static hostname", "SetStaticHostname", hostname);
                if (r < 0) {
                        if (implicit &&
                            sd_bus_error_has_names(&error,
                                                   BUS_ERROR_FILE_IS_PROTECTED,
                                                   BUS_ERROR_READ_ONLY_FILESYSTEM)) {
                                show_hint = true;
                                ret = r;
                        } else
                                return r;
                }
        }

        if (arg_transient) {
                r = set_simple_string(bus, "transient hostname", "SetHostname", hostname);
                if (r < 0)
                        return r;
        }

        if (show_hint)
                log_info("Hint: use --transient option when /etc/machine-info or /etc/hostname cannot be modified (e.g. located in read-only filesystem).");

        return ret;
}

static int set_icon_name(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "icon", "SetIconName", argv[1]);
}

static int set_chassis(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "chassis", "SetChassis", argv[1]);
}

static int set_deployment(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "deployment", "SetDeployment", argv[1]);
}

static int set_location(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "location", "SetLocation", argv[1]);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("hostnamectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sQuery or change system hostname.%s\n"
               "\nCommands:\n"
               "  status                 Show current hostname settings\n"
               "  set-hostname NAME      Set system hostname\n"
               "  set-icon-name NAME     Set icon name for host\n"
               "  set-chassis NAME       Set chassis type for host\n"
               "  set-deployment NAME    Set deployment environment for host\n"
               "  set-location NAME      Set location for host\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-ask-password   Do not prompt for password\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n"
               "  -M --machine=CONTAINER Operate on local container\n"
               "     --transient         Only set transient hostname\n"
               "     --static            Only set static hostname\n"
               "     --pretty            Only set pretty hostname\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_ASK_PASSWORD,
                ARG_TRANSIENT,
                ARG_STATIC,
                ARG_PRETTY
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "transient",       no_argument,       NULL, ARG_TRANSIENT       },
                { "static",          no_argument,       NULL, ARG_STATIC          },
                { "pretty",          no_argument,       NULL, ARG_PRETTY          },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_TRANSIENT:
                        arg_transient = true;
                        break;

                case ARG_PRETTY:
                        arg_pretty = true;
                        break;

                case ARG_STATIC:
                        arg_static = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int hostnamectl_main(sd_bus *bus, int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "status",         VERB_ANY, 1,        VERB_DEFAULT, show_status    },
                { "set-hostname",   2,        2,        0,            set_hostname   },
                { "set-icon-name",  2,        2,        0,            set_icon_name  },
                { "set-chassis",    2,        2,        0,            set_chassis    },
                { "set-deployment", 2,        2,        0,            set_deployment },
                { "set-location",   2,        2,        0,            set_location   },
                { "help",           VERB_ANY, VERB_ANY, 0,            verb_help      }, /* Not documented, but supported since it is created. */
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, false, &bus);
        if (r < 0)
                return bus_log_connect_error(r);

        return hostnamectl_main(bus, argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
