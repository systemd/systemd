/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sd-bus.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "architecture.h"
#include "bus-error.h"
#include "bus-util.h"
#include "hostname-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "spawn-polkit-agent.h"
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
} StatusInfo;

static void print_status_info(StatusInfo *i) {
        sd_id128_t mid = {}, bid = {};
        int r;

        assert(i);

        printf("   Static hostname: %s\n", strna(i->static_hostname));

        if (!isempty(i->pretty_hostname) &&
            !streq_ptr(i->pretty_hostname, i->static_hostname))
                printf("   Pretty hostname: %s\n", i->pretty_hostname);

        if (!isempty(i->hostname) &&
            !streq_ptr(i->hostname, i->static_hostname))
                printf("Transient hostname: %s\n", i->hostname);

        if (!isempty(i->icon_name))
                printf("         Icon name: %s\n",
                       strna(i->icon_name));

        if (!isempty(i->chassis))
                printf("           Chassis: %s\n",
                       strna(i->chassis));

        if (!isempty(i->deployment))
                printf("        Deployment: %s\n", i->deployment);

        if (!isempty(i->location))
                printf("          Location: %s\n", i->location);

        r = sd_id128_get_machine(&mid);
        if (r >= 0)
                printf("        Machine ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(mid));

        r = sd_id128_get_boot(&bid);
        if (r >= 0)
                printf("           Boot ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(bid));

        if (!isempty(i->virtualization))
                printf("    Virtualization: %s\n", i->virtualization);

        if (!isempty(i->os_pretty_name)) {
                _cleanup_free_ char *formatted = NULL;
                const char *t = i->os_pretty_name;

                if (i->home_url) {
                        if (terminal_urlify(i->home_url, i->os_pretty_name, &formatted) >= 0)
                                t = formatted;
                }

                printf("  Operating System: %s\n", t);
        }

        if (!isempty(i->os_cpe_name))
                printf("       CPE OS Name: %s\n", i->os_cpe_name);

        if (!isempty(i->kernel_name) && !isempty(i->kernel_release))
                printf("            Kernel: %s %s\n", i->kernel_name, i->kernel_release);

        if (!isempty(i->architecture))
                printf("      Architecture: %s\n", i->architecture);

}

static int show_one_name(sd_bus *bus, const char* attr) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *s;
        int r;

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

        printf("%s\n", s);

        return 0;
}

static int show_all_names(sd_bus *bus, sd_bus_error *error) {
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
                {}
        };

        static const struct bus_properties_map manager_map[] = {
                { "Virtualization",            "s", NULL, offsetof(StatusInfo, virtualization)  },
                { "Architecture",              "s", NULL, offsetof(StatusInfo, architecture)    },
                {}
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *host_message = NULL, *manager_message = NULL;
        int r;

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.hostname1",
                                   "/org/freedesktop/hostname1",
                                   hostname_map,
                                   0,
                                   error,
                                   &host_message,
                                   &info);
        if (r < 0)
                return r;

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.systemd1",
                                   "/org/freedesktop/systemd1",
                                   manager_map,
                                   0,
                                   error,
                                   &manager_message,
                                   &info);

        print_status_info(&info);

        return r;
}

static int show_status(int argc, char **argv, void *userdata) {
        sd_bus *bus = userdata;
        int r;

        if (arg_pretty || arg_static || arg_transient) {
                const char *attr;

                if (!!arg_static + !!arg_pretty + !!arg_transient > 1) {
                        log_error("Cannot query more than one name type at a time");
                        return -EINVAL;
                }

                attr = arg_pretty ? "PrettyHostname" :
                        arg_static ? "StaticHostname" : "Hostname";

                return show_one_name(bus, attr);
        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = show_all_names(bus, &error);
                if (r < 0)
                        return log_error_errno(r, "Failed to query system properties: %s", bus_error_message(&error, r));

                return 0;
        }
}

static int set_simple_string(sd_bus *bus, const char *method, const char *value) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r = 0;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        method,
                        &error, NULL,
                        "sb", value, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Could not set property: %s", bus_error_message(&error, -r));

        return 0;
}

static int set_hostname(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *h = NULL;
        const char *hostname = argv[1];
        sd_bus *bus = userdata;
        int r;

        if (!arg_pretty && !arg_static && !arg_transient)
                arg_pretty = arg_static = arg_transient = true;

        if (arg_pretty) {
                const char *p;

                /* If the passed hostname is already valid, then assume the user doesn't know anything about pretty
                 * hostnames, so let's unset the pretty hostname, and just set the passed hostname as static/dynamic
                 * hostname. */
                if (arg_static && hostname_is_valid(hostname, true))
                        p = ""; /* No pretty hostname (as it is redundant), just a static one */
                else
                        p = hostname; /* Use the passed name as pretty hostname */

                r = set_simple_string(bus, "SetPrettyHostname", p);
                if (r < 0)
                        return r;

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
                r = set_simple_string(bus, "SetStaticHostname", hostname);
                if (r < 0)
                        return r;
        }

        if (arg_transient) {
                r = set_simple_string(bus, "SetHostname", hostname);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int set_icon_name(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "SetIconName", argv[1]);
}

static int set_chassis(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "SetChassis", argv[1]);
}

static int set_deployment(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "SetDeployment", argv[1]);
}

static int set_location(int argc, char **argv, void *userdata) {
        return set_simple_string(userdata, "SetLocation", argv[1]);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("hostnamectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change system hostname.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-ask-password   Do not prompt for password\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n"
               "  -M --machine=CONTAINER Operate on local container\n"
               "     --transient         Only set transient hostname\n"
               "     --static            Only set static hostname\n"
               "     --pretty            Only set pretty hostname\n\n"
               "Commands:\n"
               "  status                 Show current hostname settings\n"
               "  set-hostname NAME      Set system hostname\n"
               "  set-icon-name NAME     Set icon name for host\n"
               "  set-chassis NAME       Set chassis type for host\n"
               "  set-deployment NAME    Set deployment environment for host\n"
               "  set-location NAME      Set location for host\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

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
        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, false, &bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        return hostnamectl_main(bus, argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
