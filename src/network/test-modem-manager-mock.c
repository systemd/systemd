/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Minimal mock of ModemManager's D-Bus interface for testing systemd-networkd
 * wwan/bearer support.
 *
 * Claims the org.freedesktop.ModemManager1 bus name and responds to:
 * - GetManagedObjects on /org/freedesktop/ModemManager1
 * - GetAll on /org/freedesktop/ModemManager1/Bearer/0
 * - Simple.Connect on /org/freedesktop/ModemManager1/Modem/0
 */

#include <getopt.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "string-util.h"

static char *arg_ifname = NULL;
static char *arg_ipv4_address = NULL;
static char *arg_ipv4_gateway = NULL;
static uint32_t arg_ipv4_prefix = 24;
static char *arg_ipv6_address = NULL;
static char *arg_ipv6_gateway = NULL;
static uint32_t arg_ipv6_prefix = 64;

STATIC_DESTRUCTOR_REGISTER(arg_ifname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ipv4_address, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ipv4_gateway, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ipv6_address, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ipv6_gateway, freep);

/* ModemManager enum values */
#define MM_BEARER_IP_METHOD_STATIC 2
#define MM_MODEM_PORT_TYPE_NET     2
#define MM_MODEM_STATE_CONNECTED   11

static int append_bearer_properties(sd_bus_message *reply) {
        int r;

        /* a{sv} of bearer properties */
        r = sd_bus_message_open_container(reply, 'a', "{sv}");
        if (r < 0)
                return r;

        /* Interface */
        r = sd_bus_message_append(reply, "{sv}", "Interface", "s", arg_ifname);
        if (r < 0)
                return r;

        /* Connected */
        r = sd_bus_message_append(reply, "{sv}", "Connected", "b", true);
        if (r < 0)
                return r;

        /* Ip4Config: a{sv} */
        if (arg_ipv4_address) {
                r = sd_bus_message_open_container(reply, 'e', "sv");
                if (r < 0)
                        return r;
                r = sd_bus_message_append_basic(reply, 's', "Ip4Config");
                if (r < 0)
                        return r;
                r = sd_bus_message_open_container(reply, 'v', "a{sv}");
                if (r < 0)
                        return r;
                r = sd_bus_message_open_container(reply, 'a', "{sv}");
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "method", "u", (uint32_t) MM_BEARER_IP_METHOD_STATIC);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "address", "s", arg_ipv4_address);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "prefix", "u", arg_ipv4_prefix);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "gateway", "s", arg_ipv4_gateway);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "mtu", "u", (uint32_t) 1500);
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* a{sv} */
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* v */
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* e */
                if (r < 0)
                        return r;
        }

        /* Ip6Config: a{sv} */
        if (arg_ipv6_address) {
                r = sd_bus_message_open_container(reply, 'e', "sv");
                if (r < 0)
                        return r;
                r = sd_bus_message_append_basic(reply, 's', "Ip6Config");
                if (r < 0)
                        return r;
                r = sd_bus_message_open_container(reply, 'v', "a{sv}");
                if (r < 0)
                        return r;
                r = sd_bus_message_open_container(reply, 'a', "{sv}");
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "method", "u", (uint32_t) MM_BEARER_IP_METHOD_STATIC);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "address", "s", arg_ipv6_address);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "prefix", "u", arg_ipv6_prefix);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "gateway", "s", arg_ipv6_gateway);
                if (r < 0)
                        return r;
                r = sd_bus_message_append(reply, "{sv}", "mtu", "u", (uint32_t) 1500);
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* a{sv} */
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* v */
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(reply); /* e */
                if (r < 0)
                        return r;
        }

        /* Properties: a{sv} with apn */
        r = sd_bus_message_open_container(reply, 'e', "sv");
        if (r < 0)
                return r;
        r = sd_bus_message_append_basic(reply, 's', "Properties");
        if (r < 0)
                return r;
        r = sd_bus_message_open_container(reply, 'v', "a{sv}");
        if (r < 0)
                return r;
        r = sd_bus_message_open_container(reply, 'a', "{sv}");
        if (r < 0)
                return r;
        r = sd_bus_message_append(reply, "{sv}", "apn", "s", "internet.test");
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* a{sv} */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* v */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* e */
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply); /* outer a{sv} */
        if (r < 0)
                return r;

        return 0;
}

static int handle_get_managed_objects(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        /* a{oa{sa{sv}}} */
        r = sd_bus_message_open_container(reply, 'a', "{oa{sa{sv}}}");
        if (r < 0)
                return r;

        /* Modem object */
        r = sd_bus_message_open_container(reply, 'e', "oa{sa{sv}}");
        if (r < 0)
                return r;
        r = sd_bus_message_append_basic(reply, 'o', "/org/freedesktop/ModemManager1/Modem/0");
        if (r < 0)
                return r;

        /* Array of interfaces */
        r = sd_bus_message_open_container(reply, 'a', "{sa{sv}}");
        if (r < 0)
                return r;

        /* org.freedesktop.ModemManager1.Modem interface */
        r = sd_bus_message_open_container(reply, 'e', "sa{sv}");
        if (r < 0)
                return r;
        r = sd_bus_message_append_basic(reply, 's', "org.freedesktop.ModemManager1.Modem");
        if (r < 0)
                return r;

        /* Modem properties: a{sv} */
        r = sd_bus_message_open_container(reply, 'a', "{sv}");
        if (r < 0)
                return r;

        /* Bearers: ao */
        r = sd_bus_message_append(reply, "{sv}", "Bearers", "ao", 1, "/org/freedesktop/ModemManager1/Bearer/0");
        if (r < 0)
                return r;

        /* State: i (CONNECTED) */
        r = sd_bus_message_append(reply, "{sv}", "State", "i", (int32_t) MM_MODEM_STATE_CONNECTED);
        if (r < 0)
                return r;

        /* StateFailedReason: u (NONE) */
        r = sd_bus_message_append(reply, "{sv}", "StateFailedReason", "u", (uint32_t) 0);
        if (r < 0)
                return r;

        /* Manufacturer */
        r = sd_bus_message_append(reply, "{sv}", "Manufacturer", "s", "MockModem");
        if (r < 0)
                return r;

        /* Model */
        r = sd_bus_message_append(reply, "{sv}", "Model", "s", "Virtual");
        if (r < 0)
                return r;

        /* Ports: a(su) — array of structs with port name and type */
        r = sd_bus_message_open_container(reply, 'e', "sv");
        if (r < 0)
                return r;
        r = sd_bus_message_append_basic(reply, 's', "Ports");
        if (r < 0)
                return r;
        r = sd_bus_message_open_container(reply, 'v', "a(su)");
        if (r < 0)
                return r;
        r = sd_bus_message_open_container(reply, 'a', "(su)");
        if (r < 0)
                return r;
        r = sd_bus_message_append(reply, "(su)", arg_ifname, (uint32_t) MM_MODEM_PORT_TYPE_NET);
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* a(su) */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* v */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* e */
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply); /* modem properties a{sv} */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* e sa{sv} */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* a{sa{sv}} */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* e oa{sa{sv}} */
        if (r < 0)
                return r;
        r = sd_bus_message_close_container(reply); /* a{oa{sa{sv}}} */
        if (r < 0)
                return r;

        r = sd_bus_send(NULL, reply, NULL);
        if (r < 0)
                return r;

        return 1; /* handled */
}

static int handle_get_all(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        /* bearer_get_all_handler() in networkd expects a leading interface name string
         * before the a{sv} properties dict (it calls sd_bus_message_skip(message, "s")). */
        r = sd_bus_message_append_basic(reply, 's', "org.freedesktop.ModemManager1.Bearer");
        if (r < 0)
                return r;

        r = append_bearer_properties(reply);
        if (r < 0)
                return r;

        r = sd_bus_send(NULL, reply, NULL);
        if (r < 0)
                return r;

        return 1; /* handled */
}

static int handle_simple_connect(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        /* Return the bearer path */
        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "o", "/org/freedesktop/ModemManager1/Bearer/0");
        if (r < 0)
                return r;

        r = sd_bus_send(NULL, reply, NULL);
        if (r < 0)
                return r;

        return 1; /* handled */
}

static int filter_handler(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *path, *interface, *member;
        uint8_t type;

        if (sd_bus_message_get_type(m, &type) < 0 || type != SD_BUS_MESSAGE_METHOD_CALL)
                return 0;

        path = sd_bus_message_get_path(m);
        interface = sd_bus_message_get_interface(m);
        member = sd_bus_message_get_member(m);

        if (!path || !interface || !member)
                return 0;

        if (streq(path, "/org/freedesktop/ModemManager1") &&
            streq(interface, "org.freedesktop.DBus.ObjectManager") &&
            streq(member, "GetManagedObjects"))
                return handle_get_managed_objects(m, userdata, error);

        if (startswith(path, "/org/freedesktop/ModemManager1/Bearer/") &&
            streq(interface, "org.freedesktop.DBus.Properties") &&
            streq(member, "GetAll"))
                return handle_get_all(m, userdata, error);

        if (startswith(path, "/org/freedesktop/ModemManager1/Modem/") &&
            streq(interface, "org.freedesktop.ModemManager1.Modem.Simple") &&
            streq(member, "Connect"))
                return handle_simple_connect(m, userdata, error);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_IFNAME = 0x100,
                ARG_IPV4_ADDRESS,
                ARG_IPV4_GATEWAY,
                ARG_IPV4_PREFIX,
                ARG_IPV6_ADDRESS,
                ARG_IPV6_GATEWAY,
                ARG_IPV6_PREFIX,
        };

        static const struct option options[] = {
                { "ifname",       required_argument, NULL, ARG_IFNAME       },
                { "ipv4-address", required_argument, NULL, ARG_IPV4_ADDRESS },
                { "ipv4-gateway", required_argument, NULL, ARG_IPV4_GATEWAY },
                { "ipv4-prefix",  required_argument, NULL, ARG_IPV4_PREFIX  },
                { "ipv6-address", required_argument, NULL, ARG_IPV6_ADDRESS },
                { "ipv6-gateway", required_argument, NULL, ARG_IPV6_GATEWAY },
                { "ipv6-prefix",  required_argument, NULL, ARG_IPV6_PREFIX  },
                { "version",      no_argument,       NULL, 'v'              },
                { "help",         no_argument,       NULL, 'h'              },
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "vh", options, NULL)) >= 0)
                switch (c) {
                case ARG_IFNAME:
                        if (free_and_strdup(&arg_ifname, optarg) < 0)
                                return log_oom();
                        break;
                case ARG_IPV4_ADDRESS:
                        if (free_and_strdup(&arg_ipv4_address, optarg) < 0)
                                return log_oom();
                        break;
                case ARG_IPV4_GATEWAY:
                        if (free_and_strdup(&arg_ipv4_gateway, optarg) < 0)
                                return log_oom();
                        break;
                case ARG_IPV4_PREFIX:
                        r = safe_atou32(optarg, &arg_ipv4_prefix);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv4 prefix length: %m");
                        break;
                case ARG_IPV6_ADDRESS:
                        if (free_and_strdup(&arg_ipv6_address, optarg) < 0)
                                return log_oom();
                        break;
                case ARG_IPV6_GATEWAY:
                        if (free_and_strdup(&arg_ipv6_gateway, optarg) < 0)
                                return log_oom();
                        break;
                case ARG_IPV6_PREFIX:
                        r = safe_atou32(optarg, &arg_ipv6_prefix);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv6 prefix length: %m");
                        break;
                case 'v':
                        return version();
                case 'h':
                        printf("Usage: %s [OPTIONS...]\n\n"
                               "Mock ModemManager D-Bus service for testing.\n\n"
                               "  --ifname=NAME          Interface name\n"
                               "  --ipv4-address=ADDR    IPv4 address\n"
                               "  --ipv4-gateway=ADDR    IPv4 gateway\n"
                               "  --ipv4-prefix=LEN      IPv4 prefix length\n"
                               "  --ipv6-address=ADDR    IPv6 address\n"
                               "  --ipv6-gateway=ADDR    IPv6 gateway\n"
                               "  --ipv6-prefix=LEN      IPv6 prefix length\n"
                               "  -h, --help             Show this help\n"
                               "  -v, --version          Show version\n",
                               program_invocation_short_name);
                        return 0;
                default:
                        return -EINVAL;
                }

        if (!arg_ifname)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ifname is required");

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to create event loop: %m");

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_add_filter(bus, NULL, filter_handler, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter: %m");

        r = sd_bus_request_name(bus, "org.freedesktop.ModemManager1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        (void) sd_notify(0, "READY=1");

        return sd_event_loop(event);
}

DEFINE_MAIN_FUNCTION(run);
