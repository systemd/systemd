/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <arpa/inet.h>
#include <net/if.h>
#include <getopt.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-errors.h"
#include "in-addr-util.h"
#include "af-list.h"
#include "build.h"

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

static int arg_family = AF_UNSPEC;
static int arg_ifindex = 0;

static int resolve_host(sd_bus *bus, const char *name, int _family, int _ifindex) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned c = 0;
        int r;

        assert(name);

        log_debug("Resolving %s (family %s)",
                  name, af_to_name(_family));

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveHostname");
        if (r < 0) {
                log_error("sd_bus_message_new_method_call: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_set_auto_start(req, false);
        if (r < 0) {
                log_error("sd_bus_message_set_auto_start: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_append(req, "si", name, AF_UNSPEC);
        if (r < 0) {
                log_error("sd_bus_message_append: %s", strerror(-r));
                return r;
        }

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                log_error("%s: resolve call failed: %s", name, bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(iayi)");
        if (r < 0) {
                log_error("%s: failed to parse reply: %s", name, bus_error_message(&error, r));
                return r;
        }

        while ((r = sd_bus_message_enter_container(reply, 'r', "iayi")) > 0) {
                const void *a;
                int family, ifindex;
                size_t sz;
                _cleanup_free_ char *pretty = NULL;
                char ifname[IF_NAMESIZE] = "";

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0) {
                        log_error("Cannot parse message, aborting.");
                        return -EBADMSG;
                }

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0) {
                        log_error("Cannot parse message, aborting.");
                        return -EBADMSG;
                }

                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0) {
                        log_error("Cannot parse message, aborting.");
                        return -EBADMSG;
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0) {
                        log_error("Cannot parse message, aborting.");
                        return -EBADMSG;
                }

                if ((_family != AF_UNSPEC && family != _family) ||
                    !IN_SET(family, AF_INET, AF_INET6)) {
                        log_debug("%s: skipping entry with family %hu (%s)",
                                  name, family, af_to_name(family) ?: "unknown");
                        continue;
                }

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
                        log_error("%s: systemd-resolved returned address of invalid size %zu for family %s",
                                  name, sz, af_to_name(family) ?: "unknown");
                        continue;
                }

                if (ifindex < 0) {
                        log_error("%s: systemd-resolved returned invalid interface index %i",
                                  name, ifindex);
                        continue;
                }

                if (ifindex > 0) {
                        char *t;

                        t = if_indextoname(ifindex, ifname);
                        if (!t) {
                                log_error("Failed to resolve interface name for index %i", ifindex);
                                continue;
                        }
                }

                if (_ifindex > 0 && ifindex > 0 && ifindex != _ifindex) {
                        log_debug("%s: skipping entry with ifindex %i (%s)",
                                  name, ifindex, ifname);
                        continue;
                }

                r = in_addr_to_string(family, a, &pretty);
                if (r < 0) {
                        log_error("%s: failed to print address: %s", name, strerror(-r));
                        continue;
                }

                log_info("%*s%s %s%s%.*s",
                         (int) strlen(name), c == 0 ? name : "", c == 0 ? ":" : " ",
                         pretty,
                         *ifname ? "%" : "", (int) sizeof(ifname), *ifname ? ifname: "");

                c++;
        }

        if (c == 0) {
                log_error("%s: no addresses found", name);
                return -ENONET;
        }

        return sd_bus_message_exit_container(reply);
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Resolve IPv4 or IPv6 addresses.\n\n"
               "Options:\n"
               "  -4                       Resolve IPv4 addresses\n"
               "  -6                       Resolve IPv6 addresses\n"
               "  -i INTERFACE             Filter by interface\n"
               "  -h --help                Show this help and exit\n"
               "  --version                Print version string and exit\n"
               , program_invocation_short_name
               );
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'           },
                { "version",     no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h46i:", options, NULL)) >= 0)
                switch(c) {

                case 'h':
                        help();
                        return 0; /* done */;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case '4':
                        arg_family = AF_INET;
                        break;

                case '6':
                        arg_family = AF_INET6;
                        break;

                case 'i':
                        arg_ifindex = if_nametoindex(optarg);
                        if (arg_ifindex <= 0) {
                                log_error("Unknown interfaces %s: %m", optarg);
                                return -EINVAL;
                        }
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1 /* work to do */;
}


int main(int argc, char **argv) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto end;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_error("sd_bus_open_system: %s", strerror(-r));
                goto end;
        }

        while (argv[optind]) {
                int k;

                k = resolve_host(bus, argv[optind++], arg_family, arg_ifindex);
                if (r == 0)
                        r = k;
        }

 end:
        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
