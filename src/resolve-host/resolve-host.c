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

#include <getopt.h>
#include <net/if.h>

#include "sd-bus.h"

#include "af-list.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "in-addr-util.h"
#include "parse-util.h"
#include "resolved-def.h"
#include "resolved-dns-packet.h"

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

static int arg_family = AF_UNSPEC;
static int arg_ifindex = 0;
static int arg_type = 0;
static uint16_t arg_class = 0;
static bool arg_legend = true;
static uint64_t arg_flags = 0;

static void print_source(uint64_t flags, usec_t rtt) {
        char rtt_str[FORMAT_TIMESTAMP_MAX];

        if (!arg_legend)
                return;

        if (flags == 0)
                return;

        fputs("\n-- Information acquired via", stdout);

        if (flags != 0)
                printf(" protocol%s%s%s",
                       flags & SD_RESOLVED_DNS ? " DNS" :"",
                       flags & SD_RESOLVED_LLMNR_IPV4 ? " LLMNR/IPv4" : "",
                       flags & SD_RESOLVED_LLMNR_IPV6 ? " LLMNR/IPv6" : "");

        assert_se(format_timespan(rtt_str, sizeof(rtt_str), rtt, 100));

        printf(" in %s", rtt_str);

        fputc('.', stdout);
        fputc('\n', stdout);
}

static int resolve_host(sd_bus *bus, const char *name) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *canonical = NULL;
        char ifname[IF_NAMESIZE] = "";
        unsigned c = 0;
        int r;
        uint64_t flags;
        usec_t ts;

        assert(name);

        if (arg_ifindex > 0 && !if_indextoname(arg_ifindex, ifname))
                return log_error_errno(errno, "Failed to resolve interface name for index %i: %m", arg_ifindex);

        log_debug("Resolving %s (family %s, interface %s).", name, af_to_name(arg_family) ?: "*", isempty(ifname) ? "*" : ifname);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveHostname");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isit", arg_ifindex, name, arg_family, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                log_error("%s: resolve call failed: %s", name, bus_error_message(&error, r));
                return r;
        }

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                const void *a;
                size_t sz;
                _cleanup_free_ char *pretty = NULL;
                int ifindex, family;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_read(reply, "ii", &ifindex, &family);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (!IN_SET(family, AF_INET, AF_INET6)) {
                        log_debug("%s: skipping entry with family %d (%s)", name, family, af_to_name(family) ?: "unknown");
                        continue;
                }

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
                        log_error("%s: systemd-resolved returned address of invalid size %zu for family %s", name, sz, af_to_name(family) ?: "unknown");
                        continue;
                }

                ifname[0] = 0;
                if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                        log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                r = in_addr_to_string(family, a, &pretty);
                if (r < 0)
                        return log_error_errno(r, "Failed to print address for %s: %m", name);

                printf("%*s%s %s%s%s\n",
                       (int) strlen(name), c == 0 ? name : "", c == 0 ? ":" : " ",
                       pretty,
                       isempty(ifname) ? "" : "%", ifname);

                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "st", &canonical, &flags);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!streq(name, canonical))
                printf("%*s%s (%s)\n",
                       (int) strlen(name), c == 0 ? name : "", c == 0 ? ":" : " ",
                       canonical);

        if (c == 0) {
                log_error("%s: no addresses found", name);
                return -ESRCH;
        }

        print_source(flags, ts);

        return 0;
}

static int resolve_address(sd_bus *bus, int family, const union in_addr_union *address, int ifindex) {
        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *pretty = NULL;
        char ifname[IF_NAMESIZE] = "";
        uint64_t flags;
        unsigned c = 0;
        usec_t ts;
        int r;

        assert(bus);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        if (ifindex <= 0)
                ifindex = arg_ifindex;

        r = in_addr_to_string(family, address, &pretty);
        if (r < 0)
                return log_oom();

        if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                return log_error_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

        log_debug("Resolving %s%s%s.", pretty, isempty(ifname) ? "" : "%", ifname);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveAddress");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "ii", ifindex, family);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_array(req, 'y', address, FAMILY_ADDRESS_SIZE(family));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "t", arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                log_error("%s: resolve call failed: %s", pretty, bus_error_message(&error, r));
                return r;
        }

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(is)");
        if (r < 0)
                return bus_log_create_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "is")) > 0) {
                const char *n;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_read(reply, "is", &ifindex, &n);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return r;

                ifname[0] = 0;
                if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                        log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                printf("%*s%*s%*s%s %s\n",
                       (int) strlen(pretty), c == 0 ? pretty : "",
                       isempty(ifname) ? 0 : 1, c > 0 || isempty(ifname) ? "" : "%",
                       (int) strlen(ifname), c == 0 ? ifname : "",
                       c == 0 ? ":" : " ",
                       n);

                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "t", &flags);
        if (r < 0)
                return bus_log_parse_error(r);

        if (c == 0) {
                log_error("%s: no names found", pretty);
                return -ESRCH;
        }

        print_source(flags, ts);

        return 0;
}

static int parse_address(const char *s, int *family, union in_addr_union *address, int *ifindex) {
        const char *percent, *a;
        int ifi = 0;
        int r;

        percent = strchr(s, '%');
        if (percent) {
                if (parse_ifindex(percent+1, &ifi) < 0) {
                        ifi = if_nametoindex(percent+1);
                        if (ifi <= 0)
                                return -EINVAL;
                }

                a = strndupa(s, percent - s);
        } else
                a = s;

        r = in_addr_from_string_auto(a, family, address);
        if (r < 0)
                return r;

        *ifindex = ifi;
        return 0;
}

static int resolve_record(sd_bus *bus, const char *name) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char ifname[IF_NAMESIZE] = "";
        unsigned n = 0;
        uint64_t flags;
        int r;
        usec_t ts;

        assert(name);

        if (arg_ifindex > 0 && !if_indextoname(arg_ifindex, ifname))
                return log_error_errno(errno, "Failed to resolve interface name for index %i: %m", arg_ifindex);

        log_debug("Resolving %s %s %s (interface %s).", name, dns_class_to_string(arg_class), dns_type_to_string(arg_type), isempty(ifname) ? "*" : ifname);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveRecord");
        if (r < 0)
                return bus_log_create_error(r);

        assert((uint16_t) arg_type == arg_type);
        r = sd_bus_message_append(req, "isqqt", arg_ifindex, name, arg_class, arg_type, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                log_error("%s: resolve call failed: %s", name, bus_error_message(&error, r));
                return r;
        }

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(iqqay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "iqqay")) > 0) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
                _cleanup_free_ char *s = NULL;
                uint16_t c, t;
                int ifindex;
                const void *d;
                size_t l;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_read(reply, "iqq", &ifindex, &c, &t);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &d, &l);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0);
                if (r < 0)
                        return log_oom();

                p->refuse_compression = true;

                r = dns_packet_append_blob(p, d, l, NULL);
                if (r < 0)
                        return log_oom();

                r = dns_packet_read_rr(p, &rr, NULL);
                if (r < 0) {
                        log_error("Failed to parse RR.");
                        return r;
                }

                r = dns_resource_record_to_string(rr, &s);
                if (r < 0) {
                        log_error("Failed to format RR.");
                        return r;
                }

                ifname[0] = 0;
                if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                        log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                printf("%s%s%s\n", s, isempty(ifname) ? "" : " # interface ", ifname);
                n++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "t", &flags);
        if (r < 0)
                return bus_log_parse_error(r);

        if (n == 0) {
                log_error("%s: no records found", name);
                return -ESRCH;
        }

        print_source(flags, ts);

        return 0;
}

static void help_dns_types(void) {
        int i;
        const char *t;

        if (arg_legend)
                puts("Known DNS RR types:");
        for (i = 0; i < _DNS_TYPE_MAX; i++) {
                t = dns_type_to_string(i);
                if (t)
                        puts(t);
        }
}

static void help_dns_classes(void) {
        int i;
        const char *t;

        if (arg_legend)
                puts("Known DNS RR classes:");
        for (i = 0; i < _DNS_CLASS_MAX; i++) {
                t = dns_class_to_string(i);
                if (t)
                        puts(t);
        }
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Resolve IPv4 or IPv6 addresses.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "  -4                      Resolve IPv4 addresses\n"
               "  -6                      Resolve IPv6 addresses\n"
               "  -i INTERFACE            Look on interface\n"
               "  -p --protocol=PROTOCOL  Look via protocol\n"
               "  -t --type=TYPE          Query RR with DNS type\n"
               "  -c --class=CLASS        Query RR with DNS class\n"
               "     --legend[=BOOL]      Do [not] print column headers\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_LEGEND,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "type",      required_argument, NULL, 't'           },
                { "class",     required_argument, NULL, 'c'           },
                { "legend",    optional_argument, NULL, ARG_LEGEND    },
                { "protocol",  required_argument, NULL, 'p'           },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h46i:t:c:p:", options, NULL)) >= 0)
                switch(c) {

                case 'h':
                        help();
                        return 0; /* done */;

                case ARG_VERSION:
                        return version();

                case '4':
                        arg_family = AF_INET;
                        break;

                case '6':
                        arg_family = AF_INET6;
                        break;

                case 'i': {
                        int ifi;

                        if (parse_ifindex(optarg, &ifi) >= 0)
                                arg_ifindex = ifi;
                        else {
                                ifi = if_nametoindex(optarg);
                                if (ifi <= 0)
                                        return log_error_errno(errno, "Unknown interface %s: %m", optarg);

                                arg_ifindex = ifi;
                        }

                        break;
                }

                case 't':
                        if (streq(optarg, "help")) {
                                help_dns_types();
                                return 0;
                        }

                        arg_type = dns_type_from_string(optarg);
                        if (arg_type < 0) {
                                log_error("Failed to parse RR record type %s", optarg);
                                return arg_type;
                        }
                        assert(arg_type > 0 && (uint16_t) arg_type == arg_type);

                        break;

                case 'c':
                        if (streq(optarg, "help")) {
                                help_dns_classes();
                                return 0;
                        }

                        r = dns_class_from_string(optarg, &arg_class);
                        if (r < 0) {
                                log_error("Failed to parse RR record class %s", optarg);
                                return r;
                        }

                        break;

                case ARG_LEGEND:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse --legend= argument");
                                        return r;
                                }

                                arg_legend = !!r;
                        } else
                                arg_legend = false;
                        break;

                case 'p':
                        if (streq(optarg, "dns"))
                                arg_flags |= SD_RESOLVED_DNS;
                        else if (streq(optarg, "llmnr"))
                                arg_flags |= SD_RESOLVED_LLMNR;
                        else if (streq(optarg, "llmnr-ipv4"))
                                arg_flags |= SD_RESOLVED_LLMNR_IPV4;
                        else if (streq(optarg, "llmnr-ipv6"))
                                arg_flags |= SD_RESOLVED_LLMNR_IPV6;
                        else {
                                log_error("Unknown protocol specifier: %s", optarg);
                                return -EINVAL;
                        }

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_type == 0 && arg_class != 0) {
                log_error("--class= may only be used in conjunction with --type=");
                return -EINVAL;
        }

        if (arg_type != 0 && arg_class == 0)
                arg_class = DNS_CLASS_IN;

        return 1 /* work to do */;
}

int main(int argc, char **argv) {
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (optind >= argc) {
                log_error("No arguments passed");
                r = -EINVAL;
                goto finish;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_error_errno(r, "sd_bus_open_system: %m");
                goto finish;
        }

        while (argv[optind]) {
                int family, ifindex, k;
                union in_addr_union a;

                if (arg_type != 0)
                        k = resolve_record(bus, argv[optind]);
                else {
                        k = parse_address(argv[optind], &family, &a, &ifindex);
                        if (k >= 0)
                                k = resolve_address(bus, family, &a, ifindex);
                        else
                                k = resolve_host(bus, argv[optind]);
                }

                if (r == 0)
                        r = k;

                optind++;
        }

finish:
        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
