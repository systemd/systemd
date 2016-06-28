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
#include "sd-netlink.h"

#include "af-list.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "escape.h"
#include "gcrypt-util.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "pager.h"
#include "parse-util.h"
#include "resolved-def.h"
#include "resolved-dns-packet.h"
#include "strv.h"
#include "terminal-util.h"

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

static int arg_family = AF_UNSPEC;
static int arg_ifindex = 0;
static uint16_t arg_type = 0;
static uint16_t arg_class = 0;
static bool arg_legend = true;
static uint64_t arg_flags = 0;
static bool arg_no_pager = false;

typedef enum ServiceFamily {
        SERVICE_FAMILY_TCP,
        SERVICE_FAMILY_UDP,
        SERVICE_FAMILY_SCTP,
        _SERVICE_FAMILY_INVALID = -1,
} ServiceFamily;
static ServiceFamily arg_service_family = SERVICE_FAMILY_TCP;

typedef enum RawType {
        RAW_NONE,
        RAW_PAYLOAD,
        RAW_PACKET,
} RawType;
static RawType arg_raw = RAW_NONE;

static enum {
        MODE_RESOLVE_HOST,
        MODE_RESOLVE_RECORD,
        MODE_RESOLVE_SERVICE,
        MODE_RESOLVE_OPENPGP,
        MODE_RESOLVE_TLSA,
        MODE_STATISTICS,
        MODE_RESET_STATISTICS,
        MODE_FLUSH_CACHES,
        MODE_STATUS,
} arg_mode = MODE_RESOLVE_HOST;

static ServiceFamily service_family_from_string(const char *s) {
        if (s == NULL || streq(s, "tcp"))
                return SERVICE_FAMILY_TCP;
        if (streq(s, "udp"))
                return SERVICE_FAMILY_UDP;
        if (streq(s, "sctp"))
                return SERVICE_FAMILY_SCTP;
        return _SERVICE_FAMILY_INVALID;
}

static const char* service_family_to_string(ServiceFamily service) {
        switch(service) {
        case SERVICE_FAMILY_TCP:
                return "_tcp";
        case SERVICE_FAMILY_UDP:
                return "_udp";
        case SERVICE_FAMILY_SCTP:
                return "_sctp";
        default:
                assert_not_reached("invalid service");
        }
}

static void print_source(uint64_t flags, usec_t rtt) {
        char rtt_str[FORMAT_TIMESTAMP_MAX];

        if (!arg_legend)
                return;

        if (flags == 0)
                return;

        fputs("\n-- Information acquired via", stdout);

        if (flags != 0)
                printf(" protocol%s%s%s%s%s",
                       flags & SD_RESOLVED_DNS ? " DNS" :"",
                       flags & SD_RESOLVED_LLMNR_IPV4 ? " LLMNR/IPv4" : "",
                       flags & SD_RESOLVED_LLMNR_IPV6 ? " LLMNR/IPv6" : "",
                       flags & SD_RESOLVED_MDNS_IPV4 ? "mDNS/IPv4" : "",
                       flags & SD_RESOLVED_MDNS_IPV6 ? "mDNS/IPv6" : "");

        assert_se(format_timespan(rtt_str, sizeof(rtt_str), rtt, 100));

        printf(" in %s", rtt_str);

        fputc('.', stdout);
        fputc('\n', stdout);

        printf("-- Data is authenticated: %s\n", yes_no(flags & SD_RESOLVED_AUTHENTICATED));
}

static int resolve_host(sd_bus *bus, const char *name) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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
        if (r < 0)
                return log_error_errno(r, "%s: resolve call failed: %s", name, bus_error_message(&error, r));

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                _cleanup_free_ char *pretty = NULL;
                int ifindex, family;
                const void *a;
                size_t sz;

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
                        return -EINVAL;
                }

                ifname[0] = 0;
                if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                        log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                r = in_addr_ifindex_to_string(family, a, ifindex, &pretty);
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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

        r = in_addr_ifindex_to_string(family, address, ifindex, &pretty);
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

static int output_rr_packet(const void *d, size_t l, int ifindex) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;
        char ifname[IF_NAMESIZE] = "";

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0);
        if (r < 0)
                return log_oom();

        p->refuse_compression = true;

        r = dns_packet_append_blob(p, d, l, NULL);
        if (r < 0)
                return log_oom();

        r = dns_packet_read_rr(p, &rr, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse RR: %m");

        if (arg_raw == RAW_PAYLOAD) {
                void *data;
                ssize_t k;

                k = dns_resource_record_payload(rr, &data);
                if (k < 0)
                        return log_error_errno(k, "Cannot dump RR: %m");
                fwrite(data, 1, k, stdout);
        } else {
                const char *s;

                s = dns_resource_record_to_string(rr);
                if (!s)
                        return log_oom();

                if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                        log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                printf("%s%s%s\n", s, isempty(ifname) ? "" : " # interface ", ifname);
        }

        return 0;
}

static int resolve_record(sd_bus *bus, const char *name, uint16_t class, uint16_t type) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char ifname[IF_NAMESIZE] = "";
        unsigned n = 0;
        uint64_t flags;
        int r;
        usec_t ts;
        bool needs_authentication = false;

        assert(name);

        if (arg_ifindex > 0 && !if_indextoname(arg_ifindex, ifname))
                return log_error_errno(errno, "Failed to resolve interface name for index %i: %m", arg_ifindex);

        log_debug("Resolving %s %s %s (interface %s).", name, dns_class_to_string(class), dns_type_to_string(type), isempty(ifname) ? "*" : ifname);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveRecord");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isqqt", arg_ifindex, name, class, type, arg_flags);
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

                if (arg_raw == RAW_PACKET) {
                        uint64_t u64 = htole64(l);

                        fwrite(&u64, sizeof(u64), 1, stdout);
                        fwrite(d, 1, l, stdout);
                } else {
                        r = output_rr_packet(d, l, ifindex);
                        if (r < 0)
                                return r;
                }

                if (dns_type_needs_authentication(t))
                        needs_authentication = true;

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

        if ((flags & SD_RESOLVED_AUTHENTICATED) == 0 && needs_authentication) {
                fflush(stdout);

                fprintf(stderr, "\n%s"
                       "WARNING: The resources shown contain cryptographic key data which could not be\n"
                       "         authenticated. It is not suitable to authenticate any communication.\n"
                       "         This is usually indication that DNSSEC authentication was not enabled\n"
                       "         or is not available for the selected protocol or DNS servers.%s\n",
                       ansi_highlight_red(),
                       ansi_normal());
        }

        return 0;
}

static int resolve_rfc4501(sd_bus *bus, const char *name) {
        uint16_t type = 0, class = 0;
        const char *p, *q, *n;
        int r;

        assert(bus);
        assert(name);
        assert(startswith(name, "dns:"));

        /* Parse RFC 4501 dns: URIs */

        p = name + 4;

        if (p[0] == '/') {
                const char *e;

                if (p[1] != '/')
                        goto invalid;

                e = strchr(p + 2, '/');
                if (!e)
                        goto invalid;

                if (e != p + 2)
                        log_warning("DNS authority specification not supported; ignoring specified authority.");

                p = e + 1;
        }

        q = strchr(p, '?');
        if (q) {
                n = strndupa(p, q - p);
                q++;

                for (;;) {
                        const char *f;

                        f = startswith_no_case(q, "class=");
                        if (f) {
                                _cleanup_free_ char *t = NULL;
                                const char *e;

                                if (class != 0) {
                                        log_error("DNS class specified twice.");
                                        return -EINVAL;
                                }

                                e = strchrnul(f, ';');
                                t = strndup(f, e - f);
                                if (!t)
                                        return log_oom();

                                r = dns_class_from_string(t);
                                if (r < 0) {
                                        log_error("Unknown DNS class %s.", t);
                                        return -EINVAL;
                                }

                                class = r;

                                if (*e == ';') {
                                        q = e + 1;
                                        continue;
                                }

                                break;
                        }

                        f = startswith_no_case(q, "type=");
                        if (f) {
                                _cleanup_free_ char *t = NULL;
                                const char *e;

                                if (type != 0) {
                                        log_error("DNS type specified twice.");
                                        return -EINVAL;
                                }

                                e = strchrnul(f, ';');
                                t = strndup(f, e - f);
                                if (!t)
                                        return log_oom();

                                r = dns_type_from_string(t);
                                if (r < 0) {
                                        log_error("Unknown DNS type %s.", t);
                                        return -EINVAL;
                                }

                                type = r;

                                if (*e == ';') {
                                        q = e + 1;
                                        continue;
                                }

                                break;
                        }

                        goto invalid;
                }
        } else
                n = p;

        if (class == 0)
                class = arg_class ?: DNS_CLASS_IN;
        if (type == 0)
                type = arg_type ?: DNS_TYPE_A;

        return resolve_record(bus, n, class, type);

invalid:
        log_error("Invalid DNS URI: %s", name);
        return -EINVAL;
}

static int resolve_service(sd_bus *bus, const char *name, const char *type, const char *domain) {
        const char *canonical_name, *canonical_type, *canonical_domain;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char ifname[IF_NAMESIZE] = "";
        size_t indent, sz;
        uint64_t flags;
        const char *p;
        unsigned c;
        usec_t ts;
        int r;

        assert(bus);
        assert(domain);

        name = empty_to_null(name);
        type = empty_to_null(type);

        if (arg_ifindex > 0 && !if_indextoname(arg_ifindex, ifname))
                return log_error_errno(errno, "Failed to resolve interface name for index %i: %m", arg_ifindex);

        if (name)
                log_debug("Resolving service \"%s\" of type %s in %s (family %s, interface %s).", name, type, domain, af_to_name(arg_family) ?: "*", isempty(ifname) ? "*" : ifname);
        else if (type)
                log_debug("Resolving service type %s of %s (family %s, interface %s).", type, domain, af_to_name(arg_family) ?: "*", isempty(ifname) ? "*" : ifname);
        else
                log_debug("Resolving service type %s (family %s, interface %s).", domain, af_to_name(arg_family) ?: "*", isempty(ifname) ? "*" : ifname);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveService");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isssit", arg_ifindex, name, type, domain, arg_family, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Resolve call failed: %s", bus_error_message(&error, r));

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(qqqsa(iiay)s)");
        if (r < 0)
                return bus_log_parse_error(r);

        indent =
                (name ? strlen(name) + 1 : 0) +
                (type ? strlen(type) + 1 : 0) +
                strlen(domain) + 2;

        c = 0;
        while ((r = sd_bus_message_enter_container(reply, 'r', "qqqsa(iiay)s")) > 0) {
                uint16_t priority, weight, port;
                const char *hostname, *canonical;

                r = sd_bus_message_read(reply, "qqqs", &priority, &weight, &port, &hostname);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (name)
                        printf("%*s%s", (int) strlen(name), c == 0 ? name : "", c == 0 ? "/" : " ");
                if (type)
                        printf("%*s%s", (int) strlen(type), c == 0 ? type : "", c == 0 ? "/" : " ");

                printf("%*s%s %s:%u [priority=%u, weight=%u]\n",
                       (int) strlen(domain), c == 0 ? domain : "",
                       c == 0 ? ":" : " ",
                       hostname, port,
                       priority, weight);

                r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
                if (r < 0)
                        return bus_log_parse_error(r);

                while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                        _cleanup_free_ char *pretty = NULL;
                        int ifindex, family;
                        const void *a;

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
                                return -EINVAL;
                        }

                        ifname[0] = 0;
                        if (ifindex > 0 && !if_indextoname(ifindex, ifname))
                                log_warning_errno(errno, "Failed to resolve interface name for index %i: %m", ifindex);

                        r = in_addr_to_string(family, a, &pretty);
                        if (r < 0)
                                return log_error_errno(r, "Failed to print address for %s: %m", name);

                        printf("%*s%s%s%s\n", (int) indent, "", pretty, isempty(ifname) ? "" : "%s", ifname);
                }
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read(reply, "s", &canonical);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (!streq(hostname, canonical))
                        printf("%*s(%s)\n", (int) indent, "", canonical);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(reply, 'a', "ay");
        if (r < 0)
                return bus_log_parse_error(r);

        c = 0;
        while ((r = sd_bus_message_read_array(reply, 'y', (const void**) &p, &sz)) > 0) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape_length(p, sz);
                if (!escaped)
                        return log_oom();

                printf("%*s%s\n", (int) indent, "", escaped);
                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "ssst", &canonical_name, &canonical_type, &canonical_domain, &flags);
        if (r < 0)
                return bus_log_parse_error(r);

        canonical_name = empty_to_null(canonical_name);
        canonical_type = empty_to_null(canonical_type);

        if (!streq_ptr(name, canonical_name) ||
            !streq_ptr(type, canonical_type) ||
            !streq_ptr(domain, canonical_domain)) {

                printf("%*s(", (int) indent, "");

                if (canonical_name)
                        printf("%s/", canonical_name);
                if (canonical_type)
                        printf("%s/", canonical_type);

                printf("%s)\n", canonical_domain);
        }

        print_source(flags, ts);

        return 0;
}

static int resolve_openpgp(sd_bus *bus, const char *address) {
        const char *domain, *full;
        int r;
        _cleanup_free_ char *hashed = NULL;

        assert(bus);
        assert(address);

        domain = strrchr(address, '@');
        if (!domain) {
                log_error("Address does not contain '@': \"%s\"", address);
                return -EINVAL;
        } else if (domain == address || domain[1] == '\0') {
                log_error("Address starts or ends with '@': \"%s\"", address);
                return -EINVAL;
        }
        domain++;

        r = string_hashsum_sha224(address, domain - 1 - address, &hashed);
        if (r < 0)
                return log_error_errno(r, "Hashing failed: %m");

        full = strjoina(hashed, "._openpgpkey.", domain);
        log_debug("Looking up \"%s\".", full);

        return resolve_record(bus, full,
                              arg_class ?: DNS_CLASS_IN,
                              arg_type ?: DNS_TYPE_OPENPGPKEY);
}

static int resolve_tlsa(sd_bus *bus, const char *address) {
        const char *port;
        uint16_t port_num = 443;
        _cleanup_free_ char *full = NULL;
        int r;

        assert(bus);
        assert(address);

        port = strrchr(address, ':');
        if (port) {
                r = safe_atou16(port + 1, &port_num);
                if (r < 0 || port_num == 0)
                        return log_error_errno(r, "Invalid port \"%s\".", port + 1);

                address = strndupa(address, port - address);
        }

        r = asprintf(&full, "_%u.%s.%s",
                     port_num,
                     service_family_to_string(arg_service_family),
                     address);
        if (r < 0)
                return log_oom();

        log_debug("Looking up \"%s\".", full);

        return resolve_record(bus, full,
                              arg_class ?: DNS_CLASS_IN,
                              arg_type ?: DNS_TYPE_TLSA);
}

static int show_statistics(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        uint64_t n_current_transactions, n_total_transactions,
                cache_size, n_cache_hit, n_cache_miss,
                n_dnssec_secure, n_dnssec_insecure, n_dnssec_bogus, n_dnssec_indeterminate;
        int r, dnssec_supported;

        assert(bus);

        r = sd_bus_get_property_trivial(bus,
                                        "org.freedesktop.resolve1",
                                        "/org/freedesktop/resolve1",
                                        "org.freedesktop.resolve1.Manager",
                                        "DNSSECSupported",
                                        &error,
                                        'b',
                                        &dnssec_supported);
        if (r < 0)
                return log_error_errno(r, "Failed to get DNSSEC supported state: %s", bus_error_message(&error, r));

        printf("DNSSEC supported by current servers: %s%s%s\n\n",
               ansi_highlight(),
               yes_no(dnssec_supported),
               ansi_normal());

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                "TransactionStatistics",
                                &error,
                                &reply,
                                "(tt)");
        if (r < 0)
                return log_error_errno(r, "Failed to get transaction statistics: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "(tt)",
                                &n_current_transactions,
                                &n_total_transactions);
        if (r < 0)
                return bus_log_parse_error(r);

        printf("%sTransactions%s\n"
               "Current Transactions: %" PRIu64 "\n"
               "  Total Transactions: %" PRIu64 "\n",
               ansi_highlight(),
               ansi_normal(),
               n_current_transactions,
               n_total_transactions);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                "CacheStatistics",
                                &error,
                                &reply,
                                "(ttt)");
        if (r < 0)
                return log_error_errno(r, "Failed to get cache statistics: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "(ttt)",
                                &cache_size,
                                &n_cache_hit,
                                &n_cache_miss);
        if (r < 0)
                return bus_log_parse_error(r);

        printf("\n%sCache%s\n"
               "  Current Cache Size: %" PRIu64 "\n"
               "          Cache Hits: %" PRIu64 "\n"
               "        Cache Misses: %" PRIu64 "\n",
               ansi_highlight(),
               ansi_normal(),
               cache_size,
               n_cache_hit,
               n_cache_miss);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                "DNSSECStatistics",
                                &error,
                                &reply,
                                "(tttt)");
        if (r < 0)
                return log_error_errno(r, "Failed to get DNSSEC statistics: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "(tttt)",
                                &n_dnssec_secure,
                                &n_dnssec_insecure,
                                &n_dnssec_bogus,
                                &n_dnssec_indeterminate);
        if (r < 0)
                return bus_log_parse_error(r);

        printf("\n%sDNSSEC Verdicts%s\n"
               "              Secure: %" PRIu64 "\n"
               "            Insecure: %" PRIu64 "\n"
               "               Bogus: %" PRIu64 "\n"
               "       Indeterminate: %" PRIu64 "\n",
               ansi_highlight(),
               ansi_normal(),
               n_dnssec_secure,
               n_dnssec_insecure,
               n_dnssec_bogus,
               n_dnssec_indeterminate);

        return 0;
}

static int reset_statistics(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.resolve1",
                               "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager",
                               "ResetStatistics",
                               &error,
                               NULL,
                               NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reset statistics: %s", bus_error_message(&error, r));

        return 0;
}

static int flush_caches(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.resolve1",
                               "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager",
                               "FlushCaches",
                               &error,
                               NULL,
                               NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to flush caches: %s", bus_error_message(&error, r));

        return 0;
}

static int map_link_dns_servers(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = userdata;
        int r;

        assert(bus);
        assert(member);
        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "(iay)");
        if (r < 0)
                return r;

        for (;;) {
                const void *a;
                char *pretty;
                int family;
                size_t sz;

                r = sd_bus_message_enter_container(m, 'r', "iay");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(m, "i", &family);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_array(m, 'y', &a, &sz);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                if (!IN_SET(family, AF_INET, AF_INET6)) {
                        log_debug("Unexpected family, ignoring.");
                        continue;
                }

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
                        log_debug("Address size mismatch, ignoring.");
                        continue;
                }

                r = in_addr_to_string(family, a, &pretty);
                if (r < 0)
                        return r;

                r = strv_consume(l, pretty);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_link_domains(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = userdata;
        int r;

        assert(bus);
        assert(member);
        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "(sb)");
        if (r < 0)
                return r;

        for (;;) {
                const char *domain;
                int route_only;
                char *pretty;

                r = sd_bus_message_read(m, "(sb)", &domain, &route_only);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (route_only)
                        pretty = strappend("~", domain);
                else
                        pretty = strdup(domain);
                if (!pretty)
                        return -ENOMEM;

                r = strv_consume(l, pretty);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int status_ifindex(sd_bus *bus, int ifindex, const char *name, bool *empty_line) {

        struct link_info {
                uint64_t scopes_mask;
                char *llmnr;
                char *mdns;
                char *dnssec;
                char **dns;
                char **domains;
                char **ntas;
                int dnssec_supported;
        } link_info = {};

        static const struct bus_properties_map property_map[] = {
                { "ScopesMask",                 "t",      NULL,                 offsetof(struct link_info, scopes_mask)      },
                { "DNS",                        "a(iay)", map_link_dns_servers, offsetof(struct link_info, dns)              },
                { "Domains",                    "a(sb)",  map_link_domains,     offsetof(struct link_info, domains)          },
                { "LLMNR",                      "s",      NULL,                 offsetof(struct link_info, llmnr)            },
                { "MulticastDNS",               "s",      NULL,                 offsetof(struct link_info, mdns)             },
                { "DNSSEC",                     "s",      NULL,                 offsetof(struct link_info, dnssec)           },
                { "DNSSECNegativeTrustAnchors", "as",     NULL,                 offsetof(struct link_info, ntas)             },
                { "DNSSECSupported",            "b",      NULL,                 offsetof(struct link_info, dnssec_supported) },
                {}
        };

        _cleanup_free_ char *ifi = NULL, *p = NULL;
        char ifname[IF_NAMESIZE] = "";
        char **i;
        int r;

        assert(bus);
        assert(ifindex > 0);
        assert(empty_line);

        if (!name) {
                if (!if_indextoname(ifindex, ifname))
                        return log_error_errno(errno, "Failed to resolve interface name for %i: %m", ifindex);

                name = ifname;
        }

        if (asprintf(&ifi, "%i", ifindex) < 0)
                return log_oom();

        r = sd_bus_path_encode("/org/freedesktop/resolve1/link", ifi, &p);
        if (r < 0)
                return log_oom();

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.resolve1",
                                   p,
                                   property_map,
                                   &link_info);
        if (r < 0) {
                log_error_errno(r, "Failed to get link data for %i: %m", ifindex);
                goto finish;
        }

        pager_open(arg_no_pager, false);

        if (*empty_line)
                fputc('\n', stdout);

        printf("%sLink %i (%s)%s\n",
               ansi_highlight(), ifindex, name, ansi_normal());

        if (link_info.scopes_mask == 0)
                printf("      Current Scopes: none\n");
        else
                printf("      Current Scopes:%s%s%s%s%s\n",
                       link_info.scopes_mask & SD_RESOLVED_DNS ? " DNS" : "",
                       link_info.scopes_mask & SD_RESOLVED_LLMNR_IPV4 ? " LLMNR/IPv4" : "",
                       link_info.scopes_mask & SD_RESOLVED_LLMNR_IPV6 ? " LLMNR/IPv6" : "",
                       link_info.scopes_mask & SD_RESOLVED_MDNS_IPV4 ? " mDNS/IPv4" : "",
                       link_info.scopes_mask & SD_RESOLVED_MDNS_IPV6 ? " mDNS/IPv6" : "");

        printf("       LLMNR setting: %s\n"
               "MulticastDNS setting: %s\n"
               "      DNSSEC setting: %s\n"
               "    DNSSEC supported: %s\n",
               strna(link_info.llmnr),
               strna(link_info.mdns),
               strna(link_info.dnssec),
               yes_no(link_info.dnssec_supported));

        STRV_FOREACH(i, link_info.dns) {
                printf("         %s %s\n",
                       i == link_info.dns ? "DNS Servers:" : "            ",
                       *i);
        }

        STRV_FOREACH(i, link_info.domains) {
                printf("          %s %s\n",
                       i == link_info.domains ? "DNS Domain:" : "           ",
                       *i);
        }

        STRV_FOREACH(i, link_info.ntas) {
                printf("          %s %s\n",
                       i == link_info.ntas ? "DNSSEC NTA:" : "           ",
                       *i);
        }

        *empty_line = true;

        r = 0;

finish:
        strv_free(link_info.dns);
        strv_free(link_info.domains);
        free(link_info.llmnr);
        free(link_info.mdns);
        free(link_info.dnssec);
        strv_free(link_info.ntas);
        return r;
}

static int map_global_dns_servers(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = userdata;
        int r;

        assert(bus);
        assert(member);
        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "(iiay)");
        if (r < 0)
                return r;

        for (;;) {
                const void *a;
                char *pretty;
                int family, ifindex;
                size_t sz;

                r = sd_bus_message_enter_container(m, 'r', "iiay");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(m, "ii", &ifindex, &family);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_array(m, 'y', &a, &sz);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                if (ifindex != 0) /* only show the global ones here */
                        continue;

                if (!IN_SET(family, AF_INET, AF_INET6)) {
                        log_debug("Unexpected family, ignoring.");
                        continue;
                }

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
                        log_debug("Address size mismatch, ignoring.");
                        continue;
                }

                r = in_addr_to_string(family, a, &pretty);
                if (r < 0)
                        return r;

                r = strv_consume(l, pretty);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_global_domains(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = userdata;
        int r;

        assert(bus);
        assert(member);
        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "(isb)");
        if (r < 0)
                return r;

        for (;;) {
                const char *domain;
                int route_only, ifindex;
                char *pretty;

                r = sd_bus_message_read(m, "(isb)", &ifindex, &domain, &route_only);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (ifindex != 0) /* only show the global ones here */
                        continue;

                if (route_only)
                        pretty = strappend("~", domain);
                else
                        pretty = strdup(domain);
                if (!pretty)
                        return -ENOMEM;

                r = strv_consume(l, pretty);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int status_global(sd_bus *bus, bool *empty_line) {

        struct global_info {
                char **dns;
                char **domains;
                char **ntas;
        } global_info = {};

        static const struct bus_properties_map property_map[] = {
                { "DNS",                        "a(iiay)", map_global_dns_servers, offsetof(struct global_info, dns)     },
                { "Domains",                    "a(isb)",  map_global_domains,     offsetof(struct global_info, domains) },
                { "DNSSECNegativeTrustAnchors", "as",      NULL,                   offsetof(struct global_info, ntas)    },
                {}
        };

        char **i;
        int r;

        assert(bus);
        assert(empty_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.resolve1",
                                   "/org/freedesktop/resolve1",
                                   property_map,
                                   &global_info);
        if (r < 0) {
                log_error_errno(r, "Failed to get global data: %m");
                goto finish;
        }

        if (strv_isempty(global_info.dns) && strv_isempty(global_info.domains) && strv_isempty(global_info.ntas)) {
                r = 0;
                goto finish;
        }

        pager_open(arg_no_pager, false);

        printf("%sGlobal%s\n", ansi_highlight(), ansi_normal());
        STRV_FOREACH(i, global_info.dns) {
                printf("         %s %s\n",
                       i == global_info.dns ? "DNS Servers:" : "            ",
                       *i);
        }

        STRV_FOREACH(i, global_info.domains) {
                printf("          %s %s\n",
                       i == global_info.domains ? "DNS Domain:" : "           ",
                       *i);
        }

        strv_sort(global_info.ntas);
        STRV_FOREACH(i, global_info.ntas) {
                printf("          %s %s\n",
                       i == global_info.ntas ? "DNSSEC NTA:" : "           ",
                       *i);
        }

        *empty_line = true;

        r = 0;

finish:
        strv_free(global_info.dns);
        strv_free(global_info.domains);
        strv_free(global_info.ntas);

        return r;
}

static int status_all(sd_bus *bus) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        sd_netlink_message *i;
        bool empty_line = true;
        int r;

        assert(bus);

        r = status_global(bus, &empty_line);
        if (r < 0)
                return r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate links: %m");

        r = 0;
        for (i = reply; i; i = sd_netlink_message_next(i)) {
                const char *name;
                int ifindex, q;
                uint16_t type;

                q = sd_netlink_message_get_type(i, &type);
                if (q < 0)
                        return rtnl_log_parse_error(q);

                if (type != RTM_NEWLINK)
                        continue;

                q = sd_rtnl_message_link_get_ifindex(i, &ifindex);
                if (q < 0)
                        return rtnl_log_parse_error(q);

                if (ifindex == LOOPBACK_IFINDEX)
                        continue;

                q = sd_netlink_message_read_string(i, IFLA_IFNAME, &name);
                if (q < 0)
                        return rtnl_log_parse_error(q);

                q = status_ifindex(bus, ifindex, name, &empty_line);
                if (q < 0 && r >= 0)
                        r = q;
        }

        return r;
}

static void help_protocol_types(void) {
        if (arg_legend)
                puts("Known protocol types:");
        puts("dns\nllmnr\nllmnr-ipv4\nllmnr-ipv6");
}

static void help_dns_types(void) {
        const char *t;
        int i;

        if (arg_legend)
                puts("Known DNS RR types:");
        for (i = 0; i < _DNS_TYPE_MAX; i++) {
                t = dns_type_to_string(i);
                if (t)
                        puts(t);
        }
}

static void help_dns_classes(void) {
        const char *t;
        int i;

        if (arg_legend)
                puts("Known DNS RR classes:");
        for (i = 0; i < _DNS_CLASS_MAX; i++) {
                t = dns_class_to_string(i);
                if (t)
                        puts(t);
        }
}

static void help(void) {
        printf("%1$s [OPTIONS...] HOSTNAME|ADDRESS...\n"
               "%1$s [OPTIONS...] --service [[NAME] TYPE] DOMAIN\n"
               "%1$s [OPTIONS...] --openpgp EMAIL@DOMAIN...\n"
               "%1$s [OPTIONS...] --statistics\n"
               "%1$s [OPTIONS...] --reset-statistics\n"
               "\n"
               "Resolve domain names, IPv4 and IPv6 addresses, DNS resource records, and services.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --no-pager             Do not pipe output into a pager\n"
               "  -4                        Resolve IPv4 addresses\n"
               "  -6                        Resolve IPv6 addresses\n"
               "  -i --interface=INTERFACE  Look on interface\n"
               "  -p --protocol=PROTO|help  Look via protocol\n"
               "  -t --type=TYPE|help       Query RR with DNS type\n"
               "  -c --class=CLASS|help     Query RR with DNS class\n"
               "     --service              Resolve service (SRV)\n"
               "     --service-address=BOOL Resolve address for services (default: yes)\n"
               "     --service-txt=BOOL     Resolve TXT records for services (default: yes)\n"
               "     --openpgp              Query OpenPGP public key\n"
               "     --tlsa                 Query TLS public key\n"
               "     --cname=BOOL           Follow CNAME redirects (default: yes)\n"
               "     --search=BOOL          Use search domains for single-label names\n"
               "                                                              (default: yes)\n"
               "     --raw[=payload|packet] Dump the answer as binary data\n"
               "     --legend=BOOL          Print headers and additional info (default: yes)\n"
               "     --statistics           Show resolver statistics\n"
               "     --reset-statistics     Reset resolver statistics\n"
               "     --status               Show link and server status\n"
               "     --flush-caches         Flush all local DNS caches\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_LEGEND,
                ARG_SERVICE,
                ARG_CNAME,
                ARG_SERVICE_ADDRESS,
                ARG_SERVICE_TXT,
                ARG_OPENPGP,
                ARG_TLSA,
                ARG_RAW,
                ARG_SEARCH,
                ARG_STATISTICS,
                ARG_RESET_STATISTICS,
                ARG_STATUS,
                ARG_FLUSH_CACHES,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",             no_argument,       NULL, 'h'                  },
                { "version",          no_argument,       NULL, ARG_VERSION          },
                { "type",             required_argument, NULL, 't'                  },
                { "class",            required_argument, NULL, 'c'                  },
                { "legend",           required_argument, NULL, ARG_LEGEND           },
                { "interface",        required_argument, NULL, 'i'                  },
                { "protocol",         required_argument, NULL, 'p'                  },
                { "cname",            required_argument, NULL, ARG_CNAME            },
                { "service",          no_argument,       NULL, ARG_SERVICE          },
                { "service-address",  required_argument, NULL, ARG_SERVICE_ADDRESS  },
                { "service-txt",      required_argument, NULL, ARG_SERVICE_TXT      },
                { "openpgp",          no_argument,       NULL, ARG_OPENPGP          },
                { "tlsa",             optional_argument, NULL, ARG_TLSA             },
                { "raw",              optional_argument, NULL, ARG_RAW              },
                { "search",           required_argument, NULL, ARG_SEARCH           },
                { "statistics",       no_argument,       NULL, ARG_STATISTICS,      },
                { "reset-statistics", no_argument,       NULL, ARG_RESET_STATISTICS },
                { "status",           no_argument,       NULL, ARG_STATUS           },
                { "flush-caches",     no_argument,       NULL, ARG_FLUSH_CACHES     },
                { "no-pager",         no_argument,       NULL, ARG_NO_PAGER         },
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

                        r = dns_type_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse RR record type %s", optarg);
                                return r;
                        }
                        arg_type = (uint16_t) r;
                        assert((int) arg_type == r);

                        arg_mode = MODE_RESOLVE_RECORD;
                        break;

                case 'c':
                        if (streq(optarg, "help")) {
                                help_dns_classes();
                                return 0;
                        }

                        r = dns_class_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse RR record class %s", optarg);
                                return r;
                        }
                        arg_class = (uint16_t) r;
                        assert((int) arg_class == r);

                        break;

                case ARG_LEGEND:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --legend= argument");

                        arg_legend = r;
                        break;

                case 'p':
                        if (streq(optarg, "help")) {
                                help_protocol_types();
                                return 0;
                        } else if (streq(optarg, "dns"))
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

                case ARG_SERVICE:
                        arg_mode = MODE_RESOLVE_SERVICE;
                        break;

                case ARG_OPENPGP:
                        arg_mode = MODE_RESOLVE_OPENPGP;
                        break;

                case ARG_TLSA:
                        arg_mode = MODE_RESOLVE_TLSA;
                        arg_service_family = service_family_from_string(optarg);
                        if (arg_service_family < 0) {
                                log_error("Unknown service family \"%s\".", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_RAW:
                        if (on_tty()) {
                                log_error("Refusing to write binary data to tty.");
                                return -ENOTTY;
                        }

                        if (optarg == NULL || streq(optarg, "payload"))
                                arg_raw = RAW_PAYLOAD;
                        else if (streq(optarg, "packet"))
                                arg_raw = RAW_PACKET;
                        else {
                                log_error("Unknown --raw specifier \"%s\".", optarg);
                                return -EINVAL;
                        }

                        arg_legend = false;
                        break;

                case ARG_CNAME:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --cname= argument.");
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_CNAME, r == 0);
                        break;

                case ARG_SERVICE_ADDRESS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --service-address= argument.");
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_ADDRESS, r == 0);
                        break;

                case ARG_SERVICE_TXT:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --service-txt= argument.");
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_TXT, r == 0);
                        break;

                case ARG_SEARCH:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --search argument.");
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_SEARCH, r == 0);
                        break;

                case ARG_STATISTICS:
                        arg_mode = MODE_STATISTICS;
                        break;

                case ARG_RESET_STATISTICS:
                        arg_mode = MODE_RESET_STATISTICS;
                        break;

                case ARG_FLUSH_CACHES:
                        arg_mode = MODE_FLUSH_CACHES;
                        break;

                case ARG_STATUS:
                        arg_mode = MODE_STATUS;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_type == 0 && arg_class != 0) {
                log_error("--class= may only be used in conjunction with --type=.");
                return -EINVAL;
        }

        if (arg_type != 0 && arg_mode == MODE_RESOLVE_SERVICE) {
                log_error("--service and --type= may not be combined.");
                return -EINVAL;
        }

        if (arg_type != 0 && arg_class == 0)
                arg_class = DNS_CLASS_IN;

        if (arg_class != 0 && arg_type == 0)
                arg_type = DNS_TYPE_A;

        return 1 /* work to do */;
}

int main(int argc, char **argv) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_error_errno(r, "sd_bus_open_system: %m");
                goto finish;
        }

        switch (arg_mode) {

        case MODE_RESOLVE_HOST:
                if (optind >= argc) {
                        log_error("No arguments passed.");
                        r = -EINVAL;
                        goto finish;
                }

                while (argv[optind]) {
                        int family, ifindex, k;
                        union in_addr_union a;

                        if (startswith(argv[optind], "dns:"))
                                k = resolve_rfc4501(bus, argv[optind]);
                        else {
                                k = in_addr_ifindex_from_string_auto(argv[optind], &family, &a, &ifindex);
                                if (k >= 0)
                                        k = resolve_address(bus, family, &a, ifindex);
                                else
                                        k = resolve_host(bus, argv[optind]);
                        }

                        if (r == 0)
                                r = k;

                        optind++;
                }
                break;

        case MODE_RESOLVE_RECORD:
                if (optind >= argc) {
                        log_error("No arguments passed.");
                        r = -EINVAL;
                        goto finish;
                }

                while (argv[optind]) {
                        int k;

                        k = resolve_record(bus, argv[optind], arg_class, arg_type);
                        if (r == 0)
                                r = k;

                        optind++;
                }
                break;

        case MODE_RESOLVE_SERVICE:
                if (argc < optind + 1) {
                        log_error("Domain specification required.");
                        r = -EINVAL;
                        goto finish;

                } else if (argc == optind + 1)
                        r = resolve_service(bus, NULL, NULL, argv[optind]);
                else if (argc == optind + 2)
                        r = resolve_service(bus, NULL, argv[optind], argv[optind+1]);
                else if (argc == optind + 3)
                        r = resolve_service(bus, argv[optind], argv[optind+1], argv[optind+2]);
                else {
                        log_error("Too many arguments.");
                        r = -EINVAL;
                        goto finish;
                }

                break;

        case MODE_RESOLVE_OPENPGP:
                if (argc < optind + 1) {
                        log_error("E-mail address required.");
                        r = -EINVAL;
                        goto finish;

                }

                r = 0;
                while (optind < argc) {
                        int k;

                        k = resolve_openpgp(bus, argv[optind++]);
                        if (k < 0)
                                r = k;
                }
                break;

        case MODE_RESOLVE_TLSA:
                if (argc < optind + 1) {
                        log_error("Domain name required.");
                        r = -EINVAL;
                        goto finish;

                }

                r = 0;
                while (optind < argc) {
                        int k;

                        k = resolve_tlsa(bus, argv[optind++]);
                        if (k < 0)
                                r = k;
                }
                break;

        case MODE_STATISTICS:
                if (argc > optind) {
                        log_error("Too many arguments.");
                        r = -EINVAL;
                        goto finish;
                }

                r = show_statistics(bus);
                break;

        case MODE_RESET_STATISTICS:
                if (argc > optind) {
                        log_error("Too many arguments.");
                        r = -EINVAL;
                        goto finish;
                }

                r = reset_statistics(bus);
                break;

        case MODE_FLUSH_CACHES:
                if (argc > optind) {
                        log_error("Too many arguments.");
                        r = -EINVAL;
                        goto finish;
                }

                r = flush_caches(bus);
                break;

        case MODE_STATUS:

                if (argc > optind) {
                        char **ifname;
                        bool empty_line = false;

                        r = 0;
                        STRV_FOREACH(ifname, argv + optind) {
                                int ifindex, q;

                                q = parse_ifindex(argv[optind], &ifindex);
                                if (q < 0) {
                                        ifindex = if_nametoindex(argv[optind]);
                                        if (ifindex <= 0) {
                                                log_error_errno(errno, "Failed to resolve interface name: %s", argv[optind]);
                                                continue;
                                        }
                                }

                                q = status_ifindex(bus, ifindex, NULL, &empty_line);
                                if (q < 0 && r >= 0)
                                        r = q;
                        }
                } else
                        r = status_all(bus);

                break;
        }

finish:
        pager_close();

        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
