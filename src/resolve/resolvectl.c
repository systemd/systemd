/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <net/if.h>

#include "sd-bus.h"
#include "sd-json.h"
#include "sd-netlink.h"
#include "sd-varlink.h"

#include "af-list.h"
#include "alloc-util.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-message-util.h"
#include "dns-domain.h"
#include "errno-list.h"
#include "escape.h"
#include "format-ifname.h"
#include "format-table.h"
#include "gcrypt-util.h"
#include "hostname-util.h"
#include "json-util.h"
#include "main-func.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "openssl-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "resolvconf-compat.h"
#include "resolve-util.h"
#include "resolvectl.h"
#include "resolved-def.h"
#include "resolved-dns-packet.h"
#include "resolved-util.h"
#include "socket-netlink.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"
#include "varlink-util.h"
#include "verb-log-control.h"
#include "verbs.h"

static int arg_family = AF_UNSPEC;
static int arg_ifindex = 0;
static char *arg_ifname = NULL;
static uint16_t arg_type = 0;
static uint16_t arg_class = 0;
static bool arg_legend = true;
static uint64_t arg_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
bool arg_ifindex_permissive = false; /* If true, don't generate an error if the specified interface index doesn't exist */
static const char *arg_service_family = NULL;
static bool arg_ask_password = true;

typedef enum RawType {
        RAW_NONE,
        RAW_PAYLOAD,
        RAW_PACKET,
} RawType;
static RawType arg_raw = RAW_NONE;

/* Used by compat interfaces: systemd-resolve and resolvconf. */
ExecutionMode arg_mode = MODE_RESOLVE_HOST;
char **arg_set_dns = NULL;
char **arg_set_domain = NULL;
bool arg_disable_default_route = false;
static const char *arg_set_llmnr = NULL;
static const char *arg_set_mdns = NULL;
static const char *arg_set_dns_over_tls = NULL;
static const char *arg_set_dnssec = NULL;
static char **arg_set_nta = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_ifname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_set_dns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_set_domain, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_set_nta, strv_freep);

typedef enum StatusMode {
        STATUS_ALL,
        STATUS_DNS,
        STATUS_DOMAIN,
        STATUS_DEFAULT_ROUTE,
        STATUS_LLMNR,
        STATUS_MDNS,
        STATUS_PRIVATE,
        STATUS_DNSSEC,
        STATUS_NTA,
} StatusMode;

typedef struct InterfaceInfo {
        int index;
        const char *name;
} InterfaceInfo;

static int acquire_bus(sd_bus **ret) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "sd_bus_open_system: %m");

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        *ret = TAKE_PTR(bus);
        return 0;
}

static int interface_info_compare(const InterfaceInfo *a, const InterfaceInfo *b) {
        int r;

        r = CMP(a->index, b->index);
        if (r != 0)
                return r;

        return strcmp_ptr(a->name, b->name);
}

int ifname_mangle_full(const char *s, bool drop_protocol_specifier) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_strv_free_ char **found = NULL;
        int r;

        assert(s);

        if (drop_protocol_specifier) {
                _cleanup_free_ char *buf = NULL;
                int ifindex_longest_name = -ENODEV;

                /* When invoked as resolvconf, drop the protocol specifier(s) at the end. */

                buf = strdup(s);
                if (!buf)
                        return log_oom();

                for (;;) {
                        r = rtnl_resolve_interface(&rtnl, buf);
                        if (r > 0) {
                                if (ifindex_longest_name <= 0)
                                        ifindex_longest_name = r;

                                r = strv_extend(&found, buf);
                                if (r < 0)
                                        return log_oom();
                        }

                        char *dot = strrchr(buf, '.');
                        if (!dot)
                                break;

                        *dot = '\0';
                }

                unsigned n = strv_length(found);
                if (n > 1) {
                        _cleanup_free_ char *joined = NULL;

                        joined = strv_join(found, ", ");
                        log_warning("Found multiple interfaces (%s) matching with '%s'. Using '%s' (ifindex=%i).",
                                    strna(joined), s, found[0], ifindex_longest_name);

                } else if (n == 1) {
                        const char *proto;

                        proto = ASSERT_PTR(startswith(s, found[0]));
                        if (!isempty(proto))
                                log_info("Dropped protocol specifier '%s' from '%s'. Using '%s' (ifindex=%i).",
                                         proto, s, found[0], ifindex_longest_name);
                }

                r = ifindex_longest_name;
        } else
                r = rtnl_resolve_interface(&rtnl, s);
        if (r < 0) {
                if (ERRNO_IS_DEVICE_ABSENT(r) && arg_ifindex_permissive) {
                        log_debug_errno(r, "Interface '%s' not found, but -f specified, ignoring: %m", s);
                        return 0; /* done */
                }
                return log_error_errno(r, "Failed to resolve interface \"%s\": %m", s);
        }

        if (arg_ifindex > 0 && arg_ifindex != r)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified multiple different interfaces. Refusing.");

        arg_ifindex = r;
        return free_and_strdup_warn(&arg_ifname, found ? found[0] : s); /* found */
}

static void print_source(uint64_t flags, usec_t rtt) {
        if (!arg_legend)
                return;

        if (sd_json_format_enabled(arg_json_format_flags))
                return;

        if (flags == 0)
                return;

        printf("\n%s-- Information acquired via", ansi_grey());

        printf(" protocol%s%s%s%s%s",
               flags & SD_RESOLVED_DNS ? " DNS" :"",
               flags & SD_RESOLVED_LLMNR_IPV4 ? " LLMNR/IPv4" : "",
               flags & SD_RESOLVED_LLMNR_IPV6 ? " LLMNR/IPv6" : "",
               flags & SD_RESOLVED_MDNS_IPV4 ? " mDNS/IPv4" : "",
               flags & SD_RESOLVED_MDNS_IPV6 ? " mDNS/IPv6" : "");

        printf(" in %s.%s\n"
               "%s-- Data is authenticated: %s; Data was acquired via local or encrypted transport: %s%s\n",
               FORMAT_TIMESPAN(rtt, 100),
               ansi_normal(),
               ansi_grey(),
               yes_no(flags & SD_RESOLVED_AUTHENTICATED),
               yes_no(flags & SD_RESOLVED_CONFIDENTIAL),
               ansi_normal());

        if ((flags & (SD_RESOLVED_FROM_MASK|SD_RESOLVED_SYNTHETIC)) != 0)
                printf("%s-- Data from:%s%s%s%s%s%s\n",
                       ansi_grey(),
                       FLAGS_SET(flags, SD_RESOLVED_SYNTHETIC) ? " synthetic" : "",
                       FLAGS_SET(flags, SD_RESOLVED_FROM_CACHE) ? " cache" : "",
                       FLAGS_SET(flags, SD_RESOLVED_FROM_ZONE) ? " zone" : "",
                       FLAGS_SET(flags, SD_RESOLVED_FROM_TRUST_ANCHOR) ? " trust-anchor" : "",
                       FLAGS_SET(flags, SD_RESOLVED_FROM_NETWORK) ? " network" : "",
                       ansi_normal());
}

static void print_ifindex_comment(int printed_so_far, int ifindex) {
        char ifname[IF_NAMESIZE];
        int r;

        if (ifindex <= 0)
                return;

        r = format_ifname(ifindex, ifname);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to resolve interface name for index %i, ignoring: %m", ifindex);

        printf("%*s%s-- link: %s%s",
               60 > printed_so_far ? 60 - printed_so_far : 0, " ", /* Align comment to the 60th column */
               ansi_grey(), ifname, ansi_normal());
}

static int resolve_host_error(const char *name, int r, const sd_bus_error *error) {
        if (sd_bus_error_has_name(error, BUS_ERROR_DNS_NXDOMAIN))
                return log_error_errno(r, "%s: %s", name, bus_error_message(error, r));

        return log_error_errno(r, "%s: resolve call failed: %s", name, bus_error_message(error, r));
}

static int resolve_host(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *canonical = NULL;
        unsigned c = 0;
        uint64_t flags;
        usec_t ts;
        int r;

        assert(name);

        if (sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Use --json=pretty with --type=A or --type=AAAA to acquire address record information in JSON format.");

        log_debug("Resolving %s (family %s, interface %s).", name, af_to_name(arg_family) ?: "*", isempty(arg_ifname) ? "*" : arg_ifname);

        r = bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveHostname");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isit", arg_ifindex, name, arg_family, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0)
                return resolve_host_error(name, r, &error);

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                _cleanup_free_ char *pretty = NULL;
                int ifindex, family, k;
                union in_addr_union a;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0)
                        return bus_log_parse_error(r);

                sd_bus_error_free(&error);
                r = bus_message_read_in_addr_auto(reply, &error, &family, &a);
                if (r < 0 && !sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS))
                        return log_error_errno(r, "%s: systemd-resolved returned invalid result: %s", name, bus_error_message(&error, r));

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS)) {
                        log_debug_errno(r, "%s: systemd-resolved returned invalid result, ignoring: %s", name, bus_error_message(&error, r));
                        continue;
                }

                r = in_addr_ifindex_to_string(family, &a, ifindex, &pretty);
                if (r < 0)
                        return log_error_errno(r, "Failed to print address for %s: %m", name);

                k = printf("%*s%s %s%s%s",
                           (int) strlen(name), c == 0 ? name : "", c == 0 ? ":" : " ",
                           ansi_highlight(), pretty, ansi_normal());

                print_ifindex_comment(k, ifindex);
                fputc('\n', stdout);

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

        if (c == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "%s: no addresses found", name);

        print_source(flags, ts);

        return 0;
}

static int resolve_address(sd_bus *bus, int family, const union in_addr_union *address, int ifindex) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *pretty = NULL;
        uint64_t flags;
        unsigned c = 0;
        usec_t ts;
        int r;

        assert(bus);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        if (sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Use --json=pretty with --type= to acquire resource record information in JSON format.");

        if (ifindex <= 0)
                ifindex = arg_ifindex;

        r = in_addr_ifindex_to_string(family, address, ifindex, &pretty);
        if (r < 0)
                return log_oom();

        log_debug("Resolving %s.", pretty);

        r = bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveAddress");
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

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "%s: resolve call failed: %s", pretty, bus_error_message(&error, r));

        ts = now(CLOCK_MONOTONIC) - ts;

        r = sd_bus_message_enter_container(reply, 'a', "(is)");
        if (r < 0)
                return bus_log_create_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "is")) > 0) {
                const char *n;
                int k;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_read(reply, "is", &ifindex, &n);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return r;

                k = printf("%*s%s %s%s%s",
                           (int) strlen(pretty), c == 0 ? pretty : "",
                           c == 0 ? ":" : " ",
                           ansi_highlight(), n, ansi_normal());

                print_ifindex_comment(k, ifindex);
                fputc('\n', stdout);

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

        if (c == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "%s: no names found", pretty);

        print_source(flags, ts);

        return 0;
}

static int output_rr_packet(const void *d, size_t l, int ifindex) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;

        assert(d || l == 0);

        r = dns_resource_record_new_from_raw(&rr, d, l);
        if (r < 0)
                return log_error_errno(r, "Failed to parse RR: %m");

        if (sd_json_format_enabled(arg_json_format_flags)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
                r = dns_resource_record_to_json(rr, &j);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert RR to JSON: %m");

                if (!j)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "JSON formatting for records of type %s (%u) not available.", dns_type_to_string(rr->key->type), rr->key->type);

                r = sd_json_variant_dump(j, arg_json_format_flags, NULL, NULL);
                if (r < 0)
                        return r;

        } else if (arg_raw == RAW_PAYLOAD) {
                void *data;
                ssize_t k;

                k = dns_resource_record_payload(rr, &data);
                if (k < 0)
                        return log_error_errno(k, "Cannot dump RR: %m");
                fwrite(data, 1, k, stdout);
        } else {
                const char *s;
                int k;

                s = dns_resource_record_to_string(rr);
                if (!s)
                        return log_oom();

                k = printf("%s", s);
                print_ifindex_comment(k, ifindex);
                fputc('\n', stdout);
        }

        return 0;
}

static int idna_candidate(const char *name, char **ret) {
        _cleanup_free_ char *idnafied = NULL;
        int r;

        assert(name);
        assert(ret);

        r = dns_name_apply_idna(name, &idnafied);
        if (r < 0)
                return log_error_errno(r, "Failed to apply IDNA to name '%s': %m", name);
        if (r > 0 && !streq(name, idnafied)) {
                *ret = TAKE_PTR(idnafied);
                return true;
        }

        *ret = NULL;
        return false;
}

static bool single_label_nonsynthetic(const char *name) {
        _cleanup_free_ char *first_label = NULL;
        int r;

        if (!dns_name_is_single_label(name))
                return false;

        if (is_localhost(name) ||
            is_gateway_hostname(name) ||
            is_outbound_hostname(name) ||
            is_dns_stub_hostname(name) ||
            is_dns_proxy_stub_hostname(name))
                return false;

        r = resolve_system_hostname(NULL, &first_label);
        if (r < 0) {
                log_warning_errno(r, "Failed to determine the hostname: %m");
                return false;
        }

        return !streq(name, first_label);
}

static int resolve_record(sd_bus *bus, const char *name, uint16_t class, uint16_t type, bool warn_missing) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *idnafied = NULL;
        bool needs_authentication = false;
        unsigned n = 0;
        uint64_t flags;
        usec_t ts;
        int r;

        assert(name);

        log_debug("Resolving %s %s %s (interface %s).", name, dns_class_to_string(class), dns_type_to_string(type), isempty(arg_ifname) ? "*" : arg_ifname);

        if (dns_name_dot_suffixed(name) == 0 && single_label_nonsynthetic(name))
                log_notice("(Note that search domains are not appended when --type= is specified. "
                           "Please specify fully qualified domain names, or remove --type= switch from invocation in order to request regular hostname resolution.)");

        r = idna_candidate(name, &idnafied);
        if (r < 0)
                return r;
        if (r > 0)
                log_notice("(Note that IDNA translation is not applied when --type= is specified. "
                           "Please specify translated domain names — i.e. '%s' — when resolving raw records, or remove --type= switch from invocation in order to request regular hostname resolution.",
                           idnafied);

        r = bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveRecord");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isqqt", arg_ifindex, name, class, type, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (warn_missing || r != -ENXIO)
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
                if (warn_missing)
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
                n = strndupa_safe(p, q - p);
                q++;

                for (;;) {
                        const char *f;

                        f = startswith_no_case(q, "class=");
                        if (f) {
                                _cleanup_free_ char *t = NULL;
                                const char *e;

                                if (class != 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "DNS class specified twice.");

                                e = strchrnul(f, ';');
                                t = strndup(f, e - f);
                                if (!t)
                                        return log_oom();

                                r = dns_class_from_string(t);
                                if (r < 0)
                                        return log_error_errno(r, "Unknown DNS class %s.", t);

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

                                if (type != 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "DNS type specified twice.");

                                e = strchrnul(f, ';');
                                t = strndup(f, e - f);
                                if (!t)
                                        return log_oom();

                                r = dns_type_from_string(t);
                                if (r < 0)
                                        return log_error_errno(r, "Unknown DNS type %s: %m", t);

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

        return resolve_record(bus, n, class, type, true);

invalid:
        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Invalid DNS URI: %s", name);
}

static int verb_query(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int ret = 0, r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (arg_type != 0)
                STRV_FOREACH(p, strv_skip(argv, 1))
                        RET_GATHER(ret, resolve_record(bus, *p, arg_class, arg_type, true));

        else
                STRV_FOREACH(p, strv_skip(argv, 1)) {
                        if (startswith(*p, "dns:"))
                                RET_GATHER(ret, resolve_rfc4501(bus, *p));
                        else {
                                int family, ifindex;
                                union in_addr_union a;

                                r = in_addr_ifindex_from_string_auto(*p, &family, &a, &ifindex);
                                if (r >= 0)
                                        RET_GATHER(ret, resolve_address(bus, family, &a, ifindex));
                                else
                                        RET_GATHER(ret, resolve_host(bus, *p));
                        }
                }

        return ret;
}

static int resolve_service(sd_bus *bus, const char *name, const char *type, const char *domain) {
        const char *canonical_name, *canonical_type, *canonical_domain;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

        if (name)
                log_debug("Resolving service \"%s\" of type %s in %s (family %s, interface %s).", name, type, domain, af_to_name(arg_family) ?: "*", isempty(arg_ifname) ? "*" : arg_ifname);
        else if (type)
                log_debug("Resolving service type %s of %s (family %s, interface %s).", type, domain, af_to_name(arg_family) ?: "*", isempty(arg_ifname) ? "*" : arg_ifname);
        else
                log_debug("Resolving service type %s (family %s, interface %s).", domain, af_to_name(arg_family) ?: "*", isempty(arg_ifname) ? "*" : arg_ifname);

        r = bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveService");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "isssit", arg_ifindex, name, type, domain, arg_family, arg_flags);
        if (r < 0)
                return bus_log_create_error(r);

        ts = now(CLOCK_MONOTONIC);

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
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
                        int ifindex, family, k;
                        union in_addr_union a;

                        assert_cc(sizeof(int) == sizeof(int32_t));

                        r = sd_bus_message_read(reply, "i", &ifindex);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        sd_bus_error_free(&error);
                        r = bus_message_read_in_addr_auto(reply, &error, &family, &a);
                        if (r < 0 && !sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS))
                                return log_error_errno(r, "%s: systemd-resolved returned invalid result: %s", name, bus_error_message(&error, r));

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS)) {
                                log_debug_errno(r, "%s: systemd-resolved returned invalid result, ignoring: %s", name, bus_error_message(&error, r));
                                continue;
                        }

                        r = in_addr_ifindex_to_string(family, &a, ifindex, &pretty);
                        if (r < 0)
                                return log_error_errno(r, "Failed to print address for %s: %m", name);

                        k = printf("%*s%s", (int) indent, "", pretty);
                        print_ifindex_comment(k, ifindex);
                        fputc('\n', stdout);
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

        while ((r = sd_bus_message_read_array(reply, 'y', (const void**) &p, &sz)) > 0) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape_length(p, sz);
                if (!escaped)
                        return log_oom();

                printf("%*s%s\n", (int) indent, "", escaped);
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

static int verb_service(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Use --json=pretty with --type= to acquire resource record information in JSON format.");

        if (argc == 2)
                return resolve_service(bus, NULL, NULL, argv[1]);
        else if (argc == 3)
                return resolve_service(bus, NULL, argv[1], argv[2]);
        else
                return resolve_service(bus, argv[1], argv[2], argv[3]);
}

static int resolve_openpgp(sd_bus *bus, const char *address) {
        const char *domain, *full;
        int r;
        _cleanup_free_ char *hashed = NULL;

        assert(bus);
        assert(address);

        domain = strrchr(address, '@');
        if (!domain)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Address does not contain '@': \"%s\"", address);
        if (domain == address || domain[1] == '\0')
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Address starts or ends with '@': \"%s\"", address);
        domain++;

        r = string_hashsum_sha256(address, domain - 1 - address, &hashed);
        if (r < 0)
                return log_error_errno(r, "Hashing failed: %m");

        strshorten(hashed, 56);

        full = strjoina(hashed, "._openpgpkey.", domain);
        log_debug("Looking up \"%s\".", full);

        r = resolve_record(bus, full,
                           arg_class ?: DNS_CLASS_IN,
                           arg_type ?: DNS_TYPE_OPENPGPKEY, false);

        if (IN_SET(r, -ENXIO, -ESRCH)) { /* NXDOMAIN or NODATA? */
              hashed = mfree(hashed);
              r = string_hashsum_sha224(address, domain - 1 - address, &hashed);
              if (r < 0)
                    return log_error_errno(r, "Hashing failed: %m");

              full = strjoina(hashed, "._openpgpkey.", domain);
              log_debug("Looking up \"%s\".", full);

              return resolve_record(bus, full,
                                    arg_class ?: DNS_CLASS_IN,
                                    arg_type ?: DNS_TYPE_OPENPGPKEY, true);
        }

        return r;
}

static int verb_openpgp(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Use --json=pretty with --type= to acquire resource record information in JSON format.");

        STRV_FOREACH(p, strv_skip(argv, 1))
                RET_GATHER(ret, resolve_openpgp(bus, *p));

        return ret;
}

static int resolve_tlsa(sd_bus *bus, const char *family, const char *address) {
        const char *port;
        uint16_t port_num = 443;
        _cleanup_free_ char *full = NULL;
        int r;

        assert(bus);
        assert(address);

        port = strrchr(address, ':');
        if (port) {
                r = parse_ip_port(port + 1, &port_num);
                if (r < 0)
                        return log_error_errno(r, "Invalid port \"%s\".", port + 1);

                address = strndupa_safe(address, port - address);
        }

        r = asprintf(&full, "_%u._%s.%s",
                     port_num,
                     family,
                     address);
        if (r < 0)
                return log_oom();

        log_debug("Looking up \"%s\".", full);

        return resolve_record(bus, full,
                              arg_class ?: DNS_CLASS_IN,
                              arg_type ?: DNS_TYPE_TLSA, true);
}

static bool service_family_is_valid(const char *s) {
        return STR_IN_SET(s, "tcp", "udp", "sctp");
}

static int verb_tlsa(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *family = "tcp";
        char **args;
        int r, ret = 0;

        assert(argc >= 2);

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Use --json=pretty with --type= to acquire resource record information in JSON format.");

        if (service_family_is_valid(argv[1])) {
                family = argv[1];
                args = strv_skip(argv, 2);
        } else
                args = strv_skip(argv, 1);

        STRV_FOREACH(p, args)
                RET_GATHER(ret, resolve_tlsa(bus, family, *p));

        return ret;
}

static int show_statistics(int argc, char **argv, void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_json_variant *reply = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: %m");

        r = varlink_callbo_and_log(
                        vl,
                        "io.systemd.Resolve.Monitor.DumpStatistics",
                        &reply,
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return sd_json_variant_dump(reply, arg_json_format_flags, NULL, NULL);

        struct statistics {
                sd_json_variant *transactions;
                sd_json_variant *cache;
                sd_json_variant *dnssec;
        } statistics;

        static const sd_json_dispatch_field statistics_dispatch_table[] = {
                { "transactions", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, offsetof(struct statistics, transactions), SD_JSON_MANDATORY },
                { "cache",        SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, offsetof(struct statistics, cache),        SD_JSON_MANDATORY },
                { "dnssec",       SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, offsetof(struct statistics, dnssec),       SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(reply, statistics_dispatch_table, SD_JSON_LOG, &statistics);
        if (r < 0)
                return r;

        struct transactions {
                uint64_t n_current_transactions;
                uint64_t n_transactions_total;
                uint64_t n_timeouts_total;
                uint64_t n_timeouts_served_stale_total;
                uint64_t n_failure_responses_total;
                uint64_t n_failure_responses_served_stale_total;
        } transactions;

        static const sd_json_dispatch_field transactions_dispatch_table[] = {
                { "currentTransactions",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_current_transactions),                 SD_JSON_MANDATORY },
                { "totalTransactions",               _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_transactions_total),                   SD_JSON_MANDATORY },
                { "totalTimeouts",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_timeouts_total),                       SD_JSON_MANDATORY },
                { "totalTimeoutsServedStale",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_timeouts_served_stale_total),          SD_JSON_MANDATORY },
                { "totalFailedResponses",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_failure_responses_total),              SD_JSON_MANDATORY },
                { "totalFailedResponsesServedStale", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct transactions, n_failure_responses_served_stale_total), SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(statistics.transactions, transactions_dispatch_table, SD_JSON_LOG, &transactions);
        if (r < 0)
                return r;

        struct cache {
                uint64_t cache_size;
                uint64_t n_cache_hit;
                uint64_t n_cache_miss;
        } cache;

        static const sd_json_dispatch_field cache_dispatch_table[] = {
                { "size",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct cache, cache_size),   SD_JSON_MANDATORY },
                { "hits",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct cache, n_cache_hit),  SD_JSON_MANDATORY },
                { "misses", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct cache, n_cache_miss), SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(statistics.cache, cache_dispatch_table, SD_JSON_LOG, &cache);
        if (r < 0)
                return r;

        struct dnsssec {
                uint64_t n_dnssec_secure;
                uint64_t n_dnssec_insecure;
                uint64_t n_dnssec_bogus;
                uint64_t n_dnssec_indeterminate;
        } dnsssec;

        static const sd_json_dispatch_field dnssec_dispatch_table[] = {
                { "secure",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct dnsssec, n_dnssec_secure),        SD_JSON_MANDATORY },
                { "insecure",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct dnsssec, n_dnssec_insecure),      SD_JSON_MANDATORY },
                { "bogus",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct dnsssec, n_dnssec_bogus),         SD_JSON_MANDATORY },
                { "indeterminate", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct dnsssec, n_dnssec_indeterminate), SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(statistics.dnssec, dnssec_dispatch_table, SD_JSON_LOG, &dnsssec);
        if (r < 0)
                return r;

        table = table_new_vertical();
        if (!table)
                return log_oom();

        r = table_add_many(table,
                           TABLE_STRING, "Transactions",
                           TABLE_SET_COLOR, ansi_highlight(),
                           TABLE_SET_ALIGN_PERCENT, 0,
                           TABLE_EMPTY,
                           TABLE_FIELD, "Current Transactions",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_UINT64, transactions.n_current_transactions,
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_FIELD, "Total Transactions",
                           TABLE_UINT64, transactions.n_transactions_total,
                           TABLE_EMPTY, TABLE_EMPTY,
                           TABLE_STRING, "Cache",
                           TABLE_SET_COLOR, ansi_highlight(),
                           TABLE_SET_ALIGN_PERCENT, 0,
                           TABLE_EMPTY,
                           TABLE_FIELD, "Current Cache Size",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_UINT64, cache.cache_size,
                           TABLE_FIELD, "Cache Hits",
                           TABLE_UINT64, cache.n_cache_hit,
                           TABLE_FIELD, "Cache Misses",
                           TABLE_UINT64, cache.n_cache_miss,
                           TABLE_EMPTY, TABLE_EMPTY,
                           TABLE_STRING, "Failure Transactions",
                           TABLE_SET_COLOR, ansi_highlight(),
                           TABLE_SET_ALIGN_PERCENT, 0,
                           TABLE_EMPTY,
                           TABLE_FIELD, "Total Timeouts",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_UINT64, transactions.n_timeouts_total,
                           TABLE_FIELD, "Total Timeouts (Stale Data Served)",
                           TABLE_UINT64, transactions.n_timeouts_served_stale_total,
                           TABLE_FIELD, "Total Failure Responses",
                           TABLE_UINT64, transactions.n_failure_responses_total,
                           TABLE_FIELD, "Total Failure Responses (Stale Data Served)",
                           TABLE_UINT64, transactions.n_failure_responses_served_stale_total,
                           TABLE_EMPTY, TABLE_EMPTY,
                           TABLE_STRING, "DNSSEC Verdicts",
                           TABLE_SET_COLOR, ansi_highlight(),
                           TABLE_SET_ALIGN_PERCENT, 0,
                           TABLE_EMPTY,
                           TABLE_FIELD, "Secure",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_UINT64, dnsssec.n_dnssec_secure,
                           TABLE_FIELD, "Insecure",
                           TABLE_UINT64, dnsssec.n_dnssec_insecure,
                           TABLE_FIELD, "Bogus",
                           TABLE_UINT64, dnsssec.n_dnssec_bogus,
                           TABLE_FIELD, "Indeterminate",
                           TABLE_UINT64, dnsssec.n_dnssec_indeterminate
                          );
        if (r < 0)
                return table_log_add_error(r);

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int reset_statistics(int argc, char **argv, void *userdata) {
        sd_json_variant *reply = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: %m");

        r = varlink_callbo_and_log(
                        vl,
                        "io.systemd.Resolve.Monitor.ResetStatistics",
                        &reply,
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return sd_json_variant_dump(reply, arg_json_format_flags, NULL, NULL);

        return 0;
}

static int flush_caches(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_resolve_mgr, "FlushCaches", &error, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to flush caches: %s", bus_error_message(&error, r));

        return 0;
}

static int reset_server_features(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_resolve_mgr, "ResetServerFeatures", &error, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reset server features: %s", bus_error_message(&error, r));

        return 0;
}

static int read_dns_server_one(
                sd_bus_message *m,
                bool with_ifindex,  /* read "ifindex" reply that also carries an interface index */
                bool extended,      /* read "extended" reply, i.e. with port number and server name */
                bool only_global,   /* suppress entries with an (non-loopback) ifindex set (i.e. which are specific to some interface) */
                char **ret) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *pretty = NULL;
        union in_addr_union a;
        const char *name = NULL;
        int32_t ifindex = 0;
        int family, r, k;
        uint16_t port = 0;

        assert(m);
        assert(ret);

        r = sd_bus_message_enter_container(
                        m,
                        'r',
                        with_ifindex ? (extended ? "iiayqs" : "iiay") :
                                       (extended ? "iayqs" : "iay"));
        if (r <= 0)
                return r;

        if (with_ifindex) {
                r = sd_bus_message_read(m, "i", &ifindex);
                if (r < 0)
                        return r;
        }

        k = bus_message_read_in_addr_auto(m, &error, &family, &a);
        if (k < 0 && !sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS))
                return k;

        if (extended) {
                r = sd_bus_message_read(m, "q", &port);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        if (k < 0) {
                log_debug("Invalid DNS server, ignoring: %s", bus_error_message(&error, k));
                *ret = NULL;
                return 1;
        }

        if (only_global && ifindex > 0 && ifindex != LOOPBACK_IFINDEX) {
                /* This one has an (non-loopback) ifindex set, and we were told to suppress those. Hence do so. */
                *ret = NULL;
                return 1;
        }

        r = in_addr_port_ifindex_name_to_string(family, &a, port, ifindex, name, &pretty);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(pretty);
        return 1;
}

static int map_link_dns_servers_internal(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata, bool extended) {
        char ***l = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', extended ? "(iayqs)" : "(iay)");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *pretty = NULL;

                r = read_dns_server_one(m, /* with_ifindex= */ false, extended, /* only_global= */ false, &pretty);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty(pretty))
                        continue;

                r = strv_consume(l, TAKE_PTR(pretty));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_link_dns_servers(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_link_dns_servers_internal(bus, member, m, error, userdata, false);
}

static int map_link_dns_servers_ex(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_link_dns_servers_internal(bus, member, m, error, userdata, true);
}

static int map_link_current_dns_server(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        assert(m);
        assert(userdata);

        return read_dns_server_one(m, /* with_ifindex= */ false, /* extended= */ false, /* only_global= */ false, userdata);
}

static int map_link_current_dns_server_ex(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        assert(m);
        assert(userdata);

        return read_dns_server_one(m, /* with_ifindex= */ false, /* extended= */ true, /* only_global= */ false, userdata);
}

static int read_domain_one(sd_bus_message *m, bool with_ifindex, char **ret) {
        _cleanup_free_ char *str = NULL;
        int ifindex, route_only, r;
        const char *domain;

        assert(m);
        assert(ret);

        if (with_ifindex)
                r = sd_bus_message_read(m, "(isb)", &ifindex, &domain, &route_only);
        else
                r = sd_bus_message_read(m, "(sb)", &domain, &route_only);
        if (r <= 0)
                return r;

        if (with_ifindex && ifindex != 0) {
                /* only show the global ones here */
                *ret = NULL;
                return 1;
        }

        if (route_only)
                str = strjoin("~", domain);
        else
                str = strdup(domain);
        if (!str)
                return -ENOMEM;

        *ret = TAKE_PTR(str);

        return 1;
}

static int map_link_domains(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', "(sb)");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *pretty = NULL;

                r = read_domain_one(m, false, &pretty);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty(pretty))
                        continue;

                r = strv_consume(l, TAKE_PTR(pretty));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int status_print_strv_ifindex(int ifindex, const char *ifname, char **p) {
        const unsigned indent = strlen("Global: "); /* Use the same indentation everywhere to make things nice */
        int pos1, pos2;

        if (ifname)
                printf("%s%nLink %i (%s)%n%s:", ansi_highlight(), &pos1, ifindex, ifname, &pos2, ansi_normal());
        else
                printf("%s%nGlobal%n%s:", ansi_highlight(), &pos1, &pos2, ansi_normal());

        size_t cols = columns(), position = pos2 - pos1 + 2;

        STRV_FOREACH(i, p) {
                size_t our_len = utf8_console_width(*i); /* This returns -1 on invalid utf-8 (which shouldn't happen).
                                                          * If that happens, we'll just print one item per line. */

                if (position <= indent || size_add(size_add(position, 1), our_len) < cols) {
                        printf(" %s", *i);
                        position = size_add(size_add(position, 1), our_len);
                } else {
                        printf("\n%*s%s", (int) indent, "", *i);
                        position = size_add(our_len, indent);
                }
        }

        printf("\n");

        return 0;
}

static int status_print_strv_global(char **p) {
        return status_print_strv_ifindex(0, NULL, p);
}

typedef struct LinkInfo {
        uint64_t scopes_mask;
        const char *llmnr;
        const char *mdns;
        const char *dns_over_tls;
        const char *dnssec;
        char *current_dns;
        char *current_dns_ex;
        char **dns;
        char **dns_ex;
        char **domains;
        char **ntas;
        bool dnssec_supported;
        bool default_route;
} LinkInfo;

typedef struct GlobalInfo {
        char *current_dns;
        char *current_dns_ex;
        char **dns;
        char **dns_ex;
        char **fallback_dns;
        char **fallback_dns_ex;
        char **domains;
        char **ntas;
        const char *llmnr;
        const char *mdns;
        const char *dns_over_tls;
        const char *dnssec;
        const char *resolv_conf_mode;
        bool dnssec_supported;
} GlobalInfo;

static void link_info_done(LinkInfo *p) {
        assert(p);

        free(p->current_dns);
        free(p->current_dns_ex);
        strv_free(p->dns);
        strv_free(p->dns_ex);
        strv_free(p->domains);
        strv_free(p->ntas);
}

static void global_info_done(GlobalInfo *p) {
        assert(p);

        free(p->current_dns);
        free(p->current_dns_ex);
        strv_free(p->dns);
        strv_free(p->dns_ex);
        strv_free(p->fallback_dns);
        strv_free(p->fallback_dns_ex);
        strv_free(p->domains);
        strv_free(p->ntas);
}

static int dump_list(Table *table, const char *field, char * const *l) {
        int r;

        if (strv_isempty(l))
                return 0;

        r = table_add_many(table,
                           TABLE_FIELD, field,
                           TABLE_STRV_WRAPPED, l);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int strv_extend_extended_bool(char ***strv, const char *name, const char *value) {
        int r;

        if (value) {
                r = parse_boolean(value);
                if (r >= 0)
                        return strv_extendf(strv, "%s%s", plus_minus(r), name);
        }

        return strv_extendf(strv, "%s=%s", name, value ?: "???");
}

static char** link_protocol_status(const LinkInfo *info) {
        _cleanup_strv_free_ char **s = NULL;

        if (strv_extendf(&s, "%sDefaultRoute", plus_minus(info->default_route)) < 0)
                return NULL;

        if (strv_extend_extended_bool(&s, "LLMNR", info->llmnr) < 0)
                return NULL;

        if (strv_extend_extended_bool(&s, "mDNS", info->mdns) < 0)
                return NULL;

        if (strv_extend_extended_bool(&s, "DNSOverTLS", info->dns_over_tls) < 0)
                return NULL;

        if (strv_extendf(&s, "DNSSEC=%s/%s",
                         info->dnssec ?: "???",
                         info->dnssec_supported ? "supported" : "unsupported") < 0)
                return NULL;

        return TAKE_PTR(s);
}

static char** global_protocol_status(const GlobalInfo *info) {
        _cleanup_strv_free_ char **s = NULL;

        if (strv_extend_extended_bool(&s, "LLMNR", info->llmnr) < 0)
                return NULL;

        if (strv_extend_extended_bool(&s, "mDNS", info->mdns) < 0)
                return NULL;

        if (strv_extend_extended_bool(&s, "DNSOverTLS", info->dns_over_tls) < 0)
                return NULL;

        if (strv_extendf(&s, "DNSSEC=%s/%s",
                         info->dnssec ?: "???",
                         info->dnssec_supported ? "supported" : "unsupported") < 0)
                return NULL;

        return TAKE_PTR(s);
}

static int status_ifindex(sd_bus *bus, int ifindex, const char *name, StatusMode mode, bool *empty_line) {
        static const struct bus_properties_map property_map[] = {
                { "ScopesMask",                 "t",        NULL,                           offsetof(LinkInfo, scopes_mask)      },
                { "DNS",                        "a(iay)",   map_link_dns_servers,           offsetof(LinkInfo, dns)              },
                { "DNSEx",                      "a(iayqs)", map_link_dns_servers_ex,        offsetof(LinkInfo, dns_ex)           },
                { "CurrentDNSServer",           "(iay)",    map_link_current_dns_server,    offsetof(LinkInfo, current_dns)      },
                { "CurrentDNSServerEx",         "(iayqs)",  map_link_current_dns_server_ex, offsetof(LinkInfo, current_dns_ex)   },
                { "Domains",                    "a(sb)",    map_link_domains,               offsetof(LinkInfo, domains)          },
                { "DefaultRoute",               "b",        NULL,                           offsetof(LinkInfo, default_route)    },
                { "LLMNR",                      "s",        NULL,                           offsetof(LinkInfo, llmnr)            },
                { "MulticastDNS",               "s",        NULL,                           offsetof(LinkInfo, mdns)             },
                { "DNSOverTLS",                 "s",        NULL,                           offsetof(LinkInfo, dns_over_tls)     },
                { "DNSSEC",                     "s",        NULL,                           offsetof(LinkInfo, dnssec)           },
                { "DNSSECNegativeTrustAnchors", "as",       bus_map_strv_sort,              offsetof(LinkInfo, ntas)             },
                { "DNSSECSupported",            "b",        NULL,                           offsetof(LinkInfo, dnssec_supported) },
                {}
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(link_info_done) LinkInfo link_info = {};
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *p = NULL;
        char ifi[DECIMAL_STR_MAX(int)], ifname[IF_NAMESIZE];
        int r;

        assert(bus);
        assert(ifindex > 0);

        if (!name) {
                r = format_ifname(ifindex, ifname);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve interface name for %i: %m", ifindex);

                name = ifname;
        }

        xsprintf(ifi, "%i", ifindex);
        r = sd_bus_path_encode("/org/freedesktop/resolve1/link", ifi, &p);
        if (r < 0)
                return log_oom();

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.resolve1",
                                   p,
                                   property_map,
                                   BUS_MAP_BOOLEAN_AS_BOOL,
                                   &error,
                                   &m,
                                   &link_info);
        if (r < 0)
                return log_error_errno(r, "Failed to get link data for %i: %s", ifindex, bus_error_message(&error, r));

        pager_open(arg_pager_flags);

        switch (mode) {

        case STATUS_DNS:
                return status_print_strv_ifindex(ifindex, name, link_info.dns_ex ?: link_info.dns);

        case STATUS_DOMAIN:
                return status_print_strv_ifindex(ifindex, name, link_info.domains);

        case STATUS_NTA:
                return status_print_strv_ifindex(ifindex, name, link_info.ntas);

        case STATUS_DEFAULT_ROUTE:
                printf("%sLink %i (%s)%s: %s\n",
                       ansi_highlight(), ifindex, name, ansi_normal(),
                       yes_no(link_info.default_route));

                return 0;

        case STATUS_LLMNR:
                printf("%sLink %i (%s)%s: %s\n",
                       ansi_highlight(), ifindex, name, ansi_normal(),
                       strna(link_info.llmnr));

                return 0;

        case STATUS_MDNS:
                printf("%sLink %i (%s)%s: %s\n",
                       ansi_highlight(), ifindex, name, ansi_normal(),
                       strna(link_info.mdns));

                return 0;

        case STATUS_PRIVATE:
                printf("%sLink %i (%s)%s: %s\n",
                       ansi_highlight(), ifindex, name, ansi_normal(),
                       strna(link_info.dns_over_tls));

                return 0;

        case STATUS_DNSSEC:
                printf("%sLink %i (%s)%s: %s\n",
                       ansi_highlight(), ifindex, name, ansi_normal(),
                       strna(link_info.dnssec));

                return 0;

        case STATUS_ALL:
                break;

        default:
                return 0;
        }

        if (empty_line && *empty_line)
                fputc('\n', stdout);

        printf("%sLink %i (%s)%s\n",
               ansi_highlight(), ifindex, name, ansi_normal());

        table = table_new_vertical();
        if (!table)
                return log_oom();

        r = table_add_many(table,
                           TABLE_FIELD, "Current Scopes",
                           TABLE_SET_MINIMUM_WIDTH, 19);
        if (r < 0)
                return table_log_add_error(r);

        if (link_info.scopes_mask == 0)
                r = table_add_cell(table, NULL, TABLE_STRING, "none");
        else {
                _cleanup_free_ char *buf = NULL;
                size_t len;

                if (asprintf(&buf, "%s%s%s%s%s",
                             link_info.scopes_mask & SD_RESOLVED_DNS ? "DNS " : "",
                             link_info.scopes_mask & SD_RESOLVED_LLMNR_IPV4 ? "LLMNR/IPv4 " : "",
                             link_info.scopes_mask & SD_RESOLVED_LLMNR_IPV6 ? "LLMNR/IPv6 " : "",
                             link_info.scopes_mask & SD_RESOLVED_MDNS_IPV4 ? "mDNS/IPv4 " : "",
                             link_info.scopes_mask & SD_RESOLVED_MDNS_IPV6 ? "mDNS/IPv6 " : "") < 0)
                        return log_oom();

                len = strlen(buf);
                assert(len > 0);
                buf[len - 1] = '\0';

                r = table_add_cell(table, NULL, TABLE_STRING, buf);
        }
        if (r < 0)
                return table_log_add_error(r);

        _cleanup_strv_free_ char **pstatus = link_protocol_status(&link_info);
        if (!pstatus)
                return log_oom();

        r = table_add_many(table,
                           TABLE_FIELD,       "Protocols",
                           TABLE_STRV_WRAPPED, pstatus);
        if (r < 0)
                return table_log_add_error(r);

        if (link_info.current_dns) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Current DNS Server",
                                   TABLE_STRING, link_info.current_dns_ex ?: link_info.current_dns);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = dump_list(table, "DNS Servers", link_info.dns_ex ?: link_info.dns);
        if (r < 0)
                return r;

        r = dump_list(table, "DNS Domain", link_info.domains);
        if (r < 0)
                return r;

        r = table_add_many(table,
                           TABLE_FIELD, "Default Route",
                           TABLE_BOOLEAN, link_info.default_route);
        if (r < 0)
                return table_log_add_error(r);

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        if (empty_line)
                *empty_line = true;

        return 0;
}

static int map_global_dns_servers_internal(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata,
                bool extended) {

        char ***l = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', extended ? "(iiayqs)" : "(iiay)");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *pretty = NULL;

                r = read_dns_server_one(m, /* with_ifindex= */ true, extended, /* only_global= */ true, &pretty);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty(pretty))
                        continue;

                r = strv_consume(l, TAKE_PTR(pretty));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_global_dns_servers(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_global_dns_servers_internal(bus, member, m, error, userdata, /* extended= */ false);
}

static int map_global_dns_servers_ex(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_global_dns_servers_internal(bus, member, m, error, userdata, /* extended= */ true);
}

static int map_global_current_dns_server(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return read_dns_server_one(m, /* with_ifindex= */ true, /* extended= */ false, /* only_global= */ true, userdata);
}

static int map_global_current_dns_server_ex(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return read_dns_server_one(m, /* with_ifindex= */ true, /* extended= */ true, /* only_global= */ true, userdata);
}

static int map_global_domains(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***l = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', "(isb)");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *pretty = NULL;

                r = read_domain_one(m, true, &pretty);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty(pretty))
                        continue;

                r = strv_consume(l, TAKE_PTR(pretty));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        strv_sort(*l);

        return 0;
}

static int status_global(sd_bus *bus, StatusMode mode, bool *empty_line) {
        static const struct bus_properties_map property_map[] = {
                { "DNS",                        "a(iiay)",   map_global_dns_servers,           offsetof(GlobalInfo, dns)              },
                { "DNSEx",                      "a(iiayqs)", map_global_dns_servers_ex,        offsetof(GlobalInfo, dns_ex)           },
                { "FallbackDNS",                "a(iiay)",   map_global_dns_servers,           offsetof(GlobalInfo, fallback_dns)     },
                { "FallbackDNSEx",              "a(iiayqs)", map_global_dns_servers_ex,        offsetof(GlobalInfo, fallback_dns_ex)  },
                { "CurrentDNSServer",           "(iiay)",    map_global_current_dns_server,    offsetof(GlobalInfo, current_dns)      },
                { "CurrentDNSServerEx",         "(iiayqs)",  map_global_current_dns_server_ex, offsetof(GlobalInfo, current_dns_ex)   },
                { "Domains",                    "a(isb)",    map_global_domains,               offsetof(GlobalInfo, domains)          },
                { "DNSSECNegativeTrustAnchors", "as",        bus_map_strv_sort,                offsetof(GlobalInfo, ntas)             },
                { "LLMNR",                      "s",         NULL,                             offsetof(GlobalInfo, llmnr)            },
                { "MulticastDNS",               "s",         NULL,                             offsetof(GlobalInfo, mdns)             },
                { "DNSOverTLS",                 "s",         NULL,                             offsetof(GlobalInfo, dns_over_tls)     },
                { "DNSSEC",                     "s",         NULL,                             offsetof(GlobalInfo, dnssec)           },
                { "DNSSECSupported",            "b",         NULL,                             offsetof(GlobalInfo, dnssec_supported) },
                { "ResolvConfMode",             "s",         NULL,                             offsetof(GlobalInfo, resolv_conf_mode) },
                {}
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(global_info_done) GlobalInfo global_info = {};
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(bus);
        assert(empty_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.resolve1",
                                   "/org/freedesktop/resolve1",
                                   property_map,
                                   BUS_MAP_BOOLEAN_AS_BOOL,
                                   &error,
                                   &m,
                                   &global_info);
        if (r < 0)
                return log_error_errno(r, "Failed to get global data: %s", bus_error_message(&error, r));

        pager_open(arg_pager_flags);

        switch (mode) {

        case STATUS_DNS:
                return status_print_strv_global(global_info.dns_ex ?: global_info.dns);

        case STATUS_DOMAIN:
                return status_print_strv_global(global_info.domains);

        case STATUS_NTA:
                return status_print_strv_global(global_info.ntas);

        case STATUS_LLMNR:
                printf("%sGlobal%s: %s\n", ansi_highlight(), ansi_normal(),
                       strna(global_info.llmnr));

                return 0;

        case STATUS_MDNS:
                printf("%sGlobal%s: %s\n", ansi_highlight(), ansi_normal(),
                       strna(global_info.mdns));

                return 0;

        case STATUS_PRIVATE:
                printf("%sGlobal%s: %s\n", ansi_highlight(), ansi_normal(),
                       strna(global_info.dns_over_tls));

                return 0;

        case STATUS_DNSSEC:
                printf("%sGlobal%s: %s\n", ansi_highlight(), ansi_normal(),
                       strna(global_info.dnssec));

                return 0;

        case STATUS_ALL:
                break;

        default:
                return 0;
        }

        printf("%sGlobal%s\n", ansi_highlight(), ansi_normal());

        table = table_new_vertical();
        if (!table)
                return log_oom();

        _cleanup_strv_free_ char **pstatus = global_protocol_status(&global_info);
        if (!pstatus)
                return log_oom();

        r = table_add_many(table,
                           TABLE_FIELD,            "Protocols",
                           TABLE_SET_MINIMUM_WIDTH, 19,
                           TABLE_STRV_WRAPPED,      pstatus);
        if (r < 0)
                return table_log_add_error(r);

        if (global_info.resolv_conf_mode) {
                r = table_add_many(table,
                                   TABLE_FIELD, "resolv.conf mode",
                                   TABLE_STRING, global_info.resolv_conf_mode);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (global_info.current_dns) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Current DNS Server",
                                   TABLE_STRING, global_info.current_dns_ex ?: global_info.current_dns);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = dump_list(table, "DNS Servers", global_info.dns_ex ?: global_info.dns);
        if (r < 0)
                return r;

        r = dump_list(table, "Fallback DNS Servers", global_info.fallback_dns_ex ?: global_info.fallback_dns);
        if (r < 0)
                return r;

        r = dump_list(table, "DNS Domain", global_info.domains);
        if (r < 0)
                return r;

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        *empty_line = true;

        return 0;
}

static int status_all(sd_bus *bus, StatusMode mode) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        bool empty_line = false;
        int ret = 0, r;

        assert(bus);

        r = status_global(bus, mode, &empty_line);
        if (r < 0)
                return r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate links: %m");

        _cleanup_free_ InterfaceInfo *infos = NULL;
        size_t n_infos = 0;

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                const char *name;
                int ifindex;
                uint16_t type;

                r = sd_netlink_message_get_type(i, &type);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                if (type != RTM_NEWLINK)
                        continue;

                r = sd_rtnl_message_link_get_ifindex(i, &ifindex);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                if (ifindex == LOOPBACK_IFINDEX)
                        continue;

                r = sd_netlink_message_read_string(i, IFLA_IFNAME, &name);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                if (!GREEDY_REALLOC(infos, n_infos + 1))
                        return log_oom();

                infos[n_infos++] = (InterfaceInfo) { ifindex, name };
        }

        typesafe_qsort(infos, n_infos, interface_info_compare);

        FOREACH_ARRAY(info, infos, n_infos)
                RET_GATHER(ret, status_ifindex(bus, info->index, info->name, mode, &empty_line));

        return ret;
}

static int verb_status(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        bool empty_line = false;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc <= 1)
                return status_all(bus, STATUS_ALL);

        STRV_FOREACH(ifname, strv_skip(argv, 1)) {
                int ifindex;

                ifindex = rtnl_resolve_interface(&rtnl, *ifname);
                if (ifindex < 0) {
                        log_warning_errno(ifindex, "Failed to resolve interface \"%s\", ignoring: %m", *ifname);
                        continue;
                }

                RET_GATHER(ret, status_ifindex(bus, ifindex, NULL, STATUS_ALL, &empty_line));
        }

        return ret;
}

static int call_dns(sd_bus *bus, char **dns, const BusLocator *locator, sd_bus_error *error, bool extended) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_message_new_method_call(bus, &req, locator, extended ? "SetLinkDNSEx" : "SetLinkDNS");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "i", arg_ifindex);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(req, 'a', extended ? "(iayqs)" : "(iay)");
        if (r < 0)
                return bus_log_create_error(r);

        /* If only argument is the empty string, then call SetLinkDNS() with an
         * empty list, which will clear the list of domains for an interface. */
        if (!strv_equal(dns, STRV_MAKE("")))
                STRV_FOREACH(p, dns) {
                        _cleanup_free_ char *name = NULL;
                        struct in_addr_data data;
                        uint16_t port;
                        int ifindex;

                        r = in_addr_port_ifindex_name_from_string_auto(*p, &data.family, &data.address, &port, &ifindex, &name);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse DNS server address: %s", *p);

                        if (ifindex != 0 && ifindex != arg_ifindex)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid ifindex: %i", ifindex);

                        r = sd_bus_message_open_container(req, 'r', extended ? "iayqs" : "iay");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(req, "i", data.family);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append_array(req, 'y', &data.address, FAMILY_ADDRESS_SIZE(data.family));
                        if (r < 0)
                                return bus_log_create_error(r);

                        if (extended) {
                                r = sd_bus_message_append(req, "q", port);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                r = sd_bus_message_append(req, "s", name);
                                if (r < 0)
                                        return bus_log_create_error(r);
                        }

                        r = sd_bus_message_close_container(req);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

        r = sd_bus_message_close_container(req);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, req, 0, error, NULL);
        if (r < 0 && extended && sd_bus_error_has_name(error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                sd_bus_error_free(error);
                return call_dns(bus, dns, locator, error, false);
        }
        return r;
}

static int verb_dns(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_DNS);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_DNS, NULL);

        char **args = strv_skip(argv, 2);
        r = call_dns(bus, args, bus_resolve_mgr, &error, true);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = call_dns(bus, args, bus_network_mgr, &error, true);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set DNS configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int call_domain(sd_bus *bus, char **domain, const BusLocator *locator, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_message_new_method_call(bus, &req, locator, "SetLinkDomains");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "i", arg_ifindex);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(req, 'a', "(sb)");
        if (r < 0)
                return bus_log_create_error(r);

        /* If only argument is the empty string, then call SetLinkDomains() with an
         * empty list, which will clear the list of domains for an interface. */
        if (!strv_equal(domain, STRV_MAKE("")))
                STRV_FOREACH(p, domain) {
                        const char *n;

                        n = **p == '~' ? *p + 1 : *p;

                        r = dns_name_is_valid(n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to validate specified domain %s: %m", n);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Domain not valid: %s",
                                                       n);

                        r = sd_bus_message_append(req, "(sb)", n, **p == '~');
                        if (r < 0)
                                return bus_log_create_error(r);
                }

        r = sd_bus_message_close_container(req);
        if (r < 0)
                return bus_log_create_error(r);

        return sd_bus_call(bus, req, 0, error, NULL);
}

static int verb_domain(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_DOMAIN);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_DOMAIN, NULL);

        char **args = strv_skip(argv, 2);
        r = call_domain(bus, args, bus_resolve_mgr, &error);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = call_domain(bus, args, bus_network_mgr, &error);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set domain configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_default_route(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, b;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_DEFAULT_ROUTE);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_DEFAULT_ROUTE, NULL);

        b = parse_boolean(argv[2]);
        if (b < 0)
                return log_error_errno(b, "Failed to parse boolean argument: %s", argv[2]);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "SetLinkDefaultRoute", &error, NULL, "ib", arg_ifindex, b);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(bus, bus_network_mgr, "SetLinkDefaultRoute", &error, NULL, "ib", arg_ifindex, b);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set default route configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_llmnr(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *global_llmnr_support_str = NULL;
        ResolveSupport global_llmnr_support, llmnr_support;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_LLMNR);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_LLMNR, NULL);

        llmnr_support = resolve_support_from_string(argv[2]);
        if (llmnr_support < 0)
                return log_error_errno(llmnr_support, "Invalid LLMNR setting: %s", argv[2]);

        r = bus_get_property_string(bus, bus_resolve_mgr, "LLMNR", &error, &global_llmnr_support_str);
        if (r < 0)
                return log_error_errno(r, "Failed to get the global LLMNR support state: %s", bus_error_message(&error, r));

        global_llmnr_support = resolve_support_from_string(global_llmnr_support_str);
        if (global_llmnr_support < 0)
                return log_error_errno(global_llmnr_support, "Received invalid global LLMNR setting: %s", global_llmnr_support_str);

        if (global_llmnr_support < llmnr_support)
                log_warning("Setting LLMNR support level \"%s\" for \"%s\", but the global support level is \"%s\".",
                            argv[2], arg_ifname, global_llmnr_support_str);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "SetLinkLLMNR", &error, NULL, "is", arg_ifindex, argv[2]);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(bus, bus_network_mgr, "SetLinkLLMNR", &error, NULL, "is", arg_ifindex, argv[2]);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set LLMNR configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_mdns(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *global_mdns_support_str = NULL;
        ResolveSupport global_mdns_support, mdns_support;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_MDNS);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_MDNS, NULL);

        mdns_support = resolve_support_from_string(argv[2]);
        if (mdns_support < 0)
                return log_error_errno(mdns_support, "Invalid mDNS setting: %s", argv[2]);

        r = bus_get_property_string(bus, bus_resolve_mgr, "MulticastDNS", &error, &global_mdns_support_str);
        if (r < 0)
                return log_error_errno(r, "Failed to get the global mDNS support state: %s", bus_error_message(&error, r));

        global_mdns_support = resolve_support_from_string(global_mdns_support_str);
        if (global_mdns_support < 0)
                return log_error_errno(global_mdns_support, "Received invalid global mDNS setting: %s", global_mdns_support_str);

        if (global_mdns_support < mdns_support)
                log_warning("Setting mDNS support level \"%s\" for \"%s\", but the global support level is \"%s\".",
                            argv[2], arg_ifname, global_mdns_support_str);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "SetLinkMulticastDNS", &error, NULL, "is", arg_ifindex, argv[2]);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(
                                bus,
                                bus_network_mgr,
                                "SetLinkMulticastDNS",
                                &error,
                                NULL,
                                "is", arg_ifindex, argv[2]);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set MulticastDNS configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_dns_over_tls(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_PRIVATE);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_PRIVATE, NULL);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "SetLinkDNSOverTLS", &error, NULL, "is", arg_ifindex, argv[2]);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(
                                bus,
                                bus_network_mgr,
                                "SetLinkDNSOverTLS",
                                &error,
                                NULL,
                                "is", arg_ifindex, argv[2]);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set DNSOverTLS configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_dnssec(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_DNSSEC);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_DNSSEC, NULL);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "SetLinkDNSSEC", &error, NULL, "is", arg_ifindex, argv[2]);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(bus, bus_network_mgr, "SetLinkDNSSEC", &error, NULL, "is", arg_ifindex, argv[2]);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set DNSSEC configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int call_nta(sd_bus *bus, char **nta, const BusLocator *locator,  sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_message_new_method_call(bus, &req, locator, "SetLinkDNSSECNegativeTrustAnchors");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "i", arg_ifindex);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(req, nta);
        if (r < 0)
                return bus_log_create_error(r);

        return sd_bus_call(bus, req, 0, error, NULL);
}

static int verb_nta(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char **args;
        bool clear;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return status_all(bus, STATUS_NTA);

        if (argc < 3)
                return status_ifindex(bus, arg_ifindex, NULL, STATUS_NTA, NULL);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        /* If only argument is the empty string, then call SetLinkDNSSECNegativeTrustAnchors()
         * with an empty list, which will clear the list of domains for an interface. */
        args = strv_skip(argv, 2);
        clear = strv_equal(args, STRV_MAKE(""));

        if (!clear)
                STRV_FOREACH(p, args) {
                        r = dns_name_is_valid(*p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to validate specified domain %s: %m", *p);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Domain not valid: %s",
                                                       *p);
                }

        r = call_nta(bus, clear ? NULL : args, bus_resolve_mgr, &error);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = call_nta(bus, clear ? NULL : args, bus_network_mgr, &error);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to set DNSSEC NTA configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_revert_link(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc >= 2) {
                r = ifname_mangle(argv[1]);
                if (r < 0)
                        return r;
        }

        if (arg_ifindex <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Interface argument required.");

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_resolve_mgr, "RevertLink", &error, NULL, "i", arg_ifindex);
        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_LINK_BUSY)) {
                sd_bus_error_free(&error);

                r = bus_call_method(bus, bus_network_mgr, "RevertLinkDNS", &error, NULL, "i", arg_ifindex);
        }
        if (r < 0) {
                if (arg_ifindex_permissive &&
                    sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_LINK))
                        return 0;

                return log_error_errno(r, "Failed to revert interface configuration: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int verb_log_level(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        assert(IN_SET(argc, 1, 2));

        return verb_log_control_common(bus, "org.freedesktop.resolve1", argv[0], argc == 2 ? argv[1] : NULL);
}

static int print_question(char prefix, const char *color, sd_json_variant *question) {
        sd_json_variant *q = NULL;
        int r;

        assert(color);

        JSON_VARIANT_ARRAY_FOREACH(q, question) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                char buf[DNS_RESOURCE_KEY_STRING_MAX];

                r = dns_resource_key_from_json(q, &key);
                if (r < 0) {
                        log_warning_errno(r, "Received monitor message with invalid question key, ignoring: %m");
                        continue;
                }

                printf("%s%s %c%s: %s\n",
                       color,
                       special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                       prefix,
                       ansi_normal(),
                       dns_resource_key_to_string(key, buf, sizeof(buf)));
        }

        return 0;
}

static int print_answer(sd_json_variant *answer) {
        sd_json_variant *a;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(a, answer) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                _cleanup_free_ void *d = NULL;
                sd_json_variant *jraw;
                const char *s;
                size_t l;

                jraw = sd_json_variant_by_key(a, "raw");
                if (!jraw) {
                        log_warning("Received monitor answer lacking valid raw data, ignoring.");
                        continue;
                }

                r = sd_json_variant_unbase64(jraw, &d, &l);
                if (r < 0) {
                        log_warning_errno(r, "Failed to undo base64 encoding of monitor answer raw data, ignoring.");
                        continue;
                }

                r = dns_resource_record_new_from_raw(&rr, d, l);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse monitor answer RR, ignoring: %m");
                        continue;
                }

                s = dns_resource_record_to_string(rr);
                if (!s)
                        return log_oom();

                printf("%s%s A%s: %s\n",
                       ansi_highlight_yellow(),
                       special_glyph(SPECIAL_GLYPH_ARROW_LEFT),
                       ansi_normal(),
                       s);
        }

        return 0;
}

typedef struct MonitorQueryParams {
        sd_json_variant *question;
        sd_json_variant *answer;
        sd_json_variant *collected_questions;
        int rcode;
        int error;
        int ede_code;
        const char *state;
        const char *result;
        const char *ede_msg;
} MonitorQueryParams;

static void monitor_query_params_done(MonitorQueryParams *p) {
        assert(p);

        sd_json_variant_unref(p->question);
        sd_json_variant_unref(p->answer);
        sd_json_variant_unref(p->collected_questions);
}

static void monitor_query_dump(sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "question",                SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,      offsetof(MonitorQueryParams, question),            SD_JSON_MANDATORY },
                { "answer",                  SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,      offsetof(MonitorQueryParams, answer),              0                 },
                { "collectedQuestions",      SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,      offsetof(MonitorQueryParams, collected_questions), 0                 },
                { "state",                   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MonitorQueryParams, state),               SD_JSON_MANDATORY },
                { "result",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MonitorQueryParams, result),              0                 },
                { "rcode",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(MonitorQueryParams, rcode),               0                 },
                { "errno",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(MonitorQueryParams, error),               0                 },
                { "extendedDNSErrorCode",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(MonitorQueryParams, ede_code),            0                 },
                { "extendedDNSErrorMessage", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MonitorQueryParams, ede_msg),             0                 },
                {}
        };

        _cleanup_(monitor_query_params_done) MonitorQueryParams p = {
                .rcode = -1,
                .ede_code = -1,
        };

        assert(v);

        if (sd_json_dispatch(v, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &p) < 0)
                return;

        /* First show the current question */
        print_question('Q', ansi_highlight_cyan(), p.question);

        /* And then show the questions that led to this one in case this was a CNAME chain */
        print_question('C', ansi_highlight_grey(), p.collected_questions);

        printf("%s%s S%s: %s",
               streq_ptr(p.state, "success") ? ansi_highlight_green() : ansi_highlight_red(),
               special_glyph(SPECIAL_GLYPH_ARROW_LEFT),
               ansi_normal(),
               strna(streq_ptr(p.state, "errno") ? errno_to_name(p.error) :
                     streq_ptr(p.state, "rcode-failure") ? dns_rcode_to_string(p.rcode) :
                     p.state));

        if (!isempty(p.result))
                printf(": %s", p.result);

        if (p.ede_code >= 0)
                printf(" (%s%s%s)",
                       FORMAT_DNS_EDE_RCODE(p.ede_code),
                       !isempty(p.ede_msg) ? ": " : "",
                       strempty(p.ede_msg));

        puts("");

        print_answer(p.answer);
}

static int monitor_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        if (error_id) {
                bool disconnect;

                disconnect = streq(error_id, SD_VARLINK_ERROR_DISCONNECTED);
                if (disconnect)
                        log_info("Disconnected.");
                else
                        log_error("Varlink error: %s", error_id);

                (void) sd_event_exit(ASSERT_PTR(sd_varlink_get_event(link)), disconnect ? EXIT_SUCCESS : EXIT_FAILURE);
                return 0;
        }

        if (sd_json_variant_by_key(parameters, "ready")) {
                /* The first message coming in will just indicate that we are now subscribed. We let our
                 * caller know if they asked for it. Once the caller sees this they should know that we are
                 * not going to miss any queries anymore. */
                (void) sd_notify(/* unset_environment=false */ false, "READY=1");
                return 0;
        }

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                monitor_query_dump(parameters);
                printf("\n");
        } else
                sd_json_variant_dump(parameters, arg_json_format_flags, NULL, NULL);

        fflush(stdout);

        return 0;
}

static int verb_monitor(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r, c;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: %m");

        r = sd_varlink_set_relative_timeout(vl, USEC_INFINITY); /* We want the monitor to run basically forever */
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, monitor_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback to varlink connection: %m");

        r = sd_varlink_observebo(
                        vl,
                        "io.systemd.Resolve.Monitor.SubscribeQueryResults",
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return log_error_errno(r, "Failed to issue SubscribeQueryResults() varlink call: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        r = sd_event_get_exit_code(event, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to get exit code: %m");

        return c;
}

static int dump_cache_item(sd_json_variant *item) {

        struct item_info {
                sd_json_variant *key;
                sd_json_variant *rrs;
                const char *type;
                uint64_t until;
        } item_info = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "key",   SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, offsetof(struct item_info, key),   SD_JSON_MANDATORY },
                { "rrs",   SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(struct item_info, rrs),   0                 },
                { "type",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct item_info, type),  0                 },
                { "until", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(struct item_info, until), 0                 },
                {},
        };

        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;
        int r, c = 0;

        r = sd_json_dispatch(item, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &item_info);
        if (r < 0)
                return r;

        r = dns_resource_key_from_json(item_info.key, &k);
        if (r < 0)
                return log_error_errno(r, "Failed to turn JSON data to resource key: %m");

        if (item_info.type)
                printf("%s %s%s%s\n", DNS_RESOURCE_KEY_TO_STRING(k), ansi_highlight_red(), item_info.type, ansi_normal());
        else {
                sd_json_variant *i;

                JSON_VARIANT_ARRAY_FOREACH(i, item_info.rrs) {
                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                        _cleanup_free_ void *data = NULL;
                        sd_json_variant *raw;
                        size_t size;

                        raw = sd_json_variant_by_key(i, "raw");
                        if (!raw)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "raw field missing from RR JSON data.");

                        r = sd_json_variant_unbase64(raw, &data, &size);
                        if (r < 0)
                                return log_error_errno(r, "Unable to decode raw RR JSON data: %m");

                        r = dns_resource_record_new_from_raw(&rr, data, size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse DNS data: %m");

                        printf("%s\n", dns_resource_record_to_string(rr));
                        c++;
                }
        }

        return c;
}

static int dump_cache_scope(sd_json_variant *scope) {

        struct scope_info {
                const char *protocol;
                int family;
                int ifindex;
                const char *ifname;
                sd_json_variant *cache;
        } scope_info = {
                .family = AF_UNSPEC,
        };
        sd_json_variant *i;
        int r, c = 0;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "protocol", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct scope_info, protocol), SD_JSON_MANDATORY },
                { "family",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,           offsetof(struct scope_info, family),   0                 },
                { "ifindex",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(struct scope_info, ifindex),  SD_JSON_RELAX     },
                { "ifname",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct scope_info, ifname),   0                 },
                { "cache",    SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(struct scope_info, cache),    SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(scope, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &scope_info);
        if (r < 0)
                return r;

        printf("%sScope protocol=%s", ansi_underline(), scope_info.protocol);

        if (scope_info.family != AF_UNSPEC)
                printf(" family=%s", af_to_name(scope_info.family));

        if (scope_info.ifindex > 0)
                printf(" ifindex=%i", scope_info.ifindex);
        if (scope_info.ifname)
                printf(" ifname=%s", scope_info.ifname);

        printf("%s\n", ansi_normal());

        JSON_VARIANT_ARRAY_FOREACH(i, scope_info.cache) {
                r = dump_cache_item(i);
                if (r < 0)
                        return r;

                c += r;
        }

        if (c == 0)
                printf("%sNo entries.%s\n\n", ansi_grey(), ansi_normal());
        else
                printf("\n");

        return 0;
}

static int verb_show_cache(int argc, char *argv[], void *userdata) {
        sd_json_variant *reply = NULL, *d = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: %m");

        r = varlink_callbo_and_log(
                        vl,
                        "io.systemd.Resolve.Monitor.DumpCache",
                        &reply,
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return r;

        d = sd_json_variant_by_key(reply, "dump");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "DumpCache() response is missing 'dump' key.");

        if (!sd_json_variant_is_array(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "DumpCache() response 'dump' field not an array");

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                sd_json_variant *i;

                JSON_VARIANT_ARRAY_FOREACH(i, d) {
                        r = dump_cache_scope(i);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        return sd_json_variant_dump(d, arg_json_format_flags, NULL, NULL);
}

static int dump_server_state(sd_json_variant *server) {
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;

        struct server_state {
                const char *server_name;
                const char *type;
                const char *ifname;
                int ifindex;
                const char *verified_feature_level;
                const char *possible_feature_level;
                const char *dnssec_mode;
                bool dnssec_supported;
                size_t received_udp_fragment_max;
                uint64_t n_failed_udp;
                uint64_t n_failed_tcp;
                bool packet_truncated;
                bool packet_bad_opt;
                bool packet_rrsig_missing;
                bool packet_invalid;
                bool packet_do_off;
        } server_state = {
                .ifindex = -1,
        };

        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Server",                 SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, server_name),               SD_JSON_MANDATORY },
                { "Type",                   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, type),                      SD_JSON_MANDATORY },
                { "Interface",              SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, ifname),                    0                 },
                { "InterfaceIndex",         _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(struct server_state, ifindex),                   SD_JSON_RELAX     },
                { "VerifiedFeatureLevel",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, verified_feature_level),    0                 },
                { "PossibleFeatureLevel",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, possible_feature_level),    0                 },
                { "DNSSECMode",             SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(struct server_state, dnssec_mode),               SD_JSON_MANDATORY },
                { "DNSSECSupported",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, dnssec_supported),          SD_JSON_MANDATORY },
                { "ReceivedUDPFragmentMax", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(struct server_state, received_udp_fragment_max), SD_JSON_MANDATORY },
                { "FailedUDPAttempts",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(struct server_state, n_failed_udp),              SD_JSON_MANDATORY },
                { "FailedTCPAttempts",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(struct server_state, n_failed_tcp),              SD_JSON_MANDATORY },
                { "PacketTruncated",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, packet_truncated),          SD_JSON_MANDATORY },
                { "PacketBadOpt",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, packet_bad_opt),            SD_JSON_MANDATORY },
                { "PacketRRSIGMissing",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, packet_rrsig_missing),      SD_JSON_MANDATORY },
                { "PacketInvalid",          SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, packet_invalid),            SD_JSON_MANDATORY },
                { "PacketDoOff",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(struct server_state, packet_do_off),             SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(server, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &server_state);
        if (r < 0)
                return r;

        table = table_new_vertical();
        if (!table)
                return log_oom();

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_ellipsize_percent(table, cell, 100);
        (void) table_set_align_percent(table, cell, 0);

        r = table_add_cell_stringf(table, NULL, "Server: %s", server_state.server_name);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(table,
                           TABLE_EMPTY,
                           TABLE_FIELD, "Type",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_STRING, server_state.type);
        if (r < 0)
                return table_log_add_error(r);

        if (server_state.ifname) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Interface",
                                   TABLE_STRING, server_state.ifname);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (server_state.ifindex >= 0) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Interface Index",
                                   TABLE_INT, server_state.ifindex);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (server_state.verified_feature_level) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Verified feature level",
                                   TABLE_STRING, server_state.verified_feature_level);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (server_state.possible_feature_level) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Possible feature level",
                                   TABLE_STRING, server_state.possible_feature_level);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_add_many(table,
                           TABLE_FIELD, "DNSSEC Mode",
                           TABLE_STRING, server_state.dnssec_mode,
                           TABLE_FIELD, "DNSSEC Supported",
                           TABLE_STRING, yes_no(server_state.dnssec_supported),
                           TABLE_FIELD, "Maximum UDP fragment size received",
                           TABLE_UINT64, server_state.received_udp_fragment_max,
                           TABLE_FIELD, "Failed UDP attempts",
                           TABLE_UINT64, server_state.n_failed_udp,
                           TABLE_FIELD, "Failed TCP attempts",
                           TABLE_UINT64, server_state.n_failed_tcp,
                           TABLE_FIELD, "Seen truncated packet",
                           TABLE_STRING, yes_no(server_state.packet_truncated),
                           TABLE_FIELD, "Seen OPT RR getting lost",
                           TABLE_STRING, yes_no(server_state.packet_bad_opt),
                           TABLE_FIELD, "Seen RRSIG RR missing",
                           TABLE_STRING, yes_no(server_state.packet_rrsig_missing),
                           TABLE_FIELD, "Seen invalid packet",
                           TABLE_STRING, yes_no(server_state.packet_invalid),
                           TABLE_FIELD, "Server dropped DO flag",
                           TABLE_STRING, yes_no(server_state.packet_do_off),
                           TABLE_SET_ALIGN_PERCENT, 0,
                           TABLE_EMPTY, TABLE_EMPTY);

        if (r < 0)
                return table_log_add_error(r);

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int verb_show_server_state(int argc, char *argv[], void *userdata) {
        sd_json_variant *reply = NULL, *d = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: %m");

        r = varlink_callbo_and_log(
                        vl,
                        "io.systemd.Resolve.Monitor.DumpServerState",
                        &reply,
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return r;

        d = sd_json_variant_by_key(reply, "dump");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "DumpCache() response is missing 'dump' key.");

        if (!sd_json_variant_is_array(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "DumpCache() response 'dump' field not an array");

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                sd_json_variant *i;

                JSON_VARIANT_ARRAY_FOREACH(i, d) {
                        r = dump_server_state(i);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        return sd_json_variant_dump(d, arg_json_format_flags, NULL, NULL);
}

static void help_protocol_types(void) {
        if (arg_legend)
                puts("Known protocol types:");
        puts("dns\n"
             "llmnr\n"
             "llmnr-ipv4\n"
             "llmnr-ipv6\n"
             "mdns\n"
             "mdns-ipv4\n"
             "mdns-ipv6");
}

static void help_dns_types(void) {
        if (arg_legend)
                puts("Known DNS RR types:");

        DUMP_STRING_TABLE(dns_type, int, _DNS_TYPE_MAX);
}

static void help_dns_classes(void) {
        if (arg_legend)
                puts("Known DNS RR classes:");

        DUMP_STRING_TABLE(dns_class, int, _DNS_CLASS_MAX);
}

static int compat_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("resolvectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] HOSTNAME|ADDRESS...\n"
               "%1$s [OPTIONS...] --service [[NAME] TYPE] DOMAIN\n"
               "%1$s [OPTIONS...] --openpgp EMAIL@DOMAIN...\n"
               "%1$s [OPTIONS...] --statistics\n"
               "%1$s [OPTIONS...] --reset-statistics\n"
               "\n"
               "%2$sResolve domain names, IPv4 and IPv6 addresses, DNS records, and services.%3$s\n\n"
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
               "     --reset-server-features\n"
               "                            Forget learnt DNS server feature levels\n"
               "     --set-dns=SERVER       Set per-interface DNS server address\n"
               "     --set-domain=DOMAIN    Set per-interface search domain\n"
               "     --set-llmnr=MODE       Set per-interface LLMNR mode\n"
               "     --set-mdns=MODE        Set per-interface MulticastDNS mode\n"
               "     --set-dnsovertls=MODE  Set per-interface DNS-over-TLS mode\n"
               "     --set-dnssec=MODE      Set per-interface DNSSEC mode\n"
               "     --set-nta=DOMAIN       Set per-interface DNSSEC NTA\n"
               "     --revert               Revert per-interface configuration\n"
               "\nSee the %4$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int native_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("resolvectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n"
               "\n"
               "%5$sSend control commands to the network name resolution manager, or%6$s\n"
               "%5$sresolve domain names, IPv4 and IPv6 addresses, DNS records, and services.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  query HOSTNAME|ADDRESS...    Resolve domain names, IPv4 and IPv6 addresses\n"
               "  service [[NAME] TYPE] DOMAIN Resolve service (SRV)\n"
               "  openpgp EMAIL@DOMAIN...      Query OpenPGP public key\n"
               "  tlsa DOMAIN[:PORT]...        Query TLS public key\n"
               "  status [LINK...]             Show link and server status\n"
               "  statistics                   Show resolver statistics\n"
               "  reset-statistics             Reset resolver statistics\n"
               "  flush-caches                 Flush all local DNS caches\n"
               "  reset-server-features        Forget learnt DNS server feature levels\n"
               "  monitor                      Monitor DNS queries\n"
               "  show-cache                   Show cache contents\n"
               "  show-server-state            Show servers state\n"
               "  dns [LINK [SERVER...]]       Get/set per-interface DNS server address\n"
               "  domain [LINK [DOMAIN...]]    Get/set per-interface search domain\n"
               "  default-route [LINK [BOOL]]  Get/set per-interface default route flag\n"
               "  llmnr [LINK [MODE]]          Get/set per-interface LLMNR mode\n"
               "  mdns [LINK [MODE]]           Get/set per-interface MulticastDNS mode\n"
               "  dnsovertls [LINK [MODE]]     Get/set per-interface DNS-over-TLS mode\n"
               "  dnssec [LINK [MODE]]         Get/set per-interface DNSSEC mode\n"
               "  nta [LINK [DOMAIN...]]       Get/set per-interface DNSSEC NTA\n"
               "  revert LINK                  Revert per-interface configuration\n"
               "  log-level [LEVEL]            Get/set logging threshold for systemd-resolved\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                    Show this help\n"
               "     --version                 Show package version\n"
               "     --no-pager                Do not pipe output into a pager\n"
               "     --no-ask-password         Do not prompt for password\n"
               "  -4                           Resolve IPv4 addresses\n"
               "  -6                           Resolve IPv6 addresses\n"
               "  -i --interface=INTERFACE     Look on interface\n"
               "  -p --protocol=PROTO|help     Look via protocol\n"
               "  -t --type=TYPE|help          Query RR with DNS type\n"
               "  -c --class=CLASS|help        Query RR with DNS class\n"
               "     --service-address=BOOL    Resolve address for services (default: yes)\n"
               "     --service-txt=BOOL        Resolve TXT records for services (default: yes)\n"
               "     --cname=BOOL              Follow CNAME redirects (default: yes)\n"
               "     --validate=BOOL           Allow DNSSEC validation (default: yes)\n"
               "     --synthesize=BOOL         Allow synthetic response (default: yes)\n"
               "     --cache=BOOL              Allow response from cache (default: yes)\n"
               "     --stale-data=BOOL         Allow response from cache with stale data (default: yes)\n"
               "     --relax-single-label=BOOL Allow single label lookups to go upstream (default: no)\n"
               "     --zone=BOOL               Allow response from locally registered mDNS/LLMNR\n"
               "                               records (default: yes)\n"
               "     --trust-anchor=BOOL       Allow response from local trust anchor (default:\n"
               "                               yes)\n"
               "     --network=BOOL            Allow response from network (default: yes)\n"
               "     --search=BOOL             Use search domains for single-label names (default:\n"
               "                               yes)\n"
               "     --raw[=payload|packet]    Dump the answer as binary data\n"
               "     --legend=BOOL             Print headers and additional info (default: yes)\n"
               "     --json=MODE               Output as JSON\n"
               "  -j                           Same as --json=pretty on tty, --json=short\n"
               "                               otherwise\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return native_help();
}

static int compat_parse_argv(int argc, char *argv[]) {
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
                ARG_RESET_SERVER_FEATURES,
                ARG_NO_PAGER,
                ARG_SET_DNS,
                ARG_SET_DOMAIN,
                ARG_SET_LLMNR,
                ARG_SET_MDNS,
                ARG_SET_DNS_OVER_TLS,
                ARG_SET_DNSSEC,
                ARG_SET_NTA,
                ARG_REVERT_LINK,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'                       },
                { "version",               no_argument,       NULL, ARG_VERSION               },
                { "type",                  required_argument, NULL, 't'                       },
                { "class",                 required_argument, NULL, 'c'                       },
                { "legend",                required_argument, NULL, ARG_LEGEND                },
                { "interface",             required_argument, NULL, 'i'                       },
                { "protocol",              required_argument, NULL, 'p'                       },
                { "cname",                 required_argument, NULL, ARG_CNAME                 },
                { "service",               no_argument,       NULL, ARG_SERVICE               },
                { "service-address",       required_argument, NULL, ARG_SERVICE_ADDRESS       },
                { "service-txt",           required_argument, NULL, ARG_SERVICE_TXT           },
                { "openpgp",               no_argument,       NULL, ARG_OPENPGP               },
                { "tlsa",                  optional_argument, NULL, ARG_TLSA                  },
                { "raw",                   optional_argument, NULL, ARG_RAW                   },
                { "search",                required_argument, NULL, ARG_SEARCH                },
                { "statistics",            no_argument,       NULL, ARG_STATISTICS,           },
                { "reset-statistics",      no_argument,       NULL, ARG_RESET_STATISTICS      },
                { "status",                no_argument,       NULL, ARG_STATUS                },
                { "flush-caches",          no_argument,       NULL, ARG_FLUSH_CACHES          },
                { "reset-server-features", no_argument,       NULL, ARG_RESET_SERVER_FEATURES },
                { "no-pager",              no_argument,       NULL, ARG_NO_PAGER              },
                { "set-dns",               required_argument, NULL, ARG_SET_DNS               },
                { "set-domain",            required_argument, NULL, ARG_SET_DOMAIN            },
                { "set-llmnr",             required_argument, NULL, ARG_SET_LLMNR             },
                { "set-mdns",              required_argument, NULL, ARG_SET_MDNS              },
                { "set-dnsovertls",        required_argument, NULL, ARG_SET_DNS_OVER_TLS      },
                { "set-dnssec",            required_argument, NULL, ARG_SET_DNSSEC            },
                { "set-nta",               required_argument, NULL, ARG_SET_NTA               },
                { "revert",                no_argument,       NULL, ARG_REVERT_LINK           },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h46i:t:c:p:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return compat_help();

                case ARG_VERSION:
                        return version();

                case '4':
                        arg_family = AF_INET;
                        break;

                case '6':
                        arg_family = AF_INET6;
                        break;

                case 'i':
                        r = ifname_mangle(optarg);
                        if (r < 0)
                                return r;
                        break;

                case 't':
                        if (streq(optarg, "help")) {
                                help_dns_types();
                                return 0;
                        }

                        r = dns_type_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse RR record type %s: %m", optarg);

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
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse RR record class %s: %m", optarg);

                        arg_class = (uint16_t) r;
                        assert((int) arg_class == r);

                        break;

                case ARG_LEGEND:
                        r = parse_boolean_argument("--legend=", optarg, &arg_legend);
                        if (r < 0)
                                return r;
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
                        else if (streq(optarg, "mdns"))
                                arg_flags |= SD_RESOLVED_MDNS;
                        else if (streq(optarg, "mdns-ipv4"))
                                arg_flags |= SD_RESOLVED_MDNS_IPV4;
                        else if (streq(optarg, "mdns-ipv6"))
                                arg_flags |= SD_RESOLVED_MDNS_IPV6;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown protocol specifier: %s", optarg);

                        break;

                case ARG_SERVICE:
                        arg_mode = MODE_RESOLVE_SERVICE;
                        break;

                case ARG_OPENPGP:
                        arg_mode = MODE_RESOLVE_OPENPGP;
                        break;

                case ARG_TLSA:
                        arg_mode = MODE_RESOLVE_TLSA;
                        if (!optarg || service_family_is_valid(optarg))
                                arg_service_family = optarg;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown service family \"%s\".", optarg);
                        break;

                case ARG_RAW:
                        if (on_tty())
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                                       "Refusing to write binary data to tty.");

                        if (optarg == NULL || streq(optarg, "payload"))
                                arg_raw = RAW_PAYLOAD;
                        else if (streq(optarg, "packet"))
                                arg_raw = RAW_PACKET;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown --raw specifier \"%s\".",
                                                       optarg);

                        arg_legend = false;
                        break;

                case ARG_CNAME:
                        r = parse_boolean_argument("--cname=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_CNAME, r == 0);
                        break;

                case ARG_SERVICE_ADDRESS:
                        r = parse_boolean_argument("--service-address=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_ADDRESS, r == 0);
                        break;

                case ARG_SERVICE_TXT:
                        r = parse_boolean_argument("--service-txt=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_TXT, r == 0);
                        break;

                case ARG_SEARCH:
                        r = parse_boolean_argument("--search=", optarg, NULL);
                        if (r < 0)
                                return r;
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

                case ARG_RESET_SERVER_FEATURES:
                        arg_mode = MODE_RESET_SERVER_FEATURES;
                        break;

                case ARG_STATUS:
                        arg_mode = MODE_STATUS;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_SET_DNS:
                        r = strv_extend(&arg_set_dns, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_DOMAIN:
                        r = strv_extend(&arg_set_domain, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_LLMNR:
                        arg_set_llmnr = optarg;
                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_MDNS:
                        arg_set_mdns = optarg;
                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_DNS_OVER_TLS:
                        arg_set_dns_over_tls = optarg;
                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_DNSSEC:
                        arg_set_dnssec = optarg;
                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_SET_NTA:
                        r = strv_extend(&arg_set_nta, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_mode = MODE_SET_LINK;
                        break;

                case ARG_REVERT_LINK:
                        arg_mode = MODE_REVERT_LINK;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_type == 0 && arg_class != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--class= may only be used in conjunction with --type=.");

        if (arg_type != 0 && arg_mode == MODE_RESOLVE_SERVICE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--service and --type= may not be combined.");

        if (arg_type != 0 && arg_class == 0)
                arg_class = DNS_CLASS_IN;

        if (arg_class != 0 && arg_type == 0)
                arg_type = DNS_TYPE_A;

        if (IN_SET(arg_mode, MODE_SET_LINK, MODE_REVERT_LINK)) {

                if (arg_ifindex <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--set-dns=, --set-domain=, --set-llmnr=, --set-mdns=, --set-dnsovertls=, --set-dnssec=, --set-nta= and --revert require --interface=.");
        }

        return 1 /* work to do */;
}

static int native_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_LEGEND,
                ARG_CNAME,
                ARG_VALIDATE,
                ARG_SYNTHESIZE,
                ARG_CACHE,
                ARG_ZONE,
                ARG_TRUST_ANCHOR,
                ARG_NETWORK,
                ARG_SERVICE_ADDRESS,
                ARG_SERVICE_TXT,
                ARG_RAW,
                ARG_SEARCH,
                ARG_NO_PAGER,
                ARG_NO_ASK_PASSWORD,
                ARG_JSON,
                ARG_STALE_DATA,
                ARG_RELAX_SINGLE_LABEL,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'                       },
                { "version",               no_argument,       NULL, ARG_VERSION               },
                { "type",                  required_argument, NULL, 't'                       },
                { "class",                 required_argument, NULL, 'c'                       },
                { "legend",                required_argument, NULL, ARG_LEGEND                },
                { "interface",             required_argument, NULL, 'i'                       },
                { "protocol",              required_argument, NULL, 'p'                       },
                { "cname",                 required_argument, NULL, ARG_CNAME                 },
                { "validate",              required_argument, NULL, ARG_VALIDATE              },
                { "synthesize",            required_argument, NULL, ARG_SYNTHESIZE            },
                { "cache",                 required_argument, NULL, ARG_CACHE                 },
                { "zone",                  required_argument, NULL, ARG_ZONE                  },
                { "trust-anchor",          required_argument, NULL, ARG_TRUST_ANCHOR          },
                { "network",               required_argument, NULL, ARG_NETWORK               },
                { "service-address",       required_argument, NULL, ARG_SERVICE_ADDRESS       },
                { "service-txt",           required_argument, NULL, ARG_SERVICE_TXT           },
                { "raw",                   optional_argument, NULL, ARG_RAW                   },
                { "search",                required_argument, NULL, ARG_SEARCH                },
                { "no-pager",              no_argument,       NULL, ARG_NO_PAGER              },
                { "no-ask-password",       no_argument,       NULL, ARG_NO_ASK_PASSWORD       },
                { "json",                  required_argument, NULL, ARG_JSON                  },
                { "stale-data",            required_argument, NULL, ARG_STALE_DATA            },
                { "relax-single-label",    required_argument, NULL, ARG_RELAX_SINGLE_LABEL    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h46i:t:c:p:j", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return native_help();

                case ARG_VERSION:
                        return version();

                case '4':
                        arg_family = AF_INET;
                        break;

                case '6':
                        arg_family = AF_INET6;
                        break;

                case 'i':
                        r = ifname_mangle(optarg);
                        if (r < 0)
                                return r;
                        break;

                case 't':
                        if (streq(optarg, "help")) {
                                help_dns_types();
                                return 0;
                        }

                        r = dns_type_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse RR record type %s: %m", optarg);

                        arg_type = (uint16_t) r;
                        assert((int) arg_type == r);

                        break;

                case 'c':
                        if (streq(optarg, "help")) {
                                help_dns_classes();
                                return 0;
                        }

                        r = dns_class_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse RR record class %s: %m", optarg);

                        arg_class = (uint16_t) r;
                        assert((int) arg_class == r);

                        break;

                case ARG_LEGEND:
                        r = parse_boolean_argument("--legend=", optarg, &arg_legend);
                        if (r < 0)
                                return r;
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
                        else if (streq(optarg, "mdns"))
                                arg_flags |= SD_RESOLVED_MDNS;
                        else if (streq(optarg, "mdns-ipv4"))
                                arg_flags |= SD_RESOLVED_MDNS_IPV4;
                        else if (streq(optarg, "mdns-ipv6"))
                                arg_flags |= SD_RESOLVED_MDNS_IPV6;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown protocol specifier: %s",
                                                       optarg);

                        break;

                case ARG_RAW:
                        if (on_tty())
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                                       "Refusing to write binary data to tty.");

                        if (optarg == NULL || streq(optarg, "payload"))
                                arg_raw = RAW_PAYLOAD;
                        else if (streq(optarg, "packet"))
                                arg_raw = RAW_PACKET;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown --raw specifier \"%s\".",
                                                       optarg);

                        arg_legend = false;
                        break;

                case ARG_CNAME:
                        r = parse_boolean_argument("--cname=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_CNAME, r == 0);
                        break;

                case ARG_VALIDATE:
                        r = parse_boolean_argument("--validate=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_VALIDATE, r == 0);
                        break;

                case ARG_SYNTHESIZE:
                        r = parse_boolean_argument("--synthesize=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_SYNTHESIZE, r == 0);
                        break;

                case ARG_CACHE:
                        r = parse_boolean_argument("--cache=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_CACHE, r == 0);
                        break;

                case ARG_STALE_DATA:
                        r = parse_boolean_argument("--stale-data=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_STALE, r == 0);
                        break;

                case ARG_ZONE:
                        r = parse_boolean_argument("--zone=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_ZONE, r == 0);
                        break;

                case ARG_TRUST_ANCHOR:
                        r = parse_boolean_argument("--trust-anchor=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_TRUST_ANCHOR, r == 0);
                        break;

                case ARG_NETWORK:
                        r = parse_boolean_argument("--network=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_NETWORK, r == 0);
                        break;

                case ARG_SERVICE_ADDRESS:
                        r = parse_boolean_argument("--service-address=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_ADDRESS, r == 0);
                        break;

                case ARG_SERVICE_TXT:
                        r = parse_boolean_argument("--service-txt=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_TXT, r == 0);
                        break;

                case ARG_SEARCH:
                        r = parse_boolean_argument("--search=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_NO_SEARCH, r == 0);
                        break;

                case ARG_RELAX_SINGLE_LABEL:
                        r = parse_boolean_argument("--relax-single-label=", optarg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_flags, SD_RESOLVED_RELAX_SINGLE_LABEL, r > 0);
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_type == 0 && arg_class != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--class= may only be used in conjunction with --type=.");

        if (arg_type != 0 && arg_class == 0)
                arg_class = DNS_CLASS_IN;

        if (arg_class != 0 && arg_type == 0)
                arg_type = DNS_TYPE_A;

        return 1 /* work to do */;
}

static int native_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help",                  VERB_ANY, VERB_ANY, 0,            verb_help             },
                { "status",                VERB_ANY, VERB_ANY, VERB_DEFAULT, verb_status           },
                { "query",                 2,        VERB_ANY, 0,            verb_query            },
                { "service",               2,        4,        0,            verb_service          },
                { "openpgp",               2,        VERB_ANY, 0,            verb_openpgp          },
                { "tlsa",                  2,        VERB_ANY, 0,            verb_tlsa             },
                { "statistics",            VERB_ANY, 1,        0,            show_statistics       },
                { "reset-statistics",      VERB_ANY, 1,        0,            reset_statistics      },
                { "flush-caches",          VERB_ANY, 1,        0,            flush_caches          },
                { "reset-server-features", VERB_ANY, 1,        0,            reset_server_features },
                { "dns",                   VERB_ANY, VERB_ANY, 0,            verb_dns              },
                { "domain",                VERB_ANY, VERB_ANY, 0,            verb_domain           },
                { "default-route",         VERB_ANY, 3,        0,            verb_default_route    },
                { "llmnr",                 VERB_ANY, 3,        0,            verb_llmnr            },
                { "mdns",                  VERB_ANY, 3,        0,            verb_mdns             },
                { "dnsovertls",            VERB_ANY, 3,        0,            verb_dns_over_tls     },
                { "dnssec",                VERB_ANY, 3,        0,            verb_dnssec           },
                { "nta",                   VERB_ANY, VERB_ANY, 0,            verb_nta              },
                { "revert",                VERB_ANY, 2,        0,            verb_revert_link      },
                { "log-level",             VERB_ANY, 2,        0,            verb_log_level        },
                { "monitor",               VERB_ANY, 1,        0,            verb_monitor          },
                { "show-cache",            VERB_ANY, 1,        0,            verb_show_cache       },
                { "show-server-state",     VERB_ANY, 1,        0,            verb_show_server_state},
                {}
        };

        return dispatch_verb(argc, argv, verbs, /* userdata = */ NULL);
}

static int translate(const char *verb, const char *single_arg, size_t num_args, char **args) {
        char **fake, **p;
        size_t num;

        assert(verb);
        assert(num_args == 0 || args);

        num = !!single_arg + num_args + 1;

        p = fake = newa0(char *, num + 1);
        *p++ = (char *) verb;
        if (single_arg)
                *p++ = (char *) single_arg;
        FOREACH_ARRAY(arg, args, num_args)
                *p++ = *arg;

        optind = 0;
        return native_main((int) num, fake);
}

static int compat_main(int argc, char *argv[]) {
        int r = 0;

        switch (arg_mode) {
        case MODE_RESOLVE_HOST:
        case MODE_RESOLVE_RECORD:
                return translate("query", NULL, argc - optind, argv + optind);

        case MODE_RESOLVE_SERVICE:
                return translate("service", NULL, argc - optind, argv + optind);

        case MODE_RESOLVE_OPENPGP:
                return translate("openpgp", NULL, argc - optind, argv + optind);

        case MODE_RESOLVE_TLSA:
                return translate("tlsa", arg_service_family, argc - optind, argv + optind);

        case MODE_STATISTICS:
                return translate("statistics", NULL, 0, NULL);

        case MODE_RESET_STATISTICS:
                return translate("reset-statistics", NULL, 0, NULL);

        case MODE_FLUSH_CACHES:
                return translate("flush-caches", NULL, 0, NULL);

        case MODE_RESET_SERVER_FEATURES:
                return translate("reset-server-features", NULL, 0, NULL);

        case MODE_STATUS:
                return translate("status", NULL, argc - optind, argv + optind);

        case MODE_SET_LINK:
                assert(arg_ifname);

                if (arg_disable_default_route) {
                        r = translate("default-route", arg_ifname, 1, STRV_MAKE("no"));
                        if (r < 0)
                                return r;
                }

                if (arg_set_dns) {
                        r = translate("dns", arg_ifname, strv_length(arg_set_dns), arg_set_dns);
                        if (r < 0)
                                return r;
                }

                if (arg_set_domain) {
                        r = translate("domain", arg_ifname, strv_length(arg_set_domain), arg_set_domain);
                        if (r < 0)
                                return r;
                }

                if (arg_set_nta) {
                        r = translate("nta", arg_ifname, strv_length(arg_set_nta), arg_set_nta);
                        if (r < 0)
                                return r;
                }

                if (arg_set_llmnr) {
                        r = translate("llmnr", arg_ifname, 1, (char **) &arg_set_llmnr);
                        if (r < 0)
                                return r;
                }

                if (arg_set_mdns) {
                        r = translate("mdns", arg_ifname, 1, (char **) &arg_set_mdns);
                        if (r < 0)
                                return r;
                }

                if (arg_set_dns_over_tls) {
                        r = translate("dnsovertls", arg_ifname, 1, (char **) &arg_set_dns_over_tls);
                        if (r < 0)
                                return r;
                }

                if (arg_set_dnssec) {
                        r = translate("dnssec", arg_ifname, 1, (char **) &arg_set_dnssec);
                        if (r < 0)
                                return r;
                }

                return r;

        case MODE_REVERT_LINK:
                assert(arg_ifname);

                return translate("revert", arg_ifname, 0, NULL);

        case _MODE_INVALID:
                assert_not_reached();
        }

        return 0;
}

static int run(int argc, char **argv) {
        bool compat = false;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        if (invoked_as(argv, "resolvconf")) {
                compat = true;
                r = resolvconf_parse_argv(argc, argv);
        } else if (invoked_as(argv, "systemd-resolve")) {
                compat = true;
                r = compat_parse_argv(argc, argv);
        } else
                r = native_parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (compat)
                return compat_main(argc, argv);

        return native_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
