/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>

#include "bus-error.h"
#include "bus-locator.h"
#include "dhcp-option.h"
#include "dhcp6-internal.h"
#include "escape.h"
#include "hexdecoct.h"
#include "in-addr-prefix-util.h"
#include "networkd-dhcp-common.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "vrf.h"

static uint32_t link_get_vrf_table(Link *link) {
        assert(link);
        assert(link->network);

        return link->network->vrf ? VRF(link->network->vrf)->table : RT_TABLE_MAIN;
}

uint32_t link_get_dhcp4_route_table(Link *link) {
        assert(link);
        assert(link->network);

        /* When the interface is part of an VRF use the VRFs routing table, unless
         * another table is explicitly specified. */

        if (link->network->dhcp_route_table_set)
                return link->network->dhcp_route_table;
        return link_get_vrf_table(link);
}

uint32_t link_get_ipv6_accept_ra_route_table(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->ipv6_accept_ra_route_table_set)
                return link->network->ipv6_accept_ra_route_table;
        return link_get_vrf_table(link);
}

bool link_dhcp_enabled(Link *link, int family) {
        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* Currently, sd-dhcp-client supports only ethernet and infiniband. */
        if (family == AF_INET && !IN_SET(link->iftype, ARPHRD_ETHER, ARPHRD_INFINIBAND))
                return false;

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (!link->network)
                return false;

        return link->network->dhcp & (family == AF_INET ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_IPV6);
}

void network_adjust_dhcp(Network *network) {
        assert(network);
        assert(network->dhcp >= 0);

        if (network->dhcp == ADDRESS_FAMILY_NO)
                return;

        /* Bonding slave does not support addressing. */
        if (network->bond) {
                log_warning("%s: Cannot enable DHCP= when Bond= is specified, disabling DHCP=.",
                            network->filename);
                network->dhcp = ADDRESS_FAMILY_NO;
                return;
        }

        if (!FLAGS_SET(network->link_local, ADDRESS_FAMILY_IPV6) &&
            FLAGS_SET(network->dhcp, ADDRESS_FAMILY_IPV6)) {
                log_warning("%s: DHCPv6 client is enabled but IPv6 link-local addressing is disabled. "
                            "Disabling DHCPv6 client.", network->filename);
                SET_FLAG(network->dhcp, ADDRESS_FAMILY_IPV6, false);
        }

        network_adjust_dhcp4(network);
}

static bool duid_needs_product_uuid(const DUID *duid) {
        assert(duid);

        return duid->type == DUID_TYPE_UUID && duid->raw_data_len == 0;
}

static const struct DUID fallback_duid = { .type = DUID_TYPE_EN };

const DUID *link_get_duid(Link *link, int family) {
        const DUID *duid;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (link->network) {
                duid = family == AF_INET ? &link->network->dhcp_duid : &link->network->dhcp6_duid;
                if (duid->type != _DUID_TYPE_INVALID) {
                        if (duid_needs_product_uuid(duid))
                                return &link->manager->duid_product_uuid;
                        else
                                return duid;
                }
        }

        duid = family == AF_INET ? &link->manager->dhcp_duid : &link->manager->dhcp6_duid;
        if (link->hw_addr.length == 0 && IN_SET(duid->type, DUID_TYPE_LLT, DUID_TYPE_LL))
                /* Fallback to DUID that works without MAC address.
                 * This is useful for tunnel devices without MAC address. */
                return &fallback_duid;

        return duid;
}

static int get_product_uuid_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        const void *a;
        size_t sz;
        int r;

        assert(m);

        /* To avoid calling GetProductUUID() bus method so frequently, set the flag below
         * even if the method fails. */
        manager->has_product_uuid = true;

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "Could not get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %s",
                                  bus_error_message(e, r));
                return 0;
        }

        r = sd_bus_message_read_array(m, 'y', &a, &sz);
        if (r < 0) {
                log_warning_errno(r, "Failed to get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %m");
                return 0;
        }

        if (sz != sizeof(sd_id128_t)) {
                log_warning("Invalid product UUID. Falling back to use machine-app-specific ID as DUID-UUID.");
                return 0;
        }

        log_debug("Successfully obtained product UUID");

        memcpy(&manager->duid_product_uuid.raw_data, a, sz);
        manager->duid_product_uuid.raw_data_len = sz;

        return 0;
}

int manager_request_product_uuid(Manager *m) {
        static bool bus_method_is_called = false;
        int r;

        assert(m);

        if (bus_method_is_called)
                return 0;

        if (sd_bus_is_ready(m->bus) <= 0 && !m->product_uuid_requested) {
                log_debug("Not connected to system bus, requesting product UUID later.");
                m->product_uuid_requested = true;
                return 0;
        }

        m->product_uuid_requested = false;

        r = bus_call_method_async(
                        m->bus,
                        NULL,
                        bus_hostname,
                        "GetProductUUID",
                        get_product_uuid_handler,
                        m,
                        "b",
                        false);
        if (r < 0)
                return log_warning_errno(r, "Failed to get product UUID: %m");

        log_debug("Requesting product UUID.");

        bus_method_is_called = true;

        return 0;
}

int dhcp_configure_duid(Link *link, const DUID *duid) {
        Manager *m;
        int r;

        assert(link);
        assert(link->manager);
        assert(duid);

        m = link->manager;

        if (!duid_needs_product_uuid(duid))
                return 1;

        if (m->has_product_uuid)
                return 1;

        r = manager_request_product_uuid(m);
        if (r < 0) {
                log_link_warning_errno(link, r,
                                       "Failed to get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %m");

                m->has_product_uuid = true; /* Do not request UUID again on failure. */
                return 1;
        }

        return 0;
}

bool address_is_filtered(int family, const union in_addr_union *address, uint8_t prefixlen, Set *allow_list, Set *deny_list) {
        struct in_addr_prefix *p;

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        if (allow_list) {
                SET_FOREACH(p, allow_list)
                        if (p->family == family &&
                            p->prefixlen <= prefixlen &&
                            in_addr_prefix_covers(family, &p->address, p->prefixlen, address) > 0)
                                return false;

                return true;
        }

        SET_FOREACH(p, deny_list)
                if (p->family == family &&
                    in_addr_prefix_intersect(family, &p->address, p->prefixlen, address, prefixlen) > 0)
                        return true;

        return false;
}

int link_get_captive_portal(Link *link, const char **ret) {
        const char *dhcp4_cp = NULL, *dhcp6_cp = NULL, *ndisc_cp = NULL;
        int r;

        assert(link);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        if (link->network->dhcp_use_captive_portal && link->dhcp_lease) {
                r = sd_dhcp_lease_get_captive_portal(link->dhcp_lease, &dhcp4_cp);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        if (link->network->dhcp6_use_captive_portal && link->dhcp6_lease) {
                r = sd_dhcp6_lease_get_captive_portal(link->dhcp6_lease, &dhcp6_cp);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        if (link->network->ipv6_accept_ra_use_captive_portal) {
                NDiscCaptivePortal *cp;
                usec_t usec = 0;

                /* Use the captive portal with the longest lifetime. */

                SET_FOREACH(cp, link->ndisc_captive_portals) {
                        if (cp->lifetime_usec < usec)
                                continue;

                        ndisc_cp = cp->captive_portal;
                        usec = cp->lifetime_usec;
                }

                if (set_size(link->ndisc_captive_portals) > 1)
                        log_link_debug(link, "Multiple captive portals obtained by IPv6RA, using \"%s\" and ignoring others.",
                                       ndisc_cp);
        }

        if (dhcp4_cp) {
                if (dhcp6_cp && !streq(dhcp4_cp, dhcp6_cp))
                        log_link_debug(link, "DHCPv6 captive portal (%s) does not match DHCPv4 (%s), ignoring DHCPv6 captive portal.",
                                       dhcp6_cp, dhcp4_cp);

                if (ndisc_cp && !streq(dhcp4_cp, ndisc_cp))
                        log_link_debug(link, "IPv6RA captive portal (%s) does not match DHCPv4 (%s), ignoring IPv6RA captive portal.",
                                       ndisc_cp, dhcp4_cp);

                *ret = dhcp4_cp;
                return 1;
        }

        if (dhcp6_cp) {
                if (ndisc_cp && !streq(dhcp6_cp, ndisc_cp))
                        log_link_debug(link, "IPv6RA captive portal (%s) does not match DHCPv6 (%s), ignoring IPv6RA captive portal.",
                                       ndisc_cp, dhcp6_cp);

                *ret = dhcp6_cp;
                return 1;
        }

        *ret = ndisc_cp;
        return !!ndisc_cp;
}

int config_parse_dhcp(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        AddressFamily *dhcp = data, s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Note that this is mostly like
         * config_parse_address_family(), except that it
         * understands some old names for the enum values */

        s = address_family_from_string(rvalue);
        if (s < 0) {

                /* Previously, we had a slightly different enum here,
                 * support its values for compatibility. */

                s = dhcp_deprecated_address_family_from_string(rvalue);
                if (s < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, s,
                                   "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }

                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCP=%s is deprecated, please use DHCP=%s instead.",
                           rvalue, address_family_to_string(s));
        }

        *dhcp = s;
        return 0;
}

int config_parse_dhcp_route_metric(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        uint32_t metric;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET));
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &metric);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse RouteMetric=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_route_metric = metric;
                network->dhcp_route_metric_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_route_metric_set)
                        network->dhcp_route_metric = metric;
                if (!network->ipv6_accept_ra_route_metric_set) {
                        network->ipv6_accept_ra_route_metric_high = metric;
                        network->ipv6_accept_ra_route_metric_medium = metric;
                        network->ipv6_accept_ra_route_metric_low = metric;
                }
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

int config_parse_ipv6_accept_ra_route_metric(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t metric_high, metric_medium, metric_low;
        int r, s, t;

        assert(filename);
        assert(rvalue);

        if (safe_atou32(rvalue, &metric_low) >= 0)
                metric_high = metric_medium = metric_low;
        else {
                _cleanup_free_ char *high = NULL, *medium = NULL, *low = NULL;
                const char *p = rvalue;

                r = extract_many_words(&p, ":", EXTRACT_DONT_COALESCE_SEPARATORS, &high, &medium, &low, NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r != 3 || !isempty(p)) {
                        log_syntax(unit, LOG_WARNING, filename, line, r < 0 ? r : 0,
                                   "Failed to parse RouteTable=%s, ignoring assignment: %m", rvalue);
                        return 0;
                }

                r = safe_atou32(high, &metric_high);
                s = safe_atou32(medium, &metric_medium);
                t = safe_atou32(low, &metric_low);
                if (r < 0 || s < 0 || t < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r < 0 ? r : s < 0 ? s : t,
                                   "Failed to parse RouteTable=%s, ignoring assignment: %m", rvalue);
                        return 0;
                }

                if (metric_high >= metric_medium || metric_medium >= metric_low) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid RouteTable=%s, ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

        network->ipv6_accept_ra_route_metric_high = metric_high;
        network->ipv6_accept_ra_route_metric_medium = metric_medium;
        network->ipv6_accept_ra_route_metric_low = metric_low;
        network->ipv6_accept_ra_route_metric_set = true;

        return 0;
}

int config_parse_dhcp_send_hostname(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SendHostname=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_send_hostname = r;
                network->dhcp_send_hostname_set = true;
                break;
        case AF_INET6:
                network->dhcp6_send_hostname = r;
                network->dhcp6_send_hostname_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_send_hostname_set)
                        network->dhcp_send_hostname = r;
                if (!network->dhcp6_send_hostname_set)
                        network->dhcp6_send_hostname = r;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}
int config_parse_dhcp_use_dns(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse UseDNS=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_use_dns = r;
                network->dhcp_use_dns_set = true;
                break;
        case AF_INET6:
                network->dhcp6_use_dns = r;
                network->dhcp6_use_dns_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_use_dns_set)
                        network->dhcp_use_dns = r;
                if (!network->dhcp6_use_dns_set)
                        network->dhcp6_use_dns = r;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

int config_parse_dhcp_use_domains(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        DHCPUseDomains d;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        d = dhcp_use_domains_from_string(rvalue);
        if (d < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, d,
                           "Failed to parse %s=%s, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_use_domains = d;
                network->dhcp_use_domains_set = true;
                break;
        case AF_INET6:
                network->dhcp6_use_domains = d;
                network->dhcp6_use_domains_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_use_domains_set)
                        network->dhcp_use_domains = d;
                if (!network->dhcp6_use_domains_set)
                        network->dhcp6_use_domains = d;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

int config_parse_dhcp_use_ntp(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse UseNTP=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_use_ntp = r;
                network->dhcp_use_ntp_set = true;
                break;
        case AF_INET6:
                network->dhcp6_use_ntp = r;
                network->dhcp6_use_ntp_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_use_ntp_set)
                        network->dhcp_use_ntp = r;
                if (!network->dhcp6_use_ntp_set)
                        network->dhcp6_use_ntp = r;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

int config_parse_dhcp_or_ra_route_table(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t rt;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_INET, AF_INET6));
        assert(rvalue);

        r = manager_get_route_table_from_string(network->manager, rvalue, &rt);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse RouteTable=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_route_table = rt;
                network->dhcp_route_table_set = true;
                break;
        case AF_INET6:
                network->ipv6_accept_ra_route_table = rt;
                network->ipv6_accept_ra_route_table_set = true;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

int config_parse_iaid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t iaid;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(IN_SET(ltype, AF_INET, AF_INET6));

        r = safe_atou32(rvalue, &iaid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Unable to read IAID, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (ltype == AF_INET) {
                network->dhcp_iaid = iaid;
                network->dhcp_iaid_set = true;
                if (!network->dhcp6_iaid_set_explicitly) {
                        /* Backward compatibility. Previously, IAID is shared by DHCPv4 and DHCPv6.
                         * If DHCPv6 IAID is not specified explicitly, then use DHCPv4 IAID for DHCPv6. */
                        network->dhcp6_iaid = iaid;
                        network->dhcp6_iaid_set = true;
                }
        } else {
                assert(ltype == AF_INET6);
                network->dhcp6_iaid = iaid;
                network->dhcp6_iaid_set = true;
                network->dhcp6_iaid_set_explicitly = true;
        }

        return 0;
}

int config_parse_dhcp_user_or_vendor_class(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***l = ASSERT_PTR(data);
        int r;

        assert(lvalue);
        assert(rvalue);
        assert(IN_SET(ltype, AF_INET, AF_INET6));

        if (isempty(rvalue)) {
                *l = strv_free(*l);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;
                size_t len;

                r = extract_first_word(&p, &w, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to split user classes option, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                len = strlen(w);
                if (ltype == AF_INET) {
                        if (len > UINT8_MAX || len == 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "%s length is not in the range 1…255, ignoring.", w);
                                continue;
                        }
                } else {
                        if (len > UINT16_MAX || len == 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "%s length is not in the range 1…65535, ignoring.", w);
                                continue;
                        }
                }

                r = strv_consume(l, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_dhcp_send_option(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(sd_dhcp_option_unrefp) sd_dhcp_option *opt4 = NULL;
        _cleanup_(sd_dhcp6_option_unrefp) sd_dhcp6_option *opt6 = NULL;
        _unused_ _cleanup_(sd_dhcp_option_unrefp) sd_dhcp_option *old4 = NULL;
        _unused_ _cleanup_(sd_dhcp6_option_unrefp) sd_dhcp6_option *old6 = NULL;
        uint32_t uint32_data, enterprise_identifier = 0;
        _cleanup_free_ char *word = NULL, *q = NULL;
        OrderedHashmap **options = ASSERT_PTR(data);
        uint16_t u16, uint16_data;
        union in_addr_union addr;
        DHCPOptionDataType type;
        uint8_t u8, uint8_data;
        const void *udata;
        const char *p;
        ssize_t sz;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *options = ordered_hashmap_free(*options);
                return 0;
        }

        p = rvalue;
        if (ltype == AF_INET6 && streq(lvalue, "SendVendorOption")) {
                r = extract_first_word(&p, &word, ":", 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r <= 0 || isempty(p)) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid DHCP option, ignoring assignment: %s", rvalue);
                        return 0;
                }

                r = safe_atou32(word, &enterprise_identifier);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCPv6 enterprise identifier data, ignoring assignment: %s", p);
                        return 0;
                }
                word = mfree(word);
        }

        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid DHCP option, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (ltype == AF_INET6) {
                r = safe_atou16(word, &u16);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid DHCP option, ignoring assignment: %s", rvalue);
                         return 0;
                }
                if (u16 < 1 || u16 >= UINT16_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid DHCP option, valid range is 1-65535, ignoring assignment: %s", rvalue);
                        return 0;
                }
        } else {
                r = safe_atou8(word, &u8);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid DHCP option, ignoring assignment: %s", rvalue);
                         return 0;
                }
                if (u8 < 1 || u8 >= UINT8_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid DHCP option, valid range is 1-254, ignoring assignment: %s", rvalue);
                        return 0;
                }
        }

        word = mfree(word);
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0 || isempty(p)) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid DHCP option, ignoring assignment: %s", rvalue);
                return 0;
        }

        type = dhcp_option_data_type_from_string(word);
        if (type < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, type,
                           "Invalid DHCP option data type, ignoring assignment: %s", p);
                return 0;
        }

        switch (type) {
        case DHCP_OPTION_DATA_UINT8:{
                r = safe_atou8(p, &uint8_data);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP uint8 data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = &uint8_data;
                sz = sizeof(uint8_t);
                break;
        }
        case DHCP_OPTION_DATA_UINT16:{
                uint16_t k;

                r = safe_atou16(p, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP uint16 data, ignoring assignment: %s", p);
                        return 0;
                }

                uint16_data = htobe16(k);
                udata = &uint16_data;
                sz = sizeof(uint16_t);
                break;
        }
        case DHCP_OPTION_DATA_UINT32: {
                uint32_t k;

                r = safe_atou32(p, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP uint32 data, ignoring assignment: %s", p);
                        return 0;
                }

                uint32_data = htobe32(k);
                udata = &uint32_data;
                sz = sizeof(uint32_t);

                break;
        }
        case DHCP_OPTION_DATA_IPV4ADDRESS: {
                r = in_addr_from_string(AF_INET, p, &addr);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP ipv4address data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = &addr.in;
                sz = sizeof(addr.in.s_addr);
                break;
        }
        case DHCP_OPTION_DATA_IPV6ADDRESS: {
                r = in_addr_from_string(AF_INET6, p, &addr);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP ipv6address data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = &addr.in6;
                sz = sizeof(addr.in6.s6_addr);
                break;
        }
        case DHCP_OPTION_DATA_STRING:
                sz = cunescape(p, UNESCAPE_ACCEPT_NUL, &q);
                if (sz < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, sz,
                                   "Failed to decode DHCP option data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = q;
                break;
        default:
                return -EINVAL;
        }

        if (ltype == AF_INET6) {
                r = sd_dhcp6_option_new(u16, udata, sz, enterprise_identifier, &opt6);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP option '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }

                r = ordered_hashmap_ensure_allocated(options, &dhcp6_option_hash_ops);
                if (r < 0)
                        return log_oom();

                /* Overwrite existing option */
                old6 = ordered_hashmap_get(*options, UINT_TO_PTR(u16));
                r = ordered_hashmap_replace(*options, UINT_TO_PTR(u16), opt6);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP option '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
                TAKE_PTR(opt6);
        } else {
                r = sd_dhcp_option_new(u8, udata, sz, &opt4);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP option '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }

                r = ordered_hashmap_ensure_allocated(options, &dhcp_option_hash_ops);
                if (r < 0)
                        return log_oom();

                /* Overwrite existing option */
                old4 = ordered_hashmap_get(*options, UINT_TO_PTR(u8));
                r = ordered_hashmap_replace(*options, UINT_TO_PTR(u8), opt4);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP option '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
                TAKE_PTR(opt4);
        }
        return 0;
}

int config_parse_dhcp_request_options(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                if (ltype == AF_INET)
                        network->dhcp_request_options = set_free(network->dhcp_request_options);
                else
                        network->dhcp6_request_options = set_free(network->dhcp6_request_options);

                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *n = NULL;
                uint32_t i;

                r = extract_first_word(&p, &n, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP request option, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = safe_atou32(n, &i);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "DHCP request option is invalid, ignoring assignment: %s", n);
                        continue;
                }

                if (i < 1 || i >= UINT8_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "DHCP request option is invalid, valid range is 1-254, ignoring assignment: %s", n);
                        continue;
                }

                r = set_ensure_put(ltype == AF_INET ? &network->dhcp_request_options : &network->dhcp6_request_options,
                                   NULL, UINT32_TO_PTR(i));
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP request option '%s', ignoring assignment: %m", n);
        }
}

static const char* const dhcp_use_domains_table[_DHCP_USE_DOMAINS_MAX] = {
        [DHCP_USE_DOMAINS_NO] = "no",
        [DHCP_USE_DOMAINS_ROUTE] = "route",
        [DHCP_USE_DOMAINS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dhcp_use_domains, DHCPUseDomains, DHCP_USE_DOMAINS_YES);

static const char * const dhcp_option_data_type_table[_DHCP_OPTION_DATA_MAX] = {
        [DHCP_OPTION_DATA_UINT8]       = "uint8",
        [DHCP_OPTION_DATA_UINT16]      = "uint16",
        [DHCP_OPTION_DATA_UINT32]      = "uint32",
        [DHCP_OPTION_DATA_STRING]      = "string",
        [DHCP_OPTION_DATA_IPV4ADDRESS] = "ipv4address",
        [DHCP_OPTION_DATA_IPV6ADDRESS] = "ipv6address",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp_option_data_type, DHCPOptionDataType);

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "link-layer-time",
        [DUID_TYPE_EN]   = "vendor",
        [DUID_TYPE_LL]   = "link-layer",
        [DUID_TYPE_UUID] = "uuid",
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(duid_type, DUIDType);

int config_parse_duid_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *type_string = NULL;
        const char *p = ASSERT_PTR(rvalue);
        bool force = ltype;
        DUID *duid = ASSERT_PTR(data);
        DUIDType type;
        int r;

        assert(filename);
        assert(lvalue);

        if (!force && duid->set)
                return 0;

        r = extract_first_word(&p, &type_string, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract DUID type from '%s', ignoring.", rvalue);
                return 0;
        }

        type = duid_type_from_string(type_string);
        if (type < 0) {
                uint16_t t;

                r = safe_atou16(type_string, &t);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DUID type '%s', ignoring.", type_string);
                        return 0;
                }

                type = t;
                assert(type == t); /* Check if type can store uint16_t. */
        }

        if (!isempty(p)) {
                usec_t u;

                if (type != DUID_TYPE_LLT) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = parse_timestamp(p, &u);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse timestamp, ignoring: %s", p);
                        return 0;
                }

                duid->llt_time = u;
        }

        duid->type = type;
        duid->set = force;

        return 0;
}

int config_parse_manager_duid_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *manager = ASSERT_PTR(userdata);
        int r;

        /* For backward compatibility. Setting both DHCPv4 and DHCPv6 DUID if they are not specified explicitly. */

        r = config_parse_duid_type(unit, filename, line, section, section_line, lvalue, false, rvalue, &manager->dhcp_duid, manager);
        if (r < 0)
                return r;

        return config_parse_duid_type(unit, filename, line, section, section_line, lvalue, false, rvalue, &manager->dhcp6_duid, manager);
}

int config_parse_network_duid_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        int r;

        r = config_parse_duid_type(unit, filename, line, section, section_line, lvalue, true, rvalue, &network->dhcp_duid, network);
        if (r < 0)
                return r;

        /* For backward compatibility, also set DHCPv6 DUID if not specified explicitly. */
        return config_parse_duid_type(unit, filename, line, section, section_line, lvalue, false, rvalue, &network->dhcp6_duid, network);
}

int config_parse_duid_rawdata(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint8_t raw_data[MAX_DUID_DATA_LEN];
        unsigned count = 0;
        bool force = ltype;
        DUID *duid = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (!force && duid->set)
                return 0;

        /* RawData contains DUID in format "NN:NN:NN..." */
        for (const char *p = rvalue;;) {
                int n1, n2, len, r;
                uint32_t byte;
                _cleanup_free_ char *cbyte = NULL;

                r = extract_first_word(&p, &cbyte, ":", 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to read DUID, ignoring assignment: %s.", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (count >= MAX_DUID_DATA_LEN) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Max DUID length exceeded, ignoring assignment: %s.", rvalue);
                        return 0;
                }

                len = strlen(cbyte);
                if (!IN_SET(len, 1, 2)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid length - DUID byte: %s, ignoring assignment: %s.", cbyte, rvalue);
                        return 0;
                }
                n1 = unhexchar(cbyte[0]);
                if (len == 2)
                        n2 = unhexchar(cbyte[1]);
                else
                        n2 = 0;

                if (n1 < 0 || n2 < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid DUID byte: %s. Ignoring assignment: %s.", cbyte, rvalue);
                        return 0;
                }

                byte = ((uint8_t) n1 << (4 * (len-1))) | (uint8_t) n2;
                raw_data[count++] = byte;
        }

        assert_cc(sizeof(raw_data) == sizeof(duid->raw_data));
        memcpy(duid->raw_data, raw_data, count);
        duid->raw_data_len = count;
        duid->set = force;

        return 0;
}

int config_parse_manager_duid_rawdata(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *manager = ASSERT_PTR(userdata);
        int r;

        /* For backward compatibility. Setting both DHCPv4 and DHCPv6 DUID if they are not specified explicitly. */

        r = config_parse_duid_rawdata(unit, filename, line, section, section_line, lvalue, false, rvalue, &manager->dhcp_duid, manager);
        if (r < 0)
                return r;

        return config_parse_duid_rawdata(unit, filename, line, section, section_line, lvalue, false, rvalue, &manager->dhcp6_duid, manager);
}

int config_parse_network_duid_rawdata(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        int r;

        r = config_parse_duid_rawdata(unit, filename, line, section, section_line, lvalue, true, rvalue, &network->dhcp_duid, network);
        if (r < 0)
                return r;

        /* For backward compatibility, also set DHCPv6 DUID if not specified explicitly. */
        return config_parse_duid_rawdata(unit, filename, line, section, section_line, lvalue, false, rvalue, &network->dhcp6_duid, network);
}

int config_parse_uplink(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        bool accept_none = true;
        int *index, r;
        char **name;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (streq(section, "DHCPServer")) {
                index = &network->dhcp_server_uplink_index;
                name = &network->dhcp_server_uplink_name;
        } else if (streq(section, "IPv6SendRA")) {
                index = &network->router_uplink_index;
                name = &network->router_uplink_name;
        } else if (STR_IN_SET(section, "DHCPv6PrefixDelegation", "DHCPPrefixDelegation")) {
                index = &network->dhcp_pd_uplink_index;
                name = &network->dhcp_pd_uplink_name;
                accept_none = false;
        } else
                assert_not_reached();

        if (isempty(rvalue) || streq(rvalue, ":auto")) {
                *index = UPLINK_INDEX_AUTO;
                *name = mfree(*name);
                return 0;
        }

        if (accept_none && streq(rvalue, ":none")) {
                *index = UPLINK_INDEX_NONE;
                *name = mfree(*name);
                return 0;
        }

        if (!accept_none && streq(rvalue, ":self")) {
                *index = UPLINK_INDEX_SELF;
                *name = mfree(*name);
                return 0;
        }

        r = parse_ifindex(rvalue);
        if (r > 0) {
                *index = r;
                *name = mfree(*name);
                return 0;
        }

        if (!ifname_valid_full(rvalue, IFNAME_VALID_ALTERNATIVE)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid interface name in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        /* The interface name will be resolved later. */
        r = free_and_strdup_warn(name, rvalue);
        if (r < 0)
                return r;

        /* Note, if uplink_name is set, then uplink_index will be ignored. So, the below does not mean
         * an uplink interface will be selected automatically. */
        *index = UPLINK_INDEX_AUTO;
        return 0;
}
