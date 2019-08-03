/* SPDX-License-Identifier: LGPL-2.1+ */

#include "networkd-dhcp-common.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-table.h"
#include "strv.h"

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

                if (streq(rvalue, "none"))
                        s = ADDRESS_FAMILY_NO;
                else if (streq(rvalue, "v4"))
                        s = ADDRESS_FAMILY_IPV4;
                else if (streq(rvalue, "v6"))
                        s = ADDRESS_FAMILY_IPV6;
                else if (streq(rvalue, "both"))
                        s = ADDRESS_FAMILY_YES;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
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

        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse UseDNS=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        network->dhcp_use_dns = r;
        network->dhcp6_use_dns = r;

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

        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse UseNTP=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        network->dhcp_use_ntp = r;
        network->dhcp6_use_ntp = r;

        return 0;
}

int config_parse_section_route_table(
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

        Network *network = data;
        uint32_t rt;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &rt);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse RouteTable=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        if (STRPTR_IN_SET(section, "DHCP", "DHCPv4")) {
                network->dhcp_route_table = rt;
                network->dhcp_route_table_set = true;
        } else { /* section is IPv6AcceptRA */
                network->ipv6_accept_ra_route_table = rt;
                network->ipv6_accept_ra_route_table_set = true;
        }

        return 0;
}

int config_parse_iaid(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {
        Network *network = data;
        uint32_t iaid;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(network);

        r = safe_atou32(rvalue, &iaid);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Unable to read IAID, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->iaid = iaid;
        network->iaid_set = true;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_use_domains, dhcp_use_domains, DHCPUseDomains,
                         "Failed to parse DHCP use domains setting");

static const char* const dhcp_use_domains_table[_DHCP_USE_DOMAINS_MAX] = {
        [DHCP_USE_DOMAINS_NO] = "no",
        [DHCP_USE_DOMAINS_ROUTE] = "route",
        [DHCP_USE_DOMAINS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dhcp_use_domains, DHCPUseDomains, DHCP_USE_DOMAINS_YES);
