/* SPDX-License-Identifier: LGPL-2.1+ */

#include "dhcp-internal.h"
#include "dhcp6-client-internal.h"
#include "escape.h"
#include "in-addr-util.h"
#include "networkd-dhcp-common.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-table.h"
#include "strv.h"
#include "web-util.h"

static int parse_dhcp_data(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *value,
                           DHCPOptionDataType type,
                           void **data,
                           ssize_t *length) {

        _cleanup_free_ char *q = NULL, *udata = NULL;
        union in_addr_union addr;
        uint32_t uint32_data;
        uint16_t uint16_data;
        uint8_t uint8_data;
        const char *p;
        ssize_t sz;
        int r;

        assert(type >= 0);
        assert(value);
        assert(data);
        assert(length);

        p = value;
        switch(type) {
        case DHCP_OPTION_DATA_UINT8:{
                r = safe_atou8(p, &uint8_data);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DHCP uint8 data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = memdup(&uint8_data, sizeof(uint8_t));
                if (!udata)
                        return log_oom();

                sz = sizeof(uint8_t);
                break;
        }
        case DHCP_OPTION_DATA_UINT16:{
                r = safe_atou16(p, &uint16_data);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DHCP uint16 data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = memdup(&uint16_data, sizeof(uint16_t));
                if (!udata)
                        return log_oom();

                sz = sizeof(uint16_t);
                break;
        }
        case DHCP_OPTION_DATA_UINT32: {
                r = safe_atou32(p, &uint32_data);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DHCP uint32 data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = memdup(&uint32_data, sizeof(uint32_t));
                if (!udata)
                        return log_oom();

                sz = sizeof(uint32_t);

                break;
        }
        case DHCP_OPTION_DATA_IPV4ADDRESS: {
                r = in_addr_from_string(AF_INET, p, &addr);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DHCP ipv4address data, ignoring assignment: %s", p);
                        return 0;
                }

                udata = memdup(&addr.in, sizeof(addr.in.s_addr));
                if (!udata)
                        return log_oom();

                sz = sizeof(addr.in.s_addr);
                break;
        }
        case DHCP_OPTION_DATA_STRING:
                sz = cunescape(p, UNESCAPE_ACCEPT_NUL, &q);
                if (sz < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, sz,
                                   "Failed to decode DHCP option data, ignoring assignment: %s", p);
                }

                udata = TAKE_PTR(q);

                break;
        default:
                return -EINVAL;
        }

        *data = TAKE_PTR(udata);
        *length = sz;

        return 0;
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

int config_parse_dhcp_use_sip(
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
                           "Failed to parse UseSIP=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        network->dhcp_use_sip = r;

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

int config_parse_dhcp6_pd_hint(
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

        r = in_addr_prefix_from_string(rvalue, AF_INET6, (union in_addr_union *) &network->dhcp6_pd_address, &network->dhcp6_pd_length);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse PrefixDelegationHint=%s, ignoring assignment", rvalue);
                return 0;
        }

        if (network->dhcp6_pd_length < 1 || network->dhcp6_pd_length > 128) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid prefix length='%d', ignoring assignment", network->dhcp6_pd_length);
                network->dhcp6_pd_length = 0;
                return 0;
        }

        return 0;
}

int config_parse_dhcp6_mud_url(
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

        _cleanup_free_ char *unescaped = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp6_mudurl = mfree(network->dhcp6_mudurl);
                return 0;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to Failed to unescape MUD URL, ignoring: %s", rvalue);
                return 0;
        }

        if (!http_url_is_valid(unescaped) || strlen(unescaped) > 255) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Failed to parse MUD URL '%s', ignoring: %m", rvalue);

                return 0;
        }

        return free_and_replace(network->dhcp6_mudurl, unescaped);
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

        _cleanup_(sd_dhcp_option_unrefp) sd_dhcp_option *opt = NULL, *old = NULL;
        _cleanup_free_ void *udata = NULL;
        _cleanup_free_ char *word = NULL;
        OrderedHashmap **options = data;
        DHCPOptionDataType type;
        uint8_t u;
        const char *p;
        ssize_t sz;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *options = ordered_hashmap_free(*options);
                return 0;
        }

        p = rvalue;
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP option, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = safe_atou8(word, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP option, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (u < 1 || u >= 255) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid DHCP option, valid range is 1-254, ignoring assignment: %s", rvalue);
                return 0;
        }

        word = mfree(word);
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP option, ignoring assignment: %s", rvalue);
                return 0;
        }

        type = dhcp_option_data_type_from_string(word);
        if (type < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid DHCP option data type, ignoring assignment: %s", p);
                return 0;
        }

        r = parse_dhcp_data(unit, filename, line, p, type, &udata, &sz);
        if (r < 0)
                return r;

        r = sd_dhcp_option_new(u, udata, sz, &opt);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to store DHCPv4 option '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        r = ordered_hashmap_ensure_allocated(options, &dhcp_option_hash_ops);
        if (r < 0)
                return log_oom();

        /* Overwrite existing option */
        old = ordered_hashmap_remove(*options, UINT_TO_PTR(u));
        r = ordered_hashmap_put(*options, UINT_TO_PTR(u), opt);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to store DHCPv4 option '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        TAKE_PTR(opt);
        return 0;
}

int config_parse_dhcp_send6_option(
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

        _cleanup_(sd_dhcp6_option_unrefp) sd_dhcp6_option *opt6 = NULL, *old = NULL;
        _cleanup_free_ void  *udata = NULL;
        _cleanup_free_ char *word = NULL;
        OrderedHashmap **options = data;
        DHCPOptionDataType type;
        const char *p;
        ssize_t sz;
        uint8_t u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *options = ordered_hashmap_free(*options);
                return 0;
        }

        p = rvalue;
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP6 option, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = safe_atou8(word, &u);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP6 option, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (u < 1 || u >= 255) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid DHCP6 option, valid range is 1-254, ignoring assignment: %s", rvalue);
                return 0;
        }

        word = mfree(word);
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid DHCP6 option, ignoring assignment: %s", rvalue);
                return 0;
        }

        type = dhcp_option_data_type_from_string(word);
        if (type < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid DHCP6 option data type, ignoring assignment: %s", p);
                return 0;
        }

        r = parse_dhcp_data(unit, filename, line, p, type, &udata, &sz);
        if (r < 0)
                return r;

        r = sd_dhcp6_option_new(u, udata, sz, &opt6);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to store DHCPv6 option '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        r = ordered_hashmap_ensure_allocated(options, &dhcp_option_hash_ops);
        if (r < 0)
                return log_oom();

        /* Overwrite existing option */
        old = ordered_hashmap_remove(*options, UINT_TO_PTR(u));
        r = ordered_hashmap_put(*options, UINT_TO_PTR(u), opt6);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to store DHCPv6 option '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        TAKE_PTR(opt6);
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

static const char * const dhcp_option_data_type_table[_DHCP_OPTION_DATA_MAX] = {
        [DHCP_OPTION_DATA_UINT8]       = "uint8",
        [DHCP_OPTION_DATA_UINT16]      = "uint16",
        [DHCP_OPTION_DATA_UINT32]      = "uint32",
        [DHCP_OPTION_DATA_STRING]      = "string",
        [DHCP_OPTION_DATA_IPV4ADDRESS] = "ipv4address",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp_option_data_type, DHCPOptionDataType);
