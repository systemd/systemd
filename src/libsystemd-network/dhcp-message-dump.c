/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "arphrd-util.h"
#include "dhcp-message-dump.h"
#include "dhcp-option.h"
#include "dhcp-route.h"
#include "dns-resolver-internal.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "format-table.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "iovec-wrapper.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

typedef enum DHCPOptionType {
        DHCP_OPTION_TYPE_AUTO,
        DHCP_OPTION_TYPE_HEX,
        DHCP_OPTION_TYPE_FLAG,
        DHCP_OPTION_TYPE_BOOL,
        DHCP_OPTION_TYPE_UINT8,
        DHCP_OPTION_TYPE_UINT16,
        DHCP_OPTION_TYPE_TIME,
        DHCP_OPTION_TYPE_STRING,
        DHCP_OPTION_TYPE_ADDRESS,
        _DHCP_OPTION_TYPE_AUTO_MAX,
        DHCP_OPTION_TYPE_SIP = _DHCP_OPTION_TYPE_AUTO_MAX,
        DHCP_OPTION_TYPE_FQDN,
        DHCP_OPTION_TYPE_ROUTE,
        DHCP_OPTION_TYPE_USER_CLASS,
        DHCP_OPTION_TYPE_VENDOR_SPECIFIC,
        DHCP_OPTION_TYPE_SEARCH_DOMAINS,
        DHCP_OPTION_TYPE_DNR,
        DHCP_OPTION_TYPE_6RD,
        _DHCP_OPTION_TYPE_MAX,
        _DHCP_OPTION_TYPE_INVALID = -EINVAL,
} DHCPOptionType;

static const char * const dhcp_option_type_table[_DHCP_OPTION_TYPE_AUTO_MAX] = {
        [DHCP_OPTION_TYPE_AUTO]    = "auto",
        [DHCP_OPTION_TYPE_HEX]     = "hex",
        [DHCP_OPTION_TYPE_FLAG]    = "flag",
        [DHCP_OPTION_TYPE_BOOL]    = "bool",
        [DHCP_OPTION_TYPE_UINT8]   = "uint8",
        [DHCP_OPTION_TYPE_UINT16]  = "uint16",
        [DHCP_OPTION_TYPE_TIME]    = "time",
        [DHCP_OPTION_TYPE_STRING]  = "string",
        [DHCP_OPTION_TYPE_ADDRESS] = "address",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_option_type, DHCPOptionType);

static DHCPOptionType dhcp_option_type_from_code(uint8_t code) {
        switch (code) {
        case SD_DHCP_OPTION_PAD:
                return -EINVAL;
        case SD_DHCP_OPTION_SUBNET_MASK:
        case SD_DHCP_OPTION_ROUTER:
        case SD_DHCP_OPTION_TIME_SERVER:
        case SD_DHCP_OPTION_NAME_SERVER:
        case SD_DHCP_OPTION_DOMAIN_NAME_SERVER:
        case SD_DHCP_OPTION_LOG_SERVER:
        case SD_DHCP_OPTION_QUOTES_SERVER:
        case SD_DHCP_OPTION_LPR_SERVER:
        case SD_DHCP_OPTION_IMPRESS_SERVER:
        case SD_DHCP_OPTION_RLP_SERVER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_HOST_NAME:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_BOOT_FILE_SIZE:
                return DHCP_OPTION_TYPE_UINT16;
        case SD_DHCP_OPTION_MERIT_DUMP_FILE:
        case SD_DHCP_OPTION_DOMAIN_NAME:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_SWAP_SERVER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_ROOT_PATH:
        case SD_DHCP_OPTION_EXTENSION_FILE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_FORWARD:
        case SD_DHCP_OPTION_SOURCE_ROUTE:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_MAX_DATAGRAM_ASSEMBLY:
                return DHCP_OPTION_TYPE_UINT16;
        case SD_DHCP_OPTION_DEFAULT_IP_TTL:
                return DHCP_OPTION_TYPE_UINT8;
        case SD_DHCP_OPTION_MTU_TIMEOUT:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_MTU_INTERFACE:
                return DHCP_OPTION_TYPE_UINT16;
        case SD_DHCP_OPTION_MTU_SUBNET:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_BROADCAST:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_MASK_DISCOVERY:
        case SD_DHCP_OPTION_MASK_SUPPLIER:
        case SD_DHCP_OPTION_ROUTER_DISCOVERY:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_ROUTER_REQUEST:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_STATIC_ROUTE:
                return DHCP_OPTION_TYPE_ROUTE;
        case SD_DHCP_OPTION_TRAILERS:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_ARP_TIMEOUT:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_ETHERNET:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_DEFAULT_TCP_TTL:
                return DHCP_OPTION_TYPE_UINT8;
        case SD_DHCP_OPTION_KEEPALIVE_TIME:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_KEEPALIVE_DATA:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_NIS_DOMAIN:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_NIS_SERVER:
        case SD_DHCP_OPTION_NTP_SERVER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_VENDOR_SPECIFIC:
                return DHCP_OPTION_TYPE_VENDOR_SPECIFIC;
        case SD_DHCP_OPTION_NETBIOS_NAME_SERVER:
        case SD_DHCP_OPTION_NETBIOS_DIST_SERVER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_NETBIOS_NODE_TYPE:
                return DHCP_OPTION_TYPE_UINT8;
        case SD_DHCP_OPTION_NETBIOS_SCOPE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_X_WINDOW_FONT:
        case SD_DHCP_OPTION_X_WINDOW_MANAGER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_REQUESTED_IP_ADDRESS:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_OVERLOAD:
        case SD_DHCP_OPTION_MESSAGE_TYPE:
                return DHCP_OPTION_TYPE_UINT8;
        case SD_DHCP_OPTION_SERVER_IDENTIFIER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_ERROR_MESSAGE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:
                return DHCP_OPTION_TYPE_UINT16;
        case SD_DHCP_OPTION_RENEWAL_TIME:
        case SD_DHCP_OPTION_REBINDING_TIME:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_NETWARE_IP_DOMAIN:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_NIS_DOMAIN_NAME:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_NIS_SERVER_ADDR:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_BOOT_SERVER_NAME:
        case SD_DHCP_OPTION_BOOT_FILENAME:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_HOME_AGENT_ADDRESS:
        case SD_DHCP_OPTION_SMTP_SERVER:
        case SD_DHCP_OPTION_POP3_SERVER:
        case SD_DHCP_OPTION_NNTP_SERVER:
        case SD_DHCP_OPTION_WWW_SERVER:
        case SD_DHCP_OPTION_FINGER_SERVER:
        case SD_DHCP_OPTION_IRC_SERVER:
        case SD_DHCP_OPTION_STREETTALK_SERVER:
        case SD_DHCP_OPTION_STDA_SERVER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_USER_CLASS:
                return DHCP_OPTION_TYPE_USER_CLASS;
        case SD_DHCP_OPTION_RAPID_COMMIT:
                return DHCP_OPTION_TYPE_FLAG;
        case SD_DHCP_OPTION_FQDN:
                return DHCP_OPTION_TYPE_FQDN;
        case SD_DHCP_OPTION_POSIX_TIMEZONE:
        case SD_DHCP_OPTION_TZDB_TIMEZONE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_IPV6_ONLY_PREFERRED:
                return DHCP_OPTION_TYPE_TIME;
        case SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_DOMAIN_SEARCH:
                return DHCP_OPTION_TYPE_SEARCH_DOMAINS;
        case SD_DHCP_OPTION_SIP_SERVER:
                return DHCP_OPTION_TYPE_SIP;
        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
                return DHCP_OPTION_TYPE_ROUTE;
        case SD_DHCP_OPTION_MUD_URL:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_V4_DNR:
                return DHCP_OPTION_TYPE_DNR;
        case SD_DHCP_OPTION_6RD:
                return DHCP_OPTION_TYPE_6RD;
        case SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE:
                return DHCP_OPTION_TYPE_ROUTE;
        case SD_DHCP_OPTION_END:
                return -EINVAL;
        default:
                return DHCP_OPTION_TYPE_HEX;
        }
}

static int dump_dhcp_option_hex(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, code, &len, (void**) &buf);
        if (r < 0)
                return log_error_errno(r, "Failed to read DHCP option %u: %m", code);

        _cleanup_free_ char *str = new(char, len * 3);
        if (!str)
                return log_oom();

        char *p = str;
        FOREACH_ARRAY(v, buf, len) {
                if (p != str)
                        *p++ = ':';
                *p++ = hexchar(*v >> 4);
                *p++ = hexchar(*v & 0x0f);
        }
        *p = '\0';

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRING, str);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_flag(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        r = dhcp_message_get_option_flag(message, code);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to dump DHCP option %u as flag: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_BOOLEAN, true);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_bool(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        uint8_t u;
        r = dhcp_message_get_option_u8(message, code, &u);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as boolean: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_BOOLEAN, !!u);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_uint8(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        uint8_t u;
        r = dhcp_message_get_option_u8(message, code, &u);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as uint8: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_UINT8, u);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_uint16(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        uint16_t u;
        r = dhcp_message_get_option_u16(message, code, &u);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as uint16: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_UINT16, u);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_time(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        usec_t usec;
        r = dhcp_message_get_option_sec(message, code, /* max_as_infinity= */ true, &usec);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as time: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_TIMESPAN, usec);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_string(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        _cleanup_free_ char *str = NULL;
        r = dhcp_message_get_option_string(message, code, &str);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as string: %m", code);
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRING, str);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_address(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        _cleanup_free_ struct in_addr *addrs = NULL;
        size_t n_addrs;
        r = dhcp_message_get_option_addresses(message, code, &n_addrs, &addrs);
        if (r < 0) {
                if (fallback)
                        return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);
                return log_error_errno(r, "Failed to read option %u as address: %m", code);
        }

        _cleanup_strv_free_ char **strv = NULL;
        size_t n_strv = 0;
        FOREACH_ARRAY(a, addrs, n_addrs) {
                r = strv_extend_with_size(&strv, &n_strv, IN4_ADDR_TO_STRING(a));
                if (r < 0)
                        return log_oom();
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_sip(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_SIP_SERVER);

        _cleanup_strv_free_ char **strv = NULL;
        if (dhcp_message_get_option_domains(message, code, &strv) < 0)
                return dump_dhcp_option_address(table, message, code, /* fallback= */ true);

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_fqdn(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_FQDN);

        _cleanup_free_ char *fqdn = NULL;
        uint8_t flags;
        if (dhcp_message_get_option_fqdn(message, &flags, &fqdn) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code));
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_cell_stringf(table, /* ret_cell= */ NULL, "flags: 0x%x, fqdn: %s", flags, fqdn);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_route(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);

        _cleanup_free_ sd_dhcp_route *routes = NULL;
        size_t n_routes;
        if (dhcp_message_get_option_routes(message, code, &n_routes, &routes) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        _cleanup_strv_free_ char **strv = NULL;
        size_t n_strv = 0;
        FOREACH_ARRAY(route, routes, n_routes) {
                r = strv_extendf_with_size(&strv, &n_strv, "%s via %s",
                                           IN4_ADDR_PREFIX_TO_STRING(&route->dst_addr, route->dst_prefixlen),
                                           IN4_ADDR_TO_STRING(&route->gw_addr));
                if (r < 0)
                        return log_oom();
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_user_class(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_USER_CLASS);

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        if (dhcp_message_get_option_user_class(message, &iovw) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        _cleanup_strv_free_ char **strv = NULL;
        size_t n_strv = 0;
        FOREACH_ARRAY(iov, iovw.iovec, iovw.count) {
                _cleanup_free_ char *escaped = cescape_length(iov->iov_base, iov->iov_len);
                if (!escaped)
                        return log_oom();

                r = strv_consume_with_size(&strv, &n_strv, TAKE_PTR(escaped));
                if (r < 0)
                        return log_oom();
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_vendor_specific(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_VENDOR_SPECIFIC);

        _cleanup_hashmap_free_ Hashmap *vendor_specific = NULL;
        if (dhcp_message_get_option_vendor_specific(message, &vendor_specific) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        /* Sort options by their option code, for reproducibility. */
        _cleanup_free_ sd_dhcp_option **options = NULL;
        size_t n;
        r = hashmap_dump_sorted(vendor_specific, (void***) &options, &n);
        if (r < 0)
                return log_oom();

        _cleanup_strv_free_ char **strv = NULL;
        size_t n_strv = 0;
        FOREACH_ARRAY(o, options, n) {
                size_t len = 0;
                LIST_FOREACH(option, i, *o)
                        len += i->length;

                _cleanup_free_ char *str = new(char, len * 3);
                if (!str)
                        return log_oom();

                char *p = str;
                LIST_FOREACH(option, i, *o)
                        FOREACH_ARRAY(v, i->data, i->length) {
                        if (p != str)
                                *p++ = ':';
                        *p++ = hexchar(*v >> 4);
                        *p++ = hexchar(*v & 0x0f);
                }
                *p = '\0';

                r = strv_extendf_with_size(&strv, &n_strv, "option: %u, data: %s", (*o)->option, str);
                if (r < 0)
                        return log_oom();
        }

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_search_domains(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_DOMAIN_SEARCH);

        _cleanup_strv_free_ char **strv = NULL;
        if (dhcp_message_get_option_domains(message, code, &strv) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_dnr(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_V4_DNR);

        sd_dns_resolver *resolvers = NULL;
        size_t n_resolvers = 0;
        CLEANUP_ARRAY(resolvers, n_resolvers, dns_resolver_free_array);

        if (dhcp_message_get_option_dnr(message, &n_resolvers, &resolvers) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        _cleanup_strv_free_ char **strv = NULL;
        r = dns_resolvers_to_dot_strv(resolvers, n_resolvers, &strv);
        if (r < 0)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code),
                        TABLE_STRV, strv);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_6rd(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback) {
        int r;

        assert(table);
        assert(message);
        assert(code == SD_DHCP_OPTION_6RD);

        uint8_t ipv4masklen, prefixlen;
        struct in6_addr prefix;
        size_t n_br_addresses;
        _cleanup_free_ struct in_addr *br_addresses = NULL;
        if (dhcp_message_get_option_6rd(message, &ipv4masklen, &prefixlen, &prefix, &n_br_addresses, &br_addresses) < 0)
                return dump_dhcp_option_hex(table, message, code, /* fallback= */ false);

        _cleanup_free_ char *str = asprintf_safe("ipv4masklen: %u, prefix: %s, br_addresses: ",
                                                 ipv4masklen, IN6_ADDR_PREFIX_TO_STRING(&prefix, prefixlen));
        if (!str)
                return log_oom();

        assert(n_br_addresses > 0);
        _cleanup_free_ char *br_addresses_str = NULL;
        FOREACH_ARRAY(a, br_addresses, n_br_addresses)
                if (!strextend_with_separator(&br_addresses_str, ", ", IN4_ADDR_TO_STRING(a)))
                        return log_oom();

        r = table_add_many(
                        table,
                        TABLE_UINT8, code,
                        TABLE_STRING, dhcp_option_code_to_string(code));
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_cell_stringf(table, /* ret_cell= */ NULL, "%s%s", str, br_addresses_str);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int dump_dhcp_option_one(Table *table, sd_dhcp_message *message, uint8_t code, DHCPOptionType type) {
        assert(table);
        assert(message);
        assert(!IN_SET(code, SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END));

        typedef int (*dump_dhcp_option_t)(Table *table, sd_dhcp_message *message, uint8_t code, bool fallback);

        static const dump_dhcp_option_t functions[_DHCP_OPTION_TYPE_MAX] = {
                [DHCP_OPTION_TYPE_HEX]             = dump_dhcp_option_hex,
                [DHCP_OPTION_TYPE_FLAG]            = dump_dhcp_option_flag,
                [DHCP_OPTION_TYPE_BOOL]            = dump_dhcp_option_bool,
                [DHCP_OPTION_TYPE_UINT8]           = dump_dhcp_option_uint8,
                [DHCP_OPTION_TYPE_UINT16]          = dump_dhcp_option_uint16,
                [DHCP_OPTION_TYPE_TIME]            = dump_dhcp_option_time,
                [DHCP_OPTION_TYPE_STRING]          = dump_dhcp_option_string,
                [DHCP_OPTION_TYPE_ADDRESS]         = dump_dhcp_option_address,
                [DHCP_OPTION_TYPE_SIP]             = dump_dhcp_option_sip,
                [DHCP_OPTION_TYPE_FQDN]            = dump_dhcp_option_fqdn,
                [DHCP_OPTION_TYPE_ROUTE]           = dump_dhcp_option_route,
                [DHCP_OPTION_TYPE_USER_CLASS]      = dump_dhcp_option_user_class,
                [DHCP_OPTION_TYPE_VENDOR_SPECIFIC] = dump_dhcp_option_vendor_specific,
                [DHCP_OPTION_TYPE_SEARCH_DOMAINS]  = dump_dhcp_option_search_domains,
                [DHCP_OPTION_TYPE_DNR]             = dump_dhcp_option_dnr,
                [DHCP_OPTION_TYPE_6RD]             = dump_dhcp_option_6rd,
        };

        bool fallback = false;
        if (type == DHCP_OPTION_TYPE_AUTO) {
                type = dhcp_option_type_from_code(code);
                fallback = true;
        }

        assert(functions[type]);
        return functions[type](table, message, code, fallback);
}

static void table_apply_flags(Table *table, DumpDHCPMessageFlag flags) {
        assert(table);

        table_set_header(table, FLAGS_SET(flags, DUMP_DHCP_MESSAGE_LEGEND));
        if (FLAGS_SET(flags, DUMP_DHCP_MESSAGE_FULL))
                table_set_width(table, 0);
}

int dump_dhcp_options(sd_dhcp_message *message, char * const *args, DumpDHCPMessageFlag flags) {
        int r;

        assert(message);

        _cleanup_(table_unrefp) Table *table = table_new("code", "name", "data");
        if (!table)
                return log_oom();

        table_apply_flags(table, flags);

        (void) table_set_sort(table, (size_t) 0);

        TableCell *cell = table_get_cell(table, 0, 0);
        if (!cell)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get table cell.");

        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        if (strv_isempty(args)) {
                sd_dhcp_option *option;
                HASHMAP_FOREACH(option, message->options) {
                        r = dump_dhcp_option_one(table, message, option->option, DHCP_OPTION_TYPE_AUTO);
                        if (r < 0)
                                return r;
                }

                return table_print_or_warn(table);
        }

        STRV_FOREACH(arg, args) {
                _cleanup_free_ char *buf = NULL;
                const char *code_str, *type_str;

                const char *colon = strchr(*arg, ':');
                if (colon) {
                        buf = strndup(*arg, colon - *arg);
                        if (!buf)
                                return log_oom();

                        code_str = buf;
                        type_str = colon + 1;
                } else {
                        code_str = *arg;
                        type_str = NULL;
                }

                uint8_t code;
                r = safe_atou8(code_str, &code);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse option code number '%s': %m", code_str);

                if (IN_SET(code, SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid option code number: %u", code);

                DHCPOptionType type = DHCP_OPTION_TYPE_AUTO;
                if (type_str) {
                        type = dhcp_option_type_from_string(type_str);
                        if (type < 0)
                                return log_error_errno(type, "Failed to parse option type '%s': %m", type_str);
                }

                r = dump_dhcp_option_one(table, message, code, type);
                if (r < 0)
                        return r;
        }

        return table_print_or_warn(table);
}

static int dump_buffer(Table *table, const char *field, uint8_t *buf, size_t len) {
        int r;

        assert(table);
        assert(field);
        assert(buf);
        assert(len > 0);

        uint8_t *nul = memchr(buf, 0, len);
        if (nul)
                len = nul - buf;

        if (len == 0)
                return 0;

        _cleanup_free_ char *str = NULL;
        r = make_cstring(buf, len, MAKE_CSTRING_REFUSE_TRAILING_NUL, &str);
        if (r < 0)
                return log_oom();

        if (isempty(str))
                return 0;

        r = table_add_many(
                        table,
                        TABLE_FIELD, field,
                        TABLE_STRING, str);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int dump_dhcp_header(sd_dhcp_message *message, DumpDHCPMessageFlag flags) {
        int r;

        assert(message);

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        table_apply_flags(table, flags);

        TableCell *cell = table_get_cell(table, 0, 0);
        if (!cell)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get table cell.");

        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        struct hw_addr_data hw_addr;
        r = dhcp_message_get_hw_addr(message, &hw_addr);
        if (r < 0)
                return log_error_errno(r, "Failed to get hardware address from DHCP message: %m");

        struct in_addr yiaddr = { .s_addr = message->header.yiaddr };

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Hardware Type",
                        TABLE_STRING, arphrd_to_name(message->header.htype),
                        TABLE_FIELD, "Hardware Address",
                        TABLE_STRING, HW_ADDR_TO_STR(&hw_addr),
                        TABLE_FIELD, "Client Address",
                        TABLE_STRING, IN4_ADDR_TO_STRING(&yiaddr));
        if (r < 0)
                return table_log_add_error(r);

        if (message->header.siaddr != INADDR_ANY) {
                struct in_addr siaddr = { .s_addr = message->header.siaddr };

                r = table_add_many(
                                table,
                                TABLE_FIELD, "Server Address",
                                TABLE_STRING, IN4_ADDR_TO_STRING(&siaddr));
                if (r < 0)
                        return table_log_add_error(r);
        }

        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (!FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                r = dump_buffer(table, "Server Host Name", message->header.sname, sizeof(message->header.sname));
                if (r < 0)
                        return r;
        }

        if (!FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                r = dump_buffer(table, "Boot File Name", message->header.file, sizeof(message->header.file));
                if (r < 0)
                        return r;
        }

        return table_print_or_warn(table);
}
