/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "dhcp-option.h"
#include "format-table.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "networkctl.h"
#include "networkctl-dhcp-option.h"
#include "networkctl-link-info.h"
#include "networkctl-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "strv.h"

typedef enum DHCPOptionType {
        DHCP_OPTION_TYPE_AUTO,
        DHCP_OPTION_TYPE_FLAG,
        DHCP_OPTION_TYPE_BOOL,
        DHCP_OPTION_TYPE_U8,
        DHCP_OPTION_TYPE_U16,
        DHCP_OPTION_TYPE_SEC,
        DHCP_OPTION_TYPE_STRING,
        DHCP_OPTION_TYPE_ADDRESS,
        DHCP_OPTION_TYPE_HEX,
        _DHCP_OPTION_TYPE_AUTO_MAX,
        DHCP_OPTION_TYPE_FQDN = _DHCP_OPTION_TYPE_AUTO_MAX,
        DHCP_OPTION_TYPE_SIP,
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
        [DHCP_OPTION_TYPE_FLAG]    = "flag",
        [DHCP_OPTION_TYPE_BOOL]    = "bool",
        [DHCP_OPTION_TYPE_U8]      = "u8",
        [DHCP_OPTION_TYPE_U16]     = "u16",
        [DHCP_OPTION_TYPE_SEC]     = "time",
        [DHCP_OPTION_TYPE_STRING]  = "string",
        [DHCP_OPTION_TYPE_ADDRESS] = "address",
        [DHCP_OPTION_TYPE_HEX]     = "hex",
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
                return DHCP_OPTION_TYPE_U16;
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
        case SD_DHCP_OPTION_POLICY_FILTER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_MAX_DATAGRAM_ASSEMBLY:
                return DHCP_OPTION_TYPE_U16;
        case SD_DHCP_OPTION_DEFAULT_IP_TTL:
                return DHCP_OPTION_TYPE_U8;
        case SD_DHCP_OPTION_MTU_TIMEOUT:
                return DHCP_OPTION_TYPE_SEC;
        case SD_DHCP_OPTION_MTU_INTERFACE:
                return DHCP_OPTION_TYPE_U16;
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
                return DHCP_OPTION_TYPE_SEC;
        case SD_DHCP_OPTION_ETHERNET:
                return DHCP_OPTION_TYPE_BOOL;
        case SD_DHCP_OPTION_DEFAULT_TCP_TTL:
                return DHCP_OPTION_TYPE_U8;
        case SD_DHCP_OPTION_KEEPALIVE_TIME:
                return DHCP_OPTION_TYPE_SEC;
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
                return DHCP_OPTION_TYPE_U8;
        case SD_DHCP_OPTION_NETBIOS_SCOPE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_X_WINDOW_FONT:
        case SD_DHCP_OPTION_X_WINDOW_MANAGER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_REQUESTED_IP_ADDRESS:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                return DHCP_OPTION_TYPE_SEC;
        case SD_DHCP_OPTION_OVERLOAD:
        case SD_DHCP_OPTION_MESSAGE_TYPE:
                return DHCP_OPTION_TYPE_U8;
        case SD_DHCP_OPTION_SERVER_IDENTIFIER:
                return DHCP_OPTION_TYPE_ADDRESS;
        case SD_DHCP_OPTION_ERROR_MESSAGE:
                return DHCP_OPTION_TYPE_STRING;
        case SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:
                return DHCP_OPTION_TYPE_U16;
        case SD_DHCP_OPTION_RENEWAL_TIME:
        case SD_DHCP_OPTION_REBINDING_TIME:
                return DHCP_OPTION_TYPE_SEC;
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
        case SD_DHCP_OPTION_HOME_AGENT_ADDRESSES:
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
                return DHCP_OPTION_TYPE_SEC;
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

static int dump_dhcp_option_one(Table *table, sd_dhcp_message *message, uint8_t code, DHCPOptionType type) {
        int r;

        assert(table);
        assert(message);

        if (type == DHCP_OPTION_TYPE_AUTO)
                type = dhcp_option_type_from_code(code);

        r = table_add_many(table,
                           TABLE_UINT8, code,
                           TABLE_STRING, dhcp_option_code_to_string(code));
        if (r < 0)
                return r;

        switch (type) {
        case DHCP_OPTION_TYPE_FLAG: {
                r = dhcp_message_get_option_flag(message, code);
                if (r < 0)
                        return r;

                bool b = true;
                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_BOOLEAN, &b);
        }
        case DHCP_OPTION_TYPE_BOOL: {
                uint8_t u8;
                r = dhcp_message_get_option_u8(message, code, &u8);
                if (r < 0)
                        return r;

                bool b = u8;
                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_BOOLEAN, &b);
        }
        case DHCP_OPTION_TYPE_U8: {
                uint8_t u8;
                r = dhcp_message_get_option_u8(message, code, &u8);
                if (r < 0)
                        return r;

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_UINT8, &u8);
        }
        case DHCP_OPTION_TYPE_U16: {
                uint16_t u16;
                r = dhcp_message_get_option_u16(message, code, &u16);
                if (r < 0)
                        return r;

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_UINT16, &u16);
        }
        case DHCP_OPTION_TYPE_SEC: {
                usec_t usec;
                r = dhcp_message_get_option_sec(message, code, /* max_as_infinity= */ true, &usec);
                if (r < 0)
                        return r;

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_TIMESPAN, &usec);
        }
        case DHCP_OPTION_TYPE_STRING: {
                _cleanup_free_ char *str = NULL;
                r = dhcp_message_get_option_string(message, code, &str);
                if (r < 0)
                        return r;

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_STRING, str);
        }
        case DHCP_OPTION_TYPE_ADDRESS: {
                _cleanup_free_ struct in_addr *addrs = NULL;
                size_t n_addrs;
                r = dhcp_message_get_option_addresses(message, code, &n_addrs, &addrs);
                if (r < 0)
                        return r;

                _cleanup_strv_free_ char **strv = NULL;
                size_t n_strv = 0;
                FOREACH_ARRAY(a, addrs, n_addrs) {
                        r = strv_extend_with_size(&strv, &n_strv, IN4_ADDR_TO_STRING(a));
                        if (r < 0)
                                return r;
                }

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_STRV, strv);
        }
        case DHCP_OPTION_TYPE_HEX: {
                _cleanup_free_ uint8_t *buf = NULL;
                size_t len;
                r = dhcp_message_get_option_alloc(message, code, &len, (void**) &buf);
                if (r < 0)
                        return r;

                _cleanup_free_ char *str = new(char, len * 3);
                if (!str)
                        return -ENOMEM;

                char *p = str;
                FOREACH_ARRAY(v, buf, len) {
                        if (p != str)
                                *p++ = ':';
                        *p++ = hexchar(*v >> 4);
                        *p++ = hexchar(*v & 0x0f);
                }
                *p = '\0';

                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_STRING, str);
        }
        case DHCP_OPTION_TYPE_FQDN:
        case DHCP_OPTION_TYPE_SIP:
        case DHCP_OPTION_TYPE_ROUTE:
        case DHCP_OPTION_TYPE_USER_CLASS:
        case DHCP_OPTION_TYPE_VENDOR_SPECIFIC:
        case DHCP_OPTION_TYPE_SEARCH_DOMAINS:
        case DHCP_OPTION_TYPE_DNR:
                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_STRING, "TBD");
        default:
                assert_not_reached();
        }
}

static int dump_dhcp_options(Table *table, sd_dhcp_message *message, char * const *args) {
        int r;

        assert(table);
        assert(message);

        if (strv_isempty(args)) {
                sd_dhcp_option *option;
                HASHMAP_FOREACH(option, message->options) {
                        r = dump_dhcp_option_one(table, message, option->option, DHCP_OPTION_TYPE_AUTO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to dump DHCP option %u: %m", option->option);
                }

                return 0;
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
                        return log_error_errno(r, "Failed to dump DHCP option %u: %m", code);
        }

        return 0;
}

int verb_dhcp_option(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        /* networkctl dhcp-option INTERFACE [CODE[:TYPE] ...] */
        assert(argc >= 2);

        pager_open(arg_pager_flags);

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

        const char *ifname = argv[1];

        _cleanup_(link_info_array_freep) LinkInfo *link = NULL;
        r = acquire_link_info(vl, rtnl, STRV_MAKE(ifname), &link);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL; /* already logged in acquire_link_info(). */
        if (r > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Interface name '%s' matches multiple interfaces.", ifname);

        if (!link->dhcp_message)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Interface '%s' does not have DHCPv4 lease.", link->name);

        _cleanup_(table_unrefp) Table *table = table_new("code", "description", "data");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, (size_t) 0);

        TableCell *cell = table_get_cell(table, 0, 0);
        if (!cell)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get table cell.");

        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        r = dump_dhcp_options(table, link->dhcp_message, strv_skip(argv, 2));
        if (r < 0)
                return r;

        return table_print_or_warn(table);
}
