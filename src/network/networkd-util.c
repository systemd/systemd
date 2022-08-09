/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "condition.h"
#include "conf-parser.h"
#include "escape.h"
#include "networkd-link.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "web-util.h"

/* This is used in log messages, and never used in parsing settings. So, upper cases are OK. */
static const char * const network_config_source_table[_NETWORK_CONFIG_SOURCE_MAX] = {
        [NETWORK_CONFIG_SOURCE_FOREIGN] = "foreign",
        [NETWORK_CONFIG_SOURCE_STATIC]  = "static",
        [NETWORK_CONFIG_SOURCE_IPV4LL]  = "IPv4LL",
        [NETWORK_CONFIG_SOURCE_DHCP4]   = "DHCPv4",
        [NETWORK_CONFIG_SOURCE_DHCP6]   = "DHCPv6",
        [NETWORK_CONFIG_SOURCE_DHCP_PD] = "DHCP-PD",
        [NETWORK_CONFIG_SOURCE_NDISC]   = "NDisc",
        [NETWORK_CONFIG_SOURCE_RUNTIME] = "runtime",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(network_config_source, NetworkConfigSource);

int network_config_state_to_string_alloc(NetworkConfigState s, char **ret) {
        static const char* states[] = {
                [LOG2U(NETWORK_CONFIG_STATE_REQUESTING)]  = "requesting",
                [LOG2U(NETWORK_CONFIG_STATE_CONFIGURING)] = "configuring",
                [LOG2U(NETWORK_CONFIG_STATE_CONFIGURED)]  = "configured",
                [LOG2U(NETWORK_CONFIG_STATE_MARKED)]      = "marked",
                [LOG2U(NETWORK_CONFIG_STATE_REMOVING)]    = "removing",
        };
        _cleanup_free_ char *buf = NULL;

        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(states); i++)
                if (FLAGS_SET(s, 1 << i)) {
                        assert(states[i]);

                        if (!strextend_with_separator(&buf, ",", states[i]))
                                return -ENOMEM;
                }

        *ret = TAKE_PTR(buf);
        return 0;
}

static const char * const address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "no",
        [ADDRESS_FAMILY_YES]  = "yes",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char * const routing_policy_rule_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char * const nexthop_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char * const duplicate_address_detection_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "none",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char * const dhcp_deprecated_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "none",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "v4",
        [ADDRESS_FAMILY_IPV6] = "v6",
};

static const char * const ip_masquerade_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "no",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char * const dhcp_lease_server_type_table[_SD_DHCP_LEASE_SERVER_TYPE_MAX] = {
        [SD_DHCP_LEASE_DNS]  = "DNS servers",
        [SD_DHCP_LEASE_NTP]  = "NTP servers",
        [SD_DHCP_LEASE_SIP]  = "SIP servers",
        [SD_DHCP_LEASE_POP3] = "POP3 servers",
        [SD_DHCP_LEASE_SMTP] = "SMTP servers",
        [SD_DHCP_LEASE_LPR]  = "LPR servers",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(address_family, AddressFamily, ADDRESS_FAMILY_YES);

AddressFamily link_local_address_family_from_string(const char *s) {
        if (streq_ptr(s, "fallback"))         /* compat name */
                return ADDRESS_FAMILY_YES;
        if (streq_ptr(s, "fallback-ipv4"))    /* compat name */
                return ADDRESS_FAMILY_IPV4;
        return address_family_from_string(s);
}

DEFINE_STRING_TABLE_LOOKUP(routing_policy_rule_address_family, AddressFamily);
DEFINE_STRING_TABLE_LOOKUP(nexthop_address_family, AddressFamily);
DEFINE_STRING_TABLE_LOOKUP(duplicate_address_detection_address_family, AddressFamily);
DEFINE_CONFIG_PARSE_ENUM(config_parse_link_local_address_family, link_local_address_family,
                         AddressFamily, "Failed to parse option");
DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_deprecated_address_family, AddressFamily);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(ip_masquerade_address_family, AddressFamily);
DEFINE_STRING_TABLE_LOOKUP(dhcp_lease_server_type, sd_dhcp_lease_server_type_t);

int config_parse_address_family_with_kernel(
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

        AddressFamily *fwd = data, s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* This function is mostly obsolete now. It simply redirects
         * "kernel" to "no". In older networkd versions we used to
         * distinguish IPForward=off from IPForward=kernel, where the
         * former would explicitly turn off forwarding while the
         * latter would simply not touch the setting. But that logic
         * is gone, hence silently accept the old setting, but turn it
         * to "no". */

        s = address_family_from_string(rvalue);
        if (s < 0) {
                if (streq(rvalue, "kernel"))
                        s = ADDRESS_FAMILY_NO;
                else {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Failed to parse IPForward= option, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *fwd = s;

        return 0;
}

int config_parse_ip_masquerade(
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

        AddressFamily a, *ret = data;
        int r;

        if (isempty(rvalue)) {
                *ret = ADDRESS_FAMILY_NO;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                if (r)
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "IPMasquerade=%s is deprecated, and it is handled as \"ipv4\" instead of \"both\". "
                                   "Please use \"ipv4\" or \"both\".",
                                   rvalue);

                *ret = r ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_NO;
                return 0;
        }

        a = ip_masquerade_address_family_from_string(rvalue);
        if (a < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, a,
                           "Failed to parse IPMasquerade= setting, ignoring assignment: %s", rvalue);
                return 0;
        }

        *ret = a;
        return 0;
}

int config_parse_mud_url(
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
        char **url = ASSERT_PTR(data);
        ssize_t l;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *url = mfree(*url);
                return 0;
        }

        l = cunescape(rvalue, 0, &unescaped);
        if (l < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, l,
                           "Failed to unescape MUD URL, ignoring: %s", rvalue);
                return 0;
        }

        if (l > UINT8_MAX || !http_url_is_valid(unescaped)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid MUD URL, ignoring: %s", rvalue);
                return 0;
        }

        return free_and_replace(*url, unescaped);
}

int log_link_message_full_errno(Link *link, sd_netlink_message *m, int level, int err, const char *msg) {
        const char *err_msg = NULL;

        /* link may be NULL. */

        (void) sd_netlink_message_read_string(m, NLMSGERR_ATTR_MSG, &err_msg);
        return log_link_full_errno(link, level, err,
                                   "%s: %s%s%s%m",
                                   msg,
                                   strempty(err_msg),
                                   err_msg && !endswith(err_msg, ".") ? "." : "",
                                   err_msg ? " " : "");
}
