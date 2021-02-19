/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "condition.h"
#include "conf-parser.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static const char* const address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "no",
        [ADDRESS_FAMILY_YES]  = "yes",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char* const routing_policy_rule_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char* const nexthop_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char* const duplicate_address_detection_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "none",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char* const dhcp_deprecated_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "none",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "v4",
        [ADDRESS_FAMILY_IPV6] = "v6",
};

static const char* const ip_masquerade_address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "no",
        [ADDRESS_FAMILY_YES]  = "both",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

static const char* const dhcp_lease_server_type_table[_SD_DHCP_LEASE_SERVER_TYPE_MAX] = {
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

/* Router lifetime can be set with netlink interface since kernel >= 4.5
 * so for the supported kernel we don't need to expire routes in userspace */
int kernel_route_expiration_supported(void) {
        static int cached = -1;
        int r;

        if (cached < 0) {
                Condition c = {
                        .type = CONDITION_KERNEL_VERSION,
                        .parameter = (char *) ">= 4.5"
                };
                r = condition_test(&c, NULL);
                if (r < 0)
                        return r;

                cached = r;
        }
        return cached;
}

static void network_config_hash_func(const NetworkConfigSection *c, struct siphash *state) {
        siphash24_compress_string(c->filename, state);
        siphash24_compress(&c->line, sizeof(c->line), state);
}

static int network_config_compare_func(const NetworkConfigSection *x, const NetworkConfigSection *y) {
        int r;

        r = strcmp(x->filename, y->filename);
        if (r != 0)
                return r;

        return CMP(x->line, y->line);
}

DEFINE_HASH_OPS(network_config_hash_ops, NetworkConfigSection, network_config_hash_func, network_config_compare_func);

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s) {
        NetworkConfigSection *cs;

        cs = malloc0(offsetof(NetworkConfigSection, filename) + strlen(filename) + 1);
        if (!cs)
                return -ENOMEM;

        strcpy(cs->filename, filename);
        cs->line = line;

        *s = TAKE_PTR(cs);

        return 0;
}

unsigned hashmap_find_free_section_line(Hashmap *hashmap) {
        NetworkConfigSection *cs;
        unsigned n = 0;
        void *entry;

        HASHMAP_FOREACH_KEY(entry, cs, hashmap)
                if (n < cs->line)
                        n = cs->line;

        return n + 1;
}
