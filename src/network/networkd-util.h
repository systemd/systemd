/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-lease.h"
#include "sd-netlink.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"

typedef enum AddressFamily {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO             = 0,
        ADDRESS_FAMILY_IPV4           = 1 << 0,
        ADDRESS_FAMILY_IPV6           = 1 << 1,
        ADDRESS_FAMILY_YES            = ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6,
        _ADDRESS_FAMILY_MAX,
        _ADDRESS_FAMILY_INVALID = -EINVAL,
} AddressFamily;

typedef struct NetworkConfigSection {
        unsigned line;
        bool invalid;
        char filename[];
} NetworkConfigSection;

CONFIG_PARSER_PROTOTYPE(config_parse_link_local_address_family);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_with_kernel);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_masquerade);

const char *address_family_to_string(AddressFamily b) _const_;
AddressFamily address_family_from_string(const char *s) _pure_;

AddressFamily link_local_address_family_from_string(const char *s) _pure_;

const char *routing_policy_rule_address_family_to_string(AddressFamily b) _const_;
AddressFamily routing_policy_rule_address_family_from_string(const char *s) _pure_;

const char *nexthop_address_family_to_string(AddressFamily b) _const_;
AddressFamily nexthop_address_family_from_string(const char *s) _pure_;

const char *duplicate_address_detection_address_family_to_string(AddressFamily b) _const_;
AddressFamily duplicate_address_detection_address_family_from_string(const char *s) _pure_;

AddressFamily dhcp_deprecated_address_family_from_string(const char *s) _pure_;

const char *dhcp_lease_server_type_to_string(sd_dhcp_lease_server_type_t t) _const_;
sd_dhcp_lease_server_type_t dhcp_lease_server_type_from_string(const char *s) _pure_;

int kernel_route_expiration_supported(void);

static inline NetworkConfigSection* network_config_section_free(NetworkConfigSection *cs) {
        return mfree(cs);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(NetworkConfigSection*, network_config_section_free);

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s);
extern const struct hash_ops network_config_hash_ops;
unsigned hashmap_find_free_section_line(Hashmap *hashmap);

static inline bool section_is_invalid(NetworkConfigSection *section) {
        /* If this returns false, then it does _not_ mean the section is valid. */

        if (!section)
                return false;

        return section->invalid;
}

#define DEFINE_NETWORK_SECTION_FUNCTIONS(type, free_func)               \
        static inline type* free_func##_or_set_invalid(type *p) {       \
                assert(p);                                              \
                                                                        \
                if (p->section)                                         \
                        p->section->invalid = true;                     \
                else                                                    \
                        free_func(p);                                   \
                return NULL;                                            \
        }                                                               \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func);                  \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func##_or_set_invalid);

static inline int log_message_warning_errno(sd_netlink_message *m, int err, const char *msg) {
        const char *err_msg = NULL;

        (void) sd_netlink_message_read_string(m, NLMSGERR_ATTR_MSG, &err_msg);
        return log_warning_errno(err, "%s: %s%s%m", msg, strempty(err_msg), err_msg ? " " : "");
}
