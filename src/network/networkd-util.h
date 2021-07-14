/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-lease.h"
#include "sd-netlink.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "network-util.h"
#include "string-util.h"

typedef struct Link Link;

typedef struct NetworkConfigSection {
        unsigned line;
        bool invalid;
        char filename[];
} NetworkConfigSection;

CONFIG_PARSER_PROTOTYPE(config_parse_link_local_address_family);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_with_kernel);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_masquerade);
CONFIG_PARSER_PROTOTYPE(config_parse_mud_url);

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

int log_link_message_full_errno(Link *link, sd_netlink_message *m, int level, int err, const char *msg);
#define log_link_message_error_errno(link, m, err, msg)   log_link_message_full_errno(link, m, LOG_ERR, err, msg)
#define log_link_message_warning_errno(link, m, err, msg) log_link_message_full_errno(link, m, LOG_WARNING, err, msg)
#define log_link_message_notice_errno(link, m, err, msg)  log_link_message_full_errno(link, m, LOG_NOTICE, err, msg)
#define log_link_message_info_errno(link, m, err, msg)    log_link_message_full_errno(link, m, LOG_INFO, err, msg)
#define log_link_message_debug_errno(link, m, err, msg)   log_link_message_full_errno(link, m, LOG_DEBUG, err, msg)
#define log_message_full_errno(m, level, err, msg)        log_link_message_full_errno(NULL, m, level, err, msg)
#define log_message_error_errno(m, err, msg)              log_message_full_errno(m, LOG_ERR, err, msg)
#define log_message_warning_errno(m, err, msg)            log_message_full_errno(m, LOG_WARNING, err, msg)
#define log_message_notice_errno(m, err, msg)             log_message_full_errno(m, LOG_NOTICE, err, msg)
#define log_message_info_errno(m, err, msg)               log_message_full_errno(m, LOG_INFO, err, msg)
#define log_message_debug_errno(m, err, msg)              log_message_full_errno(m, LOG_DEBUG, err, msg)
