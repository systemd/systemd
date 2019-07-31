/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "hash-funcs.h"
#include "macro.h"

typedef enum AddressFamily {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO             = 0,
        ADDRESS_FAMILY_IPV4           = 1 << 0,
        ADDRESS_FAMILY_IPV6           = 1 << 1,
        ADDRESS_FAMILY_YES            = ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6,
        ADDRESS_FAMILY_FALLBACK_IPV4  = 1 << 2,
        ADDRESS_FAMILY_FALLBACK       = ADDRESS_FAMILY_FALLBACK_IPV4 | ADDRESS_FAMILY_IPV6,
        _ADDRESS_FAMILY_MAX,
        _ADDRESS_FAMILY_INVALID = -1,
} AddressFamily;

typedef struct NetworkConfigSection {
        unsigned line;
        bool invalid;
        char filename[];
} NetworkConfigSection;

CONFIG_PARSER_PROTOTYPE(config_parse_link_local_address_family);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_with_kernel);

const char *address_family_to_string(AddressFamily b) _const_;
AddressFamily address_family_from_string(const char *s) _pure_;

const char *link_local_address_family_to_string(AddressFamily b) _const_;
AddressFamily link_local_address_family_from_string(const char *s) _pure_;

const char *routing_policy_rule_address_family_to_string(AddressFamily b) _const_;
AddressFamily routing_policy_rule_address_family_from_string(const char *s) _pure_;

int kernel_route_expiration_supported(void);

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s);
void network_config_section_free(NetworkConfigSection *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(NetworkConfigSection*, network_config_section_free);
extern const struct hash_ops network_config_hash_ops;

static inline bool section_is_invalid(NetworkConfigSection *section) {
        /* If this returns false, then it does _not_ mean the section is valid. */

        if (!section)
                return false;

        return section->invalid;
}

#define DEFINE_NETWORK_SECTION_FUNCTIONS(type, free_func)               \
        static inline void free_func##_or_set_invalid(type *p) {        \
                assert(p);                                              \
                                                                        \
                if (p->section)                                         \
                        p->section->invalid = true;                     \
                else                                                    \
                        free_func(p);                                   \
        }                                                               \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func);                  \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func##_or_set_invalid);
