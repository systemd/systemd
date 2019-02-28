/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "hash-funcs.h"
#include "macro.h"

typedef enum AddressFamilyBoolean {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO   = 0,
        ADDRESS_FAMILY_IPV4 = 1 << 0,
        ADDRESS_FAMILY_IPV6 = 1 << 1,
        ADDRESS_FAMILY_YES  = ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6,
        _ADDRESS_FAMILY_BOOLEAN_MAX,
        _ADDRESS_FAMILY_BOOLEAN_INVALID = -1,
} AddressFamilyBoolean;

typedef struct NetworkConfigSection {
        unsigned line;
        char filename[];
} NetworkConfigSection;

CONFIG_PARSER_PROTOTYPE(config_parse_address_family_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_boolean_with_kernel);

const char *address_family_boolean_to_string(AddressFamilyBoolean b) _const_;
AddressFamilyBoolean address_family_boolean_from_string(const char *s) _const_;

int kernel_route_expiration_supported(void);

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s);
void network_config_section_free(NetworkConfigSection *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(NetworkConfigSection*, network_config_section_free);
extern const struct hash_ops network_config_hash_ops;
