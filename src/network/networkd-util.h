/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "macro.h"

typedef enum AddressFamilyBoolean
{
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO = 0,
        ADDRESS_FAMILY_IPV4 = 1,
        ADDRESS_FAMILY_IPV6 = 2,
        ADDRESS_FAMILY_YES = 3,
        _ADDRESS_FAMILY_BOOLEAN_MAX,
        _ADDRESS_FAMILY_BOOLEAN_INVALID = -1,
} AddressFamilyBoolean;

CONFIG_PARSER_PROTOTYPE(config_parse_address_family_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_boolean_with_kernel);

const char *address_family_boolean_to_string(AddressFamilyBoolean b) _const_;
AddressFamilyBoolean address_family_boolean_from_string(const char *s) _const_;

int kernel_route_expiration_supported(void);
