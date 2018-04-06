/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>
***/

#include "macro.h"

typedef enum AddressFamilyBoolean {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO = 0,
        ADDRESS_FAMILY_IPV4 = 1,
        ADDRESS_FAMILY_IPV6 = 2,
        ADDRESS_FAMILY_YES = 3,
        _ADDRESS_FAMILY_BOOLEAN_MAX,
        _ADDRESS_FAMILY_BOOLEAN_INVALID = -1,
} AddressFamilyBoolean;

int config_parse_address_family_boolean(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_family_boolean_with_kernel(const char* unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *address_family_boolean_to_string(AddressFamilyBoolean b) _const_;
AddressFamilyBoolean address_family_boolean_from_string(const char *s) _const_;

int kernel_route_expiration_supported(void);
