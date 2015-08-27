/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
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

typedef enum ResolveSupport {
        RESOLVE_SUPPORT_NO,
        RESOLVE_SUPPORT_YES,
        RESOLVE_SUPPORT_RESOLVE,
        _RESOLVE_SUPPORT_MAX,
        _RESOLVE_SUPPORT_INVALID = -1,
} ResolveSupport;

int config_parse_resolve(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_family_boolean(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_family_boolean_with_kernel(const char* unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char* resolve_support_to_string(ResolveSupport i) _const_;
ResolveSupport resolve_support_from_string(const char *s) _pure_;

const char *address_family_boolean_to_string(AddressFamilyBoolean b) _const_;
AddressFamilyBoolean address_family_boolean_from_string(const char *s) _const_;
