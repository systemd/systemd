/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "util.h"
#include "conf-parser.h"

#include "networkd-util.h"

const char *address_family_boolean_to_string(AddressFamilyBoolean b) {
        if (b == ADDRESS_FAMILY_YES ||
            b == ADDRESS_FAMILY_NO)
                return yes_no(b == ADDRESS_FAMILY_YES);

        if (b == ADDRESS_FAMILY_IPV4)
                return "ipv4";
        if (b == ADDRESS_FAMILY_IPV6)
                return "ipv6";

        return NULL;
}

AddressFamilyBoolean address_family_boolean_from_string(const char *s) {
        int r;

        /* Make this a true superset of a boolean */

        r = parse_boolean(s);
        if (r > 0)
                return ADDRESS_FAMILY_YES;
        if (r == 0)
                return ADDRESS_FAMILY_NO;

        if (streq(s, "ipv4"))
                return ADDRESS_FAMILY_IPV4;
        if (streq(s, "ipv6"))
                return ADDRESS_FAMILY_IPV6;

        return _ADDRESS_FAMILY_BOOLEAN_INVALID;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_address_family_boolean, address_family_boolean, AddressFamilyBoolean, "Failed to parse option");

int config_parse_address_family_boolean_with_kernel(
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

        AddressFamilyBoolean *fwd = data, s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = address_family_boolean_from_string(rvalue);
        if (s < 0) {
                if (streq(rvalue, "kernel"))
                        s = _ADDRESS_FAMILY_BOOLEAN_INVALID;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IPForwarding= option, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *fwd = s;

        return 0;
}

static const char* const resolve_support_table[_RESOLVE_SUPPORT_MAX] = {
        [RESOLVE_SUPPORT_NO] = "no",
        [RESOLVE_SUPPORT_YES] = "yes",
        [RESOLVE_SUPPORT_RESOLVE] = "resolve",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_support, ResolveSupport);

int config_parse_resolve(
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

        ResolveSupport *resolve = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(resolve);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                *resolve = RESOLVE_SUPPORT_YES;
        else if (k == 0)
                *resolve = RESOLVE_SUPPORT_NO;
        else {
                ResolveSupport s;

                s = resolve_support_from_string(rvalue);
                if (s < 0){
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse %s= option, ignoring: %s", lvalue, rvalue);
                        return 0;
                }

                *resolve = s;
        }

        return 0;
}
