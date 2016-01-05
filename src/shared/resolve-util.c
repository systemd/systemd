/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "conf-parser.h"
#include "resolve-util.h"
#include "string-table.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_resolve_support, resolve_support, ResolveSupport, "Failed to parse resolve support setting");
DEFINE_CONFIG_PARSE_ENUM(config_parse_dnssec_mode, dnssec_mode, DnssecMode, "Failed to parse DNSSEC mode setting");

static const char* const resolve_support_table[_RESOLVE_SUPPORT_MAX] = {
        [RESOLVE_SUPPORT_NO] = "no",
        [RESOLVE_SUPPORT_YES] = "yes",
        [RESOLVE_SUPPORT_RESOLVE] = "resolve",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(resolve_support, ResolveSupport, RESOLVE_SUPPORT_YES);

static const char* const dnssec_mode_table[_DNSSEC_MODE_MAX] = {
        [DNSSEC_NO] = "no",
        [DNSSEC_ALLOW_DOWNGRADE] = "allow-downgrade",
        [DNSSEC_YES] = "yes",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dnssec_mode, DnssecMode, DNSSEC_YES);
