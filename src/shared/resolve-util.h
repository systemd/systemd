/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "macro.h"

typedef enum ResolveSupport ResolveSupport;
typedef enum DnssecMode DnssecMode;

enum ResolveSupport {
        RESOLVE_SUPPORT_NO,
        RESOLVE_SUPPORT_YES,
        RESOLVE_SUPPORT_RESOLVE,
        _RESOLVE_SUPPORT_MAX,
        _RESOLVE_SUPPORT_INVALID = -1
};

enum DnssecMode {
        /* No DNSSEC validation is done */
        DNSSEC_NO,

        /* Validate locally, if the server knows DO, but if not,
         * don't. Don't trust the AD bit. If the server doesn't do
         * DNSSEC properly, downgrade to non-DNSSEC operation. Of
         * course, we then are vulnerable to a downgrade attack, but
         * that's life and what is configured. */
        DNSSEC_ALLOW_DOWNGRADE,

        /* Insist on DNSSEC server support, and rather fail than downgrading. */
        DNSSEC_YES,

        _DNSSEC_MODE_MAX,
        _DNSSEC_MODE_INVALID = -1
};

int config_parse_resolve_support(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_dnssec_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char* resolve_support_to_string(ResolveSupport p) _const_;
ResolveSupport resolve_support_from_string(const char *s) _pure_;

const char* dnssec_mode_to_string(DnssecMode p) _const_;
DnssecMode dnssec_mode_from_string(const char *s) _pure_;
