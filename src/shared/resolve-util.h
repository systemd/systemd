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

enum ResolveSupport {
        RESOLVE_SUPPORT_NO,
        RESOLVE_SUPPORT_YES,
        RESOLVE_SUPPORT_RESOLVE,
        _RESOLVE_SUPPORT_MAX,
        _RESOLVE_SUPPORT_INVALID = -1
};

int config_parse_resolve_support(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char* resolve_support_to_string(ResolveSupport p) _const_;
ResolveSupport resolve_support_from_string(const char *s) _pure_;
