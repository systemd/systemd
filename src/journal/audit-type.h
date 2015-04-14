/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Zbigniew Jędrzejewski-Szmek

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

const char *audit_type_to_string(int type);
int audit_type_from_string(const char *s);

/* This is inspired by DNS TYPEnnn formatting */
#define audit_type_name_alloca(type)                                    \
        ({                                                              \
                const char *_s_;                                        \
                _s_ = audit_type_to_string(type);                       \
                if (!_s_) {                                             \
                        _s_ = alloca(strlen("AUDIT") + DECIMAL_STR_MAX(int)); \
                        sprintf((char*) _s_, "AUDIT%04i", type);        \
                }                                                       \
                _s_;                                                    \
        })
