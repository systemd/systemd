/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdbool.h>

#include "sd-bus.h"

#include "macro.h"

bool bus_type_is_valid(char c) _const_;
bool bus_type_is_valid_in_signature(char c) _const_;
bool bus_type_is_basic(char c) _const_;
/* "trivial" is systemd's term for what the D-Bus Specification calls
 * a "fixed type": that is, a basic type of fixed length */
bool bus_type_is_trivial(char c) _const_;
bool bus_type_is_container(char c) _const_;

int bus_type_get_alignment(char c) _const_;
int bus_type_get_size(char c) _const_;
