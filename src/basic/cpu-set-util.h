/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2015 Lennart Poettering
  Copyright 2015 Filipe Brandenburger

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

#include <sched.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(cpu_set_t*, CPU_FREE);
#define _cleanup_cpu_free_ _cleanup_(CPU_FREEp)

cpu_set_t* cpu_set_malloc(unsigned *ncpus);

int parse_cpu_set_and_warn(const char *rvalue, cpu_set_t **cpu_set, const char *unit, const char *filename, unsigned line, const char *lvalue);
