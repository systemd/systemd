/* SPDX-License-Identifier: LGPL-2.1+ */
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

#ifdef __NCPUBITS
#define CPU_SIZE_TO_NUM(n) ((n) * __NCPUBITS)
#else
#define CPU_SIZE_TO_NUM(n) ((n) * sizeof(cpu_set_t) * 8)
#endif

DEFINE_TRIVIAL_CLEANUP_FUNC(cpu_set_t*, CPU_FREE);
#define _cleanup_cpu_free_ _cleanup_(CPU_FREEp)

static inline cpu_set_t* cpu_set_mfree(cpu_set_t *p) {
        if (p)
                CPU_FREE(p);
        return NULL;
}

cpu_set_t* cpu_set_malloc(unsigned *ncpus);

int parse_cpu_set_internal(const char *rvalue, cpu_set_t **cpu_set, bool warn, const char *unit, const char *filename, unsigned line, const char *lvalue);

static inline int parse_cpu_set_and_warn(const char *rvalue, cpu_set_t **cpu_set, const char *unit, const char *filename, unsigned line, const char *lvalue) {
        assert(lvalue);

        return parse_cpu_set_internal(rvalue, cpu_set, true, unit, filename, line, lvalue);
}

static inline int parse_cpu_set(const char *rvalue, cpu_set_t **cpu_set){
        return parse_cpu_set_internal(rvalue, cpu_set, false, NULL, NULL, 0, NULL);
}
