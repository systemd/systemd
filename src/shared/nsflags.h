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

#include <sched.h>

#include "missing.h"

/* The combination of all namespace flags defined by the kernel. The right type for this isn't clear. setns() and
 * unshare() expect these flags to be passed as (signed) "int", while clone() wants them as "unsigned long". The latter
 * is definitely more appropriate for a flags parameter, and also the larger type of the two, hence let's stick to that
 * here. */
#define NAMESPACE_FLAGS_ALL                                             \
        ((unsigned long) (CLONE_NEWCGROUP|                              \
                          CLONE_NEWIPC|                                 \
                          CLONE_NEWNET|                                 \
                          CLONE_NEWNS|                                  \
                          CLONE_NEWPID|                                 \
                          CLONE_NEWUSER|                                \
                          CLONE_NEWUTS))

const char* namespace_flag_to_string(unsigned long flag);
unsigned long namespace_flag_from_string(const char *name);
int namespace_flag_from_string_many(const char *name, unsigned long *ret);
int namespace_flag_to_string_many(unsigned long flags, char **ret);

struct namespace_flag_map {
        unsigned long flag;
        const char *name;
};

extern const struct namespace_flag_map namespace_flag_map[];
