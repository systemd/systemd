#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <stdint.h>
#include <sys/capability.h>
#include <sys/types.h>

#include "macro.h"
#include "util.h"

#define CAP_ALL (uint64_t) -1

unsigned long cap_last_cap(void);
int have_effective_cap(int value);
int capability_bounding_set_drop(uint64_t keep, bool right_now);
int capability_bounding_set_drop_usermode(uint64_t keep);

int capability_ambient_set_apply(uint64_t set, bool also_inherit);
int capability_update_inherited_set(cap_t caps, uint64_t ambient_set);

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities);

int drop_capability(cap_value_t cv);

DEFINE_TRIVIAL_CLEANUP_FUNC(cap_t, cap_free);
#define _cleanup_cap_free_ _cleanup_(cap_freep)

static inline void cap_free_charpp(char **p) {
        if (*p)
                cap_free(*p);
}
#define _cleanup_cap_free_charp_ _cleanup_(cap_free_charpp)

static inline bool cap_test_all(uint64_t caps) {
        uint64_t m;
        m = (UINT64_C(1) << (cap_last_cap() + 1)) - 1;
        return (caps & m) == m;
}
