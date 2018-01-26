/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Yu Watanabe

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

#include "securebits.h"

int secure_bits_to_string_alloc(int i, char **s);
int secure_bits_from_string(const char *s);

static inline bool secure_bits_is_valid(int i) {
        return ((SECURE_ALL_BITS | SECURE_ALL_LOCKS) & i) == i;
}

static inline int secure_bits_to_string_alloc_with_check(int n, char **s) {
        if (!secure_bits_is_valid(n))
                return -EINVAL;

        return secure_bits_to_string_alloc(n, s);
}
