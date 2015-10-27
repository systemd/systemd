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

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"

bool fstab_is_mount_point(const char *mount);

int fstab_filter_options(const char *opts, const char *names, const char **namefound, char **value, char **filtered);

int fstab_extract_values(const char *opts, const char *name, char ***values);

static inline bool fstab_test_option(const char *opts, const char *names) {
        return !!fstab_filter_options(opts, names, NULL, NULL, NULL);
}

int fstab_find_pri(const char *options, int *ret);

static inline bool fstab_test_yes_no_option(const char *opts, const char *yes_no) {
        int r;
        const char *opt;

        /* If first name given is last, return 1.
         * If second name given is last or neither is found, return 0. */

        r = fstab_filter_options(opts, yes_no, &opt, NULL, NULL);
        assert(r >= 0);

        return opt == yes_no;
}

char *fstab_node_to_udev_node(const char *p);
