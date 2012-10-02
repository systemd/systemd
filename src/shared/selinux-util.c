/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "selinux-util.h"

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>

static int use_selinux_cached = -1;

bool use_selinux(void) {

        if (use_selinux_cached < 0)
                use_selinux_cached = is_selinux_enabled() > 0;

        return use_selinux_cached;
}

void retest_selinux(void) {
        use_selinux_cached = -1;
}

#endif
