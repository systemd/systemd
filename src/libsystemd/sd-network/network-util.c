/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "alloc-util.h"
#include "fd-util.h"
#include "network-util.h"
#include "strv.h"

bool network_is_online(void) {
        _cleanup_free_ char *state = NULL;
        int r;

        r = sd_network_get_operational_state(&state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        if (STR_IN_SET(state, "routable", "degraded"))
                return true;

        return false;
}
