/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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

#include <selinux/selinux.h>

#include "selinux-util.h"

static int cached_use = -1;

bool mac_selinux_use(void) {
#ifdef HAVE_SELINUX
        if (cached_use < 0)
                cached_use = is_selinux_enabled() > 0;

        return cached_use;
#else
        return false;
#endif
}

void mac_selinux_retest(void) {
#ifdef HAVE_SELINUX
        cached_use = -1;
#endif
}
