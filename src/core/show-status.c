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

#include "show-status.h"
#include "util.h"

int parse_show_status(const char *v, ShowStatus *ret) {
        int r;

        assert(v);
        assert(ret);

        if (streq(v, "auto")) {
                *ret = SHOW_STATUS_AUTO;
                return 0;
        }

        r = parse_boolean(v);
        if (r < 0)
                return r;

        *ret = r ? SHOW_STATUS_YES : SHOW_STATUS_NO;
        return 0;
}
