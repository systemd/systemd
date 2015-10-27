/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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
#include "apparmor-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "util.h"

bool mac_apparmor_use(void) {
        static int cached_use = -1;

        if (cached_use < 0) {
                _cleanup_free_ char *p = NULL;

                cached_use =
                        read_one_line_file("/sys/module/apparmor/parameters/enabled", &p) >= 0 &&
                        parse_boolean(p) > 0;
        }

        return cached_use;
}
