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

#include "bus-internal.h"

bool object_path_is_valid(const char *p) {
        const char *q;
        bool slash;

        if (!p)
                return false;

        if (p[0] != '/')
                return false;

        if (p[1] == 0)
                return true;

        for (slash = true, q = p+1; *q; q++)
                if (*q == '/') {
                        if (slash)
                                return false;

                        slash = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                (*q >= '0' && *q <= '9') ||
                                *q == '_';

                        if (!good)
                                return false;

                        slash = false;
                }

        if (slash)
                return false;

        return true;
}
