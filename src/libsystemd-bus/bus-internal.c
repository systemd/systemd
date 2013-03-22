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

bool interface_name_is_valid(const char *p) {
        const char *q;
        bool dot, found_dot;

        if (isempty(p))
                return false;

        for (dot = true, q = p; *q; q++)
                if (*q == '.') {
                        if (dot)
                                return false;

                        found_dot = dot = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                (!dot && *q >= '0' && *q <= '9') ||
                                *q == '_';

                        if (!good)
                                return false;

                        dot = false;
                }

        if (q - p > 255)
                return false;

        if (dot)
                return false;

        if (!found_dot)
                return false;

        return true;
}

bool service_name_is_valid(const char *p) {
        const char *q;
        bool dot, found_dot, unique;

        if (isempty(p))
                return false;

        unique = p[0] == ':';

        for (dot = true, q = unique ? p+1 : p; *q; q++)
                if (*q == '.') {
                        if (dot)
                                return false;

                        found_dot = dot = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                ((!dot || unique) && *q >= '0' && *q <= '9') ||
                                *q == '_' || *q == '-';

                        if (!good)
                                return false;

                        dot = false;
                }

        if (q - p > 255)
                return false;

        if (dot)
                return false;

        if (!found_dot)
                return false;

        return true;

}

bool member_name_is_valid(const char *p) {
        const char *q;

        if (isempty(p))
                return false;

        for (q = p; *q; q++) {
                bool good;

                good =
                        (*q >= 'a' && *q <= 'z') ||
                        (*q >= 'A' && *q <= 'Z') ||
                        (*q >= '0' && *q <= '9') ||
                        *q == '_';

                if (!good)
                        return false;
        }

        if (q - p > 255)
                return false;

        return true;
}
