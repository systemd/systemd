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

#include "sd-utf8.h"

#include "utf8.h"
#include "util.h"

_public_ const char *sd_utf8_is_valid(const char *s) {
        assert_return(s, NULL);

        return utf8_is_valid(s);
}

_public_ const char *sd_ascii_is_valid(const char *s) {
        assert_return(s, NULL);

        return ascii_is_valid(s);
}
