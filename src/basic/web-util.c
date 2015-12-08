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

#include <stdbool.h>

#include "string-util.h"
#include "utf8.h"
#include "web-util.h"

bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!startswith(etag, "\"") && !startswith(etag, "W/\""))
                return false;

        return true;
}

bool http_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = startswith(url, "http://");
        if (!p)
                p = startswith(url, "https://");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool documentation_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        if (http_url_is_valid(url))
                return true;

        p = startswith(url, "file:/");
        if (!p)
                p = startswith(url, "info:");
        if (!p)
                p = startswith(url, "man:");

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}
