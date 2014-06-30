/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "dropin.h"
#include "util.h"
#include "mkdir.h"
#include "fileio-label.h"

int drop_in_file(const char *dir, const char *unit, unsigned level,
                 const char *name, char **_p, char **_q) {

        _cleanup_free_ char *b = NULL;
        char *p, *q;

        char prefix[DECIMAL_STR_MAX(unsigned)];

        assert(unit);
        assert(name);
        assert(_p);
        assert(_q);

        sprintf(prefix, "%u", level);

        b = xescape(name, "/.");
        if (!b)
                return -ENOMEM;

        if (!filename_is_safe(b))
                return -EINVAL;

        p = strjoin(dir, "/", unit, ".d", NULL);
        if (!p)
                return -ENOMEM;

        q = strjoin(p, "/", prefix, "-", b, ".conf", NULL);
        if (!q) {
                free(p);
                return -ENOMEM;
        }

        *_p = p;
        *_q = q;
        return 0;
}

int write_drop_in(const char *dir, const char *unit, unsigned level,
                  const char *name, const char *data) {

        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(dir);
        assert(unit);
        assert(name);
        assert(data);

        r = drop_in_file(dir, unit, level, name, &p, &q);
        if (r < 0)
                return r;

        mkdir_p(p, 0755);
        return write_string_file_atomic_label(q, data);
}

int write_drop_in_format(const char *dir, const char *unit, unsigned level,
                         const char *name, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(dir);
        assert(unit);
        assert(name);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return write_drop_in(dir, unit, level, name, p);
}
