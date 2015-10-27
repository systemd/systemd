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

#include <stdlib.h>

#include "alloc-util.h"
#include "bus-label.h"
#include "hexdecoct.h"
#include "macro.h"
#include "util.h"

char *bus_label_escape(const char *s) {
        char *r, *t;
        const char *f;

        assert_return(s, NULL);

        /* Escapes all chars that D-Bus' object path cannot deal
         * with. Can be reversed with bus_path_unescape(). We special
         * case the empty string. */

        if (*s == 0)
                return strdup("_");

        r = new(char, strlen(s)*3 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; *f; f++) {

                /* Escape everything that is not a-zA-Z0-9. We also
                 * escape 0-9 if it's the first character */

                if (!(*f >= 'A' && *f <= 'Z') &&
                    !(*f >= 'a' && *f <= 'z') &&
                    !(f > s && *f >= '0' && *f <= '9')) {
                        *(t++) = '_';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *bus_label_unescape_n(const char *f, size_t l) {
        char *r, *t;
        size_t i;

        assert_return(f, NULL);

        /* Special case for the empty string */
        if (l == 1 && *f == '_')
                return strdup("");

        r = new(char, l + 1);
        if (!r)
                return NULL;

        for (i = 0, t = r; i < l; ++i) {
                if (f[i] == '_') {
                        int a, b;

                        if (l - i < 3 ||
                            (a = unhexchar(f[i + 1])) < 0 ||
                            (b = unhexchar(f[i + 2])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '_';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                i += 2;
                        }
                } else
                        *(t++) = f[i];
        }

        *t = 0;

        return r;
}
