/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "macro.h"
#include "util.h"
#include "specifier.h"

/*
 * Generic infrastructure for replacing %x style specifiers in
 * strings. Will call a callback for each replacement.
 *
 */

char *specifier_printf(const char *text, const Specifier table[], void *userdata) {
        char *r, *t;
        const char *f;
        bool percent = false;
        size_t l;

        assert(text);
        assert(table);

        l = strlen(text);
        if (!(r = new(char, l+1)))
                return NULL;

        t = r;

        for (f = text; *f; f++, l--) {

                if (percent) {
                        if (*f == '%')
                                *(t++) = '%';
                        else {
                                const Specifier *i;

                                for (i = table; i->specifier; i++)
                                        if (i->specifier == *f)
                                                break;

                                if (i->lookup) {
                                        char *n, *w;
                                        size_t k, j;

                                        if (!(w = i->lookup(i->specifier, i->data, userdata))) {
                                                free(r);
                                                return NULL;
                                        }

                                        j = t - r;
                                        k = strlen(w);

                                        if (!(n = new(char, j + k + l + 1))) {
                                                free(r);
                                                free(w);
                                                return NULL;
                                        }

                                        memcpy(n, r, j);
                                        memcpy(n + j, w, k);

                                        free(r);
                                        free(w);

                                        r = n;
                                        t = n + j + k;
                                } else {
                                        *(t++) = '%';
                                        *(t++) = *f;
                                }
                        }

                        percent = false;
                } else if (*f == '%')
                        percent = true;
                else
                        *(t++) = *f;
        }

        *t = 0;
        return r;
}

/* Generic handler for simple string replacements */

char* specifier_string(char specifier, void *data, void *userdata) {
        assert(data);

        return strdup(strempty(data));
}
