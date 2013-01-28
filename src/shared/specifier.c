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
        r = new(char, l+1);
        if (!r)
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

                                        w = i->lookup(i->specifier, i->data, userdata);
                                        if (!w) {
                                                free(r);
                                                return NULL;
                                        }

                                        j = t - r;
                                        k = strlen(w);

                                        n = new(char, j + k + l + 1);
                                        if (!n) {
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
        return strdup(strempty(data));
}

char *specifier_machine_id(char specifier, void *data, void *userdata) {
        sd_id128_t id;
        char *buf;
        int r;

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return NULL;

        buf = new(char, 33);
        if (!buf)
                return NULL;

        return sd_id128_to_string(id, buf);
}

char *specifier_boot_id(char specifier, void *data, void *userdata) {
        sd_id128_t id;
        char *buf;
        int r;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return NULL;

        buf = new(char, 33);
        if (!buf)
                return NULL;

        return sd_id128_to_string(id, buf);
}

char *specifier_host_name(char specifier, void *data, void *userdata) {
        return gethostname_malloc();
}
