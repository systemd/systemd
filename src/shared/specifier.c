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
#include <sys/utsname.h>

#include "alloc-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "util.h"

/*
 * Generic infrastructure for replacing %x style specifiers in
 * strings. Will call a callback for each replacement.
 *
 */

int specifier_printf(const char *text, const Specifier table[], void *userdata, char **_ret) {
        char *ret, *t;
        const char *f;
        bool percent = false;
        size_t l;
        int r;

        assert(text);
        assert(table);

        l = strlen(text);
        ret = new(char, l+1);
        if (!ret)
                return -ENOMEM;

        t = ret;

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
                                        _cleanup_free_ char *w = NULL;
                                        char *n;
                                        size_t k, j;

                                        r = i->lookup(i->specifier, i->data, userdata, &w);
                                        if (r < 0) {
                                                free(ret);
                                                return r;
                                        }

                                        j = t - ret;
                                        k = strlen(w);

                                        n = new(char, j + k + l + 1);
                                        if (!n) {
                                                free(ret);
                                                return -ENOMEM;
                                        }

                                        memcpy(n, ret, j);
                                        memcpy(n + j, w, k);

                                        free(ret);

                                        ret = n;
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
        *_ret = ret;
        return 0;
}

/* Generic handler for simple string replacements */

int specifier_string(char specifier, void *data, void *userdata, char **ret) {
        char *n;

        n = strdup(strempty(data));
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_machine_id(char specifier, void *data, void *userdata, char **ret) {
        sd_id128_t id;
        char *n;
        int r;

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        n = new(char, 33);
        if (!n)
                return -ENOMEM;

        *ret = sd_id128_to_string(id, n);
        return 0;
}

int specifier_boot_id(char specifier, void *data, void *userdata, char **ret) {
        sd_id128_t id;
        char *n;
        int r;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        n = new(char, 33);
        if (!n)
                return -ENOMEM;

        *ret = sd_id128_to_string(id, n);
        return 0;
}

int specifier_host_name(char specifier, void *data, void *userdata, char **ret) {
        char *n;

        n = gethostname_malloc();
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_kernel_release(char specifier, void *data, void *userdata, char **ret) {
        struct utsname uts;
        char *n;
        int r;

        r = uname(&uts);
        if (r < 0)
                return -errno;

        n = strdup(uts.release);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}
