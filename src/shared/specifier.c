/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

/*
 * Generic infrastructure for replacing %x style specifiers in
 * strings. Will call a callback for each replacement.
 *
 */

/* Any ASCII character or digit: our pool of potential specifiers,
 * and "%" used for escaping. */
#define POSSIBLE_SPECIFIERS ALPHANUMERICAL "%"

int specifier_printf(const char *text, const Specifier table[], void *userdata, char **_ret) {
        size_t l;
        _cleanup_free_ char *ret = NULL;
        char *t;
        const char *f;
        bool percent = false;
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
                                        if (r < 0)
                                                return r;

                                        j = t - ret;
                                        k = strlen(w);

                                        n = new(char, j + k + l + 1);
                                        if (!n)
                                                return -ENOMEM;

                                        memcpy(n, ret, j);
                                        memcpy(n + j, w, k);

                                        free_and_replace(ret, n);
                                        t = ret + j + k;
                                } else if (strchr(POSSIBLE_SPECIFIERS, *f))
                                        /* Oops, an unknown specifier. */
                                        return -EBADSLT;
                                else {
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

        /* if string ended with a stray %, also end with % */
        if (percent)
                *(t++) = '%';

        *t = 0;
        *_ret = ret;
        ret = NULL;
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

int specifier_user_name(char specifier, void *data, void *userdata, char **ret) {
        char *t;

        /* If we are UID 0 (root), this will not result in NSS, otherwise it might. This is good, as we want to be able
         * to run this in PID 1, where our user ID is 0, but where NSS lookups are not allowed.

         * We don't use getusername_malloc() here, because we don't want to look at $USER, to remain consistent with
         * specifer_user_id() below.
         */

        t = uid_to_name(getuid());
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

int specifier_user_id(char specifier, void *data, void *userdata, char **ret) {

        if (asprintf(ret, UID_FMT, getuid()) < 0)
                return -ENOMEM;

        return 0;
}

int specifier_user_home(char specifier, void *data, void *userdata, char **ret) {

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_home_dir(ret);
}

int specifier_user_shell(char specifier, void *data, void *userdata, char **ret) {

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_shell(ret);
}

int specifier_escape_strv(char **l, char ***ret) {
        char **z, **p, **q;

        assert(ret);

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        z = new(char*, strv_length(l)+1);
        if (!z)
                return -ENOMEM;

        for (p = l, q = z; *p; p++, q++) {

                *q = specifier_escape(*p);
                if (!*q) {
                        strv_free(z);
                        return -ENOMEM;
                }
        }

        *q = NULL;
        *ret = z;

        return 0;
}
