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

#include <errno.h>
#include <string.h>
#include <assert.h>

#include "path-util.h"
#include "bus-label.h"
#include "util.h"
#include "unit-name.h"
#include "def.h"
#include "strv.h"

#define VALID_CHARS                             \
        DIGITS LETTERS                          \
        ":-_.\\"

static const char* const unit_type_table[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = "service",
        [UNIT_SOCKET] = "socket",
        [UNIT_BUSNAME] = "busname",
        [UNIT_TARGET] = "target",
        [UNIT_SNAPSHOT] = "snapshot",
        [UNIT_DEVICE] = "device",
        [UNIT_MOUNT] = "mount",
        [UNIT_AUTOMOUNT] = "automount",
        [UNIT_SWAP] = "swap",
        [UNIT_TIMER] = "timer",
        [UNIT_PATH] = "path",
        [UNIT_SLICE] = "slice",
        [UNIT_SCOPE] = "scope"
};

DEFINE_STRING_TABLE_LOOKUP(unit_type, UnitType);

static const char* const unit_load_state_table[_UNIT_LOAD_STATE_MAX] = {
        [UNIT_STUB] = "stub",
        [UNIT_LOADED] = "loaded",
        [UNIT_NOT_FOUND] = "not-found",
        [UNIT_ERROR] = "error",
        [UNIT_MERGED] = "merged",
        [UNIT_MASKED] = "masked"
};

DEFINE_STRING_TABLE_LOOKUP(unit_load_state, UnitLoadState);

bool unit_name_is_valid(const char *n, enum template_valid template_ok) {
        const char *e, *i, *at;

        /* Valid formats:
         *
         *         string@instance.suffix
         *         string.suffix
         */

        assert(IN_SET(template_ok, TEMPLATE_VALID, TEMPLATE_INVALID));

        if (isempty(n))
                return false;

        if (strlen(n) >= UNIT_NAME_MAX)
                return false;

        e = strrchr(n, '.');
        if (!e || e == n)
                return false;

        if (unit_type_from_string(e + 1) < 0)
                return false;

        for (i = n, at = NULL; i < e; i++) {

                if (*i == '@' && !at)
                        at = i;

                if (!strchr("@" VALID_CHARS, *i))
                        return false;
        }

        if (at) {
                if (at == n)
                        return false;

                if (!template_ok == TEMPLATE_VALID && at+1 == e)
                        return false;
        }

        return true;
}

bool unit_instance_is_valid(const char *i) {

        /* The max length depends on the length of the string, so we
         * don't really check this here. */

        if (isempty(i))
                return false;

        /* We allow additional @ in the instance string, we do not
         * allow them in the prefix! */

        return in_charset(i, "@" VALID_CHARS);
}

bool unit_prefix_is_valid(const char *p) {

        /* We don't allow additional @ in the instance string */

        if (isempty(p))
                return false;

        return in_charset(p, VALID_CHARS);
}

int unit_name_to_instance(const char *n, char **instance) {
        const char *p, *d;
        char *i;

        assert(n);
        assert(instance);

        /* Everything past the first @ and before the last . is the instance */
        p = strchr(n, '@');
        if (!p) {
                *instance = NULL;
                return 0;
        }

        d = strrchr(n, '.');
        if (!d)
                return -EINVAL;
        if (d < p)
                return -EINVAL;

        i = strndup(p+1, d-p-1);
        if (!i)
                return -ENOMEM;

        *instance = i;
        return 1;
}

char *unit_name_to_prefix_and_instance(const char *n) {
        const char *d;

        assert(n);

        assert_se(d = strrchr(n, '.'));
        return strndup(n, d - n);
}

char *unit_name_to_prefix(const char *n) {
        const char *p;

        assert(n);

        p = strchr(n, '@');
        if (p)
                return strndup(n, p - n);

        return unit_name_to_prefix_and_instance(n);
}

char *unit_name_change_suffix(const char *n, const char *suffix) {
        char *e, *r;
        size_t a, b;

        assert(n);
        assert(suffix);
        assert(suffix[0] == '.');

        assert_se(e = strrchr(n, '.'));
        a = e - n;
        b = strlen(suffix);

        r = new(char, a + b + 1);
        if (!r)
                return NULL;

        strcpy(mempcpy(r, n, a), suffix);
        return r;
}

char *unit_name_build(const char *prefix, const char *instance, const char *suffix) {
        assert(prefix);
        assert(suffix);

        if (!instance)
                return strappend(prefix, suffix);

        return strjoin(prefix, "@", instance, suffix, NULL);
}

static char *do_escape_char(char c, char *t) {
        assert(t);

        *(t++) = '\\';
        *(t++) = 'x';
        *(t++) = hexchar(c >> 4);
        *(t++) = hexchar(c);

        return t;
}

static char *do_escape(const char *f, char *t) {
        assert(f);
        assert(t);

        /* do not create units with a leading '.', like for "/.dotdir" mount points */
        if (*f == '.') {
                t = do_escape_char(*f, t);
                f++;
        }

        for (; *f; f++) {
                if (*f == '/')
                        *(t++) = '-';
                else if (*f == '-' || *f == '\\' || !strchr(VALID_CHARS, *f))
                        t = do_escape_char(*f, t);
                else
                        *(t++) = *f;
        }

        return t;
}

char *unit_name_escape(const char *f) {
        char *r, *t;

        assert(f);

        r = new(char, strlen(f)*4+1);
        if (!r)
                return NULL;

        t = do_escape(f, r);
        *t = 0;

        return r;
}

char *unit_name_unescape(const char *f) {
        char *r, *t;

        assert(f);

        r = strdup(f);
        if (!r)
                return NULL;

        for (t = r; *f; f++) {
                if (*f == '-')
                        *(t++) = '/';
                else if (*f == '\\') {
                        int a, b;

                        if (f[1] != 'x' ||
                            (a = unhexchar(f[2])) < 0 ||
                            (b = unhexchar(f[3])) < 0) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                        } else {
                                *(t++) = (char) ((a << 4) | b);
                                f += 3;
                        }
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;
}

char *unit_name_path_escape(const char *f) {
        _cleanup_free_ char *p = NULL;

        assert(f);

        p = strdup(f);
        if (!p)
                return NULL;

        path_kill_slashes(p);

        if (STR_IN_SET(p, "/", ""))
                return strdup("-");

        return unit_name_escape(p[0] == '/' ? p + 1 : p);
}

char *unit_name_path_unescape(const char *f) {
        char *e, *w;

        assert(f);

        e = unit_name_unescape(f);
        if (!e)
                return NULL;

        if (e[0] != '/') {
                w = strappend("/", e);
                free(e);
                return w;
        }

        return e;
}

bool unit_name_is_template(const char *n) {
        const char *p, *e;

        assert(n);

        p = strchr(n, '@');
        if (!p)
                return false;

        e = strrchr(p+1, '.');
        if (!e)
                return false;

        return e == p + 1;
}

bool unit_name_is_instance(const char *n) {
        const char *p, *e;

        assert(n);

        p = strchr(n, '@');
        if (!p)
                return false;

        e = strrchr(p+1, '.');
        if (!e)
                return false;

        return e > p + 1;
}

char *unit_name_replace_instance(const char *f, const char *i) {
        const char *p, *e;
        char *r;
        size_t a, b;

        assert(f);
        assert(i);

        p = strchr(f, '@');
        if (!p)
                return strdup(f);

        e = strrchr(f, '.');
        if (!e)
                e = strchr(f, 0);

        a = p - f;
        b = strlen(i);

        r = new(char, a + 1 + b + strlen(e) + 1);
        if (!r)
                return NULL;

        strcpy(mempcpy(mempcpy(r, f, a + 1), i, b), e);
        return r;
}

char *unit_name_template(const char *f) {
        const char *p, *e;
        char *r;
        size_t a;

        assert(f);

        p = strchr(f, '@');
        if (!p)
                return strdup(f);

        e = strrchr(f, '.');
        if (!e)
                e = strchr(f, 0);

        a = p - f;

        r = new(char, a + 1 + strlen(e) + 1);
        if (!r)
                return NULL;

        strcpy(mempcpy(r, f, a + 1), e);
        return r;
}

char *unit_name_from_path(const char *path, const char *suffix) {
        _cleanup_free_ char *p = NULL;

        assert(path);
        assert(suffix);

        p = unit_name_path_escape(path);
        if (!p)
                return NULL;

        return strappend(p, suffix);
}

char *unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix) {
        _cleanup_free_ char *p = NULL;

        assert(prefix);
        assert(path);
        assert(suffix);

        p = unit_name_path_escape(path);
        if (!p)
                return NULL;

        return strjoin(prefix, "@", p, suffix, NULL);
}

char *unit_name_to_path(const char *name) {
        _cleanup_free_ char *w = NULL;

        assert(name);

        w = unit_name_to_prefix(name);
        if (!w)
                return NULL;

        return unit_name_path_unescape(w);
}

char *unit_dbus_path_from_name(const char *name) {
        _cleanup_free_ char *e = NULL;

        assert(name);

        e = bus_label_escape(name);
        if (!e)
                return NULL;

        return strappend("/org/freedesktop/systemd1/unit/", e);
}

int unit_name_from_dbus_path(const char *path, char **name) {
        const char *e;
        char *n;

        e = startswith(path, "/org/freedesktop/systemd1/unit/");
        if (!e)
                return -EINVAL;

        n = bus_label_unescape(e);
        if (!n)
                return -ENOMEM;

        *name = n;
        return 0;
}

/**
 *  Try to turn a string that might not be a unit name into a
 *  sensible unit name.
 */
char *unit_name_mangle(const char *name, enum unit_name_mangle allow_globs) {
        const char *valid_chars, *f;
        char *r, *t;

        assert(name);
        assert(IN_SET(allow_globs, MANGLE_GLOB, MANGLE_NOGLOB));

        if (is_device_path(name))
                return unit_name_from_path(name, ".device");

        if (path_is_absolute(name))
                return unit_name_from_path(name, ".mount");

        /* We'll only escape the obvious characters here, to play
         * safe. */

        valid_chars = allow_globs == MANGLE_GLOB ? "@" VALID_CHARS "[]!-*?" : "@" VALID_CHARS;

        r = new(char, strlen(name) * 4 + strlen(".service") + 1);
        if (!r)
                return NULL;

        for (f = name, t = r; *f; f++) {
                if (*f == '/')
                        *(t++) = '-';
                else if (!strchr(valid_chars, *f))
                        t = do_escape_char(*f, t);
                else
                        *(t++) = *f;
        }

        if (unit_name_to_type(name) < 0)
                strcpy(t, ".service");
        else
                *t = 0;

        return r;
}

/**
 *  Similar to unit_name_mangle(), but is called when we know
 *  that this is about a specific unit type.
 */
char *unit_name_mangle_with_suffix(const char *name, enum unit_name_mangle allow_globs, const char *suffix) {
        char *r, *t;
        const char *f;

        assert(name);
        assert(IN_SET(allow_globs, MANGLE_GLOB, MANGLE_NOGLOB));
        assert(suffix);
        assert(suffix[0] == '.');

        r = new(char, strlen(name) * 4 + strlen(suffix) + 1);
        if (!r)
                return NULL;

        for (f = name, t = r; *f; f++) {
                if (*f == '/')
                        *(t++) = '-';
                else if (!strchr(VALID_CHARS, *f))
                        t = do_escape_char(*f, t);
                else
                        *(t++) = *f;
        }

        if (!endswith(name, suffix))
                strcpy(t, suffix);
        else
                *t = 0;

        return r;
}

UnitType unit_name_to_type(const char *n) {
        const char *e;

        assert(n);

        e = strrchr(n, '.');
        if (!e)
                return _UNIT_TYPE_INVALID;

        return unit_type_from_string(e + 1);
}

int build_subslice(const char *slice, const char*name, char **subslice) {
        char *ret;

        assert(slice);
        assert(name);
        assert(subslice);

        if (streq(slice, "-.slice"))
                ret = strappend(name, ".slice");
        else {
                char *e;

                e = endswith(slice, ".slice");
                if (!e)
                        return -EINVAL;

                ret = new(char, (e - slice) + 1 + strlen(name) + 6 + 1);
                if (!ret)
                        return -ENOMEM;

                stpcpy(stpcpy(stpcpy(mempcpy(ret, slice, e - slice), "-"), name), ".slice");
        }

        *subslice = ret;
        return 0;
}
