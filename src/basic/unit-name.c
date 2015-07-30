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

#include "path-util.h"
#include "bus-label.h"
#include "util.h"
#include "unit-name.h"
#include "def.h"
#include "strv.h"

#define VALID_CHARS                             \
        DIGITS LETTERS                          \
        ":-_.\\"

bool unit_name_is_valid(const char *n, UnitNameFlags flags) {
        const char *e, *i, *at;

        assert((flags & ~(UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE)) == 0);

        if (_unlikely_(flags == 0))
                return false;

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

        if (at == n)
                return false;

        if (flags & UNIT_NAME_PLAIN)
                if (!at)
                        return true;

        if (flags & UNIT_NAME_INSTANCE)
                if (at && e > at + 1)
                        return true;

        if (flags & UNIT_NAME_TEMPLATE)
                if (at && e == at + 1)
                        return true;

        return false;
}

bool unit_prefix_is_valid(const char *p) {

        /* We don't allow additional @ in the prefix string */

        if (isempty(p))
                return false;

        return in_charset(p, VALID_CHARS);
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

bool unit_suffix_is_valid(const char *s) {
        if (isempty(s))
                return false;

        if (s[0] != '.')
                return false;

        if (unit_type_from_string(s + 1) < 0)
                return false;

        return true;
}

int unit_name_to_prefix(const char *n, char **ret) {
        const char *p;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        p = strchr(n, '@');
        if (!p)
                p = strrchr(n, '.');

        assert_se(p);

        s = strndup(n, p - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_to_instance(const char *n, char **instance) {
        const char *p, *d;
        char *i;

        assert(n);
        assert(instance);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        /* Everything past the first @ and before the last . is the instance */
        p = strchr(n, '@');
        if (!p) {
                *instance = NULL;
                return 0;
        }

        p++;

        d = strrchr(p, '.');
        if (!d)
                return -EINVAL;

        i = strndup(p, d-p);
        if (!i)
                return -ENOMEM;

        *instance = i;
        return 1;
}

int unit_name_to_prefix_and_instance(const char *n, char **ret) {
        const char *d;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        d = strrchr(n, '.');
        if (!d)
                return -EINVAL;

        s = strndup(n, d - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

UnitType unit_name_to_type(const char *n) {
        const char *e;

        assert(n);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return _UNIT_TYPE_INVALID;

        assert_se(e = strrchr(n, '.'));

        return unit_type_from_string(e + 1);
}

int unit_name_change_suffix(const char *n, const char *suffix, char **ret) {
        char *e, *s;
        size_t a, b;

        assert(n);
        assert(suffix);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        assert_se(e = strrchr(n, '.'));

        a = e - n;
        b = strlen(suffix);

        s = new(char, a + b + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, n, a), suffix);
        *ret = s;

        return 0;
}

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret) {
        char *s;

        assert(prefix);
        assert(suffix);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        if (instance && !unit_instance_is_valid(instance))
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        if (!instance)
                s = strappend(prefix, suffix);
        else
                s = strjoin(prefix, "@", instance, suffix, NULL);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
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

int unit_name_unescape(const char *f, char **ret) {
        _cleanup_free_ char *r = NULL;
        char *t;

        assert(f);

        r = strdup(f);
        if (!r)
                return -ENOMEM;

        for (t = r; *f; f++) {
                if (*f == '-')
                        *(t++) = '/';
                else if (*f == '\\') {
                        int a, b;

                        if (f[1] != 'x')
                                return -EINVAL;

                        a = unhexchar(f[2]);
                        if (a < 0)
                                return -EINVAL;

                        b = unhexchar(f[3]);
                        if (b < 0)
                                return -EINVAL;

                        *(t++) = (char) (((uint8_t) a << 4U) | (uint8_t) b);
                        f += 3;
                } else
                        *(t++) = *f;
        }

        *t = 0;

        *ret = r;
        r = NULL;

        return 0;
}

int unit_name_path_escape(const char *f, char **ret) {
        char *p, *s;

        assert(f);
        assert(ret);

        p = strdupa(f);
        if (!p)
                return -ENOMEM;

        path_kill_slashes(p);

        if (STR_IN_SET(p, "/", ""))
                s = strdup("-");
        else {
                char *e;

                if (!path_is_safe(p))
                        return -EINVAL;

                /* Truncate trailing slashes */
                e = endswith(p, "/");
                if (e)
                        *e = 0;

                /* Truncate leading slashes */
                if (p[0] == '/')
                        p++;

                s = unit_name_escape(p);
        }
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_path_unescape(const char *f, char **ret) {
        char *s;
        int r;

        assert(f);

        if (isempty(f))
                return -EINVAL;

        if (streq(f, "-")) {
                s = strdup("/");
                if (!s)
                        return -ENOMEM;
        } else {
                char *w;

                r = unit_name_unescape(f, &w);
                if (r < 0)
                        return r;

                /* Don't accept trailing or leading slashes */
                if (startswith(w, "/") || endswith(w, "/")) {
                        free(w);
                        return -EINVAL;
                }

                /* Prefix a slash again */
                s = strappend("/", w);
                free(w);
                if (!s)
                        return -ENOMEM;

                if (!path_is_safe(s)) {
                        free(s);
                        return -EINVAL;
                }
        }

        if (ret)
                *ret = s;
        else
                free(s);

        return 0;
}

int unit_name_replace_instance(const char *f, const char *i, char **ret) {
        const char *p, *e;
        char *s;
        size_t a, b;

        assert(f);
        assert(i);
        assert(ret);

        if (!unit_name_is_valid(f, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;
        if (!unit_instance_is_valid(i))
                return -EINVAL;

        assert_se(p = strchr(f, '@'));
        assert_se(e = strrchr(f, '.'));

        a = p - f;
        b = strlen(i);

        s = new(char, a + 1 + b + strlen(e) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(mempcpy(s, f, a + 1), i, b), e);

        *ret = s;
        return 0;
}

int unit_name_template(const char *f, char **ret) {
        const char *p, *e;
        char *s;
        size_t a;

        assert(f);
        assert(ret);

        if (!unit_name_is_valid(f, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;

        assert_se(p = strchr(f, '@'));
        assert_se(e = strrchr(f, '.'));

        a = p - f;

        s = new(char, a + 1 + strlen(e) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, f, a + 1), e);

        *ret = s;
        return 0;
}

int unit_name_from_path(const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL;
        char *s = NULL;
        int r;

        assert(path);
        assert(suffix);
        assert(ret);

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        r = unit_name_path_escape(path, &p);
        if (r < 0)
                return r;

        s = strappend(p, suffix);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL;
        char *s;
        int r;

        assert(prefix);
        assert(path);
        assert(suffix);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        r = unit_name_path_escape(path, &p);
        if (r < 0)
                return r;

        s = strjoin(prefix, "@", p, suffix, NULL);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_to_path(const char *name, char **ret) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(name);

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return r;

        return unit_name_path_unescape(prefix, ret);
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

static char *do_escape_mangle(const char *f, UnitNameMangle allow_globs, char *t) {
        const char *valid_chars;

        assert(f);
        assert(IN_SET(allow_globs, UNIT_NAME_GLOB, UNIT_NAME_NOGLOB));
        assert(t);

        /* We'll only escape the obvious characters here, to play
         * safe. */

        valid_chars = allow_globs == UNIT_NAME_GLOB ? "@" VALID_CHARS "[]!-*?" : "@" VALID_CHARS;

        for (; *f; f++) {
                if (*f == '/')
                        *(t++) = '-';
                else if (!strchr(valid_chars, *f))
                        t = do_escape_char(*f, t);
                else
                        *(t++) = *f;
        }

        return t;
}

/**
 *  Convert a string to a unit name. /dev/blah is converted to dev-blah.device,
 *  /blah/blah is converted to blah-blah.mount, anything else is left alone,
 *  except that @suffix is appended if a valid unit suffix is not present.
 *
 *  If @allow_globs, globs characters are preserved. Otherwise they are escaped.
 */
int unit_name_mangle_with_suffix(const char *name, UnitNameMangle allow_globs, const char *suffix, char **ret) {
        char *s, *t;
        int r;

        assert(name);
        assert(suffix);
        assert(ret);

        if (isempty(name)) /* We cannot mangle empty unit names to become valid, sorry. */
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        if (unit_name_is_valid(name, UNIT_NAME_ANY)) {
                /* No mangling necessary... */
                s = strdup(name);
                if (!s)
                        return -ENOMEM;

                *ret = s;
                return 0;
        }

        if (is_device_path(name)) {
                r = unit_name_from_path(name, ".device", ret);
                if (r >= 0)
                        return 1;
                if (r != -EINVAL)
                        return r;
        }

        if (path_is_absolute(name)) {
                r = unit_name_from_path(name, ".mount", ret);
                if (r >= 0)
                        return 1;
                if (r != -EINVAL)
                        return r;
        }

        s = new(char, strlen(name) * 4 + strlen(suffix) + 1);
        if (!s)
                return -ENOMEM;

        t = do_escape_mangle(name, allow_globs, s);
        *t = 0;

        if (unit_name_to_type(s) < 0)
                strcpy(t, suffix);

        *ret = s;
        return 1;
}

int slice_build_parent_slice(const char *slice, char **ret) {
        char *s, *dash;
        int r;

        assert(slice);
        assert(ret);

        if (!slice_name_is_valid(slice))
                return -EINVAL;

        if (streq(slice, "-.slice")) {
                *ret = NULL;
                return 0;
        }

        s = strdup(slice);
        if (!s)
                return -ENOMEM;

        dash = strrchr(s, '-');
        if (dash)
                strcpy(dash, ".slice");
        else {
                r = free_and_strdup(&s, "-.slice");
                if (r < 0) {
                        free(s);
                        return r;
                }
        }

        *ret = s;
        return 1;
}

int slice_build_subslice(const char *slice, const char*name, char **ret) {
        char *subslice;

        assert(slice);
        assert(name);
        assert(ret);

        if (!slice_name_is_valid(slice))
                return -EINVAL;

        if (!unit_prefix_is_valid(name))
                return -EINVAL;

        if (streq(slice, "-.slice"))
                subslice = strappend(name, ".slice");
        else {
                char *e;

                assert_se(e = endswith(slice, ".slice"));

                subslice = new(char, (e - slice) + 1 + strlen(name) + 6 + 1);
                if (!subslice)
                        return -ENOMEM;

                stpcpy(stpcpy(stpcpy(mempcpy(subslice, slice, e - slice), "-"), name), ".slice");
        }

        *ret = subslice;
        return 0;
}

bool slice_name_is_valid(const char *name) {
        const char *p, *e;
        bool dash = false;

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN))
                return false;

        if (streq(name, "-.slice"))
                return true;

        e = endswith(name, ".slice");
        if (!e)
                return false;

        for (p = name; p < e; p++) {

                if (*p == '-') {

                        /* Don't allow initial dash */
                        if (p == name)
                                return false;

                        /* Don't allow multiple dashes */
                        if (dash)
                                return false;

                        dash = true;
                } else
                        dash = false;
        }

        /* Don't allow trailing hash */
        if (dash)
                return false;

        return true;
}

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

static const char* const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
        [UNIT_REQUIRES] = "Requires",
        [UNIT_REQUIRES_OVERRIDABLE] = "RequiresOverridable",
        [UNIT_REQUISITE] = "Requisite",
        [UNIT_REQUISITE_OVERRIDABLE] = "RequisiteOverridable",
        [UNIT_WANTS] = "Wants",
        [UNIT_BINDS_TO] = "BindsTo",
        [UNIT_PART_OF] = "PartOf",
        [UNIT_REQUIRED_BY] = "RequiredBy",
        [UNIT_REQUIRED_BY_OVERRIDABLE] = "RequiredByOverridable",
        [UNIT_REQUISITE_OF] = "RequisiteOf",
        [UNIT_REQUISITE_OF_OVERRIDABLE] = "RequisiteOfOverridable",
        [UNIT_WANTED_BY] = "WantedBy",
        [UNIT_BOUND_BY] = "BoundBy",
        [UNIT_CONSISTS_OF] = "ConsistsOf",
        [UNIT_CONFLICTS] = "Conflicts",
        [UNIT_CONFLICTED_BY] = "ConflictedBy",
        [UNIT_BEFORE] = "Before",
        [UNIT_AFTER] = "After",
        [UNIT_ON_FAILURE] = "OnFailure",
        [UNIT_TRIGGERS] = "Triggers",
        [UNIT_TRIGGERED_BY] = "TriggeredBy",
        [UNIT_PROPAGATES_RELOAD_TO] = "PropagatesReloadTo",
        [UNIT_RELOAD_PROPAGATED_FROM] = "ReloadPropagatedFrom",
        [UNIT_JOINS_NAMESPACE_OF] = "JoinsNamespaceOf",
        [UNIT_REFERENCES] = "References",
        [UNIT_REFERENCED_BY] = "ReferencedBy",
};

DEFINE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
