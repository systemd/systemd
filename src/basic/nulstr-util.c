/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nulstr-util.h"
#include "string-util.h"
#include "strv.h"

char** strv_parse_nulstr(const char *s, size_t l) {
        /* l is the length of the input data, which will be split at NULs into elements of the resulting
         * strv. Hence, the number of items in the resulting strv will be equal to one plus the number of NUL
         * bytes in the l bytes starting at s, unless s[l-1] is NUL, in which case the final empty string is
         * not stored in the resulting strv, and length is equal to the number of NUL bytes.
         *
         * Note that contrary to a normal nulstr which cannot contain empty strings, because the input data
         * is terminated by any two consequent NUL bytes, this parser accepts empty strings in s. */

        _cleanup_strv_free_ char **v = NULL;
        size_t c = 0, i = 0;

        assert(s || l <= 0);

        if (l <= 0)
                return new0(char*, 1);

        for (const char *p = s; p < s + l; p++)
                if (*p == 0)
                        c++;

        if (s[l-1] != 0)
                c++;

        v = new0(char*, c+1);
        if (!v)
                return NULL;

        for (const char *p = s; p < s + l; ) {
                const char *e;

                e = memchr(p, 0, s + l - p);

                v[i] = memdup_suffix0(p, e ? e - p : s + l - p);
                if (!v[i])
                        return NULL;

                i++;

                if (!e)
                        break;

                p = e + 1;
        }

        assert(i == c);

        return TAKE_PTR(v);
}

char** strv_split_nulstr(const char *s) {
        _cleanup_strv_free_ char **r = NULL;

        NULSTR_FOREACH(i, s)
                if (strv_extend(&r, i) < 0)
                        return NULL;

        if (!r)
                return strv_new(NULL);

        return TAKE_PTR(r);
}

int strv_make_nulstr(char * const *l, char **ret, size_t *ret_size) {
        /* A valid nulstr with two NULs at the end will be created, but q will be the length without the two
         * trailing NULs. Thus the output string is a valid nulstr and can be iterated over using
         * NULSTR_FOREACH(), and can also be parsed by strv_parse_nulstr() as long as the length is provided
         * separately. */

        _cleanup_free_ char *m = NULL;
        size_t n = 0;

        assert(ret);
        assert(ret_size);

        STRV_FOREACH(i, l) {
                size_t z;

                z = strlen(*i);

                if (!GREEDY_REALLOC(m, n + z + 2))
                        return -ENOMEM;

                memcpy(m + n, *i, z + 1);
                n += z + 1;
        }

        if (!m) {
                m = new0(char, 2);
                if (!m)
                        return -ENOMEM;
                n = 1;
        } else
                /* make sure there is a second extra NUL at the end of resulting nulstr */
                m[n] = '\0';

        assert(n > 0);
        *ret = TAKE_PTR(m);
        *ret_size = n - 1;

        return 0;
}

const char* nulstr_get(const char *nulstr, const char *needle) {
        if (!nulstr)
                return NULL;

        NULSTR_FOREACH(i, nulstr)
                if (streq(i, needle))
                        return i;

        return NULL;
}
