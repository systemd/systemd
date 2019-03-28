/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "memory-util.h"
#include "nulstr-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

char *strv_find(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

char *strv_find_prefix(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (startswith(*i, name))
                        return *i;

        return NULL;
}

char *strv_find_startswith(char **l, const char *name) {
        char **i, *e;

        assert(name);

        /* Like strv_find_prefix, but actually returns only the
         * suffix, not the whole item */

        STRV_FOREACH(i, l) {
                e = startswith(*i, name);
                if (e)
                        return e;
        }

        return NULL;
}

void strv_clear(char **l) {
        char **k;

        if (!l)
                return;

        for (k = l; *k; k++)
                free(*k);

        *l = NULL;
}

char **strv_free(char **l) {
        strv_clear(l);
        return mfree(l);
}

char **strv_free_erase(char **l) {
        char **i;

        STRV_FOREACH(i, l)
                erase_and_freep(i);

        return mfree(l);
}

char **strv_copy(char * const *l) {
        char **r, **k;

        k = r = new(char*, strv_length(l) + 1);
        if (!r)
                return NULL;

        if (l)
                for (; *l; k++, l++) {
                        *k = strdup(*l);
                        if (!*k) {
                                strv_free(r);
                                return NULL;
                        }
                }

        *k = NULL;
        return r;
}

size_t strv_length(char * const *l) {
        size_t n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new_ap(const char *x, va_list ap) {
        const char *s;
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * STRV_IGNORE. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        if (x) {
                n = x == STRV_IGNORE ? 0 : 1;

                va_copy(aq, ap);
                while ((s = va_arg(aq, const char*))) {
                        if (s == STRV_IGNORE)
                                continue;

                        n++;
                }

                va_end(aq);
        }

        a = new(char*, n+1);
        if (!a)
                return NULL;

        if (x) {
                if (x != STRV_IGNORE) {
                        a[i] = strdup(x);
                        if (!a[i])
                                return NULL;
                        i++;
                }

                while ((s = va_arg(ap, const char*))) {

                        if (s == STRV_IGNORE)
                                continue;

                        a[i] = strdup(s);
                        if (!a[i])
                                return NULL;

                        i++;
                }
        }

        a[i] = NULL;

        return TAKE_PTR(a);
}

char **strv_new_internal(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

int strv_extend_strv(char ***a, char **b, bool filter_duplicates) {
        char **s, **t;
        size_t p, q, i = 0, j;

        assert(a);

        if (strv_isempty(b))
                return 0;

        p = strv_length(*a);
        q = strv_length(b);

        t = reallocarray(*a, p + q + 1, sizeof(char *));
        if (!t)
                return -ENOMEM;

        t[p] = NULL;
        *a = t;

        STRV_FOREACH(s, b) {

                if (filter_duplicates && strv_contains(t, *s))
                        continue;

                t[p+i] = strdup(*s);
                if (!t[p+i])
                        goto rollback;

                i++;
                t[p+i] = NULL;
        }

        assert(i <= q);

        return (int) i;

rollback:
        for (j = 0; j < i; j++)
                free(t[p + j]);

        t[p] = NULL;
        return -ENOMEM;
}

int strv_extend_strv_concat(char ***a, char **b, const char *suffix) {
        int r;
        char **s;

        STRV_FOREACH(s, b) {
                char *v;

                v = strjoin(*s, suffix);
                if (!v)
                        return -ENOMEM;

                r = strv_push(a, v);
                if (r < 0) {
                        free(v);
                        return r;
                }
        }

        return 0;
}

char **strv_split_full(const char *s, const char *separator, SplitFlags flags) {
        const char *word, *state;
        size_t l;
        size_t n, i;
        char **r;

        assert(s);

        if (!separator)
                separator = WHITESPACE;

        s += strspn(s, separator);
        if (isempty(s))
                return new0(char*, 1);

        n = 0;
        _FOREACH_WORD(word, l, s, separator, flags, state)
                n++;

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        _FOREACH_WORD(word, l, s, separator, flags, state) {
                r[i] = strndup(word, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
        }

        r[i] = NULL;
        return r;
}

char **strv_split_newlines(const char *s) {
        char **l;
        size_t n;

        assert(s);

        /* Special version of strv_split() that splits on newlines and
         * suppresses an empty string at the end */

        l = strv_split(s, NEWLINE);
        if (!l)
                return NULL;

        n = strv_length(l);
        if (n <= 0)
                return l;

        if (isempty(l[n - 1]))
                l[n - 1] = mfree(l[n - 1]);

        return l;
}

int strv_split_extract(char ***t, const char *s, const char *separators, ExtractFlags flags) {
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0, allocated = 0;
        int r;

        assert(t);
        assert(s);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&s, &word, separators, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(l, allocated, n + 2))
                        return -ENOMEM;

                l[n++] = TAKE_PTR(word);

                l[n] = NULL;
        }

        if (!l) {
                l = new0(char*, 1);
                if (!l)
                        return -ENOMEM;
        }

        *t = TAKE_PTR(l);

        return (int) n;
}

char *strv_join_prefix(char **l, const char *separator, const char *prefix) {
        char *r, *e;
        char **s;
        size_t n, k, m;

        if (!separator)
                separator = " ";

        k = strlen(separator);
        m = strlen_ptr(prefix);

        n = 0;
        STRV_FOREACH(s, l) {
                if (s != l)
                        n += k;
                n += m + strlen(*s);
        }

        r = new(char, n+1);
        if (!r)
                return NULL;

        e = r;
        STRV_FOREACH(s, l) {
                if (s != l)
                        e = stpcpy(e, separator);

                if (prefix)
                        e = stpcpy(e, prefix);

                e = stpcpy(e, *s);
        }

        *e = 0;

        return r;
}

int strv_push(char ***l, char *value) {
        char **c;
        size_t n, m;

        if (!value)
                return 0;

        n = strv_length(*l);

        /* Increase and check for overflow */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        c = reallocarray(*l, m, sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_push_pair(char ***l, char *a, char *b) {
        char **c;
        size_t n, m;

        if (!a && !b)
                return 0;

        n = strv_length(*l);

        /* increase and check for overflow */
        m = n + !!a + !!b + 1;
        if (m < n)
                return -ENOMEM;

        c = reallocarray(*l, m, sizeof(char*));
        if (!c)
                return -ENOMEM;

        if (a)
                c[n++] = a;
        if (b)
                c[n++] = b;
        c[n] = NULL;

        *l = c;
        return 0;
}

int strv_insert(char ***l, size_t position, char *value) {
        char **c;
        size_t n, m, i;

        if (!value)
                return 0;

        n = strv_length(*l);
        position = MIN(position, n);

        /* increase and check for overflow */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        c = new(char*, m);
        if (!c)
                return -ENOMEM;

        for (i = 0; i < position; i++)
                c[i] = (*l)[i];
        c[position] = value;
        for (i = position; i < n; i++)
                c[i+1] = (*l)[i];

        c[n+1] = NULL;

        free(*l);
        *l = c;

        return 0;
}

int strv_consume(char ***l, char *value) {
        int r;

        r = strv_push(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_consume_pair(char ***l, char *a, char *b) {
        int r;

        r = strv_push_pair(l, a, b);
        if (r < 0) {
                free(a);
                free(b);
        }

        return r;
}

int strv_consume_prepend(char ***l, char *value) {
        int r;

        r = strv_push_prepend(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_extend(char ***l, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume(l, v);
}

int strv_extend_front(char ***l, const char *value) {
        size_t n, m;
        char *v, **c;

        assert(l);

        /* Like strv_extend(), but prepends rather than appends the new entry */

        if (!value)
                return 0;

        n = strv_length(*l);

        /* Increase and overflow check. */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        c = reallocarray(*l, m, sizeof(char*));
        if (!c) {
                free(v);
                return -ENOMEM;
        }

        memmove(c+1, c, n * sizeof(char*));
        c[0] = v;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

char **strv_uniq(char **l) {
        char **i;

        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

bool strv_is_uniq(char **l) {
        char **i;

        STRV_FOREACH(i, l)
                if (strv_find(i+1, *i))
                        return false;

        return true;
}

char **strv_remove(char **l, const char *s) {
        char **f, **t;

        if (!l)
                return NULL;

        assert(s);

        /* Drops every occurrence of s in the string list, edits
         * in-place. */

        for (f = t = l; *f; f++)
                if (streq(*f, s))
                        free(*f);
                else
                        *(t++) = *f;

        *t = NULL;
        return l;
}

char **strv_parse_nulstr(const char *s, size_t l) {
        /* l is the length of the input data, which will be split at NULs into
         * elements of the resulting strv. Hence, the number of items in the resulting strv
         * will be equal to one plus the number of NUL bytes in the l bytes starting at s,
         * unless s[l-1] is NUL, in which case the final empty string is not stored in
         * the resulting strv, and length is equal to the number of NUL bytes.
         *
         * Note that contrary to a normal nulstr which cannot contain empty strings, because
         * the input data is terminated by any two consequent NUL bytes, this parser accepts
         * empty strings in s.
         */

        const char *p;
        size_t c = 0, i = 0;
        char **v;

        assert(s || l <= 0);

        if (l <= 0)
                return new0(char*, 1);

        for (p = s; p < s + l; p++)
                if (*p == 0)
                        c++;

        if (s[l-1] != 0)
                c++;

        v = new0(char*, c+1);
        if (!v)
                return NULL;

        p = s;
        while (p < s + l) {
                const char *e;

                e = memchr(p, 0, s + l - p);

                v[i] = strndup(p, e ? e - p : s + l - p);
                if (!v[i]) {
                        strv_free(v);
                        return NULL;
                }

                i++;

                if (!e)
                        break;

                p = e + 1;
        }

        assert(i == c);

        return v;
}

char **strv_split_nulstr(const char *s) {
        const char *i;
        char **r = NULL;

        NULSTR_FOREACH(i, s)
                if (strv_extend(&r, i) < 0) {
                        strv_free(r);
                        return NULL;
                }

        if (!r)
                return strv_new(NULL);

        return r;
}

int strv_make_nulstr(char **l, char **p, size_t *q) {
        /* A valid nulstr with two NULs at the end will be created, but
         * q will be the length without the two trailing NULs. Thus the output
         * string is a valid nulstr and can be iterated over using NULSTR_FOREACH,
         * and can also be parsed by strv_parse_nulstr as long as the length
         * is provided separately.
         */

        size_t n_allocated = 0, n = 0;
        _cleanup_free_ char *m = NULL;
        char **i;

        assert(p);
        assert(q);

        STRV_FOREACH(i, l) {
                size_t z;

                z = strlen(*i);

                if (!GREEDY_REALLOC(m, n_allocated, n + z + 2))
                        return -ENOMEM;

                memcpy(m + n, *i, z + 1);
                n += z + 1;
        }

        if (!m) {
                m = new0(char, 1);
                if (!m)
                        return -ENOMEM;
                n = 1;
        } else
                /* make sure there is a second extra NUL at the end of resulting nulstr */
                m[n] = '\0';

        assert(n > 0);
        *p = m;
        *q = n - 1;

        m = NULL;

        return 0;
}

bool strv_overlap(char **a, char **b) {
        char **i;

        STRV_FOREACH(i, a)
                if (strv_contains(b, *i))
                        return true;

        return false;
}

static int str_compare(char * const *a, char * const *b) {
        return strcmp(*a, *b);
}

char **strv_sort(char **l) {
        typesafe_qsort(l, strv_length(l), str_compare);
        return l;
}

bool strv_equal(char **a, char **b) {

        if (strv_isempty(a))
                return strv_isempty(b);

        if (strv_isempty(b))
                return false;

        for ( ; *a || *b; ++a, ++b)
                if (!streq_ptr(*a, *b))
                        return false;

        return true;
}

void strv_print(char **l) {
        char **s;

        STRV_FOREACH(s, l)
                puts(*s);
}

int strv_extendf(char ***l, const char *format, ...) {
        va_list ap;
        char *x;
        int r;

        va_start(ap, format);
        r = vasprintf(&x, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return strv_consume(l, x);
}

char **strv_reverse(char **l) {
        size_t n, i;

        n = strv_length(l);
        if (n <= 1)
                return l;

        for (i = 0; i < n / 2; i++)
                SWAP_TWO(l[i], l[n-1-i]);

        return l;
}

char **strv_shell_escape(char **l, const char *bad) {
        char **s;

        /* Escapes every character in every string in l that is in bad,
         * edits in-place, does not roll-back on error. */

        STRV_FOREACH(s, l) {
                char *v;

                v = shell_escape(*s, bad);
                if (!v)
                        return NULL;

                free(*s);
                *s = v;
        }

        return l;
}

bool strv_fnmatch(char* const* patterns, const char *s, int flags) {
        char* const* p;

        STRV_FOREACH(p, patterns)
                if (fnmatch(*p, s, flags) == 0)
                        return true;

        return false;
}

char ***strv_free_free(char ***l) {
        char ***i;

        if (!l)
                return NULL;

        for (i = l; *i; i++)
                strv_free(*i);

        return mfree(l);
}

char **strv_skip(char **l, size_t n) {

        while (n > 0) {
                if (strv_isempty(l))
                        return l;

                l++, n--;
        }

        return l;
}

int strv_extend_n(char ***l, const char *value, size_t n) {
        size_t i, j, k;
        char **nl;

        assert(l);

        if (!value)
                return 0;
        if (n == 0)
                return 0;

        /* Adds the value n times to l */

        k = strv_length(*l);

        nl = reallocarray(*l, k + n + 1, sizeof(char *));
        if (!nl)
                return -ENOMEM;

        *l = nl;

        for (i = k; i < k + n; i++) {
                nl[i] = strdup(value);
                if (!nl[i])
                        goto rollback;
        }

        nl[i] = NULL;
        return 0;

rollback:
        for (j = k; j < i; j++)
                free(nl[j]);

        nl[k] = NULL;
        return -ENOMEM;
}

int fputstrv(FILE *f, char **l, const char *separator, bool *space) {
        bool b = false;
        char **s;
        int r;

        /* Like fputs(), but for strv, and with a less stupid argument order */

        if (!space)
                space = &b;

        STRV_FOREACH(s, l) {
                r = fputs_with_space(f, *s, separator, space);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int string_strv_hashmap_put_internal(Hashmap *h, const char *key, const char *value) {
        char **l;
        int r;

        l = hashmap_get(h, key);
        if (l) {
                /* A list for this key already exists, let's append to it if it is not listed yet */
                if (strv_contains(l, value))
                        return 0;

                r = strv_extend(&l, value);
                if (r < 0)
                        return r;

                assert_se(hashmap_update(h, key, l) >= 0);
        } else {
                /* No list for this key exists yet, create one */
                _cleanup_strv_free_ char **l2 = NULL;
                _cleanup_free_ char *t = NULL;

                t = strdup(key);
                if (!t)
                        return -ENOMEM;

                r = strv_extend(&l2, value);
                if (r < 0)
                        return r;

                r = hashmap_put(h, t, l2);
                if (r < 0)
                        return r;
                TAKE_PTR(t);
                TAKE_PTR(l2);
        }

        return 1;
}

int string_strv_hashmap_put(Hashmap **h, const char *key, const char *value) {
        int r;

        r = hashmap_ensure_allocated(h, &string_strv_hash_ops);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(*h, key, value);
}

int string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value) {
        int r;

        r = ordered_hashmap_ensure_allocated(h, &string_strv_hash_ops);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(PLAIN_HASHMAP(*h), key, value);
}

DEFINE_HASH_OPS_FULL(string_strv_hash_ops, char, string_hash_func, string_compare_func, free, char*, strv_free);
