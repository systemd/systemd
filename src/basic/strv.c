/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "env-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "memory-util.h"
#include "nulstr-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

char* strv_find(char * const *l, const char *name) {
        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

char* strv_find_case(char * const *l, const char *name) {
        assert(name);

        STRV_FOREACH(i, l)
                if (strcaseeq(*i, name))
                        return *i;

        return NULL;
}

char* strv_find_prefix(char * const *l, const char *name) {
        assert(name);

        STRV_FOREACH(i, l)
                if (startswith(*i, name))
                        return *i;

        return NULL;
}

char* strv_find_startswith(char * const *l, const char *name) {
        assert(name);

        /* Like strv_find_prefix, but actually returns only the
         * suffix, not the whole item */

        STRV_FOREACH(i, l) {
                char *e;

                e = startswith(*i, name);
                if (e)
                        return e;
        }

        return NULL;
}

char* strv_find_first_field(char * const *needles, char * const *haystack) {
        STRV_FOREACH(k, needles) {
                char *value = strv_env_pairs_get((char **)haystack, *k);
                if (value)
                        return value;
        }

        return NULL;
}

char** strv_free(char **l) {
        STRV_FOREACH(k, l)
                free(*k);

        return mfree(l);
}

char** strv_free_erase(char **l) {
        STRV_FOREACH(i, l)
                erase_and_freep(i);

        return mfree(l);
}

void strv_free_many(char ***strvs, size_t n) {
        assert(strvs || n == 0);

        FOREACH_ARRAY (i, strvs, n)
                strv_free(*i);

        free(strvs);
}

char** strv_copy_n(char * const *l, size_t m) {
        _cleanup_strv_free_ char **result = NULL;
        char **k;

        result = new(char*, MIN(strv_length(l), m) + 1);
        if (!result)
                return NULL;

        k = result;
        STRV_FOREACH(i, l) {
                if (m == 0)
                        break;

                *k = strdup(*i);
                if (!*k)
                        return NULL;
                k++;

                if (m != SIZE_MAX)
                        m--;
        }

        *k = NULL;
        return TAKE_PTR(result);
}

size_t strv_length(char * const *l) {
        size_t n = 0;

        STRV_FOREACH(i, l)
                n++;

        return n;
}

char** strv_new_ap(const char *x, va_list ap) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * STRV_IGNORE. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        va_copy(aq, ap);
        for (const char *s = x; s; s = va_arg(aq, const char*)) {
                if (s == STRV_IGNORE)
                        continue;

                n++;
        }
        va_end(aq);

        a = new(char*, n+1);
        if (!a)
                return NULL;

        for (const char *s = x; s; s = va_arg(ap, const char*)) {
                if (s == STRV_IGNORE)
                        continue;

                a[i] = strdup(s);
                if (!a[i])
                        return NULL;

                i++;
        }

        a[i] = NULL;

        return TAKE_PTR(a);
}

char** strv_new_internal(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

int strv_extend_strv(char ***a, char * const *b, bool filter_duplicates) {
        size_t p, q, i = 0;
        char **t;

        assert(a);

        if (strv_isempty(b))
                return 0;

        p = strv_length(*a);
        q = strv_length(b);

        if (p >= SIZE_MAX - q)
                return -ENOMEM;

        t = reallocarray(*a, GREEDY_ALLOC_ROUND_UP(p + q + 1), sizeof(char *));
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
        free_many_charp(t + p, i);
        t[p] = NULL;
        return -ENOMEM;
}

int strv_extend_strv_concat(char ***a, char * const *b, const char *suffix) {
        int r;

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

int strv_split_newlines_full(char ***ret, const char *s, ExtractFlags flags) {
        _cleanup_strv_free_ char **l = NULL;
        size_t n;
        int r;

        assert(s);

        /* Special version of strv_split_full() that splits on newlines and
         * suppresses an empty string at the end. */

        r = strv_split_full(&l, s, NEWLINE, flags);
        if (r < 0)
                return r;

        n = strv_length(l);
        if (n > 0 && isempty(l[n - 1])) {
                l[n - 1] = mfree(l[n - 1]);
                n--;
        }

        *ret = TAKE_PTR(l);
        return n;
}

int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags) {
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0;
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

                if (!GREEDY_REALLOC(l, n + 2))
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

int strv_split_and_extend_full(char ***t, const char *s, const char *separators, bool filter_duplicates, ExtractFlags flags) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(t);
        assert(s);

        r = strv_split_full(&l, s, separators, flags);
        if (r < 0)
                return r;

        r = strv_extend_strv(t, l, filter_duplicates);
        if (r < 0)
                return r;

        return (int) strv_length(*t);
}

int strv_split_colon_pairs(char ***t, const char *s) {
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0;
        int r;

        assert(t);
        assert(s);

        for (;;) {
                _cleanup_free_ char *first = NULL, *second = NULL, *tuple = NULL, *second_or_empty = NULL;

                r = extract_first_word(&s, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                const char *p = tuple;
                r = extract_many_words(&p, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS,
                                       &first, &second, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;
                /* Enforce that at most 2 colon-separated words are contained in each group */
                if (!isempty(p))
                        return -EINVAL;

                second_or_empty = strdup(strempty(second));
                if (!second_or_empty)
                        return -ENOMEM;

                if (!GREEDY_REALLOC(l, n + 3))
                        return -ENOMEM;

                l[n++] = TAKE_PTR(first);
                l[n++] = TAKE_PTR(second_or_empty);

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

char* strv_join_full(char * const *l, const char *separator, const char *prefix, bool escape_separator) {
        char *r, *e;
        size_t n, k, m;

        if (!separator)
                separator = " ";

        k = strlen(separator);
        m = strlen_ptr(prefix);

        if (escape_separator) /* If the separator was multi-char, we wouldn't know how to escape it. */
                assert(k == 1);

        n = 0;
        STRV_FOREACH(s, l) {
                if (s != l)
                        n += k;

                bool needs_escaping = escape_separator && strchr(*s, *separator);

                n += m + strlen(*s) * (1 + needs_escaping);
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

                bool needs_escaping = escape_separator && strchr(*s, *separator);

                if (needs_escaping)
                        for (size_t i = 0; (*s)[i]; i++) {
                                if ((*s)[i] == *separator)
                                        *(e++) = '\\';
                                *(e++) = (*s)[i];
                        }
                else
                        e = stpcpy(e, *s);
        }

        *e = 0;

        return r;
}

int strv_push_with_size(char ***l, size_t *n, char *value) {
        /* n is a pointer to a variable to store the size of l.
         * If not given (i.e. n is NULL or *n is SIZE_MAX), size will be calculated using strv_length().
         * If n is not NULL, the size after the push will be returned.
         * If value is empty, no action is taken and *n is not set. */

        if (!value)
                return 0;

        size_t size = n ? *n : SIZE_MAX;
        if (size == SIZE_MAX)
                size = strv_length(*l);

        /* Check for overflow */
        if (size > SIZE_MAX-2)
                return -ENOMEM;

        char **c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(size + 2), sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[size] = value;
        c[size+1] = NULL;

        *l = c;
        if (n)
                *n = size + 1;
        return 0;
}

int strv_push_pair(char ***l, char *a, char *b) {
        char **c;
        size_t n;

        if (!a && !b)
                return 0;

        n = strv_length(*l);

        /* Check for overflow */
        if (n > SIZE_MAX-3)
                return -ENOMEM;

        /* increase and check for overflow */
        c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(n + !!a + !!b + 1), sizeof(char*));
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
        size_t n, m;

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

        for (size_t i = 0; i < position; i++)
                c[i] = (*l)[i];
        c[position] = value;
        for (size_t i = position; i < n; i++)
                c[i+1] = (*l)[i];
        c[n+1] = NULL;

        return free_and_replace(*l, c);
}

int strv_consume_with_size(char ***l, size_t *n, char *value) {
        int r;

        r = strv_push_with_size(l, n, value);
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

int strv_prepend(char ***l, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume_prepend(l, v);
}

int strv_extend_with_size(char ***l, size_t *n, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume_with_size(l, n, v);
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

char** strv_uniq(char **l) {
        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

bool strv_is_uniq(char * const *l) {
        STRV_FOREACH(i, l)
                if (strv_contains(i+1, *i))
                        return false;

        return true;
}

char** strv_remove(char **l, const char *s) {
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

bool strv_overlap(char * const *a, char * const *b) {
        STRV_FOREACH(i, a)
                if (strv_contains(b, *i))
                        return true;

        return false;
}

static int str_compare(char * const *a, char * const *b) {
        return strcmp(*a, *b);
}

char** strv_sort(char **l) {
        typesafe_qsort(l, strv_length(l), str_compare);
        return l;
}

int strv_compare(char * const *a, char * const *b) {
        int r;

        if (strv_isempty(a)) {
                if (strv_isempty(b))
                        return 0;
                else
                        return -1;
        }

        if (strv_isempty(b))
                return 1;

        for ( ; *a || *b; ++a, ++b) {
                r = strcmp_ptr(*a, *b);
                if (r != 0)
                        return r;
        }

        return 0;
}

void strv_print_full(char * const *l, const char *prefix) {
        STRV_FOREACH(s, l)
                printf("%s%s\n", strempty(prefix), *s);
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

char* startswith_strv(const char *s, char * const *l) {
        STRV_FOREACH(i, l) {
                char *found = startswith(s, *i);
                if (found)
                        return found;
        }

        return NULL;
}

char** strv_reverse(char **l) {
        size_t n;

        n = strv_length(l);
        if (n <= 1)
                return l;

        for (size_t i = 0; i < n / 2; i++)
                SWAP_TWO(l[i], l[n-1-i]);

        return l;
}

char** strv_shell_escape(char **l, const char *bad) {
        /* Escapes every character in every string in l that is in bad,
         * edits in-place, does not roll-back on error. */

        STRV_FOREACH(s, l) {
                char *v;

                v = shell_escape(*s, bad);
                if (!v)
                        return NULL;

                free_and_replace(*s, v);
        }

        return l;
}

bool strv_fnmatch_full(
                char* const* patterns,
                const char *s,
                int flags,
                size_t *ret_matched_pos) {

        assert(s);

        if (patterns)
                for (size_t i = 0; patterns[i]; i++)
                        /* NB: We treat all fnmatch() errors as equivalent to FNM_NOMATCH, i.e. if fnmatch() fails to
                         * process the pattern for some reason we'll consider this equivalent to non-matching. */
                        if (fnmatch(patterns[i], s, flags) == 0) {
                                if (ret_matched_pos)
                                        *ret_matched_pos = i;
                                return true;
                        }

        if (ret_matched_pos)
                *ret_matched_pos = SIZE_MAX;

        return false;
}

char** strv_skip(char **l, size_t n) {

        while (n > 0) {
                if (strv_isempty(l))
                        return l;

                l++, n--;
        }

        return l;
}

int strv_extend_n(char ***l, const char *value, size_t n) {
        size_t i, k;
        char **nl;

        assert(l);

        if (!value)
                return 0;
        if (n == 0)
                return 0;

        /* Adds the value n times to l */

        k = strv_length(*l);
        if (n >= SIZE_MAX - k)
                return -ENOMEM;

        nl = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(k + n + 1), sizeof(char *));
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
        for (size_t j = k; j < i; j++)
                free(nl[j]);
        nl[k] = NULL;

        return -ENOMEM;
}

int strv_extend_assignment(char ***l, const char *lhs, const char *rhs) {
        char *j;

        assert(l);
        assert(lhs);

        if (!rhs) /* value is optional, in which case we suppress the field */
                return 0;

        j = strjoin(lhs, "=", rhs);
        if (!j)
                return -ENOMEM;

        return strv_consume(l, j);
}

int fputstrv(FILE *f, char * const *l, const char *separator, bool *space) {
        bool b = false;
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

int _string_strv_hashmap_put(Hashmap **h, const char *key, const char *value  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _hashmap_ensure_allocated(h, &string_strv_hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(*h, key, value);
}

int _string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _ordered_hashmap_ensure_allocated(h, &string_strv_hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(PLAIN_HASHMAP(*h), key, value);
}

DEFINE_HASH_OPS_FULL(string_strv_hash_ops, char, string_hash_func, string_compare_func, free, char*, strv_free);

char* strv_endswith(const char *s, char **l) {
        STRV_FOREACH(i, l) {
                char *e = endswith(s, *i);
                if (e)
                        return (char*) e;
        }

        return NULL;
}
