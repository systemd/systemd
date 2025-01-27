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
#include "gunicode.h"
#include "memory-util.h"
#include "nulstr-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

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

static char* strv_find_closest_prefix(char * const *l, const char *name) {
        size_t best_distance = SIZE_MAX;
        char *best = NULL;

        assert(name);

        STRV_FOREACH(s, l) {
                char *e = startswith(*s, name);
                if (!e)
                        continue;

                size_t n = strlen(e);
                if (n < best_distance) {
                        best_distance = n;
                        best = *s;
                }
        }

        return best;
}

static char* strv_find_closest_by_levenshtein(char * const *l, const char *name) {
        ssize_t best_distance = SSIZE_MAX;
        char *best = NULL;

        assert(name);

        STRV_FOREACH(i, l) {
                ssize_t distance;

                distance = strlevenshtein(*i, name);
                if (distance < 0) {
                        log_debug_errno(distance, "Failed to determine Levenshtein distance between %s and %s: %m", *i, name);
                        return NULL;
                }

                if (distance > 5) /* If the distance is just too far off, don't make a bad suggestion */
                        continue;

                if (distance < best_distance) {
                        best_distance = distance;
                        best = *i;
                }
        }

        return best;
}

char* strv_find_closest(char * const *l, const char *name) {
        assert(name);

        /* Be more helpful to the user, and give a hint what the user might have wanted to type. We search
         * with two mechanisms: a simple prefix match and – if that didn't yield results –, a Levenshtein
         * word distance based match. */

        char *found = strv_find_closest_prefix(l, name);
        if (found)
                return found;

        return strv_find_closest_by_levenshtein(l, name);
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

int strv_copy_unless_empty(char * const *l, char ***ret) {
        assert(ret);

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        char **copy = strv_copy(l);
        if (!copy)
                return -ENOMEM;

        *ret = TAKE_PTR(copy);
        return 1;
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

        assert(a);

        q = strv_length(b);
        if (q == 0)
                return 0;

        p = strv_length(*a);
        if (p >= SIZE_MAX - q)
                return -ENOMEM;

        char **t = reallocarray(*a, GREEDY_ALLOC_ROUND_UP(p + q + 1), sizeof(char *));
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

int strv_extend_strv_consume(char ***a, char **b, bool filter_duplicates) {
        _cleanup_strv_free_ char **b_consume = b;
        size_t p, q, i;

        assert(a);

        q = strv_length(b);
        if (q == 0)
                return 0;

        p = strv_length(*a);
        if (p == 0) {
                strv_free_and_replace(*a, b_consume);

                if (filter_duplicates)
                        strv_uniq(*a);

                return strv_length(*a);
        }

        if (p >= SIZE_MAX - q)
                return -ENOMEM;

        char **t = reallocarray(*a, GREEDY_ALLOC_ROUND_UP(p + q + 1), sizeof(char *));
        if (!t)
                return -ENOMEM;

        t[p] = NULL;
        *a = t;

        if (!filter_duplicates) {
                *mempcpy_typesafe(t + p, b, q) = NULL;
                i = q;
        } else {
                i = 0;

                STRV_FOREACH(s, b) {
                        if (strv_contains(t, *s)) {
                                free(*s);
                                continue;
                        }

                        t[p+i] = *s;

                        i++;
                        t[p+i] = NULL;
                }
        }

        assert(i <= q);

        b_consume = mfree(b_consume);

        return (int) i;
}

int strv_extend_strv_biconcat(char ***a, const char *prefix, const char* const *b, const char *suffix) {
        int r;

        assert(a);

        STRV_FOREACH(s, b) {
                char *v;

                v = strjoin(strempty(prefix), *s, suffix);
                if (!v)
                        return -ENOMEM;

                r = strv_consume(a, v);
                if (r < 0)
                        return r;
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
        char **l;
        int r;

        assert(t);
        assert(s);

        r = strv_split_full(&l, s, separators, flags);
        if (r < 0)
                return r;

        r = strv_extend_strv_consume(t, l, filter_duplicates);
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
                                       &first, &second);
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

        assert(l);

        if (!value)
                return 0;

        n = strv_length(*l);
        position = MIN(position, n);

        /* check for overflow and increase */
        if (n > SIZE_MAX - 2)
                return -ENOMEM;
        m = n + 2;

        c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(m), sizeof(char*));
        if (!c)
                return -ENOMEM;

        if (n > position)
                memmove(c + position + 1, c + position, (n - position) * sizeof(char*));

        c[position] = value;
        c[n + 1] = NULL;

        *l = c;
        return 0;
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

int strv_extend_many_internal(char ***l, const char *value, ...) {
        va_list ap;
        size_t n, m;
        int r;

        assert(l);

        m = n = strv_length(*l);

        r = 0;
        va_start(ap, value);
        for (const char *s = value; s != POINTER_MAX; s = va_arg(ap, const char*)) {
                if (!s)
                        continue;

                if (m > SIZE_MAX-1) { /* overflow */
                        r = -ENOMEM;
                        break;
                }
                m++;
        }
        va_end(ap);

        if (r < 0)
                return r;
        if (m > SIZE_MAX-1)
                return -ENOMEM;

        char **c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(m+1), sizeof(char*));
        if (!c)
                return -ENOMEM;
        *l = c;

        r = 0;
        size_t i = n;
        va_start(ap, value);
        for (const char *s = value; s != POINTER_MAX; s = va_arg(ap, const char*)) {
                if (!s)
                        continue;

                c[i] = strdup(s);
                if (!c[i]) {
                        r = -ENOMEM;
                        break;
                }
                i++;
        }
        va_end(ap);

        if (r < 0) {
                /* rollback on error */
                for (size_t j = n; j < i; j++)
                        c[j] = mfree(c[j]);
                return r;
        }

        c[i] = NULL;
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

char** strv_sort_uniq(char **l) {
        if (strv_isempty(l))
                return l;

        char **tail = strv_sort(l), *prev = NULL;
        STRV_FOREACH(i, l)
                if (streq_ptr(*i, prev))
                        free(*i);
                else
                        *(tail++) = prev = *i;

        *tail = NULL;
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

bool strv_equal_ignore_order(char **a, char **b) {

        /* Just like strv_equal(), but doesn't care about the order of elements or about redundant entries
         * (i.e. it's even ok if the number of entries in the array differ, as long as the difference just
         * consists of repetitions). */

        if (a == b)
                return true;

        STRV_FOREACH(i, a)
                if (!strv_contains(b, *i))
                        return false;

        STRV_FOREACH(i, b)
                if (!strv_contains(a, *i))
                        return false;

        return true;
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

char* endswith_strv(const char *s, char * const *l) {
        STRV_FOREACH(i, l) {
                char *found = endswith(s, *i);
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

        assert(f);

        /* Like fputs(), but for strv, and with a less stupid argument order */

        if (!space)
                space = &b;

        STRV_FOREACH(s, l) {
                r = fputs_with_separator(f, *s, separator, space);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int string_strv_hashmap_put_internal(Hashmap *h, const char *key, const char *value) {
        char **l;
        int r;

        assert(h);
        assert(key);
        assert(value);

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

        assert(h);
        assert(key);
        assert(value);

        r = _hashmap_ensure_allocated(h, &string_hash_ops_free_strv_free  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(*h, key, value);
}

int _string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value  HASHMAP_DEBUG_PARAMS) {
        int r;

        assert(h);
        assert(key);
        assert(value);

        r = _ordered_hashmap_ensure_allocated(h, &string_hash_ops_free_strv_free  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(PLAIN_HASHMAP(*h), key, value);
}

int strv_rebreak_lines(char **l, size_t width, char ***ret) {
        _cleanup_strv_free_ char **broken = NULL;
        int r;

        assert(ret);

        /* Implements a simple UTF-8 line breaking algorithm
         *
         * Goes through all entries in *l, and line-breaks each line that is longer than the specified
         * character width. Breaks at the end of words/beginning of whitespace. Lines that do not contain whitespace are not
         * broken. Retains whitespace at beginning of lines, removes it at end of lines. */

        if (width == SIZE_MAX) { /* NOP? */
                broken = strv_copy(l);
                if (!broken)
                        return -ENOMEM;

                *ret = TAKE_PTR(broken);
                return 0;
        }

        STRV_FOREACH(i, l) {
                const char *start = *i, *whitespace_begin = NULL, *whitespace_end = NULL;
                bool in_prefix = true; /* still in the whitespace in the beginning of the line? */
                size_t w = 0;

                for (const char *p = start; *p != 0; p = utf8_next_char(p)) {
                        if (strchr(NEWLINE, *p)) {
                                in_prefix = true;
                                whitespace_begin = whitespace_end = NULL;
                                w = 0;
                        } else if (strchr(WHITESPACE, *p)) {
                                if (!in_prefix && (!whitespace_begin || whitespace_end)) {
                                        whitespace_begin = p;
                                        whitespace_end = NULL;
                                }
                        } else {
                                if (whitespace_begin && !whitespace_end)
                                        whitespace_end = p;

                                in_prefix = false;
                        }

                        int cw = utf8_char_console_width(p);
                        if (cw < 0) {
                                log_debug_errno(cw, "Comment to line break contains invalid UTF-8, ignoring.");
                                cw = 1;
                        }

                        w += cw;

                        if (w > width && whitespace_begin && whitespace_end) {
                                _cleanup_free_ char *truncated = NULL;

                                truncated = strndup(start, whitespace_begin - start);
                                if (!truncated)
                                        return -ENOMEM;

                                r = strv_consume(&broken, TAKE_PTR(truncated));
                                if (r < 0)
                                        return r;

                                p = start = whitespace_end;
                                whitespace_begin = whitespace_end = NULL;
                                w = cw;
                        }
                }

                /* Process rest of the line */
                assert(start);
                if (in_prefix) /* Never seen anything non-whitespace? Generate empty line! */
                        r = strv_extend(&broken, "");
                else if (whitespace_begin && !whitespace_end) { /* Ends in whitespace? Chop it off! */
                        _cleanup_free_ char *truncated = strndup(start, whitespace_begin - start);
                        if (!truncated)
                                return -ENOMEM;

                        r = strv_consume(&broken, TAKE_PTR(truncated));
                } else /* Otherwise use line as is */
                        r = strv_extend(&broken, start);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(broken);
        return 0;
}
